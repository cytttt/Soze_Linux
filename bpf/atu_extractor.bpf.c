// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * ATU (Available Transmission Unit) Extractor
 * eBPF program for extracting ATU headers from TCP packets
 * Compatible with C2L2 P4 program
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TCP option constants
#ifndef TCP_BPF_SOCK_OPS_OPT_CB_FLAG
#define TCP_BPF_SOCK_OPS_OPT_CB_FLAG 1024
#endif

// XDP action constants
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

// ATU state structure (similar to tcp_int_state)
struct atu_state {
    __u32 numer;        // ATU numerator from header
    __u32 denom;        // ATU denominator from header
    __u64 timestamp;    // When this data was last updated
    __u32 valid;        // Whether the data is valid
};

// SK_STORAGE map to attach ATU state to socket (similar to TCP-INT)
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct atu_state);
} map_atu_state SEC(".maps");

// Helper function to get ATU state from socket
static inline struct atu_state *atu_get_state(struct bpf_sock *sk)
{
    if (!sk)
        return NULL;

    return bpf_sk_storage_get(&map_atu_state, sk, NULL,
                              BPF_SK_STORAGE_GET_F_CREATE);
}

// TCP ATU Option structure (for ACK packets)
struct tcp_atu_option {
    __u8 kind;       // TCP option type (254 for custom ATU)
    __u8 length;     // Option length (10 bytes)
    __u32 numer;     // ATU numerator
    __u32 denom;     // ATU denominator
};

// ATU header structure for parsing (in data packets)
struct max_atu_h {
    __u32 numer;
    __u32 denom;
};

// Parse TCP options to find ATU option
static int parse_tcp_atu_option(void *tcp_opts, void *data_end, 
                                struct atu_state *atu_state)
{
    __u8 *opt = tcp_opts;
    __u8 *end = data_end;
    
    // Iterate through TCP options
    while (opt < end) {
        if (opt + 1 > end)
            break;
            
        __u8 kind = *opt;
        
        // End of options
        if (kind == 0)
            break;
            
        // No-op option
        if (kind == 1) {
            opt++;
            continue;
        }
        
        // Check if we have length byte
        if (opt + 2 > end)
            break;
            
        __u8 length = *(opt + 1);
        
        // ATU option (kind = 254)
        if (kind == 254 && length == 10) {
            if (opt + 10 > end)
                break;
                
            struct tcp_atu_option *atu_opt = (struct tcp_atu_option *)opt;
            atu_state->numer = bpf_ntohl(atu_opt->numer);
            atu_state->denom = bpf_ntohl(atu_opt->denom);
            atu_state->timestamp = bpf_ktime_get_ns();
            atu_state->valid = 1;
            return 1; // Found ATU option
        }
        
        // Move to next option
        if (length < 2)
            break;
        opt += length;
    }
    
    return 0; // ATU option not found
}

// Helper function to add ATU option to outgoing ACK
static int add_atu_option_to_ack(struct bpf_sock_ops *skops, 
                                 struct atu_state *atu_state)
{
    struct tcp_atu_option atu_opt = {
        .kind = 254,    // Custom ATU option type
        .length = 10,   // 2 + 4 + 4 bytes
        .numer = bpf_htonl(atu_state->numer),
        .denom = bpf_htonl(atu_state->denom)
    };
    
    // Add the ATU option to the outgoing packet
    return bpf_setsockopt(skops, SOL_TCP, TCP_BPF_SOCK_OPS_OPT_CB_FLAG,
                         &atu_opt, sizeof(atu_opt));
}

SEC("sockops")
int extract_atu_sockops(struct bpf_sock_ops *skops)
{
    struct atu_state *atu_state;
    struct bpf_sock *sk;
    __u32 key = 0;
    
    // Process various socket operations
    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_DATA_SEGS_IN_CB &&
        skops->op != BPF_SOCK_OPS_PARSE_HDR_OPT_CB &&
        skops->op != BPF_SOCK_OPS_WRITE_HDR_OPT_CB)
        return 0;
    
    sk = skops->sk;
    if (!sk)
        return 0;
    
    // Get or create ATU state for this socket
    atu_state = atu_get_state(sk);
    if (!atu_state)
        return 0;
    
    // Handle incoming packets with ATU data
    if (skops->op == BPF_SOCK_OPS_PARSE_HDR_OPT_CB) {
        void *tcp_opts = (void *)(long)skops->skb_data;
        void *data_end = (void *)(long)skops->skb_data_end;
        
        // Try to parse TCP options for ATU data
        if (parse_tcp_atu_option(tcp_opts, data_end, atu_state)) {
            return 0; // Successfully parsed ATU from TCP option
        }
        
        // Try to get ATU data from XDP temp map
        struct atu_state *temp_atu = bpf_map_lookup_elem(&temp_atu_map, &key);
        if (temp_atu && temp_atu->valid) {
            atu_state->numer = temp_atu->numer;
            atu_state->denom = temp_atu->denom;
            atu_state->timestamp = temp_atu->timestamp;
            atu_state->valid = 1;
            
            // Clear the temp data
            temp_atu->valid = 0;
            return 0;
        }
    }
    
    // Handle outgoing ACK packets - add ATU option for receiver
    if (skops->op == BPF_SOCK_OPS_WRITE_HDR_OPT_CB) {
        // Check if this is an ACK packet and we have valid ATU data
        if (atu_state->valid) {
            add_atu_option_to_ack(skops, atu_state);
        }
        return 0;
    }
    
    // For established connections, try to get ATU from XDP
    if (skops->op == BPF_SOCK_OPS_DATA_SEGS_IN_CB) {
        struct atu_state *temp_atu = bpf_map_lookup_elem(&temp_atu_map, &key);
        if (temp_atu && temp_atu->valid) {
            atu_state->numer = temp_atu->numer;
            atu_state->denom = temp_atu->denom;
            atu_state->timestamp = temp_atu->timestamp;
            atu_state->valid = 1;
            
            // Clear the temp data
            temp_atu->valid = 0;
            return 0;
        }
    }
    
    // Fallback: set default ATU values if no data found
    if (!atu_state->valid) {
        atu_state->numer = 8000;  // Default 80% utilization
        atu_state->denom = 10000;
        atu_state->timestamp = bpf_ktime_get_ns();
        atu_state->valid = 1;
    }
    
    return 0;
}

// Per-CPU array to temporarily store ATU data from XDP
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct atu_state);
} temp_atu_map SEC(".maps");

// Parse TCP options in XDP context
static int parse_tcp_options_xdp(struct tcphdr *tcp, void *data_end,
                                 struct atu_state *atu_state)
{
    void *tcp_opts = (void *)tcp + sizeof(struct tcphdr);
    void *opts_end = (void *)tcp + (tcp->doff * 4);
    
    if (opts_end > data_end)
        return 0;
    
    return parse_tcp_atu_option(tcp_opts, opts_end, atu_state);
}

// XDP program for packet-level processing
SEC("xdp")
int extract_atu_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct atu_state temp_atu = {0};
    __u32 key = 0;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // Method 1: Parse TCP options for ATU (from ACK packets)
    if (parse_tcp_options_xdp(tcp, data_end, &temp_atu)) {
        // Store in per-CPU map for sockops to retrieve
        bpf_map_update_elem(&temp_atu_map, &key, &temp_atu, BPF_ANY);
        return XDP_PASS;
    }
    
    // Method 2: Parse C2L2 max_atu header after TCP (from data packets)
    // Check if this is a data packet (not just ACK)
    if (tcp->ack && !tcp->psh && !tcp->syn && !tcp->fin) {
        // This is likely an ACK-only packet, skip custom header parsing
        return XDP_PASS;
    }
    
    // Calculate payload start after TCP header
    void *payload_start = (void *)tcp + (tcp->doff * 4);
    
    // Check if we have enough space for max_atu header (8 bytes)
    if (payload_start + sizeof(struct max_atu_h) > data_end)
        return XDP_PASS;
    
    // Check payload length to see if it matches C2L2's 2-byte payload pattern
    __u16 ip_total_len = bpf_ntohs(ip->tot_len);
    __u16 ip_hdr_len = ip->ihl * 4;
    __u16 tcp_hdr_len = tcp->doff * 4;
    __u16 payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
    
    // C2L2 uses 2-byte payload for max_atu, but we need 8 bytes for the header
    // Check if payload is exactly 8 bytes (our max_atu header size)
    if (payload_len != 8)
        return XDP_PASS;
    
    struct max_atu_h *atu = (struct max_atu_h *)payload_start;
    
    // Extract ATU from C2L2 max_atu header
    temp_atu.numer = bpf_ntohl(atu->numer);
    temp_atu.denom = bpf_ntohl(atu->denom);
    temp_atu.timestamp = bpf_ktime_get_ns();
    temp_atu.valid = 1;
    
    // Store in per-CPU map for sockops to retrieve
    bpf_map_update_elem(&temp_atu_map, &key, &temp_atu, BPF_ANY);
    
    return XDP_PASS;
}

// License declaration (required for eBPF programs)
char _license[] SEC("license") = "GPL";

// Module information
char _version[] SEC("version") = "1.0.0";
char _author[] SEC("author") = "ATU Extractor";
char _description[] SEC("description") = "eBPF program for extracting ATU headers from TCP packets and options";

// Map pinning for userspace access
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} atu_control_map SEC(".maps");