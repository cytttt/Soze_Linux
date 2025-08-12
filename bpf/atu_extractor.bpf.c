// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * ATU (Arrival Traffic Utilization)  Extractor
 * eBPF program for extracting ATU headers from TCP packets
 * Compatible with C2L2 P4 program
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


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


// C2L2 max_atu header structure (direct header parsing only)
struct max_atu_h {
    __u16 id;       // identifier 0xBEEF
    __u16 len;      // header length 12
    __u32 numer;
    __u32 denom;
};

SEC("sockops")
int extract_atu_sockops(struct bpf_sock_ops *skops)
{
    struct atu_state *atu_state;
    struct bpf_sock *sk;
    __u32 key = 0;
    
    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_DATA_SEGS_IN_CB)
        return 0;
    
    sk = skops->sk;
    if (!sk)
        return 0;
    
    // Get or create ATU state for this socket
    atu_state = atu_get_state(sk);
    if (!atu_state)
        return 0;
    
    // For data segments, try to get ATU from XDP temp map
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
    
    // Method 1: Parse max_atu header from forward path data packets
    // Method 2: Parse max_atu header from ACK packets (receiver copied from forward path)
    
    // Check if this is an ACK packet that might contain copied ATU header
    if (tcp->ack && !tcp->psh && !tcp->syn && !tcp->fin) {
        // This is an ACK packet - check if it contains copied ATU header in payload
        void *ack_payload_start = (void *)tcp + (tcp->doff * 4);
        
        // Check if we have enough space for max_atu header (12 bytes)
        if (ack_payload_start + sizeof(struct max_atu_h) > data_end)
            return XDP_PASS;
        
        // Check ACK payload length
        __u16 ip_total_len = bpf_ntohs(ip->tot_len);
        __u16 ip_hdr_len = ip->ihl * 4;
        __u16 tcp_hdr_len = tcp->doff * 4;
        __u16 ack_payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
        
        // Check if ACK contains copied ATU header (12 bytes)
        if (ack_payload_len == 12) {
            struct max_atu_h *ack_atu = (struct max_atu_h *)ack_payload_start;
            
            // Verify magic number 0xBEEF
            if (bpf_ntohs(ack_atu->id) == 0xBEEF && bpf_ntohs(ack_atu->len) == 12) {
                // Extract ATU from ACK packet (receiver copied from forward path)
                temp_atu.numer = bpf_ntohl(ack_atu->numer);
                temp_atu.denom = bpf_ntohl(ack_atu->denom);
                temp_atu.timestamp = bpf_ktime_get_ns();
                temp_atu.valid = 1;
                
                // Store in per-CPU map for sockops to retrieve
                bpf_map_update_elem(&temp_atu_map, &key, &temp_atu, BPF_ANY);
                return XDP_PASS;
            }
        }
        
        // No ATU header in ACK, continue processing
        return XDP_PASS;
    }
    
    // Calculate payload start after TCP header
    void *payload_start = (void *)tcp + (tcp->doff * 4);
    
    // Check if we have enough space for max_atu header (12 bytes)
    if (payload_start + sizeof(struct max_atu_h) > data_end)
        return XDP_PASS;
    
    // Check payload length to see if it matches C2L2's max_atu header
    __u16 ip_total_len = bpf_ntohs(ip->tot_len);
    __u16 ip_hdr_len = ip->ihl * 4;
    __u16 tcp_hdr_len = tcp->doff * 4;
    __u16 payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
    
    // C2L2 uses 12-byte max_atu header
    if (payload_len != 12)
        return XDP_PASS;
    
    struct max_atu_h *atu = (struct max_atu_h *)payload_start;
    
    // Verify magic number 0xBEEF
    if (bpf_ntohs(atu->id) != 0xBEEF)
        return XDP_PASS;
    
    // Verify header length
    if (bpf_ntohs(atu->len) != 12)
        return XDP_PASS;
    
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
char _description[] SEC("description") = "eBPF program for extracting ATU headers from forward path and ACK packets";

// Map pinning for userspace access
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} atu_control_map SEC(".maps");