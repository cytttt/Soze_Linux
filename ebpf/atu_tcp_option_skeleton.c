// SPDX-License-Identifier: GPL-2.0 OR MIT
// -----------------------------------------------------------------------------
// TCP ATU Option Skeleton (Receiver + Sender) — eBPF/TC CO-RE style
// Goal:
//  - Forward path: switch writes/updates max ATU on data packets (as payload TLV
//    or any shim you already use)
//  - Receiver:
//      * Ingress: read max ATU from incoming DATA (forward path) and cache per-flow
//      * Egress: when emitting pure ACKs, insert a TCP option (Kind=253) carrying
//                8 bytes of ATU into the ACK
//  - Sender:
//      * Ingress: parse ACK's TCP option and store ATU into sk_storage for the socket
//
// Notes:
//  - This is a *skeleton*: boundary checks, checksum updates, and error handling are
//    indicated and must be filled as needed for your exact header layout.
//  - We assume the switch-added ATU appears as a small TLV at the beginning of TCP
//    payload on DATA packets (receiver ingress can parse and cache it). Adjust the
//    parser if your shim differs.
//  - For ACK TCP option we use experimental Kind=253. Length=10 (1 kind + 1 len + 8 data).
//    You can change KIND via macro below. Do not exceed available TCP option space (~40B).
// -----------------------------------------------------------------------------

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>

// ----- Configurable constants -----
#define ATU_TCP_OPT_KIND   253        // Experimental/Private Use
#define ATU_TCP_OPT_LEN    10         // Kind(1)+Len(1)+ATU(8)
#define ATU_DATA_BYTES     8          // 8-byte ATU payload (u32 numer + u32 denom)
#define ATU_PAD2_BYTES     2          // two NOPs (Kind=1) for 32-bit alignment
#define ATU_WIRE_BYTES     (ATU_TCP_OPT_LEN + ATU_PAD2_BYTES) // total bytes we actually insert

// Assume your switch injects a DATA payload TLV like: [type=0xA1][len=8][u32 numer][u32 denom]
#define SW_TLV_TYPE_ATU    0xA1

// Helpers: feature gates
char _license[] SEC("license") = "Dual MIT/GPL";

// ----- Common structs -----
struct flow4_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto; // IPPROTO_TCP
};

static __always_inline void fill_flow4_key(struct flow4_key *k,
                                           const struct iphdr *iph,
                                           const struct tcphdr *tcph) {
    k->saddr = iph->saddr;
    k->daddr = iph->daddr;
    k->sport = tcph->source;
    k->dport = tcph->dest;
    k->proto = IPPROTO_TCP;
}

// New struct for ATU storing numer and denom separately
struct atu_val {
    __u32 numer;
    __u32 denom;
};

// Cache of latest max ATU seen on receiver side (per flow)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow4_key);
    __type(value, struct atu_val); // numer and denom (host order when stored)
    __uint(max_entries, 16384);
} rx_flow_atu SEC(".maps");

// Sender side: per-socket storage of latest ATU from ACK
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __type(key, struct sock *);
    __type(value, struct atu_val); // numer and denom
    __uint(max_entries, 0);
} sk_atu_store SEC(".maps");

// Sender side: per-flow mirror for userspace daemon to read
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow4_key);
    __type(value, struct atu_val); // numer/denom (host order)
    __uint(max_entries, 65536);
} ack_atu_by_flow SEC(".maps");

// Utility: parse L2/L3/L4 (IPv4 only in this skeleton)
static __always_inline int parse_eth(void **data, void **data_end, __u16 *eth_proto) {
    struct ethhdr *eth = (struct ethhdr *)(*data);
    if ((void *)(eth + 1) > *data_end) return -1;
    *eth_proto = bpf_ntohs(eth->h_proto);
    *data = eth + 1;
    return 0;
}

static __always_inline int parse_ipv4(void **data, void **data_end, struct iphdr **iph) {
    struct iphdr *ip = (struct iphdr *)(*data);
    if ((void *)(ip + 1) > *data_end) return -1;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return -1;
    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip)) return -1;
    if ((void *)ip + ihl_bytes > *data_end) return -1;
    *iph = ip;
    *data = (void *)ip + ihl_bytes;
    return 0;
}

static __always_inline int parse_tcp(void **data, void **data_end, struct tcphdr **tcph) {
    struct tcphdr *tcp = (struct tcphdr *)(*data);
    if ((void *)(tcp + 1) > *data_end) return -1;
    __u32 doff_bytes = tcp->doff * 4;
    if (doff_bytes < sizeof(*tcp)) return -1;
    if ((void *)tcp + doff_bytes > *data_end) return -1;
    *tcph = tcp;
    *data = (void *)tcp + doff_bytes; // points to payload start
    return 0;
}

static __always_inline __u32 ipv4_total_len(const struct iphdr *ip) {
    return bpf_ntohs(ip->tot_len);
}

// Determine TCP payload length (IPv4)
static __always_inline int tcp_payload_len(void *nh, void *data_end,
                                           const struct iphdr *ip,
                                           const struct tcphdr *tcp) {
    __u32 tot = ipv4_total_len(ip);
    __u32 l3 = ip->ihl * 4;
    __u32 l4 = tcp->doff * 4;
    if (tot < l3 + l4) return 0;
    return tot - l3 - l4;
}

// -----------------------------------------------------------------------------
// Receiver ingress (TC): read ATU from DATA payload TLV and cache per-flow
// -----------------------------------------------------------------------------
SEC("tc/rx_ingress_cache_atu")
int rx_ingress_cache_atu(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u16 ethp;
    if (parse_eth(&data, &data_end, &ethp) < 0) return BPF_OK;
    if (ethp != ETH_P_IP) return BPF_OK;

    struct iphdr *ip;
    if (parse_ipv4(&data, &data_end, &ip) < 0) return BPF_OK;

    struct tcphdr *tcp;
    void *payload;
    payload = data;
    if (parse_tcp(&payload, &data_end, &tcp) < 0) return BPF_OK;

    int plen = tcp_payload_len((void *)ip, data_end, ip, tcp);
    if (plen <= 0) return BPF_OK; // no payload

    // Expect TLV at payload start: [type][len][4B numer][4B denom]
    if (payload + 2 + ATU_DATA_BYTES > data_end) return BPF_OK;
    __u8 tlv_type = *(__u8 *)payload;
    __u8 tlv_len  = *(__u8 *)(payload + 1);
    if (tlv_type != SW_TLV_TYPE_ATU || tlv_len != 8) return BPF_OK;
    __u32 numer_net, denom_net;
    __builtin_memcpy(&numer_net, payload + 2, sizeof(__u32));
    __builtin_memcpy(&denom_net, payload + 6, sizeof(__u32));
    __u32 numer_host = bpf_ntohl(numer_net);
    __u32 denom_host = bpf_ntohl(denom_net);

    struct flow4_key k = {};
    fill_flow4_key(&k, ip, tcp);
    struct atu_val atu_host = {
        .numer = numer_host,
        .denom = denom_host,
    };
    bpf_map_update_elem(&rx_flow_atu, &k, &atu_host, BPF_ANY);

    return BPF_OK;
}

// -----------------------------------------------------------------------------
// Receiver egress (TC): if pure ACK (no payload), inject TCP option with ATU
// -----------------------------------------------------------------------------
static __always_inline int is_pure_ack(const struct tcphdr *tcp, int plen) {
    /* return 1 if pure ACK, else 0 */
    if (!tcp->ack)
        return 0;
    if (tcp->syn || tcp->fin || tcp->rst || tcp->psh)
        return 0;
    return plen == 0;
}

SEC("tc/rx_egress_add_ack_opt")
int rx_egress_add_ack_opt(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u16 ethp;
    if (parse_eth(&data, &data_end, &ethp) < 0) return BPF_OK;
    if (ethp != ETH_P_IP) return BPF_OK;

    struct iphdr *ip;
    if (parse_ipv4(&data, &data_end, &ip) < 0) return BPF_OK;

    struct tcphdr *tcp;
    void *payload;
    payload = data;
    if (parse_tcp(&payload, &data_end, &tcp) < 0) return BPF_OK;

    int plen = tcp_payload_len((void *)ip, data_end, ip, tcp);
    if (!is_pure_ack(tcp, plen)) return BPF_OK;

    // Lookup cached ATU for this flow (note: reverse direction key!)
    struct flow4_key k = {};
    // For ACK going out from receiver, invert saddr/daddr and ports to match rx_ingress key
    {
        // fabricate a pseudo key matching forward DATA direction
        k.saddr = ip->daddr;   // original sender
        k.daddr = ip->saddr;   // original receiver
        k.sport = tcp->dest;   // original sender port
        k.dport = tcp->source; // original receiver port
        k.proto = IPPROTO_TCP;
    }

    struct atu_val *atu_ptr = bpf_map_lookup_elem(&rx_flow_atu, &k);
    if (!atu_ptr) return BPF_OK; // no ATU cached → skip adding option

    // Ensure we have TCP option space to add ATU option
    __u32 opt_room = 60 - (tcp->doff * 4); // TCP header max 60 bytes
    if (opt_room < ATU_WIRE_BYTES) return BPF_OK; // not enough space

    // Grow headroom for TCP options
    if (bpf_skb_adjust_room(skb, ATU_WIRE_BYTES, BPF_ADJ_ROOM_NET, 0))
        return BPF_OK; // adjust failed

    // After adjust_room, pointers are invalid → reload
    data     = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // Re-parse to new positions
    if (parse_eth(&data, &data_end, &ethp) < 0) return BPF_OK;
    if (ethp != ETH_P_IP) return BPF_OK;
    if (parse_ipv4(&data, &data_end, &ip) < 0) return BPF_OK;
    if (parse_tcp(&data, &data_end, &tcp) < 0) return BPF_OK;

    __u32 ip_off  = (unsigned long)ip  - (unsigned long)skb->data;
    __u32 tcp_off = (unsigned long)tcp - (unsigned long)skb->data;

    // Compose the option with 2 trailing NOPs for 4-byte alignment
    __u8 opt_buf[ATU_WIRE_BYTES] = {0};
    // ATU option
    opt_buf[0] = ATU_TCP_OPT_KIND;
    opt_buf[1] = ATU_TCP_OPT_LEN; // 10 bytes follow Kind/Len (numer+denom)
    __u32 numer_net = bpf_htonl(atu_ptr->numer);
    __u32 denom_net = bpf_htonl(atu_ptr->denom);
    __builtin_memcpy(&opt_buf[2], &numer_net, sizeof(__u32));
    __builtin_memcpy(&opt_buf[6], &denom_net, sizeof(__u32));
    // Padding: two NOPs (Kind=1) appended to make total 12 bytes (multiple of 4)
    opt_buf[10] = 1; // NOP
    opt_buf[11] = 1; // NOP

    // Store bytes at start of TCP options area (immediately after struct tcphdr)
    if (bpf_skb_store_bytes(skb, tcp_off + sizeof(struct tcphdr),
                            opt_buf, ATU_WIRE_BYTES, 0)) {
        return BPF_OK;
    }

    // Update TCP data offset (doff) to include new option bytes
    // TCP doff in 32-bit words
    __u8 new_doff_words = (tcp->doff * 4 + ATU_WIRE_BYTES) / 4;

    // Write back doff (first 4 bits of th->doff) — need to rewrite the two bytes at offset 12..13
    struct tcphdr tcp_new = *tcp;
    tcp_new.doff = new_doff_words;
    if (bpf_skb_store_bytes(skb, tcp_off, &tcp_new, sizeof(tcp_new), 0))
        return BPF_OK;

    // Update IP total length
    __u16 old_tot = bpf_ntohs(ip->tot_len);
    __u16 new_tot = old_tot + ATU_WIRE_BYTES;

    __u16 new_tot_be = bpf_htons(new_tot);
    bpf_skb_store_bytes(skb, ip_off + offsetof(struct iphdr, tot_len),
                        &new_tot_be, sizeof(new_tot_be), 0);

    // Fix IPv4 header checksum for tot_len change
    bpf_l3_csum_replace(skb,
                        ip_off + offsetof(struct iphdr, check),
                        (__be32)ip->tot_len, (__be32)new_tot_be,
                        sizeof(__u16));

    // Mark TCP checksum dirty so stack/NIC will recompute
    bpf_l4_csum_replace(skb,
                        tcp_off + offsetof(struct tcphdr, check),
                        0, 0, BPF_F_MARK_MANGLED_0);

    return BPF_OK;
}

// -----------------------------------------------------------------------------
// Sender ingress (TC): parse ACK TCP option and save ATU into sk_storage
// -----------------------------------------------------------------------------
SEC("tc/tx_ingress_parse_ack_opt")
int tx_ingress_parse_ack_opt(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u16 ethp;
    if (parse_eth(&data, &data_end, &ethp) < 0) return BPF_OK;
    if (ethp != ETH_P_IP) return BPF_OK;

    struct iphdr *ip;
    if (parse_ipv4(&data, &data_end, &ip) < 0) return BPF_OK;

    struct tcphdr *tcp;
    void *opt_ptr;
    opt_ptr = data;
    if (parse_tcp(&opt_ptr, &data_end, &tcp) < 0) return BPF_OK;

    int plen = tcp_payload_len((void *)ip, data_end, ip, tcp);
    if (!tcp->ack) return BPF_OK; // interested in ACKs only

    // Iterate TCP options area to find our Kind
    __u8 *opt = (void *)tcp + sizeof(*tcp);
    __u8 *opt_end = (void *)tcp + (tcp->doff * 4);
    while (opt + 1 < opt_end) {
        __u8 kind = *opt;
        if (kind == 0) break;        // End of options
        if (kind == 1) {             // NOP
            opt += 1;
            continue;
        }
        if (opt + 2 > opt_end) break;
        __u8 len = *(opt + 1);
        if (len < 2 || opt + len > opt_end) break;
        if (kind == ATU_TCP_OPT_KIND && len == ATU_TCP_OPT_LEN) {
            if (len != 2 + ATU_DATA_BYTES) break;
            __u32 numer_net, denom_net;
            __builtin_memcpy(&numer_net, opt + 2, sizeof(__u32));
            __builtin_memcpy(&denom_net, opt + 6, sizeof(__u32));
            __u32 numer_host = bpf_ntohl(numer_net);
            __u32 denom_host = bpf_ntohl(denom_net);

            struct sock *sk = (struct sock *)(long)skb->sk;
            if (sk) {
                struct atu_val *slot = bpf_sk_storage_get(&sk_atu_store, sk, 0,
                                                 BPF_SK_STORAGE_GET_F_CREATE);
                if (slot) {
                    slot->numer = numer_host;
                    slot->denom = denom_host;
                }
            }
            // Mirror to per-flow map for userspace daemon
            struct flow4_key fk = {
                .saddr = ip->saddr,
                .daddr = ip->daddr,
                .sport = tcp->source,
                .dport = tcp->dest,
                .proto = IPPROTO_TCP,
            };
            struct atu_val vv = {.numer = numer_host, .denom = denom_host};
            bpf_map_update_elem(&ack_atu_by_flow, &fk, &vv, BPF_ANY);
            break;
        }
        opt += len;
    }

    return BPF_OK;
}
