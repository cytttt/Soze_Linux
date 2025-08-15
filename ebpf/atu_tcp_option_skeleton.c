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
//      * Ingress: parse ACK's TCP option and store ATU (and mirror per-flow)
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
#include <stdbool.h>

// ----- Configurable constants -----
/* ------------------------------------------------------------------------- */
#define ATU_TCP_OPT_KIND   253        // Experimental/Private Use
#define ATU_TCP_OPT_LEN    10         // Kind(1)+Len(1)+ATU(8)
#define ATU_DATA_BYTES     8          // 8-byte ATU payload (u32 numer + u32 denom)
#define ATU_PAD2_BYTES     2          // two NOPs (Kind=1) for 32-bit alignment
#define ATU_WIRE_BYTES     (ATU_TCP_OPT_LEN + ATU_PAD2_BYTES) // total bytes we actually insert

// Build feature switches (defaults tuned for RX build)
#ifndef ATU_TEST_MODE
#define ATU_TEST_MODE 0  /* 0=normal; 1=fill default numer/denom when TLV missing */
#endif

#ifndef BUILD_SEND
#define BUILD_SEND 0   // 0=build receiver-only by default; set to 1 when building sender
#endif

#ifndef USE_SK_STORAGE
#define USE_SK_STORAGE 0  // default off so RX build won't try to create sk_storage
#endif

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

// ATU value (numer/denom)
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

#if BUILD_SEND
// Sender side: per-flow mirror for userspace daemon to read
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow4_key);
    __type(value, struct atu_val); // numer/denom (host order)
    __uint(max_entries, 65536);
} ack_atu_by_flow SEC(".maps");
#endif

#if BUILD_SEND && USE_SK_STORAGE
// Sender side: per-socket storage of latest ATU from ACK (optional)
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __type(key, struct sock *);
    __type(value, struct atu_val); // numer and denom
    __uint(max_entries, 0);
} sk_atu_store SEC(".maps");
#endif

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

#if !BUILD_SEND
// -----------------------------------------------------------------------------
// Receiver ingress (TC): read ATU from DATA payload TLV and cache per-flow
// -----------------------------------------------------------------------------
SEC("classifier/rx_ingress_cache_atu")
int rx_ingress_cache_atu(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u16 ethp;
    if (parse_eth(&data, &data_end, &ethp) < 0) return BPF_OK;
    if (ethp != ETH_P_IP) return BPF_OK;

    struct iphdr *ip;
    if (parse_ipv4(&data, &data_end, &ip) < 0) return BPF_OK;

    struct tcphdr *tcp;
    void *payload = data; /* data now points to TCP header end */
    if (parse_tcp(&payload, &data_end, &tcp) < 0) return BPF_OK;

    int plen = tcp_payload_len((void *)ip, data_end, ip, tcp);

    /* Prepare flow key (sender->receiver for DATA). */
    struct flow4_key k = {};
    fill_flow4_key(&k, ip, tcp);

    /* Try to parse TLV at payload start: [type][len][u32 numer][u32 denom] */
    int tlv_ok = 0;
    __u32 numer_host = 0, denom_host = 0;

    if (plen > 0) {
        if (payload + 2 + ATU_DATA_BYTES <= data_end) {
            __u8 tlv_type = *(__u8 *)payload;
            __u8 tlv_len  = *(__u8 *)(payload + 1);
            if (tlv_type == SW_TLV_TYPE_ATU && tlv_len == 8) {
                __u32 numer_net = 0, denom_net = 0;
                __builtin_memcpy(&numer_net,  payload + 2, sizeof(__u32));
                __builtin_memcpy(&denom_net,  payload + 6, sizeof(__u32));
                numer_host = bpf_ntohl(numer_net);
                denom_host = bpf_ntohl(denom_net);
                tlv_ok = 1;
            }
        }
    }

#if ATU_TEST_MODE
    /* If TLV not present, synthesize a default for testing so egress can insert. */
    if (!tlv_ok) {
        numer_host = 9000;
        denom_host = 10000;
        tlv_ok = 1;
    }
#endif

    if (tlv_ok) {
        struct atu_val atu_host = {
            .numer = numer_host,
            .denom = denom_host,
        };

        bpf_printk("RX cache ATU %u/%u\n", numer_host, denom_host);
        bpf_printk("flow s=%x d=%x\n", k.saddr, k.daddr);
        bpf_printk("ports %u->%u\n", bpf_ntohs(k.sport), bpf_ntohs(k.dport));

        bpf_printk("key sa=%x da=%x\n", k.saddr, k.daddr);
        bpf_printk("key sp=%x dp=%x\n", k.sport, k.dport);
        bpf_printk("key proto=%x\n", k.proto);
        bpf_map_update_elem(&rx_flow_atu, &k, &atu_host, BPF_ANY);
    }

    return BPF_OK;
}
#endif

#if !BUILD_SEND
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

SEC("classifier/rx_egress_add_ack_opt")
int rx_egress_add_ack_opt(struct __sk_buff *skb)
{
    __u16 eth_proto = 0;
    __u32 ip_off = 14;  
    __u8  vihl = 0, proto = 0;
    __u16 tot_be = 0;
    __u32 ihl_bytes = 0, tcp_off = 0;
    __u8  doff_byte = 0, flags = 0;
    __u32 doff_bytes = 0;
    __u32 opt_room = 0;
    __u32 payload_len = 0;

    if (bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(eth_proto)) < 0)
        return BPF_OK;
    eth_proto = bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP)
        return BPF_OK;

    /* IPv4 version / IHL */
    if (bpf_skb_load_bytes(skb, ip_off + 0, &vihl, 1) < 0)
        return BPF_OK;
    if ((vihl & 0xF0) != 0x40)
        return BPF_OK;
    ihl_bytes = (vihl & 0x0F) * 4;
    if (ihl_bytes < 20)
        return BPF_OK;

    /* Protocol = TCP */
    if (bpf_skb_load_bytes(skb, ip_off + 9, &proto, 1) < 0)
        return BPF_OK;
    if (proto != IPPROTO_TCP)
        return BPF_OK;

    /* IPv4 total length */
    if (bpf_skb_load_bytes(skb, ip_off + 2, &tot_be, 2) < 0)
        return BPF_OK;
    __u16 tot = bpf_ntohs(tot_be);


    tcp_off = ip_off + ihl_bytes;
    if (bpf_skb_load_bytes(skb, tcp_off + 12, &doff_byte, 1) < 0)
        return BPF_OK;
    if (bpf_skb_load_bytes(skb, tcp_off + 13, &flags, 1) < 0)
        return BPF_OK;
    doff_bytes = ((__u32)(doff_byte >> 4) & 0xF) * 4;
    if (doff_bytes < 20)
        return BPF_OK;

    if (!(flags & 0x10))           /* ACK bit */
        return BPF_OK;
    if (flags & (0x01 | 0x02 | 0x04 | 0x08))
        return BPF_OK;

    if (tot < ihl_bytes + doff_bytes)
        return BPF_OK;
    payload_len = tot - ihl_bytes - doff_bytes;
    if (payload_len != 0)
        return BPF_OK;

    bpf_printk("EGRESS pure ACK, doff=%u, room=%u\n", doff_bytes, 60 - doff_bytes);

    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    (void)bpf_skb_load_bytes(skb, ip_off + 12, &saddr, 4);
    (void)bpf_skb_load_bytes(skb, ip_off + 16, &daddr, 4);
    (void)bpf_skb_load_bytes(skb, tcp_off + 0,  &sport, 2);
    (void)bpf_skb_load_bytes(skb, tcp_off + 2,  &dport, 2);

    struct flow4_key k = {};

    k.saddr = daddr;
    k.daddr = saddr;
    k.sport = dport;
    k.dport = sport;
    k.proto = IPPROTO_TCP;

    bpf_printk("ekey sa=%x da=%x\n", k.saddr, k.daddr);
    bpf_printk("ekey sp=%x dp=%x\n", k.sport, k.dport);
    bpf_printk("ekey proto=%x\n", k.proto);
    struct atu_val *atu_ptr = bpf_map_lookup_elem(&rx_flow_atu, &k);
    struct atu_val atu_fallback;
    bool use_fallback = false;
    if (!atu_ptr) {
#if ATU_TEST_MODE
        atu_fallback.numer = 9000;
        atu_fallback.denom = 10000;
        atu_ptr = &atu_fallback;
        use_fallback = true;
        bpf_printk("EGRESS fallback ATU %u/%u\n", atu_ptr->numer, atu_ptr->denom);
        bpf_printk("flow s=%x d=%x\n", k.saddr, k.daddr);
        bpf_printk("ports %u->%u\n", bpf_ntohs(k.sport), bpf_ntohs(k.dport));
#else
        return BPF_OK;
#endif
    } else {
        bpf_printk("EGRESS found ATU %u/%u\n", atu_ptr->numer, atu_ptr->denom);
        bpf_printk("flow s=%x d=%x\n", k.saddr, k.daddr);
        bpf_printk("ports %u->%u\n", bpf_ntohs(k.sport), bpf_ntohs(k.dport));
    }

    opt_room = 60 - doff_bytes;
    if (opt_room < ATU_WIRE_BYTES)
        return BPF_OK;


    /* ==== DEBUG BEFORE ADJUST (T0 = ip_off + ihl) ==== */
    {
        __u8 b12 = 0, b13 = 0;
        __u32 T0 = tcp_off; /* ip_off + ihl_bytes */
        if (T0 + 14 <= (__u32)skb->len) {
            (void)bpf_skb_load_bytes(skb, T0 + 12, &b12, 1); /* doff/NS */
            (void)bpf_skb_load_bytes(skb, T0 + 13, &b13, 1); /* flags    */
        }
        bpf_printk("BEF T0=%u ihl=%u\n", T0, ihl_bytes);
        bpf_printk("BEF doff=%u len=%u\n", doff_bytes, (__u32)skb->len);
        bpf_printk("BEF T0+12=%x %x\n", (__u32)b12, (__u32)b13);
    }    
    /* Ensure the old TCP header is linear before adjustment. */
    {
        __u32 need = tcp_off + doff_bytes; /* end of current TCP header */
        if (need > (__u32)skb->len) {
            bpf_printk("EGRESS need(%u) > skb->len(%u) before adjust\n", need, skb->len);
            return BPF_OK;
        }
        if (bpf_skb_pull_data(skb, need)) {
            bpf_printk("EGRESS pull_data fail before adjust @%u\n", need);
            return BPF_OK;
        }
    }
    int adj_ret = bpf_skb_adjust_room(
        skb, ATU_WIRE_BYTES,
        BPF_ADJ_ROOM_NET,
        BPF_F_ADJ_ROOM_FIXED_GSO);
        // BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET);
    if (adj_ret) {
        bpf_printk("EGRESS adjust_room failed: %d\n", adj_ret);
        return BPF_OK;
    }
    bpf_printk("EGRESS adjust_room ok (+%u bytes)\n", (unsigned)ATU_WIRE_BYTES);
    /* ==== DEBUG AFTER ADJUST: probe both T0 and T1 (=T0+12) ==== */
    {
        __u32 T0 = tcp_off;
        __u32 T1 = tcp_off + ATU_WIRE_BYTES;
        __u8 t0b12 = 0, t0b13 = 0, t1b12 = 0, t1b13 = 0;

        if (T0 + 14 <= (__u32)skb->len) {
            (void)bpf_skb_load_bytes(skb, T0 + 12, &t0b12, 1);
            (void)bpf_skb_load_bytes(skb, T0 + 13, &t0b13, 1);
        }
        if (T1 + 14 <= (__u32)skb->len) {
            (void)bpf_skb_load_bytes(skb, T1 + 12, &t1b12, 1);
            (void)bpf_skb_load_bytes(skb, T1 + 13, &t1b13, 1);
        }

        bpf_printk("AFT T0=%u T1=%u\n", T0, T1);
        bpf_printk("AFT T0+12=%x %x\n", (__u32)t0b12, (__u32)t0b13);
        bpf_printk("AFT T1+12=%x %x\n", (__u32)t1b12, (__u32)t1b13);
    }
    /* After adjust_room(+12, NET):
     *  - T0 = original TCP start (ip_off + ihl)
     *  - T1 = shifted TCP start = T0 + ATU_WIRE_BYTES
     * We will move the TCP header bytes from T1 back to T0, so the 12-byte gap
     * ends up at the end of the TCP header (right before payload).
     */
    __u32 tcp_t0 = ip_off + ihl_bytes;            /* original L4 start */
    __u32 tcp_t1 = tcp_t0 + ATU_WIRE_BYTES;       /* shifted L4 start  */
    bpf_printk("AFT SET T0=%u T1=%u\n", tcp_t0, tcp_t1);

    /* Ensure linear/writable up to end of (old header + inserted option). */
    {
        /* Ensure we can read the whole old TCP header at T1 (= T0 + 12). */
        __u32 need = tcp_t1 + doff_bytes; /* end of old header after shift */
        if (need > (__u32)skb->len) {
            bpf_printk("EGRESS need(%u) > skb->len(%u) after adjust\n", need, skb->len);
            return BPF_OK;
        }
        if (bpf_skb_pull_data(skb, need)) {
            bpf_printk("EGRESS pull_data fail after adjust @%u\n", need);
            return BPF_OK;
        }
    }

    /* Move the TCP header bytes back to T0 so the 12-byte gap ends up at the
     * end of the TCP header (between header and payload). Use constant-size
     * ops to satisfy the verifier.
     */
    {
        if (doff_bytes > 60) return BPF_OK; /* defensive: TCP header max 60B */
        /* Copy header from T1 -> T0 one byte at a time (verifier-friendly). */
        for (int i = 0; i < 60; i++) {
            if ((__u32)i >= doff_bytes)
                break;
            __u8 b = 0;
            if (bpf_skb_load_bytes(skb, tcp_t1 + i, &b, 1) < 0) {
                bpf_printk("EGRESS load @T1+%d failed\n", i);
                return BPF_OK;
            }
            if (bpf_skb_store_bytes(skb, tcp_t0 + i, &b, 1, 0)) {
                bpf_printk("EGRESS store @T0+%d failed\n", i);
                return BPF_OK;
            }
        }
        /* From here on, use tcp_off = T0 as the TCP start. */
        tcp_off = tcp_t0;
    }

    /* ----------------------- L3: IPv4 total length + checksum ----------------------- */
    __u16 new_tot = tot + ATU_WIRE_BYTES;
    __be16 new_tot_be = bpf_htons(new_tot);
    bpf_printk("EGRESS iplen %u -> %u\n", tot, new_tot);
    if (bpf_skb_store_bytes(skb, ip_off + offsetof(struct iphdr, tot_len),
                            &new_tot_be, sizeof(new_tot_be), 0)) {
        bpf_printk("EGRESS store tot_len failed\n");
        return BPF_OK;
    }
    /* incremental replace of tot_len in IP header checksum */
    bpf_l3_csum_replace(skb,
                        ip_off + offsetof(struct iphdr, check),
                        (__be32)tot_be, (__be32)new_tot_be,
                        sizeof(__u16));

    /* ----------------------- L4: TCP header/option build ----------------------- */
    /* Compose the ATU option we are inserting */
    __u8 opt_buf[ATU_WIRE_BYTES] = {0};
    __u32 numer_be = bpf_htonl(atu_ptr->numer);
    __u32 denom_be = bpf_htonl(atu_ptr->denom);

    opt_buf[0]  = ATU_TCP_OPT_KIND;
    opt_buf[1]  = ATU_TCP_OPT_LEN;
    __builtin_memcpy(&opt_buf[2], &numer_be, sizeof(numer_be));
    __builtin_memcpy(&opt_buf[6], &denom_be, sizeof(denom_be));
    opt_buf[10] = 1; /* NOP */
    opt_buf[11] = 1; /* NOP */

    /* Compute doff_new from the originally-read doff_bytes; do not re-read doff
     * in between adjust_room and this update to avoid offset confusion. */
    /* (1) Update TCP data offset **before** writing option bytes. Some kernels
     *     reject writing beyond the old header length if doff hasn't grown yet.
     */
    __u8 new_doff_words = (doff_bytes + ATU_WIRE_BYTES) / 4;
    __u8 new_doff_byte  = (new_doff_words << 4) | (doff_byte & 0x0F);
    if (bpf_skb_store_bytes(skb, tcp_off + 12, &new_doff_byte, 1, 0)) {
        bpf_printk("EGRESS store doff failed\n");
        return BPF_OK;
    }
    /* Debug/sanity: read back the updated doff byte and verify (validation only) */
    {
        __u8 rb_doff = 0;
        if (bpf_skb_load_bytes(skb, tcp_off + 12, &rb_doff, 1) == 0) {
            __u32 rb_doff_bytes = ((__u32)(rb_doff >> 4) & 0xF) * 4;
            bpf_printk("EGRESS doff rb=%u bytes (expected %u)\n",
                       rb_doff_bytes, (unsigned)(doff_bytes + ATU_WIRE_BYTES));
            /* If the nybble is unexpectedly small (< 20), bail out to avoid bad packets */
            if (rb_doff_bytes < 20) {
                bpf_printk("EGRESS doff too small after update, abort\n");
                return BPF_OK;
            }
        }
    }
    /* Skip incremental checksum updates - will do full recompute at the end */

    /* (2) Now write the option bytes at the end of the old TCP header. */
    {
        __u32 expected_new_doff = doff_bytes + ATU_WIRE_BYTES;
        __u32 need_final = tcp_off + expected_new_doff; /* tcp_off is T0 */
        if (need_final > (__u32)skb->len) {
            bpf_printk("EGRESS need_final(%u) > skb->len(%u)\n", need_final, skb->len);
            return BPF_OK;
        }
        if (bpf_skb_pull_data(skb, need_final)) {
            bpf_printk("EGRESS pull_data fail at final @%u\n", need_final);
            return BPF_OK;
        }
    }
    /* Write option at end of the *old* TCP header; the gap from adjust_room
     * extends the header area. We grow doff below so receivers account for it. */
    if (bpf_skb_store_bytes(skb, tcp_off + doff_bytes,
                            opt_buf, ATU_WIRE_BYTES, 0)) {
        bpf_printk("EGRESS write opt failed\n");
        return BPF_OK;
    }

    /* Incremental TCP checksum fixes: pseudo-len, doff/flags word, and 12B option data */
    {
        /* Debug: read original TCP checksum before any incremental updates */
        __u16 csum_be0 = 0;
        (void)bpf_skb_load_bytes(skb, tcp_off + offsetof(struct tcphdr, check), &csum_be0, 2);
        bpf_printk("DBG csum0(be)=%x\n", (__u32)csum_be0);

        /* (a) Pseudo header TCP length changed (tot_len +12): apply as diff */
        __u16 old_tcp_len = (__u16)(tot - ihl_bytes);
        __u16 new_tcp_len = (__u16)(new_tot - ihl_bytes);
        __be16 old_tcp_len_be = bpf_htons(old_tcp_len);
        __be16 new_tcp_len_be = bpf_htons(new_tcp_len);
        bpf_printk("DBG tl_old=%x tl_new=%x\n", (__u32)old_tcp_len, (__u32)new_tcp_len);
        {
            __u32 add_len = bpf_csum_diff((__be32 *)(void *)&old_tcp_len_be, sizeof(old_tcp_len_be),
                                          (__be32 *)(void *)&new_tcp_len_be, sizeof(new_tcp_len_be), 0);
            int ra = bpf_l4_csum_replace(skb,
                                tcp_off + offsetof(struct tcphdr, check),
                                0, add_len,
                                BPF_F_MARK_MANGLED_0 | 0);
            bpf_printk("DBG ra=%d\n", ra);
        }

        /* (b) Data offset nibble changed in the 16-bit word at bytes 12..13 */
        __u16 old_word = ((__u16)doff_byte << 8) | (__u16)flags;       /* network order packed later */
        __u16 new_word = ((__u16)new_doff_byte << 8) | (__u16)flags;   /* flags unchanged */
        bpf_printk("DBG w12-13 old=%x new=%x\n", (__u32)old_word, (__u32)new_word);
        int rb = bpf_l4_csum_replace(skb,
                            tcp_off + offsetof(struct tcphdr, check),
                            bpf_htons(old_word), bpf_htons(new_word),
                            BPF_F_MARK_MANGLED_0 | 2);
        bpf_printk("DBG rb=%d\n", rb);

        /* (c) Add the 12B option payload contribution (Kind/Len/8B + NOP/NOP) */
        __u32 add = bpf_csum_diff(NULL, 0, (__be32 *)(void *)opt_buf, ATU_WIRE_BYTES, 0);
        bpf_printk("DBG opt_csum_add(lo16)=%x\n", (__u32)(add & 0xFFFF));
        int rc = bpf_l4_csum_replace(skb,
                            tcp_off + offsetof(struct tcphdr, check),
                            0, add,
                            BPF_F_MARK_MANGLED_0 | 0);
        bpf_printk("DBG rc=%d\n", rc);

        __u16 csum_be1 = 0;
        (void)bpf_skb_load_bytes(skb, tcp_off + offsetof(struct tcphdr, check), &csum_be1, 2);
        bpf_printk("DBG csum1(be)=%x\n", (__u32)csum_be1);
        /* Fallback: full recompute if checksum did not change */
        if (csum_be1 == csum_be0) {
            /* Fallback: full recompute over pseudo header + TCP header (no payload). */
            __u8 ph[12] = {0};
            if (bpf_skb_load_bytes(skb, ip_off + 12, &ph[0], 4) < 0) goto _no_full;
            if (bpf_skb_load_bytes(skb, ip_off + 16, &ph[4], 4) < 0) goto _no_full;
            ph[8]  = 0;
            ph[9]  = IPPROTO_TCP;
            __u16 tcp_len = (__u16)(new_tot - ihl_bytes);
            *(__be16 *)&ph[10] = bpf_htons(tcp_len);

            __u8 tcpbuf[60] = {0};
            __u32 doff_new = doff_bytes + ATU_WIRE_BYTES;
            if (doff_new > 60) doff_new = 60;
            /* Copy TCP header bytes one by one to satisfy verifier. */
            #pragma clang loop unroll(full)
            for (int i = 0; i < 60; i++) {
                if ((__u32)i >= doff_new) break;
                __u8 b = 0;
                if (bpf_skb_load_bytes(skb, tcp_off + i, &b, 1) < 0) goto _no_full;
                tcpbuf[i] = b;
            }
            /* Zero checksum field (offset 16..17) */
            tcpbuf[offsetof(struct tcphdr, check) + 0] = 0;
            tcpbuf[offsetof(struct tcphdr, check) + 1] = 0;

            __u32 sum = 0;
            sum = bpf_csum_diff(NULL, 0, (__be32 *)(void *)ph, sizeof(ph), 0);
            sum = bpf_csum_diff(NULL, 0, (__be32 *)(void *)tcpbuf, doff_new, sum);
            /* fold */
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            __u16 sum16 = (~sum) & 0xFFFF;
            __be16 sum_be = bpf_htons(sum16);
            if (bpf_skb_store_bytes(skb, tcp_off + offsetof(struct tcphdr, check), &sum_be, 2, 0) == 0) {
                bpf_printk("DBG full_recomp=%x\n", (__u32)sum_be);
            }
        }
_no_full: ;
        /* Log inserted ATU (net order) for sanity */
        __u32 dbg_numer = 0, dbg_denom = 0;
        __builtin_memcpy(&dbg_numer, &opt_buf[2], 4);
        __builtin_memcpy(&dbg_denom, &opt_buf[6], 4);
        bpf_printk("DBG opt ATU=%x/%x\n", dbg_numer, dbg_denom);
    }
    bpf_printk("EGRESS wrote option + inc csum fixed\n");
    /* Optional: After fixing TCP checksum (at the end of the function), log final IP total length and TCP doff */
    {
        __u8 final_doff_b = 0; __u16 final_tot_be2 = 0;
        if (bpf_skb_load_bytes(skb, tcp_off + 12, &final_doff_b, 1) == 0 &&
            bpf_skb_load_bytes(skb, ip_off + 2, &final_tot_be2, 2) == 0) {
            __u16 final_tot = bpf_ntohs(final_tot_be2);
            __u32 final_doff = ((__u32)(final_doff_b >> 4) & 0xF) * 4;
            bpf_printk("EGRESS final tot=%u, doff=%u\n", final_tot, final_doff);
        }
    }
    {
        __u16 csum_be2 = 0;
        (void)bpf_skb_load_bytes(skb, tcp_off + offsetof(struct tcphdr, check), &csum_be2, 2);
        bpf_printk("DBG csum2(be)=%x\n", (__u32)csum_be2);
    }
    return BPF_OK;
}
#endif

#if BUILD_SEND
// -----------------------------------------------------------------------------
// Sender ingress (TC): parse ACK TCP option (offset-based) and mirror ATU
// -----------------------------------------------------------------------------
SEC("classifier/tx_ingress_parse_ack_opt")
int tx_ingress_parse_ack_opt(struct __sk_buff *skb)
{
    /* Offset-based parsing only: verifier-friendly */
    __u16 eth_proto = 0;
    __u32 ip_off = 14;
    __u8  vihl = 0, proto = 0;
    __u32 ihl_bytes = 0, tcp_off = 0;
    __u8  doff_byte = 0, flags = 0;
    __u32 doff_bytes = 0;

    /* Ethernet */
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(eth_proto)) < 0)
        return BPF_OK;
    eth_proto = bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP)
        return BPF_OK;

    /* IPv4 base */
    if (bpf_skb_load_bytes(skb, ip_off + 0, &vihl, 1) < 0)
        return BPF_OK;
    if ((vihl & 0xF0) != 0x40)
        return BPF_OK;
    ihl_bytes = (vihl & 0x0F) * 4;
    if (ihl_bytes < 20)
        return BPF_OK;

    if (bpf_skb_load_bytes(skb, ip_off + 9, &proto, 1) < 0)
        return BPF_OK;
    if (proto != IPPROTO_TCP)
        return BPF_OK;

    /* TCP header start & size */
    tcp_off = ip_off + ihl_bytes;
    if (bpf_skb_load_bytes(skb, tcp_off + 12, &doff_byte, 1) < 0)
        return BPF_OK;
    if (bpf_skb_load_bytes(skb, tcp_off + 13, &flags, 1) < 0)
        return BPF_OK;
    doff_bytes = ((__u32)(doff_byte >> 4) & 0xF) * 4;
    if (doff_bytes < 20)
        return BPF_OK;

    /* Only ACK packets */
    if (!(flags & 0x10))
        return BPF_OK;

    /* Flow tuple for mirroring */
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    (void)bpf_skb_load_bytes(skb, ip_off + 12, &saddr, 4);
    (void)bpf_skb_load_bytes(skb, ip_off + 16, &daddr, 4);
    (void)bpf_skb_load_bytes(skb, tcp_off + 0,  &sport, 2);
    (void)bpf_skb_load_bytes(skb, tcp_off + 2,  &dport, 2);

    /* TCP options scan: [tcp_off + 20, tcp_off + doff_bytes) */
    __u32 tcp_hdr_start = tcp_off;
    __u32 off  = tcp_hdr_start + 20;
    __u32 end  = tcp_hdr_start + doff_bytes;

    #pragma clang loop unroll(full)
    for (int iter = 0; iter < 40; iter++) {
        /* need at least 1 byte to read kind */
        if (off + 1 > end)
            break;

        __u8 kind = 0;
        if (bpf_skb_load_bytes(skb, off, &kind, 1) < 0)
            break;

        if (kind == 0)  /* EOL */
            break;

        if (kind == 1) { /* NOP */
            off += 1;
            continue;
        }

        /* For variable-length options, we must read len and skip by len */
        if (off + 2 > end)
            break;

        __u8 len = 0;
        if (bpf_skb_load_bytes(skb, off + 1, &len, 1) < 0)
            break;

        /* basic sanity: len must be at least 2 and not exceed remaining header */
        if (len < 2)
            break;

        __u32 next = off + len;
        if (next > end)
            break;

        if (kind == ATU_TCP_OPT_KIND && len == ATU_TCP_OPT_LEN) {
            __u32 numer_net = 0, denom_net = 0;
            if (bpf_skb_load_bytes(skb, off + 2, &numer_net, 4) < 0)
                break;
            if (bpf_skb_load_bytes(skb, off + 6, &denom_net, 4) < 0)
                break;

            __u32 numer = bpf_ntohl(numer_net);
            __u32 denom = bpf_ntohl(denom_net);

#if defined(BUILD_SEND) && USE_SK_STORAGE
            struct sock *sk = (struct sock *)(long)skb->sk;
            if (sk) {
                struct atu_val *slot = bpf_sk_storage_get(&sk_atu_store, sk, 0,
                                                BPF_SK_STORAGE_GET_F_CREATE);
                if (slot) {
                    slot->numer = numer;
                    slot->denom = denom;
                }
            }
#endif
#if defined(BUILD_SEND)
            struct flow4_key fk = {};
            fk.saddr = saddr;
            fk.daddr = daddr;
            fk.sport = sport;
            fk.dport = dport;
            fk.proto = IPPROTO_TCP;

            struct atu_val vv = { .numer = numer, .denom = denom };
            bpf_map_update_elem(&ack_atu_by_flow, &fk, &vv, BPF_ANY);
#endif
            break;
        }

        /* not our option: skip to the next option by its length */
        off = next;
    }


    return BPF_OK;
}
#endif
