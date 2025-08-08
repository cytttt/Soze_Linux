// SPDX-License-Identifier: GPL-2.0 OR MIT
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Your custom ATU header structure
struct max_atu_h {
    __u32 numer;
    __u32 denom;
};

// Flow identification
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Map to store ATU info per flow
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct max_atu_h);
    __uint(pinned, LIBBPF_PIN_BY_NAME);
} atu_flow_map SEC(".maps");

SEC("tc")
int extract_atu_header(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    // Look for your ATU header after TCP header
    // Adjust this based on where your header is located
    void *atu_location = (void *)tcp + (tcp->doff * 4);
    struct max_atu_h *atu = atu_location;
    
    if ((void *)(atu + 1) > data_end)
        return TC_ACT_OK;
    
    // Create flow key
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest
    };
    
    // Extract and store ATU info
    struct max_atu_h atu_info = {
        .numer = bpf_ntohl(atu->numer),
        .denom = bpf_ntohl(atu->denom)
    };
    
    bpf_map_update_elem(&atu_flow_map, &key, &atu_info, BPF_ANY);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";