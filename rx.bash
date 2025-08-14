#!/bin/bash
umount /sys/fs/bpf 2>/dev/null || true
mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc /sys/fs/bpf/atu_rx 

bpftool prog loadall ebpf/atu_rx.o /sys/fs/bpf/atu_rx

MID=$(bpftool map show | awk '/ name rx_flow_atu /{print $1; exit}' | tr -d :)
bpftool map pin id "$MID" /sys/fs/bpf/tc/rx_flow_atu

# check: ls -l /sys/fs/bpf/tc/rx_flow_atu
# check: ls -l /sys/fs/bpf/atu_rx
# check bpftool prog show | grep -E 'rx_ingress_cach|rx_egress_add_a'

ethtool -K veth-r tso off gso off gro off lro off || true
tc qdisc del dev veth-r clsact 2>/dev/null || true
tc qdisc add dev veth-r clsact 
tc filter add dev veth-r ingress pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
tc filter add dev veth-r egress  pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt
tc -s filter show dev veth-r ingress
tc -s filter show dev veth-r egress
