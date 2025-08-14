#!/bin/bash
# recv namespace
ip netns exec recv bash

# turn off offloads
ethtool -K veth-r tso off gso off gro off lro off

# clsact
tc qdisc add dev veth-r clsact

# RX ingress / egress
tc filter add dev veth-r ingress pref 10 bpf da obj ebpf/atu_rx.o sec tc/rx_ingress_cache_atu
tc filter add dev veth-r egress  pref 10 bpf da obj ebpf/atu_rx.o sec tc/rx_egress_add_ack_opt

# bpffs 並 pin rx_flow_atu
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc
MID=$(bpftool map show | grep -m1 " rx_flow_atu " | cut -d: -f1)
bpftool map pin id "$MID" /sys/fs/bpf/tc/rx_flow_atu
exit