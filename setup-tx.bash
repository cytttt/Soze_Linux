#!/bin/bash
ip netns exec send bash

ethtool -K veth-s tso off gso off gro off lro off

tc qdisc add dev veth-s clsact

tc filter add dev veth-s ingress pref 10 bpf da obj ebpf/atu_tx.o sec tc/tx_ingress_parse_ack_opt

mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc
MID=$(bpftool map show | grep -m1 " ack_atu_by_flow " | cut -d: -f1)
bpftool map pin id "$MID" /sys/fs/bpf/tc/ack_atu_by_flow
exit