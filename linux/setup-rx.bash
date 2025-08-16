#!/bin/bash
ip netns exec recv sh -lc '
  ethtool -K veth-r tso off gso off gro off lro off || true
  tc qdisc del dev veth-r clsact 2>/dev/null || true
  tc qdisc add dev veth-r clsact
  tc filter add dev veth-r ingress pref 10 bpf da obj ebpf/atu_rx.o sec classifier/rx_ingress_cache_atu
  tc filter add dev veth-r egress  pref 10 bpf da obj ebpf/atu_rx.o sec classifier/rx_egress_add_ack_opt
  tc -s -d filter show dev veth-r ingress
  tc -s -d filter show dev veth-r egress
'

PID_RX=$(ip netns exec recv tc -s filter show dev veth-r ingress | sed -n 's/.* id \([0-9]\+\) .*/\1/p')
MID_LIST=$(bpftool prog show id $PID_RX | sed -n 's/.*map_ids \([0-9,]\+\).*/\1/p')
MID_RX=$(echo "$MID_LIST" | tr ',' '\n' | while read id; do bpftool map show id "$id" | grep -q " name rx_flow_atu " && echo "$id" && break; done)
bpftool map pin id "$MID_RX" /sys/fs/bpf/tc/rx_flow_atu
ls -l /sys/fs/bpf/tc/rx_flow_atu