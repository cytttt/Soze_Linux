#!/bin/bash
ip netns exec send sh -lc '
  ethtool -K veth-s tso off gso off gro off lro off || true
  tc qdisc del dev veth-s clsact 2>/dev/null || true
  tc qdisc add dev veth-s clsact
  tc filter add dev veth-s ingress pref 10 bpf da obj ebpf/atu_tx.o sec classifier/tx_ingress_parse_ack_opt
  tc -s -d filter show dev veth-s ingress
'

PID_TX=$(ip netns exec send tc -s filter show dev veth-s ingress | sed -n 's/.* id \([0-9]\+\) .*/\1/p')
MID_LIST=$(bpftool prog show id $PID_TX | sed -n 's/.*map_ids \([0-9,]\+\).*/\1/p')
MID_TX=$(echo "$MID_LIST" | tr ',' '\n' | while read id; do bpftool map show id "$id" | grep -q " name ack_atu_by_flow " && echo "$id" && break; done)
bpftool map pin id "$MID_TX" /sys/fs/bpf/tc/ack_atu_by_flow
ls -l /sys/fs/bpf/tc/ack_atu_by_flow