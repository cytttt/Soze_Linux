#!/bin/bash
ip netns del send 2>/dev/null
ip netns del recv 2>/dev/null
umount /sys/fs/bpf 2>/dev/null || true
rm -rf /sys/fs/bpf/tc
rm -rf /sys/fs/bpf/atu_tx
rm -rf /sys/fs/bpf/atu_rx

sysctl -w net.ipv4.tcp_congestion_control=cubic
rmmod ccll
rm -rf /dev/ccll_ctl
