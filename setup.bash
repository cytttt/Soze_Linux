#!/bin/bash

# debug fs
mkdir -p /sys/kernel/debug
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
echo 1 | tee /sys/kernel/debug/tracing/tracing_on >/dev/null

# bpf
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc /sys/fs/bpf/atu_rx /sys/fs/bpf/atu_tx

ip netns add send
ip netns add recv
ip link add veth-s type veth peer name veth-r
ip link set veth-s netns send
ip link set veth-r netns recv

ip netns exec send ip addr add 10.0.0.2/24 dev veth-s
ip netns exec recv ip addr add 10.0.0.1/24 dev veth-r
ip netns exec send ip link set veth-s up
ip netns exec recv ip link set veth-r up