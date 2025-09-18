#!/bin/bash
# Sender-side setup (tx)
# With the kernel module parsing ACK via Netfilter, we no longer need
# a tc-BPF program on the sender. Keep offloads disabled and clean any
# legacy clsact state.

# ip netns exec send sh -lc '
#   ethtool -K veth-s rx off tx off tso off gso off gro off lro off || true
#   # Remove any legacy tc state from older setups
#   tc qdisc del dev veth-s clsact 2>/dev/null || true
# '
ethtool -K veth-s rx off tx off tso off gso off gro off lro off || true
tc qdisc del dev veth-s clsact 2>/dev/null || true
