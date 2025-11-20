

#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# NOTE: The userspace ATU daemon is NOT required anymore. Code remains for reference, but do not run ccll_atu_daemon.

# Args: optional --iface <dev> to attach RX eBPF on a real interface.
IFACE=""
if [[ ${1:-} == "--iface" && $# -ge 2 ]]; then
  IFACE="$2"
fi

mkdir -p /sys/kernel/debug
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
echo 1 >/sys/kernel/debug/tracing/tracing_on

mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc /sys/fs/bpf/atu_rx

# Load kernel congestion control module and set it active
make all
if ! lsmod | awk '{print $1}' | grep -qx ccll; then
  insmod ccll.ko nf_atu_enabled=1 weight_ctl_enabled=1 default_weight=100000
fi
sysctl -w net.ipv4.tcp_congestion_control=ccll || true

if [[ -n "$IFACE" ]]; then
  # Attach receiver-side eBPF to a real interface for ACK option injection
  ethtool -K "$IFACE" rx off tx off tso off gso off gro off lro off || true

  bpftool prog loadall ebpf/atu_rx.o /sys/fs/bpf/atu_rx
  MID=$(bpftool map show | awk '/ name rx_flow_atu /{print $1; exit}' | tr -d :)
  bpftool map pin id "$MID" /sys/fs/bpf/tc/rx_flow_atu

  tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
  tc qdisc add dev "$IFACE" clsact
  tc filter add dev "$IFACE" ingress pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
  tc filter add dev "$IFACE" egress  pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt
  tc filter add dev "$IFACE" egress  pref 20 protocol ip flower ip_proto tcp action csum ip tcp

  tc -s filter show dev "$IFACE" ingress
  tc -s filter show dev "$IFACE" egress
else
  # Lab mode fallback: create recv namespace and veth pair for local testing
  ip netns add recv 2>/dev/null || true
  ip link del veth-s 2>/dev/null || true
  ip link add veth-s type veth peer name veth-r
  ip link set veth-r netns recv
  ip netns exec recv ip addr add 10.0.0.1/24 dev veth-r 2>/dev/null || true
  ip netns exec recv ip link set veth-r up
  ip addr add 10.0.0.2/24 dev veth-s 2>/dev/null || true
  ip link set veth-s up

  ethtool -K veth-r rx off tx off tso off gso off gro off lro off || true
  ethtool -K veth-s rx off tx off tso off gso off gro off lro off || true

  bpftool prog loadall ebpf/atu_rx.o /sys/fs/bpf/atu_rx
  MID=$(bpftool map show | awk '/ name rx_flow_atu /{print $1; exit}' | tr -d :)
  bpftool map pin id "$MID" /sys/fs/bpf/tc/rx_flow_atu

  tc qdisc del dev veth-r clsact 2>/dev/null || true
  tc qdisc add dev veth-r clsact
  tc filter add dev veth-r ingress pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
  tc filter add dev veth-r egress  pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt
  tc filter add dev veth-r egress  pref 20 protocol ip flower ip_proto tcp action csum ip tcp

  tc -s filter show dev veth-r ingress
  tc -s filter show dev veth-r egress
fi