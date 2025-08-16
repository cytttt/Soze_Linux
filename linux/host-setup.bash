#!/bin/bash
set -euo pipefail

# =============================================================
# Host setup (NO namespaces): attach RX/TX eBPF on a real NIC
# Usage: sudo ./linux/host-setup.bash <IFACE>
# Example: sudo ./linux/host-setup.bash eno1
# Notes:
#   - Run this once per machine (per boot) on the physical interface you use.
#   - Expects eBPF objects already built in ./ebpf:
#       ebpf/atu_rx.o  (sections: tc/rx_ingress_cache_atu, tc/rx_egress_add_ack_opt)
#       ebpf/atu_tx.o  (section:  tc/tx_ingress_parse_ack_opt)
#   - Maps are pinned under /sys/fs/bpf/tc to make RX & TX share them.
# =============================================================

IFACE="${1:-}"  # required physical NIC, e.g., eno1/eth0
if [[ -z "${IFACE}" ]]; then
  echo "Usage: sudo $0 <IFACE>  (e.g., eth0)" >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root" >&2
  exit 1
fi

# --- Sanity: NIC exists ---
if ! ip link show dev "$IFACE" >/dev/null 2>&1; then
  echo "Interface '$IFACE' not found" >&2
  exit 1
fi

# --- DebugFS for bpf_printk() ---
mkdir -p /sys/kernel/debug
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
echo 1 > /sys/kernel/debug/tracing/tracing_on || true

# --- bpffs (global) ---
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc /sys/fs/bpf/atu_rx /sys/fs/bpf/atu_tx

# --- Disable troublesome offloads on the real NIC ---
echo "[net] disable offloads on $IFACE"
ethtool -K "$IFACE" tso off gso off gro off lro off rxvlan off txvlan off 2>/dev/null || true

# --- Clean + add clsact qdisc ---
echo "[tc] reset clsact on $IFACE"
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
tc qdisc add dev "$IFACE" clsact

# =============================================================
# Load RX object and pin its programs & map globally
# =============================================================
if [[ ! -f ebpf/atu_rx.o ]]; then
  echo "Missing ebpf/atu_rx.o. Build it first (e.g., make ebpf-rx)." >&2
  exit 1
fi

echo "[bpf] load RX object -> /sys/fs/bpf/atu_rx"
# This creates pinned program files under /sys/fs/bpf/atu_rx/*
# Names will be classifier_<section_name_without_prefix>
# (libbpf auto-detects tc prog type from "tc/" section)
rm -f /sys/fs/bpf/atu_rx/* 2>/dev/null || true
bpftool prog loadall ebpf/atu_rx.o /sys/fs/bpf/atu_rx

# Pin rx_flow_atu map globally so both RX ingress & egress share it
echo "[bpf] pin rx_flow_atu -> /sys/fs/bpf/tc/rx_flow_atu"
MID_RX=$(bpftool map show | awk '/ name rx_flow_atu /{print $1; exit}' | tr -d :) || true
if [[ -n "${MID_RX:-}" ]]; then
  bpftool map pin id "$MID_RX" /sys/fs/bpf/tc/rx_flow_atu 2>/dev/null || true
else
  echo "WARNING: rx_flow_atu map id not found. Ensure atu_rx.o contains it." >&2
fi

# Attach RX ingress/egress using the pinned programs
# Program pin names come from bpftool; they typically look like:
#   /sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
#   /sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt
RX_ING_PIN=/sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
RX_EGR_PIN=/sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt

if [[ ! -e "$RX_ING_PIN" || ! -e "$RX_EGR_PIN" ]]; then
  echo "ERROR: pinned RX programs not found under /sys/fs/bpf/atu_rx (got: $(ls -1 /sys/fs/bpf/atu_rx))" >&2
  exit 1
fi

echo "[tc] attach RX ingress/egress on $IFACE"
# Remove any old handles on pref 10 to avoid duplicates
(tc filter del dev "$IFACE" ingress pref 10 2>/dev/null || true)
(tc filter del dev "$IFACE" egress  pref 10 2>/dev/null || true)

tc filter add dev "$IFACE" ingress pref 10 bpf da pinned "$RX_ING_PIN"
tc filter add dev "$IFACE" egress  pref 10 bpf da pinned "$RX_EGR_PIN"

# =============================================================
# Load & attach TX ACK-option parser on the same NIC (ingress)
# =============================================================
if [[ ! -f ebpf/atu_tx.o ]]; then
  echo "Missing ebpf/atu_tx.o. Build it first (e.g., make ebpf-tx)." >&2
  exit 1
fi

echo "[tc] attach TX ACK parser on $IFACE ingress (pref 20)"
# Remove old pref 20 if exists
(tc filter del dev "$IFACE" ingress pref 20 2>/dev/null || true)
# Attach directly from section name (do not pin this one; it's fine attached by tc)
tc filter add dev "$IFACE" ingress pref 20 bpf da obj ebpf/atu_tx.o sec tc/tx_ingress_parse_ack_opt

# Pin ack_atu_by_flow (map from TX program) so userspace can read it too
PID_TX=$(tc -s filter show dev "$IFACE" ingress | awk '/\[tc\/tx_ingress_parse_ack_opt\]/{for(i=1;i<=NF;i++){if($i=="id"){print $(i+1); exit}}}') || true
if [[ -n "${PID_TX:-}" ]]; then
  MID_LIST=$(bpftool prog show id "$PID_TX" | sed -n 's/.*map_ids \([0-9,]\+\).*/\1/p') || true
  if [[ -n "${MID_LIST:-}" ]]; then
    MID_TX=$(echo "$MID_LIST" | tr ',' '\n' | while read -r id; do bpftool map show id "$id" | grep -q " name ack_atu_by_flow " && echo "$id" && break; done)
    if [[ -n "${MID_TX:-}" ]]; then
      echo "[bpf] pin ack_atu_by_flow -> /sys/fs/bpf/tc/ack_atu_by_flow"
      bpftool map pin id "$MID_TX" /sys/fs/bpf/tc/ack_atu_by_flow 2>/dev/null || true
    else
      echo "WARNING: ack_atu_by_flow map id not found in TX prog $PID_TX" >&2
    fi
  fi
else
  echo "WARNING: could not resolve TX prog id from tc output; map may not be pinned" >&2
fi

# --- Final status ---
echo
echo "==== tc filters on $IFACE ===="
tc -s filter show dev "$IFACE" ingress || true
 tc -s filter show dev "$IFACE" egress  || true

echo
echo "==== Pinned maps under /sys/fs/bpf/tc ===="
ls -l /sys/fs/bpf/tc || true

cat <<EOF

[Done]
- RX and TX eBPF attached on interface: $IFACE
- rx_flow_atu pinned at:   /sys/fs/bpf/tc/rx_flow_atu
- (if found) ack_atu_by_flow pinned at: /sys/fs/bpf/tc/ack_atu_by_flow

Quick checks (another terminal):
  sudo tcpdump -i $IFACE -vvv -s0 -n 'tcp[13] & 16 != 0' -c 5
  sudo bpftool map dump pinned /sys/fs/bpf/tc/rx_flow_atu || true
  sudo bpftool map dump pinned /sys/fs/bpf/tc/ack_atu_by_flow || true

To view bpf_printk():
  sudo cat /sys/kernel/debug/tracing/trace_pipe
EOF
