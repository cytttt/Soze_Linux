

#!/usr/bin/env bash
# Host-wide setup for CCLL on a real machine (no netns)
# - Sender role: loads ccll.ko (Netfilter ACK parser) and sets CC
# - Receiver role: attaches eBPF (ingress cache ATU, egress add ACK option)
#
# Usage examples:
#   sudo bash linux/host-setup.bash --role sender \
#        --iface eth0 \
#        --module linux/ccll.ko
#
#   sudo bash linux/host-setup.bash --role receiver \
#        --iface eth0 \
#        --bpf ebpf/atu_rx.o
#
# If --iface is omitted, the script will auto-detect the default NIC used for outbound traffic.
# All parameters are optional with sensible defaults; run with -h to see options.

set -euo pipefail

ROLE=""
IFACE=""
MOD_PATH="linux/ccll.ko"
BPF_OBJ="ebpf/atu_rx.o"
NF_ATU_ENABLED=1

usage() {
  cat <<USAGE
Usage: sudo $0 --role <sender|receiver> [--iface IFACE] [--module PATH] [--bpf PATH] [--nf 0|1]

Options:
  --role    sender | receiver   (required)
  --iface   Network interface to configure. If omitted, auto-detect default egress NIC.
  --module  Path to ccll.ko (sender role). Default: ${MOD_PATH}
  --bpf     Path to atu_rx.o (receiver role). Default: ${BPF_OBJ}
  --nf      nf_atu_enabled for ccll.ko (0 or 1). Default: ${NF_ATU_ENABLED}
  -h|--help Show this help and exit.

Examples:
  sudo $0 --role sender --iface eth0 --module linux/ccll.ko
  sudo $0 --role receiver --iface enp3s0 --bpf ebpf/atu_rx.o
USAGE
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE=${2:-}; shift 2;;
    --iface) IFACE=${2:-}; shift 2;;
    --module) MOD_PATH=${2:-}; shift 2;;
    --bpf) BPF_OBJ=${2:-}; shift 2;;
    --nf) NF_ATU_ENABLED=${2:-1}; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[host-setup] Unknown option: $1" >&2; usage; exit 1;;
  esac
done

if [[ -z "$ROLE" ]]; then
  echo "[host-setup] --role is required (sender|receiver)" >&2
  usage
  exit 1
fi

# Auto-detect default egress NIC if --iface not provided
if [[ -z "$IFACE" ]]; then
  IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}') || true
  if [[ -z "${IFACE:-}" ]]; then
    echo "[host-setup] ERROR: Could not auto-detect default interface. Please pass --iface." >&2
    exit 1
  fi
  echo "[host-setup] Auto-detected interface: ${IFACE}"
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[host-setup] ERROR: Missing command '$1'" >&2; exit 1; }
}

turn_offloads() {
  local dev="$1"
  echo "[host-setup] Disabling offloads on ${dev} (testing mode)"
  ethtool -K "$dev" rx off tx off tso off gso off gro off lro off || true
}

mount_bpffs() {
  if ! mountpoint -q /sys/fs/bpf; then
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf
  fi
}

setup_sender() {
  require_cmd ethtool
  require_cmd sysctl
  # Optional but helpful for diagnostics
  command -v modprobe >/dev/null 2>&1 || true

  # Reload module cleanly
  if lsmod | awk '{print $1}' | grep -qx ccll; then
    rmmod ccll || true
  fi
  if [[ ! -f "$MOD_PATH" ]]; then
    echo "[host-setup] ERROR: module not found: $MOD_PATH" >&2
    exit 1
  fi
  echo "[host-setup] Inserting module: $MOD_PATH (nf_atu_enabled=${NF_ATU_ENABLED})"
  # insmod "$MOD_PATH" nf_atu_enabled=${NF_ATU_ENABLED} 
  insmod "$MOD_PATH" nf_atu_enabled=${NF_ATU_ENABLED} \
    weight_ctl_enabled=${WEIGHT_CTL_ENABLED:-1} \
    default_weight=${DEFAULT_WEIGHT:-100000}

  # Set congestion control to ccll
  echo "[host-setup] Switching tcp_congestion_control to 'ccll'"
  if sysctl -n net.ipv4.tcp_available_congestion_control | tr ' ' '\n' | grep -qx ccll; then
    sysctl -w net.ipv4.tcp_congestion_control=ccll >/dev/null
  else
    if ! sysctl -w net.ipv4.tcp_congestion_control=ccll >/dev/null; then
      echo "[host-setup] WARNING: 'ccll' not listed in tcp_available_congestion_control" >&2
      dmesg | grep -i ccll | tail -n 50 || true
    fi
  fi

  turn_offloads "$IFACE"
  echo "[host-setup] Sender ready on ${IFACE}. Active CC: $(sysctl -n net.ipv4.tcp_congestion_control)"
}

setup_receiver() {
  require_cmd ethtool
  require_cmd tc
  require_cmd bpftool

  if [[ ! -f "$BPF_OBJ" ]]; then
    echo "[host-setup] ERROR: BPF object not found: $BPF_OBJ" >&2
    exit 1
  fi

  mount_bpffs
  mkdir -p /sys/fs/bpf/atu_rx /sys/fs/bpf/tc

  echo "[host-setup] Loading BPF: $BPF_OBJ -> /sys/fs/bpf/atu_rx"
  bpftool prog loadall "$BPF_OBJ" /sys/fs/bpf/atu_rx

  # Verify program pins before tc attach
  local INGRESS_PROG=/sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
  local EGRESS_PROG=/sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt
  [[ -e "$INGRESS_PROG" ]] || { echo "[host-setup] ERROR: missing $INGRESS_PROG" >&2; exit 1; }
  [[ -e "$EGRESS_PROG" ]] || { echo "[host-setup] ERROR: missing $EGRESS_PROG" >&2; exit 1; }

  turn_offloads "$IFACE"

  echo "[host-setup] Attaching tc filters on ${IFACE}"
  tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
  tc qdisc add dev "$IFACE" clsact
  tc filter add dev "$IFACE" ingress pref 10 bpf da pinned "$INGRESS_PROG"
  tc filter add dev "$IFACE" egress  pref 10 bpf da pinned "$EGRESS_PROG"
  # Ensure checksums are correct after egress modifications
  tc filter add dev "$IFACE" egress  pref 20 protocol ip flower ip_proto tcp action csum ip tcp
  tc -s filter show dev "$IFACE" ingress || true
  tc -s filter show dev "$IFACE" egress  || true

  echo "[host-setup] Receiver ready on ${IFACE}"
}

case "$ROLE" in
  sender)   setup_sender ;;
  receiver) setup_receiver ;;
  *) echo "[host-setup] ERROR: Unknown role '$ROLE' (use sender|receiver)" >&2; exit 1;;
 esac