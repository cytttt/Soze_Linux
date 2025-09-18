#!/bin/bash
set -euo pipefail

# Reload ccll module cleanly
if lsmod | awk '{print $1}' | grep -qx ccll; then
  rmmod ccll || true
fi

# Insert module (Netfilter ACK parser enabled by default via module param)
insmod ccll.ko nf_atu_enabled=1

# Switch system TCP CC to ccll if available
if sysctl -n net.ipv4.tcp_available_congestion_control | tr ' ' '\n' | grep -qx ccll; then
  sysctl -w net.ipv4.tcp_congestion_control=ccll
else
  # Try to set anyway and print a helpful warning if it fails
  if ! sysctl -w net.ipv4.tcp_congestion_control=ccll; then
    echo "[setup-ccll] WARNING: 'ccll' not listed in tcp_available_congestion_control."
    echo "[setup-ccll] dmesg (grep ccll) follows to help diagnose registration issues:"
    dmesg | grep -i ccll | tail -n 50 || true
  fi
fi

# Show a concise status summary
echo "[setup-ccll] Active CC: $(sysctl -n net.ipv4.tcp_congestion_control)"

dmesg | tail -n 20 | sed -n '/ccll/p'
