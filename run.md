# run.md

This guide shows how to build and run the ATU signal path end‑to‑end on a single host using Linux network namespaces.

Flow goal:
```
sender  --DATA-->  receiver  --ACK+ATU(Kind=253,Len=10,numer,denom,NOP,NOP)-->  sender
```

The eBPF side is split into two objects:
- **RX object (`ebpf/atu_rx.o`)**: receiver ingress cache + receiver egress insert
- **TX object (`ebpf/atu_tx.o`)**: sender ingress parse + per‑socket/per‑flow mirrors

> Why two objects? Some kernels reject `BPF_MAP_TYPE_SK_STORAGE` at tc attach time. RX doesn’t need `sk_storage`, TX does. Splitting avoids `EINVAL` on the receiver.

---

## 0) Prerequisites
- Linux 4.5+ (tc `clsact`) — 5.x recommended
- Tools: `clang`, `bpftool`, `iproute2 (tc)`, `gcc`, `libbpf-dev`
- Root privileges (`sudo`)

Install on Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool make gcc libbpf-dev iproute2 net-tools ethtool
```

---

## 1) Build everything
From repo root:
```bash
make all          # builds: ccll.ko, ebpf/atu_rx.o, ebpf/atu_tx.o, ./ccll_atu_daemon
```
Or only parts:
```bash
make kmod         # kernel module (ccll.ko)
make ebpf-rx      # eBPF RX object
make ebpf-tx      # eBPF TX object
make daemon       # userspace daemon
```
ARM64 hosts (e.g., Apple M1/Parallels) are auto-detected; you can override with `ARCH=arm64`.

---

## 2) Create namespaces & veth pair (single‑host testbed)
```bash
sudo -s
ip netns add recv
ip netns add send
ip link add veth-r type veth peer name veth-s
ip link set veth-r netns recv
ip link set veth-s netns send
ip netns exec recv ip addr add 10.0.0.1/24 dev veth-r
ip netns exec send ip addr add 10.0.0.2/24 dev veth-s
ip netns exec recv ip link set veth-r up
ip netns exec send ip link set veth-s up
```

> **Absolute path gotcha:** when calling `tc` inside a namespace, use an **absolute path** to your `.o`, or `cd` into the repo in that namespace. Example:
```bash
OBJ_RX="$(realpath ebpf/atu_rx.o)"
OBJ_TX="$(realpath ebpf/atu_tx.o)"
```

---

## 3) Receiver: what to do
The receiver does two things:

**Receiver tasks:**
- Parse DATA payload for the ATU TLV `[type=0xA1][len=8][u32 numer][u32 denom]` on ingress and cache it per‑flow.
- On **pure ACK** (no payload) egress, insert TCP option `Kind=253, Len=10, numer, denom, NOP, NOP`.

1) **Ingress**: parse DATA payload for the ATU TLV `[type=0xA1][len=8][u32 numer][u32 denom]` and cache it per‑flow.
2) **Egress (ACK path)**: on **pure ACK** (no payload), insert TCP option `Kind=253, Len=10, numer, denom, NOP, NOP`.

### Steps (in `recv` namespace)
To open an interactive shell inside the `recv` namespace:
```bash
sudo ip netns exec recv bash
```
You can keep this shell open for running all `recv`-side commands.  
**Tip:** Use two terminals — one attached to `recv` and another to `send` — so you can run both sides concurrently without switching.
```bash
# Attach clsact and RX programs
ip netns exec recv tc qdisc add dev veth-r clsact 2>/dev/null || true
ip netns exec recv tc filter add dev veth-r ingress bpf da obj "$OBJ_RX" sec tc/rx_ingress_cache_atu
ip netns exec recv tc filter add dev veth-r egress  bpf da obj "$OBJ_RX" sec tc/rx_egress_add_ack_opt

# (optional) disable offloads to make sniffing easier
ip netns exec recv ethtool -K veth-r tso off gso off gro off lro off

# Check status
ip netns exec recv tc filter show dev veth-r ingress
ip netns exec recv tc filter show dev veth-r egress
```

---

## 4) Sender: what to do
The sender does two things:

**Sender tasks:**
- Parse `Kind=253, Len=10` and extract `numer/denom` on ingress (ACK path).
- Mirror values to `ack_atu_by_flow` (for daemon) and (optionally) `sk_storage` (for kernel CC direct access).

1) **Ingress (ACK path)**: parse `Kind=253, Len=10` and extract `numer/denom`.
2) Mirror values to `ack_atu_by_flow` (for daemon) and (optionally) `sk_storage` (for kernel CC direct access).

### Steps (in `send` namespace)
```bash
# Attach clsact and TX program
ip netns exec send tc qdisc add dev veth-s clsact 2>/dev/null || true
ip netns exec send tc filter add dev veth-s ingress bpf da obj "$OBJ_TX" sec tc/tx_ingress_parse_ack_opt

# (optional) offload toggles
ip netns exec send ethtool -K veth-s tso off gso off gro off lro off

# Pin maps (ensure bpffs exists in this namespace)
ip netns exec send mkdir -p /sys/fs/bpf
ip netns exec send mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
ip netns exec send bpftool prog load "$OBJ_TX" /sys/fs/bpf/atu_prog.o \
  map name ack_atu_by_flow pinned /sys/fs/bpf/ack_atu_by_flow \
  map name rx_flow_atu     pinned /sys/fs/bpf/rx_flow_atu \
  map name sk_atu_store    pinned /sys/fs/bpf/sk_atu_store

# Inspect maps
ip netns exec send bpftool map show | grep -E 'ack_atu_by_flow|rx_flow_atu|sk_atu_store'
```

> If you prefer to pin in the host namespace, use `make pin` instead and run the daemon in the host. Otherwise, run both pinning and daemon inside `send` netns.

---

## 5) Kernel module & daemon
From repo root (host namespace):
```bash
make kmod
sudo make insmod
```
Run daemon (choose one setup):
- **Host‑pinned maps + host daemon**
  ```bash
  sudo make pin
  ./ccll_atu_daemon --map /sys/fs/bpf/ack_atu_by_flow --dev /dev/ccll_ctl
  ```
- **Send‑ns pinned maps + send‑ns daemon**
  ```bash
  ip netns exec send ./ccll_atu_daemon --map /sys/fs/bpf/ack_atu_by_flow --dev /dev/ccll_ctl
  ```

---

## 6) Generate traffic
Receiver as server:
```bash
ip netns exec recv nc -l -p 5001 >/dev/null
```
Sender as client (send data ⇒ receiver returns pure ACKs):
```bash
ip netns exec send bash -lc 'head -c 5M </dev/zero | nc 10.0.0.1 5001'
```

> If your switch isn’t yet injecting the forward‑path TLV, the receiver ingress can’t cache real ATU. For a loop test, you can temporarily enable a test mode in eBPF to fill a default numer/denom when TLV is absent (ask and we’ll add `ATU_TEST_MODE`).
> To enable this, add `#define ATU_TEST_MODE` at the very top of `ebpf/atu_tcp_option_skeleton.c` **before any includes**, then rebuild (`make ebpf-rx` or `make all`). This will cause the eBPF program to insert a fixed test numer/denom when no TLV is detected, allowing end‑to‑end verification without requiring forward‑path injection.

---

## 7) Verify
**On sender (ingress of ACK):**
```bash
ip netns exec send tcpdump -i veth-s -vvv -s 0 -n 'tcp[tcpflags] & tcp-ack != 0'
# Look for: TCP Options: NOP, NOP, Unknown(253), length 10, <8B numer/denom>

ip netns exec send bpftool map dump pinned /sys/fs/bpf/ack_atu_by_flow | head
# Expect entries with numer/denom for the flow
```
**Kernel module receiving updates:**
```bash
dmesg | grep ccll -n
```
(You can add extra `pr_debug()` in `ccll.c` to confirm ATU usage inside CC.)

---

## 8) Makefile shortcuts (host namespace)
```bash
# One‑shot attach both sides on physical IFs
sudo make attach RX_IF=<receiver-if> TX_IF=<sender-if>

# Split operations (veth/netns typical)
sudo make attach-recv RECV_IF=veth-r
sudo make attach-send SEND_IF=veth-s

# Status
make status RX_IF=<receiver-if> TX_IF=<sender-if>
make status-recv RECV_IF=veth-r
make status-send SEND_IF=veth-s

# Detach
sudo make detach RX_IF=<receiver-if> TX_IF=<sender-if>
sudo make detach-recv RECV_IF=veth-r
sudo make detach-send SEND_IF=veth-s
```

---

## 9) Troubleshooting
- `tc: Error opening object ... No such file` → Use **absolute path** to `.o` in netns, or `cd` into repo inside the netns shell.
- `libbpf: ... sk_atu_store ... Invalid argument(-22)` at receiver → you accidentally attached **TX object** on receiver, or built a unified `.o`. Use `atu_rx.o` on receiver; `atu_tx.o` on sender.
- `Permission denied` with long verifier log → ensure egress program is the **offset‑based** version (no direct pointer deref). Rebuild `make ebpf-rx`.
- Checksums look odd in `tcpdump` → disable offloads (`ethtool -K <if> tso gso gro lro off`). NIC may fix them later.
- `/dev/ccll_ctl` not found → load kernel module (`sudo make insmod`).

---

## 10) Cleanup
```bash
# Detach (split)
sudo make detach-recv RECV_IF=veth-r
sudo make detach-send SEND_IF=veth-s

# Remove namespaces
ip netns del recv || true
ip netns del send || true

# Unload module (optional)
sudo make rmmod
```
