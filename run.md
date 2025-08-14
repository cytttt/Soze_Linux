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

## local test

```
make all ATU_TEST_MODE=1
bash clean.bash
bash setup.bash
```

### Receiver side

#### setup
```
sudo -s
ip netns exec recv bash

umount /sys/fs/bpf 2>/dev/null || true
mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/tc /sys/fs/bpf/atu_rx 

bpftool prog loadall ebpf/atu_rx.o /sys/fs/bpf/atu_rx

MID=$(bpftool map show | awk '/ name rx_flow_atu /{print $1; exit}' | tr -d :)
bpftool map pin id "$MID" /sys/fs/bpf/tc/rx_flow_atu

ethtool -K veth-r tso off gso off gro off lro off || true
tc qdisc del dev veth-r clsact 2>/dev/null || true
tc qdisc add dev veth-r clsact 
tc filter add dev veth-r ingress pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_ingress_cache_atu
tc filter add dev veth-r egress  pref 10 bpf da pinned /sys/fs/bpf/atu_rx/classifier_rx_egress_add_ack_opt
tc -s filter show dev veth-r ingress
tc -s filter show dev veth-r egress
```
#### test
```
nc -l -p 5000 >/dev/null

bpftool map dump pinned /sys/fs/bpf/tc/rx_flow_atu
```

### Sender side

#### setup
```
bash setup-tx.bash
```
#### test
```
ip netns exec send bash -lc 'dd if=/dev/zero bs=1k count=1 2>/dev/null | nc -q 1 10.0.0.1 5000'
```
