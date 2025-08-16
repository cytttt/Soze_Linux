# run.md

This guide shows how to build and run the ATU signal path end‑to‑end on a single host using Linux network namespaces.


## Prerequisites
- Linux 4.5+ (tc `clsact`) — 5.x recommended
- Tools: `clang`, `bpftool`, `iproute2 (tc)`, `gcc`, `libbpf-dev`
- Root privileges (`sudo`)

Install on Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool make gcc libbpf-dev iproute2 net-tools ethtool
```

---

## Local test on ebpf


```
cd linux
make all ATU_TEST_MODE=1
bash clean.bash
bash setup.bash
```

### Receiver side

#### setup
```
# get into recv shell
sudo -s
ip netns exec recv bash

bash local-setup-rx.bash
```
#### test
```
nc -lk -p 5000

bpftool map dump pinned /sys/fs/bpf/tc/rx_flow_atu
```

### Sender side

#### setup
```
bash local-setup-tx.bash
```
#### test
```
# ignore cksum
ip netns exec send bash -lc '
    ethtool -K veth-s rx off tx off tso off gso off gro off lro off
    dd if=/dev/zero bs=1k count=1 2>/dev/null | nc -q 1 10.0.0.1 5000
'
```

### Eval
```
# tcp dump
ip netns exec recv bash -lc '
    ethtool -K veth-r rx off tx off tso off gso off gro off lro off
    tcpdump -i veth-r -Q out -n -vvv -s0 -XX "src 10.0.0.1" -c 5
'

# check hex option
ip netns exec recv tcpdump -vvv -s0 -XX 'src 10.0.0.1 and tcp' 

sudo cat /sys/kernel/debug/tracing/trace_pipe

# check recv side map
bpftool map dump pinned /sys/fs/bpf/tc/rx_flow_atu

# check sender side map
bpftool map dump pinned /sys/fs/bpf/tc/ack_atu_by_flow
```