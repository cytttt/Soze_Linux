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

## Local test

- Terminals
    - **Terminal 1**: CC-Setup, CC-Cleanup, Eval
    - **Terminal 2 in Receiver shell**: Recv-Setup, Recv-Test
    - **Terminal 3**: Send-Setup, Send-Test
    - **Terminal 4**: Daemon

```
# Experiment flow
    CC-Setup
     ↓
    Recv-Setup
     ↓
    Send-Setup
     ↓
    Daemon
     ↓
    Eval
     ↓
    Recv-Test
     ↓
    Send-Test
     ↓
    CC-Cleanup
```

### CC
#### Setup
```
cd linux
make all ATU_TEST_MODE=1
sudo bash clean.bash
sudo bash setup.bash
sudo bash setup-ccll.bash
```

#### Cleanup
- 
```
make clean
sudo bash clean.bash
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

# check recv side map
bpftool map dump pinned /sys/fs/bpf/tc/rx_flow_atu
```

### Sender side

#### setup
```
bash local-setup-tx.bash
# sudo ip netns exec send sysctl -w net.ipv4.tcp_congestion_control=ccll

```
#### test
```
# ignore cksum
sudo ip netns exec send bash -lc '
    ethtool -K veth-s rx off tx off tso off gso off gro off lro off
    dd if=/dev/zero bs=1k count=1 2>/dev/null | nc -q 1 10.0.0.1 5000
'

sudo ip netns exec send bash -lc '
  ethtool -K veth-s rx off tx off tso off gso off gro off lro off || true
  dd if=/dev/zero bs=1460 count=200 2>/dev/null | nc -q 5 10.0.0.1 5000
'

# check sender side map
bpftool map dump pinned /sys/fs/bpf/tc/ack_atu_by_flow
```

### Eval
```
# tcp dump
sudo ip netns exec recv bash -lc '
    ethtool -K veth-r rx off tx off tso off gso off gro off lro off
    tcpdump -i veth-r -Q out -n -vvv -s0 -XX "src 10.0.0.1" -c 5
'

sudo ip netns exec recv bash -lc '
  ethtool -K veth-r rx off tx off tso off gso off gro off lro off || true
  tcpdump -i veth-r -Q out -n -vvv -s0 -XX \
    "src host 10.0.0.1 and tcp[13] == 0x10" \
    -c 30
'

# check hex option
ip netns exec recv tcpdump -vvv -s0 -XX 'src 10.0.0.1 and tcp' 

# check ebpf log
sudo cat /sys/kernel/debug/tracing/trace_pipe

```
### daemon
```
sudo ./ccll_atu_daemon --map /sys/fs/bpf/tc/ack_atu_by_flow --dev /dev/ccll_ctl --interval-ms 50
```