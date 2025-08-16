# EXP

## Workflow
- ATU = numer / denom
```
header tcp_atu_opt_t {
    bit<8>  kind;     // 253
    bit<8>  len;      // 10
    bit<32> numer;
    bit<32> denom;
}

```

### End-to-End Flow Summary
```
Sender ── DATA ──> P4 Switch ── DATA+ATU ──> Receiver
   ↑                                         ↓
   │                                    Cache ATU
   │                                         ↓
   └──<──ACK+ATU(Kind=253)──<──────────────┘
```

### P4 Switch (Forward Path)
```
    Data packet (TCP, non-ACK)
         ↓
    Calculate ATU: numer = (rate_out + qdiff) << 3
                   denom = (queue_out << 4) + (queue_out << 3) + queue_out # queue_out * 25
         ↓
    Add ATU option to TCP header (Kind=253, Len=10)
         ↓
    Update IP/TCP lengths and checksums
         ↓
    Forward packet to receiver
```

### Sender
```
     TCP eBPF (tc/tx_ingress_parse_ack_opt)
         ↓
     Update BPF map (/sys/fs/bpf/ack_atu_by_flow)
         ↓
     ccll_atu_daemon (userspace)
         ↓
     /dev/ccll_ctl (char device)
         ↓
     C2L2 kernel module
         ↓
     Congestion Control
```
### Receiver
```
     Data packet with ATU (from P4 switch)
         ↓
     TCP eBPF (classifier/rx_ingress_cache_atu)
         ↓
     Update ATU in BPF map (/sys/fs/bpf/tc/rx_flow_atu)
         ↓
     Pure ACK packet (egress)
         ↓
     TCP eBPF (classifier/rx_egress_add_ack_opt)
         ↓
     Add ATU option to TCP header (Kind=253, Len=10)
         ↓
     Update IP/TCP lengths and checksums
         ↓
     Backward ack to receiver
```

## Issues

- I cannot adjust cksum at egress since the TSecr in skb will later be modified.
    - tcpdump result
     ```
     01:27:46.712007 IP (tos 0x0, ttl 64, id 38242, offset 0, flags [DF], proto TCP (6), length 64)
     10.0.0.1.5000 > 10.0.0.2.59382: Flags [.], cksum 0x72ce (incorrect -> 0x7f04), seq 1, ack 1025, win 502, options [nop,nop,TS val 3487334740 ecr 2448581683,unknown-253 0x0000232800002710,nop,nop], length 0
          0x0000:  966e fabc 0ae9 06da 0bb6 b870 0800 4500  .n.........p..E.
          0x0010:  0040 9562 4000 4006 9153 0a00 0001 0a00  .@.b@.@..S......
          0x0020:  0002 1388 e7f6 88b4 be53 d31f 0c72 b010  .........S...r..
          0x0030:  01f6 72ce 0000 0101 080a cfdc 8154 91f2  ..r..........T..
          0x0040:  6433 fd0a 0000 2328 0000 2710 0101       d3....#(..'...
     ```
    - The 32-th word (higher word of `TSecr`) is **91f2** in tcpdump but i got **4284** in sk buffer at egress stage.
    - Hence, my calculation at egress stage will never be correct.
    - commit 4473797d1cff55b31fa141450acba0be95a3c2fd
    - https://github.com/cytttt/Soze_Linux/blob/4473797d1cff55b31fa141450acba0be95a3c2fd/ebpf/atu_tcp_option_skeleton.c

- P4 comparison issues:
     ```
     // compare with old header
     if (hdr.atu_opt.isValid()) {
          bit<64> lhs = (bit<64>) numer          * (bit<64>) hdr.atu_opt.denom;
          bit<64> rhs = (bit<64>) hdr.atu_opt.numer   * (bit<64>) denom;
          if (!(lhs - rhs > 0)) { return; }
     }
     ```
     - condition too complex, limit of 4 bytes + 12 bits of PHV input exceeded
     - condition too complex, one operand must be constant
     - Hence, I just sent the `atu_numer` and the `atu_denom` to end host without comparison.
- P4 handle other options in forward packet
     - e.g. `[nop,nop,TS val 3492583381 ecr 3609098932]`

