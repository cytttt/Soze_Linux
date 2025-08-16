# EXP

## Workflow
- ATU = numer / denom

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

