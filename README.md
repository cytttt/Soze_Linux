# EXP

## Workflow

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
    congestion control
```
### Receiver
```
    TCP eBPF (classifier/rx_ingress_cache_atut)
         ↓
         ↓
    TCP eBPF (classifier/rx_egress_add_ack_opt)
```


## Issues

- I cannot adjust cksum at egress since the TSecr in skb will later be modified.
    - Reset to commit 4473797d1cff55b31fa141450acba0be95a3c2fd 
- P4 how to handle other options in forward packet
