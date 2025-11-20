## Goal

Sent packet to veth0 and go throgh pipeline then

## Packet
```python
PKT_PAYLOAD = b"PAYLOAD"

def make_pkt():
    return Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=0x0800) / \
       IP(src="10.0.0.1", dst="10.0.0.8") / \
       TCP(sport=40000, dport=50000, flags="S") / PKT_PAYLOAD
pkt = make_pkt()
sendp(pkt, iface=IFACE, inter=0, loop=0, count=COUNT)
```
The packet should egress from the correct veth interface (veth2 for port 1), and the ether_type must be 0x0800.

## Activate

- compile
```bash
./p4_build.sh pkgsrc/p4-examples/programs/c2l2/c2l2.p4
```

- run `tofino-model`
```
./run_tofino_model.sh -p c2l2

// Adding interface veth0 as port 0 (used as ingress port)
// Adding interface veth2 as port 1 (used as egress port)
// veth0 corresponds to port 0 and veth2 corresponds to port 1; this is the path used for packet forwarding
```

- run `switchd`
```
./run_switchd.sh -p c2l2
```
Note: `lag.apply()` must remain for switchd to initialize successfully.

- enter bf-shell in `switchd` pane
```
bfshell> bfrt

bfrt_root> bfrt.c2l2

// allow forwarding
// Router MAC Table
rmac.add_with_rmac_hit(0x00aabbccddee)
rmac.add_with_rmac_hit(0x001122334455)
// Forwarding Information Base
fib.add_with_fib_hit(vrf=0,dst_addr=0x0a000008, dst_addr_p_length=32,nexthop_index=0)
fib.add_with_fib_hit(vrf=0,dst_addr=0x0a080808,nexthop_index=9)

nexthop.add_with_set_nexthop_attribures(nexthop_index=0, bd=0, dmac="0x001122334455")
nexthop.add_with_set_nexthop_attribures(nexthop_index=9,bd=0,dmac="0x00beefbeef01")
```

- In control ingress
	- The ucast egress port must be set manually. For example, to ensure the packet goes out on veth2 (port 1), set:
```
ig_tm_md.ucast_egress_port = 9w1; // sets egress port to 1 (veth2)
```

Note: Removing LAG will cause switchd to crash. The hardcoded egress port is only for basic pipeline validation.

- send packet and monitor
	- Use tcpdump on veth2 (not veth3) since port 1 maps to veth2:
	```
	tcpdump -i veth2 -vvv -c 3
	^C
	```



b'SwitchIngress.lag.lag'
    Found 1 key fields:
      b'ifindex' : type=EXACT size=16
    No actions on this table.
    Found 2 data fields:
      b2025-11-12 05:39:11 PM.720424 BF_BFRT ERROR - actionIdListGet:769 Not supported
'$ACTION_MEMBER_ID' : type=UINT64 size=32
      b'$SELECTOR_GR2025-11-12 05:39:11 PM.720749 BF_BFRT ERROR - actionIdListGet:769 Not supported
OUP_ID' : type=UINT64 size=32
  b'SwitchIngress.lag.lag_selector'
    Found 1 key fields:
      b'$ACTION_MEMBER_ID' : type=EXACT size=32
    Found 2 actions:
      b'2025-11-12 05:39:11 PM.721622 BF_BFRT ERROR - actionIdListGet:3366 Table has no action IDs
SwitchIngress.lag.set_port' : id=16782434
        1 data fields:
          b'port' : type=BYTE_STREAM size=9
      b'SwitchIngress.lag.lag_miss' : id=16812231
        No data fields for b'SwitchIngress.lag.lag_miss'