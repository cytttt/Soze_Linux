#!/usr/bin/env python3
# from pyroute2 import Genl
from pyroute2.netlink.generic import GenericNetlinkSocket as Genl
from socket import htons, htonl
import argparse, ipaddress

# sudo python3 tools/set_weight.py --saddr 10.0.0.2 --sport 5000 --daddr 10.0.0.1 --dport 40000 --weight 150000
# --- constants: must match linux/ccll.c ---
CCLL_CMD_SET_WEIGHT = 1
CCLL_A_SADDR  = 1
CCLL_A_DADDR  = 2
CCLL_A_SPORT  = 3
CCLL_A_DPORT  = 4
CCLL_A_WEIGHT = 5

ap = argparse.ArgumentParser(description='Set per-flow weight (1e5 scale) via genetlink "ccll"')
ap.add_argument('--saddr', required=True, help='source IPv4, e.g., 10.0.0.2')
ap.add_argument('--sport', type=int, required=True, help='source port')
ap.add_argument('--daddr', required=True, help='dest IPv4, e.g., 10.0.0.1')
ap.add_argument('--dport', type=int, required=True, help='dest port')
ap.add_argument('--weight', type=int, required=True, help='weight in 1e5 (100000=1.0x)')
args = ap.parse_args()

def ip_to_u32_be(ipstr):
    # inet_aton gives network-order bytes; unpack to big-endian u32
    return struct.unpack('!I', inet_aton(ipstr))[0]

g = Genl()              # requires root or CAP_NET_ADMIN if GENL_ADMIN_PERM is set
fam = g.get_family('ccll')  
fid = fam['id']

msg = {
    'cmd': CCLL_CMD_SET_WEIGHT,
    'version': 1,
    'attrs': [
        (CCLL_A_SADDR,  ip_to_u32_be(args.saddr)),   # already big-endian u32
        (CCLL_A_DADDR,  ip_to_u32_be(args.daddr)),
        (CCLL_A_SPORT,  htons(args.sport)),          # u16 network order
        (CCLL_A_DPORT,  htons(args.dport)),
        (CCLL_A_WEIGHT, args.weight),                # u32 (1e5 scale)
    ]
}

g.sendmsg(fid, msg)
print(f"set weight ok: {args.saddr}:{args.sport} -> {args.daddr}:{args.dport} = {args.weight}/1e5")