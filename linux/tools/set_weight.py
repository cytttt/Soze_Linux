#!/usr/bin/env python3
from pyroute2 import Genl
from socket import htons, htonl
import argparse, ipaddress

# set_weight.py --saddr 10.0.0.2 --sport 5000 --daddr 10.0.0.1 --dport 40000 --weight 150000

ap = argparse.ArgumentParser(description='Set per-flow weight (1e5 scale) via genetlink')
ap.add_argument('--saddr', required=True, help='source IP (IPv4)')
ap.add_argument('--sport', type=int, required=True, help='source port')
ap.add_argument('--daddr', required=True, help='dest IP (IPv4)')
ap.add_argument('--dport', type=int, required=True, help='dest port')
ap.add_argument('--weight', type=int, required=True, help='weight in 1e5 scale (100000=1.0x)')
args = ap.parse_args()

def ip2u32(ip):
    return int(ipaddress.IPv4Address(ip))

g = Genl()
fid = g.get_family_id('ccll')
g.sendmsg(fid, {
    'cmd': 1,   # CCLL_C_SET_WEIGHT
    'version': 1,
    'attrs': [
        ('CCLL_A_SADDR',  htonl(ip2u32(args.saddr))),
        ('CCLL_A_DADDR',  htonl(ip2u32(args.daddr))),
        ('CCLL_A_SPORT',  htons(args.sport)),
        ('CCLL_A_DPORT',  htons(args.dport)),
        ('CCLL_A_WEIGHT', args.weight),
    ]
})
print(f"set weight ok: {args.saddr}:{args.sport} -> {args.daddr}:{args.dport} = {args.weight}/1e5")