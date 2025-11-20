#!/usr/bin/env python2
# send_burst_py2.py 2000
from scapy.all import Ether, IP, TCP, sendp
import sys

IFACE = "veth0"
COUNT = 2000  
PKT_PAYLOAD = b"PAYLOAD"

def make_pkt():
    return Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee", type=0x0800) / \
       IP(src="10.0.0.1", dst="10.0.0.8") / \
       TCP(sport=40000, dport=50000, flags="S") / PKT_PAYLOAD

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            COUNT = int(sys.argv[1])
        except:
            pass
    print "Sending %d packets on %s" % (COUNT, IFACE)
    pkt = make_pkt()
    # send many packets fast to build up queue
    sendp(pkt, iface=IFACE, inter=0, loop=0, count=COUNT)
    print "Done"