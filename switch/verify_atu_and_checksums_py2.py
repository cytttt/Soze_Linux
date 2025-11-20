#!/usr/bin/env python2
# verify_atu_and_checksums_py2.py /tmp/egress.pcap
from scapy.all import rdpcap, IP, TCP
import struct, socket, sys

def ipv4_checksum(ip_pkt):
    # ip_pkt: scapy IP layer
    ihl = ip_pkt.ihl * 4
    raw = bytearray(str(ip_pkt))[:ihl]
    # zero checksum bytes
    raw[10] = 0
    raw[11] = 0
    s = 0
    for i in range(0, len(raw), 2):
        s += (raw[i] << 8) + raw[i+1]
    while s > 0xffff:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_checksum(ip_pkt, tcp_pkt, payload):
    # pseudo-header + tcp header (with checksum zeroed) + payload
    src = socket.inet_aton(ip_pkt.src)
    dst = socket.inet_aton(ip_pkt.dst)
    placeholder = 0
    proto = ip_pkt.proto
    tcp_raw = bytearray(str(tcp_pkt))
    # tcp header length in bytes
    tcp_len = len(tcp_raw) + len(payload)
    pseudo = src + dst + struct.pack('!BBH', placeholder, proto, tcp_len)
    # zero checksum (bytes 16-17 in header)
    if len(tcp_raw) >= 18:
        tcp_raw[16] = 0
        tcp_raw[17] = 0
    data = pseudo + tcp_raw + payload
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    # for i in range(0, len(data), 2):
    #     s += (ord(data[i]) << 8) + ord(data[i+1])
    for i in range(0, len(data), 2):
        left = data[i]
        right = data[i+1] if i+1 < len(data) else 0
        if isinstance(left, str):   # Python2 bytes
            left = ord(left)
        if isinstance(right, str):
            right = ord(right)
        s += (left << 8) + right
    while s > 0xffff:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def find_atu_option(tcp_pkt):
    raw_tcp = bytearray(str(tcp_pkt))
    # header length in bytes
    header_len = tcp_pkt.dataofs * 4
    opts_bytes = raw_tcp[20:header_len]
    idx = bytes(opts_bytes).find(b'\xfd')  # 0xFD
    if idx == -1:
        return None
    if idx + 1 >= len(opts_bytes):
        return None
    optlen = ord(bytes([opts_bytes[idx+1]])) if isinstance(opts_bytes[idx+1], str) else opts_bytes[idx+1]
    # fallback: if optlen isn't valid, accept at least 10
    if optlen < 10 or idx + optlen > len(opts_bytes):
        # may be incomplete
        return None
    payload = bytes(opts_bytes[idx+2: idx+2+8])
    if len(payload) < 8:
        return None
    numer = struct.unpack("!I", payload[:4])[0]
    denom = struct.unpack("!I", payload[4:])[0]
    return numer, denom, bytes(opts_bytes[idx: idx+optlen])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: verify_atu_and_checksums_py2.py capture.pcap")
        sys.exit(1)
    pcap = sys.argv[1]
    pkts = rdpcap(pcap)
    for i,p in enumerate(pkts):
        if IP in p and TCP in p:
            ip = p[IP]
            tcp = p[TCP]
            payload = bytes(tcp.payload)
            atu = find_atu_option(tcp)
            sys.stdout.write("Packet #%d: src=%s:%s dst=%s:%s flags=%s\n" % (
                i, ip.src, tcp.sport, ip.dst, tcp.dport, tcp.flags))
            if atu:
                numer, denom, raw_opt = atu
                sys.stdout.write("  Found ATU option: numer=%d denom=%d raw=%s\n" % (numer, denom, raw_opt.encode('hex')))
            else:
                sys.stdout.write("  No ATU option found.\n")
            ip_ck = ipv4_checksum(ip)
            tcp_ck = tcp_checksum(ip, tcp, payload)
            sys.stdout.write("  IP checksum in pkt: 0x%04x computed: 0x%04x\n" % (ip.chksum, ip_ck))
            sys.stdout.write("  TCP checksum in pkt: 0x%04x computed: 0x%04x\n" % (tcp.chksum, tcp_ck))
            sys.stdout.write("---\n")