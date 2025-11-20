/*------------------------------------------------------------------------------
 * Skeleton P4_14 program derived from the P4_16 implementation in c2l2/c2l2.p4.
 *
 * WARNING:
 *   – This file is NOT a drop‑in replacement. It exists to jump‑start the
 *     manual port to P4_14 and still requires significant editing.
 *   – Architecture includes, intrinsic metadata layout, and many behavioural
 *     details need to be reconciled against the Barefoot/Tofino P4_14 model
 *     you are targeting.
 *   – Advanced TNA features (e.g. Lpf externs, action selectors/profiles,
 *     parser lookahead) have no direct P4_14 analogue and are stubbed out.
 *------------------------------------------------------------------------------
 */

// TODO: replace this include with the proper architecture header for your
//       Barefoot/Tofino SDE release (for example bf_switch.p4 or tofino.p4).
// #include <arch/tofino.p4>

/* Header definitions ------------------------------------------------------- */
header_type ethernet_t {
    fields {
        dst_addr   : 48;
        src_addr   : 48;
        ether_type : 16;
    }
}

header_type ipv4_t {
    fields {
        version        : 4;
        ihl            : 4;
        diffserv       : 8;
        total_len      : 16;
        identification : 16;
        flags          : 3;
        frag_offset    : 13;
        ttl            : 8;
        protocol       : 8;
        hdr_checksum   : 16;
        src_addr       : 32;
        dst_addr       : 32;
    }
}

header_type udp_t {
    fields {
        src_port : 16;
        dst_port : 16;
        length   : 16;
        checksum : 16;
    }
}

header_type tcp_t {
    fields {
        src_port    : 16;
        dst_port    : 16;
        seq_no      : 32;
        ack_no      : 32;
        data_offset : 4;
        res         : 4;
        flags       : 8;
        window      : 16;
        checksum    : 16;
        urgent_ptr  : 16;
    }
}

header_type tcp_atu_opt_t {
    fields {
        kind  : 8;
        len   : 8;
        numer : 32;
        denom : 32;
    }
}

header_type tcp_opt_pad2_t {
    fields {
        nop1 : 8;
        nop2 : 8;
    }
}

header ethernet_t     ethernet;
header ipv4_t         ipv4;
header udp_t          udp;
header tcp_t          tcp;
header tcp_atu_opt_t  tcp_atu_opt;
header tcp_opt_pad2_t tcp_opt_pad2;

/* Metadata definitions ----------------------------------------------------- */
metadata meta_t {
    fields {
        checksum_err     : 1;
        bd               : 16;
        vrf              : 16;
        nexthop          : 16;
        ingress_ifindex  : 16;
        egress_ifindex   : 16;
        numer_tmp        : 32;
        denom_tmp        : 32;
    }
}

/* Parser ------------------------------------------------------------------- */
parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.ether_type) {
        0x0800 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    // NOTE: P4_14 has no built-in checksum verify pipeline stage. You will
    //       need to add extern calls or a checksum unit if required.
    return select(ipv4.protocol) {
        6 : parse_tcp;
        17: parse_udp;
        default: ingress;
    }
}

parser parse_udp {
    extract(udp);
    return ingress;
}

parser parse_tcp {
    extract(tcp);
    // P4_14 lacks lookahead; TCP options parsing must be reimplemented using
    // fixed layouts or custom parser extensions.
    return ingress;
}

/* Constants ---------------------------------------------------------------- */
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTOCOL_TCP = 6;
const bit<8>  IP_PROTOCOL_UDP = 17;

/* Ingress control ---------------------------------------------------------- */
action set_nexthop(bit<16> nexthop_index, bit<16> bd, bit<16> egress_ifindex) {
    meta.nexthop         = nexthop_index;
    meta.bd              = bd;
    meta.egress_ifindex  = egress_ifindex;
}

table rmac {
    reads {
        ethernet.dst_addr : exact;
    }
    actions {
        NoAction;
    }
    size : 1024;
}

table fib_host {
    reads {
        meta.vrf    : exact;
        ipv4.dst_addr : exact;
    }
    actions {
        NoAction;
        set_nexthop;
    }
    size : 1024;
}

table fib_lpm {
    reads {
        meta.vrf      : exact;
        ipv4.dst_addr : lpm;
    }
    actions {
        NoAction;
        set_nexthop;
    }
    size : 1024;
}

action program_egress(bit<9> port) {
    // Replace with the correct intrinsic metadata symbol for your arch.
    standard_metadata.egress_spec = port;
}

table nexthop_lookup {
    reads {
        meta.nexthop : exact;
    }
    actions {
        NoAction;
        program_egress;
    }
    size : 1024;
}

control ingress {
    apply {
        if (!valid(ethernet)) {
            return;
        }

        rmac.apply();

        if (valid(ipv4)) {
            if (!fib_host.apply().hit) {
                fib_lpm.apply();
            }
            nexthop_lookup.apply();
        }
    }
}

/* Egress control ----------------------------------------------------------- */
action install_tcp_option(bit<32> numer, bit<32> denom) {
    if (!valid(tcp_atu_opt)) {
        add_header(tcp_atu_opt);
        add_header(tcp_opt_pad2);

        tcp_atu_opt.kind  = 253;
        tcp_atu_opt.len   = 10;
        tcp_opt_pad2.nop1 = 1;
        tcp_opt_pad2.nop2 = 1;

        if (valid(tcp)) {
            tcp.data_offset = tcp.data_offset + 3;
        }
        if (valid(ipv4)) {
            ipv4.total_len = ipv4.total_len + 12;
        }
    }

    tcp_atu_opt.numer = numer;
    tcp_atu_opt.denom = denom;
}

control egress {
    apply {
        // TODO: re-create lpf_rate/lpf_queue once the proper extern or register
        //       based implementation is decided. For now, reuse simple packet
        //       properties as placeholders.
        bit<32> numer = valid(ipv4) ? (ipv4.total_len << 3) : 0;
        bit<32> denom = 1; // stubbed out – replace with queue depth math.

        if (valid(tcp)) {
            install_tcp_option(numer, denom);
        }
    }
}

/* Deparser ----------------------------------------------------------------- */
control deparser {
    apply {
        emit(ethernet);
        if (valid(ipv4)) {
            emit(ipv4);
        }
        if (valid(udp)) {
            emit(udp);
        }
        if (valid(tcp)) {
            emit(tcp);
        }
        if (valid(tcp_atu_opt)) {
            emit(tcp_atu_opt);
        }
        if (valid(tcp_opt_pad2)) {
            emit(tcp_opt_pad2);
        }
    }
}

/* Pipeline bundle ---------------------------------------------------------- */
control ingress;
control egress;
control deparser;
