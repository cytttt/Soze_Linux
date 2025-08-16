/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2018-2019 Barefoot Networks, Inc.
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * Milad Sharif (msharif@barefootnetworks.com)
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<16> bd_t;
typedef bit<16> vrf_t;
typedef bit<16> nexthop_t;
typedef bit<16> ifindex_t;

#include "common/util.p4"
#include "common/headers.p4"
#include "common/lib.p4"

struct metadata_t {
    bool checksum_err;
    bd_t bd;
    vrf_t vrf;
    nexthop_t nexthop;
    ifindex_t ingress_ifindex;
    ifindex_t egress_ifindex;
}

struct eg_calc_md_t {
    // numer
    bit<32> rate_out;
    bit<32> tmp32a; 
    bit<19> tmp19; 
    bit<32> numer_tmp;
    // denom
    bit<32> queue_out;
    bit<32> tmp32b; // for queue_out << 3
    bit<32> denom_tmp;

}

struct eg_d_calc_md_t {
    bit<16> sum16;      // accumulate  16-bit sum of max atu
    bit<16> src16;
    bit<17> tmp17;      // carry fold
    bit<17> op17;   
    bit<16> lo16; 
    bit<16> hi16;
}

// LPF for Egress
Lpf<bit<32>, bit<10>>(1) lpf_rate;
Lpf<bit<32>, bit<10>>(1) lpf_queue;

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser CcllIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

    TofinoIngressParser() tofino_parser;

    state start {
        /*
        // initialization
        ig_md.checksum_err = false;
        ig_md.bd            = 16w0;
        ig_md.vrf           = 16w0;
        ig_md.nexthop       = 16w0;
        ig_md.ingress_ifindex = 16w0;
        ig_md.egress_ifindex  = 16w0;
        */

        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        ig_md.checksum_err = ipv4_checksum.verify();
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);

        transition select (hdr.tcp.data_offset) {
            // data_offset(32b words) > 5 implies options
            4w6:  parse_tcp_opt_check;
            4w7:  parse_tcp_opt_check;
            4w8:  parse_tcp_opt_check;
            4w9:  parse_tcp_opt_check;
            4w10: parse_tcp_opt_check;
            4w11: parse_tcp_opt_check;
            4w12: parse_tcp_opt_check;
            4w13: parse_tcp_opt_check;
            4w14: parse_tcp_opt_check;
            4w15: parse_tcp_opt_check;
            default: accept;
        } 
    }

    state parse_tcp_opt_check {
        bit<16> klen = pkt.lookahead<bit<16>>(); // (kind<<8) | len
        transition select (klen) {
            16w0xFD0A: parse_tcp_atu_opt;  // (253,10)
            default  : accept;
        }
    }

    state parse_tcp_atu_opt {
        pkt.extract(hdr.atu_opt);       // 10 bytes
        
        bit<16> pad = pkt.lookahead<bit<16>>();
        // also parse nop
        transition select(pad) {
            16w0x0101: parse_tcp_pad2;  // 0x01, 0x01
            default  : accept;
        }
    }

    state parse_tcp_pad2 {
        pkt.extract(hdr.tcp_pad2);      // 2 bytes
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.frag_offset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr});
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);

        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);

        pkt.emit(hdr.max_atu);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t md,
        in ingress_intrinsic_metadata_t ig_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // PortMapping(288, 1024, 1024) port_mapping;
    MAC(1024) mac;
    FIB(1024, 1024) fib;
    Nexthop(1024) nexthop;
    Lag() lag;

    bit<32> hash = 0;
//-----------------------------------------------------------------------------
// Destination MAC lookup
// key: destination MAC address.
// - Route the packet if the destination MAC address is owned by the switch.
//-----------------------------------------------------------------------------
    action rmac_hit() { }
    action rmac_miss() { }
    table rmac {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            rmac_hit;
            rmac_miss;
        }

        const default_action = rmac_miss;
        size = 1024;
    }

    apply {
        md.nexthop = 16w0;
        md.bd      = 16w0;
        ig_tm_md.ucast_egress_port = 9w0;
        
        switch (rmac.apply().action_run) {
            rmac_hit : {
                if (hdr.ipv4.isValid()) {
                    fib.apply(hdr.ipv4.dst_addr, md.vrf, md.nexthop);
                }
            }
        }

        nexthop.apply(md.nexthop, hash, md.bd, hdr.ethernet.dst_addr);
        mac.apply(hdr.ethernet.src_addr,
                  hdr.ethernet.dst_addr,
                  md.bd,
                  md.ingress_ifindex,
                  md.egress_ifindex);
        lag.apply(md.egress_ifindex, hash, ig_tm_md.ucast_egress_port);
    }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------
parser MyEgressParser(
    packet_in pkt,
    out header_t hdr,
    out metadata_t eg_md,
    out egress_intrinsic_metadata_t eg_intr_md) 
{
    state start {
        transition accept;
    }
}
// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------

control CcllEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    eg_calc_md_t eg_calc_md;

    action a_set_rate_out() {
        eg_calc_md.rate_out  = lpf_rate.execute( (bit<32>) hdr.ipv4.total_len, 0 );
    }
    table t_set_rate_out { actions = { a_set_rate_out; } const default_action = a_set_rate_out; }

    action a_set_queue_out() {
        eg_calc_md.queue_out = lpf_queue.execute( (bit<32>) eg_intr_md.deq_timedelta, 0 );
    }
    table t_set_queue_out { actions = { a_set_queue_out; } const default_action = a_set_queue_out; }

    
    // qdiff = deq_qdepth - enq_qdepth
    action a_qdiff_from_deq() { eg_calc_md.tmp19 = eg_intr_md.deq_qdepth; }
    action a_qdiff_sub_enq()  { eg_calc_md.tmp19 = eg_calc_md.tmp19 - eg_intr_md.enq_qdepth; }
    table  t_qdiff_from_deq { actions = { a_qdiff_from_deq; } const default_action = a_qdiff_from_deq; }
    table  t_qdiff_sub_enq  { actions = { a_qdiff_sub_enq; }  const default_action = a_qdiff_sub_enq; }

    
    // ---- numer = (rate_out + qdiff) << 3 ----
    action a_qdiff_to_tmp32()  { eg_calc_md.tmp32a    = (bit<32>) eg_calc_md.tmp19; }
    action a_numer_set_rate()  { eg_calc_md.numer_tmp = eg_calc_md.rate_out; }
    action a_numer_add_tmp32() { eg_calc_md.numer_tmp = eg_calc_md.numer_tmp + eg_calc_md.tmp32a; }
    action a_tmp32a_clear()    { eg_calc_md.tmp32a    = 32w0; }
    action a_numer_shl3()      { eg_calc_md.numer_tmp = eg_calc_md.numer_tmp << 3; }

    table t_qdiff_to_tmp32  { actions = { a_qdiff_to_tmp32; }  const default_action = a_qdiff_to_tmp32; }
    table t_numer_set_rate  { actions = { a_numer_set_rate; }  const default_action = a_numer_set_rate; }
    table t_numer_add_tmp32 { actions = { a_numer_add_tmp32; } const default_action = a_numer_add_tmp32; }
    table t_tmp32a_clear    { actions = { a_tmp32a_clear; }    const default_action = a_tmp32a_clear; }
    table t_numer_shl3      { actions = { a_numer_shl3; }      const default_action = a_numer_shl3; }

    action a_clear_after_numer() {
        eg_calc_md.numer_tmp = 32w0;
        eg_calc_md.tmp32a    = 32w0;
        eg_calc_md.tmp19     = 19w0;
        eg_calc_md.rate_out  = 32w0;
    }
    table  t_clear_after_numer { actions = { a_clear_after_numer; }
                                const default_action = a_clear_after_numer; }

    // ---- denom = (queue_out<<4) + (queue_out<<3) + queue_out ----
    action a_denom_set_shl4() { eg_calc_md.denom_tmp = eg_calc_md.queue_out << 4; }
    table  t_denom_set_shl4   { actions = { a_denom_set_shl4; } const default_action = a_denom_set_shl4; }

    action a_queue_shl3_store() { eg_calc_md.tmp32b = eg_calc_md.queue_out << 3; }
    table  t_queue_shl3_store   { actions = { a_queue_shl3_store; } const default_action = a_queue_shl3_store; }

    action a_denom_add_tmp() { eg_calc_md.denom_tmp = eg_calc_md.denom_tmp + eg_calc_md.tmp32b; }
    table  t_denom_add_tmp   { actions = { a_denom_add_tmp; } const default_action = a_denom_add_tmp; }

    action a_denom_add()      { eg_calc_md.denom_tmp = eg_calc_md.denom_tmp + eg_calc_md.queue_out; }
    table  t_denom_add        { actions = { a_denom_add; } const default_action = a_denom_add; }

    // checksum
    /*
    action a_sum_clear() { eg_calc_md.sum16 = 16w0; }

    action a_ext_sum()         { eg_calc_md.tmp17 = (bit<17>) eg_calc_md.sum16; }
    action a_set_from_src16()  { eg_calc_md.op17  = (bit<17>) eg_calc_md.src16; }
    action a_add_op()          { eg_calc_md.tmp17 = eg_calc_md.tmp17 + eg_calc_md.op17; }

    action a_set_lo_from_tmp() { eg_calc_md.lo16 = (bit<16>) eg_calc_md.tmp17; }
    action a_set_hi_from_tmp() { eg_calc_md.hi16 = (bit<16>) (eg_calc_md.tmp17 >> 16); }
    action a_set_sum_from_lo() { eg_calc_md.sum16 = eg_calc_md.lo16; }
    action a_add_hi_into_sum() { eg_calc_md.sum16 = eg_calc_md.sum16 + eg_calc_md.hi16; }

    action a_src_from_numer_hi(){ eg_calc_md.src16 = (bit<16>) (hdr.max_atu.numer >> 16); }
    action a_src_from_numer_lo(){ eg_calc_md.src16 = (bit<16>)  hdr.max_atu.numer; }
    action a_src_from_denom_hi(){ eg_calc_md.src16 = (bit<16>) (hdr.max_atu.denom >> 16); }
    action a_src_from_denom_lo(){ eg_calc_md.src16 = (bit<16>)  hdr.max_atu.denom; }
    action a_src_from_tcp_inv() { eg_calc_md.src16 = 16w0xFFFF ^ hdr.tcp.checksum; } // ~hdr.tcp.checksum
    action a_tcp_set_from_not_sum() { hdr.tcp.checksum = 16w0xFFFF ^ eg_calc_md.sum16; } // ~eg_calc_md.sum16
    */


    // tcp
    action a_tcp_len_add_atu() { hdr.tcp.data_offset = hdr.tcp.data_offset + 4w3; }
    table  t_tcp_len_add_atu   { actions = { a_tcp_len_add_atu; } const default_action = a_tcp_len_add_atu; }

    // ip
    action a_ip_len_add_atu() { hdr.ipv4.total_len = hdr.ipv4.total_len + 16w12; }
    table  t_ip_len_add_atu   { actions = { a_ip_len_add_atu; } const default_action = a_ip_len_add_atu; }

    
    apply {
        const bit<16> ATU_LEN = 12w12;
        // check forwarding path or not
        if (!(hdr.tcp.isValid() && !(hdr.tcp.flags == 8w0x10))) { return; } 
        
        t_set_rate_out.apply();
        t_set_queue_out.apply();
           
        if (eg_calc_md.queue_out == 0) { return; }

        // qdiff
        t_qdiff_from_deq.apply();
        t_qdiff_sub_enq.apply();
        
        // numer = (rate_out + qdiff) << 3
        t_numer_set_rate.apply();
        t_qdiff_to_tmp32.apply();
        t_numer_add_tmp32.apply();
        t_tmp32a_clear.apply();
        t_numer_shl3.apply();
        bit<32> numer = eg_calc_md.numer_tmp;

        t_clear_after_numer.apply();

        // denom = (queue<<4) + (queue<<3) + queue
        t_denom_set_shl4.apply();
        t_queue_shl3_store.apply(); 
        t_denom_add_tmp.apply(); 
        t_denom_add.apply();
        bit<32> denom = eg_calc_md.denom_tmp;

        /* TODO
        // compare with old header
        if (hdr.atu_opt.isValid()) {
            bit<64> lhs = (bit<64>) numer          * (bit<64>) hdr.atu_opt.denom;
            bit<64> rhs = (bit<64>) hdr.atu_opt.numer   * (bit<64>) denom;
            if (!(lhs - rhs > 0)) { return; }
        }
        */

        if (!hdr.atu_opt.isValid()) {
            hdr.atu_opt.setValid();
            hdr.atu_opt.kind  = 8w253;
            hdr.atu_opt.len   = 8w10;
            hdr.atu_opt.numer = numer;
            hdr.atu_opt.denom = denom;

            hdr.tcp_pad2.setValid();
            hdr.tcp_pad2.nop1 = 8w1;
            hdr.tcp_pad2.nop2 = 8w1; 

            // tcp len
            t_tcp_len_add_atu.apply();

            // ip len
            t_ip_len_add_atu.apply();

        }
        else {
            hdr.atu_opt.numer = numer;
            hdr.atu_opt.denom = denom;
        }

        /*
        else {
            hdr.max_atu.numer = numer;
            hdr.max_atu.denom = denom;
        } 
        */ 
    }

}


// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control CcllEgressDeparser<H, M>(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) csum16;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({ 
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr });
        
        if (hdr.tcp.isValid() && hdr.atu_opt.isValid()) {
            bit<16> w_klen = 16w0xFD0A; // {253,10}
            bit<16> w_nh   = (bit<16>)(hdr.atu_opt.numer >> 16);
            bit<16> w_nl   = (bit<16>) hdr.atu_opt.numer;
            bit<16> w_dh   = (bit<16>)(hdr.atu_opt.denom >> 16);
            bit<16> w_dl   = (bit<16>) hdr.atu_opt.denom;
            bit<16> w_pad  = 16w0x0101;
            bit<16> w_len  = 16w12;  // tcp 12

            bit<16> s = 16w0;
            bit<17> t;

            t = (bit<17>)s + (bit<17>)w_klen; s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));
            t = (bit<17>)s + (bit<17>)w_nh;   s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));
            t = (bit<17>)s + (bit<17>)w_nl;   s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));
            t = (bit<17>)s + (bit<17>)w_dh;   s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));
            t = (bit<17>)s + (bit<17>)w_dl;   s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));
            t = (bit<17>)s + (bit<17>)w_pad;  s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));

            t = (bit<17>)s + (bit<17>)w_len;  s = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));

            bit<16> old_inv = 16w0xFFFF ^ hdr.tcp.checksum;
            t = (bit<17>)old_inv + (bit<17>)s;
            bit<16> folded = (bit<16>)((bit<16>)t + (bit<16>)(t >> 16));
            hdr.tcp.checksum = 16w0xFFFF ^ folded;
        }
        


        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);

        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);

        pkt.emit(hdr.max_atu);
    }
}

Pipeline(CcllIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         MyEgressParser(),
         CcllEgress(),
         CcllEgressDeparser()) pipe;

Switch(pipe) main;
