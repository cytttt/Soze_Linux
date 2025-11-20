#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import os
import importlib

P4_NAME = "c2l2"
SDE = "/root/bf-sde-8.4.0"
sys.path.append(os.path.join(SDE, "install/lib/python2.7/site-packages"))

# ---- Import PD RPC modules ----
try:
    p4_pd_rpc = importlib.import_module("p4_pd_rpc")
    import pal_rpc
    import pltfm_pm_rpc
except ImportError:
    print(" -> ERROR: cannot import PD modules, check PYTHONPATH and SDE path")
    sys.exit(1)

# ---- Connect to switchd RPC ----
conn_mgr = p4_pd_rpc.conn_mgr
mc = p4_pd_rpc.mc
dev_tgt = p4_pd_rpc.DevTarget_t(0, 0xFFFF)
sess_hdl = conn_mgr.client_init()
print("[OK] Connected to bf_switchd, session handle =", sess_hdl)

# ---- Load specific P4 program module ----
try:
    client_module = importlib.import_module(P4_NAME + "_p4_pd_rpc." + P4_NAME)
except ImportError:
    print(" -> : cannot import PD client for", P4_NAME)
    sys.exit(1)

p4 = client_module.ClientInterface(conn_mgr, mc)
p4_init = getattr(client_module, P4_NAME + "_init")
p4_init()
print("[OK] P4 tables loaded:", P4_NAME)

# =============== Add entries ===============
print("\n[+] Adding entries...")

# RMAC
try:
    mac_val = 0x00AABBCCDDEE
    rmac_handle = p4.SwitchIngress_rmac_table_add_with_rmac_hit(
        sess_hdl, dev_tgt, mac_val)
    print("  RMAC added for dst=0x%012x (handle %d)" % (mac_val, rmac_handle))
except Exception as e:
    print(" --> RMAC add failed:", e)

# FIB_LPM
try:
    fib_key = client_module.SwitchIngress_fib_lpm_match_spec_t(
        vrf=0, hdr_ipv4_dst_addr=0x0A000008,
        hdr_ipv4_dst_addr_prefix_length=32)
    fib_handle = p4.SwitchIngress_fib_lpm_table_add_with_fib_hit(
        sess_hdl, dev_tgt, fib_key, nexthop_index=0)
    print("  FIB_LPM added: dst=10.0.0.8/32 -> nexthop 0 (handle %d)" % fib_handle)
except Exception as e:
    print(" --> FIB_LPM add failed:", e)

# NEXTHOP
try:
    nh_key = client_module.SwitchIngress_nexthop_match_spec_t(nexthop_index=0)
    nh_action = client_module.SwitchIngress_set_nexthop_attribures_action_spec_t(
        bd=0, dmac=0x001122334455)
    nh_handle = p4.SwitchIngress_nexthop_table_add_with_set_nexthop_attribures(
        sess_hdl, dev_tgt, nh_key, nh_action)
    print("  NEXTHOP added: idx=0 dmac=00:11:22:33:44:55 (handle %d)" % nh_handle)
except Exception as e:
    print(" --> NEXTHOP add failed:", e)

# ---- Commit ----
conn_mgr.complete_operations(sess_hdl)
print("\n[OK] Initialization complete.\n")

# =============== Dump verification ===============
print("[*] Dumping table contents...\n")

# dump RMAC
try:
    entries = p4.SwitchIngress_rmac_get_first_entry_handle(sess_hdl, dev_tgt)
    while True:
        for entry in entries:
            data = p4.SwitchIngress_rmac_get_entry(sess_hdl, dev_tgt, entry)
            print("  RMAC entry:", hex(data.match_key.hdr_ethernet_dst_addr))
        entries = p4.SwitchIngress_rmac_get_next_entry_handle(sess_hdl, dev_tgt, entries[-1], 10)
        if not entries:
            break
except Exception as e:
    print(" --> RMAC dump error:", e)

# dump FIB_LPM
try:
    entries = p4.SwitchIngress_fib_lpm_get_first_entry_handle(sess_hdl, dev_tgt)
    while True:
        for entry in entries:
            data = p4.SwitchIngress_fib_lpm_get_entry(sess_hdl, dev_tgt, entry)
            dst_ip = data.match_key.hdr_ipv4_dst_addr
            print("  FIB_LPM entry: dst=%s/%d -> nexthop=%d" %
                  ('.'.join(map(str, [(dst_ip >> (8 * i)) & 0xFF for i in [3, 2, 1, 0]])),
                   data.match_key.hdr_ipv4_dst_addr_prefix_length,
                   data.action_data.nexthop_index))
        entries = p4.SwitchIngress_fib_lpm_get_next_entry_handle(sess_hdl, dev_tgt, entries[-1], 10)
        if not entries:
            break
except Exception as e:
    print(" --> FIB_LPM dump error:", e)

# dump NEXTHOP
try:
    entries = p4.SwitchIngress_nexthop_get_first_entry_handle(sess_hdl, dev_tgt)
    while True:
        for entry in entries:
            data = p4.SwitchIngress_nexthop_get_entry(sess_hdl, dev_tgt, entry)
            print("  NEXTHOP entry: index=%d dmac=0x%012x" %
                  (data.match_key.nexthop_index, data.action_data.dmac))
        entries = p4.SwitchIngress_nexthop_get_next_entry_handle(sess_hdl, dev_tgt, entries[-1], 10)
        if not entries:
            break
except Exception as e:
    print(" --> NEXTHOP dump error:", e)

print("\n Done.")