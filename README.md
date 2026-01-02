# WPA3 & Wi-Fi Attack Framework

A comprehensive Python-based framework for testing WPA3 network security vulnerabilities and conducting advanced Layer 2 Denial-of-Service attacks. This repository combines research from the paper **"How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"** with practical infrastructure stress-testing tools.

> ⚠️ **EDUCATIONAL PURPOSES ONLY**
> This tool is designed for **authorized security testing and academic research**.
> Unauthorized use against networks you do not own or have explicit permission to test is **illegal and unethical**.

---

## 📚 Repository Overview

This framework consists of two main categories of tools:

1.  **WPA3 DoS Orchestrators**: Scripts that flood target APs with manipulated management frames (SAE, Auth, etc.) to trigger resource exhaustion or logic errors.
2.  **Double SSID Attack Tool**: A Rogue AP implementation that creates protocol confusion at Layer 2 by cloning legitimate networks.

---

## 🏗️ Repository Structure

```text
WPA3-Attack/
├── README.md                                   # This documentation
│
├── 🛠️ Infrastructure Tools
│   └── Double_SSID_Attack_Tool_WPA2_WPA3.py    # Rogue AP / BSSID Confusion Tool
│
├── ⚔️ DoS Orchestrators (Packet Injection)
│   ├── orchestator_master_en.py                # Complete arsenal (26 attacks)
│   ├── orchestator_final_mit_allen_details_en.py # Modern attacks (7 types)
│   ├── orchestator_enhanced_plus_en.py         # Enhanced attacks (9 types)
│   └── orchestator_Moderne_Angriffe_2023+_en.py# Latest modern attacks
│
├── 📂 Documentation
│   ├── documentation_orchestator_master.txt    # Master guide
│   └── ... (additional guides)
│
└── ⚙️ Setup & Resources
    ├── Wireshark settings.txt                  # Config for capturing SAE
    ├── Chipset_Identification.txt              # Broadcom/Qualcomm/MediaTek guide
    └── SAE_Parameter_Extraction.png            # Visual guide
```

---

## 🛠️ Tool 1: Double SSID Attack Tool

**Script:** `Double_SSID_Attack_Tool_WPA2_WPA3.py`

This tool automates a "Double SSID" (or BSSID Confusion) attack. Instead of jamming frequencies, it creates **exact clones** of a target Access Point (AP), duplicating its **SSID** and **BSSID (MAC Address)**.

### 🎯 How it works
1.  **Layer 2 Confusion:** Clients within range see two physical sources emitting the exact same BSSID.
2.  **Protocol Conflict:** The 802.11 protocol cannot efficiently handle duplicate BSSIDs on the same (or different) channels.
3.  **Result:** Clients suffer from constant disconnections, failed handshakes, and complete connectivity loss.

### ✨ Key Features
*   **WPA2 & WPA3 (SAE) Mixed Mode:** Configured to support both legacy and modern clients simultaneously (`WPA-PSK SAE`) with optional PMF (`802.11w`).
*   **Manual Target Configuration (Cross-Band):**
    *   You can clone a 5GHz AP but broadcast it on a 2.4GHz channel.
    *   Devices often prefer the stronger signal of the rogue 2.4GHz AP, leading to successful hijacking.
*   **Hidden Network Support:** Capable of cloning hidden SSIDs (configurable via `ignore_broadcast_ssid`).
*   **Multi-SSID Support:** Spawn multiple virtual interfaces to attack several networks at once.

### 🚀 Usage
```bash
sudo python3 Double_SSID_Attack_Tool_WPA2_WPA3.py
```
*Follow the interactive prompts to scan, select a target, and optionally override the BSSID or Channel.*

---

## ⚔️ Tool 2: WPA3 DoS Orchestrators

**Scripts:** `orchestator_*.py`

These scripts implement the attack vectors described in the "DoS attacks on WPA3-SAE" research paper. They target the logic and resource management of the Access Point.

### 🎯 Attack Arsenal

#### 1. WPA3-Specific Attacks
*   **Omnivore:** Floods with WPA3 connection attempts using random MACs to exhaust RAM.
*   **Muted:** Static MAC flooding to bypass multi-source rate limiting.
*   **Hasty:** Sends SAE Commit & Confirm frames immediately to confuse state machines.
*   **Double Decker:** Combines *Omnivore* and *Muted* for maximum stress.
*   **Cookie Guzzler:** Exploits SAE anti-clogging mechanisms to trigger excessive retransmissions.

#### 2. Universal & Cross-Band Attacks
*   **Radio Confusion:** Exploits dual-band drivers by sending frames to the 2.4GHz interface that reference the 5GHz interface (and vice versa).
*   **Amplification:** Spoofs legitimate client MACs, causing the AP to spam error responses to the victim.
*   **Open Auth Flood:** Legacy attack effective against the CPU queue of modern routers.

#### 3. Vendor-Specific Exploits
Targeted attacks for specific chipsets (Broadcom, Qualcomm, MediaTek) involving malformed packets, invalid algorithms, and sequence number fuzzing.

---

## ⚙️ Setup & Configuration

### Prerequisites
*   **OS:** Kali Linux, Parrot OS, or Ubuntu (with patched kernel).
*   **Hardware:** WiFi adapter supporting **Monitor Mode** and **Packet Injection**.
*   **Dependencies:**
    ```bash
    sudo apt update
    sudo apt install -y python3-pip aircrack-ng hostapd wireshark tshark xterm
    pip3 install scapy
    ```

### Critical: Extracting SAE Parameters (For Orchestrators)
To attack WPA3 networks using the Orchestrator scripts, you must capture valid SAE parameters from a genuine handshake attempt.

1.  **Start Wireshark** on your monitor interface.
2.  **Connect** a mobile device to the target WPA3 network using the **WRONG PASSWORD**.
3.  **Filter** for `wlan.fc.type_subtype == 0x0b` (Auth frames).
4.  **Extract:** Copy the "Finite Field Element" and "Scalar" values from the packet details.
    *   *Note: 2.4GHz and 5GHz usually have different parameters. Capture both if attacking both.*
5.  **Edit Script:** Paste these values into the `SAE_SCALAR_HEX` and `SAE_FINITE_ELEMENT_HEX` variables in the python script.

---

## 📊 Verifying Attack Success

Since these attacks do not always shut down the AP completely, use `tshark` to measure the impact.

**Method 1: Beacon Jitter (AP Overload)**
Checks if the AP is struggling to send beacons on time.
```bash
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8 && wlan.addr == <TARGET_BSSID>" -T fields -e frame.time_delta_displayed
```
*   **Normal:** ~0.1024 seconds
*   **Under Attack:** > 0.5 seconds (High Latency/DoS)

**Method 2: Client Disconnections (Double SSID/Deauth)**
Checks if clients are being forced off the network.
```bash
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x0c"
```
*   **Success:** You will see a flood of Deauthentication frames.

---

## 🔒 Legal & Defense

### Defense Recommendations
1.  **PMF (802.11w):** Set to "Required" (not just Optional) to mitigate some deauth and management frame attacks.
2.  **Firmware:** Update router firmware to patch known WPA3-SAE logic loops (Dragonblood patches).
3.  **WIDS/IPS:** Use an Intrusion Detection System to monitor for duplicate BSSIDs or excessive SAE Commit frames.

### Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS SOFTWARE. USE AT YOUR OWN RISK.

---

## 👤 Author & References

*   **Repository Maintainer:** Nuseo1
*   **Based on Research:** "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE" (Journal of Information Security and Applications, 2022).
*   **Standards:** IEEE 802.11-2020 / RFC 7664.

**Last Updated:** January, 2026
