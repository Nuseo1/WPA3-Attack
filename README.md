# Double SSID Attack Tool (WPA2/WPA3)

> **Note:** The WPA3‑SAE DoS tool previously included here has been moved to its own repository:  
> 👉 [WPA3-SAE-DoS-Research-Suite](https://github.com/Nuseo1/WPA3-SAE-DoS-Research-Suite)

---

## 📡 Double_SSID_Attack_Tool_WPA2_WPA3.py

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

### 🔧 Features

- Creates a WPA2 AP (open or with a password) and a WPA3‑SAE AP with identical SSID.
- Forces WPA3 Transition Mode clients to downgrade to WPA2.
- Captures the EAPOL handshake for offline brute‑force cracking (e.g., Hashcat).
- Simple command‑line interface, automatic channel selection.

### 📋 Prerequisites

- Linux (Kali Linux recommended)
- Python 3.7+
- `hostapd` with WPA3‑SAE support
- `dnsmasq` (optional, for DHCP)
- A wireless card that supports monitor mode and packet injection (e.g., Alfa AWUS036ACH)

### 🛠️ Installation

```bash
git clone https://github.com/Nuseo1/WPA3-Attack.git
cd WPA3-Attack
chmod +x Double_SSID_Attack_Tool_WPA2_WPA3.py
```

### 🚀 Usage

```bash
sudo python3 Double_SSID_Attack_Tool_WPA2_WPA3.py
```
*Follow the interactive prompts to scan, select a target, and optionally override the BSSID or Channel.*

### ⚠️ Important Note

This tool is intended **only** for educational and research purposes, and for security assessments on networks you own or have explicit permission to test. Unauthorized use against networks you do not own is illegal.

### 📚 Background

A Rogue AP implementation that creates protocol confusion at Layer 2 by cloning legitimate networks.

---

## 📂 Repository Structure

```
WPA3-Attack/
├── Double_SSID_Attack_Tool_WPA2_WPA3.py   # Main tool
└── README.md
```

> All other scripts and research are now located in the  
> [WPA3-SAE-DoS-Research-Suite](https://github.com/Nuseo1/WPA3-SAE-DoS-Research-Suite).
