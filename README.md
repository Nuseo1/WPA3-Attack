# Double SSID Attack Tool (WPA2/WPA3)

> **Note:** The WPA3‑SAE DoS tool previously included here has been moved to its own repository:  
> 👉 [WPA3-SAE-DoS-Research-Suite](https://github.com/Nuseo1/WPA3-SAE-DoS-Research-Suite)

---

## 📡 Double_SSID_Attack_Tool_WPA2_WPA3.py

A Python tool for testing WPA3 Transition Mode vulnerabilities (Double SSID attack). It creates a WPA2 network (with a known password) and a WPA3 network with the same SSID simultaneously, forcing clients to downgrade to WPA2 and capturing the 4‑way handshake.

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
sudo python3 Double_SSID_Attack_Tool_WPA2_WPA3.py -s <SSID> -c <channel> -i <interface>
```

**Example:**

```bash
sudo python3 Double_SSID_Attack_Tool_WPA2_WPA3.py -s TestNet -c 6 -i wlan0
```

Parameters:

- `-s`, `--ssid` : The SSID broadcast by both networks.
- `-c`, `--channel` : Wi‑Fi channel (1–13 for 2.4 GHz).
- `-i`, `--interface` : Name of the wireless interface in monitor mode.
- Additionally, the WPA2 password can be set with `--wpa2-pass` (default: `12345678`).

### ⚠️ Important Note

This tool is intended **only** for educational and research purposes, and for security assessments on networks you own or have explicit permission to test. Unauthorized use against networks you do not own is illegal.

### 📚 Background

WPA3 Transition Mode allows an access point to serve both WPA2 and WPA3 clients simultaneously. An attacker can broadcast a rogue WPA2 network with the same name, causing clients to fall back to the less secure WPA2 and exposing the WPA2 handshake for later decryption. This tool automates that attack.

---

## 📂 Repository Structure

```
WPA3-Attack/
├── Double_SSID_Attack_Tool_WPA2_WPA3.py   # Main tool
└── README.md
```

> All other scripts and research are now located in the  
> [WPA3-SAE-DoS-Research-Suite](https://github.com/Nuseo1/WPA3-SAE-DoS-Research-Suite).
