# WPA3-Attack Framework

A comprehensive Python-based framework for testing WPA3 network security vulnerabilities based on the research paper **"How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"** published in the Journal of Information Security and Applications (2022).

> ⚠️ **EDUCATIONAL PURPOSES ONLY** - This tool is designed for authorized security testing and research. Unauthorized use against networks you don't own is illegal and unethical.

---

## 📚 Overview

This framework implements a comprehensive suite of attacks targeting WPA3-SAE (Simultaneous Authentication of Equals) implementations across different hardware vendors (Broadcom, Qualcomm, MediaTek).

### Key Features

- **Multi-Band Support**: Separate SAE parameter handling for 2.4 GHz and 5 GHz bands
- **Vendor-Specific Attacks**: Targeted exploits for Broadcom, Qualcomm, and MediaTek chipsets
- **Modern WPA3 Attacks**: Omnivore, Muted, Hasty, Double Decker, Cookie Guzzler
- **Universal Attacks**: Open Authentication floods, Amplification, Back to the Future
- **Client Attacks**: Deauth floods, PMF exploits, Malformed handshake packets
- **Radio Confusion**: Cross-band attacks exploiting dual-band driver vulnerabilities
- **Automated Scanner**: Dynamic channel detection and tracking
- **Multi-Adapter Orchestration**: Coordinate attacks across multiple WiFi interfaces

---

## 🏗️ Repository Structure
WPA3-Attack/
├── README.md # This file
│
├── Python Scripts (Orchestrators)
│ ├── orchestator_master_en.py # Complete arsenal (26 attacks)
│ ├── orchestator_final_mit_allen_details_en.py # Modern attacks (7 types)
│ ├── orchestator_enhanced_plus_en.py # Enhanced attacks (9 types)
│ └── orchestator_Moderne_Angriffe_2023+_en.py # Latest modern attacks
│
├── Documentation
│ ├── documentation_orchestator_master_guide.txt # Master orchestrator guide
│ ├── documentation_orchestator_final_guide.txt # Final orchestrator guide
│ ├── documentation_orchestator_enhanced_guide.txt # Enhanced orchestrator guide
│ └── documentation_orchestator_moderne_guide.txt # Modern attacks guide
│
├── Setup & Configuration
│ ├── Wireshark settings.txt # Wireshark configuration
│ └── Broadcom Qualcomm Mediatek chipset find out.txt # Chipset identification
│
└── Resources
├── Scarlar_Finte_Wireshark_findout.png # SAE parameter extraction guide
├── Screenshot_2025-10-31_14_02_52.png # Reference screenshots
└── Screenshot_2025-10-31_14_03_17.png


---

## 🎯 Attack Arsenal

### 1. **WPA3-Specific Attacks**

#### **Omnivore**
- Floods router with WPA3 connection attempts from constantly changing random MAC addresses
- Forces memory allocation for each fake client until RAM exhaustion
- **Best for**: WPA3 routers with limited memory

#### **Muted**
- Single static MAC address flooding
- Bypasses defenses that only react to multi-source attacks
- **Best for**: WPA3 routers with source-based rate limiting

#### **Hasty**
- Sends both SAE Commit and Confirm frames immediately
- Confuses router state machine
- **Best for**: Routers with poor state management

#### **Double Decker**
- Combines Omnivore + Muted for maximum stress
- Attacks before AND after anti-DoS activation
- **Best for**: Maximum impact scenarios

#### **Cookie Guzzler**
- Exploits SAE anti-clogging token mechanism
- Triggers excessive retransmissions
- **Best for**: Routers with faulty cookie implementation

### 2. **Universal Attacks**

#### **Open Authentication Flood**
- Legacy attack flooding with Open Authentication requests
- Overloads basic CPU queue processing
- **Best for**: 5 GHz band, works on WPA2 & WPA3

#### **Amplification**
- Spoofs legitimate device MAC addresses
- Target AP responds to innocent devices, clogging channel
- **Best for**: 2.4 GHz band (more crowded)

#### **Back to the Future**
- Sends WPA3 packets to WPA2 APs
- Exploits incorrect packet handling bug
- **Best for**: WPA2 APs with memory leaks

### 3. **Vendor-Specific Attacks (Cases 1-13)**

Targeted exploits for:
- **Broadcom**: Cases 1-7 (Denial of Internet, Bad Auth Algo, Status Code exploits, Radio Confusion)
- **Qualcomm**: Cases 8-11 (Bad Auth Algo, Sequence Number, Auth Body exploits, Fuzzing)
- **MediaTek**: Cases 12-13 (Bursty Auth, Radio Confusion)

See `Broadcom Qualcomm Mediatek chipset find out.txt` for chipset identification methods.

### 4. **Client Direct Attacks**

- **Deauth Flood**: Classic deauthentication attack
- **PMF Deauth Exploit**: Bypasses Protected Management Frames
- **Malformed MSG1**: Corrupted 4-Way Handshake packets

### 5. **Generic WPA3-SAE Attacks**

- **Bad Algo**: Invalid authentication algorithm values
- **Bad Seq**: Invalid sequence numbers
- **Bad Status Code**: Invalid status codes in SAE Confirm
- **Empty Frame Confirm**: Empty SAE Confirm frames

---

## 🛠️ Installation

### Prerequisites

System requirements

    Linux (Kali Linux, Ubuntu, etc.)

    Python 3.7+

    Root privileges

    WiFi adapters supporting monitor mode

Install dependencies

sudo apt update
sudo apt install -y python3-pip aircrack-ng wireshark tshark
pip3 install scapy


### WiFi Adapter Setup

Enable monitor mode

sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airmon-ng start wlan1
... for each adapter
Verify monitor interfaces

iwconfig

---

## 📖 Quick Start Guide

### Step 1: Choose Your Orchestrator

Based on your needs, select the appropriate script:

| Script | Attack Count | Best For |
|--------|-------------|----------|
| `orchestator_master_en.py` | 26 attacks | Complete arsenal, advanced users |
| `orchestator_final_mit_allen_details_en.py` | 7 modern attacks | Modern WPA3 vulnerabilities |
| `orchestator_enhanced_plus_en.py` | 9 attacks | Enhanced attack set |
| `orchestator_Moderne_Angriffe_2023+_en.py` | Latest attacks | Newest vulnerabilities |

### Step 2: Extract SAE Parameters

**Critical: You need DIFFERENT parameters for 2.4 GHz and 5 GHz!**

See the visual guide: `Scarlar_Finte_Wireshark_findout.png`

**A. Start Wireshark**
sudo wireshark

**B. Configure Wireshark**
- Follow instructions in `Wireshark settings.txt`
- Select your monitor interface (e.g., wlan0mon)
- Start capturing

**C. Trigger WPA3 Handshake**
- Connect a device to target network with **WRONG password**
- This forces SAE Commit frame transmission

**D. Filter Packets**
1. Configure target BSSIDs

TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:FF"
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"
2. Set SAE parameters (DIFFERENT for each band!)

SAE_SCALAR_2_4_HEX = 'your_2.4ghz_scalar_here'
SAE_FINITE_2_4_HEX = 'your_2.4ghz_finite_here'
SAE_SCALAR_5_HEX = 'your_5ghz_scalar_here'
SAE_FINITE_5_HEX = 'your_5ghz_finite_here'
3. Configure attack adapters

ADAPTER_KONFIGURATION = {
"wlan2mon": {"band": "5GHz", "angriff": "double_decker"},
"wlan3mon": {"band": "2.4GHz", "angriff": "amplification"}
}

### Step 4: Run Attack

sudo python3 orchestator_master_en.py

---

## 📊 Verifying Attack Success

### Method 1: Beacon Jitter Analysis

Monitor beacon timing (should be ~0.1024s normally)

sudo tshark -i wlan0mon
-Y "wlan.fc.type_subtype == 8 && wlan.addr == AA:BB:CC:DD:EE:FF"
-T fields -e frame.time_delta_displayed
Success indicators:
Normal: ~0.1024 seconds
Under attack: >0.5 seconds
Severe: >1.0 seconds

### Method 2: Client Connectivity

- Clients cannot connect
- Existing connections drop
- Network becomes unavailable

### Method 3: Router Behavior

- Web interface becomes unresponsive
- Router may reboot automatically
- LED indicators show unusual activity

---

## 📚 Documentation

Each orchestrator has detailed documentation:

- **Master Orchestrator**: `documentation_orchestator_master_guide.txt`
  - Complete guide to all 26 attacks
  - Vendor-specific configurations
  - Advanced multi-adapter setups

- **Final Orchestrator**: `documentation_orchestator_final_guide.txt`
  - Modern WPA3 attack guide
  - Simplified configuration
  - Best practices

- **Enhanced Orchestrator**: `documentation_orchestator_enhanced_guide.txt`
  - Enhanced attack set documentation
  - PMF exploits
  - EAPOL attacks

- **Modern Attacks**: `documentation_orchestator_moderne_guide.txt`
  - Latest vulnerability exploits
  - 2023+ attack vectors

---

## ⚙️ Configuration Guide

### Scanner vs Manual Mode

Option 1: Automatic Scanner (recommended)

SCANNER_INTERFACE = "wlan0mon" # Detects channels automatically
MANUELLER_KANAL_5GHZ = ""
MANUELLER_KANAL_2_4GHZ = ""
Option 2: Manual Mode (faster startup)

SCANNER_INTERFACE = ""
MANUELLER_KANAL_5GHZ = "36" # Set known channels
MANUELLER_KANAL_2_4GHZ = "1"

### Radio Confusion Attacks

Special cross-band attacks:

TARGET: Crash 5 GHz band
Adapter on 2.4 GHz → shoots at 5 GHz

"wlan2mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"}
TARGET: Crash 2.4 GHz band
Adapter on 5 GHz → shoots at 2.4 GHz

"wlan3mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"}

### Identifying Router Chipset

Use the guide in `Broadcom Qualcomm Mediatek chipset find out.txt` to:
- Identify target router chipset
- Select optimal vendor-specific attacks
- Maximize attack effectiveness

---

## 🎭 Attack Selection Strategy

### Why Mix Attacks? (The "Symphony of Chaos")

Different attacks stress different resources:

1. **CPU Overload**: `open_auth`, `hasty` → Forces logic checks
2. **Memory Exhaustion**: `omnivore`, `double_decker` → RAM allocation
3. **Channel Saturation**: `amplification` → Wireless medium congestion
4. **State Confusion**: `hasty`, `radio_confusion` → Protocol logic errors

**Recommendation**: Use 2-4 different attack types simultaneously across multiple adapters.

### Example Configurations

**Configuration 1: Maximum Impact WPA3**
"wlan1mon": {"band": "5GHz", "angriff": "double_decker"},
"wlan2mon": {"band": "5GHz", "angriff": "open_auth"},
"wlan3mon": {"band": "2.4GHz", "angriff": "amplification"},
"wlan4mon": {"band": "2.4GHz", "angriff": "cookie_guzzler"}

**Configuration 2: Broadcom Specific**
"wlan1mon": {"band": "5GHz", "angriff": "case7_back_to_the_future"},
"wlan2mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"},
"wlan3mon": {"band": "5GHz", "angriff": "case2_bad_auth_algo_broadcom"}

---

## 🔒 Legal & Ethical Considerations

### ⚠️ WARNING

This tool is provided for **educational and authorized security testing purposes only**.

**Legal uses:**
- Testing YOUR OWN networks
- Authorized penetration testing with written permission
- Academic research with proper authorization
- Security auditing with client consent

**Illegal uses:**
- Attacking networks without permission
- Disrupting public or private networks
- Causing harm or unauthorized access
- Any use violating local laws

**By using this tool, you agree:**
- You have full authorization to test target networks
- You understand local laws regarding network security testing
- You accept full responsibility for your actions
- The authors are not liable for misuse

---

## 🧪 Research Background

This framework is based on the academic paper:

**"How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"**
- Published: Journal of Information Security and Applications (2022)
- Focus: Systematic analysis of WPA3-SAE vulnerabilities across vendors

### Key Findings

1. **Cookie Guzzler**: Most effective against routers with faulty anti-clogging implementation
2. **Radio Confusion**: Exploits poor dual-band driver isolation
3. **Vendor Variations**: Significant differences in vulnerability across chipset manufacturers
4. **Multi-Vector Effectiveness**: Combined attacks 3-5x more effective than single-type attacks

---

## 🛡️ Defense Recommendations

For network administrators:

1. **Firmware Updates**: Keep router firmware current
2. **Rate Limiting**: Implement strict authentication attempt limits
3. **Monitoring**: Deploy IDS/IPS to detect attack patterns
4. **Dual-Band Isolation**: Ensure proper isolation between 2.4/5 GHz bands
5. **PMF**: Enable Protected Management Frames (802.11w)
6. **Resource Monitoring**: Alert on abnormal CPU/memory usage

---

## 📝 Troubleshooting

### Common Issues

**"Failed to set channel"**
Verify monitor mode

iwconfig
Manual channel set

sudo iwconfig wlan0mon channel 1

**"Invalid SAE parameters"**
- Ensure hex strings have no spaces
- Verify copied from correct frame type (Commit, not Confirm)
- Check you used wrong password when capturing
- See `Scarlar_Finte_Wireshark_findout.png` for visual guide

**"No effect on router"**
- Verify target is actually WPA3
- Confirm SAE parameters match THIS network (separate for each band!)
- Try 2-3 minutes continuous attack
- Check beacon jitter to verify impact
- Consult chipset identification guide

**"Permission denied"**
Always run with sudo

sudo python3 script.py

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly on YOUR OWN networks
4. Submit pull request with detailed description

---

## 📄 License

This project is provided "as-is" for educational purposes.

---

## 📚 References

1. Original Research Paper: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
2. WPA3 Specification: IEEE 802.11-2020
3. SAE Protocol: RFC 7664
4. Scapy Documentation: https://scapy.net

---

## 👤 Author

**Nuseo1**

If you find this research useful, please:
- ⭐ Star this repository
- 📖 Cite the original research paper
- 🔒 Use responsibly and ethically

---

## 📦 Version History

- **Dec 3, 2025**: Split SAE parameters for dual-band support
- **Dec 3, 2025**: Enhanced documentation and guides
- **Dec 2, 2025**: Initial repository setup

---

## ⚠️ Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS SOFTWARE. USE AT YOUR OWN RISK AND ONLY ON NETWORKS YOU ARE AUTHORIZED TO TEST.

---

**Last Updated**: December, 2025


