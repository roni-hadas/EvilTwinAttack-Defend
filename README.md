# 📡 Evil Twin Attack Suite & Defense

## Overview

This project includes an **Evil Twin Attack toolkit** (offensive) and two **detection mechanisms** (defensive) — a **Machine Learning-based IDS** and a **Manual Defense Sniffer** — that are designed for educational and authorized penetration testing.

---

## Group Members:
- Roni Hadas
- Anthonios Deeb
- Wasim Sheblany

---

## 🚨 Evil Twin Attack Toolkit

![Evil Twin Attack Diagram](images/attack_diagram.png)


- **Purpose:** Simulates a rogue access point that mimics a real Wi-Fi network, forcing users to disconnect and reconnect to the attacker's fake AP. The attacker can then capture credentials or manipulate user traffic.
- **Key Scripts:**
  - **main.py:** Orchestrates the entire Evil Twin attack flow.
  - **beacon_spoofer.py:** Uses hostapd to broadcast a fake AP with the same SSID as the legitimate network.
  - **deauth.py:** Sends deauthentication frames (via Scapy) to disconnect clients from the real AP, forcing them to connect to the fake one.
  - **client_scanner.py:** Identifies client devices (stations) connected to the real AP, useful for targeting specific victims.
  - **dnsmasq.conf & hostapd.conf:** Provide DHCP/DNS redirection and Wi-Fi configurations for the fake AP.
  - **web_server/server.py:** Hosts a captive portal (login page) using Flask, capturing credentials or simulating phishing attacks.
- **Attack Logic:** The attacker deauthenticates clients from the real AP, then uses a cloned SSID to lure them into connecting to the rogue AP. The captive portal then captures credentials.

---

## 🔎 Detection Mechanisms

### 1️⃣ Machine Learning-Based IDS

- **Purpose:** Real-time classification of packets using features extracted from live network traffic.
- **Dataset:** AWID3 dataset ([AWID3](https://icsdweb.aegean.gr/awid/awid3)), preprocessed and labeled with 'Normal', 'Evil_Twin', and 'Deauth' classes.
- **Feature List:** Includes fields like `wlan.fc.type`, `wlan_radio.data_rate`, `frame.len`, etc., derived from tshark captures. These features represent packet-level statistics.
- **Script Summary:**
  - Uses **tshark** to capture packets live and extract features defined in a `feature_header.txt` file.
  - Applies a **RandomForestClassifier** to classify each packet as Normal, Evil_Twin, or Deauth.
  - Continuously prints alerts if suspicious activity is detected.
  - **Logic:** Every line of live capture is parsed, missing values are replaced with zeros, and each row is classified. If the label is not 'Normal', an alert is printed.

### 2️⃣ Manual Defense Sniffer

- **Purpose:** Uses scapy to sniff Wi-Fi packets in real time and manually identify suspicious APs and deauth attacks.
- **Script Summary:**
  - Starts by setting the interface to monitor mode and channel hopping across Wi-Fi channels.
  - **Deauthentication Detection:**
    - Counts the number of unprotected deauth/disas frames sent by the real AP or to the user’s device.
    - If the count exceeds a threshold within a time window, an alert is triggered.
  - **Evil Twin Detection:**
    - Monitors beacon frames.
    - If a beacon has the same SSID as the real AP but a different BSSID, it increments a counter for that BSSID.
    - After a time window, if a suspicious BSSID appears too many times, an alert is triggered.
  - **Logic:** Relies on thresholds for suspicious frames and channel hopping to catch APs on all channels.
  - - **Defense**:
    - When an Evil Twin is detected, the script can launch a **countermeasure**: it sends deauth packets **back to the Evil Twin AP** using the `send_deauth_to_ap` function (detailed below).
    - **Logic**:
      - Uses `scapy` to craft a deauthentication frame with:
        - `addr1`: the broadcast address (so all clients see it)
        - `addr2` and `addr3`: the attacker’s Evil Twin BSSID.
      - Sends this packet multiple times (default 5) to disrupt the fake AP’s connectivity and potentially disconnect its clients.


---
## 📁 Installation & Setup

**Requirements:**
- Python 3.x
- Linux with a wireless adapter supporting monitor mode
- Tools: `hostapd`, `dnsmasq`, `iwconfig`, `iptables`

**Setup for ML based-detection:**
```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies from requirements.txt
pip install -r requirements.txt

```
## 🧪 Usage

###  Evil Twin Attack

This part of the suite simulates an Evil Twin attack by selecting an interface, scanning for nearby networks, selecting a victim network and client, then launching the attack.

**Step-by-step guide:**

1. **Interface Selection**
   - Puts your wireless adapter into monitor mode.
   - Example:
     ```bash
     python3 main.py
     ```
   - Prompts:
     - "Enter your wireless interface (e.g., wlxc83a35c2fcb0):"

2. **Network Scan**
   - Scans for nearby Wi-Fi networks.
   - Prompts:
     - Lists all discovered SSIDs, BSSIDs, and channels.
     - Choose a target network to spoof.

3. **Client Detection**
   - Identifies devices probing or connected to the chosen network.
   - Prompts:
     - Lists discovered clients (MAC addresses).
     - Select a client to deauth.

4. **Evil Twin Deployment**
   - Launches the beacon spoofer that creates a fake AP with the same SSID.
   - Example:
     - Starts `beacon_spoofer.py` in the background.
     - Prompts you to press Enter to continue when ready.

5. **Deauth Attack**
   - Sends deauthentication packets to forcibly disconnect the victim from the real AP.
   - Example:
     - Uses the victim's MAC and real AP MAC.

6. **Cleanup**
   - Reverts the interface back to managed mode and cleans up processes.

---

### Machine Learning Defense

Monitors network traffic in real time and classifies packets using a trained Random Forest model based on AWID3 dataset. 

- **Start the ML-based defense:**
  ```bash
  sudo python3 ml_defense.py
  
---
### Manual Defense

Another IDS classifier works by manually analyzing each sniffed packet using 'scapy'

- **Start the Manual IDS defense:**
  ```bash
  sudo python3 manual_defense.py
  ```
 --- 
### ⚠️ Limitations

- **Machine Learning Classifier:** Currently, the machine learning-based IDS script only performs detection; it lacks a built-in defensive countermeasure mechanism. However, the manual defense script does implement active defense measures like deauth counterattacks.
- **Data Imbalance:** The training dataset (AWID3) used for building the model is imbalanced, containing significantly more normal samples than attack samples. This may affect the model’s ability to generalize to unseen attacks in real-world environments.
- **Dataset Scope:** The classifier was trained on publicly available datasets only and may not fully capture all variations of real-world Evil Twin attacks or other emerging threats.
- **Environmental Noise:** In highly congested Wi-Fi environments, legitimate networks might produce noisy traffic that could increase false positives and impact detection accuracy.
- **Monitor Mode Requirement:** Both detection and defense scripts rely on monitor mode, which may not be supported by all wireless cards and can disrupt normal connectivity on the device running the script.


## 📝 Summary

| Component               | Description |
|-------------------------|-------------|
| **Evil Twin Attack Suite** | Offensive toolkit: fake AP (hostapd), deauth frames (Scapy), captive portal (Flask). |
| **Machine Learning IDS**  | Real-time detection using RandomForest trained on AWID3, using packet features from tshark. |
| **Manual Defense Sniffer** | Real-time detection using scapy, thresholds, and BSSID/SSID logic, with channel hopping. |

**Note:** For training the ML model, we used the AWID3 dataset: [AWID3](https://icsdweb.aegean.gr/awid/awid3).
