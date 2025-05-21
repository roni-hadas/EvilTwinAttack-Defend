# 🕵️‍♂️ Evil Twin Attack Suite

Welcome to the **Evil Twin Attack Suite**, a Python-based wireless security toolkit designed for ethical hackers, penetration testers, and cybersecurity students. This project simulates a rogue access point to perform Evil Twin attacks, forcefully deauthenticating victims from legitimate networks and luring them into a maliciously cloned Wi-Fi hotspot.

---

## 🚀 Features

- 🌐 **Network Scanner** – Discover nearby Wi-Fi networks with SSID, BSSID, and channel info.
- 🎯 **Client Detector** – Identify clients probing for or connected to a specific network.
- 📡 **Evil Twin Beacon Spoofer** – Broadcast a fake access point mimicking a real one using `hostapd`.
- 🧨 **Deauthentication Attacker** – Continuously send deauth frames to force clients off the real AP.
- 🌐 **Captive Portal** – Redirect victim’s web traffic to a custom HTML login page using Flask + dnsmasq.
- 📑 **Modular Design** – Well-structured Python modules, easy to extend or integrate.

---

## 📁 Project Structure

```
.
├── main.py                  # Orchestrates the entire Evil Twin attack flow
├── beacon_spoofer.py       # Launches fake AP with hostapd + captive portal
├── deauth.py               # Sends spoofed deauth frames using Scapy
├── network_scanner.py      # Discovers nearby networks via beacon frames
├── client_scanner.py       # Finds Wi-Fi clients probing or connected
├── web_server/
│   └── server.py           # Flask server for the fake login portal
├── hostapd.conf            # Dynamically generated AP config
├── dnsmasq.conf            # DHCP and DNS redirection config
└── README.md               # You're here!
```

---

## 🛠️ Requirements

- Python 3.x
- Linux (preferably Kali, Parrot, or DragonOS)
- Tools:
  - `hostapd`
  - `dnsmasq`
  - `iwconfig`
  - `iptables`
- Python Libraries:
  - `scapy`
  - `flask`

Install dependencies:
```bash
sudo apt update
sudo apt install hostapd dnsmasq python3-pip
pip3 install scapy flask
```

---

## ⚙️ Usage

1. Put two Wi-Fi interfaces in place:
   - One for hosting the Evil Twin AP
   - One in monitor mode for scanning & deauthing

2. Run the main orchestrator script:
```bash
sudo python3 main.py
```

3. Follow the prompts to:
   - Select interfaces
   - Scan for networks
   - Choose a target
   - Launch the fake AP
   - Start deauth attack

---

## 🧪 Example Flow

- Select `wlan0` as AP interface and `wlan1mon` as monitor interface
- Choose target SSID: `Cafe_FreeWiFi`
- Select a client MAC from the list of active devices
- The beacon spoofer launches a fake AP with the same SSID and BSSID
- Deauth packets flood the victim, forcing reconnection
- Captive portal appears requesting login credentials

---

## ⚠️ Legal Notice

> **This project is for educational and authorized penetration testing only.**
> Do **NOT** run this attack on networks you do not own or have explicit permission to test.
> Misuse of this tool can result in criminal charges. You are responsible for your actions.

---