"""
Shadow Watch — synthetic attack simulator for local testing.

Run as Administrator. Sends traffic to THIS PC's LAN IP (not 127.0.0.1) so the
sniffer on Wi-Fi/Ethernet can see packets.

In Shadow Watch Settings, pick the adapter that shows your LAN IP (e.g. 192.168.x.x).
"""

from __future__ import annotations

import os
import sys
import time

from scapy.all import IP, ICMP, TCP, UDP, conf, send  # type: ignore

conf.use_pcap = True

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from modules.net_iface import get_local_ip, resolve_send_interface

ATTACKER_IP = "198.51.100.99"  # TEST-NET-2 — public range for detection + auto-block tests

SEND_IFACE, TARGET_IP = resolve_send_interface()


def _send(pkt) -> None:
    try:
        send(pkt, iface=SEND_IFACE, verbose=False)
    except OSError as e:
        print(f"Send failed on {SEND_IFACE}: {e}")
        print("Retrying without iface (OS routing)...")
        send(pkt, verbose=False)


def syn_flood(count: int = 120) -> None:
    print(f"[SYN FLOOD] Sending {count} SYN packets via {SEND_IFACE}...")
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=40000 + (i % 1000), dport=80, flags="S")
        _send(pkt)
    print("Done.")


def port_scan(count: int = 20) -> None:
    print(f"[PORT SCAN] Scanning {count} ports...")
    for port in range(1, count + 1):
        pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=50000, dport=port, flags="S")
        _send(pkt)
        time.sleep(0.01)
    print("Done.")


def brute_force(count: int = 25) -> None:
    print(f"[BRUTE FORCE] {count} SYN attempts to port 3389...")
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=45000 + i, dport=3389, flags="S")
        _send(pkt)
    print("Done.")


def icmp_flood(count: int = 60) -> None:
    print(f"[ICMP FLOOD] Sending {count} echo requests...")
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / ICMP(type=8, code=0)
        _send(pkt)
    print("Done.")


def anomaly_burst(count: int = 80) -> None:
    print(f"[ANOMALY] Burst of {count} UDP packets...")
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / UDP(sport=30000 + i, dport=53)
        _send(pkt)
    print("Done.")


def menu() -> None:
    options = {
        "1": ("SYN Flood", syn_flood),
        "2": ("Port Scan", port_scan),
        "3": ("Brute Force (RDP 3389)", brute_force),
        "4": ("ICMP Flood", icmp_flood),
        "5": ("Anomaly Burst (UDP)", anomaly_burst),
        "6": ("Run ALL tests (sequential)", None),
        "0": ("Exit", None),
    }
    print("\n--- IMPORTANT ---")
    print("Target is your LAN IP (NOT 127.0.0.1) so the sniffer can see packets.")
    print(f"  Target IP   : {TARGET_IP}")
    print(f"  Npcap device: {SEND_IFACE}")
    print(f"  Attacker IP : {ATTACKER_IP}")
    print("In Shadow Watch → Settings, select the adapter with IP", TARGET_IP)
    print("-----------------\n")

    while True:
        print("\n=== Shadow Watch Attack Simulator ===")
        print(f"Attacker: {ATTACKER_IP}  →  Target: {TARGET_IP}")
        for k, (name, _) in options.items():
            print(f"  {k}. {name}")
        choice = input("Select option: ").strip()
        if choice == "0":
            break
        if choice == "6":
            for key in ["1", "2", "3", "4", "5"]:
                options[key][1]()
                time.sleep(2)
            continue
        if choice in options and options[choice][1]:
            options[choice][1]()
        else:
            print("Invalid option.")


if __name__ == "__main__":
    try:
        menu()
    except PermissionError:
        print("ERROR: Run as Administrator")
    except KeyboardInterrupt:
        print("\nStopped.")
