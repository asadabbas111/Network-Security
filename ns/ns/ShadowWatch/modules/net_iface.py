"""
Windows network interface helpers for Shadow Watch.

On Windows/Npcap, Scapy sniff() and send() must use the NPF device path:
  \\Device\\NPF_{GUID}
Using only {GUID} causes "Error opening adapter (123)" and zero packets captured.
"""

from __future__ import annotations

import platform
import socket
from typing import Dict, List, Optional, Tuple

from scapy.all import conf, get_if_addr, get_if_list  # type: ignore


def get_local_ip() -> str:
    """Return this PC's primary LAN IPv4 (not loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def to_scapy_device(iface: Optional[str]) -> str:
    """
    Convert a GUID, friendly name, or NPF path to the Npcap device string Scapy needs.
    """
    if not iface:
        return resolve_capture_interface()

    iface = str(iface).strip()
    if iface.startswith("\\Device\\NPF"):
        return iface

    candidates = [iface]
    if iface.startswith("{"):
        candidates.append(iface)
    else:
        candidates.append("{" + iface.strip("{}") + "}")

    for key in candidates:
        if key in conf.ifaces:
            dev = getattr(conf.ifaces[key], "network_name", None)
            if dev:
                return str(dev)

    for key, val in conf.ifaces.items():
        if iface.strip("{}").upper() in key.upper():
            dev = getattr(val, "network_name", None)
            if dev:
                return str(dev)

    return iface


def interface_label(iface: Optional[str]) -> str:
    """Human-readable label for title bar / status."""
    if not iface:
        return "—"
    guid = iface
    if iface.startswith("\\Device\\NPF_"):
        guid = "{" + iface.split("_", 1)[-1] + "}"
    for entry in _windows_ifaces():
        if entry.get("id") == guid or entry.get("device") == iface:
            return entry.get("label", entry.get("name", guid))
    return iface


def _ipv4_from_ips(ips: List[str]) -> Optional[str]:
    for ip in ips or []:
        if ":" in ip:
            continue
        if ip.startswith("127."):
            continue
        return ip
    return None


def _windows_ifaces() -> List[Dict[str, str]]:
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        return []

    local_ip = get_local_ip()
    out: List[Dict[str, str]] = []
    for entry in get_windows_if_list():
        guid = str(entry.get("guid") or "").strip()
        if not guid:
            continue
        name = str(entry.get("name") or guid)
        desc = str(entry.get("description") or "")
        ipv4 = _ipv4_from_ips(list(entry.get("ips") or []))
        
        
        if ipv4 != local_ip:
            continue

        low = name.lower()
        if "loopback" in low and "npcap" not in low:
            continue

        device = to_scapy_device(guid)
        label = name
        if ipv4:
            label = f"{name} — {ipv4}"
            if ipv4 == local_ip:
                label += " (active — use this)"
        elif desc:
            label = f"{name} — {desc[:40]}"

        out.append(
            {
                "id": guid,
                "device": device,
                "name": name,
                "label": label,
                "ip": ipv4 or "",
                "description": desc,
                "is_active": str(ipv4 == local_ip),
            }
        )

    out.sort(key=lambda x: (x.get("is_active") != "True", x.get("label", "")))
    return out


def list_interfaces() -> List[Dict[str, str]]:
    """List adapters for the Settings dropdown (id = GUID for storage)."""
    if platform.system().lower() == "windows":
        win = _windows_ifaces()
        if win:
            return win

    out: List[Dict[str, str]] = []
    for iface in get_if_list():
        name = iface or ""
        low = name.lower()
        if "loopback" in low and "npcap" not in low:
            continue
        addr = get_if_addr(iface) or ""
        device = to_scapy_device(name)
        if addr in ("", "0.0.0.0") and not name.startswith("{"):
            continue
        label = f"{addr} — {name}" if addr and not addr.startswith("127.") else name
        out.append(
            {
                "id": name,
                "device": device,
                "name": name,
                "label": label,
                "ip": addr if addr not in ("", "0.0.0.0") else "",
                "description": "",
                "is_active": str(addr == get_local_ip()),
            }
        )
    return out


def resolve_capture_interface(preferred: Optional[str] = None) -> str:
    """
    Return the Npcap device path for sniff() / send().
    `preferred` is usually the GUID saved from Settings.
    """
    if preferred:
        return to_scapy_device(preferred)

    local_ip = get_local_ip()
    if platform.system().lower() == "windows":
        for entry in _windows_ifaces():
            if entry.get("ip") == local_ip:
                return entry["device"]

    for iface in get_if_list():
        low = (iface or "").lower()
        if "loopback" in low and "npcap" not in low:
            continue
        addr = get_if_addr(iface) or ""
        if addr == local_ip:
            return to_scapy_device(iface)

    interfaces = get_if_list()
    if not interfaces:
        raise RuntimeError("No network interfaces detected by Scapy.")
    return to_scapy_device(interfaces[0])


def resolve_send_interface(target_ip: Optional[str] = None) -> Tuple[str, str]:
    """Return (npcap_device_path, target_ip) for test_attacks.py."""
    target_ip = target_ip or get_local_ip()
    if target_ip.startswith("127."):
        target_ip = get_local_ip()

    if platform.system().lower() == "windows":
        for entry in _windows_ifaces():
            if entry.get("ip") == target_ip:
                return entry["device"], target_ip

    try:
        _gw, iface, _src = conf.route.route(target_ip)
        if iface:
            return to_scapy_device(str(iface)), target_ip
    except Exception:
        pass

    return resolve_capture_interface(), target_ip
