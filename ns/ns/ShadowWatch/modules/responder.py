"""
Windows firewall responder for Shadow Watch.

All blocking and unblocking is performed using:
  netsh advfirewall firewall
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from typing import Dict, List

import config
from . import logger as db_logger

log = logging.getLogger("shadowwatch.responder")


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return True
    for r in config.PRIVATE_IP_RANGES:
        try:
            if addr in ipaddress.ip_network(r, strict=False):
                return True
        except Exception:
            continue
    return False


def _rule_exists(ip: str) -> bool:
    return ip in list_blocked()


def block_ip(ip: str, blocked_by: str = "AUTO", reason: str = "") -> Dict[str, str | bool]:
    if not ip:
        return {"success": False, "message": "Missing IP", "ip": ip}
    if _is_private(ip):
        return {"success": False, "message": "Refusing to block private IP", "ip": ip}

    rule_name = f"ShadowWatch-BLOCK-{ip}"
    firewall_ok = False
    try:
        proc = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
            ],
            capture_output=True,
            text=True,
        )
        out = ((proc.stderr or "") + (proc.stdout or "")).lower()
        if proc.returncode == 0:
            firewall_ok = True
        elif "already exists" in out or "duplicate" in out or _rule_exists(ip):
            firewall_ok = True
        else:
            msg = (proc.stderr or proc.stdout or "").strip() or "netsh failed"
            return {"success": False, "message": msg, "ip": ip}

        db_logger.insert_block(ip, blocked_by=blocked_by or "AUTO", reason=reason or "Blocked")
        return {
            "success": True,
            "message": f"Blocked {ip} (firewall + database)",
            "ip": ip,
            "firewall": firewall_ok,
        }
    except Exception as e:
        log.exception("Failed to block IP %s", ip)
        return {"success": False, "message": str(e), "ip": ip}


def unblock_ip(ip: str) -> Dict[str, str | bool]:
    if not ip:
        return {"success": False, "message": "Missing IP", "ip": ip}
    rule_name = f"ShadowWatch-BLOCK-{ip}"
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
        )
        out = ((proc.stderr or "") + (proc.stdout or "")).lower()
        if proc.returncode != 0 and "no rules" not in out and "cannot find" not in out:
            if not _rule_exists(ip):
                db_logger.insert_unblock(ip)
                return {"success": True, "message": f"Unblocked {ip} (removed from database)", "ip": ip}
            msg = (proc.stderr or proc.stdout or "").strip() or "netsh failed"
            return {"success": False, "message": msg, "ip": ip}
        db_logger.insert_unblock(ip)
        return {"success": True, "message": f"Unblocked {ip}", "ip": ip}
    except Exception as e:
        log.exception("Failed to unblock IP %s", ip)
        return {"success": False, "message": str(e), "ip": ip}


def list_blocked() -> List[str]:
    """
    Return a list of IPs that have ShadowWatch-BLOCK-* rules.
    """
    blocked: List[str] = []
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return blocked
        text = proc.stdout or ""
        current_name = ""
        remote_ip = ""
        for line in text.splitlines():
            s = line.strip()
            if s.lower().startswith("rule name:"):
                current_name = s.split(":", 1)[1].strip()
                remote_ip = ""
                if current_name.startswith("ShadowWatch-BLOCK-"):
                    ip_from_name = current_name.replace("ShadowWatch-BLOCK-", "").strip()
                    if ip_from_name and ip_from_name not in blocked:
                        blocked.append(ip_from_name)
            elif current_name.startswith("ShadowWatch-BLOCK-") and s.lower().startswith("remoteip:"):
                remote_ip = s.split(":", 1)[1].strip()
                ip = current_name.replace("ShadowWatch-BLOCK-", "").strip()
                if remote_ip and remote_ip.lower() not in ("any", "localsubnet"):
                    ip = remote_ip.split(",")[0].strip()
                if ip and ip not in blocked:
                    blocked.append(ip)
                elif ip in blocked:
                    pass
                else:
                    if ip:
                        blocked.append(ip)
        return blocked
    except Exception:
        log.exception("Failed listing blocked IPs")
        return blocked


def should_auto_block(severity: str) -> bool:
    if not config.AUTO_BLOCK:
        return False
    return str(severity).upper() in [s.upper() for s in config.AUTO_BLOCK_SEVERITY]

