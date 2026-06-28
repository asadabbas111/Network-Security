"""
Threat intelligence enrichment for Shadow Watch.

Features:
- Local blacklist (IP and CIDR) checks
- AbuseIPDB check (optional, disabled when API key is empty)
- SQLite caching (TTL 24h) via logger module
- Skips private IPs automatically
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

import config
from . import logger

log = logging.getLogger("shadowwatch.threat_intel")


@dataclass
class ThreatIntelResult:
    is_blacklisted: bool
    abuse_score: int
    country_code: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    usage_type: Optional[str]
    risk_score: float


class ThreatIntel:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blacklist_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._blacklist_ips: set[str] = set()
        self._private_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = [
            ipaddress.ip_network(r, strict=False) for r in config.PRIVATE_IP_RANGES
        ]
        self._blacklist_path = self._resolve_path(config.BLACKLIST_PATH)

        self.reload_blacklist()

    @staticmethod
    def _resolve_path(rel_path: str) -> str:
        base = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(base)
        return os.path.abspath(os.path.join(root, rel_path))

    def reload_blacklist(self) -> None:
        networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        ips: set[str] = set()
        path = self._blacklist_path

        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Shadow Watch blacklist\n")

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = (line or "").strip()
                if not s or s.startswith("#"):
                    continue
                try:
                    if "/" in s:
                        networks.append(ipaddress.ip_network(s, strict=False))
                    else:
                        ipaddress.ip_address(s)
                        ips.add(s)
                except Exception:
                    continue

        with self._lock:
            self._blacklist_networks = networks
            self._blacklist_ips = ips
        log.info("Blacklist loaded: %d IPs, %d CIDRs", len(ips), len(networks))

    def is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return True
        for net in self._private_networks:
            if addr in net:
                return True
        return False

    def _is_blacklisted(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blacklist_ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
            except Exception:
                return False
            for net in self._blacklist_networks:
                if addr in net:
                    return True
        return False

    def lookup(self, ip: str) -> ThreatIntelResult:
        """
        Enrich an IP address using blacklist + AbuseIPDB (optional).
        Caches AbuseIPDB responses in SQLite for 24 hours.
        """
        if not ip or self.is_private(ip):
            return ThreatIntelResult(
                is_blacklisted=False,
                abuse_score=0,
                country_code=None,
                isp=None,
                asn=None,
                usage_type=None,
                risk_score=0.0,
            )

        blacklisted = self._is_blacklisted(ip)

        abuse_score = 0
        cc = None
        isp = None
        asn = None
        usage_type = None
        raw = ""

        cached = logger.get_cached_ip_reputation(ip, ttl_seconds=86400)
        if cached:
            abuse_score = int(cached.get("abuse_score") or 0)
            cc = cached.get("country_code")
            isp = cached.get("isp")
            asn = cached.get("asn")
            usage_type = cached.get("usage_type")
            raw = cached.get("raw_response") or ""
        else:
            if config.ABUSEIPDB_API_KEY:
                try:
                    resp = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                        timeout=10,
                    )
                    raw = resp.text
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        abuse_score = int(data.get("abuseConfidenceScore") or 0)
                        cc = data.get("countryCode")
                        isp = data.get("isp")
                        asn_val = data.get("asn")
                        asn = f"AS{asn_val}" if asn_val else None
                        usage_type = data.get("usageType")
                    else:
                        log.warning("AbuseIPDB check failed for %s: %s", ip, resp.status_code)
                except Exception:
                    log.exception("AbuseIPDB request failed for %s", ip)
            # cache even if empty (prevents spamming)
            try:
                logger.cache_ip_reputation(ip, abuse_score, cc, isp, asn, usage_type, raw_response=raw)
            except Exception:
                log.exception("Failed caching reputation for %s", ip)

        base_score = 0.0
        risk = base_score + (abuse_score * 0.4) + (30.0 if blacklisted else 0.0)

        return ThreatIntelResult(
            is_blacklisted=blacklisted,
            abuse_score=int(abuse_score),
            country_code=cc,
            isp=isp,
            asn=asn,
            usage_type=usage_type,
            risk_score=float(round(risk, 2)),
        )

