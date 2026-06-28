"""
SQLite logging and query layer for Shadow Watch.

Responsibilities:
- Initialize and migrate the SQLite schema automatically.
- Provide thread-safe insert/query helpers for alerts, firewall actions, intel cache, and traffic stats.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import config

_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _db_abspath() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    # modules/ -> ShadowWatch/
    root = os.path.dirname(base)
    return os.path.abspath(os.path.join(root, config.DB_PATH))


def _connect() -> sqlite3.Connection:
    path = _db_abspath()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def initialize_database() -> None:
    """Create the database and all tables/indexes if not present."""
    schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.executescript(schema_sql)
        finally:
            conn.close()


def get_db_size_mb() -> float:
    path = _db_abspath()
    if not os.path.exists(path):
        return 0.0
    return round(os.path.getsize(path) / (1024 * 1024), 2)


def insert_alert(threat_event: Any, threat_intel_result: Any) -> int:
    """
    Insert an alert row.

    threat_event: ThreatEvent dataclass
    threat_intel_result: ThreatIntelResult dataclass
    """
    ts = getattr(threat_event, "timestamp", None) or _utc_now_iso()
    source_ip = getattr(threat_event, "source_ip", "")
    destination_ip = getattr(threat_event, "destination_ip", "")
    attack_type = getattr(threat_event, "attack_type", "")
    severity = getattr(threat_event, "severity", "")
    confidence = int(getattr(threat_event, "confidence", 0))
    packet_count = int(getattr(threat_event, "packet_count", 0))
    time_window = int(getattr(threat_event, "time_window", 0))
    extra = getattr(threat_event, "extra", {}) or {}

    is_blacklisted = bool(getattr(threat_intel_result, "is_blacklisted", False))
    abuse_score = int(getattr(threat_intel_result, "abuse_score", 0) or 0)
    cc = getattr(threat_intel_result, "country_code", None)
    isp = getattr(threat_intel_result, "isp", None)
    asn = getattr(threat_intel_result, "asn", None)

    base_score = float(extra.get("base_score", 0.0))
    threat_score = float(base_score + (abuse_score * 0.4) + (30.0 if is_blacklisted else 0.0))

    raw_data = {
        "event": _safe_asdict(threat_event),
        "intel": _safe_asdict(threat_intel_result),
    }

    with _LOCK:
        conn = _connect()
        try:
            with conn:
                cur = conn.execute(
                    """
                    INSERT INTO alerts(
                      timestamp, source_ip, destination_ip, attack_type, severity, confidence,
                      packet_count, time_window, threat_score, country_code, isp, asn,
                      auto_blocked, resolved, notes, raw_data
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ts,
                        source_ip,
                        destination_ip,
                        attack_type,
                        severity,
                        confidence,
                        packet_count,
                        time_window,
                        threat_score,
                        cc,
                        isp,
                        asn,
                        0,
                        0,
                        None,
                        json.dumps(raw_data, ensure_ascii=False),
                    ),
                )
                return int(cur.lastrowid)
        finally:
            conn.close()


def mark_alert_auto_blocked(alert_id: int) -> None:
    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.execute("UPDATE alerts SET auto_blocked=1 WHERE id=?", (int(alert_id),))
        finally:
            conn.close()


def insert_block(ip: str, blocked_by: str, reason: str) -> None:
    now = _utc_now_iso()
    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO blocked_ips(ip_address, blocked_at, blocked_by, reason, is_active)
                    VALUES(?,?,?,?,1)
                    ON CONFLICT(ip_address) DO UPDATE SET
                      blocked_at=excluded.blocked_at,
                      blocked_by=excluded.blocked_by,
                      reason=excluded.reason,
                      unblocked_at=NULL,
                      is_active=1
                    """,
                    (ip, now, blocked_by or "AUTO", reason),
                )
        finally:
            conn.close()


def insert_unblock(ip: str) -> None:
    now = _utc_now_iso()
    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.execute(
                    """
                    UPDATE blocked_ips
                    SET unblocked_at=?, is_active=0
                    WHERE ip_address=? AND is_active=1
                    """,
                    (now, ip),
                )
        finally:
            conn.close()


def insert_traffic_stat(stats_dict: Dict[str, Any]) -> None:
    ts = _utc_now_iso()
    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO traffic_stats(
                      timestamp, packets_per_second, bytes_per_second, tcp_count, udp_count, icmp_count, unique_sources
                    ) VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        ts,
                        float(stats_dict.get("packets_per_second", 0.0)),
                        float(stats_dict.get("bytes_per_second", 0.0)),
                        int(stats_dict.get("tcp_count", 0)),
                        int(stats_dict.get("udp_count", 0)),
                        int(stats_dict.get("icmp_count", 0)),
                        int(stats_dict.get("unique_sources", 0)),
                    ),
                )
        finally:
            conn.close()


def cache_ip_reputation(
    ip_address: str,
    abuse_score: int,
    country_code: Optional[str],
    isp: Optional[str],
    asn: Optional[str],
    usage_type: Optional[str],
    raw_response: str,
    last_checked_iso: Optional[str] = None,
) -> None:
    last_checked = last_checked_iso or _utc_now_iso()
    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO ip_reputation(
                      ip_address, abuse_score, country_code, isp, asn, usage_type, last_checked, raw_response
                    ) VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                      abuse_score=excluded.abuse_score,
                      country_code=excluded.country_code,
                      isp=excluded.isp,
                      asn=excluded.asn,
                      usage_type=excluded.usage_type,
                      last_checked=excluded.last_checked,
                      raw_response=excluded.raw_response
                    """,
                    (ip_address, int(abuse_score), country_code, isp, asn, usage_type, last_checked, raw_response),
                )
        finally:
            conn.close()


def get_cached_ip_reputation(ip_address: str, ttl_seconds: int = 86400) -> Optional[Dict[str, Any]]:
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM ip_reputation WHERE ip_address=?",
                (ip_address,),
            ).fetchone()
            if not row:
                return None
            last_checked = row["last_checked"]
            try:
                dt = datetime.strptime(last_checked, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except Exception:
                return None
            if datetime.now(timezone.utc) - dt > timedelta(seconds=ttl_seconds):
                return None
            return dict(row)
        finally:
            conn.close()


def get_alerts(limit: int = 100, severity: Optional[str] = None, hours: int = 24) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 2000))
    hours = max(1, min(int(hours), 24 * 30))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    where = "WHERE timestamp >= ?"
    params: List[Any] = [since_iso]
    if severity:
        where += " AND severity = ?"
        params.append(severity.upper())

    sql = f"""
      SELECT * FROM alerts
      {where}
      ORDER BY id DESC
      LIMIT ?
    """
    params.append(limit)

    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_severity_counts(hours: int = 24) -> Dict[str, int]:
    """Fast severity breakdown via SQL (avoids loading thousands of rows)."""
    hours = max(1, min(int(hours), 24 * 30))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS c
                FROM alerts
                WHERE timestamp >= ?
                GROUP BY severity
                """,
                (since_iso,),
            ).fetchall()
            for r in rows:
                sev = str(r["severity"]).upper()
                if sev in counts:
                    counts[sev] = int(r["c"])
            return counts
        finally:
            conn.close()


def get_heatmap_grid(hours: int = 24 * 7) -> List[List[int]]:
    """Return 24x7 grid [hour][weekday] with alert counts (Mon=0 .. Sun=6)."""
    hours = max(1, min(int(hours), 24 * 7))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    grid = [[0 for _ in range(7)] for _ in range(24)]
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT
                  CAST(strftime('%H', timestamp) AS INTEGER) AS hour,
                  CAST(strftime('%w', timestamp) AS INTEGER) AS dow,
                  COUNT(*) AS c
                FROM alerts
                WHERE timestamp >= ?
                GROUP BY hour, dow
                """,
                (since_iso,),
            ).fetchall()
            for r in rows:
                hour = int(r["hour"])
                # SQLite %w: 0=Sunday .. 6=Saturday -> Python Mon=0 .. Sun=6
                dow = (int(r["dow"]) + 6) % 7
                if 0 <= hour < 24 and 0 <= dow < 7:
                    grid[hour][dow] = int(r["c"])
            return grid
        finally:
            conn.close()


def get_stats_summary() -> Dict[str, Any]:
    with _LOCK:
        conn = _connect()
        try:
            total_alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            high_alerts = conn.execute(
                "SELECT COUNT(*) AS c FROM alerts WHERE severity IN ('HIGH','CRITICAL')"
            ).fetchone()["c"]
            blocked_count = conn.execute(
                "SELECT COUNT(*) AS c FROM blocked_ips WHERE is_active=1"
            ).fetchone()["c"]
            packets_captured = conn.execute("SELECT COUNT(*) AS c FROM traffic_stats").fetchone()["c"]
            return {
                "total_alerts": int(total_alerts),
                "high_alerts": int(high_alerts),
                "blocked_count": int(blocked_count),
                "packets_captured": int(packets_captured),
            }
        finally:
            conn.close()


def get_attack_distribution(hours: int = 24) -> List[Tuple[str, int]]:
    hours = max(1, min(int(hours), 24 * 30))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT attack_type, COUNT(*) AS c
                FROM alerts
                WHERE timestamp >= ?
                GROUP BY attack_type
                ORDER BY c DESC
                """,
                (since_iso,),
            ).fetchall()
            return [(r["attack_type"], int(r["c"])) for r in rows]
        finally:
            conn.close()


def get_top_attackers(limit: int = 10, hours: int = 24) -> List[Tuple[str, int]]:
    limit = max(1, min(int(limit), 100))
    hours = max(1, min(int(hours), 24 * 30))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT source_ip, COUNT(*) AS c
                FROM alerts
                WHERE timestamp >= ?
                GROUP BY source_ip
                ORDER BY c DESC
                LIMIT ?
                """,
                (since_iso, limit),
            ).fetchall()
            return [(r["source_ip"], int(r["c"])) for r in rows]
        finally:
            conn.close()


def get_timeline(hours: int = 24) -> List[Tuple[str, int]]:
    hours = max(1, min(int(hours), 24 * 30))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT substr(timestamp, 1, 13) || ':00:00Z' AS hour_bucket, COUNT(*) AS c
                FROM alerts
                WHERE timestamp >= ?
                GROUP BY hour_bucket
                ORDER BY hour_bucket ASC
                """,
                (since_iso,),
            ).fetchall()
            return [(r["hour_bucket"], int(r["c"])) for r in rows]
        finally:
            conn.close()


def sync_blocked_from_firewall(firewall_ips: List[str]) -> None:
    """Ensure every Windows firewall ShadowWatch rule exists in SQLite."""
    for ip in firewall_ips:
        if not ip:
            continue
        insert_block(ip, blocked_by="FIREWALL", reason="Synced from Windows Firewall")


def get_blocked_ips(active_only: bool = True) -> List[Dict[str, Any]]:
    where = "WHERE is_active=1" if active_only else ""
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM blocked_ips {where} ORDER BY id DESC",
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_traffic_history(minutes: int = 60) -> List[Dict[str, Any]]:
    minutes = max(1, min(int(minutes), 24 * 60))
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT timestamp, packets_per_second, bytes_per_second, tcp_count, udp_count, icmp_count, unique_sources
                FROM traffic_stats
                WHERE timestamp >= ?
                ORDER BY id ASC
                """,
                (since_iso,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def resolve_alert(alert_id: int) -> None:
    with _LOCK:
        conn = _connect()
        try:
            with conn:
                conn.execute("UPDATE alerts SET resolved=1 WHERE id=?", (int(alert_id),))
        finally:
            conn.close()


def _safe_asdict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "__dict__"):
        out: Dict[str, Any] = {}
        for k, v in obj.__dict__.items():
            try:
                json.dumps(v, ensure_ascii=False)
                out[k] = v
            except Exception:
                out[k] = str(v)
        return out
    try:
        return dict(obj)  # type: ignore[arg-type]
    except Exception:
        return {"value": str(obj)}

