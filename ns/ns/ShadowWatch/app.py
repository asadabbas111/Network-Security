"""
Shadow Watch — SOC-Level Intrusion Detection & Response System
Air University, Dept. of Cyber Security — v2.0

Run as Administrator on Windows 10/11.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import psutil
from flask import Flask, jsonify, render_template, request, send_file
from flask_socketio import SocketIO
import config
from modules.net_iface import get_local_ip, list_interfaces
from modules import logger as db
from modules.alerts import AlertsCoordinator
from modules.detector import Detector
from modules.responder import block_ip, list_blocked, unblock_ip
from modules.sniffer import Sniffer
from modules.threat_intel import ThreatIntel

APP_NAME = "Shadow Watch"
APP_SUBTITLE = "SOC-Level Intrusion Detection & Response System"
APP_VERSION = "v2.0"

_start_time = time.time()
_engine_lock = threading.Lock()
_db_stats_cache: Dict[str, Any] = {"ts": 0.0, "summary": {}, "severity": {}}
_DB_STATS_CACHE_SEC = 5.0
_sniffer: Optional[Sniffer] = None
_detector: Optional[Detector] = None
_alerts: Optional[AlertsCoordinator] = None
_intel = ThreatIntel()
_engine_running = False
_recent_packet_clients: List[Dict[str, Any]] = []


def setup_logging() -> None:
    log_path = os.path.join(ROOT, "shadowwatch.log")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)


setup_logging()
log = logging.getLogger("shadowwatch.app")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "shadowwatch-soc-key-change-in-production"
# threading mode: compatible with Python 3.14+ (eventlet does not support 3.13+ yet)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


def emit_activity(message: str, level: str = "info") -> None:
    """Push a toast notification to all connected dashboards."""
    try:
        socketio.emit(
            "activity",
            {"message": message, "level": level, "timestamp": time.time()},
            namespace="/",
        )
    except Exception:
        log.exception("Failed to emit activity toast")


def _uptime_seconds() -> int:
    return int(time.time() - _start_time)


def _mbps(bytes_per_second: float) -> float:
    return round((bytes_per_second * 8.0) / (1024 * 1024), 3)


def _ensure_engine() -> None:
    global _sniffer, _detector, _alerts, _engine_running
    with _engine_lock:
        if _engine_running:
            return
        iface = config.INTERFACE
        _sniffer = Sniffer(interface=iface)
        _sniffer.start()
        _detector = Detector(_sniffer.queue)
        _detector.start()
        _alerts = AlertsCoordinator(_detector.get_event_queue())
        _alerts.start(socketio)
        _engine_running = True
        log.info("Engine started")
        emit_activity(f"Engine started on {(_sniffer.active_interface if _sniffer else 'interface')}", "success")


def _stop_engine() -> None:
    global _engine_running
    with _engine_lock:
        if _alerts:
            _alerts.stop()
        if _detector:
            _detector.stop()
        if _sniffer:
            _sniffer.stop()
        _engine_running = False
        log.info("Engine stopped")
        emit_activity("Capture engine stopped", "warning")


def _cached_db_stats() -> tuple[Dict[str, Any], Dict[str, int]]:
    now = time.time()
    if now - _db_stats_cache["ts"] < _DB_STATS_CACHE_SEC:
        return _db_stats_cache["summary"], _db_stats_cache["severity"]
    summary = db.get_stats_summary()
    severity = db.get_severity_counts(24)
    _db_stats_cache["ts"] = now
    _db_stats_cache["summary"] = summary
    _db_stats_cache["severity"] = severity
    return summary, severity


def _stats_payload() -> Dict[str, Any]:
    summary, severity_counts = _cached_db_stats()
    sniffer_stats = _sniffer.get_stats() if _sniffer else {}
    pps = float(sniffer_stats.get("packets_per_second", 0.0))
    bps = float(sniffer_stats.get("bytes_per_second", 0.0))
    return {
        "uptime_seconds": _uptime_seconds(),
        "packets_captured": int(sniffer_stats.get("packets_captured", 0)),
        "pps": round(pps, 2),
        "mbps": _mbps(bps),
        "threats_total": int(summary.get("total_alerts", 0)),
        "blocked_total": int(summary.get("blocked_count", 0)),
        "severity_counts": severity_counts,
        "tcp_count": int(sniffer_stats.get("tcp_count", 0)),
        "udp_count": int(sniffer_stats.get("udp_count", 0)),
        "icmp_count": int(sniffer_stats.get("icmp_count", 0)),
    }


def background_emitter() -> None:
    last_traffic_insert = 0.0
    while True:
        try:
            if _engine_running and _sniffer:
                stats = _sniffer.get_stats()
                payload = _stats_payload()
                socketio.emit("stats_update", payload, namespace="/")
                socketio.emit(
                    "traffic_data",
                    {
                        "pps": payload["pps"],
                        "mbps": payload["mbps"],
                        "tcp_count": payload["tcp_count"],
                        "udp_count": payload["udp_count"],
                        "icmp_count": payload["icmp_count"],
                        "packets_captured": payload["packets_captured"],
                    },
                    namespace="/",
                )
                now = time.time()
                if now - last_traffic_insert >= 30:
                    db.insert_traffic_stat(
                        {
                            "packets_per_second": stats.get("packets_per_second", 0.0),
                            "bytes_per_second": stats.get("bytes_per_second", 0.0),
                            "tcp_count": int(stats.get("tcp_count", 0)),
                            "udp_count": int(stats.get("udp_count", 0)),
                            "icmp_count": int(stats.get("icmp_count", 0)),
                            "unique_sources": 0,
                        }
                    )
                    last_traffic_insert = now
        except Exception:
            log.exception("Background emitter error")
        time.sleep(2)


@app.route("/")
def page_dashboard():
    return render_template("dashboard.html", page="dashboard", title="Dashboard")


@app.route("/alerts")
def page_alerts():
    return render_template("alerts.html", page="alerts", title="Alerts")


@app.route("/traffic")
def page_traffic():
    return render_template("traffic.html", page="traffic", title="Traffic")


@app.route("/blocked")
def page_blocked():
    return render_template("blocked.html", page="blocked", title="Blocked IPs")


@app.route("/analytics")
def page_analytics():
    return render_template("analytics.html", page="analytics", title="Analytics")


@app.route("/settings")
def page_settings():
    return render_template("settings.html", page="settings", title="Settings")


@app.get("/api/stats")
def api_stats():
    return jsonify(_stats_payload())


@app.get("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 100))
    severity = request.args.get("severity") or None
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_alerts(limit=limit, severity=severity, hours=hours))


@app.get("/api/attack-distribution")
def api_attack_distribution():
    data = db.get_attack_distribution(hours=int(request.args.get("hours", 24)))
    return jsonify([{"attack_type": a, "count": c} for a, c in data])


@app.get("/api/timeline")
def api_timeline():
    data = db.get_timeline(hours=int(request.args.get("hours", 24)))
    return jsonify([{"hour": h, "count": c} for h, c in data])


@app.get("/api/top-attackers")
def api_top_attackers():
    data = db.get_top_attackers(limit=int(request.args.get("limit", 10)))
    return jsonify([{"ip": ip, "count": c} for ip, c in data])


@app.get("/api/traffic")
def api_traffic():
    rows = db.get_traffic_history(minutes=int(request.args.get("minutes", 60)))
    out = []
    for r in rows:
        bps = float(r.get("bytes_per_second", 0.0))
        out.append(
            {
                "timestamp": r.get("timestamp"),
                "pps": float(r.get("packets_per_second", 0.0)),
                "mbps": _mbps(bps),
            }
        )
    return jsonify(out)


@app.get("/api/packets")
def api_packets():
    if not _sniffer:
        return jsonify([])
    return jsonify(_sniffer.get_recent_packets(limit=int(request.args.get("limit", 50))))


@app.get("/api/blocked")
def api_blocked():
    active = request.args.get("active_only", "1") != "0"
    try:
        fw_ips = list_blocked()
        if active and fw_ips:
            db.sync_blocked_from_firewall(fw_ips)
    except Exception:
        log.exception("Firewall sync failed")
    return jsonify(db.get_blocked_ips(active_only=active))


@app.post("/api/block")
def api_block():
    body = request.get_json(silent=True) or {}
    ip = str(body.get("ip", "")).strip()
    reason = str(body.get("reason", "Manual block")).strip()
    result = block_ip(ip, blocked_by="MANUAL", reason=reason)
    if result.get("success"):
        socketio.emit("ip_blocked", {"ip": ip, "reason": reason, "manual": True}, namespace="/")
        emit_activity(f"Blocked IP {ip}", "success")
    else:
        emit_activity(f"Block failed: {result.get('message', ip)}", "error")
    return jsonify(result)


@app.post("/api/unblock")
def api_unblock():
    body = request.get_json(silent=True) or {}
    ip = str(body.get("ip", "")).strip()
    result = unblock_ip(ip)
    if result.get("success"):
        emit_activity(f"Unblocked IP {ip}", "success")
    else:
        emit_activity(f"Unblock failed: {result.get('message', ip)}", "error")
    return jsonify(result)


@app.post("/api/resolve")
def api_resolve():
    body = request.get_json(silent=True) or {}
    alert_id = int(body.get("alert_id", 0))
    if alert_id:
        db.resolve_alert(alert_id)
        emit_activity(f"Alert #{alert_id} marked resolved", "info")
    return jsonify({"success": True, "alert_id": alert_id})


@app.get("/api/status")
def api_status():
    mem = psutil.Process().memory_info().rss / (1024 * 1024)
    return jsonify(
        {
            "sniffer_running": bool(_sniffer and _sniffer.is_running()),
            "detector_running": bool(_detector and _detector.is_running()),
            "uptime": _uptime_seconds(),
            "db_size_mb": db.get_db_size_mb(),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_mb": round(mem, 1),
            "interface": _sniffer.active_interface if _sniffer else "",
            "local_ip": get_local_ip(),
            "engine_running": _engine_running,
            "version": APP_VERSION,
        }
    )


@app.get("/api/settings")
def api_get_settings():
    return jsonify(
        {
            "INTERFACE": config.INTERFACE,
            "TIME_WINDOW": config.TIME_WINDOW,
            "SYN_FLOOD_THRESHOLD_HIGH": config.SYN_FLOOD_THRESHOLD_HIGH,
            "SYN_FLOOD_THRESHOLD_MEDIUM": config.SYN_FLOOD_THRESHOLD_MEDIUM,
            "PORT_SCAN_THRESHOLD_HIGH": config.PORT_SCAN_THRESHOLD_HIGH,
            "PORT_SCAN_THRESHOLD_MEDIUM": config.PORT_SCAN_THRESHOLD_MEDIUM,
            "PORT_SCAN_WINDOW_SLOW": config.PORT_SCAN_WINDOW_SLOW,
            "BRUTE_FORCE_THRESHOLD": config.BRUTE_FORCE_THRESHOLD,
            "BRUTE_FORCE_WINDOW": config.BRUTE_FORCE_WINDOW,
            "BRUTE_FORCE_PORTS": config.BRUTE_FORCE_PORTS,
            "ICMP_FLOOD_THRESHOLD": config.ICMP_FLOOD_THRESHOLD,
            "ANOMALY_MULTIPLIER": config.ANOMALY_MULTIPLIER,
            "AUTO_BLOCK": config.AUTO_BLOCK,
            "AUTO_BLOCK_SEVERITY": config.AUTO_BLOCK_SEVERITY,
            "ABUSEIPDB_API_KEY": config.ABUSEIPDB_API_KEY,
            "interfaces": list_interfaces(),
            "local_ip": get_local_ip(),
        }
    )


@app.post("/api/settings")
def api_post_settings():
    body = request.get_json(silent=True) or {}
    mapping = {
        "INTERFACE": ("INTERFACE", lambda v: v if v else None),
        "TIME_WINDOW": ("TIME_WINDOW", int),
        "SYN_FLOOD_THRESHOLD_HIGH": ("SYN_FLOOD_THRESHOLD_HIGH", int),
        "SYN_FLOOD_THRESHOLD_MEDIUM": ("SYN_FLOOD_THRESHOLD_MEDIUM", int),
        "PORT_SCAN_THRESHOLD_HIGH": ("PORT_SCAN_THRESHOLD_HIGH", int),
        "PORT_SCAN_THRESHOLD_MEDIUM": ("PORT_SCAN_THRESHOLD_MEDIUM", int),
        "PORT_SCAN_WINDOW_SLOW": ("PORT_SCAN_WINDOW_SLOW", int),
        "BRUTE_FORCE_THRESHOLD": ("BRUTE_FORCE_THRESHOLD", int),
        "BRUTE_FORCE_WINDOW": ("BRUTE_FORCE_WINDOW", int),
        "BRUTE_FORCE_PORTS": ("BRUTE_FORCE_PORTS", lambda v: [int(x) for x in v]),
        "ICMP_FLOOD_THRESHOLD": ("ICMP_FLOOD_THRESHOLD", int),
        "ANOMALY_MULTIPLIER": ("ANOMALY_MULTIPLIER", float),
        "AUTO_BLOCK": ("AUTO_BLOCK", lambda v: bool(v)),
        "AUTO_BLOCK_SEVERITY": ("AUTO_BLOCK_SEVERITY", lambda v: list(v)),
        "ABUSEIPDB_API_KEY": ("ABUSEIPDB_API_KEY", str),
    }
    for key, (attr, caster) in mapping.items():
        if key in body:
            try:
                setattr(config, attr, caster(body[key]))
            except Exception:
                log.exception("Invalid setting %s", key)
    if _alerts:
        _alerts.reload_blacklist()
    if "INTERFACE" in body:
        _stop_engine()
        time.sleep(0.5)
        _ensure_engine()
    emit_activity("Settings saved", "success")
    return jsonify({"success": True})


@app.get("/api/blacklist")
def api_get_blacklist():
    path = os.path.join(ROOT, config.BLACKLIST_PATH)
    if not os.path.exists(path):
        return jsonify({"content": ""})
    with open(path, "r", encoding="utf-8") as f:
        return jsonify({"content": f.read()})


@app.post("/api/blacklist")
def api_save_blacklist():
    body = request.get_json(silent=True) or {}
    content = str(body.get("content", ""))
    path = os.path.join(ROOT, config.BLACKLIST_PATH)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    _intel.reload_blacklist()
    if _alerts:
        _alerts.reload_blacklist()
    emit_activity("Blacklist updated", "success")
    return jsonify({"success": True})


@app.post("/api/engine/stop")
def api_engine_stop():
    _stop_engine()
    return jsonify({"success": True})


@app.post("/api/engine/start")
def api_engine_start():
    _ensure_engine()
    return jsonify({"success": True})


@app.post("/api/engine/restart")
def api_engine_restart():
    _stop_engine()
    time.sleep(1)
    _ensure_engine()
    emit_activity("Engine restarted", "success")
    return jsonify({"success": True})


@app.post("/api/alerts/clear")
def api_clear_alerts():
    path = db._db_abspath()
    conn = db._connect()
    try:
        with conn:
            conn.execute("DELETE FROM alerts")
    finally:
        conn.close()
    emit_activity("All alerts cleared", "warning")
    return jsonify({"success": True})


@app.get("/api/export/db")
def api_export_db():
    path = db._db_abspath()
    if not os.path.exists(path):
        return jsonify({"success": False, "message": "Database not found"}), 404
    export_name = f"shadowwatch_export_{int(time.time())}.db"
    export_path = os.path.join(ROOT, "database", export_name)
    shutil.copy2(path, export_path)
    return send_file(export_path, as_attachment=True, download_name=export_name)


@app.get("/api/heatmap")
def api_heatmap():
    return jsonify({"grid": db.get_heatmap_grid(hours=24 * 7)})


@app.get("/api/intel/<ip>")
def api_intel(ip: str):
    result = _intel.lookup(ip)
    return jsonify(
        {
            "ip": ip,
            "is_blacklisted": result.is_blacklisted,
            "abuse_score": result.abuse_score,
            "country_code": result.country_code,
            "isp": result.isp,
            "asn": result.asn,
            "risk_score": result.risk_score,
        }
    )


@app.context_processor
def inject_globals():
    return {
        "app_name": APP_NAME,
        "app_subtitle": APP_SUBTITLE,
        "app_version": APP_VERSION,
    }


if __name__ == "__main__":
    db.initialize_database()
    _ensure_engine()
    threading.Thread(target=background_emitter, name="ShadowWatch-Emitter", daemon=True).start()
    log.info("%s %s starting on http://%s:%s", APP_NAME, APP_VERSION, config.FLASK_HOST, config.FLASK_PORT)
    socketio.run(app, host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG, allow_unsafe_werkzeug=True)
