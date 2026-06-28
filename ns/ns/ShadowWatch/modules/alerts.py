"""
Alerts coordinator for Shadow Watch.

Bridges detector -> threat intel -> logger -> responder -> SocketIO.
Runs in a background daemon thread.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict
from queue import Empty, Queue
from typing import Any, Dict, Optional

import config
from .detector import ThreatEvent
from . import logger
from .responder import block_ip, should_auto_block
from .threat_intel import ThreatIntel, ThreatIntelResult

log = logging.getLogger("shadowwatch.alerts")


class AlertsCoordinator:
    def __init__(self, event_queue: "Queue[ThreatEvent]") -> None:
        self._event_queue = event_queue
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._socketio = None
        self._intel = ThreatIntel()

    def start(self, socketio_instance: Any) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._socketio = socketio_instance
        self._running.set()
        self._thread = threading.Thread(target=self._run, name="ShadowWatch-Alerts", daemon=True)
        self._thread.start()
        log.info("Alerts coordinator started")

    def stop(self) -> None:
        self._running.clear()
        log.info("Alerts coordinator stopping...")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._running.is_set()

    def reload_blacklist(self) -> None:
        self._intel.reload_blacklist()

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            if self._socketio is not None:
                self._socketio.emit(event, payload, namespace="/")
        except Exception:
            log.exception("Socket emit failed: %s", event)

    def _run(self) -> None:
        while self._running.is_set():
            try:
                ev = self._event_queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                intel = self._intel.lookup(ev.source_ip)
                alert_id = logger.insert_alert(ev, intel)
                alert_dict = self._build_alert_dict(alert_id, ev, intel)

                self._emit("new_alert", alert_dict)
                self._emit(
                    "activity",
                    {
                        "message": f"Alert: {ev.attack_type} from {ev.source_ip} [{ev.severity}]",
                        "level": "error" if ev.severity in ("HIGH", "CRITICAL") else "info",
                    },
                )

                if should_auto_block(ev.severity) and not self._intel.is_private(ev.source_ip):
                    res = block_ip(ev.source_ip, blocked_by="AUTO", reason=f"{ev.attack_type} {ev.severity}")
                    if bool(res.get("success")):
                        logger.mark_alert_auto_blocked(alert_id)
                        self._emit(
                            "ip_blocked",
                            {"ip": ev.source_ip, "reason": f"{ev.attack_type} {ev.severity}", "alert_id": alert_id},
                        )
                        self._emit(
                            "activity",
                            {
                                "message": f"Auto-blocked {ev.source_ip} ({ev.attack_type})",
                                "level": "warning",
                            },
                        )
            except Exception:
                log.exception("Alerts coordinator error")

    @staticmethod
    def _build_alert_dict(alert_id: int, ev: ThreatEvent, intel: ThreatIntelResult) -> Dict[str, Any]:
        d = asdict(ev)
        d["id"] = int(alert_id)
        d["intel"] = {
            "is_blacklisted": bool(intel.is_blacklisted),
            "abuse_score": int(intel.abuse_score),
            "country_code": intel.country_code,
            "isp": intel.isp,
            "asn": intel.asn,
            "usage_type": intel.usage_type,
            "risk_score": float(intel.risk_score),
        }
        return d

