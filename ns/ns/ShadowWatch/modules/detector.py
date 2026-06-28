"""
Threat detector for Shadow Watch.

Consumes PacketData from the sniffer queue and emits ThreatEvent objects to an
event queue for enrichment, logging, and response.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any, Deque, Dict, Optional, Set, Tuple

import config

log = logging.getLogger("shadowwatch.detector")


@dataclass
class ThreatEvent:
    source_ip: str
    destination_ip: str
    attack_type: str
    severity: str  # LOW/MEDIUM/HIGH/CRITICAL
    confidence: int  # 0-100
    packet_count: int
    time_window: int
    timestamp: str
    extra: Dict[str, Any] = field(default_factory=dict)


class Detector:
    def __init__(self, packet_queue: "Queue[Any]") -> None:
        self._packet_queue = packet_queue
        self._event_queue: "Queue[ThreatEvent]" = Queue(maxsize=20000)
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._lock = threading.Lock()

        # Windows for detections
        self._syn_window: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20000))
        self._icmp_window: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20000))
        self._port_window_fast: Dict[str, Deque[Tuple[float, int]]] = defaultdict(lambda: deque(maxlen=20000))
        self._port_window_slow: Dict[str, Deque[Tuple[float, int]]] = defaultdict(lambda: deque(maxlen=20000))
        self._bruteforce_window: Dict[Tuple[str, int], Deque[float]] = defaultdict(lambda: deque(maxlen=20000))

        # EMA baselines for anomaly detection (per IP)
        self._ema_rate: Dict[str, float] = defaultdict(float)
        self._ema_last_ts: Dict[str, float] = defaultdict(float)
        self._rate_window: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20000))

        self._last_emit: Dict[Tuple[str, str], float] = defaultdict(float)

    def get_event_queue(self) -> "Queue[ThreatEvent]":
        return self._event_queue

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._run, name="ShadowWatch-Detector", daemon=True)
        self._thread.start()
        log.info("Detector started")

    def stop(self) -> None:
        self._running.clear()
        log.info("Detector stopping...")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._running.is_set()

    def _run(self) -> None:
        while self._running.is_set():
            try:
                pkt = self._packet_queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                self._process_packet(pkt)
            except Exception:
                log.exception("Detector error processing packet")

    @staticmethod
    def _utc_now_iso() -> str:
        # UTC string without external deps
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _emit(self, event: ThreatEvent) -> None:
        key = (event.source_ip, event.attack_type)
        now = time.time()
        # simple de-duplication to avoid spamming repeated emits every packet
        if now - self._last_emit.get(key, 0.0) < 2.0:
            return
        self._last_emit[key] = now
        try:
            self._event_queue.put_nowait(event)
        except Exception:
            return

    @staticmethod
    def _is_private(ip: str) -> bool:
        if not ip:
            return True
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
                except ValueError:
                    pass
        return False

    def _trim_deque(self, dq: Deque, cutoff: float) -> None:
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _process_packet(self, pkt: Any) -> None:
        now = float(getattr(pkt, "timestamp", time.time()))
        src = str(getattr(pkt, "src_ip", "") or "")
        dst = str(getattr(pkt, "dst_ip", "") or "")
        proto = str(getattr(pkt, "protocol", "") or "")
        flags = str(getattr(pkt, "flags", "") or "")
        dport = getattr(pkt, "dst_port", None)

        if not src:
            return

        # Skip heavy analysis for routine private-to-private traffic
        if self._is_private(src) and self._is_private(dst):
            return

        # Rate window for anomaly
        rw = self._rate_window[src]
        rw.append(now)
        self._trim_deque(rw, now - config.TIME_WINDOW)
        current_rate = float(len(rw)) / float(max(1, config.TIME_WINDOW))

        last_ts = self._ema_last_ts.get(src, 0.0)
        ema = self._ema_rate.get(src, 0.0)
        # EMA update with time-aware smoothing
        if last_ts <= 0.0:
            ema = current_rate
        else:
            dt = max(0.01, now - last_ts)
            alpha = min(1.0, 0.2 * (dt / 1.0))
            ema = (1.0 - alpha) * ema + alpha * current_rate
        self._ema_last_ts[src] = now
        self._ema_rate[src] = ema

        if ema > 0 and current_rate > (config.ANOMALY_MULTIPLIER * ema) and len(rw) >= 10:
            severity = "MEDIUM" if current_rate < (config.ANOMALY_MULTIPLIER * ema * 1.5) else "HIGH"
            confidence = min(95, int(60 + (current_rate / (ema + 0.001)) * 10))
            self._emit(
                ThreatEvent(
                    source_ip=src,
                    destination_ip=dst,
                    attack_type="ANOMALY",
                    severity=severity,
                    confidence=confidence,
                    packet_count=len(rw),
                    time_window=config.TIME_WINDOW,
                    timestamp=self._utc_now_iso(),
                    extra={"baseline_rate": round(ema, 2), "current_rate": round(current_rate, 2), "base_score": 35.0},
                )
            )

        # SYN flood and brute force / port scan
        if proto == "TCP":
            is_syn_only = ("S" in flags) and ("A" not in flags) and ("F" not in flags) and ("R" not in flags)
            if is_syn_only:
                syn = self._syn_window[src]
                syn.append(now)
                self._trim_deque(syn, now - config.TIME_WINDOW)

                syn_count = len(syn)
                if syn_count >= config.SYN_FLOOD_THRESHOLD_HIGH:
                    self._emit(
                        ThreatEvent(
                            source_ip=src,
                            destination_ip=dst,
                            attack_type="SYN_FLOOD",
                            severity="HIGH",
                            confidence=90,
                            packet_count=syn_count,
                            time_window=config.TIME_WINDOW,
                            timestamp=self._utc_now_iso(),
                            extra={"base_score": 60.0},
                        )
                    )
                elif syn_count >= config.SYN_FLOOD_THRESHOLD_MEDIUM:
                    self._emit(
                        ThreatEvent(
                            source_ip=src,
                            destination_ip=dst,
                            attack_type="SYN_FLOOD",
                            severity="MEDIUM",
                            confidence=75,
                            packet_count=syn_count,
                            time_window=config.TIME_WINDOW,
                            timestamp=self._utc_now_iso(),
                            extra={"base_score": 40.0},
                        )
                    )

                if isinstance(dport, int):
                    if dport in config.BRUTE_FORCE_PORTS:
                        key = (src, int(dport))
                        bf = self._bruteforce_window[key]
                        bf.append(now)
                        self._trim_deque(bf, now - config.BRUTE_FORCE_WINDOW)
                        if len(bf) >= config.BRUTE_FORCE_THRESHOLD:
                            self._emit(
                                ThreatEvent(
                                    source_ip=src,
                                    destination_ip=dst,
                                    attack_type="BRUTE_FORCE",
                                    severity="HIGH",
                                    confidence=88,
                                    packet_count=len(bf),
                                    time_window=config.BRUTE_FORCE_WINDOW,
                                    timestamp=self._utc_now_iso(),
                                    extra={"port": int(dport), "base_score": 55.0},
                                )
                            )

            # Port scan: unique dst ports per src within windows
            if isinstance(dport, int) and dport > 0:
                fast = self._port_window_fast[src]
                slow = self._port_window_slow[src]
                fast.append((now, int(dport)))
                slow.append((now, int(dport)))
                self._trim_port_windows(src, now)

                uniq_fast = self._count_unique_ports(fast, now - config.TIME_WINDOW)
                uniq_slow = self._count_unique_ports(slow, now - config.PORT_SCAN_WINDOW_SLOW)

                if uniq_fast >= config.PORT_SCAN_THRESHOLD_HIGH:
                    self._emit(
                        ThreatEvent(
                            source_ip=src,
                            destination_ip=dst,
                            attack_type="PORT_SCAN",
                            severity="HIGH",
                            confidence=90,
                            packet_count=uniq_fast,
                            time_window=config.TIME_WINDOW,
                            timestamp=self._utc_now_iso(),
                            extra={"unique_ports": uniq_fast, "base_score": 55.0},
                        )
                    )
                elif uniq_slow >= config.PORT_SCAN_THRESHOLD_MEDIUM:
                    self._emit(
                        ThreatEvent(
                            source_ip=src,
                            destination_ip=dst,
                            attack_type="PORT_SCAN",
                            severity="MEDIUM",
                            confidence=78,
                            packet_count=uniq_slow,
                            time_window=config.PORT_SCAN_WINDOW_SLOW,
                            timestamp=self._utc_now_iso(),
                            extra={"unique_ports": uniq_slow, "base_score": 38.0},
                        )
                    )

        # ICMP flood: echo requests (type 8)
        if proto == "ICMP":
            # scapy ICMP type isn't captured in PacketData; rely on rate on src
            ic = self._icmp_window[src]
            ic.append(now)
            self._trim_deque(ic, now - config.TIME_WINDOW)
            if len(ic) >= config.ICMP_FLOOD_THRESHOLD:
                self._emit(
                    ThreatEvent(
                        source_ip=src,
                        destination_ip=dst,
                        attack_type="ICMP_FLOOD",
                        severity="MEDIUM",
                        confidence=72,
                        packet_count=len(ic),
                        time_window=config.TIME_WINDOW,
                        timestamp=self._utc_now_iso(),
                        extra={"base_score": 30.0},
                    )
                )

    def _trim_port_windows(self, src: str, now: float) -> None:
        fast = self._port_window_fast[src]
        slow = self._port_window_slow[src]
        cutoff_fast = now - config.TIME_WINDOW
        cutoff_slow = now - config.PORT_SCAN_WINDOW_SLOW
        while fast and fast[0][0] < cutoff_fast:
            fast.popleft()
        while slow and slow[0][0] < cutoff_slow:
            slow.popleft()

    @staticmethod
    def _count_unique_ports(window: Deque[Tuple[float, int]], cutoff: float) -> int:
        seen: Set[int] = set()
        for ts, port in window:
            if ts >= cutoff:
                seen.add(int(port))
        return len(seen)

