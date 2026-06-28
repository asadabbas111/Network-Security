"""
Packet sniffer for Shadow Watch (Windows).

Uses Scapy with Npcap in WinPcap-compat mode. Captures IP traffic (TCP/UDP/ICMP)
and emits normalized PacketData into a thread-safe Queue for downstream analysis.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque, namedtuple
from queue import Queue
from typing import Any, Deque, Dict, Optional

from scapy.all import IP, ICMP, TCP, UDP, conf, get_if_addr, get_if_list, sniff  # type: ignore

import config
from .net_iface import get_local_ip, interface_label, resolve_capture_interface

conf.use_pcap = True

log = logging.getLogger("shadowwatch.sniffer")

PacketData = namedtuple(
    "PacketData",
    [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "flags",
        "packet_size",
        "timestamp",
    ],
)


class Sniffer:
    def __init__(self, interface: Optional[str] = None) -> None:
        self._interface = interface
        self._queue: "Queue[PacketData]" = Queue(maxsize=50000)
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._lock = threading.Lock()
        self._packets_captured = 0
        self._bytes_captured = 0
        self._tcp = 0
        self._udp = 0
        self._icmp = 0

        self._pps_window: Deque[float] = deque(maxlen=5000)
        self._bps_window: Deque[tuple[float, int]] = deque(maxlen=5000)
        self._last_stats_time = time.time()
        self._last_packets_captured = 0
        self._last_bytes_captured = 0

        self._active_interface_name = ""
        self._display_name = ""
        self._recent_packets: Deque[Dict[str, Any]] = deque(maxlen=200)

    @property
    def queue(self) -> "Queue[PacketData]":
        return self._queue

    @property
    def active_interface(self) -> str:
        return self._display_name or self._active_interface_name

    def _select_interface(self) -> str:
        preferred = self._interface or config.INTERFACE
        device = resolve_capture_interface(preferred)
        self._display_name = interface_label(preferred or device)
        log.info(
            "Capture device: %s [%s] | PC LAN IP: %s",
            self._display_name,
            device,
            get_local_ip(),
        )
        return device

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        device = self._select_interface()
        self._active_interface_name = device

        self._thread = threading.Thread(
            target=self._run,
            name="ShadowWatch-Sniffer",
            daemon=True,
            args=(device,),
        )
        self._thread.start()
        log.info("Sniffer started on: %s", self._display_name or device)

    def stop(self) -> None:
        self._running.clear()
        log.info("Sniffer stopping...")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._running.is_set()

    def _on_packet(self, pkt) -> None:  # scapy dynamic type
        try:
            if IP not in pkt:
                return
            ip = pkt[IP]
            src_ip = getattr(ip, "src", "")
            dst_ip = getattr(ip, "dst", "")
            proto = "IP"
            src_port = None
            dst_port = None
            flags = ""

            if TCP in pkt:
                tcp = pkt[TCP]
                proto = "TCP"
                src_port = int(getattr(tcp, "sport", 0) or 0)
                dst_port = int(getattr(tcp, "dport", 0) or 0)
                flags = str(getattr(tcp, "flags", "")) or ""
            elif UDP in pkt:
                udp = pkt[UDP]
                proto = "UDP"
                src_port = int(getattr(udp, "sport", 0) or 0)
                dst_port = int(getattr(udp, "dport", 0) or 0)
            elif ICMP in pkt:
                proto = "ICMP"

            ts = time.time()
            size = int(len(bytes(pkt)))
            pdata = PacketData(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                flags=flags,
                packet_size=size,
                timestamp=ts,
            )

            try:
                self._queue.put_nowait(pdata)
            except Exception:
                # Queue full; drop packet to avoid blocking capture thread.
                return

            with self._lock:
                self._packets_captured += 1
                self._bytes_captured += size
                if proto == "TCP":
                    self._tcp += 1
                elif proto == "UDP":
                    self._udp += 1
                elif proto == "ICMP":
                    self._icmp += 1
                self._pps_window.append(ts)
                self._bps_window.append((ts, size))
                self._recent_packets.append(
                    {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "flags": flags,
                        "packet_size": size,
                        "timestamp": ts,
                    }
                )
        except Exception:
            log.exception("Error processing captured packet")

    def _run(self, iface: str) -> None:
        try:
            sniff(
                iface=iface,
                filter="ip",
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            )
        except PermissionError:
            log.error("Run as Administrator")
            self._running.clear()
        except OSError as e:
            msg = str(e).lower()
            if "access is denied" in msg or "permission" in msg:
                log.error("Run as Administrator")
            else:
                log.exception("Sniffer OS error: %s", e)
            self._running.clear()
        except Exception:
            log.exception("Sniffer crashed")
            self._running.clear()

    def get_stats(self) -> Dict[str, float]:
        now = time.time()
        with self._lock:
            # Windowed pkt/s via timestamps over last 1s
            while self._pps_window and self._pps_window[0] < now - 1.0:
                self._pps_window.popleft()
            pps = float(len(self._pps_window))

            bytes_last_sec = 0
            while self._bps_window and self._bps_window[0][0] < now - 1.0:
                self._bps_window.popleft()
            for _, sz in self._bps_window:
                bytes_last_sec += int(sz)
            bps = float(bytes_last_sec)

            stats = {
                "packets_captured": float(self._packets_captured),
                "packets_per_second": pps,
                "bytes_per_second": bps,
                "tcp_count": float(self._tcp),
                "udp_count": float(self._udp),
                "icmp_count": float(self._icmp),
            }
            return stats

    def get_recent_packets(self, limit: int = 50) -> list:
        limit = max(1, min(int(limit), 200))
        with self._lock:
            items = list(self._recent_packets)[-limit:]
        return list(reversed(items))

