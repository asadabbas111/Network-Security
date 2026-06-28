"""
Shadow Watch configuration.

All runtime-tunable settings live here. The web UI can update many values at
runtime (in-memory) without requiring a restart.
"""

from __future__ import annotations

INTERFACE = None  # None = auto-select first active non-loopback interface

TIME_WINDOW = 5

SYN_FLOOD_THRESHOLD_HIGH = 100
SYN_FLOOD_THRESHOLD_MEDIUM = 50

PORT_SCAN_THRESHOLD_HIGH = 15
PORT_SCAN_THRESHOLD_MEDIUM = 8
PORT_SCAN_WINDOW_SLOW = 10

BRUTE_FORCE_THRESHOLD = 20
BRUTE_FORCE_WINDOW = 30
BRUTE_FORCE_PORTS = [22, 21, 3389, 23, 3306, 5432]

ICMP_FLOOD_THRESHOLD = 50

ANOMALY_MULTIPLIER = 3.0

AUTO_BLOCK = True
AUTO_BLOCK_SEVERITY = ["HIGH", "CRITICAL"]

ABUSEIPDB_API_KEY = ""

DB_PATH = "database/security_logs.db"
BLACKLIST_PATH = "blacklist.txt"

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False

PRIVATE_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]

