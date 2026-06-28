"""
Shadow Watch modules package.

This package contains the SOC-level pipeline components:
- Sniffer: packet capture -> PacketData queue
- Detector: packet analysis -> ThreatEvent queue
- Threat Intel: IP reputation and blacklist checks
- Responder: Windows firewall blocking/unblocking
- Logger: SQLite persistence and queries for the dashboard
- Alerts coordinator: enrich, log, respond, and emit to the UI
"""

