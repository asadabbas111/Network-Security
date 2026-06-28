# Shadow Watch

**SOC-Level Intrusion Detection & Response System** — v2.0  
Air University, Dept. of Cyber Security

Shadow Watch is a Windows-native SI-IDRS that captures live network traffic, detects common attacks (SYN flood, port scan, brute force, ICMP flood, traffic anomalies), enriches alerts with threat intelligence, optionally blocks attackers via the Windows Firewall, and presents everything in a professional SOC-style web dashboard.

---

## Requirements

- Windows 10/11 (64-bit)
- Python 3.10+ (you have **3.14** — supported via threading mode; for best compatibility use **3.10–3.12**)
- [Npcap](https://nmap.org/npcap/) (enable **WinPcap API-compatible Mode** during install)
- [Nmap](https://nmap.org/download.html) (optional, for network tooling)
- **Administrator privileges** (required for packet capture and firewall rules)

---

## Installation

1. Open **Command Prompt as Administrator**.
2. Navigate to the project folder:

```bat
cd C:\Users\theej\Desktop\ns\ShadowWatch
```

3. Install Python dependencies:

```bat
pip install -r requirements.txt
```

---

## Running Shadow Watch

1. **Run as Administrator** (mandatory).
2. Start the application:

```bat
python app.py
```

3. Open your browser:

```
http://localhost:5000
```

4. Go to **Settings → Network Interface** and select your active adapter (or leave auto-detect).
5. The capture engine starts automatically. Live stats and alerts update via WebSocket.

---

## Testing Detections Locally

Use the included attack simulator (also requires Administrator):

```bat
python test_attacks.py
```

Choose an attack type from the menu while Shadow Watch is running. Synthetic packets use documentation IP `198.51.100.99` as the attacker source.

> **Note:** Auto-block will not block private/documentation IPs used as destinations on your LAN rules, but detections still appear in the dashboard.

---

## Project Structure

```
ShadowWatch/
├── app.py                 # Flask + SocketIO web server & engine orchestration
├── config.py              # All tunable thresholds and settings
├── modules/
│   ├── sniffer.py         # Scapy/Npcap packet capture
│   ├── detector.py        # 5 detection algorithms
│   ├── threat_intel.py    # Blacklist + AbuseIPDB
│   ├── responder.py       # netsh advfirewall blocking
│   ├── logger.py          # SQLite persistence
│   └── alerts.py          # Coordinator pipeline
├── database/              # SQLite schema + logs
├── static/                # CSS + JavaScript dashboard
└── templates/             # HTML pages
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Run as Administrator` in logs | Close terminal, right-click CMD → **Run as administrator**, restart `python app.py` |
| No packets captured | Select correct interface in Settings; confirm Npcap is installed with WinPcap compat mode |
| Scapy/Npcap errors | Reinstall Npcap; reboot; ensure no other capture tool holds the adapter |
| Port 5000 in use | Change `FLASK_PORT` in `config.py` |
| Auto-block not working | Severity must be HIGH/CRITICAL; `AUTO_BLOCK` must be enabled; private IPs are never blocked |
| `eventlet` / `start_joinable_thread` error | You are on Python 3.13+. Pull latest `app.py` (uses threading, not eventlet) and run `python app.py` again |
| AbuseIPDB errors | Add API key in Settings or leave blank to disable external lookups |
| Firewall rule failures | Run as Administrator; verify Windows Firewall service is running |

---

## AbuseIPDB (Optional)

1. Register at [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
2. Copy your API key into **Settings → AbuseIPDB API Key**
3. Results are cached in SQLite for 24 hours

---

## License & Academic Use

Built as a university final project for real-network demonstration. Use only on networks you own or have explicit permission to monitor.
