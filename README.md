<div align="center">

# ╔════════════════════════════════════════════════════════════╗
# 🛡️ SHADOW WATCH 🛡️
### *Network Intrusion Detection & Prevention System (IDS/IPS)*
# ╚════════════════════════════════════════════════════════════╝

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-success?style=for-the-badge&logo=windows)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)

**Real-Time Network Monitoring • Intrusion Detection • Intrusion Prevention**

</div>

---

# 📖 Overview

**Shadow Watch** is a Python-based **Intrusion Detection and Prevention System (IDS/IPS)** that continuously monitors network traffic to identify suspicious or malicious activities.

The system analyzes live packets, detects abnormal network behavior, classifies threats based on severity, and automatically protects the system when high-risk attacks are detected.

Designed as a **Network Security** project, Shadow Watch demonstrates practical cybersecurity concepts including packet analysis, intrusion detection, and automated response mechanisms.

---

# ✨ Features

- 🔍 Real-Time Network Traffic Monitoring
- 🛡️ Intrusion Detection System (IDS)
- 🚫 Intrusion Prevention System (IPS)
- 📊 Severity-Based Threat Classification
- ⚠️ Suspicious Activity Detection
- 🔒 Automatic Protection for High Severity Threats
- 🌐 Network Scanning using Nmap
- 📦 Live Packet Capture using Npcap
- 📝 Event Logging
- 💻 User-Friendly Interface

---

# 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Core Programming Language |
| Scapy | Packet Capture & Analysis |
| Nmap | Network Scanning |
| Python-Nmap | Python Interface for Nmap |
| Npcap | Packet Capture Driver |
| Tkinter | Graphical User Interface |

---

# ⚙️ Requirements

Install the following before running the project.

## 🐍 Python

https://www.python.org/downloads/

---

## 🌐 Nmap

https://nmap.org/download.html

---

## 📡 Npcap

https://npcap.com/

> Install using the default settings.

---

# 📦 Install Required Libraries

```bash
pip install scapy python-nmap psutil colorama
```

or

```bash
pip install -r requirements.txt
```

---

# 🚀 How to Run

Clone the repository

```bash
git clone https://github.com/asadabbas111/Shadow-Watch.git
```

Open the project folder

```bash
cd Shadow-Watch
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python main.py
```

---

# 🧠 Detection Capabilities

Shadow Watch is capable of detecting:

- ✅ Port Scanning
- ✅ Suspicious Network Traffic
- ✅ Unauthorized Access Attempts
- ✅ Network Reconnaissance
- ✅ Possible Intrusion Attempts
- ✅ High Severity Threats
- ✅ Malicious Connection Attempts

---

# 📁 Project Structure

```
Shadow-Watch
│
├── main.py
├── detector.py
├── scanner.py
├── firewall.py
├── requirements.txt
├── README.md
├── logs/
└── assets/
```

---

# 🔄 How It Works

```
Network Traffic
        │
        ▼
 Packet Capture (Npcap)
        │
        ▼
 Packet Analysis (Scapy)
        │
        ▼
 Threat Detection Engine
        │
        ▼
 Severity Classification
        │
        ├──────────────┐
        ▼              ▼
    Low Risk      High Risk
        │              │
        ▼              ▼
     Log Event    Block & Protect
```

---

# 🔮 Future Improvements

- 🤖 Machine Learning Threat Detection
- 📧 Email Notifications
- 📱 Web Dashboard
- 🌍 Multi-Device Monitoring
- ☁️ Cloud Log Storage
- 📈 Traffic Analytics

---

# ⚠️ Disclaimer

This project is intended **for educational and research purposes only**. Users are responsible for ensuring compliance with all applicable laws and regulations when monitoring or analyzing network traffic.

---

<div align="center">

# 👨‍💻 Developer

### **Asad Abbas**

**BS Cybersecurity Undergraduate**

🌐 GitHub: **https://github.com/asadabbas111**

---

### ⭐ If you found this project useful, consider giving it a Star!

</div>
