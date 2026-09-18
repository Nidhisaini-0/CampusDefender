# 🛡️ CampusDefender

A lightweight Python-based intrusion detection and automated-response system that monitors SSH authentication logs and live network traffic to detect SSH brute-force attacks and port scans — logging every event to a database, visualizing it on a web dashboard, and automatically blocking attacking IPs via UFW.

Built as a defensive (blue-team) cybersecurity project: instead of only finding vulnerabilities offensively, CampusDefender continuously monitors a host for suspicious activity, detects it, records it, visualizes it, and responds to it automatically.

---

## 🎯 Overview

CampusDefender runs two detection engines in parallel background threads:

```
                    CampusDefender
                         |
              -----------------------
              |                     |
       SSH Log Monitor        Network Monitor
              |                     |
       /var/log/auth.log          Scapy
              |                     |
        SSH Detection          Port Scan Detection
              |                     |
              --------- SQLite Database ----------
                         |
                    Flask Dashboard
```

When an attack is detected, it's logged to a SQLite database and — for port scans — the attacking IP is automatically blocked using UFW.

---

## 🔍 Detection Logic

### SSH Brute-Force Detection
- Monitors `/var/log/auth.log` for failed SSH authentication attempts
- Extracts the source IP from each failed attempt
- **Threshold:** 3 failed attempts from the same IP triggers a detection
- The event is logged to the database

### Port Scan Detection
- Uses **Scapy** to capture live packets on network interface `enp0s3`
- Tracks TCP connection attempts from source IPs across different ports
- **Threshold:** 5 connection attempts from the same IP within 10 seconds → flagged as `PORT_SCAN`
- Ignores localhost (`127.0.0.1`)
- On detection: logs the attack, records the attacker's IP, and blocks it via UFW

### Monitoring Mode
This is a **continuous background monitoring system**, not an on-demand scanner. Running `run.py` starts both the SSH detector and the port-scan detector in separate threads that run persistently.

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python |
| Web dashboard | Flask |
| Packet capture | Scapy |
| Database | SQLite |
| Firewall response | UFW |

---

## 📁 Project Structure

```
CampusDefender/
├── app/
│   ├── __init__.py      # Makes app a Python package
│   ├── database.py      # Database operations
│   ├── detector.py       # SSH brute-force detection
│   ├── logger.py         # Records detected attacks
│   └── portscan.py       # Scapy-based port-scan detection
├── templates/
│   ├── dashboard.html    # Main alert dashboard
│   ├── analytics.html    # Attack statistics view
│   └── login.html        # Login page
├── dashboard.py           # Flask application entry point
├── init_db.py             # Initializes the SQLite database
├── run.py                 # Starts detection engines + dashboard
└── .gitignore
```

---

## 🗄️ Database Schema

`init_db.py` sets up `campusdefender.db` with an `attacks` table:

| Field | Description |
|---|---|
| `id` | Unique attack ID |
| `timestamp` | When the attack was detected |
| `attack_type` | e.g. `SSH_BRUTE_FORCE`, `PORT_SCAN` |
| `ip` | Attacker/source IP |
| `action` | Action taken (e.g. `LOGGED`, `BLOCKED`) |
| `details` | Additional context |

**Example record:**
```
IP: 192.168.1.10
Attack Type: PORT_SCAN
Time: 2026-09-18 12:30:15
Action: BLOCKED
Details: Multiple connection attempts detected
```

---

## 📊 Dashboard

The Flask dashboard (`http://127.0.0.1:5000`) displays detected alerts pulled from the SQLite database, along with an analytics view (`analytics.html`) showing attack statistics.

> **Note:** The dashboard pulls the latest data from the database when the page loads/refreshes — it is not a real-time WebSocket-based live feed (see [Future Improvements](#-future-improvements)).

---

## 🚫 Automated Response

For detected port scans, CampusDefender automatically blocks the attacking IP:

```
sudo ufw deny from <IP>
```

The action is recorded in the database (`action = BLOCKED`), so CampusDefender isn't just a logger — it includes a basic automated incident-response mechanism.

---

## ⚙️ Setup & Usage

### Prerequisites
- Linux environment (developed and tested on Ubuntu)
- Python 3
- Root/sudo privileges (required for Scapy packet capture and UFW commands)

### Configuration
Before running, check these environment-specific settings in the code:
- **SSH log path:** `/var/log/auth.log`
- **Network interface:** `enp0s3` (change this to match your machine — e.g. `eth0`, `ens33`)

### Running the project

CampusDefender runs as two separate processes — the detection engine and the web dashboard — so you'll need **two terminals**.

```bash
# 1. Initialize the database (first time only)
python3 init_db.py
```

```bash
# Terminal 1 — start the detection engines (SSH + port scan monitoring)
sudo python3 run.py
```

```bash
# Terminal 2 — start the Flask dashboard
python3 dashboard.py
```

Then open the dashboard at:
```
http://127.0.0.1:5000
```

---

## 🧪 Testing

CampusDefender was developed and tested in an isolated Ubuntu virtual-machine home-lab environment using simulated attacks:

- **SSH brute-force:** repeated failed SSH login attempts against the monitored VM
- **Port scan:** Nmap-generated scans against the monitored machine, observed and flagged by the Scapy detector

---

## 💡 Motivation

This project was built as a college cybersecurity project with a focus on practical SOC/blue-team concepts — moving beyond offensive vulnerability-finding into building a defensive system that detects, logs, visualizes, and responds to attacks in real time.

**Biggest challenges:**
- Working with real system data (auth logs + live packets) instead of a typical CRUD app
- Understanding how Scapy interprets TCP packets to identify scanning behavior
- Wiring together detection → logging → SQLite → Flask → dashboard → automated firewall response into one coherent pipeline

---

## 🚧 Future Improvements

- [ ] Real-time dashboard updates via WebSockets / Flask-SocketIO
- [ ] Email and Slack/Discord webhook alerts
- [ ] Configurable block thresholds, temporary blocks, and an IP allowlist
- [ ] Additional detections (SYN flood, ICMP flood, suspicious DNS activity)
- [ ] Richer analytics (top attacking IPs, attack timeline, most common attack type)
- [ ] Externalized config file instead of hard-coded interface/log path/thresholds

---

## ⚠️ Scope

CampusDefender is a college-level intrusion detection and automated-response project demonstrating core SOC concepts — log monitoring, packet-based detection, alert storage, visualization, and firewall response. It is not a full enterprise IDS/SIEM.
