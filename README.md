# 🛡️ Mini SIEM — Security Information & Event Management Dashboard

A full-featured **Security Information and Event Management (SIEM)** system built in Python and Flask, demonstrating real-world SOC (Security Operations Center) workflows including log ingestion, rule-based threat detection, alert management, and security event visualization.

---

## 🎯 What This Project Demonstrates

| SOC Concept | Implementation |
|---|---|
| **Log Ingestion** | Parses and stores structured security events from multiple sources |
| **Threat Detection** | 7 rule-based detection engines (brute force, port scan, data exfiltration, etc.) |
| **Alert Management** | Severity-tiered alerts with open/resolved status tracking |
| **Security Visualization** | Real-time charts for event severity, types, timeline, and top IPs |
| **Incident Response** | One-click alert resolution workflow |
| **Audit Trail** | Complete immutable log of all security events |
| **Threat Intelligence** | Top attacker IP identification with threat scoring |

---

## 🚨 Threat Detection Rules

The detection engine (`threat_detector.py`) runs 7 automated detection rules:

1. **Brute Force Attack** — 5+ failed logins from same IP → CRITICAL alert
2. **Privilege Escalation** — Any sudo/escalation attempt → CRITICAL alert
3. **Data Exfiltration** — Abnormal outbound data transfer → CRITICAL alert
4. **Malware Detection** — Known malware signature match → CRITICAL alert
5. **Port Scan** — Reconnaissance scanning activity → HIGH alert
6. **Multiple Account Lockouts** — Credential stuffing pattern → HIGH alert
7. **Critical File Modification** — System file integrity violation → HIGH alert

---

## 🏗️ Architecture

```
siem-dashboard/
├── app.py              # Flask API + real-time dashboard UI
├── threat_detector.py  # Rule-based threat detection engine
├── log_generator.py    # Realistic security log generator (200+ events)
├── siem.db             # SQLite database (auto-generated)
└── README.md
```

---

## 📊 Dashboard Features

- **KPI Cards** — Live counts of Critical, High, Medium events and total logs
- **Severity Donut Chart** — Visual breakdown of event severity distribution
- **Top Event Types Bar Chart** — Most frequent security event categories
- **24-Hour Timeline** — Event volume over time (line chart)
- **Top Source IPs** — Ranked attacker IPs with threat level bars
- **Active Alerts Panel** — Open alerts with one-click resolution
- **Live Log Feed** — Last 50 security events with full details
- **Auto-refresh** — Dashboard updates every 30 seconds

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/uzzwol01/siem-dashboard.git

# Install dependencies
pip install flask

# Run the application
python app.py
```

Open your browser: **http://localhost:5001**

The system auto-generates 200 realistic security log events on startup and runs all detection rules immediately.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/summary` | KPI counts (total, critical, high, medium) |
| `GET` | `/api/charts` | Chart data (severity, event types, timeline) |
| `GET` | `/api/top-ips` | Top 8 source IPs by event count |
| `GET` | `/api/alerts` | Open alerts list |
| `POST` | `/api/alerts/<id>/resolve` | Resolve a specific alert |
| `GET` | `/api/logs` | Last 50 log entries |
| `POST` | `/api/regenerate` | Generate fresh log data |

---

## 🔍 Security Events Monitored

| Event Type | Severity | Description |
|---|---|---|
| BRUTE_FORCE | HIGH | Multiple failed authentication attempts |
| PRIVILEGE_ESC | CRITICAL | Unauthorized privilege escalation |
| DATA_EXFIL | CRITICAL | Suspicious outbound data transfer |
| MALWARE | CRITICAL | Malware signature detected |
| PORT_SCAN | HIGH | Network reconnaissance scanning |
| LOGIN_FAILED | MEDIUM | Single authentication failure |
| FILE_MODIFIED | MEDIUM | Critical file integrity change |
| ACCOUNT_LOCKED | HIGH | User account lockout |
| FIREWALL_BLOCK | MEDIUM | Blocked connection attempt |
| CONFIG_CHANGE | HIGH | System configuration modification |

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, Vanilla JavaScript
- **Charts:** Chart.js
- **Detection:** Custom rule-based engine

---

## 🌐 Real-World SIEM Comparisons

| Feature | This Project | Splunk | IBM QRadar |
|---|---|---|---|
| Log Ingestion | ✅ | ✅ | ✅ |
| Rule-based Detection | ✅ | ✅ | ✅ |
| Alert Management | ✅ | ✅ | ✅ |
| Dashboards & Charts | ✅ | ✅ | ✅ |
| ML-based Detection | ❌ | ✅ | ✅ |
| Enterprise Scale | ❌ | ✅ | ✅ |

---

## 🔭 Future Enhancements

- [ ] Machine learning anomaly detection
- [ ] Real log file ingestion (syslog, Windows Event Log)
- [ ] Email/SMS alert notifications
- [ ] Threat intelligence feed integration (IP reputation APIs)
- [ ] User behavior analytics (UEBA)
- [ ] Export reports to PDF

---

## 👤 Author

**Ujjwal Dhakal**
- LinkedIn: [linkedin.com/in/ujjwal-dhakal-67bb763a4](https://www.linkedin.com/in/ujjwal-dhakal-67bb763a4)
- Email: dhakalujjwal16@gmail.com

---

## 📄 License

MIT License — free to use and modify.
