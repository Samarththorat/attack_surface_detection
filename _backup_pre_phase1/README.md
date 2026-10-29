# Attack Surface Reduction and Security Assessment System

A local, read-only security assessment tool for Windows that identifies attack
surface exposure on the current machine, calculates an explainable risk score,
and provides actionable recommendations — all through a web dashboard.

Built as a college project for Information Security and Cryptography (ISC).

## What it does

- Collects basic system information (OS, CPU, RAM, network, uptime)
- Identifies locally listening ports and the processes using them
- Analyzes running services and flags third-party processes for review
- Checks Windows Firewall status across all profiles
- Checks UAC, Remote Desktop, and Windows Update service status
- Calculates a 0–100 risk score with a fully explainable breakdown
- Generates specific, actionable recommendations
- Saves every scan to a local SQLite database
- Shows scan history and a risk-score trend chart
- Lets you compare two saved scans (before vs after applying fixes)

## What it deliberately does NOT do

- Does not scan or contact any other computer or network
- Does not send any network traffic anywhere
- Does not change firewall rules, stop services, or modify the registry
- Does not claim to detect specific CVEs / vulnerabilities — it reports
  configuration exposure only

## Requirements

- Windows 10/11
- Python 3.11+
- pip packages: Flask, psutil (see `requirements.txt`)

## Setup

```powershell
cd Attack-Surface-Reduction
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```powershell
python app.py
```

Then open a browser to:
- http://127.0.0.1:5000/ — landing page
- http://127.0.0.1:5000/dashboard — main dashboard

## Project structure

```
Attack-Surface-Reduction/
│
├── app.py                     # Flask app, routes, orchestration
├── requirements.txt
├── README.md
│
├── scanner/
│   ├── __init__.py
│   ├── system_info.py         # OS/CPU/RAM/network/uptime
│   ├── port_scanner.py        # Listening ports (local, passive)
│   ├── service_scanner.py     # Running processes cross-referenced with ports
│   ├── firewall_checker.py    # Windows Firewall status (netsh, read-only)
│   ├── security_checker.py    # UAC/RDP/Windows Update + finding aggregation
│   ├── risk_analyzer.py       # Explainable 0-100 risk scoring
│   └── recommendation_engine.py  # Finding -> Risk -> Reason -> Action
│
├── database/
│   ├── database.py            # SQLite schema, save/read scan history
│   └── scans.db                # created automatically on first run
│
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   └── report.html
│
└── static/
    ├── css/style.css
    └── js/dashboard.js
```

## API endpoints

| Route | Method | Description |
|---|---|---|
| `/` | GET | Landing page |
| `/dashboard` | GET | Main dashboard page |
| `/api/scan` | GET | Runs a full scan, saves it, returns JSON |
| `/api/history?limit=20` | GET | Returns recent scan summaries |
| `/api/scan/<id>` | GET | Returns full stored result for one scan |
| `/api/compare?before=X&after=Y` | GET | Compares two saved scans |

## Risk scoring methodology

The risk score (0–100) is a weighted sum of concrete, observed findings —
never random. Weights:

| Category | Max Points | Reasoning |
|---|---|---|
| Firewall disabled (any profile) | 25 | Primary network gatekeeper |
| Network-exposed listening ports | 30 (capped, 3 pts/port) | Each port is a potential entry point |
| Flagged third-party services | 15 (capped, 3 pts/service) | Lower weight — "flagged" ≠ confirmed risk |
| RDP enabled | 15 | Common brute-force/credential attack target |
| UAC disabled | 10 | Loses a privilege-escalation defense layer |
| Windows Update service stopped | 5 | Indirect risk if no alternate patch path |

Bands: 0–30 = Low, 31–60 = Medium, 61–100 = High.

### Known limitations

- Does not perform vulnerability scanning against known CVEs
- Windows Update check only verifies service status, not patch completeness
- Flagged services are recommended for manual review, not confirmed malicious
- Some registry checks (UAC, RDP) may be inconclusive without Administrator rights

## License / Usage

Built strictly for educational and defensive use, scanning only the machine
it is run on, with the owner's own authorization.
