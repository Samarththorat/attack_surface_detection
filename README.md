# Attack Surface Reduction and Security Assessment System

A local Windows security-assessment dashboard for observing the current
machine's attack surface, assessing installed software against NIST NVD data,
prioritizing evidence-based findings, and recording remediation verification.
This is an educational project, not a certified security product.

## Project objectives

- Discover locally listening TCP/UDP sockets and their process associations.
- Review Windows Firewall, UAC, Remote Desktop, Windows Update, and services.
- Inventory installed software using read-only Windows Registry queries.
- Match software identity and available version data to CVE affected-version
  criteria in the NIST National Vulnerability Database (NVD).
- Explain a deterministic 0-100 risk score and finding priorities.
- Preserve scan, alert, finding-lifecycle, and remediation audit history.
- Provide trend analytics, scan comparisons, and Excel reporting.

The application does not scan other hosts or networks. An explicitly requested
online vulnerability assessment makes HTTPS requests to the official NVD API;
Chart.js is loaded from a public CDN for browser visualizations.

## Architecture and technology

- Python 3.11+, Flask, SQLite, `psutil`, and `openpyxl`.
- HTML, CSS, and JavaScript dashboard; Chart.js for charts.
- Windows built-in Registry, `netsh`, and Service Control Manager interfaces.
- `app.py` composes scanner, persistence, dashboard/API, scheduling, and report
  workflows. `database/database.py` owns SQLite initialization and additive
  migrations.

### Main modules

| Module | Responsibility |
|---|---|
| `scanner/system_info.py` | Local OS, hardware, network, and uptime metadata |
| `scanner/port_scanner.py` | Local TCP/UDP listening sockets |
| `scanner/service_scanner.py` | Running process/service inventory and review flags |
| `scanner/firewall_checker.py` | Read-only Windows Firewall profile status |
| `scanner/security_checker.py` | UAC, RDP, Windows Update, and configuration checks |
| `scanner/attack_surface.py` | Combined current inventory and observed changes |
| `scanner/monitor.py` | Singleton background monitor, change events, SSE |
| `scanner/task_monitoring.py` | Read-only process snapshots and system resource telemetry |
| `scanner/software_inventory.py` | Read-only installed-software registry inventory |
| `scanner/vulnerability_scanner.py` | NVD client, caching, CPE/version matching |
| `scanner/risk_analyzer.py` | 0-100 score, unified findings, priorities |
| `scanner/recommendation_engine.py` | Deterministic recommendations and impacts |
| `scanner/analytics.py` | Analytics from stored records and scan comparisons |
| `scanner/reporting.py` | In-memory Excel workbook generation |
| `scanner/port_hardening.py` | Confirmed, privileged firewall/service remediation |

## Windows setup and startup

Use PowerShell from the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/` or `http://127.0.0.1:5000/dashboard`.
The server binds to loopback and starts the single background monitor on its
first non-test request. Stop it with Ctrl+C.

To use an NVD API key, set `NVD_API_KEY` in the process environment before
starting the app. The key is optional, must not be committed, and is sent only
as the NVD API request header. For example, in the current PowerShell session:

```powershell
$env:NVD_API_KEY = "<your NVD API key>"
python app.py
```

NVD requests use a bounded timeout, a 24-hour local response cache, and handle
rate limits and offline operation. Automated tests mock NVD responses and do
not require network access.

## Database and data preservation

SQLite data is stored at `database/scans.db`. On startup, initialization uses
`CREATE TABLE IF NOT EXISTS` and additive `ALTER TABLE` migrations; it does
not delete existing scan, monitoring, or remediation records. Back up the
database file before manual changes, copying it while the app is stopped.
SQLite connections use a busy timeout for concurrent monitor and web activity.

Tables include scan history, remediation history, monitoring events, schedule
configuration, software inventory, vulnerability findings, NVD cache, and
finding lifecycle records. The app does not fabricate historical entries.

## Vulnerability assessment and limitations

The software inventory reads Windows uninstall registry keys under the
machine and current-user hives. It records available name, publisher, version,
install date/location, source, and detection time; missing metadata stays
unknown. It does not install, repair, or uninstall software.

NVD CVEs are matched using CPE vendor/product identity and exact or bounded
affected-version criteria. Product-description similarity without enough
version evidence is labeled a potential match. Each record includes evidence,
CVSS/severity when provided, references, status, and timestamp. A version
match does not establish exploitability, and a no-match result does not prove
that software is secure. Portable applications and products with incomplete
registry/CPE metadata may be missed or require manual review.

Assessment statuses are Confirmed Version Match, Potential Match, Insufficient
Information, No Matching Vulnerability Found, Assessment Incomplete, and
Vulnerability Source Unavailable.

The vulnerability page shows source-cache age separately from the latest
assessment state; cached data is not described as a live connection. An
assessment that is limited by the configured software cap or lacks required
version/source evidence is marked partial. The findings table keeps identity
matching, version-match confidence, vulnerability severity, and assessment
completeness as separate fields. Known test-fixture data is labeled
unverified and excluded from verified-match totals without modifying the
stored record. Excel reporting preserves the recorded status alongside its
effective, evidence-aware display status.

## Risk scoring and priorities

The score is a deterministic project heuristic from 0 to 100, capped at 100.
It is not a CVSS score, certification, or proof of compromise. The defaults
are documented in `scanner/risk_analyzer.py`:

| Component | Default weighting |
|---|---|
| Firewall | 25 when all profiles are disabled; 15 when partially disabled |
| RDP exposure | Up to 20, based on listener/interface evidence |
| Sensitive services | SMB 15; Telnet/VNC 12; unencrypted database 10; group cap 20 |
| Other listening ports | 2 per all-interface listener, 1 per specific-interface listener; cap 15 |
| Flagged services | 2 per service; cap 10; review flag is not proof of maliciousness |
| UAC / Windows Update | 10 / 5 when the respective control is disabled/stopped |
| Unknown process identity | 1 per listener; cap 5 |
| CVE findings | Confirmed: Critical 15, High 8, Medium 3; potential Critical/High 3; cap 25 |
| Failed remediation verification | 5 per deduplicated target; cap 10 |
| Unrepresented active monitoring events | High/Critical 5, Medium 2 per target; cap 15 |

Related findings are deduplicated before event-derived score points are added.
Priorities are P1 Immediate Review, P2 High Priority, P3 Planned Remediation,
and P4 Monitor. A listening socket is local evidence only: it does not prove
internet reachability. Exposure scope and confidence influence priority.

## Monitoring, alerts, and scheduling

One thread-safe monitor samples local ports, firewall profiles, security
settings, and flagged services. Failed samples are marked unavailable and are
not treated as evidence that a port or service disappeared. Meaningful changes
are persisted, and repeated process-change alerts use cooldown suppression.
The dashboard uses Server-Sent Events with polling fallback.

Alerts can be filtered by severity, acknowledged, and marked reviewed;
acknowledgment does not resolve a finding. The schedule uses the existing
monitor loop rather than a second scheduler. It supports intervals from 5
minutes to 7 days, category selection, optional NVD refresh, and optional
Excel report generation. Scheduling is disabled by default. Scan/API failures
are recorded as schedule errors.

## Remediation safety

Assessments and inventory collection are read-only. Firewall/service changes
are separate, user-triggered operations and require explicit confirmation;
operations requiring elevation return an error when the process is not
administrator-elevated. Port/protocol and service identifiers are validated,
protected core services cannot be disabled, subprocesses use argument lists,
and verification is performed after an action. Undo only removes application-
managed firewall rules. A failed or partial verification is recorded as such
and cannot mark a finding resolved. When an explicitly confirmed action is
reported as applied, the app stores a fresh local assessment and links it to
the remediation audit record with `verification_scan_id`, leaving the
initiating `scan_id` unchanged. Only independently verified firewall or
service state changes create their corresponding monitoring event.

Do not perform remediation on a production host as part of a demonstration.
Use an isolated Windows VM and an explicitly approved test target if you need
to demonstrate a privileged action.

## Dashboard and reports

The Overview page opens with the latest saved assessment, its completeness,
monitoring freshness, four data-backed summary values, the highest-priority
open findings, recent activity, and up to two charts. It does not launch a new
scan just by opening the page; use **Run New Assessment** to create and save a
new assessment. The Listening Ports card counts listening sockets detected by
the scanner; listening alone does not establish that a port is externally
exposed or vulnerable. The expandable overview tools retain scheduling and
recommendations; detailed ports, CVEs, activity, analytics, reports, and
remediation history are on their dedicated pages.

Use `/analytics` for stored risk history, severity and category distributions,
remediation outcomes, recorded port changes, and vulnerability trends. Use
`/activity` for the paginated monitoring event history and acknowledge/review
actions, `/task-monitoring` for live process and system-resource snapshots,
`/reports` to download the existing workbook, and the navigation links to access
Attack Surface, Port Hardening, and Vulnerabilities. Charts use stored backend
data only. Chart.js is CDN-hosted, so charts require browser access to the CDN;
text tables and API data remain available without it.

Task Monitoring refreshes live data every 5, 10, 30, or 60 seconds. System-level
resource samples are stored at most once per minute and retained for seven
days. Process snapshots are live only and are not retained. The page is
read-only: process termination is not offered. GPU utilization, per-process
network attribution, and per-process energy consumption are not available
through this collector and are displayed as unavailable rather than estimated.

`GET /api/reports/excel` downloads a workbook with executive summary, scan
history, findings, risk analysis, vulnerability findings, monitoring events,
remediation history, verification results, stored process/system samples,
trends, and methodology/limitations. Only stored records are included.
Formula-like spreadsheet text is escaped.
Scheduled report output is written to
`reports/latest-scheduled-assessment.xlsx`. PDF export is not implemented;
the optional dependency was not added.

## API overview

| Route | Method | Purpose |
|---|---|---|
| `/api/scan` | POST | Run and persist a local assessment |
| `/api/history`, `/api/scan/<id>` | GET | Read scan history or a stored scan |
| `/api/compare?before=X&after=Y` | GET | Compare score and complete finding snapshots |
| `/api/analytics` | GET | Return analytics from stored data |
| `/api/reports/excel` | GET | Download the Excel report |
| `/api/findings` | GET | Current unified findings |
| `/api/findings/<id>/status` | POST | Update lifecycle; Resolved requires verification |
| `/api/ports`, `/api/port-analysis` | GET | Inspect local ports and classifications |
| `/api/port/block`, `/api/port/unblock` | POST | Confirmed firewall-rule remediation |
| `/api/service/stop`, `/api/service/disable` | POST | Confirmed service remediation |
| `/api/remediation/verify`, `/api/remediation-history` | POST/GET | Verify and inspect audit history |
| `/api/task-monitoring/snapshot`, `/api/task-monitoring/history` | GET | Read live telemetry and bounded stored system samples |
| `/api/monitoring/status`, `/api/monitoring/events` | GET | Monitor health and alert records |
| `/api/monitoring/stream` | GET | SSE event stream |
| `/api/monitoring/events/<id>/acknowledge` | POST | Acknowledge without resolving |
| `/api/monitoring/events/<id>/review` | POST | Mark an alert reviewed |
| `/api/schedule` | GET/POST | Read or configure scheduled assessments |
| `/api/attack-surface/changes` | GET | Read monitor health, last successful check, and current changes |
| `/api/software-inventory` | GET | Read stored inventory; `?fresh=true` refreshes it |
| `/api/vulnerabilities` | GET | Filter stored CVE findings |
| `/api/vulnerabilities/scan` | POST | Assess installed software against NVD/cache |

`/api/scan` returns the computed risk object under both `risk` and the
backward-compatible `risk_score` alias. `risk.breakdown` remains the legacy
object of named category totals and includes `items`, an array of itemized
category records. `risk.breakdown_items` is the canonical array for chart
consumers; each entry contains `category`, `points_awarded`, `max_points`,
`finding_type`, `severity`, and `reason`. Scores use these bands: 0–24 Low,
25–54 Medium, 55–79 High, and 80–100 Critical. The `level` field uses uppercase
labels, and `risk_level` uses title case for the same band.
The response also includes `assessment_status` (`COMPLETE` or `PARTIAL`) and
`incomplete_sections`; a partial vulnerability assessment is not represented
as a complete zero-finding result. Monitoring status distinguishes the latest
check from the last fully successful sample. Port analysis reports firewall
rule presence, socket listening state, and traffic-block verification
separately; firewall rule presence alone does not verify traffic blocking or
close the local socket.

Browser-originated state-changing requests are restricted to the same origin.
There is no login/session system; the development server is intentionally
loopback-only. Do not bind it to a public or shared network without adding
authentication, authorization, HTTPS, and a deployment security review.

## Testing

Install declared dependencies, then run the complete standard-library test
suite (external APIs and privileged actions are mocked):

```

Check the vulnerability page JavaScript:

```powershell
node --check static\js\vulnerabilities.js
node --test tests\test_vulnerabilities_frontend.js
```powershell
python -m pip install -r requirements.txt
python -m unittest discover -v
```

Run focused phase tests as needed:

```powershell
python -m unittest tests.test_phase4_vulnerability -v
python -m unittest tests.test_phase5_monitoring_risk -v
python -m unittest tests.test_phase6_analytics_reporting -v
python -m unittest tests.test_phase7_monitoring_reliability -v
python -m unittest tests.test_phase8_request_origin -v
```

## Safe demonstration guide

1. Start the app locally and open the dashboard; avoid sharing visible
   hostname, process, or inventory details in screenshots.
2. Run a local scan and show its stored score, evidence, and comparison view.
3. Open `http://127.0.0.1:5000/vulnerabilities`. The overview cards and
   inventory use stored/collected backend data. Use the inventory search,
   sort headers, and page-size control to inspect the read-only registry data.
4. For a no-network CVE demo, run:
   `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/vulnerabilities/scan -ContentType 'application/json' -Body '{"offline_mode":true,"max_items":10}'`.
   This uses locally available cache data and does not invent CVE matches;
   the page reports partial or unavailable results when no cache is present.
5. Open `/task-monitoring` to review the live, read-only process snapshot and
   system-resource charts. Choose a refresh interval; process details are not
   retained, and historical resource charts appear only after samples have
   been stored.
6. Review analytics and download the Excel report; sections with no stored data
   will explicitly show no records.
7. Demonstrate scheduling with a long interval and disable it afterward.
8. Do not stop services or change firewall rules on a real machine. Demonstrate
   those flows through the mocked automated tests, or in an isolated VM after
   explicit authorization.

## Troubleshooting and known limitations

- Run from the project root with Python 3.11+ and install `requirements.txt`.
- Registry, service, and firewall visibility varies with Windows version and
  administrator privileges; inconclusive observations remain unknown.
- NVD connectivity can be unavailable or rate-limited. Cached/offline results
  are used when possible; otherwise findings indicate an incomplete or
  unavailable source, not a clean bill of health.
- The NVD keyword query is bounded to a limited number of results per product;
  matching may miss records beyond that response window.
- Analytics are limited to retained records (typically the latest 500 scans or
  1,000 events/actions per report section); the application does not synthesize
  prior values.
- Historical comparison classifies absence only for comparable scans with
  complete required sections; it is not independent remediation verification.
- The system is local-only, has no user authentication, and is an educational
  heuristic. Do not expose it as a network service.
- Chart.js requires the CDN; PDF reports and email notifications are not
  implemented.

## License and use

For educational, defensive assessment of the machine on which it is run, with
the owner's authorization. No license grant is implied by this project notice.
