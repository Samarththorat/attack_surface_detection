# Runtime Validation Report

**Generated:** 2026-10-29  
**Target:** Attack Surface Reduction & Security Assessment System

## Summary

| Validation | Status | Result |
|---|---|---|
| Startup and database initialization | PASS | Flask started on `127.0.0.1:5000` with an isolated SQLite database; 11 tables initialized |
| Python tests | PASS | 144 run, 0 failures, 0 errors, 0 skipped |
| Frontend tests | PASS | 27 run, 0 failures |
| JavaScript syntax | PASS | 14 files checked, 0 failures |
| Routes and read-only APIs | PASS | 9 page routes and 14 API routes returned HTTP 200 |
| Browser rendering | PASS | 8 pages at desktop and mobile widths; no console errors, failed requests, or horizontal overflow |
| Isolated Excel report | PASS | Counts matched seeded records; incomplete status and formula protection verified |
| Existing database preservation | PASS | SHA-256 unchanged; existing record counts unchanged |

**Overall:** PASS for the tested local demonstration scope. No application defect was confirmed; no production source files were changed.

## Startup and Browser Evidence

The documented Flask application was started on loopback with an isolated database path to avoid touching `database/scans.db`. The app initialized its schema and stopped cleanly. Pages checked: `/`, `/dashboard`, `/port-hardening`, `/attack-surface`, `/vulnerabilities`, `/analytics`, `/activity`, `/reports`, and `/task-monitoring`.

The 14 successful read-only API probes covered history, findings, analytics, Excel export, ports and port analysis, attack surface, monitoring status and events, task-monitoring snapshot and history, software inventory, vulnerabilities, and remediation history.

The integrated browser checked the eight primary application pages at approximately 1366px and 390px widths. No browser console errors, page errors, failed requests, HTTP errors, or viewport overflow were observed. The live monitoring banner reported healthy status. The task-monitoring snapshot returned measured CPU, memory, disk, process, and system I/O data. GPU, per-process network, and energy telemetry were explicitly unavailable rather than shown as measurements. The task snapshot took about 7 seconds on this host.

Port status was checked read-only for the local app port: firewall rule `NOT_PRESENT`, socket `LISTENING`, traffic verification `NOT_PERFORMED`. No firewall rule or service was changed.

## Test Evidence

- Python: full `unittest` discovery, run with `database.database.DB_PATH` redirected to a temporary SQLite file. **144 passed; 0 failed, 0 errors, 0 skipped; exit code 0.**
- Frontend: `node --test` over all `tests/*_frontend.js`. **27 passed; 0 failed; exit code 0.**
- Syntax: `node --check` across all `static/js/*.js` and `tests/*.js`. **14 checked; 0 failures; exit code 0.**
- Browser: 16 page/viewport checks, all HTTP 200. Zero observed JavaScript errors or failed API/resource requests.
- The integrated browser tool was used; local Playwright packages were not installed.

An initial ad-hoc workbook assertion assumed the CVE identifier was the first column. The workbook correctly places its database `id` column first; the check was corrected to use column headers and passed. This was a validation assertion issue, not an application defect.

## Isolated Excel Report

A temporary database was seeded with one partial scan and finding, one monitoring event, one incomplete vulnerability assessment and finding, one remediation record, and one system-monitoring sample. Exported counts matched stored rows:

| Record type | Stored | Exported |
|---|---:|---:|
| Scans | 1 | 1 |
| Security findings | 1 | 1 |
| Monitoring events | 1 | 1 |
| Vulnerability findings | 1 | 1 |
| Remediation records | 1 | 1 |
| System-monitoring samples | 1 | 1 |

Findings, monitoring events, vulnerabilities, and remediations appeared in separate sheets. Evidence remained readable, formula-like input was escaped, and the partial assessment/report status was disclosed.

## Existing Database Preservation

`database/scans.db` retained the same SHA-256 before and after validation:

`A06BC0C3296E44D780CECCCD04E58C317331C037E333ECEC7657AE322396DAB4`

Existing counts were unchanged: 76 scans, 2,430 monitoring events, 115 remediation records, and 3 vulnerability assessment runs. Runtime and report tests used temporary databases; those test databases were removed.

## Limitations

- Firewall and service remediation were not performed against the host. Remediation and synchronization were covered only by tests that mock privileged operations.
- Traffic blocking was not verified.
- The application has no login/session system and is suitable only for loopback use as configured; do not expose it on a shared or public network without appropriate deployment protections.
- Docker was unavailable and not required for this SQLite application. Python 3.14.6 was used; Node.js 26.9.0 was available.
- The task-monitoring API took about 7 seconds to return its live process snapshot on this machine.
