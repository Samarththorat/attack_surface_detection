"""
app.py
Main Flask application for the Attack Surface Reduction & Security
Assessment System. Wires together all scanner modules into a web app.
"""

import json
import ipaddress
import queue
import os
import threading
import datetime
from urllib.parse import urlsplit
from flask import Flask, render_template, jsonify, request, Response, send_file

from scanner.system_info import collect_system_info
from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_running_services, get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import run_security_checks
from scanner.risk_analyzer import calculate_risk_score, get_unified_findings
from scanner.recommendation_engine import generate_recommendations
from scanner.port_risk_analyzer import get_port_analysis, get_port_by_number
from scanner.port_hardening import (
    block_port, unblock_port, is_port_blocked,
    stop_service, disable_service, get_service_info,
    is_admin_user, get_asr_blocked_ports, is_protected_service,
    execute_remediation_with_verification, get_service_remediation_metadata,
    _check_listening_socket,
)
from scanner.attack_surface import get_attack_surface_inventory, get_attack_surface_changes
from scanner.monitor import get_monitor
from scanner.software_inventory import get_installed_software
from scanner.vulnerability_scanner import run_vulnerability_scan
from scanner.analytics import build_security_analytics, compare_scans
from scanner.reporting import build_excel_report
from scanner.task_monitoring import task_monitoring_collector
from database.database import (
    init_db, save_scan, get_scan_history, get_scan_by_id,
    save_remediation_action, get_remediation_history,
    get_monitoring_events, resolve_monitoring_event,
    get_monitoring_event_severity_counts,
    get_software_inventory, save_software_inventory,
    get_vulnerability_findings,
    get_vulnerability_overview,
    record_vulnerability_assessment_run,
    get_latest_vulnerability_assessment_run,
    get_cve_cache_status,
    save_monitoring_event,
    get_finding_lifecycles, update_finding_status,
    update_monitoring_event_state,
    get_scheduled_assessment_config, save_scheduled_assessment_config,
    record_scheduled_assessment,
    get_system_monitor_samples,
    link_remediation_verification_scan,
)


app = Flask(__name__)

# Ensure the database and table exist as soon as the app starts
init_db()

# Initialize monitor
monitor = get_monitor()
assessment_lock = threading.Lock()


@app.before_request
def reject_cross_origin_mutations():
    """Keep the unauthenticated single-user app accessible only over loopback."""
    remote_addr = request.remote_addr
    try:
        if not remote_addr or not ipaddress.ip_address(remote_addr).is_loopback:
            return jsonify({"error": "This application is restricted to loopback clients."}), 403
    except ValueError:
        return jsonify({"error": "Invalid client address."}), 403

    # Reject browser-originated state changes from origins other than this app.
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    origin = request.headers.get("Origin")
    if not origin:
        return None
    try:
        parsed_origin = urlsplit(origin)
    except ValueError:
        return jsonify({"error": "Invalid request origin."}), 403
    if (
        parsed_origin.scheme != request.scheme
        or not parsed_origin.netloc
        or parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.path not in ("", "/")
        or parsed_origin.query
        or parsed_origin.fragment
        or parsed_origin.netloc.casefold() != request.host.casefold()
    ):
        return jsonify({"error": "Cross-origin state-changing requests are not allowed."}), 403
    return None


def start_background_monitor():
    """Starts the monitor thread if not in test mode."""
    if not app.config.get("TESTING") and not monitor.is_active():
        monitor.start()


@app.before_request
def ensure_background_monitor():
    """Start monitoring on the first production request; test clients remain side-effect free."""
    start_background_monitor()


def run_full_scan(categories=None, refresh_vulnerabilities=False):
    """
    Runs every scanner module and assembles a single results dictionary.
    Wrapped in try/except per-section so one failing module doesn't
    break the entire scan (per project error-handling requirements).
    """
    results = {}
    selected = set(categories or ("network", "security"))

    try:
        results["system_info"] = collect_system_info()
    except Exception as e:
        results["system_info"] = {"error": str(e)}

    if "network" in selected:
        try:
            results["ports"] = get_listening_ports()
        except Exception as e:
            results["ports"] = {"error": str(e)}

        try:
            results["services"] = get_running_services()
            results["flagged_services"] = get_flagged_services()
        except Exception as e:
            results["services"] = {"error": str(e)}
            results["flagged_services"] = []

    if "security" in selected:
        try:
            results["firewall"] = get_firewall_status()
        except Exception as e:
            results["firewall"] = {"error": str(e)}

        try:
            results["security_findings"] = run_security_checks()
        except Exception as e:
            results["security_findings"] = {"error": str(e)}

    if "vulnerabilities" in selected:
        try:
            software = get_installed_software()
            save_software_inventory(software)
            vulnerability_result = run_vulnerability_scan(
                software_list=software,
                offline_mode=not refresh_vulnerabilities,
                persist=False,
            )
            results["vulnerabilities"] = vulnerability_result.get("findings", [])
            results["vulnerability_scan"] = vulnerability_result
            statuses = vulnerability_result.get("statuses", {})
            incomplete_statuses = {
                "Insufficient Information",
                "Assessment Incomplete",
                "Vulnerability Source Unavailable",
            }
            software_evaluated = vulnerability_result.get("software_count", 0)
            assessment_complete = (
                software_evaluated >= len(software)
                and not any(statuses.get(status, 0) for status in incomplete_statuses)
            )
            results["vulnerability_scan"]["assessment_complete"] = assessment_complete
            record_vulnerability_assessment_run(
                software_evaluated=software_evaluated,
                findings=results["vulnerabilities"],
                assessment_complete=assessment_complete,
                software_total=len(software),
            )
        except Exception as e:
            results["vulnerabilities"] = {"error": str(e)}
            results["vulnerability_scan"] = {"error": str(e), "assessment_complete": False}

    # Aliases for API compatibility
    results["open_ports"] = results.get("ports", [])
    results["security_checks"] = results.get("security_findings", [])
    try:
        results["monitoring_events"] = get_monitoring_events(limit=1000, unresolved_only=True)
    except Exception:
        app.logger.exception("Unable to include monitoring events in risk analysis")
        results["monitoring_events"] = []
    try:
        results["risk"] = calculate_risk_score(results)
    except Exception as e:
        results["risk"] = {"error": str(e)}

    risk = results.get("risk")
    if isinstance(risk, dict):
        for finding in risk.get("unified_findings", []):
            if finding.get("priority_code") not in ("P1", "P2"):
                continue
            if finding.get("status") in ("Resolved", "Accepted Risk"):
                continue
            save_monitoring_event(
                event_type="HIGH_PRIORITY_FINDING",
                severity=finding.get("severity", "HIGH"),
                component=finding.get("category", "security"),
                target=finding.get("id", finding.get("title", "finding")),
                details=finding,
                cooldown_seconds=900,
            )

    try:
        results["recommendations"] = generate_recommendations(results)
    except Exception as e:
        results["recommendations"] = {"error": str(e)}

    incomplete_sections = []
    section_names = {
        "system_info": ("system_info",),
        "network": ("ports", "services", "flagged_services"),
        "security": ("firewall", "security_findings"),
        "vulnerabilities": ("vulnerability_scan",),
    }
    if isinstance(results.get("system_info"), dict) and results["system_info"].get("error"):
        incomplete_sections.append("system_info")
    for category, keys in section_names.items():
        if category not in selected:
            continue
        incomplete_sections.extend(
            key for key in keys
            if isinstance(results.get(key), dict) and results[key].get("error")
        )
    vulnerability_scan = results.get("vulnerability_scan")
    if (
        "vulnerabilities" in selected
        and isinstance(vulnerability_scan, dict)
        and vulnerability_scan.get("assessment_complete") is False
        and "vulnerabilities" not in incomplete_sections
    ):
        incomplete_sections.append("vulnerabilities")
    if isinstance(results.get("risk"), dict) and results["risk"].get("error"):
        incomplete_sections.append("risk")
    if isinstance(results.get("recommendations"), dict) and results["recommendations"].get("error"):
        incomplete_sections.append("recommendations")
    results["incomplete_sections"] = sorted(set(incomplete_sections))
    results["assessment_status"] = "PARTIAL" if incomplete_sections else "COMPLETE"

    results["risk_score"] = results.get("risk", {})
    results["assessment_categories"] = sorted(selected)

    return results


def run_due_scheduled_assessment():
    """Runs a due assessment on the existing monitor loop, never a second scheduler thread."""
    config = get_scheduled_assessment_config()
    if not config or not config.get("enabled") or not config.get("next_run"):
        return
    try:
        next_run = datetime.datetime.strptime(config["next_run"], "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        app.logger.error("Scheduled assessment has an invalid next_run timestamp.")
        return
    if datetime.datetime.now() < next_run:
        return
    if not assessment_lock.acquire(blocking=False):
        return

    run_time = datetime.datetime.now()
    next_time = run_time + datetime.timedelta(minutes=config["interval_minutes"])
    error = None
    try:
        results = run_full_scan(
            categories=config.get("categories"),
            refresh_vulnerabilities=config.get("refresh_vulnerabilities", False),
        )
        scan_id = save_scan(results)
        if scan_id is None:
            raise RuntimeError("Scheduled assessment completed but could not be saved.")
        if config.get("generate_report"):
            report_dir = os.path.join(os.path.dirname(__file__), "reports")
            os.makedirs(report_dir, exist_ok=True)
            report = build_excel_report()
            with open(os.path.join(report_dir, "latest-scheduled-assessment.xlsx"), "wb") as report_file:
                report_file.write(report.getvalue())
    except Exception as exc:
        error = str(exc)
        app.logger.exception("Scheduled assessment failed")
    finally:
        try:
            record_scheduled_assessment(
                run_time.strftime("%Y-%m-%d %H:%M:%S"),
                next_time.strftime("%Y-%m-%d %H:%M:%S") if config.get("enabled") else None,
                error=error,
            )
        except Exception:
            app.logger.exception("Unable to persist scheduled assessment outcome")
        assessment_lock.release()


monitor.set_scheduled_assessment_callback(run_due_scheduled_assessment)


@app.route("/")
def index():
    """Landing page - simple welcome/start-scan page."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Main dashboard page (renders template; data loaded via JS fetch)."""
    return render_template("dashboard.html")


@app.route("/analytics")
def analytics_page():
    """Historical analytics page backed by persisted assessment data."""
    return render_template("analytics.html")


@app.route("/reports")
def reports_page():
    """Reports page for existing assessment exports."""
    return render_template("reports.html")


@app.route("/activity")
def activity_page():
    """Monitoring event history and review actions."""
    return render_template("activity.html")


@app.route("/task-monitoring")
def task_monitoring_page():
    """Read-only process and system-resource monitoring page."""
    return render_template("task_monitoring.html")


@app.route("/api/task-monitoring/snapshot", methods=["GET"])
def api_task_monitoring_snapshot():
    """Return a live, read-only snapshot of process and system resources."""
    try:
        return jsonify(task_monitoring_collector.collect())
    except Exception:
        app.logger.exception("api_task_monitoring_snapshot failed")
        return jsonify({"error": "Unable to collect task-monitoring data."}), 500


@app.route("/api/task-monitoring/history", methods=["GET"])
def api_task_monitoring_history():
    """Return stored system-resource samples for a bounded historical window."""
    hours = request.args.get("hours", default=24, type=int)
    if hours is None or not 1 <= hours <= 168:
        return jsonify({"error": "hours must be between 1 and 168."}), 400
    try:
        return jsonify(get_system_monitor_samples(hours=hours))
    except Exception:
        app.logger.exception("api_task_monitoring_history failed")
        return jsonify({"error": "Unable to load stored task-monitoring history."}), 500


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Runs a full scan, saves it to the database, and returns all results
    as JSON. The risk object retains its legacy breakdown totals object and
    also exposes breakdown_items as the canonical array for dashboard charts.
    """
    try:
        with assessment_lock:
            results = run_full_scan()
            risk = results.get("risk")
            if isinstance(risk, dict) and not risk.get("error"):
                if "breakdown_items" not in risk:
                    legacy_breakdown = risk.get("breakdown")
                    if isinstance(legacy_breakdown, list):
                        risk["breakdown_items"] = legacy_breakdown
                    elif isinstance(legacy_breakdown, dict) and isinstance(legacy_breakdown.get("items"), list):
                        risk["breakdown_items"] = legacy_breakdown["items"]
                    else:
                        app.logger.error("Scan response has no valid risk breakdown item list.")
                        risk["breakdown_items"] = []
                        risk["breakdown_error"] = "Risk breakdown data is missing or invalid."
                elif not isinstance(risk["breakdown_items"], list):
                    app.logger.error("Scan response risk breakdown_items is not an array.")
                    risk["breakdown_items"] = []
                    risk["breakdown_error"] = "Risk breakdown data has an unexpected format."
                results["risk_score"] = risk
            scan_id = save_scan(results)
            if scan_id is None:
                app.logger.error("Scan completed but its results could not be persisted.")
                return jsonify({"error": "Scan completed but could not be saved to scan history."}), 500
    except Exception as exc:
        app.logger.exception("Scan request failed.")
        return jsonify({"error": f"Scan failed: {exc}"}), 500
    results["scan_id"] = scan_id  # let the frontend know which DB row this was

    return jsonify(results)


@app.route("/api/history", methods=["GET"])
def api_history():
    """Returns a lightweight list of previous scans (newest first)."""
    limit = request.args.get("limit", default=20, type=int)
    history = get_scan_history(limit=limit)
    return jsonify(history)


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_scan_detail(scan_id):
    """Returns the full stored result for a single past scan."""
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/compare")
def api_compare():
    """
    Compares two saved scans by ID, passed as query params:
    /api/compare?before=3&after=6
    Returns both full scans plus a computed delta summary.
    """
    before_id = request.args.get("before", type=int)
    after_id = request.args.get("after", type=int)

    if before_id is None or after_id is None:
        return jsonify({"error": "Both 'before' and 'after' scan IDs are required."}), 400

    before_scan = get_scan_by_id(before_id)
    after_scan = get_scan_by_id(after_id)

    if before_scan is None or after_scan is None:
        return jsonify({"error": "One or both scan IDs were not found."}), 404

    before_score = before_scan.get("risk_score")
    after_score = after_scan.get("risk_score")
    delta = {
        "ports_change": (
            after_scan["listening_ports_count"] - before_scan["listening_ports_count"]
            if after_scan.get("listening_ports_count") is not None and before_scan.get("listening_ports_count") is not None
            else None
        ),
        "findings_change": (
            after_scan["findings_count"] - before_scan["findings_count"]
            if after_scan.get("findings_count") is not None and before_scan.get("findings_count") is not None
            else None
        ),
        "risk_score_change": after_score - before_score if before_score is not None and after_score is not None else None,
        "findings": compare_scans(before_id, after_id),
    }

    return jsonify({
        "before": before_scan,
        "after": after_scan,
        "delta": delta,
    })


@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    """Returns historical analytics derived from persisted project data."""
    try:
        return jsonify(build_security_analytics())
    except Exception:
        app.logger.exception("api_analytics failed")
        return jsonify({"error": "Unable to build security analytics from stored data."}), 500


@app.route("/api/reports/excel", methods=["GET"])
def api_excel_report():
    """Downloads an Excel workbook generated from persisted assessment data."""
    try:
        return send_file(
            build_excel_report(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name="attack-surface-security-assessment.xlsx",
        )
    except Exception:
        app.logger.exception("Excel report generation failed")
        return jsonify({"error": "Unable to generate the Excel assessment report."}), 500


@app.route("/api/findings", methods=["GET"])
def api_findings():
    """Returns findings from the latest stored scan and persisted lifecycle metadata."""
    history = get_scan_history(limit=1)
    latest = get_scan_by_id(history[0]["id"]) if history else None
    results = (latest or {}).get("full_results") or {}
    findings = (results.get("risk") or {}).get("unified_findings") or []
    return jsonify({"count": len(findings), "findings": findings})


@app.route("/api/findings/<path:finding_id>/status", methods=["POST"])
def api_update_finding_status(finding_id):
    """Updates finding lifecycle state; Resolved requires fresh independent verification."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required."}), 400
    status = data.get("status")
    notes = data.get("notes")
    assigned_to = data.get("assigned_to")
    if not isinstance(status, str):
        return jsonify({"error": "A valid finding status is required."}), 400

    lifecycles = get_finding_lifecycles(limit=1000)
    finding = next((item for item in lifecycles if item.get("finding_id") == finding_id), None)
    if finding is None:
        return jsonify({"error": "Finding lifecycle record not found."}), 404

    verification_status = None
    if status == "Resolved":
        target_type = finding.get("target_type")
        target_name = finding.get("target_name") or ""
        verified = False
        if target_type == "port":
            try:
                port_text, protocol = target_name.split("/", 1)
                port = int(port_text)
                blocked = is_port_blocked(port, protocol)
                socket_state = _check_listening_socket(port, protocol)
                verified = bool(blocked.get("blocked")) and not bool(socket_state.get("listening"))
            except (ValueError, TypeError):
                verified = False
        elif target_type == "service":
            state = get_service_info(target_name)
            verified = bool(state) and (
                state.get("status") in ("stopped", "stop_pending")
                or state.get("start_type") == "disabled"
            )
        elif target_type == "firewall":
            firewall = get_firewall_status()
            verified = firewall.get("overall_status") == "PROTECTED"
        elif target_type == "policy":
            checks = run_security_checks()
            matched_check = next((item for item in checks if item.get("title") == target_name), None)
            verified = bool(matched_check) and matched_check.get("status") == "PASS"
        elif target_type == "software":
            cve_id = finding.get("title", "").split(" ", 1)[0]
            software_name = finding.get("title", "").split(" in ", 1)[-1].split(" (", 1)[0]
            latest_vulns = get_vulnerability_findings(limit=1000)
            verified = not any(
                row.get("cve_id") == cve_id
                and row.get("software_name") == software_name
                and row.get("effective_assessment_status") in (
                    "Confirmed Version Match",
                    "Potential Match",
                )
                for row in latest_vulns
            )
        if not verified:
            return jsonify({
                "error": "Finding was not marked resolved because independent verification did not confirm remediation."
            }), 409
        verification_status = "VERIFIED"

    try:
        updated = update_finding_status(
            finding_id,
            status,
            notes=notes,
            assigned_to=assigned_to,
            verification_status=verification_status,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not updated:
        return jsonify({"error": "Unable to update finding lifecycle."}), 404
    return jsonify({"success": True, "finding_id": finding_id, "status": status})


@app.route("/port-hardening")
def port_hardening_page():
    """Port Hardening & Attack Surface Reduction page."""
    return render_template("port_hardening.html")


@app.route("/api/ports", methods=["GET"])
def api_ports():
    """Returns the raw (enhanced) listening-port list, unclassified."""
    try:
        ports = get_listening_ports()
        return jsonify(ports)
    except Exception as e:
        app.logger.error(f"api_ports failed: {e}")
        return jsonify({"error": "Unable to read listening ports."}), 500


@app.route("/api/ports/<int:port_number>", methods=["GET"])
def api_port_detail(port_number):
    """Returns all classified entries matching a specific port number."""
    try:
        matches = get_port_by_number(port_number)
        return jsonify(matches)
    except Exception as e:
        app.logger.error(f"api_port_detail failed: {e}")
        return jsonify({"error": "Unable to read this port."}), 500


@app.route("/api/port-analysis", methods=["GET"])
def api_port_analysis():
    """Returns every listening port, classified by risk, with a summary."""
    try:
        analysis = get_port_analysis()
        admin_status = is_admin_user()

        for p in analysis.get("ports", []):
            p["firewall_rule_status"] = p.get(
                "firewall_rule_status",
                "ACTIVE" if p.get("is_blocked") else "NOT_PRESENT",
            )
            p["traffic_block_verification"] = "NOT_PERFORMED"
            svc_name = p.get("service_name")
            p["is_protected_service"] = is_protected_service(svc_name)[0] if svc_name else False

        analysis["is_admin"] = admin_status
        return jsonify(analysis)
    except Exception as e:
        app.logger.error(f"api_port_analysis failed: {e}")
        return jsonify({"error": "Unable to analyze ports."}), 500


@app.route("/api/port/<int:port_number>/status", methods=["GET"])
def api_port_status(port_number):
    """
    Verifies whether a specific port currently has an ASR firewall block
    rule applied. Used by the UI's Refresh/Verify action.
    """
    protocol = request.args.get("protocol", default="TCP")
    try:
        result = is_port_blocked(port_number, protocol)
        socket_state = _check_listening_socket(port_number, protocol)
        result["firewall_rule_status"] = (
            "UNKNOWN" if result.get("error") else "ACTIVE" if result.get("blocked") else "NOT_PRESENT"
        )
        result["socket_status"] = (
            "UNKNOWN" if socket_state.get("error")
            else "LISTENING" if socket_state.get("listening")
            else "NOT_LISTENING"
        )
        result["is_listening"] = socket_state.get("listening")
        result["traffic_block_verification"] = "NOT_PERFORMED"
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"api_port_status failed: {e}")
        return jsonify({"error": "Unable to verify port status."}), 500


def _synchronize_after_remediation(action_type, result, port=None, protocol=None):
    """Refresh saved state and publish verified remediation changes."""
    if not result.get("action_applied"):
        return

    firewall_state = result.get("firewall_state")
    expected_firewall_state = {
        "BLOCK_PORT": "BLOCKED",
        "UNBLOCK_PORT": "UNBLOCKED",
    }.get(action_type)
    if result.get("verified") is True and expected_firewall_state == firewall_state:
        try:
            event_id = save_monitoring_event(
                event_type="FIREWALL_RULE_CHANGED",
                severity="INFO",
                component="firewall",
                target=f"{port}/{protocol}",
                details={
                    "action_type": action_type,
                    "firewall_state": firewall_state,
                    "socket_state": result.get("socket_state", "UNKNOWN"),
                    "verification_status": result.get("verification_status", "INCONCLUSIVE"),
                    "remediation_id": result.get("audit_record_id"),
                },
                is_resolved=1,
            )
            result["firewall_event_id"] = event_id
            result["firewall_event_saved"] = event_id is not None
        except Exception:
            app.logger.exception("Unable to record verified firewall change for %s/%s", port, protocol)
            result["firewall_event_saved"] = False
            result["firewall_event_error"] = "The verified change could not be added to monitoring history."

    if action_type in ("STOP_SERVICE", "DISABLE_SERVICE") and result.get("verified") is True:
        try:
            event_id = save_monitoring_event(
                event_type="SERVICE_REMEDIATION_VERIFIED",
                severity="INFO",
                component="service",
                target=result.get("target", ""),
                details={
                    "action_type": action_type,
                    "previous_state": result.get("previous_state"),
                    "new_state": result.get("new_state"),
                    "verification_status": result.get("verification_status", "INCONCLUSIVE"),
                    "remediation_id": result.get("audit_record_id"),
                },
                is_resolved=1,
            )
            result["service_event_id"] = event_id
            result["service_event_saved"] = event_id is not None
        except Exception:
            app.logger.exception("Unable to record verified service change for %s", result.get("target"))
            result["service_event_saved"] = False
            result["service_event_error"] = "The verified change could not be added to monitoring history."

    try:
        with assessment_lock:
            assessment = run_full_scan()
            scan_id = save_scan(assessment)
        if scan_id is None:
            raise RuntimeError("The refreshed assessment could not be saved.")
        result["assessment_refresh"] = {
            "status": assessment.get("assessment_status", "UNKNOWN"),
            "scan_id": scan_id,
        }
        remediation_id = result.get("audit_record_id")
        if remediation_id is not None:
            result["assessment_scan_linked"] = link_remediation_verification_scan(
                remediation_id, scan_id
            )
            if not result["assessment_scan_linked"]:
                app.logger.warning(
                    "Post-remediation assessment %s could not be linked to audit record %s",
                    scan_id,
                    remediation_id,
                )
        else:
            result["assessment_scan_linked"] = False
    except Exception:
        app.logger.exception("Unable to refresh assessment after %s", action_type)
        result["assessment_refresh"] = {
            "status": "UNAVAILABLE",
            "message": "The remediation result is recorded, but a refreshed assessment could not be saved.",
        }

    try:
        monitor.publish_event({
            "type": "remediation",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "data": {
                "action_type": action_type,
                "target": result.get("target") or (f"{port}/{protocol}" if port else ""),
                "success": bool(result.get("success")),
                "verification_status": result.get("verification_status", "INCONCLUSIVE"),
                "audit_record_id": result.get("audit_record_id"),
                "assessment_refresh": result.get("assessment_refresh"),
            },
        })
        result["dashboard_notification_sent"] = True
    except Exception:
        app.logger.exception("Unable to publish remediation update for %s", action_type)
        result["dashboard_notification_sent"] = False


@app.route("/api/port/block", methods=["POST"])
def api_port_block():
    """
    Blocks a port via Windows Firewall. Requires an explicit confirm=true
    in the JSON body - without it, the action is refused (not performed).
    Body: {"port": 3389, "protocol": "TCP", "confirm": true, "reason": "optional"}
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON request body is required."}), 400
    port = data.get("port")
    protocol = data.get("protocol")
    confirm = data.get("confirm") is True
    reason = data.get("reason", "User-initiated port block via Port Hardening page")
    scan_id = data.get("scan_id")

    try:
        result = execute_remediation_with_verification(
            action_type="BLOCK_PORT",
            target_type="port",
            target_name=f"{port}/{protocol}",
            port=port,
            protocol=protocol,
            confirm=confirm,
            reason=reason,
            scan_id=scan_id,
        )
    except Exception as e:
        app.logger.error(f"api_port_block crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while blocking port."}), 500

    _synchronize_after_remediation("BLOCK_PORT", result, port=port, protocol=protocol)
    status_code = 200 if result.get("success") else (403 if result.get("error") == "elevation_required" else 400)
    return jsonify(result), status_code


@app.route("/api/port/unblock", methods=["POST"])
def api_port_unblock():
    """
    Removes a previously created ASR firewall block rule for a port.
    Body: {"port": 3389, "protocol": "TCP", "confirm": true}
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON request body is required."}), 400
    port = data.get("port")
    protocol = data.get("protocol")
    confirm = data.get("confirm") is True
    reason = data.get("reason", "User-initiated port unblock via Port Hardening page")
    scan_id = data.get("scan_id")

    try:
        result = execute_remediation_with_verification(
            action_type="UNBLOCK_PORT",
            target_type="port",
            target_name=f"{port}/{protocol}",
            port=port,
            protocol=protocol,
            confirm=confirm,
            reason=reason,
            scan_id=scan_id,
        )
    except Exception as e:
        app.logger.error(f"api_port_unblock crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while unblocking port."}), 500

    _synchronize_after_remediation("UNBLOCK_PORT", result, port=port, protocol=protocol)
    status_code = 200 if result.get("success") else (403 if result.get("error") == "elevation_required" else 400)
    return jsonify(result), status_code


@app.route("/api/service/info", methods=["GET"])
def api_service_info():
    """Returns current state/startup-type, dependencies, and operational impact for a service."""
    service_name = request.args.get("name", "")
    if not service_name:
        return jsonify({"error": "Service name is required."}), 400
    try:
        meta = get_service_remediation_metadata(service_name)
        if meta is None:
            return jsonify({"error": f"Service '{service_name}' not found."}), 404
        return jsonify(meta)
    except Exception as e:
        app.logger.error(f"api_service_info failed: {e}")
        return jsonify({"error": "Unable to read service info."}), 500


@app.route("/api/service/stop", methods=["POST"])
def api_service_stop():
    """
    Stops a running service. Requires confirm=true.
    Body: {"service_name": "TermService", "confirm": true}
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON request body is required."}), 400
    service_name = data.get("service_name")
    confirm = data.get("confirm") is True
    reason = data.get("reason", "User-initiated service stop via Port Hardening page")
    scan_id = data.get("scan_id")

    try:
        result = execute_remediation_with_verification(
            action_type="STOP_SERVICE",
            target_type="service",
            target_name=service_name,
            service_name=service_name,
            confirm=confirm,
            reason=reason,
            scan_id=scan_id,
        )
    except Exception as e:
        app.logger.error(f"api_service_stop crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while stopping service."}), 500

    _synchronize_after_remediation("STOP_SERVICE", result)
    status_code = 200 if result.get("success") else (403 if result.get("error") == "elevation_required" else 400)
    return jsonify(result), status_code


@app.route("/api/service/disable", methods=["POST"])
def api_service_disable():
    """
    Sets a service's startup type to Disabled.
    Requires confirm=true AND confirm_disable=true.
    Body: {"service_name": "TermService", "confirm": true, "confirm_disable": true}
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "A JSON request body is required."}), 400
    service_name = data.get("service_name")
    confirm = data.get("confirm") is True
    confirm_disable = data.get("confirm_disable") is True
    reason = data.get("reason", "User-initiated service disable via Port Hardening page")
    scan_id = data.get("scan_id")

    try:
        result = execute_remediation_with_verification(
            action_type="DISABLE_SERVICE",
            target_type="service",
            target_name=service_name,
            service_name=service_name,
            confirm=confirm,
            confirm_disable=confirm_disable,
            reason=reason,
            scan_id=scan_id,
        )
    except Exception as e:
        app.logger.error(f"api_service_disable crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while disabling service."}), 500

    _synchronize_after_remediation("DISABLE_SERVICE", result)
    status_code = 200 if result.get("success") else (403 if result.get("error") == "elevation_required" else 400)
    return jsonify(result), status_code


@app.route("/api/remediation/verify", methods=["POST"])
def api_remediation_verify():
    """
    Independently verifies whether a port firewall rule or service state is active.
    Body: {"target_type": "port"|"service", "port": 3389, "protocol": "TCP", "service_name": "TermService"}
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required."}), 400
    target_type = (data.get("target_type") or "").strip().lower()

    try:
        if target_type == "port":
            port = data.get("port")
            protocol = data.get("protocol", "TCP")
            blk = is_port_blocked(port, protocol)
            sock = _check_listening_socket(port, protocol)
            is_blocked = blk.get("blocked", False)
            is_listening = sock.get("listening", False)

            if blk.get("error"):
                status = "INCONCLUSIVE"
                msg = "Verification inconclusive."
            elif is_blocked and not is_listening:
                status = "RESOLVED"
                msg = f"Port {port}/{protocol} is blocked by firewall and closed locally."
            elif is_blocked and is_listening:
                status = "PARTIALLY_RESOLVED"
                msg = f"Port {port}/{protocol} is blocked by firewall, but listening locally."
            else:
                status = "UNRESOLVED"
                msg = f"Port {port}/{protocol} has no active ASR firewall block rule."

            return jsonify({
                "target_type": "port",
                "port": port,
                "protocol": protocol,
                "is_blocked": is_blocked,
                "is_listening": is_listening,
                "firewall_rule_status": (
                    "UNKNOWN" if blk.get("error") else "ACTIVE" if is_blocked else "NOT_PRESENT"
                ),
                "socket_status": (
                    "UNKNOWN" if sock.get("error")
                    else "LISTENING" if is_listening
                    else "NOT_LISTENING"
                ),
                "traffic_block_verification": "NOT_PERFORMED",
                "verification_status": status,
                "message": msg,
            })

        elif target_type == "service":
            s_name = data.get("service_name")
            info = get_service_info(s_name)
            if not info:
                return jsonify({"error": f"Service '{s_name}' not found."}), 404
            status = info.get("status")
            start_type = info.get("start_type")
            return jsonify({
                "target_type": "service",
                "service_name": s_name,
                "status": status,
                "start_type": start_type,
                "is_stopped": status in ("stopped", "stop_pending"),
                "is_disabled": start_type == "disabled",
                "verification_status": "RESOLVED" if (status in ("stopped", "stop_pending") or start_type == "disabled") else "UNRESOLVED",
            })
        else:
            return jsonify({"error": "Invalid target_type. Must be 'port' or 'service'."}), 400
    except Exception as e:
        app.logger.error(f"api_remediation_verify failed: {e}")
        return jsonify({"error": "Verification check failed."}), 500


@app.route("/api/remediation-history", methods=["GET"])
def api_remediation_history():
    """Returns the full remediation action audit log, newest first."""
    limit = request.args.get("limit", default=50, type=int)
    try:
        history = get_remediation_history(limit=limit)
        return jsonify(history)
    except Exception as e:
        app.logger.error(f"api_remediation_history failed: {e}")
        return jsonify({"error": "Unable to read remediation history."}), 500


@app.route("/attack-surface")
def attack_surface_page():
    """Attack Surface Inventory page."""
    return render_template("attack_surface.html")


@app.route("/api/attack-surface", methods=["GET"])
def api_attack_surface():
    """Returns the full combined attack-surface inventory snapshot."""
    try:
        inventory = get_attack_surface_inventory()
        return jsonify(inventory)
    except Exception as e:
        app.logger.error(f"api_attack_surface failed: {e}")
        return jsonify({"error": "Unable to build attack-surface inventory."}), 500


@app.route("/api/attack-surface/changes", methods=["GET"])
def api_attack_surface_changes():
    """
    Returns real-time attack-surface changes since previous snapshot,
    along with monitor health and recent event logs.
    """
    try:
        data = get_attack_surface_changes()
        return jsonify(data)
    except Exception as e:
        app.logger.error(f"api_attack_surface_changes failed: {e}")
        return jsonify({"error": f"Unable to check attack-surface changes ({e})"}), 500


@app.route("/api/monitoring/status", methods=["GET"])
def api_monitoring_status():
    """Returns current real-time monitor status, interval, and health metrics."""
    try:
        status = get_monitor().get_status()
        status["scheduled_assessment"] = get_scheduled_assessment_config()
        alerts = get_monitoring_events(limit=20)
        status["recent_alerts"] = alerts
        severity_counts = get_monitoring_event_severity_counts(unresolved_only=True)
        status["alert_counts_by_severity"] = {
            severity: severity_counts.get(severity, 0)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"api_monitoring_status failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/start", methods=["POST"])
def api_monitoring_start():
    """Starts the real-time background monitoring daemon thread."""
    try:
        mon = get_monitor()
        mon.start()
        return jsonify({"success": True, "monitoring_active": mon.is_active()})
    except Exception as e:
        app.logger.error(f"api_monitoring_start failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/monitoring/stop", methods=["POST"])
def api_monitoring_stop():
    """Stops the real-time background monitoring daemon thread."""
    try:
        mon = get_monitor()
        mon.stop()
        return jsonify({"success": True, "monitoring_active": mon.is_active()})
    except Exception as e:
        app.logger.error(f"api_monitoring_stop failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/monitoring/events", methods=["GET"])
def api_monitoring_events():
    """Returns stored monitoring events from SQLite with filtering."""
    limit = request.args.get("limit", default=50, type=int)
    if limit is None or limit < 1:
        return jsonify({"error": "limit must be a positive integer"}), 400
    limit = min(limit, 1000)
    offset = request.args.get("offset", default=0, type=int)
    if offset is None or offset < 0:
        return jsonify({"error": "offset must be a non-negative integer"}), 400
    unresolved_only = request.args.get("unresolved", default=0, type=int) == 1
    try:
        severity = request.args.get("severity", "").strip().upper() or None
        acknowledged = request.args.get("acknowledged")
        acknowledged_filter = acknowledged == "true" if acknowledged in ("true", "false") else None
        reviewed = request.args.get("reviewed")
        reviewed_filter = reviewed == "true" if reviewed in ("true", "false") else None
        events = get_monitoring_events(
            limit=limit,
            unresolved_only=unresolved_only,
            offset=offset,
            severity=severity,
            acknowledged=acknowledged_filter,
            reviewed=reviewed_filter,
        )
        return jsonify(events)
    except Exception as e:
        app.logger.error(f"api_monitoring_events failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/events/<int:event_id>/acknowledge", methods=["POST"])
def api_acknowledge_monitoring_event(event_id):
    try:
        if not update_monitoring_event_state(event_id, "acknowledged"):
            return jsonify({"error": "Monitoring event not found."}), 404
        return jsonify({"success": True, "event_id": event_id, "acknowledged": True})
    except Exception:
        app.logger.exception("Alert acknowledgment failed")
        return jsonify({"error": "Unable to acknowledge monitoring event."}), 500


@app.route("/api/monitoring/events/<int:event_id>/review", methods=["POST"])
def api_review_monitoring_event(event_id):
    try:
        if not update_monitoring_event_state(event_id, "reviewed"):
            return jsonify({"error": "Monitoring event not found."}), 404
        return jsonify({"success": True, "event_id": event_id, "reviewed": True})
    except Exception:
        app.logger.exception("Alert review update failed")
        return jsonify({"error": "Unable to update monitoring event review state."}), 500


@app.route("/api/schedule", methods=["GET", "POST"])
def api_assessment_schedule():
    if request.method == "GET":
        return jsonify(get_scheduled_assessment_config())
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required."}), 400
    enabled = data.get("enabled")
    interval = data.get("interval_minutes")
    categories = data.get("categories")
    if not isinstance(enabled, bool) or not isinstance(interval, int) or isinstance(interval, bool):
        return jsonify({"error": "enabled must be boolean and interval_minutes must be an integer."}), 400
    if not isinstance(data.get("refresh_vulnerabilities", False), bool) or not isinstance(data.get("generate_report", False), bool):
        return jsonify({"error": "refresh_vulnerabilities and generate_report must be boolean."}), 400
    try:
        save_scheduled_assessment_config(
            enabled,
            interval,
            categories,
            refresh_vulnerabilities=data.get("refresh_vulnerabilities", False),
            generate_report=data.get("generate_report", False),
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(get_scheduled_assessment_config())


@app.route("/api/monitoring/resolve/<int:event_id>", methods=["POST"])
def api_monitoring_resolve(event_id):
    """Marks a specific monitoring event as resolved in SQLite."""
    try:
        count = resolve_monitoring_event(event_id=event_id)
        return jsonify({"success": True, "resolved_count": count})
    except Exception as e:
        app.logger.error(f"api_monitoring_resolve failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/monitoring/stream", methods=["GET"])
def api_monitoring_stream():
    """
    Server-Sent Events (SSE) streaming endpoint.
    Pushes real-time attack-surface alerts and heartbeat packets to connected clients
    without requiring page reload.
    """
    mon = get_monitor()
    if not mon.is_active():
        mon.start()

    def generate_events():
        q = mon.subscribe()
        try:
            # Send initial state immediately
            initial_status = mon.get_status()
            yield f"data: {json.dumps({'type': 'init', 'data': initial_status})}\n\n"

            while True:
                try:
                    item = q.get(timeout=15)
                    yield f"data: {json.dumps(item)}\n\n"
                except queue.Empty:
                    # Heartbeat comment to keep connection alive
                    yield f": heartbeat\n\n"
        except GeneratorExit:
            mon.unsubscribe(q)
        finally:
            mon.unsubscribe(q)

    response = Response(generate_events(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


# ============================================================================
# PHASE 4: VULNERABILITY ASSESSMENT ROUTES
# ============================================================================

@app.route("/vulnerabilities")
def vulnerabilities_page():
    """Renders the Vulnerability Assessment & Software Inventory dashboard page."""
    return render_template("vulnerabilities.html")


@app.route("/api/software-inventory", methods=["GET"])
def api_software_inventory():
    """
    Returns list of installed Windows software.
    Uses query parameter ?fresh=true to force a live winreg rescan,
    otherwise returns cached inventory from SQLite if available.
    """
    try:
        force_fresh = request.args.get("fresh", "false").lower() in ("true", "1", "yes")
        if force_fresh:
            software = get_installed_software()
            save_software_inventory(software)
        else:
            software = get_software_inventory()
            if not software:
                software = get_installed_software()
                save_software_inventory(software)
        return jsonify({"count": len(software), "software": software})
    except Exception as e:
        app.logger.error(f"api_software_inventory failed: {e}")
        return jsonify({"error": "Failed to collect software inventory", "detail": str(e)}), 500


@app.route("/api/vulnerabilities", methods=["GET"])
def api_vulnerabilities():
    """
    Returns vulnerability findings with optional filtering:
    - severity: CRITICAL, HIGH, MEDIUM, LOW
    - status: Confirmed Version Match, Potential Match, etc.
    - limit: max records
    """
    try:
        severity = request.args.get("severity")
        status = request.args.get("status")
        limit = request.args.get("limit", default=200, type=int)

        findings = get_vulnerability_findings(severity=severity, status=status, limit=limit)
        overview = get_vulnerability_overview()
        latest_run = get_latest_vulnerability_assessment_run()
        cache_status = get_cve_cache_status()
        latest_findings = latest_run.get("findings", []) if latest_run else []
        latest_statuses = {
            f.get("assessment_status")
            for f in latest_findings if isinstance(f, dict)
        }
        source_error_findings = [
            f for f in latest_findings
            if isinstance(f, dict)
            and f.get("assessment_status") in (
                "Assessment Incomplete",
                "Vulnerability Source Unavailable",
            )
        ]
        latest_text = " ".join(
            str(f.get(key, ""))
            for f in source_error_findings
            for key in ("description", "evidence")
        ).casefold()
        rate_limited = (
            "rate limit" in latest_text
            or "http error 429" in latest_text
            or "http status 429" in latest_text
            or "429 too many requests" in latest_text
        )
        source_unavailable = (
            "Vulnerability Source Unavailable" in latest_statuses
            or "unreachable" in latest_text
            or "timed out" in latest_text
            or "nvd api http error" in latest_text
            or "nvd api returned http" in latest_text
            or "nvd api access forbidden" in latest_text
        )
        if rate_limited:
            source_state = "Rate limited during latest assessment"
        elif source_unavailable:
            source_state = "Source unavailable during latest assessment"
        elif latest_run is None:
            source_state = "No assessment recorded"
        elif latest_run.get("effective_assessment_complete"):
            source_state = "Latest assessment complete; live connection not asserted"
        elif latest_run.get("contains_test_fixtures"):
            source_state = "Latest snapshot contains test fixtures; completeness is unverified"
        else:
            source_state = "Latest assessment partial"
        return jsonify({
            "count": len(findings),
            "findings": findings,
            "overview": overview,
            "filters": {"severity": severity, "status": status, "limit": limit},
            "nvd_status": {
                **cache_status,
                "rate_limited": rate_limited,
                "source_unavailable": source_unavailable,
                "source_state": source_state,
                "assessment_timestamp": latest_run.get("completed_at") if latest_run else None,
                "assessment_complete": (
                    bool(latest_run.get("effective_assessment_complete")) if latest_run else None
                ),
                "software_evaluated": latest_run.get("software_evaluated") if latest_run else None,
                "software_total": latest_run.get("software_total") if latest_run else None,
            },
        })
    except Exception as e:
        app.logger.error(f"api_vulnerabilities failed: {e}")
        return jsonify({"error": "Failed to retrieve vulnerability findings", "detail": str(e)}), 500


@app.route("/api/vulnerabilities/scan", methods=["POST"])
def api_vulnerabilities_scan():
    """
    Executes a vulnerability assessment scan against installed software.
    Accepts JSON body:
    - offline_mode (bool): If True, queries only local cache/offline rules
    - max_items (int): Max software items to evaluate
    """
    if not assessment_lock.acquire(blocking=False):
        return jsonify({
            "success": False,
            "error": "A CVE assessment is already running. Wait for it to finish before starting another."
        }), 409

    try:
        data = request.get_json(silent=True) or {}
        offline_mode = data.get("offline_mode", False)
        max_items = data.get("max_items", 25)
        if not isinstance(offline_mode, bool):
            return jsonify({"success": False, "error": "offline_mode must be boolean."}), 400
        if not isinstance(max_items, int) or isinstance(max_items, bool) or not 1 <= max_items <= 100:
            return jsonify({"success": False, "error": "max_items must be an integer between 1 and 100."}), 400

        # 1. Fetch current software inventory
        software = get_installed_software()
        save_software_inventory(software)

        # Limit items to control external API volume and response latency.
        eval_list = software[:max_items]

        # 2. Run scan
        result = run_vulnerability_scan(
            software_list=eval_list,
            offline_mode=offline_mode,
            max_software=max_items,
            persist=False,
        )
        findings = result.get("findings", [])
        software_evaluated = result.get("software_count", len(eval_list))

        statuses = result.get("statuses", {})
        incomplete_statuses = {
            "Insufficient Information",
            "Assessment Incomplete",
            "Vulnerability Source Unavailable",
        }
        assessment_complete = (
            software_evaluated >= len(software)
            and not any(statuses.get(status, 0) for status in incomplete_statuses)
        )
        record_vulnerability_assessment_run(
            software_evaluated=software_evaluated,
            findings=findings,
            assessment_complete=assessment_complete,
            software_total=len(software),
        )

        return jsonify({
            "success": True,
            "software_evaluated": software_evaluated,
            "software_total": len(software),
            "findings_count": len(findings),
            "assessment_complete": assessment_complete,
            "statuses": statuses,
            "summary": result.get("summary", {}),
            "findings": findings,
        })
    except Exception:
        app.logger.exception("api_vulnerabilities_scan failed")
        return jsonify({
            "success": False,
            "error": "Unable to complete the CVE assessment. Check the application logs and try again."
        }), 500
    finally:
        assessment_lock.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False, use_reloader=False, port=5000)
