"""
app.py
Main Flask application for the Attack Surface Reduction & Security
Assessment System. Wires together all scanner modules into a web app.
"""

from flask import Flask, render_template, jsonify, request

from scanner.system_info import collect_system_info
from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_running_services, get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import run_security_checks
from scanner.risk_analyzer import calculate_risk_score
from scanner.recommendation_engine import generate_recommendations
from scanner.port_risk_analyzer import get_port_analysis, get_port_by_number
from scanner.port_hardening import (
    block_port, unblock_port, is_port_blocked,
    stop_service, disable_service, get_service_info,
    is_admin_user, get_asr_blocked_ports, is_protected_service,
)
from scanner.attack_surface import get_attack_surface_inventory
from database.database import (
    init_db, save_scan, get_scan_history, get_scan_by_id,
    save_remediation_action, get_remediation_history,
)


app = Flask(__name__)

# Ensure the database and table exist as soon as the app starts
init_db()


def run_full_scan():
    """
    Runs every scanner module and assembles a single results dictionary.
    Wrapped in try/except per-section so one failing module doesn't
    break the entire scan (per project error-handling requirements).
    """
    results = {}

    try:
        results["system_info"] = collect_system_info()
    except Exception as e:
        results["system_info"] = {"error": str(e)}

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

    try:
        results["firewall"] = get_firewall_status()
    except Exception as e:
        results["firewall"] = {"error": str(e)}

    try:
        results["security_findings"] = run_security_checks()
    except Exception as e:
        results["security_findings"] = {"error": str(e)}

    try:
        results["risk"] = calculate_risk_score()
    except Exception as e:
        results["risk"] = {"error": str(e)}

    try:
        results["recommendations"] = generate_recommendations()
    except Exception as e:
        results["recommendations"] = {"error": str(e)}

    return results


@app.route("/")
def index():
    """Landing page - simple welcome/start-scan page."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Main dashboard page (renders template; data loaded via JS fetch)."""
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["GET"])
def api_scan():
    """
    Runs a full scan, saves it to the database, and returns all results
    as JSON. This is the endpoint the dashboard's JavaScript calls.
    """
    results = run_full_scan()

    scan_id = save_scan(results)
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

    delta = {
        "ports_change": after_scan["listening_ports_count"] - before_scan["listening_ports_count"],
        "findings_change": after_scan["findings_count"] - before_scan["findings_count"],
        "risk_score_change": after_scan["risk_score"] - before_scan["risk_score"],
    }

    return jsonify({
        "before": before_scan,
        "after": after_scan,
        "delta": delta,
    })


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
        blocked_ports = get_asr_blocked_ports()
        admin_status = is_admin_user()

        for p in analysis.get("ports", []):
            port_num = p.get("port")
            proto = (p.get("protocol") or "TCP").upper()
            p["is_blocked"] = (port_num, proto) in blocked_ports
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
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"api_port_status failed: {e}")
        return jsonify({"error": "Unable to verify port status."}), 500


@app.route("/api/port/block", methods=["POST"])
def api_port_block():
    """
    Blocks a port via Windows Firewall. Requires an explicit confirm=true
    in the JSON body - without it, the action is refused (not performed).
    Body: {"port": 3389, "protocol": "TCP", "confirm": true}
    """
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    protocol = data.get("protocol")
    confirm = bool(data.get("confirm", False))

    try:
        result = block_port(port, protocol, confirm=confirm)
    except Exception as e:
        app.logger.error(f"block_port crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while blocking port."}), 500

    save_remediation_action(
        action_type="BLOCK_PORT", target_type="port", target_name=f"{port}/{protocol}",
        port=port, protocol=protocol,
        previous_state=result.get("previous_state"), new_state=result.get("new_state"),
        reason="User-initiated port block via Port Hardening page",
        status="SUCCESS" if result.get("success") else "FAILED",
        error_message=result.get("error"),
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/api/port/unblock", methods=["POST"])
def api_port_unblock():
    """
    Removes a previously created ASR firewall block rule for a port.
    Body: {"port": 3389, "protocol": "TCP", "confirm": true}
    """
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    protocol = data.get("protocol")
    confirm = bool(data.get("confirm", False))

    try:
        result = unblock_port(port, protocol, confirm=confirm)
    except Exception as e:
        app.logger.error(f"unblock_port crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while unblocking port."}), 500

    save_remediation_action(
        action_type="UNBLOCK_PORT", target_type="port", target_name=f"{port}/{protocol}",
        port=port, protocol=protocol,
        previous_state=result.get("previous_state"), new_state=result.get("new_state"),
        reason="User-initiated port unblock via Port Hardening page",
        status="SUCCESS" if result.get("success") else "FAILED",
        error_message=result.get("error"),
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/api/service/info", methods=["GET"])
def api_service_info():
    """Returns current state/startup-type info for a named service."""
    service_name = request.args.get("name", "")
    try:
        info = get_service_info(service_name)
        if info is None:
            return jsonify({"error": "Service not found."}), 404
        return jsonify(info)
    except Exception as e:
        app.logger.error(f"api_service_info failed: {e}")
        return jsonify({"error": "Unable to read service info."}), 500


@app.route("/api/service/stop", methods=["POST"])
def api_service_stop():
    """
    Stops a running service. Requires confirm=true.
    Body: {"service_name": "TermService", "confirm": true}
    """
    data = request.get_json(silent=True) or {}
    service_name = data.get("service_name")
    confirm = bool(data.get("confirm", False))

    try:
        result = stop_service(service_name, confirm=confirm)
    except Exception as e:
        app.logger.error(f"stop_service crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while stopping service."}), 500

    save_remediation_action(
        action_type="STOP_SERVICE", target_type="service", target_name=service_name,
        previous_state=result.get("previous_state"), new_state=result.get("new_state"),
        reason="User-initiated service stop via Port Hardening page",
        status="SUCCESS" if result.get("success") else "FAILED",
        error_message=result.get("error"),
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/api/service/disable", methods=["POST"])
def api_service_disable():
    """
    Sets a service's startup type to Disabled. Requires confirm=true.
    Body: {"service_name": "TermService", "confirm": true}
    """
    data = request.get_json(silent=True) or {}
    service_name = data.get("service_name")
    confirm = bool(data.get("confirm", False))

    try:
        result = disable_service(service_name, confirm=confirm)
    except Exception as e:
        app.logger.error(f"disable_service crashed: {e}")
        return jsonify({"success": False, "message": "Internal error while disabling service."}), 500

    save_remediation_action(
        action_type="DISABLE_SERVICE", target_type="service", target_name=service_name,
        previous_state=result.get("previous_state"), new_state=result.get("new_state"),
        reason="User-initiated service disable via Port Hardening page",
        status="SUCCESS" if result.get("success") else "FAILED",
        error_message=result.get("error"),
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


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
    Placeholder for real-time change detection (planned - requires a
    running monitoring session to compare against). Returns an empty,
    clearly-labelled response rather than a 404, so the frontend can
    already be built against this contract.
    """
    return jsonify({
        "monitoring_active": False,
        "changes": [],
        "note": "Real-time monitoring is not yet implemented. Start monitoring is planned for a future update.",
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
