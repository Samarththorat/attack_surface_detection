"""
recommendation_engine.py
Generates actionable recommendations based on findings from risk_analyzer.py,
security_checker.py, port_scanner.py, and service_scanner.py.

Each recommendation includes: finding, risk, reason, recommended_action.
This module SUGGESTS actions only - it never modifies firewall rules,
stops services, or changes any system configuration.
"""

from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import (
    _check_uac_enabled,
    _check_rdp_enabled,
    _check_windows_update_service,
)


def generate_recommendations():
    """
    Returns a list of recommendation dictionaries, each with:
    finding, risk, reason, recommended_action
    """
    recommendations = []

    # --- Firewall ---
    firewall = get_firewall_status()
    if firewall["overall_status"] in ("NOT PROTECTED", "PARTIALLY PROTECTED"):
        recommendations.append({
            "finding": f"Firewall status: {firewall['overall_status']}",
            "risk": "High",
            "reason": "A disabled firewall profile removes a primary barrier against "
                      "unsolicited inbound network traffic.",
            "recommended_action": "Enable all firewall profiles (Domain, Private, Public) "
                                   "via Windows Security settings.",
        })

    # --- Exposed ports ---
    ports = get_listening_ports()
    ports = [p for p in ports if "error" not in p]
    exposed_ports = [
        p for p in ports if p.get("local_address") not in ("127.0.0.1", "::1")
    ]
    seen_ports = set()
    for p in exposed_ports:
        port_num = p.get("port")
        if port_num in seen_ports:
            continue
        seen_ports.add(port_num)

        risk_level = "Medium"
        if port_num in (21, 23, 3389, 5900):
            risk_level = "High"
        elif port_num in (139, 445, 135):
            risk_level = "Medium"

        recommendations.append({
            "finding": f"Port {port_num} ({p.get('protocol')}) is listening on "
                       f"{p.get('local_address')}, used by {p.get('process_name')}",
            "risk": risk_level,
            "reason": p.get("risk_note", "This port is reachable beyond localhost."),
            "recommended_action": "Review whether this service needs to be reachable "
                                   "from the network. If not required, disable the "
                                   "service or restrict it to localhost/trusted hosts only.",
        })

    # --- Flagged third-party services ---
    flagged = get_flagged_services()
    for service in flagged:
        recommendations.append({
            "finding": f"Process '{service['name']}' (PID {service['pid']}) has open "
                       f"listening port(s): {service['listening_ports']}",
            "risk": "Low-Medium",
            "reason": "Third-party processes with open ports increase attack surface "
                      "and should be verified as legitimate and necessary.",
            "recommended_action": "Confirm this process is required. If not actively "
                                   "used, uninstall it or disable its network-facing "
                                   "feature. Do not terminate the process directly "
                                   "without understanding its purpose.",
        })

    # --- RDP ---
    rdp = _check_rdp_enabled()
    if rdp is True:
        recommendations.append({
            "finding": "Remote Desktop (RDP) is enabled",
            "risk": "High",
            "reason": "RDP is a common target for brute-force and credential-based "
                      "attacks if exposed to untrusted networks.",
            "recommended_action": "Disable RDP if not actively needed. If required, "
                                   "restrict access via firewall rules, use strong "
                                   "unique credentials, and enable Network Level "
                                   "Authentication (NLA).",
        })

    # --- UAC ---
    uac = _check_uac_enabled()
    if uac is False:
        recommendations.append({
            "finding": "User Account Control (UAC) is disabled",
            "risk": "Medium",
            "reason": "UAC provides a defense-in-depth layer against unauthorized "
                      "privilege escalation and unwanted system changes.",
            "recommended_action": "Re-enable UAC via Control Panel > User Accounts > "
                                   "Change User Account Control settings.",
        })

    # --- Windows Update ---
    wu_status = _check_windows_update_service()
    if wu_status == "stopped":
        recommendations.append({
            "finding": "Windows Update service is stopped",
            "risk": "Medium",
            "reason": "If updates are not applied through this service or an "
                      "alternative mechanism, the system may miss critical security "
                      "patches over time.",
            "recommended_action": "Verify how updates are being managed. If no "
                                   "alternative patch mechanism is in place, re-enable "
                                   "the Windows Update service (services.msc > "
                                   "Windows Update > Start).",
        })

    # --- General best-practice recommendations (always included) ---
    recommendations.append({
        "finding": "General attack surface posture",
        "risk": "Informational",
        "reason": "Ongoing hygiene reduces attack surface over time, beyond any "
                  "single scan's findings.",
        "recommended_action": "Apply least-privilege principles, remove unused "
                               "software, and review network exposure periodically.",
    })

    return recommendations


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    recs = generate_recommendations()
    print(f"Total recommendations: {len(recs)}\n")
    print(json.dumps(recs, indent=4))
