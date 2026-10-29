"""
risk_analyzer.py
Calculates an explainable 0-100 risk score from findings produced by
security_checker.py, port_scanner.py, and service_scanner.py.

The score is a WEIGHTED SUM of concrete, observed conditions - not random,
and every point awarded is traceable to a specific finding.
"""

from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import (
    _check_uac_enabled,
    _check_rdp_enabled,
    _check_windows_update_service,
)


# Fixed, documented weights. See README/report for rationale of each value.
WEIGHTS = {
    "firewall_disabled": 25,
    "exposed_ports_max": 30,   # scaled: points_per_port * unique_exposed_ports, capped here
    "points_per_exposed_port": 3,
    "flagged_services_max": 15,
    "points_per_flagged_service": 3,
    "rdp_enabled": 15,
    "uac_disabled": 10,
    "windows_update_stopped": 5,
}
# WEIGHTS = {
#     "firewall_disabled": 25,

#     # Network exposure
#     "exposed_ports_max": 30,
#     "points_per_exposed_port": 2,

#     # Flagged services
#     "flagged_services_max": 15,
#     "points_per_flagged_service": 2,

#     "rdp_enabled": 15,
#     "uac_disabled": 10,
#     "windows_update_stopped": 5,
# }

def _unique_exposed_ports():
    """
    Returns the count of UNIQUE ports (deduplicated across IPv4/IPv6) that are
    bound to a network-reachable address (i.e. not localhost-only).
    """
    ports = get_listening_ports()
    ports = [p for p in ports if "error" not in p]

    exposed_port_numbers = set()
    for p in ports:
        if p.get("local_address") not in ("127.0.0.1", "::1") and p.get("port") is not None:
            exposed_port_numbers.add(p["port"])

    return len(exposed_port_numbers)


def calculate_risk_score():
    """
    Returns a dictionary with:
    - total_score (0-100)
    - risk_level ("Low" / "Medium" / "High")
    - breakdown: list of {category, points_awarded, max_points, reason}
    - limitations: known limitations of this scoring method
    """
    breakdown = []
    total_score = 0

    # --- Firewall ---
    firewall = get_firewall_status()
    if firewall["overall_status"] in ("NOT PROTECTED", "PARTIALLY PROTECTED"):
        points = WEIGHTS["firewall_disabled"]
        breakdown.append({
            "category": "Firewall",
            "points_awarded": points,
            "max_points": WEIGHTS["firewall_disabled"],
            "reason": f"Firewall status: {firewall['overall_status']}",
        })
        total_score += points
    else:
        breakdown.append({
            "category": "Firewall",
            "points_awarded": 0,
            "max_points": WEIGHTS["firewall_disabled"],
            "reason": "All firewall profiles enabled - no points added",
        })

    # --- Exposed ports ---
    exposed_count = _unique_exposed_ports()
    port_points = min(
        exposed_count * WEIGHTS["points_per_exposed_port"],
        WEIGHTS["exposed_ports_max"],
    )
    breakdown.append({
        "category": "Network-Exposed Ports",
        "points_awarded": port_points,
        "max_points": WEIGHTS["exposed_ports_max"],
        "reason": f"{exposed_count} unique port(s) exposed beyond localhost "
                  f"({WEIGHTS['points_per_exposed_port']} pts each, capped at "
                  f"{WEIGHTS['exposed_ports_max']})",
    })
    total_score += port_points

    # --- Flagged services ---
    flagged = get_flagged_services()
    service_points = min(
        len(flagged) * WEIGHTS["points_per_flagged_service"],
        WEIGHTS["flagged_services_max"],
    )
    breakdown.append({
        "category": "Flagged Third-Party Services",
        "points_awarded": service_points,
        "max_points": WEIGHTS["flagged_services_max"],
        "reason": f"{len(flagged)} service(s) flagged for review "
                  f"({WEIGHTS['points_per_flagged_service']} pts each, capped at "
                  f"{WEIGHTS['flagged_services_max']})",
    })
    total_score += service_points

    # --- RDP ---
    rdp = _check_rdp_enabled()
    if rdp is True:
        points = WEIGHTS["rdp_enabled"]
        breakdown.append({
            "category": "Remote Desktop (RDP)",
            "points_awarded": points,
            "max_points": WEIGHTS["rdp_enabled"],
            "reason": "RDP is enabled",
        })
        total_score += points
    else:
        breakdown.append({
            "category": "Remote Desktop (RDP)",
            "points_awarded": 0,
            "max_points": WEIGHTS["rdp_enabled"],
            "reason": "RDP disabled or undetermined - no points added",
        })

    # --- UAC ---
    uac = _check_uac_enabled()
    if uac is False:
        points = WEIGHTS["uac_disabled"]
        breakdown.append({
            "category": "User Account Control (UAC)",
            "points_awarded": points,
            "max_points": WEIGHTS["uac_disabled"],
            "reason": "UAC is disabled",
        })
        total_score += points
    else:
        breakdown.append({
            "category": "User Account Control (UAC)",
            "points_awarded": 0,
            "max_points": WEIGHTS["uac_disabled"],
            "reason": "UAC enabled or undetermined - no points added",
        })

    # --- Windows Update service ---
    wu_status = _check_windows_update_service()
    if wu_status == "stopped":
        points = WEIGHTS["windows_update_stopped"]
        breakdown.append({
            "category": "Windows Update Service",
            "points_awarded": points,
            "max_points": WEIGHTS["windows_update_stopped"],
            "reason": "Windows Update service is stopped",
        })
        total_score += points
    else:
        breakdown.append({
            "category": "Windows Update Service",
            "points_awarded": 0,
            "max_points": WEIGHTS["windows_update_stopped"],
            "reason": "Service running or undetermined - no points added",
        })

    # --- Final classification ---
    total_score = min(total_score, 100)  # safety cap

    if total_score <= 30:
        risk_level = "Low"
    elif total_score <= 60:
        risk_level = "Medium"
    else:
        risk_level = "High"

    limitations = [
        "This score reflects locally observable configuration only; it does not "
        "perform vulnerability scanning against known CVEs.",
        "Windows Update check verifies service status only, not whether all "
        "patches are actually installed.",
        "Flagged third-party services are not verified as malicious or vulnerable - "
        "'flagged' means 'recommended for manual review' only.",
        "Some registry-based checks (UAC, RDP) may be inconclusive without "
        "Administrator privileges.",
    ]

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "limitations": limitations,
    }


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    result = calculate_risk_score()
    print(json.dumps(result, indent=4))
