"""
attack_surface.py
Aggregates the existing scanner modules into a single "attack surface
inventory" - network interfaces, listening ports (classified), running
services, firewall status, and security configuration findings.

This module performs NO new system calls of its own and makes NO changes
to the system - it purely combines the output of modules that already
exist (system_info, port_risk_analyzer, service_scanner, firewall_checker,
security_checker), so there is nothing new to validate for safety here.
"""

import datetime

from scanner.system_info import collect_system_info
from scanner.port_risk_analyzer import get_port_analysis
from scanner.service_scanner import get_running_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import run_security_checks


# A port is considered "potentially exposed" for inventory purposes if its
# recommended status is anything other than "Likely Required" - i.e. the
# port_risk_analyzer thinks a human should look at it.
EXPOSED_STATUSES = {"Potentially Unnecessary - verify before disabling.", "Needs Review"}


def get_attack_surface_inventory():
    """
    Returns a single combined inventory dictionary:
        {
            generated_at, network_interfaces, listening_ports,
            running_services, firewall, security_configuration,
            potentially_exposed_services
        }
    Each section is wrapped so a failure in one does not prevent the
    others from being returned (same pattern as app.run_full_scan()).
    """
    inventory = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        sysinfo = collect_system_info()
        inventory["network_interfaces"] = sysinfo.get("network", {})
    except Exception as e:
        inventory["network_interfaces"] = {"error": str(e)}

    try:
        port_analysis = get_port_analysis()
        inventory["listening_ports"] = port_analysis.get("ports", [])
        inventory["port_summary"] = port_analysis.get("summary", {})
        inventory["potentially_exposed_services"] = [
            p for p in port_analysis.get("ports", [])
            if p.get("recommended_status") in EXPOSED_STATUSES
        ]
    except Exception as e:
        inventory["listening_ports"] = []
        inventory["port_summary"] = {}
        inventory["potentially_exposed_services"] = []
        inventory["ports_error"] = str(e)

    try:
        inventory["running_services"] = get_running_services()
    except Exception as e:
        inventory["running_services"] = []
        inventory["services_error"] = str(e)

    try:
        inventory["firewall"] = get_firewall_status()
    except Exception as e:
        inventory["firewall"] = {"error": str(e)}

    try:
        inventory["security_configuration"] = run_security_checks()
    except Exception as e:
        inventory["security_configuration"] = {"error": str(e)}

    return inventory


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    data = get_attack_surface_inventory()
    print(json.dumps(data, indent=2, default=str))
