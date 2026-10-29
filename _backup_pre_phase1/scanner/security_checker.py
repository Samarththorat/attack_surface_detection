"""
security_checker.py
Aggregates findings from other scanner modules and performs a few additional
safe, read-only configuration checks (UAC, RDP, Windows Update service).

Every finding is tagged with a category:
- "confirmed_finding"    -> directly observed fact with security relevance
- "informational"        -> observed fact, neutral / context only
- "recommendation"       -> suggested action based on a finding

No configuration is changed. No registry keys are written.
"""

import psutil

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows platform; registry checks will degrade gracefully

from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_flagged_services
from scanner.firewall_checker import get_firewall_status


def _check_uac_enabled():
    """Read UAC (User Account Control) status from the registry. Read-only."""
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        )
        value, _ = winreg.QueryValueEx(key, "EnableLUA")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return None  # Key not found - can't determine
    except Exception:
        return None


def _check_rdp_enabled():
    """Read whether Remote Desktop is enabled from the registry. Read-only.
    fDenyTSConnections == 0 means RDP is ENABLED; 1 means disabled.
    """
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        )
        value, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
        winreg.CloseKey(key)
        return value == 0  # True if RDP is enabled
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _check_windows_update_service():
    """Check if the Windows Update service (wuauserv) is running."""
    try:
        service = psutil.win_service_get("wuauserv")
        info = service.as_dict()
        return info.get("status")  # e.g. "running", "stopped"
    except Exception:
        return None


def run_security_checks():
    """
    Master function: gathers findings from all modules plus new checks,
    and returns a structured list of findings, each with a category.
    """
    findings = []

    # --- Firewall ---
    firewall = get_firewall_status()
    if firewall["overall_status"] == "NOT PROTECTED":
        findings.append({
            "category": "confirmed_finding",
            "area": "Firewall",
            "detail": "All firewall profiles are disabled.",
        })
    elif firewall["overall_status"] == "PARTIALLY PROTECTED":
        findings.append({
            "category": "confirmed_finding",
            "area": "Firewall",
            "detail": "One or more firewall profiles are disabled.",
        })
    elif firewall["overall_status"] == "PROTECTED":
        findings.append({
            "category": "informational",
            "area": "Firewall",
            "detail": "All firewall profiles are enabled.",
        })
    else:
        findings.append({
            "category": "informational",
            "area": "Firewall",
            "detail": "Firewall status could not be determined.",
        })

    # --- Listening ports exposed beyond localhost ---
    ports = get_listening_ports()
    ports = [p for p in ports if "error" not in p]
    exposed_ports = [
        p for p in ports
        if p.get("local_address") not in ("127.0.0.1", "::1")
    ]
    if exposed_ports:
        findings.append({
            "category": "confirmed_finding",
            "area": "Network Exposure",
            "detail": f"{len(exposed_ports)} listening port(s) bound to a network-reachable "
                      f"address (not localhost-only).",
        })
    else:
        findings.append({
            "category": "informational",
            "area": "Network Exposure",
            "detail": "All listening ports are bound to localhost only.",
        })

    # --- Flagged third-party services with open ports ---
    flagged = get_flagged_services()
    if flagged:
        findings.append({
            "category": "informational",
            "area": "Services",
            "detail": f"{len(flagged)} third-party process(es) have open listening ports "
                      f"and may deserve manual review.",
        })

    # --- UAC ---
    uac = _check_uac_enabled()
    if uac is True:
        findings.append({
            "category": "informational",
            "area": "UAC",
            "detail": "User Account Control (UAC) is enabled.",
        })
    elif uac is False:
        findings.append({
            "category": "confirmed_finding",
            "area": "UAC",
            "detail": "User Account Control (UAC) is disabled.",
        })
    else:
        findings.append({
            "category": "informational",
            "area": "UAC",
            "detail": "UAC status could not be determined.",
        })

    # --- RDP ---
    rdp = _check_rdp_enabled()
    if rdp is True:
        findings.append({
            "category": "confirmed_finding",
            "area": "Remote Desktop",
            "detail": "Remote Desktop (RDP) is enabled.",
        })
    elif rdp is False:
        findings.append({
            "category": "informational",
            "area": "Remote Desktop",
            "detail": "Remote Desktop (RDP) is disabled.",
        })
    else:
        findings.append({
            "category": "informational",
            "area": "Remote Desktop",
            "detail": "Remote Desktop status could not be determined.",
        })

    # --- Windows Update service ---
    wu_status = _check_windows_update_service()
    if wu_status == "stopped":
        findings.append({
            "category": "recommendation",
            "area": "Windows Update",
            "detail": "Windows Update service is stopped. Ensure updates are still "
                      "applied through another mechanism, or re-enable the service.",
        })
    elif wu_status is None:
        findings.append({
            "category": "informational",
            "area": "Windows Update",
            "detail": "Windows Update service status could not be determined.",
        })
    else:
        findings.append({
            "category": "informational",
            "area": "Windows Update",
            "detail": f"Windows Update service status: {wu_status}.",
        })

    return findings


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    results = run_security_checks()
    print(json.dumps(results, indent=4))
