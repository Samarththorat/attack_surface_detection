"""
security_checker.py
Aggregates security findings across network exposure, Windows Firewall,
User Account Control (UAC), Remote Desktop (RDP), and system maintenance services.

Phase 2 improvements:
- Structured findings with title, severity, component, evidence, risk explanation,
  recommended action, operational impact, confidence, and status.
- De-duplication and correlation between registry settings and actual listening ports.
- Distinguishes CONFIRMED findings, PROBABLE risks, and INCONCLUSIVE / UNKNOWN states.
- Fully backward compatible with existing keys (area, detail, category).
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
    """Read UAC (User Account Control) status from the Windows registry. Read-only."""
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
        return None
    except Exception:
        return None


def _check_rdp_enabled():
    """
    Read whether Remote Desktop is enabled from the registry. Read-only.
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
    Master function: gathers findings from all scanner modules and registry checks.
    Produces structured findings adhering to Phase 2 specifications while maintaining
    full backward compatibility with 'area', 'category', and 'detail' keys.
    """
    findings = []

    # -------------------------------------------------------------
    # 1. Windows Firewall Status
    # -------------------------------------------------------------
    firewall = get_firewall_status()
    fw_status = firewall.get("overall_status", "UNKNOWN")
    fw_profiles = firewall.get("profiles", {})

    disabled_profiles = [name for name, p in fw_profiles.items() if p.get("state") == "OFF"]
    enabled_profiles = [name for name, p in fw_profiles.items() if p.get("state") == "ON"]

    if fw_status == "NOT PROTECTED":
        findings.append({
            "title": "Windows Firewall Completely Disabled",
            "severity": "CRITICAL",
            "area": "Firewall",
            "component": "Firewall",
            "category": "confirmed_finding",
            "evidence": "All Windows Firewall profiles (Domain, Private, Public) report state = OFF.",
            "detail": "All firewall profiles are disabled. The host has no OS packet filter protecting against unsolicited network traffic.",
            "risk_explanation": "Without host firewall filtering, every listening port is directly accessible to any device on the network segment, significantly widening the attack surface.",
            "recommended_action": "Enable Windows Defender Firewall across all network profiles via Windows Security or 'netsh advfirewall set allprofiles state on'.",
            "operational_impact": "Legitimate applications may need explicit inbound firewall allow rules if they listen on non-standard ports.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    elif fw_status == "PARTIALLY PROTECTED":
        findings.append({
            "title": f"Firewall Partially Disabled ({', '.join(disabled_profiles)} profile)",
            "severity": "HIGH",
            "area": "Firewall",
            "component": "Firewall",
            "category": "confirmed_finding",
            "evidence": f"Disabled profiles: {', '.join(disabled_profiles)}. Enabled profiles: {', '.join(enabled_profiles)}.",
            "detail": f"One or more firewall profiles ({', '.join(disabled_profiles)}) are disabled.",
            "risk_explanation": "If the active network connection matches a disabled profile, the host is unprotected from unsolicited inbound probes and lateral movement attempts.",
            "recommended_action": f"Re-enable the disabled profiles ({', '.join(disabled_profiles)}) in Windows Security.",
            "operational_impact": "Inbound connections on the previously unprotected profile will require firewall allow rules.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    elif fw_status == "PROTECTED":
        findings.append({
            "title": "Windows Firewall Enforced on All Profiles",
            "severity": "INFORMATIONAL",
            "area": "Firewall",
            "component": "Firewall",
            "category": "informational",
            "evidence": "All profiles (Domain, Private, Public) report state = ON.",
            "detail": "All firewall profiles are enabled.",
            "risk_explanation": "Inbound traffic is filtered according to active Windows Defender Firewall policy rules.",
            "recommended_action": "Maintain existing firewall configuration and periodically review application exception rules.",
            "operational_impact": "None. System is operating under standard security baseline.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    else:
        findings.append({
            "title": "Firewall Status Inconclusive",
            "severity": "INFORMATIONAL",
            "area": "Firewall",
            "component": "Firewall",
            "category": "unknown_state",
            "evidence": firewall.get("note", "Unable to query firewall via netsh."),
            "detail": "Firewall status could not be determined.",
            "risk_explanation": "Could not query advfirewall via netsh; elevated privileges may be required.",
            "recommended_action": "Run application as Administrator to verify firewall configuration.",
            "operational_impact": "None.",
            "confidence": "INCONCLUSIVE",
            "status": "UNKNOWN",
        })

    # -------------------------------------------------------------
    # 2. Network Exposure & Sensitive Ports Analysis
    # -------------------------------------------------------------
    ports = get_listening_ports(include_udp=True)
    valid_ports = [p for p in ports if "error" not in p and p.get("port") is not None]

    # Partition ports by binding scope
    all_interfaces_ports = [p for p in valid_ports if p.get("local_address") in ("0.0.0.0", "::")]
    specific_ip_ports = [p for p in valid_ports if p.get("local_address") not in ("127.0.0.1", "::1", "0.0.0.0", "::") and p.get("local_address") is not None]
    localhost_ports = [p for p in valid_ports if p.get("local_address") in ("127.0.0.1", "::1")]

    exposed_ports = all_interfaces_ports + specific_ip_ports

    # Check for specific critical services in exposed ports
    exposed_port_numbers = {p["port"] for p in exposed_ports}
    rdp_listening = any(p["port"] == 3389 for p in exposed_ports)
    smb_listening = any(p["port"] in (445, 139) for p in exposed_ports)
    rpc_listening = any(p["port"] == 135 for p in exposed_ports)
    telnet_listening = any(p["port"] == 23 for p in exposed_ports)
    vnc_listening = any(p["port"] in (5900, 5901) for p in exposed_ports)

    # General network exposure finding
    if exposed_ports:
        findings.append({
            "title": f"{len(exposed_ports)} Port(s) Bound Beyond Localhost",
            "severity": "MEDIUM" if len(all_interfaces_ports) > 0 else "LOW",
            "area": "Network Exposure",
            "component": "Network Exposure",
            "category": "confirmed_finding",
            "evidence": f"{len(all_interfaces_ports)} listening on 0.0.0.0/::; {len(specific_ip_ports)} listening on specific interface IPs.",
            "detail": f"{len(exposed_ports)} listening port(s) bound to a network-reachable address (not localhost-only).",
            "risk_explanation": "Network-bound ports are exposed to other machines on the local network or untrusted subnets. Each open port represents a potential attack surface.",
            "recommended_action": "Review the Port Hardening page and consider binding development servers to localhost (127.0.0.1) or blocking unneeded ports.",
            "operational_impact": "Restricting services to localhost prevents external devices from accessing them while preserving local functionality.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    else:
        findings.append({
            "title": "All Listening Ports Bound to Localhost Only",
            "severity": "INFORMATIONAL",
            "area": "Network Exposure",
            "component": "Network Exposure",
            "category": "informational",
            "evidence": f"Total {len(localhost_ports)} listening sockets, 100% bound to 127.0.0.1 or ::1.",
            "detail": "All listening ports are bound to localhost only.",
            "risk_explanation": "Services are isolated from network access; only processes running on this machine can connect.",
            "recommended_action": "Maintain this configuration unless external network access is specifically required.",
            "operational_impact": "None.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })

    # Specific SMB finding (avoid duplicate counting with general exposure)
    if smb_listening:
        findings.append({
            "title": "SMB File Sharing Exposed on Network",
            "severity": "HIGH",
            "area": "Network Exposure",
            "component": "Network Exposure",
            "category": "confirmed_finding",
            "evidence": "Port 445/TCP or 139/TCP is actively listening on a network interface.",
            "detail": "Server Message Block (SMB) file sharing port 445/139 is reachable over the network.",
            "risk_explanation": "SMB is one of the most frequently targeted Windows protocols for lateral movement, credential theft (NTLM relay), and ransomware propagation.",
            "recommended_action": "If network file sharing is not required on this computer, disable the 'Server' (LanmanServer) service or block port 445 in the firewall.",
            "operational_impact": "Disabling SMB prevents other computers from accessing shared folders and local network printers hosted on this machine.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })

    # -------------------------------------------------------------
    # 3. Remote Desktop (RDP) - Correlated Check (Registry + Port)
    # -------------------------------------------------------------
    rdp_reg = _check_rdp_enabled()

    if rdp_reg is True and rdp_listening:
        findings.append({
            "title": "Remote Desktop (RDP) Enabled and Reachable on Network",
            "severity": "HIGH",
            "area": "Remote Desktop",
            "component": "Remote Desktop",
            "category": "confirmed_finding",
            "evidence": "Registry fDenyTSConnections=0 (RDP enabled) AND port 3389/TCP is actively listening.",
            "detail": "Remote Desktop (RDP) is enabled and actively listening on port 3389.",
            "risk_explanation": "RDP exposure without Network Level Authentication (NLA) or IP restrictions is a leading vector for credential brute forcing and ransomware infiltration.",
            "recommended_action": "Disable Remote Desktop in System Settings if remote management is not actively needed. If required, enforce Network Level Authentication and restrict access via firewall rules.",
            "operational_impact": "Disabling RDP prevents remote graphical logins to this machine; local console logon remains fully functional.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    elif rdp_reg is True and not rdp_listening:
        findings.append({
            "title": "Remote Desktop (RDP) Enabled in Registry (Port Not Listening)",
            "severity": "MEDIUM",
            "area": "Remote Desktop",
            "component": "Remote Desktop",
            "category": "potential_risk",
            "evidence": "Registry fDenyTSConnections=0, but port 3389 is currently stopped or blocked.",
            "detail": "Remote Desktop (RDP) is enabled in registry, though the listener is currently inactive.",
            "risk_explanation": "RDP service may start automatically upon logon or service activation, exposing the machine to remote connections.",
            "recommended_action": "Set Remote Desktop to Disabled in Windows Settings if not intended for use.",
            "operational_impact": "Prevents unexpected activation of remote management.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    elif rdp_reg is False:
        findings.append({
            "title": "Remote Desktop (RDP) Disabled",
            "severity": "INFORMATIONAL",
            "area": "Remote Desktop",
            "component": "Remote Desktop",
            "category": "informational",
            "evidence": "Registry fDenyTSConnections=1 (RDP disabled).",
            "detail": "Remote Desktop (RDP) is disabled.",
            "risk_explanation": "No remote desktop connections are accepted.",
            "recommended_action": "Keep RDP disabled unless remote administration is explicitly required.",
            "operational_impact": "None.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    else:
        findings.append({
            "title": "Remote Desktop (RDP) Status Inconclusive",
            "severity": "INFORMATIONAL",
            "area": "Remote Desktop",
            "component": "Remote Desktop",
            "category": "unknown_state",
            "evidence": "Unable to read fDenyTSConnections from Terminal Server registry hive.",
            "detail": "Remote Desktop status could not be determined.",
            "risk_explanation": "Registry key was not accessible with current process permissions.",
            "recommended_action": "Run as Administrator to confirm RDP configuration.",
            "operational_impact": "None.",
            "confidence": "INCONCLUSIVE",
            "status": "UNKNOWN",
        })

    # -------------------------------------------------------------
    # 4. User Account Control (UAC)
    # -------------------------------------------------------------
    uac = _check_uac_enabled()
    if uac is False:
        findings.append({
            "title": "User Account Control (UAC) Disabled",
            "severity": "HIGH",
            "area": "UAC",
            "component": "UAC",
            "category": "confirmed_finding",
            "evidence": "Registry EnableLUA=0 in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.",
            "detail": "User Account Control (UAC) is disabled.",
            "risk_explanation": "Disabling UAC allows processes launched under administrative accounts to execute with full administrator privileges without confirmation, bypassing defense-in-depth against silent malware installation.",
            "recommended_action": "Re-enable UAC via Control Panel > User Accounts > Change User Account Control settings or set EnableLUA=1.",
            "operational_impact": "Administrative operations will display an elevation prompt before executing.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    elif uac is True:
        findings.append({
            "title": "User Account Control (UAC) Enabled",
            "severity": "INFORMATIONAL",
            "area": "UAC",
            "component": "UAC",
            "category": "informational",
            "evidence": "Registry EnableLUA=1.",
            "detail": "User Account Control (UAC) is enabled.",
            "risk_explanation": "Standard and administrative accounts must consent to privilege elevation.",
            "recommended_action": "Maintain UAC at default or higher notification level.",
            "operational_impact": "None.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    else:
        findings.append({
            "title": "UAC Status Inconclusive",
            "severity": "INFORMATIONAL",
            "area": "UAC",
            "component": "UAC",
            "category": "unknown_state",
            "evidence": "Unable to query EnableLUA registry key.",
            "detail": "UAC status could not be determined.",
            "risk_explanation": "Registry key inaccessible; Administrator privileges required.",
            "recommended_action": "Verify UAC settings manually or run as Administrator.",
            "operational_impact": "None.",
            "confidence": "INCONCLUSIVE",
            "status": "UNKNOWN",
        })

    # -------------------------------------------------------------
    # 5. Flagged Third-Party Services
    # -------------------------------------------------------------
    flagged = get_flagged_services()
    if flagged:
        sample_names = ", ".join(s["name"] for s in flagged[:4])
        findings.append({
            "title": f"{len(flagged)} Third-Party Process(es) with Listening Ports",
            "severity": "LOW",
            "area": "Services",
            "component": "Services",
            "category": "potential_risk",
            "evidence": f"Identified processes with open ports: {sample_names}{'...' if len(flagged) > 4 else ''}.",
            "detail": f"{len(flagged)} third-party process(es) have open listening ports and may deserve manual review.",
            "risk_explanation": "Third-party software with network listeners can expand attack surface if software is unpatched, outdated, or unnecessarily listening.",
            "recommended_action": "Review the Flagged Services section on the dashboard and confirm that each application is recognized and legitimately requires network access.",
            "operational_impact": "Stopping an active third-party application will terminate its running session.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })

    # -------------------------------------------------------------
    # 6. Windows Update Service
    # -------------------------------------------------------------
    wu_status = _check_windows_update_service()
    if wu_status == "stopped":
        findings.append({
            "title": "Windows Update Service (wuauserv) Stopped",
            "severity": "MEDIUM",
            "area": "Windows Update",
            "component": "Windows Update",
            "category": "recommendation",
            "evidence": "Service 'wuauserv' status = 'stopped'.",
            "detail": "Windows Update service is stopped. Ensure updates are still applied through another mechanism, or re-enable the service.",
            "risk_explanation": "If Windows Update is stopped and no enterprise patch management is active, critical security updates may not be installed, leaving known vulnerabilities unpatched.",
            "recommended_action": "Start the Windows Update service (services.msc > Windows Update > Start) or verify managed enterprise deployment.",
            "operational_impact": "Starting Windows Update allows background downloading and installation of OS updates.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    elif wu_status is not None:
        findings.append({
            "title": f"Windows Update Service Status: {wu_status.capitalize()}",
            "severity": "INFORMATIONAL",
            "area": "Windows Update",
            "component": "Windows Update",
            "category": "informational",
            "evidence": f"Service 'wuauserv' status = '{wu_status}'.",
            "detail": f"Windows Update service status: {wu_status}.",
            "risk_explanation": "Windows Update service is operating as reported.",
            "recommended_action": "Ensure automatic updates or scheduled patch cycles are active.",
            "operational_impact": "None.",
            "confidence": "CONFIRMED",
            "status": "ACTIVE",
        })
    else:
        findings.append({
            "title": "Windows Update Service Status Unknown",
            "severity": "INFORMATIONAL",
            "area": "Windows Update",
            "component": "Windows Update",
            "category": "unknown_state",
            "evidence": "Unable to query 'wuauserv' via psutil.",
            "detail": "Windows Update service status could not be determined.",
            "risk_explanation": "Service status could not be queried with current permissions.",
            "recommended_action": "Verify Windows Update in services.msc.",
            "operational_impact": "None.",
            "confidence": "INCONCLUSIVE",
            "status": "UNKNOWN",
        })

    return findings


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    results = run_security_checks()
    print(f"Total findings: {len(results)}\n")
    print(json.dumps(results, indent=2))
