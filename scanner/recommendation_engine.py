"""
recommendation_engine.py
Actionable Security Recommendation Engine for Attack Surface Reduction (Phase 2).

Generates prioritized, contextual recommendations based on concrete findings from:
- risk_analyzer.py
- security_checker.py
- port_scanner.py / port_risk_analyzer.py
- service_scanner.py
- firewall_checker.py

Key Principles:
- Every recommendation is specific to an observed finding with clear technical rationale.
- Clearly details the potential OPERATIONAL IMPACT before suggesting an action
  (e.g., explaining that disabling SMB breaks printer sharing, or blocking RDP prevents remote admin).
- Distinguishes actionable remediation from informational best-practice guidance.
- Prioritizes findings by severity (Critical / High first, Informational last).
- Avoids blindly advising users to disable unfamiliar services without review.
- Retains full backward compatibility with 'finding', 'risk', 'reason', 'recommended_action'.
"""

from scanner.port_scanner import get_listening_ports
from scanner.port_risk_analyzer import classify_port
from scanner.service_scanner import get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import (
    _check_uac_enabled,
    _check_rdp_enabled,
    _check_windows_update_service,
)


def generate_recommendations(scan_data=None):
    """
    Generates a structured, prioritized list of security recommendations.
    Accepts optional scan_data dictionary or runs live collectors.
    Each item includes:
        - id: unique string identifier
        - title: concise action title
        - finding: observed condition
        - risk: severity label (Critical / High / Medium / Low / Informational)
        - priority: int (1 = Highest, 5 = Lowest)
        - reason: why the change is advised
        - recommended_action / recommendation: concrete steps to remediate
        - operational_impact: functional consequence of taking this action
        - is_actionable: bool (True for direct config/remediation changes)
        - target_type: "port" | "service" | "firewall" | "policy"
        - target_name: e.g. "3389/TCP", "LanmanServer", "Domain Profile"
    """
    recommendations = []

    # If caller provided scan_data with security_checks, convert them into recommendations
    if scan_data is not None and isinstance(scan_data, dict):
        # 1. Checks from scan_data
        for chk in scan_data.get("security_checks") or scan_data.get("security_findings") or []:
            if chk.get("status") == "FAIL" or chk.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                sev = chk.get("severity", "Medium")
                prio = 1 if sev == "CRITICAL" else (2 if sev == "HIGH" else 3)
                act = chk.get("recommended_action") or f"Remediate {chk.get('title')}"
                recommendations.append({
                    "id": f"REC-CHK-{len(recommendations)+1}",
                    "title": chk.get("title") or "Security Configuration Issue",
                    "finding": chk.get("title", ""),
                    "risk": sev,
                    "priority": prio,
                    "reason": chk.get("risk_explanation", ""),
                    "recommended_action": act,
                    "recommendation": act,
                    "evidence": chk.get("evidence", ""),
                    "operational_impact": chk.get("operational_impact", "None expected."),
                    "is_actionable": True,
                    "target_type": chk.get("component", "system"),
                    "target_name": chk.get("title", ""),
                })

        # 2. Ports from scan_data
        raw_p = scan_data.get("open_ports") or scan_data.get("ports") or []
        seen_ports = set()
        for p in raw_p:
            port_num = p.get("port")
            proto = (p.get("protocol") or "TCP").upper()
            if not port_num or p.get("risk_level") == "SAFE":
                continue
            if (port_num, proto) in seen_ports:
                continue
            seen_ports.add((port_num, proto))

            proc = p.get("process_name") or p.get("service") or "Unknown"
            reason_text = p.get("risk_reason") or p.get("risk_explanation") or f"Port {port_num} is exposed on network."
            act = p.get("action_required") or p.get("recommended_action") or f"Verify reachability of port {port_num}."

            sev = p.get("risk_level", "Medium")
            prio = 1 if sev == "CRITICAL" else (2 if sev == "HIGH" else 3)
            recommendations.append({
                "id": f"REC-PORT-{port_num}",
                "title": f"Review Port {port_num}/{proto} ({proc})",
                "finding": f"Port {port_num}/{proto} ({proc}) exposed on {p.get('local_address') or 'network'}",
                "risk": sev,
                "priority": prio,
                "reason": reason_text,
                "recommended_action": act,
                "recommendation": act,
                "evidence": f"Port {port_num}/{proto} listening on {p.get('local_address')}",
                "operational_impact": p.get("operational_impact", f"Blocking port {port_num} prevents network clients from reaching {proc}."),
                "is_actionable": True,
                "target_type": "port",
                "target_name": f"{port_num}/{proto}",
            })

        recommendations.sort(key=lambda r: (r.get("priority", 5), r.get("risk", "Low")))
        return recommendations

    # -------------------------------------------------------------
    # 1. Windows Firewall Recommendations (Live)
    # -------------------------------------------------------------
    try:
        firewall = get_firewall_status()
        fw_status = firewall.get("overall_status", "UNKNOWN")
        fw_profiles = firewall.get("profiles", {})
        disabled_profiles = [name for name, p in fw_profiles.items() if p.get("state") == "OFF"]

        if fw_status == "NOT PROTECTED":
            recommendations.append({
                "id": "REC-FW-01",
                "title": "Enable Windows Defender Firewall on All Profiles",
                "finding": "Firewall status: NOT PROTECTED (all profiles disabled)",
                "risk": "High",
                "priority": 1,
                "reason": "Host-based packet filtering is completely inactive, exposing all listening ports to unsolicited network connections.",
                "recommended_action": "Turn on Windows Defender Firewall across Domain, Private, and Public profiles via Windows Security or execute 'netsh advfirewall set allprofiles state on'.",
                "operational_impact": "Inbound connections from other machines will be blocked unless explicitly permitted by an existing inbound firewall rule.",
                "is_actionable": True,
                "target_type": "firewall",
                "target_name": "All Profiles",
            })
        elif fw_status == "PARTIALLY PROTECTED":
            recommendations.append({
                "id": "REC-FW-02",
                "title": f"Enable Firewall on {', '.join(disabled_profiles)} Profile(s)",
                "finding": f"Firewall status: PARTIALLY PROTECTED ({', '.join(disabled_profiles)} profile OFF)",
                "risk": "High",
                "priority": 1,
                "reason": "Disabling firewall on any profile leaves the system vulnerable whenever that network connection type becomes active.",
                "recommended_action": f"Re-enable the disabled firewall profiles ({', '.join(disabled_profiles)}) in Windows Security.",
                "operational_impact": "Applications receiving inbound traffic on the affected profile will require an application rule.",
                "is_actionable": True,
                "target_type": "firewall",
                "target_name": ", ".join(disabled_profiles),
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 2. Remote Desktop (RDP) Recommendations
    # -------------------------------------------------------------
    try:
        rdp_reg = _check_rdp_enabled()
        ports = get_listening_ports(include_udp=True)
        valid_ports = [p for p in ports if "error" not in p and p.get("port") is not None]
        rdp_ports = [p for p in valid_ports if p["port"] == 3389]

        if rdp_reg is True and rdp_ports:
            local_addr = rdp_ports[0].get("local_address", "0.0.0.0")
            recommendations.append({
                "id": "REC-RDP-01",
                "title": "Disable Unneeded Remote Desktop (RDP) or Restrict Access",
                "finding": f"Remote Desktop (RDP) is enabled and listening on port 3389 ({local_addr})",
                "risk": "High",
                "priority": 1,
                "reason": "RDP is a top initial-access vector for brute force, password spraying, and credential-stuffing campaigns.",
                "recommended_action": "If remote graphical management is not required, disable RDP in Settings > System > Remote Desktop. If necessary, configure an ASR Firewall block rule or restrict access to trusted bastion hosts.",
                "operational_impact": "Disabling RDP prevents remote graphical logon; physical/console login remains unaffected.",
                "is_actionable": True,
                "target_type": "port",
                "target_name": "3389/TCP",
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 3. SMB / File Sharing Recommendations
    # -------------------------------------------------------------
    try:
        smb_ports = [p for p in valid_ports if p["port"] in (445, 139) and p.get("local_address") not in ("127.0.0.1", "::1")]
        if smb_ports:
            recommendations.append({
                "id": "REC-SMB-01",
                "title": "Harden SMB File Sharing Exposure",
                "finding": f"SMB file sharing is listening on network interface(s) ({', '.join(str(p['port']) for p in smb_ports)}/TCP)",
                "risk": "High",
                "priority": 2,
                "reason": "SMB is frequently leveraged by threat actors for lateral movement, NTLM relay attacks, and network-wide malware propagation.",
                "recommended_action": "If this workstation does not share files or printers with other machines, block inbound port 445 on Public network profiles using Port Hardening or disable the 'Server' service.",
                "operational_impact": "Other computers will no longer be able to access shared folders or printers hosted on this machine. Outbound connections to other file shares remain unaffected.",
                "is_actionable": True,
                "target_type": "port",
                "target_name": "445/TCP",
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 4. User Account Control (UAC) Recommendations
    # -------------------------------------------------------------
    try:
        uac = _check_uac_enabled()
        if uac is False:
            recommendations.append({
                "id": "REC-UAC-01",
                "title": "Re-Enable User Account Control (UAC)",
                "finding": "User Account Control (UAC) is disabled in Windows registry",
                "risk": "High",
                "priority": 2,
                "reason": "Disabling UAC allows malware running in an administrative session to execute system-level operations silently without user notification.",
                "recommended_action": "Re-enable UAC via Control Panel > User Accounts > Change User Account Control settings, choosing 'Always notify' or 'Default'.",
                "operational_impact": "Programs requesting administrative elevation will display a prompt asking for user confirmation.",
                "is_actionable": True,
                "target_type": "policy",
                "target_name": "EnableLUA",
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 5. Network-Exposed Development & Third-Party Ports
    # -------------------------------------------------------------
    try:
        classified_ports = [classify_port(p) for p in valid_ports]
        exposed_high_risk = [
            p for p in classified_ports
            if p.get("risk_level") in ("CRITICAL", "HIGH")
            and p.get("port") not in (3389, 445, 139)
        ]

        seen_high_risk_ports = set()
        deduped_high_risk = []
        for p in exposed_high_risk:
            key = (p.get("port"), p.get("protocol"))
            if key in seen_high_risk_ports:
                continue
            seen_high_risk_ports.add(key)
            deduped_high_risk.append(p)

        for p in deduped_high_risk[:3]:  # Top 3 non-RDP/SMB high risk ports
            port_num = p.get("port")
            proto = p.get("protocol")
            proc = p.get("process_name") or "Unknown"
            reason_text = p.get("risk_reason", "")

            recommendations.append({
                "id": f"REC-PORT-{port_num}",
                "title": f"Review Sensitive Port {port_num}/{proto} ({proc})",
                "finding": f"Port {port_num}/{proto} ({proc}) exposed on {p.get('interface')}",
                "risk": p.get("risk_level", "Medium"),
                "priority": 2,
                "reason": reason_text,
                "recommended_action": f"Verify whether '{proc}' requires external network reachability. If for local use only, rebind to 127.0.0.1 or block via Port Hardening.",
                "operational_impact": f"Blocking port {port_num} prevents network clients from reaching {proc}.",
                "is_actionable": True,
                "target_type": "port",
                "target_name": f"{port_num}/{proto}",
            })

        # Development servers bound to 0.0.0.0
        exposed_dev = [
            p for p in classified_ports
            if p.get("service_type") == "Development Server"
            and p.get("exposure_type") == "ALL_INTERFACES"
        ]
        if exposed_dev:
            sample_ports = ", ".join(str(p["port"]) for p in exposed_dev[:4])
            recommendations.append({
                "id": "REC-DEV-01",
                "title": f"Bind Development Servers to Localhost ({sample_ports})",
                "finding": f"Development server(s) on port(s) {sample_ports} listening on all network interfaces (0.0.0.0)",
                "risk": "Medium",
                "priority": 3,
                "reason": "Development servers (e.g., Vite, Webpack, Flask dev server) lack production security hardening and should not be exposed to untrusted network traffic.",
                "recommended_action": "Configure the development server configuration to bind strictly to host '127.0.0.1' or 'localhost'.",
                "operational_impact": "The development server will only be accessible from this local computer, not other devices on the LAN.",
                "is_actionable": False,
                "target_type": "configuration",
                "target_name": "Development Server Bindings",
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 6. Flagged Services Review
    # -------------------------------------------------------------
    try:
        flagged = get_flagged_services()
        if flagged:
            sample_svcs = ", ".join(s["name"] for s in flagged[:3])
            recommendations.append({
                "id": "REC-SVC-01",
                "title": f"Audit {len(flagged)} Third-Party Network Services",
                "finding": f"{len(flagged)} third-party process(es) ({sample_svcs}) have active listening ports",
                "risk": "Low",
                "priority": 4,
                "reason": "Third-party applications listening on the network increase attack surface. Verification ensures only authorized software opens network ports.",
                "recommended_action": "Review the Flagged Services table on the dashboard. Do NOT immediately disable services without verifying their software vendor and operational need.",
                "operational_impact": "Terminating or disabling legitimate third-party services will stop their background features (e.g. syncing, local IDE servers).",
                "is_actionable": False,
                "target_type": "service",
                "target_name": sample_svcs,
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 7. Windows Update Service
    # -------------------------------------------------------------
    try:
        wu_status = _check_windows_update_service()
        if wu_status == "stopped":
            recommendations.append({
                "id": "REC-WU-01",
                "title": "Verify Windows Update Service Operation",
                "finding": "Windows Update service (wuauserv) is stopped",
                "risk": "Medium",
                "priority": 3,
                "reason": "If automatic updates or enterprise patch deployment is disabled, the system will miss critical security patches against known CVEs.",
                "recommended_action": "If no alternative patch management tool (e.g., SCCM, Intune) is deployed, start the Windows Update service via services.msc.",
                "operational_impact": "Starting the service allows Windows to search for and download OS security updates in the background.",
                "is_actionable": True,
                "target_type": "service",
                "target_name": "wuauserv",
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 8. General Defensive Hygiene (Always included, Priority 5)
    # -------------------------------------------------------------
    recommendations.append({
        "id": "REC-GEN-01",
        "title": "Continuous Attack Surface Hygiene",
        "finding": "Ongoing attack surface posture management",
        "risk": "Informational",
        "priority": 5,
        "reason": "Attack surface drift naturally occurs as new software is installed, services are enabled, or developer tools are run.",
        "recommended_action": "Periodically run the Attack Surface Reduction scanner, review the Real-Time Monitoring events table, and remove unused software.",
        "operational_impact": "Proactive hygiene prevents forgotten administrative or development servers from remaining permanently exposed.",
        "is_actionable": False,
        "target_type": "hygiene",
        "target_name": "Attack Surface Management",
    })

    for r in recommendations:
        if "recommendation" not in r:
            r["recommendation"] = r.get("recommended_action", "")
        if "evidence" not in r:
            r["evidence"] = r.get("finding", "")
        if "status" not in r:
            r["status"] = "ACTIVE"

    # Sort recommendations by priority (1 = Highest, 5 = Lowest)
    recommendations.sort(key=lambda r: (r.get("priority", 5), r.get("risk", "Low")))
    return recommendations


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    recs = generate_recommendations()
    print(f"Total recommendations: {len(recs)}\n")
    for r in recs:
        print(f"[{r['risk'].upper()} - Priority {r['priority']}] {r['title']}")
        print(f"  Finding: {r['finding']}")
        print(f"  Action: {r['recommended_action']}")
        print(f"  Operational Impact: {r['operational_impact']}\n")
