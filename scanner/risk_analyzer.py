"""
risk_analyzer.py
Improved Risk Scoring Engine for Attack Surface Reduction (Phase 2).

Calculates an explainable 0–100 project-specific risk score based on:
- Windows Firewall enforcement status
- Sensitive service exposure (RDP, SMB, Remote Access)
- General network exposure deduplicated from dedicated service findings
- System security controls (UAC, Windows Update)
- Flagged third-party processes cross-referenced with port listeners
- Unidentified / elevated process review factors

Key Architecture Principles:
- Documented, configurable weights with strictly capped maximums.
- Avoids double-counting: RDP, SMB, and specific high-risk services are
  evaluated once in their dedicated component, not duplicated in generic port counts.
- Distinguishes CONFIRMED findings from POTENTIAL risks and UNKNOWN states.
- Applies firewall mitigation context to generic port risk.
- Explicitly labeled as a project-specific assessment rather than a certified rating.
- Resilient: handles partial or failing scanner sub-modules without crashing.
"""

import hashlib
import json

from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import (
    _check_uac_enabled,
    _check_rdp_enabled,
    _check_windows_update_service,
    run_security_checks,
)

# Configurable, documented scoring weights
DEFAULT_WEIGHTS = {
    # 1. Host Firewall (Max 25 pts)
    "firewall_all_disabled": 25,
    "firewall_partially_disabled": 15,

    # 2. Remote Desktop (Max 20 pts)
    "rdp_exposed_all_interfaces": 20,
    "rdp_exposed_specific_ip": 14,
    "rdp_enabled_port_inactive": 6,

    # 3. High-Risk Network Services (SMB, Telnet, VNC) (Max 20 pts)
    "smb_exposed": 15,
    "telnet_or_vnc_exposed": 12,
    "unencrypted_db_exposed": 10,
    "sensitive_services_cap": 20,

    # 4. Generic Network Exposure (Deduplicated, Max 15 pts)
    "points_per_all_interfaces_port": 2,
    "points_per_specific_ip_port": 1,
    "generic_ports_cap": 15,

    # 5. Third-Party Flagged Services (Max 10 pts)
    "points_per_flagged_service": 2,
    "flagged_services_cap": 10,

    # 6. Privilege & Maintenance Controls (Max 15 pts)
    "uac_disabled": 10,
    "windows_update_stopped": 5,

    # 7. Review / Unknown State Factor (Max 5 pts)
    "unknown_process_review_cap": 5,

    # 8. CVE Vulnerabilities (Phase 5, Max 25 pts)
    "points_per_critical_cve": 15,
    "points_per_high_cve": 8,
    "points_per_medium_cve": 3,
    "vulnerabilities_cap": 25,

    # 9. Remediation Defects (Phase 5, Max 10 pts)
    "points_per_failed_verification": 5,
    "remediation_defects_cap": 10,

    # 10. Unrepresented Monitoring Events (Phase 5, Max 15 pts)
    "points_per_high_monitoring_event": 5,
    "points_per_medium_monitoring_event": 2,
    "monitoring_events_cap": 15,
}

RISK_WEIGHTS = DEFAULT_WEIGHTS
ASSESSMENT_LABEL = "ISC Project-Specific Risk Assessment (0–100)"


def calculate_risk_score(data_or_weights=None, weights=None):
    """
    Computes a transparent, explainable 0–100 risk assessment score.
    Supports either live system collection or caller-provided scan_data dict.
    Returns:
    {
        "score": int (0-100),
        "total_score": int (0-100),
        "level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "risk_level": "Low" | "Medium" | "High" | "Critical",
        "assessment_label": str,
        "breakdown": dict with legacy category point totals and itemized list,
        "breakdown_items": list of itemized category point details,
        "severity_distribution": dict,
        "top_findings": list,
        "mitigating_factors": list,
        "limitations": list
    }
    """
    scan_data = None
    w = dict(DEFAULT_WEIGHTS)
    if isinstance(data_or_weights, dict):
        is_scan = (
            "open_ports" in data_or_weights or
            "security_checks" in data_or_weights or
            "services" in data_or_weights or
            "firewall" in data_or_weights or
            "ports" in data_or_weights or
            len(data_or_weights) == 0
        )
        if any(k in data_or_weights for k in DEFAULT_WEIGHTS):
            is_scan = False
            w.update(data_or_weights)
        if is_scan:
            scan_data = data_or_weights

    if weights and isinstance(weights, dict):
        w.update(weights)

    breakdown = []
    total_score = 0
    mitigating_factors = []
    top_findings = []

    # Dedicated point counters for breakdown analysis
    fw_points = 0
    rdp_exposure_points = 0
    smb_exposure_points = 0
    sensitive_services_points = 0
    exposed_ports_points = 0
    flagged_services_points = 0
    uac_points = 0
    windows_update_points = 0
    unknown_process_points = 0

    # -------------------------------------------------------------
    # 1. Collect / Parse Inputs Safely
    # -------------------------------------------------------------
    if scan_data is not None:
        fw_raw = scan_data.get("firewall")
        if fw_raw is None or not isinstance(fw_raw, dict):
            firewall = {"overall_status": "UNKNOWN"}
        else:
            firewall = dict(fw_raw)
            if "any_profile_active" in fw_raw:
                firewall["overall_status"] = "PROTECTED" if fw_raw["any_profile_active"] else "NOT PROTECTED"
            elif "overall_status" not in firewall:
                firewall["overall_status"] = "UNKNOWN"

        raw_ports = scan_data.get("open_ports") if "open_ports" in scan_data else scan_data.get("ports", [])
        ports = []
        for p in (raw_ports or []):
            if isinstance(p, dict) and "error" not in p and p.get("port") is not None:
                entry = dict(p)
                if not entry.get("local_address"):
                    entry["local_address"] = "0.0.0.0"
                ports.append(entry)

        raw_svcs = scan_data.get("services") if "services" in scan_data else scan_data.get("flagged_services", [])
        flagged_services = [s for s in (raw_svcs or []) if isinstance(s, dict) and (s.get("review_flag") in ("FLAGGED", True) or s.get("risk_level") in ("CRITICAL", "HIGH"))]

        sec_checks = scan_data.get("security_checks") or scan_data.get("security_findings") or []
        uac_found = next((c for c in sec_checks if "UAC" in c.get("title", "")), None)
        if uac_found:
            uac_enabled = (uac_found.get("status") != "FAIL" and "Disabled" not in uac_found.get("title", ""))
        elif "security_checks" in scan_data or "security_findings" in scan_data:
            uac_enabled = True
        else:
            uac_enabled = None

        rdp_found = next((c for c in sec_checks if "Remote Desktop" in c.get("title", "") or "RDP" in c.get("title", "")), None)
        if rdp_found:
            rdp_enabled = (rdp_found.get("status") == "FAIL" or "Enabled" in rdp_found.get("title", ""))
        elif "security_checks" in scan_data or "security_findings" in scan_data:
            rdp_enabled = False
        else:
            rdp_enabled = None

        wu_found = next((c for c in sec_checks if "Windows Update" in c.get("title", "")), None)
        if wu_found:
            wu_status = "Stopped" if wu_found.get("status") == "FAIL" else "Running"
        elif "security_checks" in scan_data or "security_findings" in scan_data:
            wu_status = "Running"
        else:
            wu_status = None
    else:
        try:
            firewall = get_firewall_status()
        except Exception as e:
            firewall = {"overall_status": "UNKNOWN", "profiles": {}, "error": str(e)}

        try:
            raw_ports = get_listening_ports(include_udp=True)
            ports = [p for p in raw_ports if "error" not in p and p.get("port") is not None]
        except Exception:
            ports = []

        try:
            flagged_services = get_flagged_services()
        except Exception:
            flagged_services = []

        try:
            uac_enabled = _check_uac_enabled()
        except Exception:
            uac_enabled = None

        try:
            rdp_enabled = _check_rdp_enabled()
        except Exception:
            rdp_enabled = None

        try:
            wu_status = _check_windows_update_service()
        except Exception:
            wu_status = None

    # Track dedicated ports to avoid double-counting in generic network exposure
    dedicated_scored_ports = set()

    # -------------------------------------------------------------
    # 2. Host Firewall Evaluation
    # -------------------------------------------------------------
    fw_status = firewall.get("overall_status", "UNKNOWN")
    if fw_status == "NOT PROTECTED":
        fw_points = w["firewall_all_disabled"]
        breakdown.append({
            "category": "Host Firewall",
            "points_awarded": fw_points,
            "max_points": w["firewall_all_disabled"],
            "finding_type": "CONFIRMED",
            "severity": "CRITICAL",
            "reason": "All Windows Firewall profiles are disabled. Inbound traffic is completely unfiltered.",
        })
        total_score += fw_points
        top_findings.append("All Windows Firewall profiles are disabled.")
    elif fw_status == "PARTIALLY PROTECTED":
        fw_points = w["firewall_partially_disabled"]
        breakdown.append({
            "category": "Host Firewall",
            "points_awarded": fw_points,
            "max_points": w["firewall_all_disabled"],
            "finding_type": "CONFIRMED",
            "severity": "HIGH",
            "reason": "One or more Windows Firewall profiles are disabled. Exposure depends on the active network profile.",
        })
        total_score += fw_points
        top_findings.append("Firewall is disabled on at least one network profile.")
    elif fw_status == "PROTECTED":
        breakdown.append({
            "category": "Host Firewall",
            "points_awarded": 0,
            "max_points": w["firewall_all_disabled"],
            "finding_type": "CONFIRMED",
            "severity": "INFORMATIONAL",
            "reason": "All firewall profiles (Domain, Private, Public) are active. Inbound filtering enforced.",
        })
        mitigating_factors.append("Windows Firewall Active: Enforcing inbound protection on all profiles.")
    else:
        breakdown.append({
            "category": "Host Firewall",
            "points_awarded": 0,
            "max_points": w["firewall_all_disabled"],
            "finding_type": "UNKNOWN",
            "severity": "INFORMATIONAL",
            "reason": "Firewall status could not be conclusively verified. No penalty assessed without evidence.",
        })

    # -------------------------------------------------------------
    # 3. Remote Desktop (RDP) Evaluation (De-duplicated)
    # -------------------------------------------------------------
    rdp_ports = [p for p in ports if p["port"] == 3389]
    if rdp_ports:
        dedicated_scored_ports.add(3389)

    rdp_on_all = any(p.get("local_address") in ("0.0.0.0", "::") for p in rdp_ports)
    rdp_on_specific = any(p.get("local_address") not in ("127.0.0.1", "::1", "0.0.0.0", "::") for p in rdp_ports)

    if (rdp_enabled is True and (rdp_on_all or rdp_ports)) or (rdp_on_all and rdp_ports):
        rdp_exposure_points = w["rdp_exposed_all_interfaces"] if rdp_on_all else w["rdp_exposed_specific_ip"]
        breakdown.append({
            "category": "Remote Desktop (RDP)",
            "points_awarded": rdp_exposure_points,
            "max_points": w["rdp_exposed_all_interfaces"],
            "finding_type": "CONFIRMED",
            "severity": "HIGH",
            "reason": "Remote Desktop is enabled and actively listening on network interfaces.",
        })
        total_score += rdp_exposure_points
        top_findings.append("RDP is enabled and reachable across network interfaces.")
    elif rdp_enabled is True and not rdp_ports:
        rdp_exposure_points = w["rdp_enabled_port_inactive"]
        breakdown.append({
            "category": "Remote Desktop (RDP)",
            "points_awarded": rdp_exposure_points,
            "max_points": w["rdp_exposed_all_interfaces"],
            "finding_type": "POTENTIAL",
            "severity": "MEDIUM",
            "reason": "Remote Desktop is enabled in registry, but the listener port is currently inactive or stopped.",
        })
        total_score += rdp_exposure_points
    else:
        breakdown.append({
            "category": "Remote Desktop (RDP)",
            "points_awarded": 0,
            "max_points": w["rdp_exposed_all_interfaces"],
            "finding_type": "CONFIRMED",
            "severity": "INFORMATIONAL",
            "reason": "Remote Desktop is disabled or bound only to loopback. No remote exposure.",
        })
        if rdp_enabled is False:
            mitigating_factors.append("Remote Desktop (RDP) is disabled.")

    # -------------------------------------------------------------
    # 4. Sensitive Network Services (SMB, Telnet, VNC, DB)
    # -------------------------------------------------------------
    sensitive_pts = 0
    sensitive_reasons = []

    # SMB Check (Ports 445 / 139)
    smb_ports = [p for p in ports if p["port"] in (445, 139) and p.get("local_address") not in ("127.0.0.1", "::1")]
    if smb_ports:
        dedicated_scored_ports.update([445, 139])
        smb_exposure_points = w["smb_exposed"]
        sensitive_reasons.append("SMB file sharing (ports 445/139) exposed beyond localhost")
        top_findings.append("SMB file sharing is exposed to inbound network traffic.")

    # Telnet (23) or VNC (5900)
    insecure_remote = [p for p in ports if p["port"] in (23, 5900, 5901) and p.get("local_address") not in ("127.0.0.1", "::1")]
    if insecure_remote:
        for p in insecure_remote:
            dedicated_scored_ports.add(p["port"])
        sensitive_pts += w["telnet_or_vnc_exposed"]
        sensitive_reasons.append(f"Unencrypted remote access ({', '.join(str(p['port']) for p in insecure_remote)}) exposed")

    # Exposed Databases
    exposed_db = [p for p in ports if p["port"] in (1433, 3306, 5432, 6379, 27017) and p.get("local_address") not in ("127.0.0.1", "::1")]
    if exposed_db:
        for p in exposed_db:
            dedicated_scored_ports.add(p["port"])
        sensitive_pts += w["unencrypted_db_exposed"]
        sensitive_reasons.append("Database listener exposed on network interface")

    combined_sensitive = sensitive_pts + smb_exposure_points
    sensitive_services_points = min(combined_sensitive, w["sensitive_services_cap"])
    if sensitive_services_points > 0:
        breakdown.append({
            "category": "Sensitive Network Services",
            "points_awarded": sensitive_services_points,
            "max_points": w["sensitive_services_cap"],
            "finding_type": "CONFIRMED",
            "severity": "HIGH",
            "reason": "; ".join(sensitive_reasons),
        })
        total_score += sensitive_services_points
    else:
        breakdown.append({
            "category": "Sensitive Network Services",
            "points_awarded": 0,
            "max_points": w["sensitive_services_cap"],
            "finding_type": "CONFIRMED",
            "severity": "INFORMATIONAL",
            "reason": "No high-risk administrative, unencrypted remote terminal, or database ports exposed.",
        })
        mitigating_factors.append("No sensitive administrative or database services are exposed to network traffic.")

    # -------------------------------------------------------------
    # 5. Generic Network Exposure (Deduplicated)
    # -------------------------------------------------------------
    def _is_all_interfaces(addr):
        if not addr:
            return True
        s = str(addr).strip()
        if ":" in s and not s.startswith("::"):
            s = s.split(":")[0]
        return s in ("0.0.0.0", "::", "[::]")

    def _is_loopback(addr):
        if not addr:
            return False
        s = str(addr).strip()
        if ":" in s and not s.startswith("::"):
            s = s.split(":")[0]
        return s in ("127.0.0.1", "::1", "[::1]")

    # Filter out localhost and ports already scored in dedicated categories
    other_exposed_ports = [
        p for p in ports
        if not _is_loopback(p.get("local_address"))
        and p.get("port") not in dedicated_scored_ports
    ]

    all_int_count = sum(1 for p in other_exposed_ports if _is_all_interfaces(p.get("local_address")))
    spec_ip_count = len(other_exposed_ports) - all_int_count

    raw_generic_pts = (all_int_count * w["points_per_all_interfaces_port"]) + (spec_ip_count * w["points_per_specific_ip_port"])
    if fw_status == "PROTECTED":
        exposed_ports_points = min(raw_generic_pts // 2, w["generic_ports_cap"])
    else:
        exposed_ports_points = min(raw_generic_pts, w["generic_ports_cap"])

    breakdown.append({
        "category": "Generic Network-Exposed Ports",
        "points_awarded": exposed_ports_points,
        "max_points": w["generic_ports_cap"],
        "finding_type": "PROBABLE",
        "severity": "MEDIUM" if exposed_ports_points > 8 else ("LOW" if exposed_ports_points > 0 else "INFORMATIONAL"),
        "reason": (
            f"{len(other_exposed_ports)} additional port(s) exposed beyond localhost ({all_int_count} on 0.0.0.0, "
            f"{spec_ip_count} on specific IPs), excluding dedicated services."
            + (" (Firewall protection active; weight attenuated)." if fw_status == "PROTECTED" and exposed_ports_points > 0 else "")
        ),
    })
    total_score += exposed_ports_points

    # -------------------------------------------------------------
    # 6. Flagged Third-Party Services
    # -------------------------------------------------------------
    relevant_flagged = [
        s for s in flagged_services
        if not any(p in dedicated_scored_ports for p in s.get("listening_ports", []))
    ]

    raw_service_pts = len(relevant_flagged) * w["points_per_flagged_service"]
    flagged_services_points = min(raw_service_pts, w["flagged_services_cap"])

    breakdown.append({
        "category": "Flagged Third-Party Services",
        "points_awarded": flagged_services_points,
        "max_points": w["flagged_services_cap"],
        "finding_type": "POTENTIAL",
        "severity": "LOW" if flagged_services_points > 0 else "INFORMATIONAL",
        "reason": f"{len(relevant_flagged)} third-party process(es) listening on network ports (excluding core system services).",
    })
    total_score += flagged_services_points

    # -------------------------------------------------------------
    # 7. Privilege & Maintenance Controls (UAC & Windows Update)
    # -------------------------------------------------------------
    if uac_enabled is False:
        uac_points = w["uac_disabled"]
        breakdown.append({
            "category": "User Account Control (UAC)",
            "points_awarded": uac_points,
            "max_points": w["uac_disabled"],
            "finding_type": "CONFIRMED",
            "severity": "HIGH",
            "reason": "User Account Control (UAC) is disabled. Silent privilege elevation is possible.",
        })
        total_score += uac_points
        top_findings.append("User Account Control (UAC) is disabled.")
    else:
        breakdown.append({
            "category": "User Account Control (UAC)",
            "points_awarded": 0,
            "max_points": w["uac_disabled"],
            "finding_type": "CONFIRMED",
            "severity": "INFORMATIONAL",
            "reason": "UAC is enabled or enforced at default level.",
        })
        if uac_enabled is True:
            mitigating_factors.append("User Account Control (UAC) is active.")

    if str(wu_status).lower() == "stopped":
        windows_update_points = w["windows_update_stopped"]
        breakdown.append({
            "category": "Windows Update Service",
            "points_awarded": windows_update_points,
            "max_points": w["windows_update_stopped"],
            "finding_type": "CONFIRMED",
            "severity": "MEDIUM",
            "reason": "Windows Update service is stopped. Security patches may not be delivered automatically.",
        })
        total_score += windows_update_points
    else:
        breakdown.append({
            "category": "Windows Update Service",
            "points_awarded": 0,
            "max_points": w["windows_update_stopped"],
            "finding_type": "CONFIRMED",
            "severity": "INFORMATIONAL",
            "reason": f"Windows Update service status: {wu_status or 'running'}.",
        })

    # -------------------------------------------------------------
    # 8. Unidentified Process Review Factor
    # -------------------------------------------------------------
    unidentified_ports = [p for p in ports if p.get("process_name") in (None, "Access Denied / Unavailable", "")]
    if unidentified_ports:
        unknown_process_points = min(len(unidentified_ports), w["unknown_process_review_cap"])
        breakdown.append({
            "category": "Process Ambiguity / Review Factor",
            "points_awarded": unknown_process_points,
            "max_points": w["unknown_process_review_cap"],
            "finding_type": "UNKNOWN",
            "severity": "LOW",
            "reason": (
                f"{len(unidentified_ports)} listening socket(s) had unresolvable process identities due to "
                "standard user account permission limits. Minor review weight assigned without presuming malice."
            ),
        })
        total_score += unknown_process_points

    # -------------------------------------------------------------
    # 8b. Additional Security Check Findings (Critical/High findings)
    # -------------------------------------------------------------
    if scan_data is not None:
        for chk in (scan_data.get("security_checks") or []):
            title = chk.get("title", "")
            if "UAC" in title or "RDP" in title or "Remote Desktop" in title or "Windows Update" in title:
                continue
            sev = chk.get("severity", "").upper()
            if sev == "CRITICAL":
                total_score += 15
            elif sev == "HIGH":
                total_score += 8
            elif sev == "MEDIUM":
                total_score += 3

    # -------------------------------------------------------------
    # 8c. Phase 5: CVE Vulnerability Points
    # -------------------------------------------------------------
    vulnerability_points = 0
    vuln_list = []
    if scan_data is not None:
        vuln_list = scan_data.get("vulnerabilities") or scan_data.get("vulnerability_findings") or []
    else:
        try:
            from database.database import get_vulnerability_findings
            vuln_list = get_vulnerability_findings(limit=100)
        except Exception:
            vuln_list = []

    unique_vulnerabilities = {}
    for v in vuln_list:
        if not isinstance(v, dict):
            continue
        vulnerability_key = (
            (v.get("cve_id") or "").casefold(),
            (v.get("software_name") or "").casefold(),
        )
        if not vulnerability_key[0] or vulnerability_key in unique_vulnerabilities:
            continue
        unique_vulnerabilities[vulnerability_key] = v

    for v in unique_vulnerabilities.values():
        if v.get("is_test_fixture"):
            continue
        v_status = v.get("effective_assessment_status", v.get("assessment_status", ""))
        v_sev = (v.get("severity") or "").upper()
        if v_status == "Confirmed Version Match":
            if v_sev == "CRITICAL":
                vulnerability_points += w.get("points_per_critical_cve", 15)
            elif v_sev == "HIGH":
                vulnerability_points += w.get("points_per_high_cve", 8)
            elif v_sev == "MEDIUM":
                vulnerability_points += w.get("points_per_medium_cve", 3)
        elif v_status == "Potential Match":
            if v_sev in ("CRITICAL", "HIGH"):
                vulnerability_points += w.get("points_per_medium_cve", 3)

    vulnerability_points = min(vulnerability_points, w.get("vulnerabilities_cap", 25))
    if vulnerability_points > 0:
        breakdown.append({
            "category": "CVE Vulnerabilities",
            "points_awarded": vulnerability_points,
            "max_points": w.get("vulnerabilities_cap", 25),
            "finding_type": "CONFIRMED",
            "severity": "HIGH",
            "reason": f"Installed software matches confirmed or potential CVE vulnerabilities.",
        })
        total_score += vulnerability_points

    # -------------------------------------------------------------
    # 8d. Phase 5: Remediation Defect Points
    # -------------------------------------------------------------
    remediation_defect_points = 0
    rem_history = []
    if scan_data is not None:
        rem_history = scan_data.get("remediation_history") or []
    else:
        try:
            from database.database import get_remediation_history
            rem_history = get_remediation_history(limit=20)
        except Exception:
            rem_history = []

    failed_rems_by_target = {}
    for rem in rem_history:
        if not isinstance(rem, dict):
            continue
        if rem.get("verification_status") != "FAILED" and rem.get("status") != "FAILED":
            continue
        key = rem.get("finding_id") or (
            rem.get("target_name"),
            rem.get("target_type"),
            rem.get("action_type"),
        )
        failed_rems_by_target[key] = rem
    failed_rems = list(failed_rems_by_target.values())
    if failed_rems:
        remediation_defect_points = min(len(failed_rems) * w.get("points_per_failed_verification", 5), w.get("remediation_defects_cap", 10))
        breakdown.append({
            "category": "Remediation Verification Defects",
            "points_awarded": remediation_defect_points,
            "max_points": w.get("remediation_defects_cap", 10),
            "finding_type": "CONFIRMED",
            "severity": "HIGH",
            "reason": f"{len(failed_rems)} remediation action(s) failed independent verification; attack surface remains exposed.",
        })
        total_score += remediation_defect_points

    unified = get_unified_findings(scan_data=scan_data)
    monitoring_points = 0
    monitoring_findings = [
        finding for finding in unified
        if finding.get("category") == "Monitoring Event"
    ]
    if monitoring_findings:
        monitoring_points = min(
            sum(
                w.get("points_per_high_monitoring_event", 5)
                if finding.get("severity") in ("CRITICAL", "HIGH")
                else w.get("points_per_medium_monitoring_event", 2)
                for finding in monitoring_findings
                if finding.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
            ),
            w.get("monitoring_events_cap", 15),
        )
        if monitoring_points:
            breakdown.append({
                "category": "Unrepresented Monitoring Events",
                "points_awarded": monitoring_points,
                "max_points": w.get("monitoring_events_cap", 15),
                "finding_type": "CONFIRMED",
                "severity": "HIGH",
                "reason": (
                    f"{len(monitoring_findings)} unresolved, deduplicated monitoring event(s) "
                    "remain outside current configuration findings."
                ),
            })
            total_score += monitoring_points

    # -------------------------------------------------------------
    # 9. Final Score Normalization & Risk Bands
    # -------------------------------------------------------------
    total_score = max(0, min(total_score, 100))

    if total_score >= 80:
        level = "CRITICAL"
        risk_level = "Critical"
    elif total_score >= 55:
        level = "HIGH"
        risk_level = "High"
    elif total_score >= 25:
        level = "MEDIUM"
        risk_level = "Medium"
    else:
        level = "LOW"
        risk_level = "Low"

    # Severity distribution from security checker
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    if scan_data is not None:
        for chk in (scan_data.get("security_checks") or scan_data.get("security_findings") or []):
            sev = chk.get("severity", "INFORMATIONAL").upper()
            if sev in severity_distribution:
                severity_distribution[sev] += 1
    else:
        try:
            findings_list = run_security_checks()
            for f in findings_list:
                sev = f.get("severity", "INFORMATIONAL").upper()
                if sev in severity_distribution:
                    severity_distribution[sev] += 1
        except Exception:
            pass

    limitations = [
        "This assessment reflects locally observable configuration and attack surface exposure only.",
        "It does not perform remote active exploit verification or credential validation.",
        "An open port indicates network exposure and reachable attack surface, not necessarily an active vulnerability.",
        "Unknown processes reflect lack of administrative elevation during scan and are marked for review rather than assumed dangerous.",
        "Score is an educational and defensive project heuristic, not a commercial certification.",
    ]

    breakdown_dict = {
        "firewall_points": fw_points,
        "rdp_exposure_points": rdp_exposure_points,
        "smb_exposure_points": smb_exposure_points,
        "sensitive_services_points": sensitive_services_points,
        "exposed_ports_points": exposed_ports_points,
        "flagged_services_points": flagged_services_points,
        "uac_points": uac_points,
        "windows_update_points": windows_update_points,
        "unknown_process_points": unknown_process_points,
        "vulnerability_points": vulnerability_points,
        "remediation_defect_points": remediation_defect_points,
        "monitoring_event_points": monitoring_points,
        "items": breakdown,
    }

    # Generate unified findings for this scan context
    priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for uf in unified:
        pcode = uf.get("priority_code", "P4")
        if pcode in priority_counts:
            priority_counts[pcode] += 1

    return {
        "score": total_score,
        "total_score": total_score,
        "level": level,
        "risk_level": risk_level,
        "assessment_label": ASSESSMENT_LABEL,
        "breakdown": breakdown_dict,
        "breakdown_items": breakdown,
        "severity_distribution": severity_distribution,
        "priority_distribution": priority_counts,
        "top_findings": [f for f in unified if f.get("priority_code") in ("P1", "P2")][:5],
        "unified_findings": unified,
        "mitigating_factors": mitigating_factors,
        "limitations": limitations,
    }


# ============================================================================
# PHASE 5: UNIFIED FINDINGS INTEGRATION & PRIORITIZATION
# ============================================================================

PRIORITY_P1 = "P1: Immediate Review"
PRIORITY_P2 = "P2: High Priority"
PRIORITY_P3 = "P3: Planned Remediation"
PRIORITY_P4 = "P4: Monitor"


def determine_priority(severity, confidence="CONFIRMED", exposure_scope=None, verification_failed=False):
    """
    Deterministically computes finding priority (P1-P4) and explanation based on:
    - severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
    - confidence (CONFIRMED, HIGH, MEDIUM, POTENTIAL, UNKNOWN)
    - exposure_scope (ALL_INTERFACES, SPECIFIC_INTERFACE, LOCALHOST)
    - verification status (failed verification immediately elevates priority)
    """
    sev = (severity or "LOW").upper()
    conf = (confidence or "MEDIUM").upper()

    if verification_failed:
        return "P1", PRIORITY_P1, "Remediation attempt failed independent verification; attack surface remains exposed."

    if sev == "CRITICAL":
        if exposure_scope == "LOCALHOST":
            return "P2", PRIORITY_P2, "Critical issue bound strictly to local loopback; remote exploitation is mitigated."
        if conf in ("CONFIRMED", "HIGH"):
            return "P1", PRIORITY_P1, "Critical finding with confirmed evidence; immediate review is warranted."
        return "P2", PRIORITY_P2, "Potential critical issue requires prompt validation before remediation."

    if sev == "HIGH":
        if conf not in ("CONFIRMED", "HIGH"):
            return "P3", PRIORITY_P3, "High-severity possibility needs validation before priority remediation."
        if exposure_scope == "ALL_INTERFACES" or conf == "CONFIRMED":
            return "P2", PRIORITY_P2, "High severity issue with confirmed exposure across network interfaces."
        return "P2", PRIORITY_P2, "High severity security issue requiring prompt remediation planning."

    if sev == "MEDIUM":
        if exposure_scope == "ALL_INTERFACES":
            return "P3", PRIORITY_P3, "Medium severity finding exposed on network interfaces; schedule for remediation."
        return "P3", PRIORITY_P3, "Medium severity configuration finding suitable for planned maintenance."

    return "P4", PRIORITY_P4, "Low risk or informational finding recommended for baseline monitoring."


def get_unified_findings(scan_data=None):
    """
    Integrates and deduplicates security findings from all system dimensions:
    - Exposed listening ports
    - Sensitive & flagged services
    - Windows Firewall enforcement
    - Security configurations (UAC, Windows Update, RDP)
    - CVE Vulnerability assessments
    - Real-time monitoring events
    - Failed or partially verified remediation actions

    Returns list of normalized findings with explainable priorities and lifecycle status.
    """
    findings = []
    seen_finding_ids = set()

    # Load stored lifecycle records for status tracking
    lifecycles = {}
    try:
        from database.database import get_finding_lifecycles
        rows = get_finding_lifecycles(limit=1000)
        for r in rows:
            lifecycles[r["finding_id"]] = r
    except Exception:
        pass

    # Extract scan components
    data = scan_data if scan_data is not None else {}
    ports = data.get("open_ports") if "open_ports" in data else data.get("ports", [])
    services = data.get("flagged_services") if "flagged_services" in data else data.get("services", [])
    firewall = data.get("firewall", {})
    sec_checks = data.get("security_checks") if "security_checks" in data else data.get("security_findings", [])
    vulns = data.get("vulnerabilities") if "vulnerabilities" in data else data.get("vulnerability_findings", [])
    rem_history = data.get("remediation_history", [])

    # If live scan data not supplied, load from database/modules safely
    if scan_data is None and not vulns:
        try:
            from database.database import get_vulnerability_findings
            vulns = get_vulnerability_findings(limit=100)
        except Exception:
            vulns = []

    if scan_data is None and not rem_history:
        try:
            from database.database import get_remediation_history
            rem_history = get_remediation_history(limit=50)
        except Exception:
            rem_history = []

    monitoring_events = data.get("monitoring_events") or []
    if scan_data is None and not monitoring_events:
        try:
            from database.database import get_monitoring_events
            monitoring_events = get_monitoring_events(limit=1000, unresolved_only=True)
        except Exception:
            monitoring_events = []

    # 1. RDP Exposure Deduplicated Finding
    has_rdp_port = any(p.get("port") == 3389 for p in (ports or []) if isinstance(p, dict))
    has_rdp_svc = any("term" in (s.get("name") or s.get("service_name") or "").lower() for s in (services or []) if isinstance(s, dict))
    has_rdp_check = any("RDP" in c.get("title", "") and c.get("status") == "FAIL" for c in (sec_checks or []) if isinstance(c, dict))

    if has_rdp_port or has_rdp_check:
        fid = "FINDING-RDP-EXPOSURE"
        p_item = next((p for p in (ports or []) if isinstance(p, dict) and p.get("port") == 3389), {})
        addr = p_item.get("local_address", "0.0.0.0")
        is_loopback = "127.0.0.1" in addr or "::1" in addr
        exposure = "LOCALHOST" if is_loopback else ("ALL_INTERFACES" if addr == "0.0.0.0" else "SPECIFIC_INTERFACE")
        sev = "MEDIUM" if is_loopback else "CRITICAL"
        pcode, prio, reason = determine_priority(sev, "CONFIRMED", exposure)

        findings.append({
            "id": fid,
            "category": "Network Exposure",
            "title": "Remote Desktop Protocol (RDP) Exposed",
            "severity": sev,
            "priority": prio,
            "priority_code": pcode,
            "priority_reason": reason,
            "confidence": "CONFIRMED",
            "evidence": f"Port 3389/TCP listening on {addr}. TermService active. RDP connection enabled.",
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": "Disable Remote Desktop in System Properties or block Port 3389 via Windows Firewall.",
            "operational_impact": "Disabling RDP prevents remote administrative desktop access.",
            "requires_admin": True,
            "requires_confirmation": True,
            "verification_status": "UNVERIFIED",
            "target_type": "port",
            "target_name": "3389/TCP",
            "detected_time": p_item.get("detected_time", ""),
        })
        seen_finding_ids.add(fid)

    # 2. SMB Exposure Deduplicated Finding
    has_smb_port = any(p.get("port") == 445 for p in (ports or []) if isinstance(p, dict))
    if has_smb_port:
        fid = "FINDING-SMB-EXPOSURE"
        p_item = next((p for p in (ports or []) if isinstance(p, dict) and p.get("port") == 445), {})
        addr = p_item.get("local_address", "0.0.0.0")
        is_loopback = "127.0.0.1" in addr or "::1" in addr
        exposure = "LOCALHOST" if is_loopback else ("ALL_INTERFACES" if addr == "0.0.0.0" else "SPECIFIC_INTERFACE")
        pcode, prio, reason = determine_priority("HIGH", "CONFIRMED", exposure)

        findings.append({
            "id": fid,
            "category": "Network Exposure",
            "title": "Server Message Block (SMB) Port 445 Exposed",
            "severity": "HIGH",
            "priority": prio,
            "priority_code": pcode,
            "priority_reason": reason,
            "confidence": "CONFIRMED",
            "evidence": f"Port 445/TCP listening on {addr}. LanmanServer active.",
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": "Block inbound Port 445 on public/untrusted network interfaces via Windows Firewall.",
            "operational_impact": "Disabling or blocking SMB prevents local network file and printer sharing.",
            "requires_admin": True,
            "requires_confirmation": True,
            "verification_status": "UNVERIFIED",
            "target_type": "port",
            "target_name": "445/TCP",
            "detected_time": p_item.get("detected_time", ""),
        })
        seen_finding_ids.add(fid)

    # 3. Host Firewall Findings
    fw_overall = firewall.get("overall_status")
    if fw_overall == "NOT PROTECTED":
        fid = "FINDING-FIREWALL-DISABLED"
        pcode, prio, reason = determine_priority("CRITICAL", "CONFIRMED")
        findings.append({
            "id": fid,
            "category": "Firewall",
            "title": "Windows Firewall Disabled Across All Profiles",
            "severity": "CRITICAL",
            "priority": prio,
            "priority_code": pcode,
            "priority_reason": reason,
            "confidence": "CONFIRMED",
            "evidence": "All Windows Firewall profiles (Domain, Private, Public) are disabled.",
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": "Enable Windows Defender Firewall on all active network profiles immediately.",
            "operational_impact": "Restores inbound connection filtering across all network interfaces.",
            "requires_admin": True,
            "requires_confirmation": False,
            "verification_status": "UNVERIFIED",
            "target_type": "firewall",
            "target_name": "All Profiles",
            "detected_time": "",
        })
        seen_finding_ids.add(fid)

    # 4. Generic Exposed Listening Ports (Deduplicated dual-stack)
    seen_port_keys = set()
    for p in (ports or []):
        if not isinstance(p, dict) or "error" in p:
            continue
        pnum = p.get("port")
        proto = (p.get("protocol") or "TCP").upper()
        if not pnum or pnum in (3389, 445) or p.get("risk_level") == "SAFE":
            continue
        
        port_key = (pnum, proto)
        if port_key in seen_port_keys:
            continue
        seen_port_keys.add(port_key)

        fid = f"FINDING-PORT-{pnum}-{proto}"
        addr = p.get("local_address", "0.0.0.0")
        is_loopback = "127.0.0.1" in addr or "::1" in addr
        exposure = "LOCALHOST" if is_loopback else ("ALL_INTERFACES" if addr in ("0.0.0.0", "::") else "SPECIFIC_INTERFACE")
        sev = p.get("risk_level", "Medium").upper()
        pcode, prio, reason = determine_priority(sev, "CONFIRMED", exposure)

        proc = p.get("process_name") or p.get("service") or "Unknown Process"
        findings.append({
            "id": fid,
            "category": "Network Exposure",
            "title": f"Listening Port {pnum}/{proto} ({proc})",
            "severity": sev,
            "priority": prio,
            "priority_code": pcode,
            "priority_reason": reason,
            "confidence": "CONFIRMED",
            "evidence": f"Port {pnum}/{proto} bound to {addr} (PID {p.get('pid', 'N/A')}). Process: {proc}.",
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": f"Verify necessity of port {pnum}. Block or restrict in firewall if unused.",
            "operational_impact": f"Closing or blocking port {pnum} terminates network connectivity for {proc}.",
            "requires_admin": True,
            "requires_confirmation": True,
            "verification_status": "UNVERIFIED",
            "target_type": "port",
            "target_name": f"{pnum}/{proto}",
            "detected_time": p.get("detected_time", ""),
        })
        seen_finding_ids.add(fid)

    # 5. Security Configuration Checks
    for chk in (sec_checks or []):
        if not isinstance(chk, dict) or chk.get("status") == "PASS":
            continue
        title = chk.get("title", "")
        if "RDP" in title or "Remote Desktop" in title:
            continue  # covered by dedicated RDP finding

        title_key = hashlib.sha256(title.encode("utf-8")).hexdigest()[:12]
        fid = f"FINDING-CFG-{title_key}"
        sev = chk.get("severity", "MEDIUM").upper()
        pcode, prio, reason = determine_priority(sev, "CONFIRMED")
        findings.append({
            "id": fid,
            "category": "System Configuration",
            "title": title,
            "severity": sev,
            "priority": prio,
            "priority_code": pcode,
            "priority_reason": reason,
            "confidence": "CONFIRMED",
            "evidence": chk.get("evidence") or chk.get("risk_explanation", ""),
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": chk.get("recommended_action", "Reconfigure security policy."),
            "operational_impact": chk.get("operational_impact", "Standard system operation."),
            "requires_admin": True,
            "requires_confirmation": False,
            "verification_status": "UNVERIFIED",
            "target_type": "policy",
            "target_name": title,
            "detected_time": "",
        })
        seen_finding_ids.add(fid)

    # 6. CVE Vulnerability Findings
    for v in (vulns or []):
        if not isinstance(v, dict):
            continue
        cve_id = v.get("cve_id", "")
        if not cve_id or cve_id == "N/A":
            continue
        sw_name = v.get("software_name", "Software")
        v_version = v.get("version") or v.get("software_version") or ""
        software_key = hashlib.sha256(sw_name.casefold().encode("utf-8")).hexdigest()[:10]
        fid = f"FINDING-CVE-{cve_id}-{software_key}"
        if fid in seen_finding_ids:
            continue
        seen_finding_ids.add(fid)

        if v.get("is_test_fixture"):
            continue
        v_status = v.get("effective_assessment_status", v.get("assessment_status", ""))
        sev = (v.get("severity") or "HIGH").upper()
        conf = "CONFIRMED" if v_status == "Confirmed Version Match" else "POTENTIAL"
        pcode, prio, reason = determine_priority(sev, conf)

        findings.append({
            "id": fid,
            "category": "Vulnerability",
            "title": f"{cve_id} in {sw_name} ({v_version})",
            "severity": sev,
            "priority": prio,
            "priority_code": pcode,
            "priority_reason": f"{reason} Assessment status: {v_status}.",
            "confidence": conf,
            "evidence": v.get("evidence") or v.get("description", ""),
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": f"Upgrade {sw_name} beyond vulnerable version range or apply vendor patch.",
            "operational_impact": f"Application restart required during update of {sw_name}.",
            "requires_admin": True,
            "requires_confirmation": False,
            "verification_status": "UNVERIFIED",
            "target_type": "software",
            "target_name": f"{sw_name} {v_version}",
            "detected_time": v.get("detected_time", ""),
        })

    # Include active monitor observations only when no current finding already
    # represents the same target, preventing duplicate risk points.
    seen_monitoring_targets = set()
    for event in monitoring_events:
        if not isinstance(event, dict) or event.get("is_resolved"):
            continue
        event_type = (event.get("event_type") or "").upper()
        if event_type not in {
            "PORT_OPENED",
            "PORT_PROCESS_CHANGED",
            "FIREWALL_CHANGED",
            "SECURITY_CONFIG_CHANGED",
            "SERVICE_STARTED",
            "HIGH_PRIORITY_FINDING",
        }:
            continue
        severity = (event.get("severity") or "INFO").upper()
        if severity not in ("CRITICAL", "HIGH", "MEDIUM"):
            continue

        target = str(event.get("target") or "Unknown target")
        component = (event.get("component") or "monitoring").casefold()
        event_key = (component, target.casefold())
        if event_key in seen_monitoring_targets:
            continue
        seen_monitoring_targets.add(event_key)
        details = event.get("details_parsed") or event.get("details") or {}
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (TypeError, json.JSONDecodeError):
                details = {"evidence": details}
        if not isinstance(details, dict):
            details = {"evidence": str(details)}

        if event_type == "HIGH_PRIORITY_FINDING" and details.get("id") in seen_finding_ids:
            continue
        if any(
            str(finding.get("target_name") or "").casefold() == target.casefold()
            or (
                component == "firewall"
                and finding.get("category") == "Firewall"
            )
            or (
                component == "security_config"
                and target.casefold() in finding.get("title", "").casefold()
            )
            for finding in findings
        ):
            continue

        event_id = event.get("id")
        fid = f"FINDING-MONITOR-{event_id}" if event_id is not None else (
            f"FINDING-MONITOR-{component}-{hashlib.sha256(target.casefold().encode('utf-8')).hexdigest()[:12]}"
        )
        if fid in seen_finding_ids:
            continue
        pcode, priority, reason = determine_priority(
            severity,
            "CONFIRMED",
            verification_failed=event_type == "REMEDIATION_FAILED",
        )
        findings.append({
            "id": fid,
            "category": "Monitoring Event",
            "title": f"{event_type.replace('_', ' ').title()}: {target}",
            "severity": severity,
            "priority": priority,
            "priority_code": pcode,
            "priority_reason": reason,
            "confidence": "CONFIRMED",
            "evidence": json.dumps(details, sort_keys=True, default=str),
            "status": lifecycles.get(fid, {}).get("status", "New"),
            "recommended_action": (
                f"Review the {event_type.replace('_', ' ').lower()} evidence for {target} "
                "and validate the current system state before taking action."
            ),
            "operational_impact": "Review is non-disruptive; any subsequent configuration change requires authorization.",
            "requires_admin": False,
            "requires_confirmation": True,
            "verification_status": "UNVERIFIED",
            "target_type": component,
            "target_name": target,
            "detected_time": event.get("timestamp", ""),
        })
        seen_finding_ids.add(fid)

    # 7. Failed Remediation Verification Defects
    for r in (rem_history or []):
        if not isinstance(r, dict):
            continue
        if r.get("verification_status") == "FAILED" or r.get("status") == "FAILED":
            rid = r.get("id") or hashlib.sha256(
                json.dumps(r, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()[:10]
            fid = f"FINDING-REM-DEFECT-{rid}"
            if fid in seen_finding_ids:
                continue
            seen_finding_ids.add(fid)

            target = r.get("target_name") or f"{r.get('port')}/{r.get('protocol')}" or "Resource"
            pcode, prio, reason = determine_priority("HIGH", "CONFIRMED", verification_failed=True)
            findings.append({
                "id": fid,
                "category": "Remediation Defect",
                "title": f"Failed Remediation Verification on {target}",
                "severity": "HIGH",
                "priority": prio,
                "priority_code": pcode,
                "priority_reason": reason,
                "confidence": "CONFIRMED",
                "evidence": f"Remediation action {r.get('action_type', 'ACTION')} executed but independent verification check failed.",
                "status": lifecycles.get(fid, {}).get("status", "New"),
                "recommended_action": f"Investigate root cause of failed verification for {target}. Ensure elevation and re-verify socket/service.",
                "operational_impact": "Failure to remediate leaves the component in an insecure state.",
                "requires_admin": True,
                "requires_confirmation": True,
                "verification_status": "FAILED_VERIFICATION",
                "target_type": r.get("target_type", "resource"),
                "target_name": target,
                "detected_time": r.get("timestamp", ""),
            })

    # Synchronize all discovered findings into the lifecycle database
    try:
        from database.database import save_finding_lifecycle
        for f in findings:
            save_finding_lifecycle(
                finding_id=f["id"],
                category=f["category"],
                title=f["title"],
                severity=f["severity"],
                priority=f["priority"],
                confidence=f["confidence"],
                evidence=f["evidence"],
                verification_status=f["verification_status"],
                target_type=f.get("target_type"),
                target_name=f.get("target_name"),
            )
    except Exception:
        pass

    # Sort: P1 first, then P2, P3, P4
    prio_order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    findings.sort(key=lambda x: (prio_order.get(x.get("priority_code", "P4"), 5), x.get("severity", "LOW")))
    for finding in findings:
        finding.setdefault(
            "expected_security_benefit",
            "Reduces the evidenced attack surface or improves verification of the affected control.",
        )
        finding["current_status"] = finding.get("status", "New")
        finding.setdefault("verification_status", "UNVERIFIED")
        finding.setdefault("evidence_timestamp", finding.get("detected_time", ""))
    return findings


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    result = calculate_risk_score()
    print(f"Risk Score: {result['total_score']} ({result['risk_level']})")
    print(f"Assessment: {result['assessment_label']}")
    print("\nBreakdown:")
    for b in result["breakdown"]:
        print(f"  [{b['points_awarded']}/{b['max_points']}] {b['category']}: {b['reason']}")
    print("\nSeverity Distribution:", result["severity_distribution"])
    print("\nMitigating Factors:", result["mitigating_factors"])
