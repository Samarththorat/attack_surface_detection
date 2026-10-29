"""
port_risk_analyzer.py
Improved port risk assessment engine for Attack Surface Reduction (Phase 2).

Classifies each listening port into an explainable risk category based on:
- Port number and protocol (TCP / UDP)
- Network binding scope: Localhost vs Specific Interface vs All Interfaces (0.0.0.0 / ::)
- Associated process, executable path, and Windows service identity
- Remote-access exposure (RDP, VNC, SSH, Telnet, WinRM)
- Security-sensitive services (SMB, RPC, Databases, Unencrypted protocols)
- Infrastructure/Discovery protocols (mDNS, SSDP, DNS, DHCP, NTP)
- Active Windows Firewall status and ASR firewall block rules
- Process ambiguity / missing elevated permissions

Risk Levels:
- SAFE: Expected, benign service or strictly localhost-bound verified process.
- LOW: Minor exposure or local discovery service on trusted interfaces.
- MEDIUM: Unhardened development server, non-standard port exposed, or unverified service.
- HIGH: Sensitive administrative or unencrypted service reachable across the network.
- CRITICAL: High-value attack target (RDP, SMB, Telnet, VNC) exposed on ALL interfaces (0.0.0.0/::).
- UNKNOWN: Process identity could not be determined (requires review, NOT assumed malicious).

IMPORTANT PRINCIPLE:
An open port does not automatically indicate a vulnerability.
Unknown ports are marked "UNKNOWN / Needs Review" rather than auto-flagged as dangerous.
"""

from scanner.port_scanner import get_listening_ports

LOCALHOST_ADDRESSES = ("127.0.0.1", "::1")
ALL_INTERFACES_ADDRESSES = ("0.0.0.0", "::")

# Public severity and scope constants
PORT_SEV_SAFE = "SAFE"
PORT_SEV_LOW = "LOW"
PORT_SEV_MEDIUM = "MEDIUM"
PORT_SEV_HIGH = "HIGH"
PORT_SEV_CRITICAL = "CRITICAL"
PORT_SEV_UNKNOWN = "UNKNOWN"

BINDING_LOOPBACK = "LOOPBACK"
BINDING_ALL_INTERFACES = "ALL_INTERFACES"
BINDING_SPECIFIC = "SPECIFIC_INTERFACE"
BINDING_UNKNOWN = "UNKNOWN"

# Sensitive remote management and terminal access protocols
REMOTE_ACCESS_PORTS = {
    22: ("SSH", "Secure Shell remote terminal access"),
    23: ("Telnet", "Unencrypted remote terminal access - credentials sent in plaintext"),
    3389: ("RDP", "Windows Remote Desktop - frequent target for brute force and credential stuffing"),
    5900: ("VNC", "Virtual Network Computing - remote graphical desktop, often weakly authenticated"),
    5901: ("VNC-1", "VNC display :1 remote graphical desktop"),
    5985: ("WinRM-HTTP", "Windows Remote Management over unencrypted HTTP"),
    5986: ("WinRM-HTTPS", "Windows Remote Management over HTTPS"),
}

# Sensitive services commonly targeted for lateral movement, credential extraction, or data access
HIGH_SENSITIVITY_PORTS = {
    21: ("FTP", "File Transfer Protocol - unencrypted authentication and data channel"),
    23: ("Telnet", "Unencrypted remote terminal protocol"),
    135: ("RPC", "Windows RPC Endpoint Mapper - heavily abused in lateral movement techniques"),
    139: ("NetBIOS", "NetBIOS Session Service - legacy file sharing protocol"),
    445: ("SMB", "Server Message Block - core Windows file sharing; prime lateral movement vector"),
    1433: ("MSSQL", "Microsoft SQL Server database listener"),
    1521: ("Oracle DB", "Oracle database listener"),
    3306: ("MySQL", "MySQL database listener"),
    5432: ("PostgreSQL", "PostgreSQL database listener"),
    6379: ("Redis", "Redis in-memory store - often deployed without authentication"),
    27017: ("MongoDB", "MongoDB NoSQL database listener"),
}

# Medium-sensitivity management, auxiliary, or container endpoints
MEDIUM_SENSITIVITY_PORTS = {
    2375: ("Docker HTTP", "Docker REST API without TLS - allows root-equivalent execution"),
    2376: ("Docker HTTPS", "Docker REST API with TLS"),
    5985: ("WinRM HTTP", "Windows Remote PowerShell management"),
    5986: ("WinRM HTTPS", "Windows Remote PowerShell management"),
    8080: ("HTTP Alt", "Alternative HTTP web/proxy service"),
    8443: ("HTTPS Alt", "Alternative HTTPS management/service port"),
    9000: ("Portainer/SonarQube", "Administrative application web console"),
}

# Standard web-facing service ports
WEB_SERVICE_PORTS = {
    80: ("HTTP", "Standard World Wide Web HTTP service"),
    443: ("HTTPS", "Standard World Wide Web HTTPS encrypted service"),
}

# Local discovery and core networking protocols
INFRASTRUCTURE_PORTS = {
    53: ("DNS", "Domain Name System resolution"),
    67: ("DHCP Server", "Dynamic Host Configuration Protocol server"),
    68: ("DHCP Client", "Dynamic Host Configuration Protocol client"),
    123: ("NTP", "Network Time Protocol synchronization"),
    161: ("SNMP", "Simple Network Management Protocol queries"),
    162: ("SNMP Trap", "Simple Network Management Protocol traps"),
    5353: ("mDNS", "Multicast DNS local service discovery"),
    1900: ("SSDP", "Simple Service Discovery Protocol (UPnP)"),
}

# Common development and debug server ports
COMMON_DEV_PORTS = {
    3000, 3001, 4200, 5000, 5173, 8000, 8080, 8888, 9000
}


def _interface_label(local_address):
    """Classify how broadly a port is exposed, in plain language."""
    if local_address in LOCALHOST_ADDRESSES:
        return "Localhost Only"
    if local_address in ALL_INTERFACES_ADDRESSES:
        return "All Interfaces (0.0.0.0 / ::)"
    if local_address is None:
        return "Unknown"
    return f"Specific Interface ({local_address})"


def _exposure_scope(local_address):
    """Return an enum-like classification of network binding."""
    if local_address in LOCALHOST_ADDRESSES:
        return "LOOPBACK"
    if local_address in ALL_INTERFACES_ADDRESSES:
        return "ALL_INTERFACES"
    if local_address is None:
        return "UNKNOWN"
    return "SPECIFIC_INTERFACE"


def _identity_unknown(entry):
    """
    True if we could not determine what process owns this port.
    Occurs when lacking administrative privileges or if process terminated during scan.
    """
    process_name = entry.get("process_name")
    if process_name in (None, "Access Denied / Unavailable", ""):
        return True
    if "Access Denied" in str(process_name):
        return True
    return False


determine_binding_scope = _exposure_scope


def analyze_port_risk(port, protocol="TCP", local_address="0.0.0.0", service="", process_name="", pid=None, firewall_status=None, is_asr_blocked=False):
    """
    Convenience evaluator for a specific port combination.
    Builds an entry dictionary and passes it to classify_port().
    """
    entry = {
        "port": port,
        "protocol": protocol,
        "local_address": local_address,
        "service_name": service,
        "process_name": process_name,
        "pid": pid,
    }
    fw_ok = True
    if firewall_status is not None:
        fw_ok = firewall_status.get("any_profile_active", True)
    return classify_port(entry, firewall_protected=fw_ok, is_asr_blocked=is_asr_blocked)


def _classify_port_internal(entry, firewall_protected=True, is_asr_blocked=False):
    result = dict(entry)
    port = entry.get("port")
    proto = (entry.get("protocol") or "TCP").upper()
    local_address = entry.get("local_address")
    proc_name = entry.get("process_name") or ""
    svc_name = entry.get("service_display_name") or entry.get("service_name") or ""

    exposure = _exposure_scope(local_address)
    interface_str = _interface_label(local_address)
    result["interface"] = interface_str
    result["exposure_type"] = exposure
    result["is_blocked"] = bool(is_asr_blocked)
    result["firewall_rule_status"] = "ACTIVE" if is_asr_blocked else "NOT_PRESENT"
    result["traffic_block_verification"] = "NOT_PERFORMED"
    result["socket_status"] = "LISTENING"
    result["is_listening"] = True

    # -------------------------------------------------------------
    # 1. Missing Process Identity (Elevated permissions or race condition)
    # -------------------------------------------------------------
    if _identity_unknown(entry):
        result["risk_level"] = "UNKNOWN"
        result["risk_reason"] = (
            f"Process owning port {port}/{proto} could not be inspected (requires elevated Administrator privileges "
            "or the process exited). Process details could not be resolved. This does NOT indicate malicious activity; manual administrator inspection is recommended."
        )
        result["recommended_status"] = "Needs Review"
        result["service_type"] = "Unknown Process"
        result["confidence"] = "Low"
        result["operational_impact"] = "Requires administrative rights to determine operational dependencies."
        return result

    # -------------------------------------------------------------
    # 2. Localhost-Only Bound Sockets (Loopback 127.0.0.1 / ::1)
    # -------------------------------------------------------------
    if exposure == "LOOPBACK":
        result["service_type"] = "Localhost Service"
        result["confidence"] = "High"
        result["operational_impact"] = f"Stopping or blocking this will disrupt local inter-process communication for {proc_name}."

        if port in REMOTE_ACCESS_PORTS:
            result["risk_level"] = "MEDIUM" if port == 3389 else "LOW"
            name, desc = REMOTE_ACCESS_PORTS[port]
            result["risk_reason"] = f"{name} ({desc}) bound to loopback/localhost only. Unreachable from external network."
            result["recommended_status"] = "Likely Required"
        elif port in HIGH_SENSITIVITY_PORTS:
            result["risk_level"] = "LOW"
            name, desc = HIGH_SENSITIVITY_PORTS[port]
            result["risk_reason"] = f"{name} ({desc}) bound to loopback. Safe from remote network traffic."
            result["recommended_status"] = "Likely Required"
        elif port in COMMON_DEV_PORTS:
            result["risk_level"] = "SAFE"
            result["risk_reason"] = "Local development server bound to loopback interface. Normal and safe."
            result["recommended_status"] = "Likely Required"
        else:
            result["risk_level"] = "SAFE"
            result["risk_reason"] = f"Identified application ({proc_name}) bound exclusively to localhost. Not network reachable."
            result["recommended_status"] = "Likely Required"
        return result

    # -------------------------------------------------------------
    # 3. Remote Access Protocols (Network-Exposed)
    # -------------------------------------------------------------
    if port in REMOTE_ACCESS_PORTS:
        name, desc = REMOTE_ACCESS_PORTS[port]
        result["service_type"] = "Remote Access"
        result["confidence"] = "High"
        result["operational_impact"] = f"Disabling or blocking {name} prevents remote administrative sessions over {proto}."

        if exposure == "ALL_INTERFACES":
            result["risk_level"] = "CRITICAL" if port in (23, 3389, 5900) else "HIGH"
            result["risk_reason"] = (
                f"Remote Desktop / {name} ({desc}) is listening on ALL interfaces (0.0.0.0 / ::). "
                "Exposed to any host capable of reaching this machine's IP addresses."
            )
            result["recommended_status"] = "Potentially Unnecessary - verify before disabling."
        else:
            result["risk_level"] = "HIGH"
            result["risk_reason"] = f"{name} ({desc}) is listening on specific network interface {local_address}."
            result["recommended_status"] = "Potentially Unnecessary - verify before disabling."
        return result

    # -------------------------------------------------------------
    # 4. High-Sensitivity Services (SMB, NetBIOS, RPC, Databases)
    # -------------------------------------------------------------
    if port in HIGH_SENSITIVITY_PORTS:
        name, desc = HIGH_SENSITIVITY_PORTS[port]
        result["service_type"] = "Sensitive Network Service"
        result["confidence"] = "CONFIRMED"
        result["operational_impact"] = f"Blocking {name} may disrupt network file sharing, domain joins, or database client access."

        if exposure == "ALL_INTERFACES":
            result["risk_level"] = "CRITICAL" if port in (445, 139, 21, 23) else "HIGH"
            result["risk_reason"] = f"{name} ({desc}) is bound to ALL network interfaces (0.0.0.0 / ::)."
            result["recommended_status"] = "Potentially Unnecessary - verify before disabling."
        else:
            result["risk_level"] = "HIGH"
            result["risk_reason"] = f"{name} ({desc}) is listening on specific network address {local_address}."
            result["recommended_status"] = "Potentially Unnecessary - verify before disabling."
        return result

    # -------------------------------------------------------------
    # 5. Medium-Sensitivity Endpoints (WinRM, Docker, Alt HTTP)
    # -------------------------------------------------------------
    if port in MEDIUM_SENSITIVITY_PORTS:
        name, desc = MEDIUM_SENSITIVITY_PORTS[port]
        result["service_type"] = "Administrative / Container Service"
        result["confidence"] = "CONFIRMED"
        result["operational_impact"] = f"Blocking {name} impacts remote management or container management tools."
        result["risk_level"] = "HIGH" if exposure == "ALL_INTERFACES" and port == 2375 else "MEDIUM"
        result["risk_reason"] = f"{name} ({desc}) exposed beyond localhost ({interface_str})."
        result["recommended_status"] = "Needs Review"
        return result

    # -------------------------------------------------------------
    # 6. Infrastructure & Discovery Services (mDNS, SSDP, DNS, NTP)
    # -------------------------------------------------------------
    if port in INFRASTRUCTURE_PORTS:
        name, desc = INFRASTRUCTURE_PORTS[port]
        result["service_type"] = "Network Infrastructure / Discovery"
        result["confidence"] = "CONFIRMED"
        result["operational_impact"] = f"Disabling {name} degrades local device discovery (printers, Chromecast, media servers) or name resolution."

        if proto == "UDP" and port in (5353, 1900):
            result["risk_level"] = "LOW"
            result["risk_reason"] = f"{name} ({desc}) is standard multicast service discovery for local subnet devices ({proc_name})."
            result["recommended_status"] = "Likely Required"
        else:
            result["risk_level"] = "LOW" if exposure != "ALL_INTERFACES" else "MEDIUM"
            result["risk_reason"] = f"{name} ({desc}) listening on {interface_str}."
            result["recommended_status"] = "Likely Required"
        return result

    # -------------------------------------------------------------
    # 7. Standard Web Services (80 HTTP, 443 HTTPS)
    # -------------------------------------------------------------
    if port in WEB_SERVICE_PORTS:
        name, desc = WEB_SERVICE_PORTS[port]
        result["service_type"] = "Web Service"
        result["confidence"] = "CONFIRMED"
        result["operational_impact"] = "Disabling web services prevents external clients from reaching hosted web applications."
        result["risk_level"] = "SAFE" if port == 443 else "LOW"
        result["risk_reason"] = f"{name} ({desc}) running by {proc_name}. Expected web service port."
        result["recommended_status"] = "Likely Required"
        return result

    # -------------------------------------------------------------
    # 8. Development Servers Exposed Beyond Localhost
    # -------------------------------------------------------------
    if port in COMMON_DEV_PORTS:
        result["service_type"] = "Development Server"
        result["confidence"] = "PROBABLE"
        result["operational_impact"] = "Stopping development server interrupts local testing and API endpoints."
        result["risk_level"] = "MEDIUM"
        result["risk_reason"] = (
            f"Common development port {port} is exposed beyond localhost on {interface_str}. "
            "Development application servers are typically not hardened against untrusted network traffic."
        )
        result["recommended_status"] = "Needs Review"
        return result

    # -------------------------------------------------------------
    # 9. Generic / Unrecognized Service Exposed on Network
    # -------------------------------------------------------------
    is_known_standard = (
        port in REMOTE_ACCESS_PORTS or
        port in HIGH_SENSITIVITY_PORTS or
        port in MEDIUM_SENSITIVITY_PORTS or
        port in WEB_SERVICE_PORTS or
        port in INFRASTRUCTURE_PORTS or
        port in COMMON_DEV_PORTS or
        port in (80, 443, 22, 53, 123)
    )

    if not is_known_standard:
        result["service_type"] = "Unrecognized Service"
        result["confidence"] = "Low"
        result["operational_impact"] = f"Blocking network access may disable network features of {proc_name}."
        result["risk_level"] = "UNKNOWN"
        result["risk_reason"] = (
            f"Port {port}/{proto} is not associated with a known standard service catalogue. "
            f"Opened on {interface_str} by '{proc_name}'. "
            "Marked for review rather than assumed malicious."
        )
        result["recommended_status"] = "Needs Review"
        return result

    result["service_type"] = "General Application Service"
    result["confidence"] = "Medium"
    result["operational_impact"] = f"Blocking network access may disable network features of {proc_name}."

    if exposure == "ALL_INTERFACES":
        result["risk_level"] = "MEDIUM"
        result["risk_reason"] = (
            f"Process '{proc_name}' (PID {entry.get('pid')}) opened listening port {port}/{proto} on ALL network interfaces. "
            "Verify whether network accessibility is required."
        )
        result["recommended_status"] = "Needs Review"
    else:
        result["risk_level"] = "LOW"
        result["risk_reason"] = (
            f"Process '{proc_name}' is listening on specific network address {local_address}. "
            "Not in high-risk service catalogue."
        )
        result["recommended_status"] = "Likely Required"

    return result


def classify_port(entry, firewall_protected=True, is_asr_blocked=False):
    """
    Evaluates a single port entry (from get_listening_ports()) and returns an
    enriched dictionary with:
        - risk_level: SAFE, LOW, MEDIUM, HIGH, CRITICAL, or UNKNOWN
        - risk_reason / risk_explanation: Technical justification for the classification
        - recommended_status / action_required: "Likely Required" / "Potentially Unnecessary" / "Needs Review"
        - service_type: High-level category
        - exposure_type / binding_scope: LOOPBACK, SPECIFIC_INTERFACE, ALL_INTERFACES, UNKNOWN
        - operational_impact: What happens if blocked
        - confidence: High, Medium, Low
        - is_blocked: bool
    """
    res = _classify_port_internal(entry, firewall_protected=firewall_protected, is_asr_blocked=is_asr_blocked)
    res["risk_explanation"] = res.get("risk_reason", "")
    res["action_required"] = res.get("recommended_status", "Needs Review")
    res["binding_scope"] = res.get("exposure_type", "UNKNOWN")
    raw_conf = res.get("confidence", "Medium")
    if raw_conf in ("CONFIRMED", "High", "HIGH"):
        res["confidence"] = "High"
    elif raw_conf in ("INCONCLUSIVE", "Low", "LOW"):
        res["confidence"] = "Low"
    else:
        res["confidence"] = "Medium"
    return res


def get_port_analysis(include_udp=True):
    """
    Runs port enumeration and classifies every entry with enriched Phase 2 metadata.
    Returns:
    {
        "ports": [...],
        "summary": {"SAFE": N, "LOW": N, "MEDIUM": N, "HIGH": N, "CRITICAL": N, "UNKNOWN": N},
        "total": N
    }
    """
    raw_ports = get_listening_ports(include_udp=include_udp)

    if raw_ports and "error" in raw_ports[0]:
        return {"ports": [], "summary": {}, "total": 0, "error": raw_ports[0]["error"]}

    # Try to check firewall status and blocked ports safely
    firewall_ok = True
    firewall_status_known = False
    blocked_ports = set()
    blocked_ports_known = False
    try:
        from scanner.port_hardening import get_asr_blocked_ports
        blocked_ports = get_asr_blocked_ports()
        blocked_ports_known = True
    except Exception:
        blocked_ports_known = False
    try:
        from scanner.firewall_checker import get_firewall_status
        status = get_firewall_status()
        if isinstance(status, dict) and not status.get("error"):
            firewall_ok = bool(status.get("any_profile_active"))
            firewall_status_known = True
    except Exception:
        firewall_status_known = False

    classified = []
    for p in raw_ports:
        port_num = p.get("port")
        proto = (p.get("protocol") or "TCP").upper()
        is_blocked = (port_num, proto) in blocked_ports if port_num else False
        classified_entry = classify_port(p, firewall_protected=firewall_ok, is_asr_blocked=is_blocked)
        classified_entry["firewall_rule_status"] = (
            "UNKNOWN" if not blocked_ports_known else "ACTIVE" if is_blocked else "NOT_PRESENT"
        )
        classified_entry["traffic_block_verification"] = "NOT_PERFORMED"
        classified_entry["socket_status"] = "LISTENING"
        classified_entry["is_listening"] = True
        classified_entry["firewall_profile_status"] = (
            "UNKNOWN" if not firewall_status_known else "PROTECTED" if firewall_ok else "NOT_PROTECTED"
        )
        classified.append(classified_entry)

    summary = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
    for p in classified:
        level = p.get("risk_level", "UNKNOWN")
        summary[level] = summary.get(level, 0) + 1

    return {
        "ports": classified,
        "summary": summary,
        "total": len(classified),
    }


def get_port_by_number(port_number):
    """Return classified port entry or entries matching a given port number."""
    analysis = get_port_analysis()
    return [p for p in analysis.get("ports", []) if p.get("port") == port_number]
