"""
port_risk_analyzer.py
Classifies each discovered listening port into a risk category, based on
the port number, the identified service/process, and its network exposure.

This module performs NO system changes of any kind - it only reads the
output of port_scanner.get_listening_ports() and produces a classification.

Risk categories (as required by the project spec):
    SAFE      - expected, low-concern (e.g. HTTPS exposed, or a safe
                localhost-only service)
    LOW       - minor concern, usually fine but worth awareness
    MEDIUM    - should be reviewed; depends heavily on the user's environment
    HIGH      - commonly targeted / sensitive service exposed to the network
    CRITICAL  - high-value target exposed as broadly as possible (0.0.0.0/::)
    UNKNOWN   - the process/service identity could not be determined at all;
                this is explicitly "Needs Review", never auto-labelled risky

IMPORTANT: An unknown port is NEVER assumed to be malicious. "UNKNOWN" means
"we could not identify it", not "this is dangerous". A human must review it.
"""

from scanner.port_scanner import get_listening_ports


LOCALHOST_ADDRESSES = ("127.0.0.1", "::1")
ALL_INTERFACES_ADDRESSES = ("0.0.0.0", "::")

# Ports with well-established, high-impact security implications when
# exposed beyond localhost. This is a small, explainable reference table -
# not a vulnerability database, and not exhaustive.
HIGH_SENSITIVITY_PORTS = {
    21: "FTP - credentials and data transmitted in plaintext",
    23: "Telnet - fully unencrypted remote access protocol",
    139: "NetBIOS - legacy file-sharing protocol, frequent lateral-movement target",
    445: "SMB - file sharing, one of the most frequently attacked Windows services",
    3389: "RDP (Remote Desktop) - common target for brute-force and credential attacks",
    5900: "VNC - remote access; often deployed with weak/no authentication",
}

MEDIUM_SENSITIVITY_PORTS = {
    135: "Windows RPC endpoint mapper - used in several known lateral-movement techniques",
    5985: "WinRM (HTTP) - remote PowerShell management",
    5986: "WinRM (HTTPS) - remote PowerShell management",
}

# Ports that are normal/expected for a machine that intentionally runs a
# web-facing service. Still flagged SAFE only when the process identity is
# known; an unrecognised process on these ports is treated as MEDIUM, not SAFE.
WEB_SERVICE_PORTS = {80: "HTTP", 443: "HTTPS"}

# Common local development server ports - normally fine when localhost-only.
COMMON_DEV_PORTS = {3000, 3001, 4200, 5000, 5173, 5432, 6379, 8000, 8080, 8888, 27017}


def _interface_label(local_address):
    """Classify how broadly a port is exposed, in plain language."""
    if local_address in LOCALHOST_ADDRESSES:
        return "Localhost Only"
    if local_address in ALL_INTERFACES_ADDRESSES:
        return "All Interfaces (0.0.0.0)"
    if local_address is None:
        return "Unknown"
    return "Specific Interface"


def _is_exposed(local_address):
    """True if the port is reachable from somewhere other than this machine."""
    return local_address not in LOCALHOST_ADDRESSES and local_address is not None


def _identity_unknown(entry):
    """
    True if we could not determine what is actually using this port.
    This is the ONLY condition that produces an UNKNOWN classification.
    """
    process_name = entry.get("process_name")
    return process_name in (None, "Access Denied / Unavailable")


def classify_port(entry):
    """
    Classify a single port entry (as produced by get_listening_ports()).
    Returns the entry with three new keys added:
        risk_level            - one of SAFE/LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN
        risk_reason            - human-readable explanation
        recommended_status      - "Likely Required" / "Potentially Unnecessary -
                                   verify before disabling." / "Needs Review"
    Does not mutate the original dict's existing keys.
    """
    result = dict(entry)
    port = entry.get("port")
    local_address = entry.get("local_address")
    exposed = _is_exposed(local_address)
    interface = _interface_label(local_address)

    # --- Rule 1: identity unknown -> always UNKNOWN / Needs Review ---
    if _identity_unknown(entry):
        result["risk_level"] = "UNKNOWN"
        result["risk_reason"] = (
            "Process identity could not be determined (requires elevated "
            "privileges or the process has since exited). This does NOT mean "
            "the port is dangerous - it means a human must review it."
        )
        result["recommended_status"] = "Needs Review"
        result["interface"] = interface
        return result

    # --- Rule 2: well-known high-sensitivity services ---
    if port in HIGH_SENSITIVITY_PORTS:
        reason = HIGH_SENSITIVITY_PORTS[port]
        if not exposed:
            result["risk_level"] = "LOW"
            result["risk_reason"] = f"{reason}. Currently bound to localhost only, so not network-reachable."
            result["recommended_status"] = "Likely Required"
        elif interface == "All Interfaces (0.0.0.0)":
            result["risk_level"] = "CRITICAL"
            result["risk_reason"] = f"{reason}. Exposed on ALL network interfaces (0.0.0.0) - maximum exposure."
            result["recommended_status"] = "Potentially Unnecessary - verify before disabling."
        else:
            result["risk_level"] = "HIGH"
            result["risk_reason"] = f"{reason}. Exposed on a specific network interface."
            result["recommended_status"] = "Potentially Unnecessary - verify before disabling."
        result["interface"] = interface
        return result

    # --- Rule 3: medium-sensitivity well-known services ---
    if port in MEDIUM_SENSITIVITY_PORTS:
        reason = MEDIUM_SENSITIVITY_PORTS[port]
        if not exposed:
            result["risk_level"] = "LOW"
            result["risk_reason"] = f"{reason}. Currently localhost-only."
            result["recommended_status"] = "Likely Required"
        else:
            result["risk_level"] = "MEDIUM"
            result["risk_reason"] = f"{reason}. Exposed beyond localhost."
            result["recommended_status"] = "Needs Review"
        result["interface"] = interface
        return result

    # --- Rule 4: standard web service ports ---
    if port in WEB_SERVICE_PORTS:
        result["risk_level"] = "SAFE"
        result["risk_reason"] = (
            f"{WEB_SERVICE_PORTS[port]} is a normal, expected port for a machine "
            f"intentionally running a web-facing service."
        )
        result["recommended_status"] = "Likely Required"
        result["interface"] = interface
        return result

    # --- Rule 5: common local development ports ---
    if port in COMMON_DEV_PORTS:
        if not exposed:
            result["risk_level"] = "LOW"
            result["risk_reason"] = "Common local development server port, bound to localhost only."
            result["recommended_status"] = "Likely Required"
        else:
            result["risk_level"] = "MEDIUM"
            result["risk_reason"] = (
                "Common development server port, but exposed beyond localhost - "
                "development servers are rarely hardened for network exposure."
            )
            result["recommended_status"] = "Needs Review"
        result["interface"] = interface
        return result

    # --- Rule 6: identified process, but not in any known-port list ---
    if not exposed:
        result["risk_level"] = "SAFE"
        result["risk_reason"] = "Process identified; bound to localhost only, not network-reachable."
        result["recommended_status"] = "Likely Required"
    else:
        result["risk_level"] = "MEDIUM"
        result["risk_reason"] = (
            "Process identified, but this port is not in the curated reference list "
            "and is exposed beyond localhost. Not confirmed dangerous - recommend review."
        )
        result["recommended_status"] = "Needs Review"
    result["interface"] = interface
    return result


def get_port_analysis():
    """
    Runs the full port scan and classifies every entry.
    Returns a dict: {"ports": [...], "summary": {risk_level: count, ...}, "total": N}
    Gracefully passes through any error dict from get_listening_ports() unchanged.
    """
    raw_ports = get_listening_ports()

    if raw_ports and "error" in raw_ports[0]:
        return {"ports": [], "summary": {}, "total": 0, "error": raw_ports[0]["error"]}

    classified = [classify_port(p) for p in raw_ports]

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
    """Return the classified entry/entries matching a specific port number."""
    analysis = get_port_analysis()
    matches = [p for p in analysis.get("ports", []) if p.get("port") == port_number]
    return matches


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    analysis = get_port_analysis()
    print(json.dumps(analysis, indent=4))
    print(f"\nTotal ports: {analysis['total']}")
    print(f"Risk summary: {analysis['summary']}")
