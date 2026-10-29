"""
port_hardening.py
Remediation actions for the Attack Surface Reduction system: blocking a port
via Windows Firewall, and stopping/disabling a Windows service.

SAFETY MODEL (read this before changing anything in this file):
  - Nothing in this module executes automatically. Every function here is
    only ever called after the user has explicitly confirmed an action in
    the UI; the API layer (app.py) additionally requires a `confirm=True`
    flag on every POST before calling into this module at all.
  - No destructive action ever accepts a raw, unvalidated string from the
    user. Port numbers are range-checked, protocols are restricted to
    TCP/UDP, and service names are validated against the set of services
    actually discovered on this machine (via psutil) before any command
    referencing them is built.
  - No subprocess call in this file uses shell=True. Every command is a
    fixed argument list; no part of it is ever built via string
    concatenation of user input into a shell command line.
  - A fixed, conservative list of core Windows services can never be
    disabled through this module, regardless of what the UI sends.
  - Every function returns a structured result dict and never raises an
    uncaught exception - callers (the Flask API layer) can always turn the
    result directly into a JSON response.
"""

import subprocess
import re

import psutil

_win_service_iter = getattr(psutil, "win_service_iter", None)
_win_service_get = getattr(psutil, "win_service_get", None)


# ----------------------------------------------------------------------
# Protected services: core OS plumbing that must never be disabled from
# this UI, because doing so can break networking, logon, diagnostics, or
# Windows Firewall itself. This list is DELIBERATELY conservative - it
# does NOT include security-relevant-but-safe-to-toggle services like
# "TermService" (Remote Desktop) or "LanmanServer" (SMB server), since a
# user may legitimately want to disable those as an attack-surface
# reduction measure. This module only blocks disabling of services whose
# loss would likely break the operating system itself.
# ----------------------------------------------------------------------
PROTECTED_SERVICES = {
    "rpcss": "Remote Procedure Call (RPC) - core OS service; most of Windows depends on this",
    "dcomlaunch": "DCOM Server Process Launcher - required for RPC/DCOM activation",
    "eventlog": "Windows Event Log - required for diagnostics and many dependent services",
    "plugplay": "Plug and Play - required for hardware/device detection",
    "power": "Power - required for power management; disabling can destabilize the OS",
    "lsm": "Local Session Manager - required for user session management",
    "winmgmt": "Windows Management Instrumentation - required by many admin/monitoring tools",
    "bfe": "Base Filtering Engine - required for Windows Firewall and IPsec to function at all",
    "mpssvc": "Windows Defender Firewall - disabling this removes firewall protection entirely",
    "samss": "Security Accounts Manager - required for user logon",
    "cryptsvc": "Cryptographic Services - required for Windows Update and certificate validation",
    "trustedinstaller": "Windows Modules Installer - required to install/remove Windows updates and components",
    "dhcp": "DHCP Client - required for automatic IP configuration on most networks",
    "dnscache": "DNS Client - required for hostname resolution used by most applications",
}

FIREWALL_RULE_PREFIX = "ASR_Block"


# ----------------------------------------------------------------------
# Validation helpers
# ----------------------------------------------------------------------

def validate_port(port):
    """Return (is_valid, port_as_int_or_None, error_message)."""
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return False, None, "Port must be a whole number."
    if not (1 <= port_int <= 65535):
        return False, None, "Port must be between 1 and 65535."
    return True, port_int, None


def validate_protocol(protocol):
    """Return (is_valid, protocol_as_UPPER_or_None, error_message)."""
    if not isinstance(protocol, str):
        return False, None, "Protocol must be 'TCP' or 'UDP'."
    normalized = protocol.strip().upper()
    if normalized not in ("TCP", "UDP"):
        return False, None, "Protocol must be 'TCP' or 'UDP'."
    return True, normalized, None


def is_valid_service_name(service_name):
    """
    Validates service name to prevent arbitrary command injection or invalid identifiers.
    Returns True if valid alphanumeric/underscore/hyphen/period identifier.
    """
    if not service_name or not isinstance(service_name, str):
        return False
    trimmed = service_name.strip()
    if not trimmed or len(trimmed) > 256:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]{1,256}$', trimmed))


KNOWN_SERVICE_IMPACTS = {
    "termservice": "Remote Desktop Administration: Stopping or disabling prevents all inbound RDP remote desktop connections.",
    "lanmanserver": "SMB File & Printer Sharing: Disabling prevents network file sharing and remote access to local printers.",
    "lanmanworkstation": "SMB Client Networking: Disabling prevents accessing file shares hosted on other machines.",
    "spooler": "Print Spooler: Disabling prevents all document printing on local and network printers.",
    "wuauserv": "Windows Update: Disabling prevents automatic detection, download, and installation of Windows security updates.",
    "sshd": "OpenSSH SSH Server: Disabling prevents secure shell remote command-line access to this host.",
    "winrm": "Windows Remote Management: Disabling prevents remote PowerShell management and WinRM automation.",
    "snmp": "SNMP Agent: Disabling prevents network management systems from querying performance metrics via SNMP.",
    "ftpsvc": "Microsoft FTP Service: Disabling prevents incoming FTP file transfers.",
    "w3svc": "IIS Web Server: Disabling stops local websites and HTTP services hosted by IIS.",
    "dnscache": "DNS Client Cache: Protected service. Disabling will break domain name resolution for all applications.",
    "dhcp": "DHCP Client: Protected service. Disabling breaks automatic IP address configuration on local networks.",
}


def get_service_dependencies(service_name):
    """
    Returns list of dependent services using 'sc enumdepend' without shell=True.
    Returns empty list if not on Windows or on any query failure.
    """
    if not is_valid_service_name(service_name):
        return []
    try:
        ok, out = _run_sc(["enumdepend", service_name.strip(), "256"])
        if not ok or not out:
            return []
        deps = []
        for line in out.splitlines():
            line = line.strip()
            if line.upper().startswith("SERVICE_NAME:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    dep = parts[1].strip()
                    if dep:
                        deps.append(dep)
        return deps
    except Exception:
        return []


def get_service_remediation_metadata(service_name):
    """
    Returns complete remediation metadata for a proposed service action:
    - Service name, display name, current state, associated process
    - Reason for recommendation
    - Operational impact (networking, printing, remote access, etc.)
    - Potential dependencies
    """
    if not service_name or not is_valid_service_name(service_name):
        return None
    info = get_service_info(service_name)
    if not info:
        return None

    key = service_name.strip().lower()
    protected, prot_reason = is_protected_service(key)

    dependencies = get_service_dependencies(info["name"])

    # Determine specific operational impact
    impact = KNOWN_SERVICE_IMPACTS.get(
        key,
        f"Stopping or disabling '{info.get('display_name') or info['name']}' may prevent dependent components from functioning normally."
    )

    reason = "Identified as network-exposed or unhardened service during attack-surface assessment."
    if protected:
        reason = f"Protected core operating system service: {prot_reason}"

    return {
        "service_name": info["name"],
        "display_name": info.get("display_name") or info["name"],
        "current_state": info.get("status", "unknown"),
        "start_type": info.get("start_type", "unknown"),
        "pid": info.get("pid"),
        "associated_process": info.get("name"),
        "is_protected": protected,
        "protection_reason": prot_reason,
        "dependencies": dependencies,
        "operational_impact": impact,
        "recommendation_reason": reason,
    }


def _check_listening_socket(port, protocol):
    """
    Checks whether a local process is currently listening on the given port/protocol.
    Used to distinguish between a firewall-blocked port and a closed listening socket.
    """
    try:
        from scanner.port_scanner import get_listening_ports
        ports = get_listening_ports()
        for p in ports:
            p_num = p.get("port")
            p_proto = (p.get("protocol") or "TCP").upper()
            if p_num == port and p_proto == protocol.upper():
                return {
                    "listening": True,
                    "process_name": p.get("process_name"),
                    "pid": p.get("pid"),
                    "local_address": p.get("local_address")
                }
        return {"listening": False}
    except Exception:
        return {"listening": False, "error": "Could not inspect sockets"}


def list_all_services():
    """
    Returns {service_name_lower: {name, display_name, status, start_type,
    description, pid}} for every service currently discoverable on this
    machine. Used to validate that a requested service actually exists
    before any command references it. Returns {} on non-Windows or on
    any enumeration failure (degrades gracefully, never raises).
    """
    services = {}
    if _win_service_iter is None:
        return services

    try:
        for svc in _win_service_iter():
            try:
                info = svc.as_dict()
                name = info.get("name")
                if name:
                    services[name.lower()] = {
                        "name": name,
                        "display_name": info.get("display_name"),
                        "status": info.get("status"),
                        "start_type": info.get("start_type"),
                        "description": info.get("description"),
                        "pid": info.get("pid"),
                    }
            except Exception:
                continue
    except Exception:
        pass

    return services


def get_service_info(service_name):
    """
    Return current info for a single service, validated against the real
    discovered service list. Returns None if the service does not exist.
    """
    if not service_name:
        return None
    services = list_all_services()
    return services.get(service_name.strip().lower())


def is_protected_service(service_name):
    """Return (is_protected, reason_or_None)."""
    if not service_name:
        return False, None
    key = service_name.strip().lower()
    if key in PROTECTED_SERVICES:
        return True, PROTECTED_SERVICES[key]
    return False, None


def is_admin_user():
    """Check if the current process has Administrator privileges on Windows."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
    except Exception:
        return False


def get_asr_blocked_ports():
    """
    Query all existing ASR firewall rules in one pass.
    Returns a set of tuples: {(port_int, protocol_upper), ...}
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        pattern = re.compile(rf"{FIREWALL_RULE_PREFIX}_(TCP|UDP)_(\d+)", re.IGNORECASE)
        matches = pattern.findall(result.stdout or "")
        return {(int(port), proto.upper()) for proto, port in matches}
    except Exception:
        return set()


# ----------------------------------------------------------------------
# Firewall rule naming + low-level netsh wrapper
# ----------------------------------------------------------------------

def _rule_name(port, protocol):
    return f"{FIREWALL_RULE_PREFIX}_{protocol}_{port}"


def _run_netsh(args, timeout=15):
    """
    Run a netsh command as a fixed argument list (never shell=True).
    Returns (success, stdout_text, stderr_text_or_None).
    """
    try:
        result = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 and "Ok." in result.stdout:
            return True, result.stdout.strip(), None
        return False, output.strip(), None
    except FileNotFoundError:
        return False, None, "netsh was not found on this system."
    except subprocess.TimeoutExpired:
        return False, None, "The firewall command timed out."
    except Exception as e:
        return False, None, f"Unexpected error running netsh: {e}"

def _run_netsh_elevated(args):
    """
    Fallback when the server process is not elevated:
    Runs netsh via PowerShell Start-Process with -Verb RunAs to trigger Windows UAC elevation.
    """
    try:
        arg_parts = []
        for a in args:
            if " " in a or "=" in a:
                arg_parts.append(f'\\"{a}\\"')
            else:
                arg_parts.append(a)
        arg_str = " ".join(arg_parts)
        ps_cmd = f"Start-Process -FilePath netsh.exe -ArgumentList '{arg_str}' -Verb RunAs -Wait -WindowStyle Hidden"
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return res.returncode == 0
    except Exception:
        return False


def _interpret_failure(raw_message):
    """Turn a raw netsh/sc failure message into a friendlier explanation."""
    if not raw_message:
        return "The command failed for an unknown reason."
    lower = raw_message.lower()
    if "requires elevation" in lower or "access is denied" in lower or "access denied" in lower:
        return "Administrator privileges are required to perform this action. Please restart the application as Administrator."
    if "the parameter is incorrect" in lower:
        return "The firewall rejected the request - double-check the port and protocol."
    return raw_message


# ----------------------------------------------------------------------
# Port blocking (Windows Firewall) - the only mechanism used to restrict
# a port; this module NEVER kills a process to "close" a port.
# ----------------------------------------------------------------------

def is_port_blocked(port, protocol):
    """
    Check whether an ASR-created block rule already exists for this
    port/protocol. Returns a dict with at least {"blocked": bool}.
    """
    ok_port, port_int, err = validate_port(port)
    ok_proto, proto, perr = validate_protocol(protocol)
    if not ok_port:
        return {"blocked": False, "error": err}
    if not ok_proto:
        return {"blocked": False, "error": perr}

    rule = _rule_name(port_int, proto)
    success, output, error = _run_netsh(["advfirewall", "firewall", "show", "rule", f"name={rule}"])

    if error:
        return {"blocked": False, "error": error}

    if output and "No rules match the specified criteria" in output:
        return {"blocked": False}

    # If the rule was found, the command exits 0 but won't contain "Ok."
    # (that's only printed for add/delete), so re-check directly for the name.
    success2, output2, _ = _run_netsh(["advfirewall", "firewall", "show", "rule", f"name={rule}"])
    if output2 and rule in output2 and "No rules match" not in output2:
        return {"blocked": True, "rule_name": rule}

    return {"blocked": False}


def block_port(port, protocol, confirm=False, check_privileges=True):
    """
    Create a Windows Firewall rule blocking INBOUND traffic to the given
    port/protocol. Requires confirm=True and Administrator privileges.
    Independently verifies firewall rule creation and distinguishes between
    blocked network exposure and closed listening sockets.

    Returns a result dict:
        {success, message, rule_name, previous_state, new_state, action_applied,
         verified, verification_status, socket_state, firewall_state, error}
    """
    ok_port, port_int, err = validate_port(port)
    if not ok_port:
        return {
            "success": False, "message": err, "error": err,
            "action_applied": False, "verified": False, "verification_status": "UNRESOLVED"
        }

    ok_proto, proto, perr = validate_protocol(protocol)
    if not ok_proto:
        return {
            "success": False, "message": perr, "error": perr,
            "action_applied": False, "verified": False, "verification_status": "UNRESOLVED"
        }

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if check_privileges and not is_admin_user():
        return {
            "success": False,
            "message": "Administrator privileges are required to modify Windows Firewall rules. Please run the application as Administrator.",
            "error": "elevation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    rule = _rule_name(port_int, proto)

    # Avoid creating duplicate rule if one already exists
    existing = is_port_blocked(port_int, proto)
    if existing.get("blocked"):
        socket_info = _check_listening_socket(port_int, proto)
        is_listening = socket_info.get("listening", False)
        ver_status = "PARTIALLY_RESOLVED" if is_listening else "RESOLVED"
        return {
            "success": True,
            "message": f"Port {port_int}/{proto} is already blocked by application firewall rule '{rule}'.",
            "rule_name": rule,
            "previous_state": "FIREWALL_BLOCKED",
            "new_state": "FIREWALL_BLOCKED",
            "action_applied": False,
            "verified": True,
            "verification_status": ver_status,
            "socket_state": "LISTENING" if is_listening else "CLOSED",
            "firewall_state": "BLOCKED",
        }

    success, output, error = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={rule}",
        "dir=in",
        "action=block",
        f"protocol={proto}",
        f"localport={port_int}",
    ])

    if error:
        return {
            "success": False,
            "message": _interpret_failure(error),
            "error": error,
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if not success:
        return {
            "success": False,
            "message": _interpret_failure(output),
            "error": output,
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    # Independent Verification of the created rule
    ver = is_port_blocked(port_int, proto)
    if ver.get("error"):
        return {
            "success": False,
            "message": "Verification inconclusive.",
            "error": ver.get("error"),
            "rule_name": rule,
            "action_applied": True,
            "verified": False,
            "verification_status": "INCONCLUSIVE",
        }

    if not ver.get("blocked"):
        return {
            "success": False,
            "message": "Firewall command executed, but independent verification failed to confirm rule exists.",
            "error": "verification_failed",
            "rule_name": rule,
            "action_applied": True,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    # Re-check network exposure and socket state
    socket_info = _check_listening_socket(port_int, proto)
    is_listening = socket_info.get("listening", False)
    ver_status = "PARTIALLY_RESOLVED" if is_listening else "RESOLVED"

    return {
        "success": True,
        "message": f"Created Windows Firewall rule '{rule}' blocking inbound {proto} port {port_int} (Independently Verified).",
        "rule_name": rule,
        "previous_state": "LISTENING",
        "new_state": "FIREWALL_BLOCKED",
        "action_applied": True,
        "verified": True,
        "verification_status": ver_status,
        "socket_state": "LISTENING" if is_listening else "CLOSED",
        "firewall_state": "BLOCKED",
    }


def unblock_port(port, protocol, confirm=False, check_privileges=True):
    """
    Remove a previously created ASR firewall block rule for this port/protocol.
    Only removes rules created and managed by this application (ASR_Block_* prefix).
    Independently verifies removal.
    """
    ok_port, port_int, err = validate_port(port)
    if not ok_port:
        return {
            "success": False, "message": err, "error": err,
            "action_applied": False, "verified": False, "verification_status": "UNRESOLVED"
        }

    ok_proto, proto, perr = validate_protocol(protocol)
    if not ok_proto:
        return {
            "success": False, "message": perr, "error": perr,
            "action_applied": False, "verified": False, "verification_status": "UNRESOLVED"
        }

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if check_privileges and not is_admin_user():
        return {
            "success": False,
            "message": "Administrator privileges are required to modify Windows Firewall rules. Please run the application as Administrator.",
            "error": "elevation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    rule = _rule_name(port_int, proto)

    # Restriction: refuse to delete any rule not managed by this application
    if not rule.startswith(FIREWALL_RULE_PREFIX):
        return {
            "success": False,
            "message": "Deletion refused: only application-managed ASR firewall rules can be removed.",
            "error": "unauthorized_rule_removal",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    success, output, error = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule}"])

    if error:
        return {
            "success": False,
            "message": _interpret_failure(error),
            "error": error,
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if not success:
        return {
            "success": False,
            "message": _interpret_failure(output),
            "error": output,
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    # Independent Verification of removal
    ver = is_port_blocked(port_int, proto)
    if ver.get("error"):
        return {
            "success": False,
            "message": "Verification inconclusive.",
            "error": ver.get("error"),
            "rule_name": rule,
            "action_applied": True,
            "verified": False,
            "verification_status": "INCONCLUSIVE",
        }

    if ver.get("blocked"):
        return {
            "success": False,
            "message": "Firewall delete command ran, but verification confirms rule remains active.",
            "error": "verification_failed",
            "rule_name": rule,
            "action_applied": True,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    socket_info = _check_listening_socket(port_int, proto)
    is_listening = socket_info.get("listening", False)

    return {
        "success": True,
        "message": f"Removed Windows Firewall rule '{rule}'. Inbound {proto} port {port_int} is unblocked (Independently Verified).",
        "rule_name": rule,
        "previous_state": "FIREWALL_BLOCKED",
        "new_state": "LISTENING" if is_listening else "CLOSED",
        "action_applied": True,
        "verified": True,
        "verification_status": "RESOLVED",
        "socket_state": "LISTENING" if is_listening else "CLOSED",
        "firewall_state": "UNBLOCKED",
    }


def _run_sc(args, timeout=15):
    """Run sc.exe as a fixed argument list (never shell=True)."""
    try:
        result = subprocess.run(
            ["sc"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except FileNotFoundError:
        return False, "sc.exe was not found on this system."
    except subprocess.TimeoutExpired:
        return False, "The service command timed out."
    except Exception as e:
        return False, f"Unexpected error running sc: {e}"


def _run_sc_elevated(args):
    """
    Fallback when the server process is not elevated:
    Runs sc.exe via PowerShell Start-Process with -Verb RunAs to trigger Windows UAC elevation.
    """
    try:
        escaped_args = []
        for a in args:
            if " " in a:
                escaped_args.append(f'\\"{a}\\"')
            else:
                escaped_args.append(a)
        arg_str = " ".join(escaped_args)
        ps_cmd = f"Start-Process -FilePath sc.exe -ArgumentList '{arg_str}' -Verb RunAs -Wait -WindowStyle Hidden"
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return res.returncode == 0
    except Exception:
        return False


def stop_service(service_name, confirm=False, check_privileges=True):
    """
    Stop a running service. Service name is strictly validated and checked against
    currently discovered services. Refuses protected core Windows services.
    Requires explicit confirmation and Administrator privileges.
    Independently verifies the post-operation service state.
    """
    if not service_name:
        return {
            "success": False, "message": "No service name provided.", "error": "missing_service_name",
            "action_applied": False, "verified": False, "verification_status": "UNRESOLVED"
        }

    if not is_valid_service_name(service_name):
        return {
            "success": False,
            "message": f"Service name '{service_name}' contains invalid characters. Refusing to proceed.",
            "error": "invalid_service_name",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    info = get_service_info(service_name)
    if info is None:
        return {
            "success": False,
            "message": f"Service '{service_name}' was not found among currently discovered services. Refusing to proceed.",
            "error": "unknown_service",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    protected, reason = is_protected_service(info["name"])
    if protected:
        return {
            "success": False,
            "message": f"'{info['name']}' is a protected core Windows service and cannot be stopped from this tool. {reason}",
            "error": "protected_service",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if check_privileges and not is_admin_user():
        return {
            "success": False,
            "message": "Administrator privileges are required to stop Windows services. Please run as Administrator.",
            "error": "elevation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    previous_state = info.get("status")

    ok, output = _run_sc(["stop", info["name"]])
    if not ok:
        return {
            "success": False,
            "message": _interpret_failure(output),
            "error": output,
            "previous_state": previous_state,
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    # Independent Verification: check fresh service state
    fresh_info = get_service_info(info["name"])
    if fresh_info is None:
        return {
            "success": False,
            "message": "Verification inconclusive.",
            "error": "verification_inconclusive",
            "previous_state": previous_state,
            "action_applied": True,
            "verified": False,
            "verification_status": "INCONCLUSIVE",
        }

    new_state = fresh_info.get("status", "stop_pending")
    if new_state in ("stopped", "stop_pending"):
        return {
            "success": True,
            "message": f"Service '{info['name']}' stop command verified. Current state: {new_state}.",
            "previous_state": previous_state,
            "new_state": new_state,
            "action_applied": True,
            "verified": True,
            "verification_status": "RESOLVED",
        }
    else:
        return {
            "success": False,
            "message": f"Stop command issued to '{info['name']}', but service state remains '{new_state}'.",
            "previous_state": previous_state,
            "new_state": new_state,
            "action_applied": True,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }


def disable_service(service_name, confirm=False, confirm_disable=False, check_privileges=True):
    """
    Set a service's startup type to Disabled (sc config ... start= disabled).
    Refuses protected services. Requires explicit confirm=True AND additional confirm_disable=True.
    Requires Administrator privileges. Independently verifies the service startup type post-operation.
    """
    if not service_name:
        return {
            "success": False, "message": "No service name provided.", "error": "missing_service_name",
            "action_applied": False, "verified": False, "verification_status": "UNRESOLVED"
        }

    if not is_valid_service_name(service_name):
        return {
            "success": False,
            "message": f"Service name '{service_name}' contains invalid characters. Refusing to proceed.",
            "error": "invalid_service_name",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    info = get_service_info(service_name)
    if info is None:
        return {
            "success": False,
            "message": f"Service '{service_name}' was not found among currently discovered services. Refusing to proceed.",
            "error": "unknown_service",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    protected, reason = is_protected_service(info["name"])
    if protected:
        return {
            "success": False,
            "message": f"'{info['name']}' is a protected core Windows service and cannot be disabled from this tool. {reason}",
            "error": "protected_service",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if not confirm_disable:
        return {
            "success": False,
            "message": "Disabling a service requires explicit secondary confirmation (confirm_disable=True).",
            "error": "disable_confirmation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    if check_privileges and not is_admin_user():
        return {
            "success": False,
            "message": "Administrator privileges are required to disable Windows services. Please run as Administrator.",
            "error": "elevation_required",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    previous_state = info.get("start_type")

    # Note the required space after "start=" - strict sc.exe syntax
    ok, output = _run_sc(["config", info["name"], "start=", "disabled"])
    if not ok:
        return {
            "success": False,
            "message": _interpret_failure(output),
            "error": output,
            "previous_state": previous_state,
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    # Independent Verification
    fresh_info = get_service_info(info["name"])
    if fresh_info is None:
        return {
            "success": False,
            "message": "Verification inconclusive.",
            "error": "verification_inconclusive",
            "previous_state": previous_state,
            "action_applied": True,
            "verified": False,
            "verification_status": "INCONCLUSIVE",
        }

    if fresh_info.get("start_type") == "disabled":
        return {
            "success": True,
            "message": f"Service '{info['name']}' startup type verified as Disabled (Verified).",
            "previous_state": previous_state,
            "new_state": "disabled",
            "action_applied": True,
            "verified": True,
            "verification_status": "RESOLVED",
        }
    else:
        return {
            "success": False,
            "message": f"Disable command was sent, but startup type remains '{fresh_info.get('start_type')}'.",
            "previous_state": previous_state,
            "new_state": fresh_info.get("start_type"),
            "action_applied": True,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }


def execute_remediation_with_verification(
    action_type, target_type, target_name=None,
    port=None, protocol=None, service_name=None,
    confirm=False, confirm_disable=False,
    reason=None, scan_id=None, check_privileges=True,
    finding_id=None,
):
    """
    Unified before-and-after verification engine:
    1. Collects baseline system state and baseline risk score.
    2. Performs the requested remediation action safely.
    3. Independently verifies post-action system and firewall/service state.
    4. Re-evaluates relevant findings and recalculates post-remediation risk score.
    5. Saves full audit and verification record to SQLite remediation_history.
    6. Returns structured before-and-after comparison payload.
    """
    # 1. Baseline risk score
    before_risk_score = None
    try:
        from scanner.risk_analyzer import calculate_risk_score
        before_res = calculate_risk_score()
        before_risk_score = before_res.get("total_score")
    except Exception:
        pass

    # 2. Dispatch action
    norm_action = (action_type or "").strip().upper()
    if norm_action == "BLOCK_PORT":
        result = block_port(port, protocol, confirm=confirm, check_privileges=check_privileges)
    elif norm_action == "UNBLOCK_PORT":
        result = unblock_port(port, protocol, confirm=confirm, check_privileges=check_privileges)
    elif norm_action == "STOP_SERVICE":
        s_name = service_name or target_name
        result = stop_service(s_name, confirm=confirm, check_privileges=check_privileges)
    elif norm_action == "DISABLE_SERVICE":
        s_name = service_name or target_name
        result = disable_service(s_name, confirm=confirm, confirm_disable=confirm_disable, check_privileges=check_privileges)
    else:
        return {
            "success": False,
            "message": f"Unknown action type '{action_type}'.",
            "error": "unknown_action_type",
            "action_applied": False,
            "verified": False,
            "verification_status": "UNRESOLVED",
        }

    # 3. Post-remediation risk score
    after_risk_score = before_risk_score
    try:
        from scanner.risk_analyzer import calculate_risk_score
        after_res = calculate_risk_score()
        after_risk_score = after_res.get("total_score")
    except Exception:
        pass

    risk_delta = (before_risk_score - after_risk_score) if (before_risk_score is not None and after_risk_score is not None) else 0

    # Safety: Never report successful remediation if verification failed
    if not result.get("verified") and result.get("success"):
        result["success"] = False
        result["verification_status"] = "UNRESOLVED"

    ver_status = result.get("verification_status", "UNRESOLVED")
    if ver_status == "INCONCLUSIVE":
        result["message"] = "Verification inconclusive."

    # 4. Save to database
    audit_record_id = None
    try:
        from database.database import save_remediation_action
        audit_record_id = save_remediation_action(
            action_type=norm_action,
            target_type=target_type,
            target_name=target_name or (f"{port}/{protocol}" if port else service_name),
            port=port,
            protocol=protocol,
            previous_state=result.get("previous_state"),
            new_state=result.get("new_state"),
            requested_change=norm_action,
            actual_outcome="SUCCESS" if result.get("success") else "FAILED",
            verification_status=ver_status,
            reason=reason or f"User requested {norm_action}",
            status="SUCCESS" if result.get("success") else "FAILED",
            error_message=result.get("error"),
            scan_id=scan_id,
            before_risk_score=before_risk_score,
            after_risk_score=after_risk_score,
            finding_id=finding_id,
        )
    except Exception as e:
        print(f"[port_hardening] Failed to save remediation history: {e}")

    result["before_risk_score"] = before_risk_score
    result["after_risk_score"] = after_risk_score
    result["risk_delta"] = risk_delta
    result["target"] = target_name or (f"{port}/{protocol}" if port else service_name)
    result["action_type"] = norm_action
    result["audit_record_id"] = audit_record_id
    result["audit_record_saved"] = audit_record_id is not None

    return result


# Quick manual test when running this file directly - READ ONLY calls only,
# does not block any port or touch any service, safe to run anytime.
if __name__ == "__main__":
    import json
    print("Protected services:")
    print(json.dumps(PROTECTED_SERVICES, indent=2))
    print("\nDiscovered services (first 5):")
    svcs = list_all_services()
    for name in list(svcs.keys())[:5]:
        print(json.dumps(svcs[name], indent=2))
    print(f"\nTotal discovered services: {len(svcs)}")
