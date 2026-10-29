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


def block_port(port, protocol, confirm=False):
    """
    Create a Windows Firewall rule blocking INBOUND traffic to the given
    port/protocol. Requires confirm=True (defense-in-depth - the UI layer
    must also have obtained explicit user confirmation before calling this
    with confirm=True). Requires Administrator privileges to succeed.

    Returns a result dict:
        {success, message, rule_name, previous_state, new_state, error}
    """
    ok_port, port_int, err = validate_port(port)
    if not ok_port:
        return {"success": False, "message": err, "error": err}

    ok_proto, proto, perr = validate_protocol(protocol)
    if not ok_proto:
        return {"success": False, "message": perr, "error": perr}

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
        }

    rule = _rule_name(port_int, proto)

    # Avoid creating a duplicate rule if one already exists.
    existing = is_port_blocked(port_int, proto)
    if existing.get("blocked"):
        return {
            "success": True,
            "message": f"Port {port_int}/{proto} is already blocked by rule '{rule}'.",
            "rule_name": rule,
            "previous_state": "FIREWALL_BLOCKED",
            "new_state": "FIREWALL_BLOCKED",
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
        return {"success": False, "message": _interpret_failure(error), "error": error}

    if success:
        return {
            "success": True,
            "message": f"Created Windows Firewall rule '{rule}' blocking inbound {proto} port {port_int}.",
            "rule_name": rule,
            "previous_state": "LISTENING",
            "new_state": "FIREWALL_BLOCKED",
        }

    # Elevation fallback: if netsh failed due to elevation, prompt UAC via PowerShell
    if "requires elevation" in (output or "").lower() or "access is denied" in (output or "").lower():
        _run_netsh_elevated([
            "advfirewall", "firewall", "add", "rule",
            f"name={rule}",
            "dir=in",
            "action=block",
            f"protocol={proto}",
            f"localport={port_int}",
        ])
        if is_port_blocked(port_int, proto).get("blocked"):
            return {
                "success": True,
                "message": f"Created Windows Firewall rule '{rule}' blocking inbound {proto} port {port_int} (via UAC elevation).",
                "rule_name": rule,
                "previous_state": "LISTENING",
                "new_state": "FIREWALL_BLOCKED",
            }

    friendly = _interpret_failure(output)
    return {"success": False, "message": friendly, "error": output}


def unblock_port(port, protocol, confirm=False):
    """
    Remove a previously created ASR firewall block rule for this
    port/protocol. Only ever removes rules this module created (by the
    fixed ASR_Block_<proto>_<port> naming convention) - never touches any
    other firewall rule on the system.
    """
    ok_port, port_int, err = validate_port(port)
    if not ok_port:
        return {"success": False, "message": err, "error": err}

    ok_proto, proto, perr = validate_protocol(protocol)
    if not ok_proto:
        return {"success": False, "message": perr, "error": perr}

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
        }

    rule = _rule_name(port_int, proto)

    success, output, error = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule}"])

    if error:
        return {"success": False, "message": _interpret_failure(error), "error": error}

    if success:
        return {
            "success": True,
            "message": f"Removed Windows Firewall rule '{rule}'. Port {port_int}/{proto} is no longer blocked by ASR.",
            "rule_name": rule,
            "previous_state": "FIREWALL_BLOCKED",
            "new_state": "LISTENING",
        }

    # Elevation fallback: if netsh delete failed due to elevation, prompt UAC via PowerShell
    if "requires elevation" in (output or "").lower() or "access is denied" in (output or "").lower():
        _run_netsh_elevated(["advfirewall", "firewall", "delete", "rule", f"name={rule}"])
        if not is_port_blocked(port_int, proto).get("blocked"):
            return {
                "success": True,
                "message": f"Removed Windows Firewall rule '{rule}'. Port {port_int}/{proto} is no longer blocked by ASR (via UAC elevation).",
                "rule_name": rule,
                "previous_state": "FIREWALL_BLOCKED",
                "new_state": "LISTENING",
            }

    friendly = _interpret_failure(output)
    return {"success": False, "message": friendly, "error": output}


# ----------------------------------------------------------------------
# Service control - stop / disable, both strictly validated and gated
# behind confirm=True, and refusing anything in PROTECTED_SERVICES.
# ----------------------------------------------------------------------

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


def stop_service(service_name, confirm=False):
    """
    Stop a running service. The service MUST already exist in the
    currently discovered service list - arbitrary names are rejected
    before any command is built. Does not change the service's startup
    type, only its current running state.
    """
    if not service_name:
        return {"success": False, "message": "No service name provided.", "error": "missing_service_name"}

    info = get_service_info(service_name)
    if info is None:
        return {
            "success": False,
            "message": f"Service '{service_name}' was not found among currently discovered services. Refusing to proceed.",
            "error": "unknown_service",
        }

    protected, reason = is_protected_service(info["name"])
    if protected:
        return {
            "success": False,
            "message": f"'{info['name']}' is a protected core Windows service and cannot be stopped from this tool. {reason}",
            "error": "protected_service",
        }

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
        }

    previous_state = info.get("status")

    ok, output = _run_sc(["stop", info["name"]])

    if not ok:
        if "access is denied" in (output or "").lower() or "requires elevation" in (output or "").lower():
            _run_sc_elevated(["stop", info["name"]])
            fresh_info = get_service_info(info["name"])
            if fresh_info and fresh_info.get("status") != previous_state:
                return {
                    "success": True,
                    "message": f"Stop command sent to service '{info['name']}' (via UAC elevation).",
                    "previous_state": previous_state,
                    "new_state": fresh_info.get("status", "stop_pending"),
                }
        return {
            "success": False,
            "message": _interpret_failure(output),
            "error": output,
            "previous_state": previous_state,
        }

    return {
        "success": True,
        "message": f"Stop command sent to service '{info['name']}'.",
        "previous_state": previous_state,
        "new_state": "stop_pending",
    }


def disable_service(service_name, confirm=False):
    """
    Set a service's startup type to Disabled (sc config ... start= disabled).
    This does NOT stop the service if it is currently running - callers
    should stop_service() first if an immediate effect is required.
    Refuses protected services and requires confirm=True.
    """
    if not service_name:
        return {"success": False, "message": "No service name provided.", "error": "missing_service_name"}

    info = get_service_info(service_name)
    if info is None:
        return {
            "success": False,
            "message": f"Service '{service_name}' was not found among currently discovered services. Refusing to proceed.",
            "error": "unknown_service",
        }

    protected, reason = is_protected_service(info["name"])
    if protected:
        return {
            "success": False,
            "message": f"'{info['name']}' is a protected core Windows service and cannot be disabled from this tool. {reason}",
            "error": "protected_service",
        }

    if not confirm:
        return {
            "success": False,
            "message": "This action requires explicit confirmation and was not performed.",
            "error": "confirmation_required",
        }

    previous_state = info.get("start_type")

    # Note the required space after "start=" - this is actual sc.exe syntax,
    # not a typo; sc.exe is strict about this format.
    ok, output = _run_sc(["config", info["name"], "start=", "disabled"])

    if not ok:
        if "access is denied" in (output or "").lower() or "requires elevation" in (output or "").lower():
            _run_sc_elevated(["config", info["name"], "start=", "disabled"])
            fresh_info = get_service_info(info["name"])
            if fresh_info and fresh_info.get("start_type") == "disabled":
                return {
                    "success": True,
                    "message": f"Service '{info['name']}' startup type set to Disabled (via UAC elevation).",
                    "previous_state": previous_state,
                    "new_state": "disabled",
                }
        return {
            "success": False,
            "message": _interpret_failure(output),
            "error": output,
            "previous_state": previous_state,
        }

    return {
        "success": True,
        "message": f"Service '{info['name']}' startup type set to Disabled.",
        "previous_state": previous_state,
        "new_state": "disabled",
    }


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
