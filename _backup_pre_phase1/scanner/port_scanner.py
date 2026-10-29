"""
port_scanner.py
Identifies locally listening ports on this machine using psutil.
This is PASSIVE and LOCAL ONLY: it reads existing OS connection tables.
It does not scan any other host, open connections, or send any packets.
"""

import psutil


# A short reference table of ports commonly exposed unnecessarily on
# desktop/workstation machines. Used only to generate a basic, explainable
# risk note per port. This is informational, not a vulnerability database.
COMMON_RISK_NOTES = {
    21: "FTP - unencrypted file transfer, avoid if not required",
    23: "Telnet - unencrypted remote access, high risk if enabled",
    135: "Windows RPC - commonly targeted, restrict external access",
    139: "NetBIOS - legacy file sharing, restrict to trusted networks",
    445: "SMB - file sharing, frequent target for lateral movement",
    3389: "RDP - remote desktop, must be restricted/secured if enabled",
    5900: "VNC - remote access, ensure strong authentication",
}

# Cache the PID -> Windows service mapping for the lifetime of one scan.
# win_service_iter() is Windows-only; on other platforms (or if it fails)
# this degrades to an empty map, same pattern as winreg in security_checker.py.
_win_service_iter = getattr(psutil, "win_service_iter", None)


def _build_service_pid_map():
    """
    Build a {pid: {"name": ..., "display_name": ..., "description": ...}} map
    from Windows services. Returns {} on any failure or non-Windows platform.
    This is read-only: it only enumerates service metadata, never changes any.
    """
    service_map = {}
    if _win_service_iter is None:
        return service_map

    try:
        for svc in _win_service_iter():
            try:
                pid = svc.pid()
                if pid:
                    service_map[pid] = {
                        "name": svc.name(),
                        "display_name": svc.display_name(),
                        "description": svc.description(),
                    }
            except Exception:
                continue
    except Exception:
        pass

    return service_map


def _get_process_name(pid):
    """Safely resolve a PID to a process name. Returns None if unavailable."""
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Access Denied / Unavailable"
    except Exception:
        return None


def _get_exe_path(pid):
    """Safely resolve a PID to its executable path. Returns None if unavailable."""
    if pid is None:
        return None
    try:
        return psutil.Process(pid).exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except Exception:
        return None


def _interface_label(local_address):
    """Human-readable label for how broadly a port is exposed."""
    if local_address in ("127.0.0.1", "::1"):
        return "Loopback (Localhost)"
    if local_address in ("0.0.0.0", "::"):
        return "All Interfaces"
    if local_address is None:
        return "Unknown"
    return "Specific Interface"


def _risk_note_for_port(port):
    """Return a short, explainable risk note for known common ports."""
    return COMMON_RISK_NOTES.get(port, "No specific known risk on record for this port")


def get_listening_ports():
    """
    Returns a list of dictionaries, one per listening port.

    Original fields (unchanged, kept for backward compatibility with
    service_scanner.py, security_checker.py, risk_analyzer.py,
    recommendation_engine.py):
        port, protocol, local_address, status, pid, process_name, risk_note

    Additional fields (new, added for the Port Hardening module):
        remote_address, exe_path, service_name, service_display_name,
        service_description, interface
    """
    listening_ports = []

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # On some systems, full connection info requires admin rights.
        return [{
            "error": "Access denied reading connections. Try running as Administrator."
        }]
    except Exception as e:
        return [{"error": f"Unable to read network connections ({e})"}]

    service_map = _build_service_pid_map()

    for conn in connections:
        try:
            if conn.status != psutil.CONN_LISTEN:
                continue  # We only care about ports actively listening

            protocol = "TCP" if conn.type.name == "SOCK_STREAM" else "UDP"
            local_ip, local_port = conn.laddr if conn.laddr else (None, None)
            remote_address = None
            if conn.raddr:
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"

            svc = service_map.get(conn.pid, {})

            listening_ports.append({
                # --- original fields, unchanged ---
                "port": local_port,
                "protocol": protocol,
                "local_address": local_ip,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": _get_process_name(conn.pid),
                "risk_note": _risk_note_for_port(local_port),
                # --- new fields for Port Hardening module ---
                "remote_address": remote_address,
                "exe_path": _get_exe_path(conn.pid),
                "service_name": svc.get("name"),
                "service_display_name": svc.get("display_name"),
                "service_description": svc.get("description"),
                "interface": _interface_label(local_ip),
            })
        except Exception:
            # If a single connection entry is malformed, skip it and continue.
            continue

    # Sort by port number for readability
    listening_ports.sort(key=lambda x: (x["port"] is None, x["port"]))
    return listening_ports


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    ports = get_listening_ports()
    print(json.dumps(ports, indent=4))
    print(f"\nTotal listening ports found: {len(ports)}")
