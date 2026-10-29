"""
service_scanner.py
Analyzes running processes/services on the machine and cross-references
them with listening ports. READ-ONLY: does not terminate, suspend, or
modify any process.
"""

import psutil
from scanner.port_scanner import get_listening_ports


# Processes that are core Windows system components.
# Used only to distinguish "expected system service" from "third-party /
# unusual" in the review flag - this is informational, not a whitelist
# that suppresses findings.
KNOWN_SYSTEM_PROCESSES = {
    "system", "svchost.exe", "wininit.exe", "services.exe",
    "lsass.exe", "spoolsv.exe", "csrss.exe", "smss.exe",
    "winlogon.exe", "dwm.exe", "explorer.exe",
}


def _build_port_map(listening_ports):
    """Build a {pid: [ports]} map from the port scanner's output."""
    port_map = {}
    for entry in listening_ports:
        pid = entry.get("pid")
        port = entry.get("port")
        if pid is None or port is None:
            continue
        port_map.setdefault(pid, set()).add(port)
    return port_map


def get_running_services():
    """
    Returns a list of dictionaries, one per running process, with:
    pid, name, status, listening_ports, review_flag, review_reason
    """
    services = []

    try:
        listening_ports = get_listening_ports()
    except Exception:
        listening_ports = []

    # If port_scanner returned an error dict instead of real data, ignore it
    listening_ports = [p for p in listening_ports if "error" not in p]
    port_map = _build_port_map(listening_ports)

    for proc in psutil.process_iter(attrs=["pid", "name", "status"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "Unknown"
            status = proc.info["status"]
            ports = sorted(port_map.get(pid, []))

            is_known_system = name.lower() in KNOWN_SYSTEM_PROCESSES
            has_open_ports = len(ports) > 0

            review_flag = False
            review_reason = None

            if has_open_ports and not is_known_system:
                review_flag = True
                review_reason = "Third-party/unknown process with open listening port(s)"
            elif has_open_ports and is_known_system:
                review_reason = "Known Windows system process with open port(s) - normal"
            else:
                review_reason = "No listening ports associated"

            services.append({
                "pid": pid,
                "name": name,
                "status": status,
                "listening_ports": ports,
                "review_flag": review_flag,
                "review_reason": review_reason,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process exited mid-scan or we lack permission - skip it safely
            continue
        except Exception:
            continue

    # Sort so flagged services appear first (most relevant for review)
    services.sort(key=lambda s: (not s["review_flag"], s["name"].lower()))
    return services


def get_flagged_services():
    """Convenience function: returns only services flagged for manual review."""
    return [s for s in get_running_services() if s["review_flag"]]


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    all_services = get_running_services()
    flagged = [s for s in all_services if s["review_flag"]]

    print(f"Total processes scanned: {len(all_services)}")
    print(f"Processes flagged for review: {len(flagged)}\n")
    print(json.dumps(flagged, indent=4))
