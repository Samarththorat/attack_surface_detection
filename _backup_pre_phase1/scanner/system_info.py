"""
system_info.py
Collects basic, non-invasive system information for the security assessment report.
All data here is read-only: no configuration is changed, nothing is installed or modified.
"""

import platform
import socket
import psutil
import datetime


def get_os_info():
    """Return basic operating system details."""
    return {
        "os_name": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
    }


def get_hostname():
    """Return the computer's hostname."""
    try:
        return socket.gethostname()
    except Exception as e:
        return f"Unavailable ({e})"


def get_cpu_info():
    """Return processor name and current usage."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
    except Exception:
        cpu_percent = None

    return {
        "processor": platform.processor(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_usage_percent": cpu_percent,
    }


def get_ram_info():
    """Return RAM usage statistics in GB."""
    try:
        mem = psutil.virtual_memory()
        return {
            "total_gb": round(mem.total / (1024 ** 3), 2),
            "used_gb": round(mem.used / (1024 ** 3), 2),
            "available_gb": round(mem.available / (1024 ** 3), 2),
            "usage_percent": mem.percent,
        }
    except Exception as e:
        return {"error": f"Unable to read RAM info ({e})"}


def get_network_info():
    """Return network interfaces and their IP addresses."""
    interfaces = {}
    try:
        addrs = psutil.net_if_addrs()
        for iface_name, iface_addresses in addrs.items():
            ip_list = []
            for addr in iface_addresses:
                if addr.family == socket.AF_INET:  # IPv4 only, keeps output simple
                    ip_list.append(addr.address)
            if ip_list:
                interfaces[iface_name] = ip_list
    except Exception as e:
        interfaces["error"] = f"Unable to read network interfaces ({e})"

    return interfaces


def get_uptime():
    """Return system uptime as a human-readable string."""
    try:
        boot_time_timestamp = psutil.boot_time()
        boot_time = datetime.datetime.fromtimestamp(boot_time_timestamp)
        now = datetime.datetime.now()
        uptime_delta = now - boot_time

        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        return f"{days}d {hours}h {minutes}m"
    except Exception as e:
        return f"Unavailable ({e})"


def collect_system_info():
    """
    Master function: gathers all system information into a single dictionary.
    This is the function other modules (like app.py) will call.
    """
    info = {
        "hostname": get_hostname(),
        "os": get_os_info(),
        "cpu": get_cpu_info(),
        "ram": get_ram_info(),
        "network": get_network_info(),
        "uptime": get_uptime(),
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return info


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    data = collect_system_info()
    print(json.dumps(data, indent=4))
