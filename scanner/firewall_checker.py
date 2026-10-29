"""
firewall_checker.py
Checks Windows Firewall status across all profiles (Domain, Private, Public).
READ-ONLY: only queries status via netsh, never modifies firewall settings.
"""

import subprocess


def _run_netsh_command():
    """
    Runs the safe, read-only netsh command to query firewall profile states.
    Returns the raw text output, or None if the command fails.
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except FileNotFoundError:
        # netsh not found - not a Windows system, or PATH issue
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _parse_firewall_output(raw_output):
    """
    Parses netsh's plain-text output into a per-profile dictionary.
    Expected profile names: Domain, Private, Public.
    """
    profiles = {}
    current_profile = None

    if not raw_output:
        return profiles

    for line in raw_output.splitlines():
        line = line.strip()

        for profile_name in ("Domain Profile", "Private Profile", "Public Profile"):
            if line.startswith(profile_name):
                current_profile = profile_name.replace(" Profile", "")
                profiles[current_profile] = {"state": "Unknown"}

        if current_profile and line.lower().startswith("state"):
            if "ON" in line.upper():
                profiles[current_profile]["state"] = "ON"
            elif "OFF" in line.upper():
                profiles[current_profile]["state"] = "OFF"

    return profiles


def get_firewall_status():
    """
    Returns a dictionary with per-profile firewall status and an overall
    summary, e.g.:
    {
        "profiles": {"Domain": {"state": "ON"}, "Private": {"state": "ON"}, "Public": {"state": "OFF"}},
        "overall_status": "PARTIALLY PROTECTED",
        "note": "..."
    }
    """
    raw_output = _run_netsh_command()

    if raw_output is None:
        return {
            "profiles": {},
            "overall_status": "UNKNOWN",
            "note": "Unable to query firewall status. Try running as Administrator, "
                     "or this may not be a supported Windows environment.",
        }

    profiles = _parse_firewall_output(raw_output)

    if not profiles:
        return {
            "profiles": {},
            "overall_status": "UNKNOWN",
            "note": "Firewall profiles could not be parsed from system output.",
        }

    states = [p["state"] for p in profiles.values()]

    if all(s == "ON" for s in states):
        overall = "PROTECTED"
        note = "All firewall profiles are enabled."
    elif all(s == "OFF" for s in states):
        overall = "NOT PROTECTED"
        note = "All firewall profiles are disabled. This significantly increases attack surface."
    else:
        overall = "PARTIALLY PROTECTED"
        note = "Some firewall profiles are disabled. Review which network profile is active."

    return {
        "profiles": profiles,
        "overall_status": overall,
        "note": note,
    }


# Quick manual test when running this file directly
if __name__ == "__main__":
    import json
    status = get_firewall_status()
    print(json.dumps(status, indent=4))
