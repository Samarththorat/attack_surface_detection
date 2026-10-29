"""
software_inventory.py
Phase 4: Software Inventory Collection for Windows.

Performs safe, read-only enumeration of installed software packages using
the Windows Registry (winreg). Never executes MSI repair or msiexec actions.
Handles missing fields, deduplicates across 32-bit and 64-bit registry hives,
and extracts version and publisher metadata.
"""

import datetime
import re

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    winreg = None
    HAS_WINREG = False


REGISTRY_UNINSTALL_PATHS = [
    (getattr(winreg, "HKEY_LOCAL_MACHINE", None), r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_64"),
    (getattr(winreg, "HKEY_LOCAL_MACHINE", None), r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_32"),
    (getattr(winreg, "HKEY_CURRENT_USER", None), r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
]


def _format_install_date(raw_date):
    """Normalize raw InstallDate values (e.g. '20250315' -> '2025-03-15')."""
    if not raw_date or not isinstance(raw_date, str):
        return ""
    cleaned = raw_date.strip()
    if len(cleaned) == 8 and cleaned.isdigit():
        return f"{cleaned[:4]}-{cleaned[4:6]}-{cleaned[6:]}"
    return cleaned

_format_registry_date = _format_install_date


def _is_system_component_or_hotfix(name):
    """Checks whether a display name belongs to a Windows hotfix, KB patch, or security update."""
    if not name:
        return False
    name_str = str(name).strip()
    if re.search(r"\bKB\d+\b", name_str, re.IGNORECASE):
        return True
    if re.search(r"\b(security update|hotfix|cumulative update|service pack)\b", name_str, re.IGNORECASE):
        return True
    return False


def _clean_string(val):
    if val is None:
        return ""
    if isinstance(val, str):
        return val.strip().replace("\x00", "")
    return str(val).strip()


def get_installed_software(include_system_components=False):
    """
    Enumerates installed software packages from Windows Registry uninstall keys.
    Returns a deduplicated list of dictionaries:
        [{
            "software_name": str,
            "publisher": str,
            "version": str,
            "install_date": str,
            "install_location": str,
            "source": str,
            "detected_time": str,
        }, ...]
    Safe on non-Windows systems (returns empty list without crashing).
    """
    if not HAS_WINREG or winreg is None:
        return []

    collected = []
    seen_keys = set()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for root_hive, subkey_path, source_tag in REGISTRY_UNINSTALL_PATHS:
        if root_hive is None:
            continue
        try:
            with winreg.OpenKey(root_hive, subkey_path, 0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as root_key:
                num_subkeys = winreg.QueryInfoKey(root_key)[0]
                for i in range(num_subkeys):
                    try:
                        key_name = winreg.EnumKey(root_key, i)
                        with winreg.OpenKey(root_key, key_name, 0, winreg.KEY_READ) as item_key:
                            def _read_val(vname):
                                try:
                                    val, _ = winreg.QueryValueEx(item_key, vname)
                                    return val
                                except Exception:
                                    return None

                            display_name = _clean_string(_read_val("DisplayName"))
                            if not display_name:
                                continue

                            # Skip Windows system components/patches if not requested
                            is_sys_component = _read_val("SystemComponent") == 1
                            parent_key = _read_val("ParentKeyName")
                            release_type = _clean_string(_read_val("ReleaseType"))

                            if not include_system_components:
                                if is_sys_component or parent_key:
                                    continue
                                if release_type.lower() in ("security update", "update", "hotfix"):
                                    continue
                                if _is_system_component_or_hotfix(display_name):
                                    continue

                            publisher = _clean_string(_read_val("Publisher"))
                            version = _clean_string(_read_val("DisplayVersion"))
                            install_date = _format_install_date(_clean_string(_read_val("InstallDate")))
                            install_location = _clean_string(_read_val("InstallLocation"))

                            # Deduplication key: normalized name + version + publisher
                            dedup_key = (
                                display_name.lower(),
                                version.lower(),
                                publisher.lower(),
                            )

                            if dedup_key in seen_keys:
                                continue
                            seen_keys.add(dedup_key)

                            collected.append({
                                "software_name": display_name,
                                "publisher": publisher,
                                "version": version,
                                "install_date": install_date,
                                "install_location": install_location,
                                "source": f"{source_tag}\\{key_name}",
                                "detected_time": now_str,
                            })

                    except OSError:
                        continue
        except OSError:
            continue

    # Sort alphabetically by software name
    collected.sort(key=lambda x: x["software_name"].lower())
    return collected


if __name__ == "__main__":
    import json
    software = get_installed_software()
    print(f"Discovered {len(software)} software packages.")
    print("Sample packages (first 5):")
    for s in software[:5]:
        print(json.dumps(s, indent=2))
