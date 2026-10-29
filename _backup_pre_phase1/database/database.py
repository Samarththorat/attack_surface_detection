"""
database.py
Handles SQLite storage for scan results: schema creation, saving scans,
and retrieving scan history. Uses only Python's built-in sqlite3 module.
"""

import sqlite3
import os
import json
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def get_connection():
    """Returns a new SQLite connection. Caller is responsible for closing it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


def init_db():
    """
    Creates the scans table and the remediation_history table if they
    don't already exist. Safe to call every time the app starts
    (CREATE TABLE IF NOT EXISTS).
    """
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                hostname TEXT,
                listening_ports_count INTEGER,
                findings_count INTEGER,
                firewall_status TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                full_results_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS remediation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target_type TEXT,
                target_name TEXT,
                port INTEGER,
                protocol TEXT,
                previous_state TEXT,
                new_state TEXT,
                reason TEXT,
                status TEXT NOT NULL,
                error_message TEXT,
                scan_id INTEGER
            )
        """)
        conn.commit()
    finally:
        conn.close()


def save_scan(results):
    """
    Saves a full scan result dictionary (from app.run_full_scan()) into the
    database. Stores key summary fields as columns for fast querying, plus
    the entire result as JSON for full detail retrieval later.
    Returns the new scan's row ID, or None if saving failed.
    """
    try:
        scan_time = results.get("system_info", {}).get("scan_time") \
            or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = results.get("system_info", {}).get("hostname", "Unknown")

        ports = results.get("ports", [])
        ports_count = len(ports) if isinstance(ports, list) else 0

        findings = results.get("security_findings", [])
        findings_count = len(findings) if isinstance(findings, list) else 0

        firewall = results.get("firewall", {})
        firewall_status = firewall.get("overall_status", "Unknown") if isinstance(firewall, dict) else "Unknown"

        risk = results.get("risk", {})
        risk_score = risk.get("total_score") if isinstance(risk, dict) else None
        risk_level = risk.get("risk_level", "Unknown") if isinstance(risk, dict) else "Unknown"

        full_json = json.dumps(results)

        conn = get_connection()
        try:
            cursor = conn.execute("""
                INSERT INTO scans (
                    scan_time, hostname, listening_ports_count, findings_count,
                    firewall_status, risk_score, risk_level, full_results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_time, hostname, ports_count, findings_count,
                firewall_status, risk_score, risk_level, full_json
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    except Exception as e:
        print(f"[database] Failed to save scan: {e}")
        return None


def get_scan_history(limit=20):
    """
    Returns a list of summary dictionaries for the most recent scans
    (newest first), without the full JSON blob (for a lightweight list view).
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, scan_time, hostname, listening_ports_count,
                   findings_count, firewall_status, risk_score, risk_level
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[database] Failed to fetch history: {e}")
        return []
    finally:
        conn.close()


def get_scan_by_id(scan_id):
    """
    Returns the FULL scan result (parsed from JSON) for a given scan ID,
    or None if not found.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

        if row is None:
            return None

        result = dict(row)
        result["full_results"] = json.loads(result["full_results_json"])
        del result["full_results_json"]  # avoid duplicating the huge string
        return result
    except Exception as e:
        print(f"[database] Failed to fetch scan {scan_id}: {e}")
        return None
    finally:
        conn.close()


def save_remediation_action(action_type, target_type=None, target_name=None, port=None,
                             protocol=None, previous_state=None, new_state=None,
                             reason=None, status="UNKNOWN", error_message=None, scan_id=None):
    """
    Records one remediation action (block port, stop service, disable
    service, etc.) into the remediation_history table for audit purposes.
    Returns the new row's ID, or None if saving failed.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        try:
            cursor = conn.execute("""
                INSERT INTO remediation_history (
                    timestamp, action_type, target_type, target_name, port,
                    protocol, previous_state, new_state, reason, status,
                    error_message, scan_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, action_type, target_type, target_name, port,
                protocol, previous_state, new_state, reason, status,
                error_message, scan_id
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()
    except Exception as e:
        print(f"[database] Failed to save remediation action: {e}")
        return None


def get_remediation_history(limit=50):
    """
    Returns a list of remediation action records, newest first.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, timestamp, action_type, target_type, target_name, port,
                   protocol, previous_state, new_state, reason, status,
                   error_message, scan_id
            FROM remediation_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[database] Failed to fetch remediation history: {e}")
        return []
    finally:
        conn.close()


# Quick manual test when running this file directly
if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")

    # Insert a dummy scan to verify everything works end-to-end
    dummy_results = {
        "system_info": {"hostname": "TEST-PC", "scan_time": "2026-08-04 12:00:00"},
        "ports": [{"port": 445}, {"port": 3389}],
        "security_findings": [{"area": "Firewall", "detail": "test"}],
        "firewall": {"overall_status": "PROTECTED"},
        "risk": {"total_score": 42, "risk_level": "Medium"},
    }

    new_id = save_scan(dummy_results)
    print(f"Saved dummy scan with ID: {new_id}")

    history = get_scan_history()
    print(f"\nScan history ({len(history)} entries):")
    for h in history:
        print(h)

    if new_id:
        full = get_scan_by_id(new_id)
        print(f"\nFull scan {new_id} hostname: {full['full_results']['system_info']['hostname']}")

    # Quick remediation_history round-trip test
    rem_id = save_remediation_action(
        action_type="BLOCK_PORT", target_type="port", target_name="3389/TCP",
        port=3389, protocol="TCP", previous_state="LISTENING",
        new_state="FIREWALL_BLOCKED", reason="Test entry", status="SUCCESS",
        scan_id=new_id,
    )
    print(f"\nSaved dummy remediation action with ID: {rem_id}")
    print("Remediation history:")
    for r in get_remediation_history():
        print(r)
