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
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA busy_timeout = 10000")
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
                scan_id INTEGER,
                verification_status TEXT DEFAULT 'UNVERIFIED',
                requested_change TEXT,
                actual_outcome TEXT,
                before_risk_score INTEGER,
                after_risk_score INTEGER,
                finding_id TEXT,
                verification_scan_id INTEGER
            )
        """)
        # Safe non-destructive column migration for existing databases
        cursor = conn.execute("PRAGMA table_info(remediation_history)")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        cols_to_add = [
            ("verification_status", "TEXT DEFAULT 'UNVERIFIED'"),
            ("requested_change", "TEXT"),
            ("actual_outcome", "TEXT"),
            ("before_risk_score", "INTEGER"),
            ("after_risk_score", "INTEGER"),
            ("finding_id", "TEXT"),
            ("verification_scan_id", "INTEGER"),
        ]
        for col_name, col_def in cols_to_add:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE remediation_history ADD COLUMN {col_name} {col_def}")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                component TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT,
                is_resolved INTEGER DEFAULT 0
            )
        """)
        event_columns = {row["name"] for row in conn.execute("PRAGMA table_info(monitoring_events)").fetchall()}
        for column_name, column_definition in (
            ("is_acknowledged", "INTEGER NOT NULL DEFAULT 0"),
            ("acknowledged_at", "TEXT"),
            ("is_reviewed", "INTEGER NOT NULL DEFAULT 0"),
            ("reviewed_at", "TEXT"),
        ):
            if column_name not in event_columns:
                conn.execute(f"ALTER TABLE monitoring_events ADD COLUMN {column_name} {column_definition}")
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_monitoring_events_timestamp 
            ON monitoring_events(timestamp DESC)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_assessment_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_minutes INTEGER NOT NULL DEFAULT 60,
                categories_json TEXT NOT NULL DEFAULT '["network","security"]',
                refresh_vulnerabilities INTEGER NOT NULL DEFAULT 0,
                generate_report INTEGER NOT NULL DEFAULT 0,
                next_run TEXT,
                last_run TEXT,
                last_error TEXT,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            INSERT OR IGNORE INTO scheduled_assessment_config (id, updated_at)
            VALUES (1, ?)
        """, (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))

        # Phase 4: Software Inventory & CVE Vulnerability Findings
        conn.execute("""
            CREATE TABLE IF NOT EXISTS software_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                software_name TEXT NOT NULL,
                publisher TEXT,
                version TEXT,
                install_date TEXT,
                install_location TEXT,
                source TEXT,
                detected_time TEXT NOT NULL,
                scan_id INTEGER
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_software_inventory_name 
            ON software_inventory(software_name)
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                software_name TEXT NOT NULL,
                publisher TEXT,
                version TEXT,
                cvss_score REAL,
                severity TEXT NOT NULL,
                description TEXT,
                references_json TEXT,
                assessment_status TEXT NOT NULL,
                evidence TEXT,
                detected_time TEXT NOT NULL,
                scan_id INTEGER
            )
        """)
        vulnerability_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vulnerability_findings)").fetchall()
        }
        if "assessment_run_id" not in vulnerability_columns:
            conn.execute("""
                ALTER TABLE vulnerability_findings
                ADD COLUMN assessment_run_id INTEGER
            """)
        if "affected_versions_json" not in vulnerability_columns:
            conn.execute("""
                ALTER TABLE vulnerability_findings
                ADD COLUMN affected_versions_json TEXT
            """)
        if "source" not in vulnerability_columns:
            conn.execute("""
                ALTER TABLE vulnerability_findings
                ADD COLUMN source TEXT
            """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_cve 
            ON vulnerability_findings(cve_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_status 
            ON vulnerability_findings(assessment_status)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_assessment_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                completed_at TEXT NOT NULL,
                software_evaluated INTEGER NOT NULL,
                assessment_complete INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            )
        """)
        assessment_run_columns = {
            row["name"] for row in conn.execute(
                "PRAGMA table_info(vulnerability_assessment_runs)"
            ).fetchall()
        }
        if "software_total" not in assessment_run_columns:
            conn.execute("""
                ALTER TABLE vulnerability_assessment_runs
                ADD COLUMN software_total INTEGER
            """)
        if "assessment_complete" not in assessment_run_columns:
            conn.execute("""
                ALTER TABLE vulnerability_assessment_runs
                ADD COLUMN assessment_complete INTEGER NOT NULL DEFAULT 0
            """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                query_key TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
        """)

        # Phase 5: Security Findings Lifecycle & Prioritization
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_findings_lifecycle (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                confidence TEXT,
                evidence TEXT,
                notes TEXT,
                assigned_to TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                verification_status TEXT
            )
        """)
        lifecycle_columns = {
            row["name"] for row in conn.execute(
                "PRAGMA table_info(security_findings_lifecycle)"
            ).fetchall()
        }
        for column_name, column_definition in (
            ("target_type", "TEXT"),
            ("target_name", "TEXT"),
        ):
            if column_name not in lifecycle_columns:
                conn.execute(
                    f"ALTER TABLE security_findings_lifecycle ADD COLUMN {column_name} {column_definition}"
                )
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_lifecycle_status
            ON security_findings_lifecycle(status)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_lifecycle_priority
            ON security_findings_lifecycle(priority)
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_monitor_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sampled_at TEXT NOT NULL,
                cpu_usage_percent REAL,
                memory_usage_percent REAL,
                memory_used_bytes INTEGER,
                memory_total_bytes INTEGER,
                disk_usage_percent REAL,
                disk_used_bytes INTEGER,
                disk_total_bytes INTEGER,
                disk_read_bytes INTEGER,
                disk_write_bytes INTEGER,
                disk_read_bytes_per_sec REAL,
                disk_write_bytes_per_sec REAL,
                network_received_bytes INTEGER,
                network_sent_bytes INTEGER,
                network_received_bytes_per_sec REAL,
                network_sent_bytes_per_sec REAL,
                running_processes INTEGER,
                collection_errors_json TEXT NOT NULL DEFAULT '[]'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_system_monitor_samples_time
            ON system_monitor_samples(sampled_at DESC)
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
                             reason=None, status="UNKNOWN", error_message=None, scan_id=None,
                             verification_status="UNVERIFIED", requested_change=None,
                             actual_outcome=None, before_risk_score=None,
                             after_risk_score=None, finding_id=None):
    """
    Records one remediation action (block port, stop service, disable
    service, etc.) into the remediation_history table for audit purposes.
    Maintains full backward compatibility while supporting Phase 3 verification metadata.
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
                    error_message, scan_id, verification_status, requested_change,
                    actual_outcome, before_risk_score, after_risk_score, finding_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, action_type, target_type, target_name, port,
                protocol, previous_state, new_state, reason, status,
                error_message, scan_id, verification_status, requested_change,
                actual_outcome or status, before_risk_score, after_risk_score, finding_id
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
    Includes Phase 3 verification details and target aliases.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, timestamp, action_type, target_type, target_name, port,
                   protocol, previous_state, new_state, reason, status,
                   error_message, scan_id, verification_status, requested_change,
                   actual_outcome, before_risk_score, after_risk_score, finding_id,
                   verification_scan_id
            FROM remediation_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["target"] = item.get("target_name") or (f"{item['port']}/{item['protocol']}" if item.get("port") else "-")
            result.append(item)
        return result
    except Exception as e:
        print(f"[database] Failed to fetch remediation history: {e}")
        return []
    finally:
        conn.close()


def link_remediation_verification_scan(remediation_id, scan_id):
    """Associate a remediation audit record with its post-action assessment."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """UPDATE remediation_history
               SET verification_scan_id = ?
               WHERE id = ? AND verification_scan_id IS NULL""",
            (scan_id, remediation_id),
        )
        conn.commit()
        return cursor.rowcount == 1
    except Exception as e:
        print(f"[database] Failed to link remediation assessment: {e}")
        return False
    finally:
        conn.close()


def save_monitoring_event(event_type, severity, component, target, details=None, is_resolved=0,
                          cooldown_seconds=0):
    """
    Records one attack-surface monitoring event (e.g. PORT_OPENED, PORT_CLOSED,
    FIREWALL_CHANGED, SERVICE_STARTED, SERVICE_STOPPED, SECURITY_CONFIG_CHANGED).
    Returns the new row ID, or None if failed.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details_str = json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details is not None else "")
        conn = get_connection()
        try:
            if cooldown_seconds:
                cutoff = (
                    datetime.datetime.now() - datetime.timedelta(seconds=max(0, int(cooldown_seconds)))
                ).strftime("%Y-%m-%d %H:%M:%S")
                existing = conn.execute("""
                    SELECT id FROM monitoring_events
                    WHERE event_type = ? AND component = ? AND target = ? AND timestamp >= ?
                    ORDER BY id DESC LIMIT 1
                """, (event_type, component, target, cutoff)).fetchone()
                if existing:
                    return None
            cursor = conn.execute("""
                INSERT INTO monitoring_events (
                    timestamp, event_type, severity, component, target, details, is_resolved
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, event_type, severity, component, target, details_str, int(is_resolved)))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()
    except Exception as e:
        print(f"[database] Failed to save monitoring event: {e}")
        return None


def get_monitoring_events(limit=50, unresolved_only=False, offset=0, severity=None,
                          acknowledged=None, reviewed=None):
    """
    Returns a list of monitoring event dictionaries, newest first.
    If unresolved_only is True, filters to is_resolved = 0.
    """
    conn = get_connection()
    try:
        query = """
            SELECT id, timestamp, event_type, severity, component, target, details, is_resolved,
                   is_acknowledged, acknowledged_at, is_reviewed, reviewed_at
            FROM monitoring_events
        """
        params = []
        filters = []
        if unresolved_only:
            filters.append("is_resolved = 0")
        if severity:
            filters.append("UPPER(severity) = ?")
            params.append(str(severity).upper())
        if acknowledged is not None:
            filters.append("is_acknowledged = ?")
            params.append(int(bool(acknowledged)))
        if reviewed is not None:
            filters.append("is_reviewed = ?")
            params.append(int(bool(reviewed)))
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY id DESC LIMIT ? "
        params.append(limit)
        query += " OFFSET ?"
        params.append(offset)

        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            # Try to decode details JSON if applicable
            if item.get("details"):
                try:
                    item["details_parsed"] = json.loads(item["details"])
                except Exception:
                    item["details_parsed"] = item["details"]
            result.append(item)
        return result
    except Exception as e:
        print(f"[database] Failed to fetch monitoring events: {e}")
        return []
    finally:
        conn.close()


def resolve_monitoring_event(event_id=None, component=None, target=None):
    """
    Marks one or more monitoring events as resolved (e.g. when an opened port
    has subsequently been closed).
    Returns the count of updated rows.
    """
    conn = get_connection()
    try:
        if event_id is not None:
            cursor = conn.execute("UPDATE monitoring_events SET is_resolved = 1 WHERE id = ?", (event_id,))
        elif component is not None and target is not None:
            cursor = conn.execute(
                "UPDATE monitoring_events SET is_resolved = 1 WHERE component = ? AND target = ? AND is_resolved = 0",
                (component, target)
            )
        else:
            return 0
        conn.commit()
        return cursor.rowcount
    except Exception as e:
        print(f"[database] Failed to resolve monitoring event: {e}")
        return 0
    finally:
        conn.close()


def get_unresolved_events_count():
    """Returns the total number of unresolved monitoring events."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT COUNT(*) FROM monitoring_events WHERE is_resolved = 0").fetchone()
        return row[0] if row else 0
    except Exception as e:
        print(f"[database] Failed to count unresolved events: {e}")
        return 0
    finally:
        conn.close()


def get_monitoring_event_severity_counts(unresolved_only=True):
    """Returns severity totals across stored monitoring events, not just the recent page."""
    conn = get_connection()
    try:
        query = "SELECT UPPER(severity) AS severity, COUNT(*) AS event_count FROM monitoring_events"
        if unresolved_only:
            query += " WHERE is_resolved = 0"
        query += " GROUP BY UPPER(severity)"
        return {row["severity"]: row["event_count"] for row in conn.execute(query).fetchall()}
    finally:
        conn.close()


def save_system_monitor_sample(sample, min_interval_seconds=60, retention_days=7):
    """Persist bounded system-resource history without storing process command lines."""
    sampled_at = sample.get("sampled_at")
    if not isinstance(sampled_at, str) or not sampled_at:
        raise ValueError("sampled_at is required")
    sample_time = datetime.datetime.fromisoformat(sampled_at)
    if not 1 <= int(retention_days) <= 30 or int(min_interval_seconds) < 1:
        raise ValueError("Invalid system monitoring retention configuration")

    fields = (
        "cpu_usage_percent", "memory_usage_percent", "memory_used_bytes",
        "memory_total_bytes", "disk_usage_percent", "disk_used_bytes",
        "disk_total_bytes", "disk_read_bytes", "disk_write_bytes",
        "disk_read_bytes_per_sec", "disk_write_bytes_per_sec",
        "network_received_bytes", "network_sent_bytes",
        "network_received_bytes_per_sec", "network_sent_bytes_per_sec",
        "running_processes",
    )
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        latest = conn.execute(
            "SELECT sampled_at FROM system_monitor_samples ORDER BY sampled_at DESC LIMIT 1"
        ).fetchone()
        if latest:
            latest_time = datetime.datetime.fromisoformat(latest["sampled_at"])
            if (sample_time - latest_time).total_seconds() < int(min_interval_seconds):
                conn.rollback()
                return False

        conn.execute("""
            INSERT INTO system_monitor_samples (
                sampled_at, cpu_usage_percent, memory_usage_percent,
                memory_used_bytes, memory_total_bytes, disk_usage_percent,
                disk_used_bytes, disk_total_bytes, disk_read_bytes,
                disk_write_bytes, disk_read_bytes_per_sec,
                disk_write_bytes_per_sec, network_received_bytes,
                network_sent_bytes, network_received_bytes_per_sec,
                network_sent_bytes_per_sec, running_processes,
                collection_errors_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sampled_at,
            *(sample.get(field) for field in fields),
            json.dumps(sample.get("collection_errors", []), ensure_ascii=True),
        ))
        cutoff = (sample_time - datetime.timedelta(days=int(retention_days))).isoformat()
        conn.execute("DELETE FROM system_monitor_samples WHERE sampled_at < ?", (cutoff,))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_system_monitor_samples(hours=24, limit=10000):
    """Return real system-resource samples for at most seven days."""
    if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 168:
        raise ValueError("hours must be between 1 and 168")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10080:
        raise ValueError("limit must be between 1 and 10080")
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    ).isoformat(timespec="seconds")
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT sampled_at, cpu_usage_percent, memory_usage_percent,
                   memory_used_bytes, memory_total_bytes, disk_usage_percent,
                   disk_used_bytes, disk_total_bytes, disk_read_bytes,
                   disk_write_bytes, disk_read_bytes_per_sec,
                   disk_write_bytes_per_sec, network_received_bytes,
                   network_sent_bytes, network_received_bytes_per_sec,
                   network_sent_bytes_per_sec, running_processes,
                   collection_errors_json
            FROM system_monitor_samples
            WHERE sampled_at >= ?
            ORDER BY sampled_at DESC
            LIMIT ?
        """, (cutoff, limit)).fetchall()
        samples = []
        for row in rows:
            item = dict(row)
            try:
                item["collection_errors"] = json.loads(item.pop("collection_errors_json") or "[]")
            except json.JSONDecodeError:
                item["collection_errors"] = ["Stored collection error data is malformed."]
            samples.append(item)
        return samples
    finally:
        conn.close()


def update_monitoring_event_state(event_id, field):
    """Acknowledges or reviews an alert without resolving its underlying event."""
    fields = {
        "acknowledged": ("is_acknowledged", "acknowledged_at"),
        "reviewed": ("is_reviewed", "reviewed_at"),
    }
    if field not in fields:
        raise ValueError("field must be 'acknowledged' or 'reviewed'")
    flag_column, timestamp_column = fields[field]
    conn = get_connection()
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            f"UPDATE monitoring_events SET {flag_column} = 1, {timestamp_column} = ? WHERE id = ?",
            (now_str, event_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_scheduled_assessment_config():
    """Returns persisted schedule settings, creating defaults through init_db if absent."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scheduled_assessment_config WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["categories"] = json.loads(result.pop("categories_json"))
        except (TypeError, json.JSONDecodeError):
            result["categories"] = ["network", "security"]
            result.pop("categories_json", None)
        result["enabled"] = bool(result["enabled"])
        result["refresh_vulnerabilities"] = bool(result["refresh_vulnerabilities"])
        result["generate_report"] = bool(result["generate_report"])
        return result
    finally:
        conn.close()


def save_scheduled_assessment_config(enabled, interval_minutes, categories,
                                     refresh_vulnerabilities=False, generate_report=False):
    """Validates and persists one scheduled assessment configuration."""
    if not isinstance(interval_minutes, int) or not 5 <= interval_minutes <= 10080:
        raise ValueError("interval_minutes must be between 5 and 10080")
    allowed_categories = {"network", "security", "vulnerabilities"}
    if not isinstance(categories, list) or not categories or not set(categories).issubset(allowed_categories):
        raise ValueError("categories must include one or more supported assessment categories")
    now = datetime.datetime.now()
    next_run = (
        (now + datetime.timedelta(minutes=interval_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        if enabled else None
    )
    conn = get_connection()
    try:
        conn.execute("""
            UPDATE scheduled_assessment_config
            SET enabled = ?, interval_minutes = ?, categories_json = ?,
                refresh_vulnerabilities = ?, generate_report = ?, next_run = ?,
                last_error = NULL, updated_at = ?
            WHERE id = 1
        """, (
            int(bool(enabled)), interval_minutes, json.dumps(categories),
            int(bool(refresh_vulnerabilities)), int(bool(generate_report)),
            next_run, now.strftime("%Y-%m-%d %H:%M:%S"),
        ))
        conn.commit()
    finally:
        conn.close()


def record_scheduled_assessment(run_time, next_run=None, error=None):
    """Records the outcome of one scheduled assessment."""
    conn = get_connection()
    try:
        conn.execute("""
            UPDATE scheduled_assessment_config
            SET last_run = ?, next_run = ?, last_error = ?, updated_at = ?
            WHERE id = 1
        """, (run_time, next_run, error, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Phase 4: Software Inventory & CVE Vulnerability Findings Storage
# ----------------------------------------------------------------------

def save_software_inventory(software_list, scan_id=None):
    """
    Saves a list of software dictionaries to the software_inventory table.
    Avoids duplicate entries for the same scan_id, software_name, and version.
    Returns the count of saved rows.
    """
    if not software_list:
        return 0
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    count = 0
    try:
        for sw in software_list:
            name = sw.get("software_name") or sw.get("name")
            if not name:
                continue
            publisher = sw.get("publisher", "")
            version = sw.get("version", "")
            install_date = sw.get("install_date", "")
            install_location = sw.get("install_location", "")
            source = sw.get("source", "Registry")
            det_time = sw.get("detected_time") or now_str

            # Check for duplicate
            if scan_id is None:
                exists = conn.execute("""
                    SELECT id FROM software_inventory
                    WHERE software_name = ? AND version = ? AND publisher = ? AND scan_id IS NULL
                """, (name, version, publisher)).fetchone()
            else:
                exists = conn.execute("""
                    SELECT id FROM software_inventory
                    WHERE software_name = ? AND version = ? AND publisher = ? AND scan_id = ?
                """, (name, version, publisher, scan_id)).fetchone()

            if not exists:
                conn.execute("""
                    INSERT INTO software_inventory (
                        software_name, publisher, version, install_date, install_location,
                        source, detected_time, scan_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (name, publisher, version, install_date, install_location, source, det_time, scan_id))
                count += 1
        conn.commit()
        return count
    except Exception as e:
        print(f"[database] Failed to save software inventory: {e}")
        return count
    finally:
        conn.close()


def get_software_inventory(scan_id=None, limit=500):
    """Returns installed software inventory list."""
    conn = get_connection()
    try:
        if scan_id is not None:
            rows = conn.execute("""
                SELECT * FROM software_inventory WHERE scan_id = ? ORDER BY software_name ASC LIMIT ?
            """, (scan_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM software_inventory ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[database] Failed to get software inventory: {e}")
        return []
    finally:
        conn.close()


def _insert_vulnerability_findings(conn, findings, scan_id=None, assessment_run_id=None):
    """Insert vulnerability observations associated with a scan or assessment."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    count = 0
    for finding in findings or []:
        cve_id = finding.get("cve_id")
        if not cve_id:
            continue
        software_name = finding.get("software_name", "")
        if assessment_run_id is not None:
            exists = conn.execute("""
                SELECT id FROM vulnerability_findings
                WHERE cve_id = ? AND software_name = ? AND assessment_run_id = ?
            """, (cve_id, software_name, assessment_run_id)).fetchone()
        elif scan_id is not None:
            exists = conn.execute("""
                SELECT id FROM vulnerability_findings
                WHERE cve_id = ? AND software_name = ? AND scan_id = ?
            """, (cve_id, software_name, scan_id)).fetchone()
        else:
            exists = conn.execute("""
                SELECT id FROM vulnerability_findings
                WHERE cve_id = ? AND software_name = ? AND scan_id IS NULL
                  AND assessment_run_id IS NULL
            """, (cve_id, software_name)).fetchone()
        if exists:
            continue

        references = finding.get("references", [])
        references_json = (
            json.dumps(references) if isinstance(references, list) else str(references)
        )
        affected_versions = finding.get("affected_versions", [])
        affected_versions_json = (
            json.dumps(affected_versions) if isinstance(affected_versions, list) else None
        )
        conn.execute("""
            INSERT INTO vulnerability_findings (
                cve_id, software_name, publisher, version, cvss_score, severity,
                description, references_json, assessment_status, evidence,
                detected_time, scan_id, assessment_run_id, affected_versions_json, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            software_name,
            finding.get("publisher", ""),
            finding.get("version") or finding.get("software_version", ""),
            finding.get("cvss_score"),
            finding.get("severity", "MEDIUM"),
            finding.get("description", ""),
            references_json,
            finding.get("assessment_status", "Assessment Incomplete"),
            finding.get("evidence", ""),
            finding.get("detected_time") or now_str,
            scan_id,
            assessment_run_id,
            affected_versions_json,
            finding.get("source"),
        ))
        count += 1
    return count


def _is_test_fixture_finding(finding):
    return (
        finding.get("cve_id") == "CVE-2024-9999"
        and finding.get("software_name") == "MockApp"
        and str(finding.get("evidence") or "").strip().casefold() == "mock evidence"
    )


def _effective_finding_status(finding):
    if _is_test_fixture_finding(finding):
        return "Test Fixture - Not Verified"
    version = finding.get("version") or finding.get("software_version")
    usable_version = (
        isinstance(version, str)
        and version.strip()
        and version.strip().casefold() not in {"unknown", "n/a", "na", "not reported", "none"}
    )
    if (
        finding.get("assessment_status") in ("Confirmed Version Match", "Potential Match")
        and not usable_version
    ):
        return "Insufficient Information"
    return finding.get("assessment_status")


def save_vulnerability_findings(findings, scan_id=None):
    """
    Saves a list of CVE vulnerability findings.
    Avoids duplicate entries for the same cve_id, software_name, and scan_id.
    Returns the count of saved rows.
    """
    if not findings:
        return 0
    conn = get_connection()
    count = 0
    try:
        count = _insert_vulnerability_findings(conn, findings, scan_id=scan_id)
        conn.commit()
        return count
    except Exception as e:
        print(f"[database] Failed to save vulnerability findings: {e}")
        return count
    finally:
        conn.close()


def get_vulnerability_findings(scan_id=None, limit=200, severity=None, status=None):
    """Returns stored vulnerability findings with parsed references."""
    conn = get_connection()
    try:
        query = "SELECT * FROM vulnerability_findings WHERE 1=1"
        params = []
        if scan_id is not None:
            query += " AND scan_id = ?"
            params.append(scan_id)
        if severity:
            query += " AND UPPER(severity) = ?"
            params.append(severity.upper())
        if status:
            query += """
                AND CASE
                    WHEN cve_id = 'CVE-2024-9999'
                     AND software_name = 'MockApp'
                     AND LOWER(TRIM(COALESCE(evidence, ''))) = 'mock evidence'
                        THEN 'Test Fixture - Not Verified'
                    WHEN assessment_status IN ('Confirmed Version Match', 'Potential Match')
                     AND LOWER(TRIM(COALESCE(version, ''))) IN ('', 'unknown', 'n/a', 'na', 'not reported', 'none')
                        THEN 'Insufficient Information'
                    ELSE assessment_status
                END = ?
            """
            params.append(status)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            if item.get("references_json"):
                try:
                    item["references"] = json.loads(item["references_json"])
                except Exception:
                    item["references"] = [item["references_json"]]
            else:
                item["references"] = []
            if item.get("affected_versions_json"):
                try:
                    item["affected_versions"] = json.loads(item["affected_versions_json"])
                except (TypeError, ValueError):
                    item["affected_versions"] = []
            else:
                item["affected_versions"] = []
            item["is_test_fixture"] = _is_test_fixture_finding(item)
            item["effective_assessment_status"] = _effective_finding_status(item)
            effective_status = item["effective_assessment_status"]
            if item["is_test_fixture"]:
                item["software_identity_match"] = "Unverified fixture"
            elif effective_status in ("Confirmed Version Match", "Potential Match"):
                item["software_identity_match"] = "Matched in assessment"
            elif effective_status in ("Insufficient Information", "Assessment Incomplete",
                                      "Vulnerability Source Unavailable"):
                item["software_identity_match"] = "Not fully assessed"
            else:
                item["software_identity_match"] = "Not established"
            if effective_status == "Confirmed Version Match":
                item["version_match_confidence"] = "Confirmed by version criteria"
            elif effective_status == "Potential Match":
                item["version_match_confidence"] = "Unconfirmed"
            elif effective_status in ("Insufficient Information", "Assessment Incomplete",
                                      "Vulnerability Source Unavailable", "Test Fixture - Not Verified"):
                item["version_match_confidence"] = "Not assessable"
            else:
                item["version_match_confidence"] = "No version match"
            item["assessment_completeness"] = (
                "Incomplete"
                if effective_status in (
                    "Insufficient Information",
                    "Assessment Incomplete",
                    "Vulnerability Source Unavailable",
                    "Test Fixture - Not Verified",
                )
                else "Complete"
            )
            result.append(item)
        return result
    except Exception as e:
        print(f"[database] Failed to get vulnerability findings: {e}")
        return []
    finally:
        conn.close()


def get_vulnerability_overview():
    """Return exact counts from persisted findings without counting known test fixtures."""
    conn = get_connection()
    try:
        row = conn.execute("""
            WITH classified AS (
                SELECT
                    cve_id,
                    UPPER(COALESCE(severity, 'UNKNOWN')) AS severity,
                    CASE
                        WHEN cve_id = 'CVE-2024-9999'
                         AND software_name = 'MockApp'
                         AND LOWER(TRIM(COALESCE(evidence, ''))) = 'mock evidence'
                            THEN 'Test Fixture - Not Verified'
                        WHEN assessment_status IN ('Confirmed Version Match', 'Potential Match')
                         AND LOWER(TRIM(COALESCE(version, ''))) IN
                            ('', 'unknown', 'n/a', 'na', 'not reported', 'none')
                            THEN 'Insufficient Information'
                        ELSE assessment_status
                    END AS effective_status
                FROM vulnerability_findings
            )
            SELECT
                COUNT(*) AS finding_records,
                SUM(CASE WHEN cve_id <> 'N/A'
                    AND effective_status IN ('Confirmed Version Match', 'Potential Match')
                    THEN 1 ELSE 0 END) AS total_cve_matches,
                SUM(CASE WHEN cve_id <> 'N/A'
                    AND effective_status IN ('Confirmed Version Match', 'Potential Match')
                    AND severity IN ('CRITICAL', 'HIGH')
                    THEN 1 ELSE 0 END) AS critical_high_cves,
                SUM(CASE WHEN cve_id <> 'N/A'
                    AND effective_status = 'Confirmed Version Match'
                    THEN 1 ELSE 0 END) AS confirmed_version_matches
            FROM classified
        """).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}
    finally:
        conn.close()


def record_vulnerability_assessment_run(
    software_evaluated,
    findings,
    assessment_complete,
    software_total=None,
):
    """Persist an assessment snapshot and its observations atomically."""
    completed_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings_json = json.dumps(findings if isinstance(findings, list) else [])
    conn = get_connection()
    try:
        cursor = conn.execute("""
            INSERT INTO vulnerability_assessment_runs (
                completed_at, software_evaluated, assessment_complete, findings_json, software_total
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            completed_at,
            int(software_evaluated),
            int(bool(assessment_complete)),
            findings_json,
            int(software_total) if software_total is not None else int(software_evaluated),
        ))
        _insert_vulnerability_findings(
            conn,
            findings,
            assessment_run_id=cursor.lastrowid,
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_latest_vulnerability_assessment_run():
    """Return the latest completed assessment snapshot, or None if unavailable."""
    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT id, completed_at, software_evaluated, assessment_complete, findings_json,
                   software_total
            FROM vulnerability_assessment_runs
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            result["findings"] = json.loads(result.pop("findings_json"))
        except (TypeError, ValueError):
            result["findings"] = []
            result["snapshot_error"] = "Stored assessment snapshot is invalid JSON."
        snapshot_findings = result["findings"]
        if not isinstance(snapshot_findings, list):
            snapshot_findings = []
            result["snapshot_error"] = "Stored assessment findings have an invalid format."
            result["findings"] = []
        result["contains_test_fixtures"] = any(
            isinstance(finding, dict) and _is_test_fixture_finding(finding)
            for finding in snapshot_findings
        )
        incomplete_statuses = {
            "Insufficient Information",
            "Assessment Incomplete",
            "Vulnerability Source Unavailable",
            "Test Fixture - Not Verified",
        }
        scope_complete = (
            result.get("software_total") is None
            or result.get("software_total") <= result.get("software_evaluated", 0)
        )
        result["effective_assessment_complete"] = (
            bool(result.get("assessment_complete")) and scope_complete and not any(
            isinstance(finding, dict)
            and _effective_finding_status(finding) in incomplete_statuses
            for finding in snapshot_findings
            )
        )
        return result
    finally:
        conn.close()


def get_cve_cache_status(max_age_hours=24):
    """Return NVD cache availability and the time of its most recent successful write."""
    conn = get_connection()
    try:
        rows = conn.execute("SELECT cached_at FROM cve_cache").fetchall()
    finally:
        conn.close()

    now = datetime.datetime.now()
    valid_count = 0
    latest_success = None
    for row in rows:
        try:
            cached_at = datetime.datetime.strptime(row["cached_at"], "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            continue
        if latest_success is None or cached_at > latest_success:
            latest_success = cached_at
        if 0 <= (now - cached_at).total_seconds() <= max_age_hours * 3600:
            valid_count += 1

    return {
        "cached_data_available": valid_count > 0,
        "cached_data_entries": valid_count,
        "last_successful_source_request": (
            latest_success.strftime("%Y-%m-%d %H:%M:%S") if latest_success else None
        ),
    }


def get_vulnerability_analytics():
    """Aggregate all stored vulnerability observations and the latest run snapshot."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT cve_id, software_name, assessment_status, detected_time, version, evidence
            FROM vulnerability_findings
        """).fetchall()
    finally:
        conn.close()

    unique_cves = set()
    pair_observations = {}
    confirmed_pairs = set()
    potential_pairs = set()
    findings_by_day = {}
    for row in rows:
        cve_id = (row["cve_id"] or "").strip()
        software_name = (row["software_name"] or "").strip()
        finding = dict(row)
        status = (_effective_finding_status(finding) or "").strip().casefold()
        if _is_test_fixture_finding(finding):
            continue
        if cve_id:
            normalized_cve = cve_id.casefold()
            unique_cves.add(normalized_cve)
            pair = (normalized_cve, software_name.casefold())
            pair_observations[pair] = pair_observations.get(pair, 0) + 1
            if status == "confirmed version match":
                confirmed_pairs.add(pair)
            elif status == "potential match":
                potential_pairs.add(pair)
        detected_time = row["detected_time"]
        if detected_time:
            day = detected_time[:10]
            findings_by_day[day] = findings_by_day.get(day, 0) + 1

    latest = get_latest_vulnerability_assessment_run()
    active_pairs = set()
    active_cves = set()
    active_confirmed = set()
    active_potential = set()
    if latest:
        for finding in latest.get("findings", []):
            if not isinstance(finding, dict):
                continue
            cve_id = (finding.get("cve_id") or "").strip()
            software_name = (finding.get("software_name") or "").strip()
            status = (_effective_finding_status(finding) or "").strip().casefold()
            if _is_test_fixture_finding(finding):
                continue
            if not cve_id or status not in ("confirmed version match", "potential match"):
                continue
            normalized_cve = cve_id.casefold()
            pair = (normalized_cve, software_name.casefold())
            active_pairs.add(pair)
            active_cves.add(normalized_cve)
            if status == "confirmed version match":
                active_confirmed.add(pair)
            else:
                active_potential.add(pair)

    complete = bool(latest and latest.get("effective_assessment_complete"))
    return {
        "unique_cves": len(unique_cves),
        "unique_affected_software_cve_pairs": len(pair_observations),
        "stored_observations": len(rows),
        "repeated_observations": sum(count - 1 for count in pair_observations.values()),
        "confirmed_software_cve_pairs": len(confirmed_pairs),
        "potential_software_cve_pairs": len(potential_pairs),
        "current_assessment_state": (
            "COMPLETE" if complete else "INCOMPLETE" if latest else "NO_ASSESSMENT"
        ),
        "current_assessment_time": latest.get("completed_at") if latest else None,
        "current_software_evaluated": latest.get("software_evaluated") if latest else None,
        "current_software_total": latest.get("software_total") if latest else None,
        "currently_active_findings": len(active_pairs) if complete else None,
        "currently_active_unique_cves": len(active_cves) if complete else None,
        "currently_active_confirmed_pairs": len(active_confirmed) if complete else None,
        "currently_active_potential_pairs": len(active_potential) if complete else None,
        "vulnerability_findings_by_day": dict(sorted(findings_by_day.items())),
    }


def get_cve_cache(query_key, max_age_hours=24):
    """Returns cached CVE JSON data if valid and not expired, else None."""
    if not query_key:
        return None
    conn = get_connection()
    try:
        norm_key = f"nvd_{query_key.strip().lower()}" if not query_key.startswith("nvd_") else query_key
        row = conn.execute(
            "SELECT response_json, cached_at FROM cve_cache WHERE query_key = ? OR query_key = ? ORDER BY cached_at DESC LIMIT 1",
            (query_key, norm_key)
        ).fetchone()
        if not row:
            return None
        cached_at = datetime.datetime.strptime(row["cached_at"], "%Y-%m-%d %H:%M:%S")
        if (datetime.datetime.now() - cached_at).total_seconds() > max_age_hours * 3600:
            return None
        return json.loads(row["response_json"])
    except Exception:
        return None
    finally:
        conn.close()


def set_cve_cache(query_key, response_data):
    """Caches CVE query response in cve_cache table."""
    conn = get_connection()
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data_json = json.dumps(response_data)
        conn.execute("""
            INSERT OR REPLACE INTO cve_cache (query_key, response_json, cached_at)
            VALUES (?, ?, ?)
        """, (query_key, data_json, now_str))
        conn.commit()
    except Exception as e:
        print(f"[database] Failed to cache CVE query: {e}")
    finally:
        conn.close()


# ============================================================================
# PHASE 5: SECURITY FINDINGS LIFECYCLE & PRIORITIZATION
# ============================================================================

VALID_FINDING_STATUSES = [
    "New",
    "Acknowledged",
    "In Progress",
    "Remediation Pending",
    "Resolved",
    "Partially Resolved",
    "Reopened",
    "Accepted Risk",
]


def save_finding_lifecycle(finding_id, category, title, severity, priority, status="New",
                           confidence=None, evidence=None, notes=None, assigned_to=None,
                           verification_status=None, target_type=None, target_name=None):
    """
    Inserts or updates a security finding's lifecycle record in SQLite.
    Preserves existing status if record already exists unless explicitly updating.
    """
    if not finding_id:
        return None
    conn = get_connection()
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        existing = conn.execute(
            "SELECT id, status FROM security_findings_lifecycle WHERE finding_id = ?",
            (finding_id,)
        ).fetchone()

        if existing:
            # Update metadata, keeping existing status unless changed
            conn.execute("""
                UPDATE security_findings_lifecycle
                SET category = ?, title = ?, severity = ?, priority = ?,
                    confidence = COALESCE(?, confidence),
                    evidence = COALESCE(?, evidence),
                    verification_status = CASE WHEN status = 'Resolved' THEN 'UNVERIFIED' ELSE COALESCE(?, verification_status) END,
                    target_type = COALESCE(?, target_type),
                    target_name = COALESCE(?, target_name),
                    status = CASE WHEN status = 'Resolved' THEN 'Reopened' ELSE status END,
                    resolved_at = CASE WHEN status = 'Resolved' THEN NULL ELSE resolved_at END,
                    updated_at = ?
                WHERE finding_id = ?
            """, (
                category, title, severity, priority, confidence, evidence,
                verification_status, target_type, target_name, now_str, finding_id,
            ))
            conn.commit()
            return existing["id"]
        else:
            cursor = conn.execute("""
                INSERT INTO security_findings_lifecycle (
                    finding_id, category, title, severity, priority, status,
                    confidence, evidence, notes, assigned_to, created_at, updated_at,
                    verification_status, target_type, target_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, category, title, severity, priority, status,
                confidence, evidence, notes, assigned_to, now_str, now_str,
                verification_status, target_type, target_name,
            ))
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"[database] Failed to save finding lifecycle: {e}")
        return None
    finally:
        conn.close()


def get_finding_lifecycles(status=None, priority=None, limit=500):
    """Returns stored findings lifecycle records with optional status/priority filtering."""
    conn = get_connection()
    try:
        query = "SELECT * FROM security_findings_lifecycle WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND (priority = ? OR priority LIKE ?)"
            params.extend([priority, f"{priority}%"])
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[database] Failed to get finding lifecycles: {e}")
        return []
    finally:
        conn.close()


def update_finding_status(finding_id, new_status, notes=None, assigned_to=None, verification_status=None):
    """
    Updates the lifecycle status of a finding.
    Enforces valid statuses. If status is 'Resolved', records resolved_at timestamp.
    """
    if new_status not in VALID_FINDING_STATUSES:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {', '.join(VALID_FINDING_STATUSES)}")
    if new_status == "Resolved" and verification_status not in ("VERIFIED", "RESOLVED"):
        raise ValueError("A finding can only be resolved with successful verification.")

    conn = get_connection()
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        resolved_at = now_str if new_status == "Resolved" else None

        cursor = conn.execute("""
            UPDATE security_findings_lifecycle
            SET status = ?,
                notes = COALESCE(?, notes),
                assigned_to = COALESCE(?, assigned_to),
                verification_status = COALESCE(?, verification_status),
                updated_at = ?,
                resolved_at = CASE WHEN ? = 'Resolved' THEN ? ELSE resolved_at END
            WHERE finding_id = ?
        """, (new_status, notes, assigned_to, verification_status, now_str, new_status, resolved_at, finding_id))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"[database] Failed to update finding status: {e}")
        return False
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
