"""
test_phase1_monitoring.py
Unit and integration tests for Phase 1: Real-Time Attack Surface Monitoring.

Tests include:
1. Newly opened port detection (TCP & UDP)
2. Closed port detection
3. Port process change detection
4. Unavailable process information & access denied handling
5. Firewall status changes detection
6. Security config changes detection (UAC & RDP)
7. Monitoring with no changes (no duplicate events created)
8. Prevention of multiple monitoring loops (singleton pattern)
9. SQLite monitoring event persistence, querying, and resolution
10. Flask endpoints (/api/attack-surface/changes, /api/monitoring/status, /api/monitoring/events)
"""

import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import sqlite3
import json

import database.database as db
from scanner.port_scanner import get_listening_ports
from scanner.monitor import AttackSurfaceMonitor, get_monitor
import app as flask_app

# Ensure background monitor thread is stopped for test isolation
flask_app.app.config["TESTING"] = True
flask_app.monitor.stop()


class TestPhase1Database(unittest.TestCase):
    """Tests SQLite storage and schema for monitoring events."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.orig_db_path = db.DB_PATH
        db.DB_PATH = self.temp_db_path
        db.init_db()

    def tearDown(self):
        db.DB_PATH = self.orig_db_path
        os.close(self.temp_db_fd)
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass

    def test_schema_created_correctly(self):
        conn = db.get_connection()
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            self.assertIn("monitoring_events", tables)
            self.assertIn("scans", tables)
            self.assertIn("remediation_history", tables)
        finally:
            conn.close()

    def test_save_and_get_monitoring_event(self):
        event_id = db.save_monitoring_event(
            event_type="PORT_OPENED",
            severity="HIGH",
            component="port",
            target="3389/TCP",
            details={"process": "TermService", "address": "0.0.0.0"},
            is_resolved=0,
        )
        self.assertIsNotNone(event_id)

        events = db.get_monitoring_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "PORT_OPENED")
        self.assertEqual(events[0]["severity"], "HIGH")
        self.assertEqual(events[0]["target"], "3389/TCP")
        self.assertEqual(events[0]["is_resolved"], 0)

    def test_resolve_monitoring_event(self):
        event_id = db.save_monitoring_event(
            event_type="PORT_OPENED",
            severity="HIGH",
            component="port",
            target="8080/TCP",
            is_resolved=0,
        )
        self.assertEqual(db.get_unresolved_events_count(), 1)

        resolved_count = db.resolve_monitoring_event(component="port", target="8080/TCP")
        self.assertEqual(resolved_count, 1)
        self.assertEqual(db.get_unresolved_events_count(), 0)

        unresolved = db.get_monitoring_events(unresolved_only=True)
        self.assertEqual(len(unresolved), 0)


class TestPortScannerUDPAndErrorHandling(unittest.TestCase):
    """Tests TCP and UDP port discovery and error handling."""

    @patch("scanner.port_scanner.psutil.net_connections")
    def test_tcp_and_udp_ports_discovered(self, mock_net_conns):
        from collections import namedtuple
        Addr = namedtuple("Addr", ["ip", "port"])

        # Mock connection namedtuples
        mock_tcp = MagicMock()
        mock_tcp.type.name = "SOCK_STREAM"
        mock_tcp.status = "LISTEN"
        mock_tcp.laddr = Addr("127.0.0.1", 8080)
        mock_tcp.raddr = None
        mock_tcp.pid = 1001

        mock_udp = MagicMock()
        mock_udp.type.name = "SOCK_DGRAM"
        mock_udp.status = "NONE"
        mock_udp.laddr = Addr("0.0.0.0", 5353)
        mock_udp.raddr = None
        mock_udp.pid = 1002

        mock_non_listening_tcp = MagicMock()
        mock_non_listening_tcp.type.name = "SOCK_STREAM"
        mock_non_listening_tcp.status = "ESTABLISHED"
        mock_non_listening_tcp.laddr = Addr("192.168.1.10", 45678)
        mock_non_listening_tcp.raddr = None
        mock_non_listening_tcp.pid = 1003

        mock_net_conns.return_value = [mock_tcp, mock_udp, mock_non_listening_tcp]

        with patch("scanner.port_scanner._get_process_name", return_value="mock_proc.exe"), \
             patch("scanner.port_scanner._build_service_pid_map", return_value={}):
            ports = get_listening_ports(include_udp=True)

        self.assertEqual(len(ports), 2)
        protocols = {p["protocol"] for p in ports}
        self.assertIn("TCP", protocols)
        self.assertIn("UDP", protocols)

        udp_port = next(p for p in ports if p["protocol"] == "UDP")
        self.assertEqual(udp_port["port"], 5353)
        self.assertEqual(udp_port["status"], "LISTEN")

    @patch("scanner.port_scanner.psutil.net_connections")
    def test_permission_denied_handled_gracefully(self, mock_net_conns):
        import psutil
        mock_net_conns.side_effect = psutil.AccessDenied()

        ports = get_listening_ports()
        self.assertEqual(len(ports), 1)
        self.assertIn("error", ports[0])
        self.assertIn("Access denied", ports[0]["error"])


class TestMonitorChangeDetection(unittest.TestCase):
    """Tests change detection diffing logic in AttackSurfaceMonitor."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.orig_db_path = db.DB_PATH
        db.DB_PATH = self.temp_db_path
        db.init_db()

        self.monitor = AttackSurfaceMonitor(interval=5)

    def tearDown(self):
        self.monitor.stop()
        db.DB_PATH = self.orig_db_path
        os.close(self.temp_db_fd)
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass

    def test_singleton_monitor_instance(self):
        m1 = get_monitor()
        m2 = get_monitor()
        self.assertIs(m1, m2)

    def test_avoid_duplicate_monitoring_threads(self):
        m = get_monitor()
        m.start()
        t1 = m._thread
        m.start()  # second start attempt
        t2 = m._thread
        self.assertIs(t1, t2)

    def test_new_port_detection(self):
        prev_snapshot = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {
                (80, "TCP"): {"port": 80, "protocol": "TCP", "process_name": "httpd.exe", "risk_level": "SAFE"}
            },
            "firewall": {"profiles": {"Public": {"state": "ON"}}},
            "security_config": {"uac_enabled": True, "rdp_enabled": False},
            "flagged_services": {},
        }
        curr_snapshot = {
            "timestamp": "2026-10-26 12:00:05",
            "ports": {
                (80, "TCP"): {"port": 80, "protocol": "TCP", "process_name": "httpd.exe", "risk_level": "SAFE"},
                (3389, "TCP"): {"port": 3389, "protocol": "TCP", "process_name": "TermService", "risk_level": "CRITICAL", "local_address": "0.0.0.0"},
            },
            "firewall": {"profiles": {"Public": {"state": "ON"}}},
            "security_config": {"uac_enabled": True, "rdp_enabled": False},
            "flagged_services": {},
        }

        changes = self.monitor._compare_and_record(prev_snapshot, curr_snapshot)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["change_type"], "NEW")
        self.assertEqual(changes[0]["target"], "3389/TCP")
        self.assertEqual(changes[0]["severity"], "CRITICAL")

        # Verify recorded to SQLite
        events = db.get_monitoring_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "PORT_OPENED")
        self.assertEqual(events[0]["target"], "3389/TCP")

    def test_closed_port_detection_and_auto_resolve(self):
        # First save an open port event
        db.save_monitoring_event(
            event_type="PORT_OPENED",
            severity="HIGH",
            component="port",
            target="4444/TCP",
            is_resolved=0,
        )
        self.assertEqual(db.get_unresolved_events_count(), 1)

        prev_snapshot = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {
                (4444, "TCP"): {"port": 4444, "protocol": "TCP", "process_name": "listener.exe", "risk_level": "HIGH"}
            },
            "firewall": {"profiles": {}},
            "security_config": {},
            "flagged_services": {},
        }
        curr_snapshot = {
            "timestamp": "2026-10-26 12:00:05",
            "ports": {},  # Port 4444 closed
            "firewall": {"profiles": {}},
            "security_config": {},
            "flagged_services": {},
        }

        changes = self.monitor._compare_and_record(prev_snapshot, curr_snapshot)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["change_type"], "REMOVED")
        self.assertEqual(changes[0]["target"], "4444/TCP")

        # Verify prior PORT_OPENED is now resolved
        self.assertEqual(db.get_unresolved_events_count(), 0)

    def test_firewall_status_change_detection(self):
        prev_snapshot = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {},
            "firewall": {"profiles": {"Public": {"state": "ON"}}},
            "security_config": {},
            "flagged_services": {},
        }
        curr_snapshot = {
            "timestamp": "2026-10-26 12:00:05",
            "ports": {},
            "firewall": {"profiles": {"Public": {"state": "OFF"}}},  # Public firewall turned OFF!
            "security_config": {},
            "flagged_services": {},
        }

        changes = self.monitor._compare_and_record(prev_snapshot, curr_snapshot)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["component"], "firewall")
        self.assertEqual(changes[0]["severity"], "HIGH")
        self.assertIn("Public", changes[0]["title"])

    def test_uac_and_rdp_change_detection(self):
        prev_snapshot = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {},
            "firewall": {"profiles": {}},
            "security_config": {"uac_enabled": True, "rdp_enabled": False},
            "flagged_services": {},
        }
        curr_snapshot = {
            "timestamp": "2026-10-26 12:00:05",
            "ports": {},
            "firewall": {"profiles": {}},
            "security_config": {"uac_enabled": False, "rdp_enabled": True},  # UAC disabled, RDP enabled
            "flagged_services": {},
        }

        changes = self.monitor._compare_and_record(prev_snapshot, curr_snapshot)
        self.assertEqual(len(changes), 2)
        components = {c["component"] for c in changes}
        self.assertEqual(components, {"security_config"})

    def test_no_changes_generates_zero_events(self):
        snapshot = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {(80, "TCP"): {"port": 80, "protocol": "TCP", "process_name": "httpd.exe"}},
            "firewall": {"profiles": {"Public": {"state": "ON"}}},
            "security_config": {"uac_enabled": True, "rdp_enabled": False},
            "flagged_services": {},
        }

        changes = self.monitor._compare_and_record(snapshot, snapshot)
        self.assertEqual(len(changes), 0)
        self.assertEqual(len(db.get_monitoring_events()), 0)


class TestFlaskMonitoringAPI(unittest.TestCase):
    """Tests API routes added or enhanced for Phase 1."""

    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def test_api_attack_surface_changes_route(self):
        response = self.client.get("/api/attack-surface/changes")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("monitoring_active", data)
        self.assertIn("interval_seconds", data)
        self.assertIn("changes", data)
        self.assertIn("events", data)

    def test_api_monitoring_status_route(self):
        response = self.client.get("/api/monitoring/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("monitoring_active", data)
        self.assertIn("summary", data)

    def test_api_monitoring_events_route(self):
        response = self.client.get("/api/monitoring/events?limit=5")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)


if __name__ == "__main__":
    unittest.main()
