import unittest
import os
import tempfile
import datetime
from unittest.mock import MagicMock, patch

import app as flask_app
from app import app
import database.database as db
from scanner.monitor import AttackSurfaceMonitor


class TestMonitoringReliability(unittest.TestCase):
    def test_incomplete_samples_do_not_emit_close_events(self):
        monitor = AttackSurfaceMonitor(interval=5)
        previous = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {(8080, "TCP"): {"process_name": "TestService"}},
            "flagged_services": {"testservice": {"name": "TestService"}},
            "firewall": {"profiles": {}},
            "security_config": {},
            "availability": {"ports": True, "flagged_services": True, "firewall": True},
        }
        current = {
            "timestamp": "2026-10-26 12:00:05",
            "ports": {},
            "flagged_services": {},
            "firewall": {"profiles": {}},
            "security_config": {},
            "availability": {"ports": False, "flagged_services": False, "firewall": True},
        }
        with (
            patch("scanner.monitor.save_monitoring_event") as save_event,
            patch("scanner.monitor.resolve_monitoring_event") as resolve_event,
        ):
            changes = monitor._compare_and_record(previous, current)

        self.assertEqual(changes, [])
        save_event.assert_not_called()
        resolve_event.assert_not_called()

    def test_collection_failure_marks_sample_unavailable(self):
        monitor = AttackSurfaceMonitor(interval=5)
        with (
            patch("scanner.monitor.get_listening_ports", side_effect=OSError("unavailable")),
            patch("scanner.monitor.get_firewall_status", return_value={"profiles": {}}),
            patch("scanner.monitor._check_uac_enabled", return_value=None),
            patch("scanner.monitor._check_rdp_enabled", return_value=None),
            patch("scanner.monitor._check_windows_update_service", return_value=None),
            patch("scanner.monitor.get_flagged_services", side_effect=OSError("unavailable")),
        ):
            snapshot = monitor._collect_snapshot()

        self.assertFalse(snapshot["availability"]["ports"])
        self.assertFalse(snapshot["availability"]["flagged_services"])

    def test_monitor_health_marks_degraded_and_does_not_advance_success_time(self):
        monitor = AttackSurfaceMonitor(interval=5)
        monitor._is_running = True
        monitor._thread = MagicMock()
        monitor._thread.is_alive.return_value = True
        monitor.current_snapshot = {
            "ports": {},
            "firewall": {"overall_status": "ON"},
            "security_config": {},
            "availability": {"ports": False, "firewall": True, "flagged_services": True},
        }
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        monitor.last_check_time = current_time
        monitor.last_successful_check_time = current_time

        status = monitor.get_status()

        self.assertEqual(status["monitoring_health"], "DEGRADED")
        self.assertEqual(status["last_successful_check_time"], current_time)

    def test_monitor_health_marks_old_check_stale(self):
        monitor = AttackSurfaceMonitor(interval=5)
        monitor._is_running = True
        monitor._thread = MagicMock()
        monitor._thread.is_alive.return_value = True
        old_time = (datetime.datetime.now() - datetime.timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
        monitor.current_snapshot = {
            "ports": {},
            "firewall": {"overall_status": "ON"},
            "security_config": {},
            "availability": {"ports": True, "firewall": True, "flagged_services": True},
        }
        monitor.last_check_time = old_time
        monitor.last_successful_check_time = old_time

        self.assertEqual(monitor.get_status()["monitoring_health"], "STALE")

    def test_monitor_health_recovers_after_complete_sample(self):
        monitor = AttackSurfaceMonitor(interval=5)
        monitor._is_running = True
        monitor._thread = MagicMock()
        monitor._thread.is_alive.return_value = True
        monitor.current_snapshot = {
            "ports": {},
            "firewall": {"overall_status": "ON"},
            "security_config": {},
            "availability": {"ports": False, "firewall": True, "flagged_services": True},
        }
        monitor.last_check_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(monitor.get_status()["monitoring_health"], "DEGRADED")

        monitor.current_snapshot["availability"]["ports"] = True
        self.assertEqual(monitor.get_status()["monitoring_health"], "HEALTHY")

    def test_review_action_persists_reviewed_event_state(self):
        event_id = db.save_monitoring_event(
            "PORT_OPENED", "HIGH", "port", "9443/TCP",
        )
        app.config["TESTING"] = True
        response = app.test_client().post(f"/api/monitoring/events/{event_id}/review")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["reviewed"])
        events = db.get_monitoring_events(limit=20)
        reviewed = next(event for event in events if event["id"] == event_id)
        self.assertTrue(reviewed["is_reviewed"])

    def test_windows_update_status_change_generates_alert(self):
        monitor = AttackSurfaceMonitor(interval=5)
        previous = {
            "timestamp": "2026-10-26 12:00:00",
            "ports": {},
            "firewall": {"profiles": {}},
            "security_config": {"windows_update_status": "Running"},
            "flagged_services": {},
        }
        current = {
            "timestamp": "2026-10-26 12:00:05",
            "ports": {},
            "firewall": {"profiles": {}},
            "security_config": {"windows_update_status": "Stopped"},
            "flagged_services": {},
        }
        with patch("scanner.monitor.save_monitoring_event", return_value=8) as save_event:
            changes = monitor._compare_and_record(previous, current)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["target"], "Windows Update Service")
        self.assertEqual(changes[0]["severity"], "HIGH")
        save_event.assert_called_once()

    def test_status_endpoint_counts_all_active_events(self):
        app.config["TESTING"] = True
        client = app.test_client()
        monitor = MagicMock()
        monitor.get_status.return_value = {"monitoring_active": True}
        recent_events = [{"id": 1, "severity": "HIGH"}]
        with (
            patch("app.get_monitor", return_value=monitor),
            patch("app.get_scheduled_assessment_config", return_value={"enabled": False}),
            patch("app.get_monitoring_events", return_value=recent_events),
            patch("app.get_monitoring_event_severity_counts", return_value={"HIGH": 34}),
        ):
            response = client.get("/api/monitoring/status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["alert_counts_by_severity"]["HIGH"], 34)
        self.assertEqual(len(response.json["recent_alerts"]), 1)

    def test_alert_cooldown_and_severity_counts_use_stored_state(self):
        flask_app.monitor.stop()
        monitor_thread = flask_app.monitor._thread
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=10)
        self.assertFalse(monitor_thread and monitor_thread.is_alive())

        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        with patch.object(db, "DB_PATH", path):
            try:
                db.init_db()
                first_id = db.save_monitoring_event(
                    "PORT_PROCESS_CHANGED", "MEDIUM", "port", "8080/TCP",
                    cooldown_seconds=300,
                )
                suppressed_id = db.save_monitoring_event(
                    "PORT_PROCESS_CHANGED", "MEDIUM", "port", "8080/TCP",
                    cooldown_seconds=300,
                )
                db.save_monitoring_event("PORT_OPENED", "HIGH", "port", "443/TCP")
                db.save_monitoring_event(
                    "PORT_CLOSED", "INFO", "port", "443/TCP", is_resolved=1
                )

                self.assertIsNotNone(first_id)
                self.assertIsNone(suppressed_id)
                self.assertEqual(
                    db.get_monitoring_event_severity_counts(),
                    {"HIGH": 1, "MEDIUM": 1},
                )
            finally:
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
