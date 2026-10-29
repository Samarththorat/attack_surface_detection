import os
import tempfile
import unittest
from unittest.mock import patch

import app as flask_app
import database.database as db


class TestSimplifiedDashboardPages(unittest.TestCase):
    def setUp(self):
        descriptor, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(descriptor)
        self.db_path_patch = patch.object(db, "DB_PATH", self.db_path)
        self.db_path_patch.start()
        db.init_db()
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def tearDown(self):
        self.db_path_patch.stop()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_primary_pages_render_with_shared_dashboard_navigation(self):
        for path in (
            "/dashboard", "/attack-surface", "/port-hardening",
            "/task-monitoring", "/vulnerabilities", "/analytics", "/reports", "/activity",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)

        dashboard = self.client.get("/dashboard").get_data(as_text=True)
        for destination in (
            'href="/dashboard"',
            'href="/attack-surface"',
            'href="/port-hardening"',
            'href="/task-monitoring"',
            'href="/vulnerabilities"',
            'href="/analytics"',
            'href="/reports"',
        ):
            self.assertIn(destination, dashboard)
        self.assertIn("What Needs Attention?", dashboard)
        self.assertIn('href="/port-hardening"', dashboard)
        self.assertIn(">Listening Ports<", dashboard)
        self.assertNotIn(">Exposed Ports<", dashboard)
        self.assertRegex(
            dashboard,
            r'<a class="summary-card" href="/port-hardening">\s*<span class="summary-label">Listening Ports</span>',
        )
        self.assertIn("Review exposure in Port Hardening", dashboard)
        self.assertIn("dashboard-recent-activity-body", dashboard)
        self.assertIn('href="/activity">View All Activity</a>', dashboard)
        self.assertEqual(dashboard.count("<canvas"), 2)
        self.assertLess(dashboard.index("What Needs Attention?"), dashboard.index("Risk Distribution by Severity"))
        self.assertLess(dashboard.index("Risk Distribution by Severity"), dashboard.index("Historical Risk Trend"))
        self.assertLess(dashboard.index("Historical Risk Trend"), dashboard.index("Recent Activity"))
        self.assertNotIn('id="ports-table"', dashboard)
        self.assertNotIn('id="dashboard-remediation-table"', dashboard)
        self.assertNotIn('id="riskChart"', dashboard)
        self.assertNotIn('id="live-alert-container"', dashboard)
        self.assertIn('id="schedule-form"', dashboard)
        self.assertIn('id="recommendations-table"', dashboard)
        self.assertNotIn("analytics-category-chart", dashboard)

        analytics = self.client.get("/analytics").get_data(as_text=True)
        self.assertIn('id="assessment-history-body"', analytics)
        self.assertIn('id="compare-btn"', analytics)
        self.assertIn('id="analytics-risk-breakdown-chart"', analytics)

    def test_task_monitoring_page_and_routes_use_read_only_telemetry(self):
        response = self.client.get("/task-monitoring")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        for element_id in (
            "task-cpu", "task-memory", "task-disk-capacity", "task-disk-io",
            "task-network", "task-gpu", "task-process-count",
            "task-process-search", "task-process-sort", "task-process-body",
        ):
            self.assertIn(f'id="{element_id}"', html)
        self.assertIn("Read-only snapshot", html)
        self.assertNotIn("Terminate process", html)

        payload = {
            "sampled_at": "2026-10-29T00:00:00+00:00",
            "cpu_usage_percent": 20.0,
            "processes": [],
            "running_processes": 0,
        }
        with patch.object(flask_app.task_monitoring_collector, "collect", return_value=payload):
            snapshot = self.client.get("/api/task-monitoring/snapshot")
        self.assertEqual(snapshot.status_code, 200)
        self.assertEqual(snapshot.get_json()["cpu_usage_percent"], 20.0)

        self.assertEqual(self.client.get("/api/task-monitoring/history?hours=1").status_code, 200)
        self.assertEqual(self.client.get("/api/task-monitoring/history?hours=169").status_code, 400)

    def test_explicit_port_remediation_synchronizes_distinct_event_and_saved_assessment(self):
        result = {
            "action_applied": True,
            "success": True,
            "verified": True,
            "firewall_state": "BLOCKED",
            "socket_state": "LISTENING",
            "verification_status": "PARTIALLY_RESOLVED",
            "audit_record_id": 17,
            "target": "3389/TCP",
        }
        with (
            patch.object(flask_app, "save_monitoring_event", return_value=31) as save_event,
            patch.object(flask_app, "run_full_scan", return_value={"assessment_status": "COMPLETE"}),
            patch.object(flask_app, "save_scan", return_value=42),
            patch.object(flask_app, "link_remediation_verification_scan", return_value=True) as link_scan,
            patch.object(flask_app.monitor, "publish_event") as publish,
        ):
            flask_app._synchronize_after_remediation("BLOCK_PORT", result, 3389, "TCP")

        self.assertEqual(result["assessment_refresh"], {"status": "COMPLETE", "scan_id": 42})
        self.assertTrue(result["assessment_scan_linked"])
        link_scan.assert_called_once_with(17, 42)
        self.assertEqual(result["firewall_event_id"], 31)
        save_event.assert_called_once()
        self.assertEqual(save_event.call_args.kwargs["event_type"], "FIREWALL_RULE_CHANGED")
        self.assertEqual(save_event.call_args.kwargs["details"]["socket_state"], "LISTENING")
        publish.assert_called_once()
        self.assertEqual(publish.call_args.args[0]["type"], "remediation")

    def test_unverified_remediation_is_not_recorded_as_a_verified_firewall_change(self):
        result = {
            "action_applied": True,
            "success": False,
            "verified": False,
            "firewall_state": "BLOCKED",
            "verification_status": "INCONCLUSIVE",
            "target": "3389/TCP",
        }
        with (
            patch.object(flask_app, "save_monitoring_event") as save_event,
            patch.object(flask_app, "run_full_scan", return_value={"assessment_status": "PARTIAL"}),
            patch.object(flask_app, "save_scan", return_value=43),
            patch.object(flask_app.monitor, "publish_event") as publish,
        ):
            flask_app._synchronize_after_remediation("BLOCK_PORT", result, 3389, "TCP")

        save_event.assert_not_called()
        self.assertEqual(result["assessment_refresh"]["scan_id"], 43)
        publish.assert_called_once()

    def test_verified_service_remediation_uses_a_distinct_monitoring_event(self):
        result = {
            "action_applied": True,
            "verified": True,
            "success": True,
            "target": "ExampleService",
            "previous_state": "running",
            "new_state": "disabled",
            "verification_status": "RESOLVED",
        }
        with (
            patch.object(flask_app, "save_monitoring_event", return_value=51) as save_event,
            patch.object(flask_app, "run_full_scan", return_value={"assessment_status": "COMPLETE"}),
            patch.object(flask_app, "save_scan", return_value=52),
            patch.object(flask_app.monitor, "publish_event"),
        ):
            flask_app._synchronize_after_remediation("DISABLE_SERVICE", result)

        self.assertEqual(save_event.call_args.kwargs["event_type"], "SERVICE_REMEDIATION_VERIFIED")
        self.assertEqual(save_event.call_args.kwargs["component"], "service")
        self.assertEqual(result["service_event_id"], 51)

    def test_port_hardening_content_and_error_recovery_controls_render(self):
        response = self.client.get("/port-hardening")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('<main id="ph-content">', html)
        self.assertNotIn('<main id="ph-content" class="hidden">', html)
        self.assertIn('id="risk-summary-grid"', html)
        self.assertIn('id="search-input"', html)
        self.assertIn('id="risk-filter"', html)
        self.assertIn('id="protocol-filter"', html)
        self.assertIn('id="exposure-filter"', html)
        self.assertIn('id="ports-table"', html)
        self.assertIn('id="remediation-table"', html)
        self.assertIn('id="retry-btn"', html)
        self.assertIn("Read-only port monitoring remains available.", html)

    def test_monitoring_event_api_supports_filtered_offset_pagination(self):
        db.save_monitoring_event("PORT_OPENED", "HIGH", "port", "443", {"evidence": "first"})
        db.save_monitoring_event("FIREWALL_CHANGED", "LOW", "firewall", "private", {"evidence": "second"})
        db.save_monitoring_event("PORT_CLOSED", "HIGH", "port", "8443", {"evidence": "third"}, is_resolved=1)

        first_page = self.client.get("/api/monitoring/events?limit=1")
        second_page = self.client.get("/api/monitoring/events?limit=1&offset=1")
        high_events = self.client.get("/api/monitoring/events?limit=10&severity=HIGH")
        unresolved = self.client.get("/api/monitoring/events?limit=10&unresolved=1")
        invalid_offset = self.client.get("/api/monitoring/events?offset=-1")

        self.assertEqual(first_page.status_code, 200)
        self.assertEqual(second_page.status_code, 200)
        self.assertEqual(first_page.get_json()[0]["target"], "8443")
        self.assertEqual(second_page.get_json()[0]["target"], "private")
        self.assertEqual([event["severity"] for event in high_events.get_json()], ["HIGH", "HIGH"])
        self.assertEqual(len(unresolved.get_json()), 2)
        self.assertEqual(invalid_offset.status_code, 400)
        self.assertEqual(len(db.get_monitoring_events(limit=10)), 3)


if __name__ == "__main__":
    unittest.main()
