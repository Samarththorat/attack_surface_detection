import unittest
from unittest.mock import patch

from scanner.risk_analyzer import calculate_risk_score


class TestMonitoringRiskIntegration(unittest.TestCase):
    def setUp(self):
        self.lifecycle_patches = [
            patch("database.database.get_finding_lifecycles", return_value=[]),
            patch("database.database.save_finding_lifecycle"),
        ]
        for patcher in self.lifecycle_patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def _scan(events, ports=None):
        return {
            "open_ports": ports or [],
            "services": [],
            "firewall": {"overall_status": "PROTECTED", "profiles": {}},
            "security_checks": [],
            "monitoring_events": events,
        }

    def test_unrepresented_high_event_adds_explainable_score(self):
        event = {
            "id": 101,
            "event_type": "SERVICE_STARTED",
            "severity": "HIGH",
            "component": "service",
            "target": "UnexpectedService",
            "details_parsed": {"process_name": "UnexpectedService"},
            "timestamp": "2026-10-26 12:00:00",
            "is_resolved": 0,
        }

        risk = calculate_risk_score(self._scan([event]))

        self.assertEqual(risk["breakdown"]["monitoring_event_points"], 5)
        finding = next(f for f in risk["unified_findings"] if f["category"] == "Monitoring Event")
        self.assertEqual(finding["target_name"], "UnexpectedService")
        self.assertEqual(finding["priority_code"], "P2")
        self.assertIn("Review the service started evidence", finding["recommended_action"])

    def test_duplicate_events_for_same_target_count_once(self):
        events = [
            {
                "id": event_id,
                "event_type": "SERVICE_STARTED",
                "severity": "HIGH",
                "component": "service",
                "target": "UnexpectedService",
                "is_resolved": 0,
            }
            for event_id in (101, 102)
        ]

        risk = calculate_risk_score(self._scan(events))

        self.assertEqual(risk["breakdown"]["monitoring_event_points"], 5)
        self.assertEqual(
            sum(f["category"] == "Monitoring Event" for f in risk["unified_findings"]),
            1,
        )

    def test_current_port_finding_prevents_duplicate_event_score(self):
        event = {
            "id": 103,
            "event_type": "PORT_OPENED",
            "severity": "HIGH",
            "component": "port",
            "target": "5900/TCP",
            "is_resolved": 0,
        }
        port = {
            "port": 5900,
            "protocol": "TCP",
            "local_address": "127.0.0.1",
            "risk_level": "MEDIUM",
            "process_name": "TestService",
        }

        risk = calculate_risk_score(self._scan([event], [port]))

        self.assertEqual(risk["breakdown"]["monitoring_event_points"], 0)
        self.assertFalse(any(f["category"] == "Monitoring Event" for f in risk["unified_findings"]))


if __name__ == "__main__":
    unittest.main()
