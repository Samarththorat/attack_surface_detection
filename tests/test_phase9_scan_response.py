"""Regression coverage for the scan API risk response contract."""

import unittest
from unittest.mock import patch

import app as flask_app
from scanner.risk_analyzer import calculate_risk_score


class TestScanResponseContract(unittest.TestCase):
    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def request_scan_with_risk(self, risk):
        results = {"risk": risk, "risk_score": risk}
        with patch.object(flask_app, "run_full_scan", return_value=results), patch.object(
            flask_app, "save_scan", return_value=123
        ):
            return self.client.post("/api/scan")

    def test_valid_breakdown_array_is_returned_canonically(self):
        items = [{"category": "Firewall", "points_awarded": 0}]
        response = self.request_scan_with_risk({"breakdown": items})

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["risk"]["breakdown_items"], items)
        self.assertEqual(data["risk_score"]["breakdown_items"], items)

    def test_legacy_breakdown_object_is_preserved_and_normalized(self):
        items = [{"category": "Firewall", "points_awarded": 0}]
        legacy = {"firewall_points": 0, "items": items}
        response = self.request_scan_with_risk({"breakdown": legacy})

        self.assertEqual(response.status_code, 200)
        risk = response.get_json()["risk"]
        self.assertEqual(risk["breakdown"], legacy)
        self.assertEqual(risk["breakdown_items"], items)

    def test_missing_and_null_breakdown_are_explicitly_reported(self):
        for risk in ({}, {"breakdown": None}):
            with self.subTest(risk=risk):
                response = self.request_scan_with_risk(risk)
                normalized = response.get_json()["risk"]
                self.assertEqual(response.status_code, 200)
                self.assertEqual(normalized["breakdown_items"], [])
                self.assertIn("breakdown_error", normalized)

    def test_unexpected_breakdown_items_type_is_reported(self):
        response = self.request_scan_with_risk({"breakdown_items": {"Firewall": 0}})

        risk = response.get_json()["risk"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(risk["breakdown_items"], [])
        self.assertIn("unexpected format", risk["breakdown_error"])

    def test_scan_exception_returns_a_useful_json_error(self):
        with patch.object(flask_app, "run_full_scan", side_effect=RuntimeError("scanner unavailable")), patch.object(
            flask_app, "save_scan"
        ) as save_scan:
            response = self.client.post("/api/scan")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {"error": "Scan failed: scanner unavailable"})
        save_scan.assert_not_called()

    def test_get_scan_is_not_allowed(self):
        response = self.client.get("/api/scan")

        self.assertEqual(response.status_code, 405)

    def test_scanner_failures_mark_scan_as_partial(self):
        with (
            patch.object(flask_app, "collect_system_info", return_value={"hostname": "test"}),
            patch.object(flask_app, "get_listening_ports", side_effect=OSError("ports unavailable")),
            patch.object(flask_app, "get_running_services", return_value=[]),
            patch.object(flask_app, "get_flagged_services", return_value=[]),
            patch.object(flask_app, "calculate_risk_score", return_value={"total_score": 0, "unified_findings": []}),
            patch.object(flask_app, "generate_recommendations", return_value=[]),
            patch.object(flask_app, "get_monitoring_events", return_value=[]),
        ):
            results = flask_app.run_full_scan(categories=("network",))

        self.assertEqual(results["assessment_status"], "PARTIAL")
        self.assertIn("ports", results["incomplete_sections"])

    def test_empty_scan_has_zero_score_no_findings_and_valid_breakdown(self):
        risk = calculate_risk_score({})

        self.assertEqual(risk["total_score"], 0)
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], "LOW")
        self.assertEqual(risk["risk_level"], "Low")
        self.assertEqual(risk["unified_findings"], [])
        self.assertIsInstance(risk["breakdown_items"], list)

    def test_score_band_and_display_severity_stay_consistent(self):
        bands = (
            (24, "LOW", "Low"),
            (25, "MEDIUM", "Medium"),
            (54, "MEDIUM", "Medium"),
            (55, "HIGH", "High"),
            (79, "HIGH", "High"),
            (80, "CRITICAL", "Critical"),
            (100, "CRITICAL", "Critical"),
        )
        scan = {"firewall": {"overall_status": "NOT PROTECTED"}}

        for score, expected_level, expected_label in bands:
            with self.subTest(score=score):
                risk = calculate_risk_score(
                    scan,
                    weights={"firewall_all_disabled": score},
                )
                self.assertEqual(risk["total_score"], score)
                self.assertEqual(risk["level"], expected_level)
                self.assertEqual(risk["risk_level"], expected_label)
