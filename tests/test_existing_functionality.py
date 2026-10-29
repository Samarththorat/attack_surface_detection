"""
test_existing_functionality.py
Regression test suite ensuring existing features, scanner modules,
API endpoints, database tables, and scan histories continue to work
without regressions.
"""

import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import json

import database.database as db
import app as flask_app
from scanner.system_info import collect_system_info
from scanner.port_scanner import get_listening_ports
from scanner.service_scanner import get_running_services, get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import run_security_checks
from scanner.risk_analyzer import calculate_risk_score
from scanner.recommendation_engine import generate_recommendations
from scanner.port_risk_analyzer import get_port_analysis
from scanner.attack_surface import get_attack_surface_inventory


class TestExistingScanners(unittest.TestCase):
    """Verifies that all baseline scanner modules continue to function and return valid structures."""

    def test_collect_system_info(self):
        info = collect_system_info()
        self.assertIn("hostname", info)
        self.assertIn("os", info)
        self.assertIn("cpu", info)
        self.assertIn("ram", info)
        self.assertIn("scan_time", info)

    def test_get_listening_ports(self):
        ports = get_listening_ports()
        self.assertIsInstance(ports, list)
        if ports and "error" not in ports[0]:
            p = ports[0]
            self.assertIn("port", p)
            self.assertIn("protocol", p)
            self.assertIn("local_address", p)
            self.assertIn("status", p)

    def test_get_running_services(self):
        services = get_running_services()
        self.assertIsInstance(services, list)
        if services:
            s = services[0]
            self.assertIn("pid", s)
            self.assertIn("name", s)
            self.assertIn("status", s)
            self.assertIn("listening_ports", s)
            self.assertIn("review_flag", s)

    def test_get_firewall_status(self):
        fw = get_firewall_status()
        self.assertIn("profiles", fw)
        self.assertIn("overall_status", fw)

    def test_run_security_checks(self):
        findings = run_security_checks()
        self.assertIsInstance(findings, list)
        for f in findings:
            self.assertIn("category", f)
            self.assertIn("area", f)
            self.assertIn("detail", f)

    def test_calculate_risk_score(self):
        risk = calculate_risk_score()
        self.assertIn("total_score", risk)
        self.assertIn("risk_level", risk)
        self.assertIn("breakdown", risk)
        self.assertTrue(0 <= risk["total_score"] <= 100)
        self.assertIn(risk["risk_level"], ["Low", "Medium", "High", "Critical"])

    def test_generate_recommendations(self):
        recs = generate_recommendations()
        self.assertIsInstance(recs, list)
        for r in recs:
            self.assertIn("finding", r)
            self.assertIn("risk", r)
            self.assertIn("reason", r)
            self.assertIn("recommended_action", r)

    def test_get_port_analysis(self):
        analysis = get_port_analysis()
        self.assertIn("ports", analysis)
        self.assertIn("summary", analysis)
        self.assertIn("total", analysis)

    def test_get_attack_surface_inventory(self):
        inventory = get_attack_surface_inventory()
        self.assertIn("generated_at", inventory)
        self.assertIn("network_interfaces", inventory)
        self.assertIn("listening_ports", inventory)
        self.assertIn("running_services", inventory)
        self.assertIn("firewall", inventory)
        self.assertIn("security_configuration", inventory)


class TestExistingApiEndpoints(unittest.TestCase):
    """Verifies that existing Flask API endpoints respond correctly."""

    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def test_index_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)

    def test_dashboard_page(self):
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)

    def test_port_hardening_page(self):
        res = self.client.get("/port-hardening")
        self.assertEqual(res.status_code, 200)

    def test_attack_surface_page(self):
        res = self.client.get("/attack-surface")
        self.assertEqual(res.status_code, 200)

    def test_api_history(self):
        res = self.client.get("/api/history?limit=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)

    def test_api_ports(self):
        res = self.client.get("/api/ports")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)

    def test_api_port_analysis(self):
        res = self.client.get("/api/port-analysis")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("ports", data)
        self.assertIn("summary", data)

    def test_api_attack_surface(self):
        res = self.client.get("/api/attack-surface")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("generated_at", data)


if __name__ == "__main__":
    unittest.main()
