"""
test_phase2_risk_analysis.py
Comprehensive test suite for Phase 2: Improved Risk Analysis.

Validates:
1. Port Risk Analysis:
   - Safe, Low, Medium, High, Critical, Unknown classifications
   - Binding scope handling (Loopback vs Specific Interface vs All Interfaces)
   - Unknown ports marked for review rather than automatically malicious
   - Missing/incomplete process information handled with uncertainty
2. Risk Analyzer & Scoring:
   - De-duplication (no double-counting of RDP, SMB, DB ports across buckets)
   - Mitigating factors (firewall active mitigates generic exposed port score)
   - Clamping boundaries (always 0 <= score <= 100 even with extreme inputs)
   - Incomplete / empty / malformed scan results resilience
   - Score breakdown and explanation fields
3. Security Findings & Recommendations:
   - Rich finding schema (title, severity, component, evidence, risk_explanation,
     recommended_action, operational_impact, confidence, status)
   - Recommendation deduplication (IPv4 + IPv6 for same port)
   - Priority sorting and operational impact explanations
4. API Compatibility:
   - Existing endpoints preserve response keys while exposing Phase 2 enhancements
"""

import unittest
from unittest.mock import patch, MagicMock
import json

from scanner.port_risk_analyzer import (
    analyze_port_risk,
    get_port_analysis,
    determine_binding_scope,
    BINDING_LOOPBACK,
    BINDING_ALL_INTERFACES,
    BINDING_SPECIFIC,
    PORT_SEV_SAFE,
    PORT_SEV_LOW,
    PORT_SEV_MEDIUM,
    PORT_SEV_HIGH,
    PORT_SEV_CRITICAL,
    PORT_SEV_UNKNOWN
)
from scanner.security_checker import run_security_checks
from scanner.risk_analyzer import calculate_risk_score, RISK_WEIGHTS
from scanner.recommendation_engine import generate_recommendations
import app as flask_app


class TestPortRiskAnalyzer(unittest.TestCase):
    """Tests for Phase 2 Port Risk Analysis classifications and binding scopes."""

    def test_determine_binding_scope(self):
        self.assertEqual(determine_binding_scope("127.0.0.1"), BINDING_LOOPBACK)
        self.assertEqual(determine_binding_scope("::1"), BINDING_LOOPBACK)
        self.assertEqual(determine_binding_scope("0.0.0.0"), BINDING_ALL_INTERFACES)
        self.assertEqual(determine_binding_scope("::"), BINDING_ALL_INTERFACES)
        self.assertEqual(determine_binding_scope("192.168.1.50"), BINDING_SPECIFIC)
        self.assertEqual(determine_binding_scope("10.0.0.2"), BINDING_SPECIFIC)

    def test_rdp_port_all_interfaces_classified_critical(self):
        """Port 3389 bound to 0.0.0.0 without active firewall should be CRITICAL."""
        fw_inactive = {"domain_active": False, "private_active": False, "public_active": False, "any_profile_active": False}
        res = analyze_port_risk(3389, "TCP", "0.0.0.0", "TermService", "svchost.exe", firewall_status=fw_inactive)
        self.assertEqual(res["risk_level"], PORT_SEV_CRITICAL)
        self.assertIn("Remote Desktop", res["risk_explanation"])
        self.assertEqual(res["confidence"], "High")

    def test_firewall_rule_does_not_make_listening_socket_safe(self):
        result = analyze_port_risk(
            3389,
            "TCP",
            "0.0.0.0",
            "TermService",
            "svchost.exe",
            is_asr_blocked=True,
        )

        self.assertNotEqual(result["risk_level"], PORT_SEV_SAFE)
        self.assertEqual(result["firewall_rule_status"], "ACTIVE")
        self.assertEqual(result["socket_status"], "LISTENING")
        self.assertEqual(result["traffic_block_verification"], "NOT_PERFORMED")

    def test_rdp_port_loopback_downgraded_to_medium(self):
        """Port 3389 bound strictly to 127.0.0.1 cannot be reached remotely, so severity is downgraded."""
        res = analyze_port_risk(3389, "TCP", "127.0.0.1", "TermService", "svchost.exe")
        self.assertEqual(res["risk_level"], PORT_SEV_MEDIUM)
        self.assertIn("loopback", res["risk_explanation"].lower())

    def test_rdp_port_on_specific_interface_is_high(self):
        result = analyze_port_risk(
            3389,
            "TCP",
            "192.168.1.50",
            "TermService",
            "svchost.exe",
        )

        self.assertEqual(result["binding_scope"], BINDING_SPECIFIC)
        self.assertEqual(result["risk_level"], PORT_SEV_HIGH)

    def test_smb_port_445_classified_high_or_critical(self):
        """Port 445 (SMB) exposed on 0.0.0.0 is High/Critical given lateral movement risks."""
        res = analyze_port_risk(445, "TCP", "0.0.0.0", "LanmanServer", "System")
        self.assertIn(res["risk_level"], [PORT_SEV_HIGH, PORT_SEV_CRITICAL])
        self.assertIn("SMB", res["risk_explanation"])

    def test_safe_loopback_standard_dev_port(self):
        """A dev port bound strictly to 127.0.0.1 is SAFE."""
        res = analyze_port_risk(3000, "TCP", "127.0.0.1", "node", "node.exe")
        self.assertEqual(res["risk_level"], PORT_SEV_SAFE)

    def test_unknown_port_marked_for_review_not_malicious(self):
        """Unknown ports must NOT be arbitrarily classified as High/Critical."""
        res = analyze_port_risk(49159, "TCP", "0.0.0.0", "custom_daemon", "custom.exe")
        self.assertEqual(res["risk_level"], PORT_SEV_UNKNOWN)
        self.assertIn("Needs Review", res["action_required"])
        self.assertEqual(res["confidence"], "Low")

    def test_missing_process_information_handled_gracefully(self):
        """Missing PID or process name handled with uncertainty noted in explanation."""
        res = analyze_port_risk(8080, "TCP", "0.0.0.0", "", "Unknown (Access Denied / Terminated)")
        self.assertIn(res["risk_level"], [PORT_SEV_MEDIUM, PORT_SEV_UNKNOWN])
        self.assertIn("Process details could not be resolved", res["risk_explanation"])
        self.assertEqual(res["confidence"], "Low")

    def test_udp_discovery_port_classified_low(self):
        """UDP discovery ports like mDNS (5353) or SSDP (1900) should be LOW risk, not CRITICAL."""
        res = analyze_port_risk(5353, "UDP", "0.0.0.0", "mDNS", "chrome.exe")
        self.assertEqual(res["risk_level"], PORT_SEV_LOW)


class TestRiskScoringAndDeduplication(unittest.TestCase):
    """Tests for Phase 2 Risk Scoring formula, de-duplication, and edge cases."""

    def test_empty_or_missing_scan_results_does_not_crash(self):
        """Risk calculation must gracefully handle empty dicts and missing sections."""
        res1 = calculate_risk_score({})
        self.assertEqual(res1["score"], 0)
        self.assertEqual(res1["level"], "LOW")
        self.assertIn("breakdown", res1)

        res2 = calculate_risk_score({"open_ports": None, "security_checks": None, "services": None})
        self.assertEqual(res2["score"], 0)

    def test_score_boundary_clamped_to_100(self):
        """Even with an overwhelming number of critical findings, score must never exceed 100."""
        extreme_ports = [{"port": p, "risk_level": "CRITICAL", "protocol": "TCP", "service": "danger"} for p in range(1000, 1050)]
        extreme_checks = [
            {"severity": "CRITICAL", "title": f"Critical vulnerability {i}", "category": "General"}
            for i in range(20)
        ]
        extreme_services = [
            {"name": f"MaliciousService{i}", "review_flag": "FLAGGED", "risk_level": "CRITICAL"}
            for i in range(20)
        ]

        scan_data = {
            "open_ports": extreme_ports,
            "security_checks": extreme_checks,
            "services": extreme_services,
            "firewall": {"any_profile_active": False, "inbound_default_block": False}
        }
        res = calculate_risk_score(scan_data)
        self.assertLessEqual(res["score"], 100)
        self.assertGreaterEqual(res["score"], 0)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["level"], "CRITICAL")

    def test_deduplication_of_rdp_issue(self):
        """
        Verify RDP is NOT double counted:
        If port 3389 is listening AND RDP registry check is enabled,
        it should be counted in dedicated RDP risk, not duplicate into generic open ports.
        """
        ports = [
            {"port": 3389, "protocol": "TCP", "service": "TermService", "risk_level": "CRITICAL", "local_address": "0.0.0.0:3389"}
        ]
        checks = [
            {
                "title": "Remote Desktop Protocol (RDP) is Enabled",
                "severity": "HIGH",
                "category": "Remote Access",
                "status": "FAIL",
                "evidence": "fDenyTSConnections = 0"
            }
        ]
        scan_data = {
            "open_ports": ports,
            "security_checks": checks,
            "firewall": {"any_profile_active": True, "inbound_default_block": True}
        }

        res = calculate_risk_score(scan_data)
        breakdown = res["breakdown"]
        # Dedicated RDP points should be applied
        self.assertGreater(breakdown["rdp_exposure_points"], 0)
        # Port 3389 should NOT also contribute to exposed_ports_points
        self.assertEqual(breakdown["exposed_ports_points"], 0)

    def test_deduplication_of_smb_issue(self):
        """Port 445 should be scored in smb_exposure_points and excluded from generic exposed_ports_points."""
        ports = [
            {"port": 445, "protocol": "TCP", "service": "LanmanServer", "risk_level": "HIGH", "local_address": "0.0.0.0:445"}
        ]
        scan_data = {
            "open_ports": ports,
            "security_checks": [],
            "firewall": {"any_profile_active": True, "inbound_default_block": True}
        }
        res = calculate_risk_score(scan_data)
        breakdown = res["breakdown"]
        self.assertGreater(breakdown["smb_exposure_points"], 0)
        self.assertEqual(breakdown["exposed_ports_points"], 0)

    def test_firewall_active_acts_as_mitigating_factor(self):
        """Generic exposed ports have their risk score reduced by firewall active mitigation factor."""
        ports = [
            {"port": 8080, "protocol": "TCP", "service": "http-alt", "risk_level": "MEDIUM", "local_address": "0.0.0.0:8080"}
        ]
        # Case A: Firewall is ON
        scan_fw_on = {
            "open_ports": ports,
            "security_checks": [],
            "firewall": {"any_profile_active": True, "inbound_default_block": True}
        }
        res_fw_on = calculate_risk_score(scan_fw_on)

        # Case B: Firewall is OFF
        scan_fw_off = {
            "open_ports": ports,
            "security_checks": [],
            "firewall": {"any_profile_active": False, "inbound_default_block": False}
        }
        res_fw_off = calculate_risk_score(scan_fw_off)

        # With firewall off, the port points should be strictly higher
        self.assertGreater(res_fw_off["breakdown"]["exposed_ports_points"], res_fw_on["breakdown"]["exposed_ports_points"])
        # And mitigating factors list should mention Windows Firewall Active
        self.assertTrue(any("Firewall Active" in m for m in res_fw_on["mitigating_factors"]))


class TestSecurityFindingsAndRecommendations(unittest.TestCase):
    """Tests for Phase 2 Security Findings Schema and Recommendation Generation."""

    def test_security_findings_schema_completeness(self):
        """Findings must contain title, severity, component, evidence, risk_explanation, recommended_action, confidence."""
        findings = run_security_checks()
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        for required_field in ["title", "severity", "component", "evidence", "risk_explanation", "recommended_action", "operational_impact", "confidence", "status"]:
            self.assertIn(required_field, f)

    def test_recommendation_deduplication_for_dual_stack_ports(self):
        """IPv4 and IPv6 bindings of the same port/service should yield one deduplicated recommendation."""
        ports = [
            {"port": 8080, "protocol": "TCP", "local_address": "0.0.0.0:8080", "service": "Tomcat", "risk_level": "MEDIUM", "action_required": "Restrict or bind to localhost"},
            {"port": 8080, "protocol": "TCP", "local_address": "[::]:8080", "service": "Tomcat", "risk_level": "MEDIUM", "action_required": "Restrict or bind to localhost"}
        ]
        scan_data = {"open_ports": ports, "security_checks": [], "services": []}
        recs = generate_recommendations(scan_data)
        
        port_8080_recs = [r for r in recs if "8080" in r.get("recommendation", "") or "8080" in r.get("evidence", "")]
        self.assertEqual(len(port_8080_recs), 1)

    def test_recommendations_have_priorities_and_impact(self):
        """Recommendations must have priority 1-5, operational_impact, and actionable flag."""
        scan_data = {
            "open_ports": [
                {"port": 3389, "protocol": "TCP", "local_address": "0.0.0.0:3389", "service": "TermService", "risk_level": "CRITICAL", "action_required": "Disable or restrict RDP access"}
            ],
            "security_checks": [
                {
                    "title": "User Account Control (UAC) is Disabled",
                    "severity": "CRITICAL",
                    "component": "UAC",
                    "evidence": "EnableLUA = 0",
                    "risk_explanation": "Processes can elevate silently.",
                    "recommended_action": "Enable UAC via registry or Control Panel.",
                    "operational_impact": "Users will see consent prompts when launching administrative apps.",
                    "confidence": "High",
                    "status": "FAIL"
                }
            ],
            "services": []
        }
        recs = generate_recommendations(scan_data)
        self.assertGreaterEqual(len(recs), 1)
        for r in recs:
            self.assertIn("priority", r)
            self.assertIn("operational_impact", r)
            self.assertIn("is_actionable", r)
            self.assertIn(r["priority"], [1, 2, 3, 4, 5])


class TestPhase2APICompatibility(unittest.TestCase):
    """Verifies existing API endpoints return enriched Phase 2 data without breaking contracts."""

    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def test_api_scan_returns_phase2_fields(self):
        """The /api/scan response must include Phase 2 score breakdowns and distribution."""
        response = self.client.post("/api/scan")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        # Baseline legacy compatibility checks
        self.assertIn("risk_score", data)
        self.assertIn("open_ports", data)
        self.assertIn("security_checks", data)
        self.assertIn("recommendations", data)

        # Phase 2 enrichment checks
        risk_score_obj = data["risk_score"]
        self.assertIn("breakdown", risk_score_obj)
        self.assertIn("severity_distribution", risk_score_obj)
        self.assertIn("top_findings", risk_score_obj)
        self.assertIn("mitigating_factors", risk_score_obj)
        self.assertIn("assessment_label", risk_score_obj)

    def test_api_port_analysis_includes_scope_and_explanation(self):
        """The /api/port-analysis response must include binding_scope and risk_explanation."""
        response = self.client.get("/api/port-analysis")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        ports_list = data.get("ports", data) if isinstance(data, dict) else data
        self.assertIsInstance(ports_list, list)
        if ports_list:
            p = ports_list[0]
            self.assertIn("binding_scope", p)
            self.assertIn("risk_explanation", p)
            self.assertIn("confidence", p)
            self.assertIn("operational_impact", p)


if __name__ == "__main__":
    unittest.main()
