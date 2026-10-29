"""
test_phase3_remediation.py
Comprehensive test suite for Phase 3: Safe Remediation & Verification.

Covers all 18 required scenarios:
1. Invalid port numbers
2. Invalid protocols
3. Duplicate firewall-rule prevention
4. Firewall-rule creation failure
5. Firewall-rule removal restrictions
6. Missing administrator privileges
7. Protected Windows services
8. Invalid service names
9. Service-stop failure
10. Service-disable confirmation requirements
11. Successful mocked remediation
12. Failed verification
13. Inconclusive verification
14. Before-and-after risk calculations
15. Preservation of remediation history
16. Existing real-time monitoring compatibility
17. Existing risk analysis compatibility
18. Existing scan and dashboard APIs
"""

import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import sqlite3

import app as flask_app
import database.database as db
from scanner.port_hardening import (
    validate_port, validate_protocol, is_valid_service_name,
    is_protected_service, is_admin_user, is_port_blocked,
    block_port, unblock_port, stop_service, disable_service,
    get_service_info, get_service_remediation_metadata,
    execute_remediation_with_verification, PROTECTED_SERVICES,
    FIREWALL_RULE_PREFIX, _check_listening_socket,
)
from scanner.risk_analyzer import calculate_risk_score
from scanner.monitor import get_monitor


class TestPhase3PortRemediation(unittest.TestCase):
    """Tests 1 through 6: Port validation, rules, privileges, and duplicate prevention."""

    def test_invalid_port_numbers(self):
        """1. Invalid port numbers (<1, >65535, negative, non-numeric)."""
        invalid_ports = [0, -1, 65536, 70000, "abc", "", None, [80], -8080]
        for p in invalid_ports:
            valid, port_int, err = validate_port(p)
            self.assertFalse(valid, f"Port {p} should be invalid")
            self.assertIsNone(port_int)
            self.assertIsNotNone(err)

            res = block_port(p, "TCP", confirm=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "UNRESOLVED")

    def test_invalid_protocols(self):
        """2. Invalid protocols (ICMP, invalid strings, numbers, None)."""
        invalid_protos = ["ICMP", "HTTP", "FTP", "", None, 123, "TCP/UDP"]
        for proto in invalid_protos:
            valid, proto_upper, err = validate_protocol(proto)
            self.assertFalse(valid, f"Protocol {proto} should be invalid")
            self.assertIsNone(proto_upper)
            self.assertIsNotNone(err)

            res = block_port(8080, proto, confirm=True)
            self.assertFalse(res["success"])
            self.assertEqual(res["verification_status"], "UNRESOLVED")

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.is_port_blocked")
    @patch("scanner.port_hardening._run_netsh")
    def test_duplicate_firewall_rule_prevention(self, mock_netsh, mock_is_blocked, mock_admin):
        """3. Duplicate firewall-rule prevention."""
        # Port is already blocked
        mock_is_blocked.return_value = {"blocked": True, "rule_name": "ASR_Block_TCP_3389"}

        res = block_port(3389, "TCP", confirm=True)
        # Should not call netsh to add a duplicate rule
        mock_netsh.assert_not_called()
        self.assertTrue(res["success"])
        self.assertTrue(res["verified"])
        self.assertFalse(res["action_applied"])  # Already present
        self.assertIn("already blocked", res["message"])

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.is_port_blocked", return_value={"blocked": False})
    @patch("scanner.port_hardening._run_netsh", return_value=(False, "The parameter is incorrect.", None))
    def test_firewall_rule_creation_failure(self, mock_netsh, mock_is_blocked, mock_admin):
        """4. Firewall-rule creation failure handled safely."""
        res = block_port(8080, "TCP", confirm=True)
        self.assertFalse(res["success"])
        self.assertFalse(res["verified"])
        self.assertEqual(res["verification_status"], "UNRESOLVED")
        self.assertIn("firewall rejected", res["message"].lower())

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.is_port_blocked", return_value={"blocked": False})
    @patch("scanner.port_hardening._run_netsh", return_value=(True, "Ok.", None))
    def test_firewall_rule_removal_restrictions(self, mock_netsh, mock_is_blocked, mock_admin):
        """5. Firewall-rule removal restricted to application-managed ASR rules only."""
        # Unblocking port constructs rule ASR_Block_TCP_445
        res = unblock_port(445, "TCP", confirm=True)
        self.assertTrue(res["success"])
        self.assertTrue(res["rule_name"].startswith(FIREWALL_RULE_PREFIX))

        # Direct verification that the rule name check refuses non-ASR prefixes
        with patch("scanner.port_hardening._rule_name", return_value="Core_Networking_Rule"):
            res_bad = unblock_port(445, "TCP", confirm=True)
            self.assertFalse(res_bad["success"])
            self.assertEqual(res_bad["error"], "unauthorized_rule_removal")
            self.assertEqual(res_bad["verification_status"], "UNRESOLVED")

    @patch("scanner.port_hardening.is_admin_user", return_value=False)
    def test_missing_administrator_privileges(self, mock_admin):
        """6. Missing administrator privileges safely refuses execution."""
        res_block = block_port(3389, "TCP", confirm=True)
        self.assertFalse(res_block["success"])
        self.assertEqual(res_block["error"], "elevation_required")
        self.assertEqual(res_block["verification_status"], "UNRESOLVED")

        res_unblock = unblock_port(3389, "TCP", confirm=True)
        self.assertFalse(res_unblock["success"])
        self.assertEqual(res_unblock["error"], "elevation_required")

        res_service = stop_service("TermService", confirm=True)
        self.assertFalse(res_service["success"])
        self.assertEqual(res_service["error"], "elevation_required")


class TestPhase3ServiceRemediation(unittest.TestCase):
    """Tests 7 through 10: Service validation, protections, failures, and confirmation."""

    def test_protected_windows_services(self):
        """7. Protected Windows services (rpcss, mpssvc, bfe, etc.) cannot be stopped or disabled."""
        protected_sample = ["rpcss", "mpssvc", "bfe", "cryptsvc", "samss"]
        for svc in protected_sample:
            is_prot, reason = is_protected_service(svc)
            self.assertTrue(is_prot, f"Service {svc} must be protected")
            self.assertIsNotNone(reason)

            # Attempt stop
            with patch("scanner.port_hardening.get_service_info", return_value={"name": svc, "status": "running"}):
                res_stop = stop_service(svc, confirm=True, check_privileges=False)
                self.assertFalse(res_stop["success"])
                self.assertEqual(res_stop["error"], "protected_service")

                # Attempt disable
                res_dis = disable_service(svc, confirm=True, confirm_disable=True, check_privileges=False)
                self.assertFalse(res_dis["success"])
                self.assertEqual(res_dis["error"], "protected_service")

    def test_invalid_service_names(self):
        """8. Invalid service names (injection strings, shell metacharacters, empty names) rejected."""
        invalid_names = [
            "svc; calc.exe",
            "svc & whoami",
            "svc | net user",
            "../svc",
            "svc\x00malicious",
            "",
            None,
            "   ",
        ]
        for name in invalid_names:
            self.assertFalse(is_valid_service_name(name), f"Name '{name}' should be rejected")
            res = stop_service(name, confirm=True)
            self.assertFalse(res["success"])

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.get_service_info")
    @patch("scanner.port_hardening._run_sc", return_value=(False, "[SC] ControlService FAILED 1062"))
    def test_service_stop_failure(self, mock_sc, mock_info, mock_admin):
        """9. Service-stop command failure handled gracefully."""
        mock_info.return_value = {"name": "TestService", "status": "running"}
        res = stop_service("TestService", confirm=True)
        self.assertFalse(res["success"])
        self.assertFalse(res["verified"])
        self.assertEqual(res["verification_status"], "UNRESOLVED")

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.get_service_info")
    def test_service_disable_confirmation_requirements(self, mock_info, mock_admin):
        """10. Service-disable confirmation requirements (confirm_disable=True required)."""
        mock_info.return_value = {"name": "TermService", "status": "running", "start_type": "auto"}

        # Attempt with confirm=True but missing confirm_disable
        res = disable_service("TermService", confirm=True, confirm_disable=False)
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "disable_confirmation_required")
        self.assertEqual(res["verification_status"], "UNRESOLVED")

        # Attempt with confirm=False
        res_no_confirm = disable_service("TermService", confirm=False, confirm_disable=True)
        self.assertFalse(res_no_confirm["success"])
        self.assertEqual(res_no_confirm["error"], "confirmation_required")


class TestPhase3VerificationWorkflow(unittest.TestCase):
    """Tests 11 through 15: Mocked remediation, verification logic, risk deltas, and DB preservation."""

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.is_port_blocked")
    @patch("scanner.port_hardening._check_listening_socket")
    @patch("scanner.port_hardening._run_netsh")
    def test_successful_mocked_remediation(self, mock_netsh, mock_sock, mock_is_blocked, mock_admin):
        """11. Successful mocked remediation independently verified."""
        mock_is_blocked.side_effect = [
            {"blocked": False},  # Pre-check: not blocked
            {"blocked": True, "rule_name": "ASR_Block_TCP_3389"},  # Verification: blocked
        ]
        mock_netsh.return_value = (True, "Ok.", None)
        mock_sock.return_value = {"listening": True, "process_name": "svchost.exe"}

        res = block_port(3389, "TCP", confirm=True)
        self.assertTrue(res["success"])
        self.assertTrue(res["verified"])
        self.assertTrue(res["action_applied"])
        # Listening locally while traffic blocked by firewall -> PARTIALLY_RESOLVED
        self.assertEqual(res["verification_status"], "PARTIALLY_RESOLVED")
        self.assertEqual(res["socket_state"], "LISTENING")
        self.assertEqual(res["firewall_state"], "BLOCKED")

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.is_port_blocked")
    @patch("scanner.port_hardening._run_netsh")
    def test_failed_verification(self, mock_netsh, mock_is_blocked, mock_admin):
        """12. Failed verification: command returned 0, but independent check failed."""
        mock_netsh.return_value = (True, "Ok.", None)
        # Verification check finds rule does NOT exist
        mock_is_blocked.side_effect = [
            {"blocked": False},  # Pre-check
            {"blocked": False},  # Post-action verification fails
        ]

        res = block_port(8080, "TCP", confirm=True)
        self.assertFalse(res["success"])
        self.assertFalse(res["verified"])
        self.assertEqual(res["verification_status"], "UNRESOLVED")
        self.assertEqual(res["error"], "verification_failed")

    @patch("scanner.port_hardening.is_admin_user", return_value=True)
    @patch("scanner.port_hardening.is_port_blocked")
    @patch("scanner.port_hardening._run_netsh")
    def test_inconclusive_verification(self, mock_netsh, mock_is_blocked, mock_admin):
        """13. Inconclusive verification handled with explicit message."""
        mock_netsh.return_value = (True, "Ok.", None)
        # Verification check times out or errors
        mock_is_blocked.side_effect = [
            {"blocked": False},  # Pre-check
            {"blocked": False, "error": "The firewall command timed out."},
        ]

        res = block_port(8080, "TCP", confirm=True)
        self.assertFalse(res["success"])
        self.assertFalse(res["verified"])
        self.assertEqual(res["verification_status"], "INCONCLUSIVE")
        self.assertIn("inconclusive", res["message"].lower())

    @patch("scanner.risk_analyzer.calculate_risk_score")
    @patch("scanner.port_hardening.block_port")
    def test_before_and_after_risk_calculations(self, mock_block, mock_calc_risk):
        """14. Before-and-after risk calculations."""
        # Baseline score: 55, post-remediation score: 35
        mock_calc_risk.side_effect = [
            {"total_score": 55, "risk_level": "High"},
            {"total_score": 35, "risk_level": "Medium"},
        ]
        mock_block.return_value = {
            "success": True,
            "verified": True,
            "verification_status": "PARTIALLY_RESOLVED",
            "previous_state": "LISTENING",
            "new_state": "FIREWALL_BLOCKED",
            "rule_name": "ASR_Block_TCP_3389",
        }

        with patch("database.database.save_remediation_action", return_value=19):
            res = execute_remediation_with_verification(
                action_type="BLOCK_PORT",
                target_type="port",
                target_name="3389/TCP",
                port=3389,
                protocol="TCP",
                confirm=True,
                check_privileges=False,
            )

        self.assertEqual(res["before_risk_score"], 55)
        self.assertEqual(res["after_risk_score"], 35)
        self.assertEqual(res["risk_delta"], 20)
        self.assertEqual(res["verification_status"], "PARTIALLY_RESOLVED")
        self.assertEqual(res["audit_record_id"], 19)
        self.assertTrue(res["audit_record_saved"])

    def test_preservation_of_remediation_history(self):
        """15. Preservation of remediation history and Phase 3 schema persistence."""
        history_before = db.get_remediation_history(limit=100)
        initial_count = len(history_before)

        # Save an enriched Phase 3 record
        row_id = db.save_remediation_action(
            action_type="BLOCK_PORT",
            target_type="port",
            target_name="445/TCP",
            port=445,
            protocol="TCP",
            previous_state="LISTENING",
            new_state="FIREWALL_BLOCKED",
            reason="Phase 3 integration test record",
            status="SUCCESS",
            verification_status="RESOLVED",
            requested_change="BLOCK_PORT",
            actual_outcome="SUCCESS",
            before_risk_score=60,
            after_risk_score=30,
            finding_id="FINDING_SMB_445",
        )

        self.assertIsNotNone(row_id)
        history_after = db.get_remediation_history(limit=100)
        self.assertEqual(len(history_after), initial_count + 1)

        newest = history_after[0]
        self.assertEqual(newest["verification_status"], "RESOLVED")
        self.assertEqual(newest["before_risk_score"], 60)
        self.assertEqual(newest["after_risk_score"], 30)
        self.assertEqual(newest["finding_id"], "FINDING_SMB_445")
        self.assertIn("target", newest)


class TestPhase3CompatibilityAndAPIs(unittest.TestCase):
    """Tests 16 through 18: Real-time monitor, risk analysis, and Flask API integration."""

    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def test_existing_real_time_monitoring(self):
        """16. Existing real-time monitoring functions seamlessly with Phase 3."""
        monitor = get_monitor()
        self.assertIsNotNone(monitor)
        status = monitor.get_status()
        self.assertIn("monitoring_active", status)
        self.assertIn("interval_seconds", status)

    def test_existing_risk_analysis(self):
        """17. Existing Phase 2 risk analysis functions seamlessly."""
        risk = calculate_risk_score()
        self.assertIn("total_score", risk)
        self.assertIn("risk_level", risk)
        self.assertIn("breakdown", risk)
        self.assertIn("severity_distribution", risk)

    def test_existing_scan_and_dashboard_apis(self):
        """18. Scan, port-analysis, service, and remediation APIs."""
        # 1. /api/scan
        resp_scan = self.client.post("/api/scan")
        self.assertEqual(resp_scan.status_code, 200)

        # 2. /api/port-analysis
        resp_pa = self.client.get("/api/port-analysis")
        self.assertEqual(resp_pa.status_code, 200)

        # 3. /api/remediation-history
        resp_hist = self.client.get("/api/remediation-history")
        self.assertEqual(resp_hist.status_code, 200)
        data = resp_hist.get_json()
        self.assertIsInstance(data, list)

        # 4. /api/service/info for protected service
        resp_svc = self.client.get("/api/service/info?name=rpcss")
        if resp_svc.status_code == 200:
            s_data = resp_svc.get_json()
            self.assertTrue(s_data.get("is_protected"))
            self.assertIn("operational_impact", s_data)

        # 5. /api/port/block without confirmation rejected
        resp_blk_unconf = self.client.post("/api/port/block", json={"port": 3389, "protocol": "TCP", "confirm": False})
        self.assertEqual(resp_blk_unconf.status_code, 400)

        # 6. /api/service/disable without confirm_disable rejected
        resp_dis_unconf = self.client.post("/api/service/disable", json={"service_name": "TermService", "confirm": True})
        self.assertEqual(resp_dis_unconf.status_code, 400)

        # 7. /api/remediation/verify endpoint responds
        resp_verify = self.client.post("/api/remediation/verify", json={"target_type": "port", "port": 3389, "protocol": "TCP"})
        self.assertEqual(resp_verify.status_code, 200)
        v_data = resp_verify.get_json()
        self.assertIn("verification_status", v_data)


if __name__ == "__main__":
    unittest.main()
