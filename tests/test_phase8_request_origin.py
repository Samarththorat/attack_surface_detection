import unittest
from unittest.mock import patch

from app import app


class TestRequestOriginProtection(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_cross_origin_state_change_is_rejected_before_mutation(self):
        with patch("app.update_monitoring_event_state") as update_state:
            response = self.client.post(
                "/api/monitoring/events/42/acknowledge",
                headers={"Origin": "https://untrusted.example"},
            )

        self.assertEqual(response.status_code, 403)
        update_state.assert_not_called()

    def test_scan_rejects_cross_origin_before_running(self):
        with patch("app.run_full_scan") as run_scan:
            response = self.client.post(
                "/api/scan",
                headers={"Origin": "https://untrusted.example"},
            )

        self.assertEqual(response.status_code, 403)
        run_scan.assert_not_called()

    def test_non_loopback_client_is_rejected(self):
        response = self.client.get("/api/monitoring/status", environ_base={"REMOTE_ADDR": "192.0.2.10"})

        self.assertEqual(response.status_code, 403)

    def test_same_origin_state_change_is_allowed(self):
        with patch("app.update_monitoring_event_state", return_value=True):
            response = self.client.post(
                "/api/monitoring/events/42/acknowledge",
                headers={"Origin": "http://localhost"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["success"])

    def test_non_browser_request_without_origin_remains_supported(self):
        with patch("app.update_monitoring_event_state", return_value=True):
            response = self.client.post("/api/monitoring/events/42/acknowledge")

        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
