import datetime
import os
import tempfile
import unittest
from unittest.mock import patch

import psutil

import database.database as database
from scanner.task_monitoring import TaskMonitoringCollector


class TaskMonitoringCollectorTests(unittest.TestCase):
    def setUp(self):
        descriptor, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(descriptor)
        self.db_path_patch = patch.object(database, "DB_PATH", self.db_path)
        self.db_path_patch.start()
        database.init_db()

    def tearDown(self):
        self.db_path_patch.stop()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    @staticmethod
    def _memory(total=8_000_000_000, used=4_000_000_000, percent=50.0):
        return type("Memory", (), {"total": total, "used": used, "percent": percent})()

    @staticmethod
    def _disk(total=100_000, used=40_000, percent=40.0):
        return type("Disk", (), {"total": total, "used": used, "percent": percent})()

    def test_snapshot_reports_actual_metrics_and_separates_unsupported_sources(self):
        process = unittest.mock.Mock()
        process.info = {
            "pid": 42,
            "name": "example.exe",
            "username": "user",
            "create_time": 1000.0,
            "status": "running",
            "memory_info": type("MemoryInfo", (), {"rss": 1024})(),
        }
        process.cpu_percent.return_value = 0.0
        process.memory_percent.return_value = 0.01
        process.io_counters.return_value = type("IO", (), {"read_bytes": 100, "write_bytes": 200})()
        collector = TaskMonitoringCollector()
        with (
            patch("scanner.task_monitoring.psutil.cpu_percent", side_effect=[11.5, 12.5]),
            patch("scanner.task_monitoring.psutil.virtual_memory", return_value=self._memory()),
            patch("scanner.task_monitoring.psutil.disk_usage", return_value=self._disk()),
            patch("scanner.task_monitoring.psutil.disk_io_counters", return_value=None),
            patch("scanner.task_monitoring.psutil.net_io_counters", return_value=None),
            patch("scanner.task_monitoring.psutil.process_iter", return_value=[process]),
            patch("scanner.task_monitoring.psutil.pids", return_value=[42]),
        ):
            first = collector.collect()
            second = collector.collect()

        self.assertIsNone(first["cpu_usage_percent"])
        self.assertEqual(second["cpu_usage_percent"], 12.5)
        self.assertEqual(second["memory_usage_percent"], 50.0)
        self.assertEqual(second["disk_usage_percent"], 40.0)
        self.assertEqual(second["running_processes"], 1)
        self.assertIsNone(second["gpu_usage_percent"])
        self.assertTrue(second["availability_notes"]["network_per_process"].startswith("The operating system"))
        self.assertIsNone(second["processes"][0]["network_sent_bytes"])
        self.assertEqual(second["processes"][0]["cpu_percent"], 0.0)
        self.assertEqual(second["processes"][0]["disk_read_bytes"], 100)

    def test_denied_and_terminated_processes_do_not_break_snapshot(self):
        denied = unittest.mock.Mock()
        denied.info = {
            "pid": 8, "name": "restricted", "username": None, "create_time": 10.0,
            "status": "running", "memory_info": None,
        }
        denied.cpu_percent.side_effect = psutil.AccessDenied(pid=8)
        gone = unittest.mock.Mock()
        gone.info = {
            "pid": 9, "name": "terminated", "username": None, "create_time": 11.0,
            "status": "running", "memory_info": None,
        }
        gone.cpu_percent.side_effect = psutil.NoSuchProcess(pid=9)
        collector = TaskMonitoringCollector()
        with (
            patch("scanner.task_monitoring.psutil.cpu_percent", return_value=15.0),
            patch("scanner.task_monitoring.psutil.virtual_memory", return_value=self._memory()),
            patch("scanner.task_monitoring.psutil.disk_usage", return_value=self._disk()),
            patch("scanner.task_monitoring.psutil.disk_io_counters", return_value=None),
            patch("scanner.task_monitoring.psutil.net_io_counters", return_value=None),
            patch("scanner.task_monitoring.psutil.process_iter", return_value=[denied, gone]),
            patch("scanner.task_monitoring.psutil.pids", return_value=[8, 9]),
        ):
            snapshot = collector.collect()

        self.assertEqual(snapshot["running_processes"], 2)
        self.assertEqual(snapshot["processes"], [])
        self.assertGreaterEqual(snapshot["process_access_denied"], 1)

    def test_system_sample_history_is_rate_limited_and_retained_for_seven_days(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        old_sample = {"sampled_at": (now - datetime.timedelta(days=8)).isoformat()}
        new_sample = {"sampled_at": now.isoformat(), "cpu_usage_percent": 20.0}
        self.assertTrue(database.save_system_monitor_sample(old_sample))
        self.assertTrue(database.save_system_monitor_sample(new_sample))
        self.assertFalse(database.save_system_monitor_sample({
            "sampled_at": (now + datetime.timedelta(seconds=30)).isoformat()
        }))

        samples = database.get_system_monitor_samples(hours=168)
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["cpu_usage_percent"], 20.0)
        with self.assertRaises(ValueError):
            database.get_system_monitor_samples(hours=169)

    def test_remediation_keeps_initial_scan_link_and_attaches_verification_scan(self):
        initial_scan_id = database.save_scan({"ports": [], "risk": {}})
        verification_scan_id = database.save_scan({"ports": [], "risk": {}})
        remediation_id = database.save_remediation_action(
            action_type="BLOCK_PORT",
            target_type="port",
            target_name="3389/TCP",
            port=3389,
            protocol="TCP",
            status="SUCCESS",
            scan_id=initial_scan_id,
        )

        self.assertTrue(database.link_remediation_verification_scan(
            remediation_id, verification_scan_id
        ))
        self.assertFalse(database.link_remediation_verification_scan(
            remediation_id, verification_scan_id
        ))
        history = database.get_remediation_history(limit=1)
        self.assertEqual(history[0]["scan_id"], initial_scan_id)
        self.assertEqual(history[0]["verification_scan_id"], verification_scan_id)
