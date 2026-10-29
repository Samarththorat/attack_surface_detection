"""Read-only process and system-resource snapshots for Task Monitoring."""

import datetime
import os
import threading

import psutil

from database.database import save_system_monitor_sample


class TaskMonitoringCollector:
    """Collect live process data and persist one bounded system sample per minute."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cpu_primed = False
        self._primed_processes = set()
        self._previous_counters = None
        self._previous_counter_time = None

    def collect(self):
        with self._lock:
            return self._collect_locked()

    def _collect_locked(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        sampled_at = now.isoformat(timespec="seconds")
        errors = []
        cpu = self._read_system_metric(
            lambda: psutil.cpu_percent(interval=None),
            errors,
            "CPU",
        )
        if not self._cpu_primed:
            self._cpu_primed = True
            cpu = None

        memory = self._read_system_metric(psutil.virtual_memory, errors, "Memory")
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        disk = self._read_system_metric(lambda: psutil.disk_usage(drive), errors, "Disk capacity")
        disk_io = self._read_system_metric(psutil.disk_io_counters, errors, "Disk I/O")
        network_io = self._read_system_metric(psutil.net_io_counters, errors, "Network I/O")
        counters = {
            "disk_read_bytes": getattr(disk_io, "read_bytes", None),
            "disk_write_bytes": getattr(disk_io, "write_bytes", None),
            "network_received_bytes": getattr(network_io, "bytes_recv", None),
            "network_sent_bytes": getattr(network_io, "bytes_sent", None),
        }
        rates = self._counter_rates(counters, now.timestamp())
        processes, inaccessible_processes = self._read_processes(errors)
        try:
            process_count = len(psutil.pids())
        except psutil.Error as error:
            errors.append(f"Process count unavailable: {error.__class__.__name__}")
            process_count = None

        snapshot = {
            "sampled_at": sampled_at,
            "cpu_usage_percent": cpu,
            "memory_usage_percent": getattr(memory, "percent", None),
            "memory_used_bytes": getattr(memory, "used", None),
            "memory_total_bytes": getattr(memory, "total", None),
            "disk_usage_percent": getattr(disk, "percent", None),
            "disk_used_bytes": getattr(disk, "used", None),
            "disk_total_bytes": getattr(disk, "total", None),
            **counters,
            **rates,
            "running_processes": process_count,
            "gpu_usage_percent": None,
            "per_process_energy_estimate": None,
            "collection_errors": errors,
        }
        availability = {
            "cpu": cpu is not None,
            "memory": memory is not None,
            "disk_capacity": disk is not None,
            "disk_io": disk_io is not None,
            "network_io": network_io is not None,
        }
        snapshot.update({
            "processes": processes,
            "processes_observed": len(processes),
            "process_access_denied": inaccessible_processes,
            "availability": availability,
            "availability_notes": {
                "cpu": "CPU percentage is unavailable until a second sample is collected." if cpu is None else None,
                "disk_io": "Disk activity counters are unavailable on this system." if disk_io is None else None,
                "network_io": "Network activity counters are unavailable on this system." if network_io is None else None,
                "network_per_process": "The operating system does not provide supported per-process network attribution.",
                "gpu": "GPU utilization is unavailable; no supported GPU telemetry provider is configured.",
                "energy": "Per-process energy is not measured or estimated.",
            },
            "process_cpu_basis": "Percent of one logical CPU; a process can exceed 100% on multicore systems.",
            "history_interval_seconds": 60,
            "history_retention_days": 7,
        })
        try:
            snapshot["history_sample_saved"] = save_system_monitor_sample(snapshot)
            snapshot["history_error"] = None
        except (OSError, ValueError, RuntimeError) as error:
            snapshot["history_sample_saved"] = False
            snapshot["history_error"] = f"Live measurements are available, but history could not be saved: {error}"
        return snapshot

    @staticmethod
    def _read_system_metric(reader, errors, label):
        try:
            return reader()
        except (OSError, psutil.Error) as error:
            errors.append(f"{label} unavailable: {error.__class__.__name__}")
            return None

    def _counter_rates(self, counters, now):
        rates = {
            "disk_read_bytes_per_sec": None,
            "disk_write_bytes_per_sec": None,
            "network_received_bytes_per_sec": None,
            "network_sent_bytes_per_sec": None,
        }
        if self._previous_counters is not None and self._previous_counter_time is not None:
            elapsed = now - self._previous_counter_time
            if elapsed > 0:
                pairs = (
                    ("disk_read_bytes", "disk_read_bytes_per_sec"),
                    ("disk_write_bytes", "disk_write_bytes_per_sec"),
                    ("network_received_bytes", "network_received_bytes_per_sec"),
                    ("network_sent_bytes", "network_sent_bytes_per_sec"),
                )
                for counter_name, rate_name in pairs:
                    current = counters[counter_name]
                    previous = self._previous_counters[counter_name]
                    if current is not None and previous is not None and current >= previous:
                        rates[rate_name] = round((current - previous) / elapsed, 2)
        self._previous_counters = counters
        self._previous_counter_time = now
        return rates

    def _read_processes(self, errors):
        processes = []
        inaccessible = 0
        current_keys = set()
        for process in psutil.process_iter(
            attrs=["pid", "name", "username", "create_time", "status", "memory_info"],
            ad_value=None,
        ):
            try:
                info = process.info
                pid = info.get("pid")
                create_time = info.get("create_time")
                if pid is None:
                    continue
                identity = f"{pid}:{create_time:.6f}" if isinstance(create_time, (int, float)) else f"{pid}:unknown"
                current_keys.add(identity)
                if identity in self._primed_processes:
                    cpu_percent = process.cpu_percent(interval=None)
                else:
                    process.cpu_percent(interval=None)
                    cpu_percent = None
                    self._primed_processes.add(identity)

                memory_info = info.get("memory_info")
                try:
                    memory_percent = process.memory_percent()
                except psutil.Error:
                    memory_percent = None
                    inaccessible += 1
                try:
                    io = process.io_counters()
                except (psutil.Error, OSError, AttributeError):
                    io = None
                processes.append({
                    "identity": identity,
                    "pid": pid,
                    "name": info.get("name") or "Unavailable",
                    "cpu_percent": cpu_percent,
                    "memory_rss_bytes": getattr(memory_info, "rss", None),
                    "memory_percent": memory_percent,
                    "disk_read_bytes": getattr(io, "read_bytes", None),
                    "disk_write_bytes": getattr(io, "write_bytes", None),
                    "network_sent_bytes": None,
                    "network_received_bytes": None,
                    "start_time": (
                        datetime.datetime.fromtimestamp(create_time, datetime.timezone.utc).isoformat(timespec="seconds")
                        if isinstance(create_time, (int, float)) else None
                    ),
                    "state": info.get("status"),
                    "username": info.get("username"),
                })
            except psutil.AccessDenied:
                inaccessible += 1
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        self._primed_processes.intersection_update(current_keys)
        if inaccessible:
            errors.append(f"Some process details were unavailable due to access restrictions ({inaccessible}).")
        processes.sort(key=lambda item: (item["name"].casefold(), item["pid"]))
        return processes, inaccessible


task_monitoring_collector = TaskMonitoringCollector()
