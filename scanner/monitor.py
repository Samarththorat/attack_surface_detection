"""
monitor.py
Real-time Attack Surface Monitoring engine for Windows.

Monitors local attack surface changes:
- Newly opened and closed listening ports (TCP & UDP)
- Process and service associations for listening ports
- Changes in running/flagged services
- Windows Firewall profile state changes (Domain, Private, Public)
- Security configuration changes (UAC, Remote Desktop)

Architectural properties:
- Thread-safe singleton background monitor loop
- Configurable check interval (default 5 seconds)
- Prevents redundant/duplicate loops when multiple tabs or clients connect
- Graceful exception handling for permission denied / unavailable metrics
- Event persistence in SQLite via database.database
- Server-Sent Events (SSE) support for zero-reload dashboard alerts
"""

import time
import datetime
import threading
import queue
import json
import logging

from scanner.port_scanner import get_listening_ports
from scanner.port_risk_analyzer import classify_port
from scanner.service_scanner import get_flagged_services
from scanner.firewall_checker import get_firewall_status
from scanner.security_checker import _check_uac_enabled, _check_rdp_enabled, _check_windows_update_service
from database.database import (
    save_monitoring_event,
    get_monitoring_events,
    resolve_monitoring_event,
    get_unresolved_events_count,
)

logger = logging.getLogger(__name__)


class AttackSurfaceMonitor:
    """
    Centralized singleton monitor for continuous attack-surface change detection.
    """
    _instance = None
    _singleton_lock = threading.RLock()

    @classmethod
    def get_instance(cls, interval=5):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls(interval=interval)
            return cls._instance

    def __init__(self, interval=5):
        self.interval = max(2, int(interval))
        self._lock = threading.RLock()
        self._thread = None
        self._stop_event = threading.Event()
        self._is_running = False

        self.previous_snapshot = None
        self.current_snapshot = None
        self.last_check_time = None
        self.last_successful_check_time = None
        self.snapshots_count = 0

        # In-memory recent changes buffer
        self.recent_changes = []
        # SSE subscriber queues
        self._subscribers = []
        self._scheduled_assessment_callback = None

    def set_scheduled_assessment_callback(self, callback):
        """Registers the single scheduled-assessment callback on the monitor loop."""
        with self._lock:
            self._scheduled_assessment_callback = callback

    def start(self):
        """Starts the background monitoring thread if not already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return  # already running, do not spawn another thread

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="AttackSurfaceMonitorThread",
            )
            self._is_running = True
            self._thread.start()

    def stop(self):
        """Signals the background thread to stop."""
        with self._lock:
            self._stop_event.set()
            self._is_running = False

    def is_active(self):
        with self._lock:
            return self._is_running and (self._thread is not None and self._thread.is_alive())

    def set_interval(self, new_interval):
        """Configures the monitoring check interval in seconds."""
        with self._lock:
            self.interval = max(2, int(new_interval))

    def subscribe(self):
        """Registers a queue for Server-Sent Events (SSE). Returns a queue.Queue."""
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        """Removes an SSE subscriber queue."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast_event(self, event_data):
        """Sends an event dictionary to all active SSE listeners."""
        with self._lock:
            dead_queues = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event_data)
                except queue.Full:
                    dead_queues.append(q)
            for dq in dead_queues:
                if dq in self._subscribers:
                    self._subscribers.remove(dq)

    def publish_event(self, event_data):
        """Publish a state change created outside the monitor sampling loop."""
        if not isinstance(event_data, dict):
            raise TypeError("event_data must be a dictionary")
        self._broadcast_event(event_data)

    def _collect_snapshot(self):
        """
        Safely collects the current system snapshot across ports, firewall,
        services, and security configurations.
        """
        snapshot_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        availability = {
            "ports": True,
            "firewall": True,
            "flagged_services": True,
        }

        # 1. Ports (both TCP & UDP)
        ports_dict = {}
        try:
            raw_ports = get_listening_ports(include_udp=True)
            if isinstance(raw_ports, dict):
                raw_ports = [raw_ports]
            if any(isinstance(port, dict) and "error" in port for port in raw_ports):
                availability["ports"] = False
            for p in raw_ports:
                if not isinstance(p, dict):
                    availability["ports"] = False
                    continue
                if "error" in p or p.get("port") is None:
                    continue
                port_num = p["port"]
                proto = (p.get("protocol") or "TCP").upper()
                classified = classify_port(p)
                key = (port_num, proto)
                ports_dict[key] = {
                    "port": port_num,
                    "protocol": proto,
                    "local_address": p.get("local_address"),
                    "pid": p.get("pid"),
                    "process_name": p.get("process_name"),
                    "service_name": p.get("service_name"),
                    "service_display_name": p.get("service_display_name"),
                    "interface": p.get("interface"),
                    "risk_level": classified.get("risk_level", "UNKNOWN"),
                    "risk_reason": classified.get("risk_reason"),
                    "recommended_status": classified.get("recommended_status"),
                }
        except Exception:
            availability["ports"] = False
            logger.exception("Unable to collect listening ports for monitoring")

        # 2. Firewall profiles
        firewall_info = {}
        try:
            firewall_info = get_firewall_status()
            if isinstance(firewall_info, dict) and firewall_info.get("error"):
                availability["firewall"] = False
        except Exception as e:
            availability["firewall"] = False
            firewall_info = {"error": str(e), "profiles": {}, "overall_status": "UNKNOWN"}

        # 3. Security configurations
        sec_config = {}
        try:
            sec_config["uac_enabled"] = _check_uac_enabled()
        except Exception:
            sec_config["uac_enabled"] = None

        try:
            sec_config["rdp_enabled"] = _check_rdp_enabled()
        except Exception:
            sec_config["rdp_enabled"] = None

        try:
            sec_config["windows_update_status"] = _check_windows_update_service()
        except Exception:
            sec_config["windows_update_status"] = None

        # 4. Flagged services
        flagged_services = {}
        try:
            for s in get_flagged_services():
                name = s.get("name")
                if name:
                    flagged_services[name.lower()] = {
                        "name": name,
                        "pid": s.get("pid"),
                        "status": s.get("status"),
                        "ports": s.get("listening_ports", []),
                        "review_reason": s.get("review_reason"),
                    }
        except Exception:
            availability["flagged_services"] = False
            logger.exception("Unable to collect flagged services for monitoring")

        return {
            "timestamp": snapshot_time,
            "ports": ports_dict,
            "firewall": firewall_info,
            "security_config": sec_config,
            "flagged_services": flagged_services,
            "availability": availability,
        }

    def _compare_and_record(self, prev, curr):
        """
        Compares two consecutive snapshots, detects changes, persists events
        to SQLite, and returns a list of detected change dictionaries.
        """
        changes = []
        now_str = curr["timestamp"]

        # -------------------------------------------------------------
        # A. PORT CHANGES (TCP and UDP)
        # -------------------------------------------------------------
        prev_availability = prev.get("availability", {})
        curr_availability = curr.get("availability", {})
        ports_available = (
            prev_availability.get("ports", True)
            and curr_availability.get("ports", True)
        )
        prev_ports = prev.get("ports", {}) if ports_available else {}
        curr_ports = curr.get("ports", {}) if ports_available else {}

        prev_port_keys = set(prev_ports.keys())
        curr_port_keys = set(curr_ports.keys())

        # Newly opened ports
        new_ports = curr_port_keys - prev_port_keys
        for port_num, proto in sorted(new_ports):
            p_data = curr_ports[(port_num, proto)]
            target = f"{port_num}/{proto}"
            risk_level = p_data.get("risk_level", "MEDIUM")
            severity = risk_level if risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"

            detail = {
                "port": port_num,
                "protocol": proto,
                "process_name": p_data.get("process_name"),
                "pid": p_data.get("pid"),
                "service": p_data.get("service_display_name") or p_data.get("service_name"),
                "address": p_data.get("local_address"),
                "interface": p_data.get("interface"),
                "risk_reason": p_data.get("risk_reason"),
            }

            event_id = save_monitoring_event(
                event_type="PORT_OPENED",
                severity=severity,
                component="port",
                target=target,
                details=detail,
                is_resolved=0,
            )

            change_entry = {
                "id": event_id,
                "change_type": "NEW",
                "component": "port",
                "target": target,
                "severity": severity,
                "title": f"New Listening Port: {target}",
                "description": f"Port {target} is now listening ({p_data.get('process_name') or 'Unknown process'}, PID {p_data.get('pid') or '?'}) on {p_data.get('local_address') or '?'}.",
                "details": detail,
                "timestamp": now_str,
            }
            changes.append(change_entry)

        # Closed ports
        closed_ports = prev_port_keys - curr_port_keys
        for port_num, proto in sorted(closed_ports):
            p_data = prev_ports[(port_num, proto)]
            target = f"{port_num}/{proto}"

            # Auto-resolve prior PORT_OPENED events for this target
            resolve_monitoring_event(component="port", target=target)

            detail = {
                "port": port_num,
                "protocol": proto,
                "previous_process": p_data.get("process_name"),
                "previous_pid": p_data.get("pid"),
            }

            event_id = save_monitoring_event(
                event_type="PORT_CLOSED",
                severity="INFO",
                component="port",
                target=target,
                details=detail,
                is_resolved=1,
            )

            change_entry = {
                "id": event_id,
                "change_type": "REMOVED",
                "component": "port",
                "target": target,
                "severity": "INFO",
                "title": f"Port Closed: {target}",
                "description": f"Port {target} stopped listening (previously used by {p_data.get('process_name') or 'Unknown'}).",
                "details": detail,
                "timestamp": now_str,
            }
            changes.append(change_entry)

        # Process/Service changed on existing listening port
        common_ports = curr_port_keys & prev_port_keys
        for port_num, proto in common_ports:
            old_p = prev_ports[(port_num, proto)]
            new_p = curr_ports[(port_num, proto)]

            old_proc = old_p.get("process_name")
            new_proc = new_p.get("process_name")
            old_pid = old_p.get("pid")
            new_pid = new_p.get("pid")

            if (new_proc and old_proc and new_proc != old_proc) or (new_pid and old_pid and new_pid != old_pid and new_proc != old_proc):
                target = f"{port_num}/{proto}"
                detail = {
                    "port": port_num,
                    "protocol": proto,
                    "previous_process": old_proc,
                    "previous_pid": old_pid,
                    "current_process": new_proc,
                    "current_pid": new_pid,
                }
                event_id = save_monitoring_event(
                    event_type="PORT_PROCESS_CHANGED",
                    severity="MEDIUM",
                    component="port",
                    target=target,
                    details=detail,
                    is_resolved=0,
                    cooldown_seconds=300,
                )
                if event_id is None:
                    continue
                changes.append({
                    "id": event_id,
                    "change_type": "CHANGED",
                    "component": "port",
                    "target": target,
                    "severity": "MEDIUM",
                    "title": f"Process Changed on Port {target}",
                    "description": f"Port {target} changed process from '{old_proc}' (PID {old_pid}) to '{new_proc}' (PID {new_pid}).",
                    "details": detail,
                    "timestamp": now_str,
                })

        # -------------------------------------------------------------
        # B. FIREWALL PROFILE CHANGES
        # -------------------------------------------------------------
        firewall_available = (
            prev_availability.get("firewall", True)
            and curr_availability.get("firewall", True)
        )
        prev_fw = prev.get("firewall", {}).get("profiles", {}) if firewall_available else {}
        curr_fw = curr.get("firewall", {}).get("profiles", {}) if firewall_available else {}

        for profile_name in ("Domain", "Private", "Public"):
            old_state = prev_fw.get(profile_name, {}).get("state")
            new_state = curr_fw.get(profile_name, {}).get("state")

            if old_state and new_state and old_state != new_state:
                target = f"{profile_name} Profile"
                severity = "HIGH" if new_state == "OFF" else "INFO"
                detail = {"profile": profile_name, "old_state": old_state, "new_state": new_state}

                event_id = save_monitoring_event(
                    event_type="FIREWALL_CHANGED",
                    severity=severity,
                    component="firewall",
                    target=target,
                    details=detail,
                    is_resolved=1 if new_state == "ON" else 0,
                )
                changes.append({
                    "id": event_id,
                    "change_type": "CHANGED",
                    "component": "firewall",
                    "target": target,
                    "severity": severity,
                    "title": f"Firewall Profile Changed: {target}",
                    "description": f"{profile_name} profile changed from {old_state} to {new_state}.",
                    "details": detail,
                    "timestamp": now_str,
                })

        # -------------------------------------------------------------
        # C. SECURITY SETTINGS (UAC, RDP, Windows Update)
        # -------------------------------------------------------------
        prev_sec = prev.get("security_config", {})
        curr_sec = curr.get("security_config", {})

        # UAC
        old_uac = prev_sec.get("uac_enabled")
        new_uac = curr_sec.get("uac_enabled")
        if old_uac is not None and new_uac is not None and old_uac != new_uac:
            severity = "HIGH" if new_uac is False else "INFO"
            detail = {"setting": "UAC", "previous": old_uac, "current": new_uac}
            event_id = save_monitoring_event(
                event_type="SECURITY_CONFIG_CHANGED",
                severity=severity,
                component="security_config",
                target="User Account Control (UAC)",
                details=detail,
                is_resolved=1 if new_uac is True else 0,
            )
            changes.append({
                "id": event_id,
                "change_type": "CHANGED",
                "component": "security_config",
                "target": "UAC",
                "severity": severity,
                "title": "UAC Status Changed",
                "description": f"User Account Control (UAC) is now {'ENABLED' if new_uac else 'DISABLED'}.",
                "details": detail,
                "timestamp": now_str,
            })

        # RDP
        old_rdp = prev_sec.get("rdp_enabled")
        new_rdp = curr_sec.get("rdp_enabled")
        if old_rdp is not None and new_rdp is not None and old_rdp != new_rdp:
            severity = "HIGH" if new_rdp is True else "INFO"
            detail = {"setting": "RDP", "previous": old_rdp, "current": new_rdp}
            event_id = save_monitoring_event(
                event_type="SECURITY_CONFIG_CHANGED",
                severity=severity,
                component="security_config",
                target="Remote Desktop (RDP)",
                details=detail,
                is_resolved=1 if new_rdp is False else 0,
            )
            changes.append({
                "id": event_id,
                "change_type": "CHANGED",
                "component": "security_config",
                "target": "RDP",
                "severity": severity,
                "title": "Remote Desktop Status Changed",
                "description": f"Remote Desktop (RDP) was {'ENABLED' if new_rdp else 'DISABLED'}.",
                "details": detail,
                "timestamp": now_str,
            })

        old_update_status = prev_sec.get("windows_update_status")
        new_update_status = curr_sec.get("windows_update_status")
        if (
            old_update_status is not None
            and new_update_status is not None
            and old_update_status != new_update_status
        ):
            stopped = str(new_update_status).casefold() == "stopped"
            severity = "HIGH" if stopped else "INFO"
            detail = {
                "setting": "Windows Update service",
                "previous": old_update_status,
                "current": new_update_status,
            }
            event_id = save_monitoring_event(
                event_type="SECURITY_CONFIG_CHANGED",
                severity=severity,
                component="security_config",
                target="Windows Update Service",
                details=detail,
                is_resolved=not stopped,
            )
            changes.append({
                "id": event_id,
                "change_type": "CHANGED",
                "component": "security_config",
                "target": "Windows Update Service",
                "severity": severity,
                "title": "Windows Update Service Status Changed",
                "description": f"Windows Update service changed from {old_update_status} to {new_update_status}.",
                "details": detail,
                "timestamp": now_str,
            })

        # -------------------------------------------------------------
        # D. FLAGGED SERVICES
        # -------------------------------------------------------------
        services_available = (
            prev_availability.get("flagged_services", True)
            and curr_availability.get("flagged_services", True)
        )
        prev_svcs = prev.get("flagged_services", {}) if services_available else {}
        curr_svcs = curr.get("flagged_services", {}) if services_available else {}

        new_svcs = set(curr_svcs.keys()) - set(prev_svcs.keys())
        for s_key in new_svcs:
            s_data = curr_svcs[s_key]
            detail = s_data
            event_id = save_monitoring_event(
                event_type="SERVICE_STARTED",
                severity="MEDIUM",
                component="service",
                target=s_data.get("name"),
                details=detail,
                is_resolved=0,
            )
            changes.append({
                "id": event_id,
                "change_type": "NEW",
                "component": "service",
                "target": s_data.get("name"),
                "severity": "MEDIUM",
                "title": f"Flagged Service Detected: {s_data.get('name')}",
                "description": f"Process '{s_data.get('name')}' (PID {s_data.get('pid')}) opened listening port(s) {s_data.get('ports')}.",
                "details": detail,
                "timestamp": now_str,
            })

        stopped_svcs = set(prev_svcs.keys()) - set(curr_svcs.keys())
        for s_key in stopped_svcs:
            s_data = prev_svcs[s_key]
            resolve_monitoring_event(component="service", target=s_data.get("name"))
            event_id = save_monitoring_event(
                event_type="SERVICE_STOPPED",
                severity="INFO",
                component="service",
                target=s_data.get("name"),
                details=s_data,
                is_resolved=1,
            )
            changes.append({
                "id": event_id,
                "change_type": "REMOVED",
                "component": "service",
                "target": s_data.get("name"),
                "severity": "INFO",
                "title": f"Flagged Service Stopped: {s_data.get('name')}",
                "description": f"Process '{s_data.get('name')}' is no longer flagged or has stopped.",
                "details": s_data,
                "timestamp": now_str,
            })

        return changes

    def perform_check(self):
        """
        Executes one observation cycle:
        Collects snapshot, compares to previous, updates state, and broadcasts changes.
        """
        curr = self._collect_snapshot()
        detected_changes = []

        with self._lock:
            if self.previous_snapshot is not None:
                detected_changes = self._compare_and_record(self.previous_snapshot, curr)
                if detected_changes:
                    # Prepend new changes to recent buffer, keeping up to 50
                    self.recent_changes = (detected_changes + self.recent_changes)[:50]

            self.previous_snapshot = self.current_snapshot or curr
            self.current_snapshot = curr
            self.last_check_time = curr["timestamp"]
            if curr.get("availability") and all(curr["availability"].values()):
                self.last_successful_check_time = curr["timestamp"]
            self.snapshots_count += 1
            check_health = (
                "HEALTHY"
                if all(curr.get("availability", {}).get(key, False) for key in ("ports", "firewall", "flagged_services"))
                else "DEGRADED"
            )

        # Broadcast newly detected changes or heartbeat to SSE subscribers
        if detected_changes:
            for chg in detected_changes:
                self._broadcast_event({
                    "type": "change",
                    "data": chg,
                    "timestamp": curr["timestamp"],
                    "unresolved_count": get_unresolved_events_count(),
                    "last_check_time": self.last_check_time,
                    "last_successful_check_time": self.last_successful_check_time,
                    "monitoring_health": check_health,
                })
        else:
            self._broadcast_event({
                "type": "heartbeat",
                "timestamp": curr["timestamp"],
                "unresolved_count": get_unresolved_events_count(),
                "ports_count": len(curr.get("ports", {})),
                "last_check_time": self.last_check_time,
                "last_successful_check_time": self.last_successful_check_time,
                "monitoring_health": check_health,
            })

        return detected_changes

    def _monitoring_loop(self):
        """Main loop of the background monitor daemon thread."""
        while not self._stop_event.is_set():
            try:
                self.perform_check()
            except Exception:
                logger.exception("Attack-surface monitoring cycle failed")

            with self._lock:
                callback = self._scheduled_assessment_callback
            if callback is not None:
                try:
                    callback()
                except Exception:
                    logger.exception("Scheduled assessment callback failed")

            # Sleep in small slices to respond promptly to stop_event
            sleep_duration = self.interval
            slices = int(sleep_duration / 0.5)
            for _ in range(max(1, slices)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.5)

    def get_status(self):
        """
        Returns a comprehensive real-time status dictionary for API and UI consumption.
        """
        with self._lock:
            ports_monitored = len(self.current_snapshot.get("ports", {})) if self.current_snapshot else 0
            fw_status = (
                self.current_snapshot.get("firewall", {}).get("overall_status", "UNKNOWN")
                if self.current_snapshot else "UNKNOWN"
            )
            uac = (
                self.current_snapshot.get("security_config", {}).get("uac_enabled")
                if self.current_snapshot else None
            )
            rdp = (
                self.current_snapshot.get("security_config", {}).get("rdp_enabled")
                if self.current_snapshot else None
            )

            is_active_val = self._is_running and (self._thread is not None and self._thread.is_alive())
            availability = (
                dict(self.current_snapshot.get("availability", {}))
                if self.current_snapshot else {}
            )
            if not is_active_val:
                health = "STOPPED"
            elif not self.current_snapshot:
                health = "STARTING"
            elif not all(availability.get(key, True) for key in ("ports", "firewall", "flagged_services")):
                health = "DEGRADED"
            else:
                health = "HEALTHY"

            try:
                last_check = datetime.datetime.strptime(self.last_check_time, "%Y-%m-%d %H:%M:%S")
                if is_active_val and (datetime.datetime.now() - last_check).total_seconds() > self.interval * 2:
                    health = "STALE"
            except (TypeError, ValueError):
                if is_active_val and health == "HEALTHY":
                    health = "STALE"

            status = {
                "monitoring_active": is_active_val,
                "monitoring_health": health,
                "interval_seconds": self.interval,
                "last_check_time": self.last_check_time,
                "last_successful_check_time": self.last_successful_check_time,
                "sample_availability": availability,
                "snapshots_collected": self.snapshots_count,
                "recent_changes": list(self.recent_changes[:20]),
                "unresolved_events_count": get_unresolved_events_count(),
                "summary": {
                    "listening_ports_count": ports_monitored,
                    "firewall_status": fw_status,
                    "uac_enabled": uac,
                    "rdp_enabled": rdp,
                },
            }
            return status


# Module-level convenience function
def get_monitor():
    return AttackSurfaceMonitor.get_instance()
