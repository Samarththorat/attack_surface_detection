"""Analytics derived only from persisted scans, findings, and audit records."""

from collections import Counter
from datetime import datetime

from database.database import (
    get_finding_lifecycles,
    get_monitoring_events,
    get_remediation_history,
    get_scan_by_id,
    get_scan_history,
    get_vulnerability_analytics,
)


def _scan_finding_snapshot(scan):
    results = (scan or {}).get("full_results") or {}
    risk = results.get("risk")
    if not isinstance(risk, dict) or not isinstance(risk.get("unified_findings"), list):
        return None
    required_sections = ("ports", "services", "firewall", "security_findings")
    if any(
        section not in results
        or isinstance(results[section], dict) and "error" in results[section]
        for section in required_sections
    ):
        return None
    return {
        finding.get("id"): finding
        for finding in risk["unified_findings"]
        if isinstance(finding, dict) and finding.get("id")
    }


def compare_scans(before_id, after_id):
    """Compare stored findings without treating an incomplete scan as resolution evidence."""
    before = get_scan_by_id(before_id)
    after = get_scan_by_id(after_id)
    if before is None or after is None:
        return None

    previous = _scan_finding_snapshot(before)
    current = _scan_finding_snapshot(after)
    if previous is None or current is None:
        return {
            "before_scan_id": before_id,
            "after_scan_id": after_id,
            "comparable": False,
            "new": [],
            "persistent": [],
            "resolved": [],
            "reopened": [],
            "limitations": ["At least one selected scan lacks complete findings data; missing findings are not classified as resolved."],
        }

    new = []
    persistent = []
    resolved = []
    reopened = []
    for finding_id, finding in current.items():
        if finding.get("status") == "Reopened":
            reopened.append(finding)
        elif finding_id in previous:
            persistent.append(finding)
        else:
            new.append(finding)
    resolved.extend(
        finding for finding_id, finding in previous.items()
        if finding_id not in current
    )
    return {
        "before_scan_id": before_id,
        "after_scan_id": after_id,
        "comparable": True,
        "new": new,
        "persistent": persistent,
        "resolved": resolved,
        "reopened": reopened,
        "limitations": [
            "Resolution here means absent from two comparable complete scan snapshots; it is not a remediation verification.",
            "An open listening port does not prove internet reachability or exploitability.",
        ],
    }


def build_security_analytics():
    """Builds trend and distribution values from available stored records."""
    history = get_scan_history(limit=500)
    ordered_history = sorted(history, key=lambda item: item.get("id", 0))
    loaded_scans = [get_scan_by_id(item["id"]) for item in ordered_history]
    loaded_scans = [scan for scan in loaded_scans if scan is not None]

    risk_trend = [
        {
            "scan_id": item["id"],
            "timestamp": item["scan_time"],
            "score": item.get("risk_score"),
        }
        for item in ordered_history
        if item.get("risk_score") is not None
    ]
    comparable_differences = []
    snapshots = []
    for scan in loaded_scans:
        snapshot = _scan_finding_snapshot(scan)
        snapshots.append((scan["id"], snapshot))
    for (before_id, before), (after_id, after) in zip(snapshots, snapshots[1:]):
        if before is not None and after is not None:
            comparable_differences.append({
                "before_scan_id": before_id,
                "after_scan_id": after_id,
                "risk_score_change": (
                    (next((s.get("risk_score") for s in ordered_history if s["id"] == after_id), None) or 0)
                    - (next((s.get("risk_score") for s in ordered_history if s["id"] == before_id), None) or 0)
                ),
                "new_count": len(set(after) - set(before)),
                "resolved_count": len(set(before) - set(after)),
            })

    latest_snapshot = next((snapshot for _, snapshot in reversed(snapshots) if snapshot is not None), {})
    severity_counts = Counter()
    category_counts = Counter()
    for finding in latest_snapshot.values():
        severity_counts[(finding.get("severity") or "UNKNOWN").upper()] += 1
        category_counts[finding.get("category") or "Uncategorized"] += 1

    remediation = get_remediation_history(limit=1000)
    remediation_outcomes = Counter(
        (item.get("verification_status") or item.get("status") or "UNKNOWN").upper()
        for item in remediation
    )
    verification_results = [
        (item.get("verification_status") or "").upper()
        for item in remediation
        if (item.get("verification_status") or "").upper() not in ("", "UNVERIFIED")
    ]
    verified_count = sum(
        status in ("VERIFIED", "SUCCESS", "RESOLVED")
        for status in verification_results
    )
    verification_count = len(verification_results)
    lifecycle = get_finding_lifecycles(limit=1000)
    resolution_durations = []
    for item in lifecycle:
        if not item.get("resolved_at") or not item.get("created_at"):
            continue
        try:
            start = datetime.strptime(item["created_at"], "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(item["resolved_at"], "%Y-%m-%d %H:%M:%S")
            if end >= start:
                resolution_durations.append((end - start).total_seconds())
        except ValueError:
            continue

    monitoring = get_monitoring_events(limit=1000)
    attack_changes = Counter(
        item.get("event_type", "UNKNOWN")
        for item in monitoring
        if item.get("event_type") in ("PORT_OPENED", "PORT_CLOSED")
    )
    vulnerability_analytics = get_vulnerability_analytics()

    return {
        "risk_trend": risk_trend,
        "severity_distribution": dict(severity_counts),
        "finding_categories": dict(category_counts),
        "remediation_outcomes": dict(remediation_outcomes),
        "remediation_success_rate": (
            round(verified_count / verification_count * 100, 2)
            if verification_count else None
        ),
        "average_resolution_seconds": (
            round(sum(resolution_durations) / len(resolution_durations), 2)
            if resolution_durations else None
        ),
        "attack_surface_changes": {
            "PORT_OPENED": attack_changes.get("PORT_OPENED", 0),
            "PORT_CLOSED": attack_changes.get("PORT_CLOSED", 0),
        },
        "vulnerability_findings_by_day": vulnerability_analytics["vulnerability_findings_by_day"],
        "vulnerability_summary": {
            key: value
            for key, value in vulnerability_analytics.items()
            if key != "vulnerability_findings_by_day"
        },
        "comparable_scan_differences": comparable_differences,
        "finding_lifecycle": {
            "new": sum(item.get("status") == "New" for item in lifecycle),
            "persistent": sum(item.get("status") in ("Acknowledged", "In Progress", "Remediation Pending") for item in lifecycle),
            "reopened": sum(item.get("status") == "Reopened" for item in lifecycle),
            "resolved": sum(item.get("status") == "Resolved" for item in lifecycle),
            "partially_resolved": sum(item.get("status") == "Partially Resolved" for item in lifecycle),
        },
        "methodology": {
            "risk_trend": "Stored risk_score values per scan, ordered by scan ID.",
            "severity_and_category": "Counts from the latest stored scan with complete unified finding data.",
            "remediation_success_rate": "Verified/successful verification outcomes divided by records with a non-UNVERIFIED verification status; null when there is no denominator.",
            "resolution_time": "Mean created_at-to-resolved_at for lifecycle records with valid timestamps.",
            "attack_surface_changes": "Stored PORT_OPENED and PORT_CLOSED monitoring events only.",
            "vulnerability_trend": "Stored vulnerability observations grouped by detected_time date; repeat observations are counted.",
            "vulnerability_summary": "Unique CVEs and affected software/CVE pairs are counted separately from stored observations. Current active pairs use only the latest completed vulnerability assessment snapshot; a missing or incomplete latest assessment is reported as unavailable, not zero.",
            "limitations": "No historical values are synthesized; absent or incomplete scans are excluded from comparisons.",
        },
    }
