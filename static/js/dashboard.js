let trendChartInstance = null;
const analyticsChartInstances = {};
let assessmentRunning = false;
let dashboardMonitoringStatus = null;
let latestDashboardScanId = null;
let dashboardAssessmentRefreshInProgress = false;

async function runScan() {
    const content = document.getElementById("dashboard-content");
    const feedback = document.getElementById("scan-feedback");
    const button = document.getElementById("rescan-btn");
    if (assessmentRunning) return;
    assessmentRunning = true;

    if (button) {
        button.disabled = true;
        button.textContent = "Assessment running…";
    }
    if (feedback) {
        feedback.textContent = "Assessment in progress. This may take a few moments.";
        feedback.classList.remove("hidden");
        feedback.classList.remove("error");
    }
    if (content) content.setAttribute("aria-busy", "true");

    try {
        const response = await fetch("/api/scan", { method: "POST" });
        let data;
        try {
            data = await response.json();
        } catch (err) {
            throw new Error(`Server returned an invalid response (HTTP ${response.status}).`);
        }
        if (!response.ok) {
            throw new Error(`Assessment could not be completed (HTTP ${response.status}). Retry or review the application logs.`);
        }
        if (!data || typeof data !== "object" || Array.isArray(data)) {
            throw new Error("Server returned an invalid scan response.");
        }
        if (data.success === false) {
            throw new Error("Assessment did not complete successfully. Retry or review the application logs.");
        }
        if (data.error) {
            throw new Error("Assessment did not complete. Retry or review the application logs.");
        }
        if (!data.risk || typeof data.risk !== "object" || Array.isArray(data.risk)) {
            throw new Error("Assessment response was incomplete. Retry or review the application logs.");
        }
        if (data.risk.error) {
            throw new Error("Risk scoring could not be completed. Review the application logs.");
        }
        await refreshMonitoringSummary(data);
        renderDashboard(data);
        latestDashboardScanId = Number.isSafeInteger(data.scan_id) ? data.scan_id : latestDashboardScanId;
        await loadHistory();
        await loadRecentActivity();
        if (feedback) {
            const incomplete = Array.isArray(data.incomplete_sections) && data.incomplete_sections.length > 0;
            feedback.textContent = data.assessment_status === "PARTIAL" || incomplete
                ? "Assessment finished with incomplete checks. Review the status above for details."
                : data.assessment_status === "COMPLETE"
                    ? "Assessment completed."
                    : "Assessment finished; completeness status was not recorded.";
            feedback.classList.remove("hidden");
        }
    } catch (err) {
        if (feedback) {
            feedback.textContent = err.message || "Assessment could not be completed. Retry or review the application logs.";
            feedback.classList.remove("hidden");
            feedback.classList.add("error");
        }
    } finally {
        assessmentRunning = false;
        if (button) {
            button.disabled = false;
            button.textContent = "Run New Assessment";
        }
        if (content) content.removeAttribute("aria-busy");
    }
}

function renderDashboard(data) {
    const assessment = data && typeof data === "object" && !Array.isArray(data) ? data : {};
    renderExecutiveSummary(assessment);
    const completeness = document.getElementById("scan-completeness-status");
    if (completeness) {
        const incomplete = Array.isArray(assessment.incomplete_sections) ? assessment.incomplete_sections : [];
        const partial = assessment.assessment_status === "PARTIAL" || incomplete.length > 0;
        const complete = assessment.assessment_status === "COMPLETE" && !partial;
        const timestamp = typeof assessment.assessment_timestamp === "string" ? assessment.assessment_timestamp : "";
        completeness.textContent = partial
            ? `Partial assessment${timestamp ? ` · ${timestamp}` : ""}: ${incomplete.join(", ") || "some checks unavailable"}.`
            : complete
                ? `Assessment complete${timestamp ? ` · ${timestamp}` : ""}.`
                : Object.keys(assessment).length === 0
                    ? "No saved assessment data is available."
                    : "Assessment completeness was not recorded.";
        completeness.classList.toggle("warning", partial || !complete);
        completeness.classList.toggle("complete", complete);
    }
    const risk = assessment.risk && typeof assessment.risk === "object" && !Array.isArray(assessment.risk)
        ? assessment.risk
        : {};
    const hasAssessment = Object.keys(assessment).length > 0;
    renderRiskScore(risk);
    renderSystemInfo(assessment.system_info);
    renderAttentionFindings(risk.unified_findings, hasAssessment);
    renderOverviewSeverityChart(risk.severity_distribution);
    renderRecommendations(assessment.recommendations);
}

function renderExecutiveSummary(data) {
    const assessment = data && typeof data === "object" && !Array.isArray(data) ? data : {};
    const risk = assessment.risk && typeof assessment.risk === "object" && !Array.isArray(assessment.risk)
        ? assessment.risk
        : {};
    const findings = Array.isArray(risk.unified_findings) ? risk.unified_findings : null;
    const highPriority = findings && findings.filter(finding =>
        finding && typeof finding === "object" && !Array.isArray(finding) &&
        ["P1", "P2"].includes(finding.priority_code) &&
        !["Resolved", "Accepted Risk"].includes(finding.status)
    ).length;
    const ports = Array.isArray(assessment.ports) ? assessment.ports.length : null;
    const unresolvedEvents = Number.isInteger(assessment.monitoring_unresolved_count)
        ? assessment.monitoring_unresolved_count
        : dashboardMonitoringStatus && Number.isInteger(dashboardMonitoringStatus.unresolved_events_count)
            ? dashboardMonitoringStatus.unresolved_events_count
            : null;
    const values = {
        "summary-risk-score": typeof risk.total_score === "number" && Number.isFinite(risk.total_score)
            ? `${risk.total_score}/100`
            : "—",
        "summary-listening-sockets": ports === null ? "—" : String(ports),
        "summary-active-findings": highPriority === null ? "—" : String(highPriority),
        "summary-unresolved-alerts": unresolvedEvents === null ? "—" : String(unresolvedEvents),
    };
    for (const [id, value] of Object.entries(values)) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }
    const riskNote = document.getElementById("summary-risk-note");
    if (riskNote) riskNote.textContent = risk.risk_level
        ? `${risk.risk_level} overall risk${assessment.assessment_timestamp ? ` · ${assessment.assessment_timestamp}` : ""}`
        : "Latest saved assessment";
}

function findingDestination(finding) {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) return "/attack-surface";

    const routes = {
        "/attack-surface": "/attack-surface",
        "/port-hardening": "/port-hardening",
        "/vulnerabilities": "/vulnerabilities",
        "/activity": "/activity",
        "/analytics": "/analytics",
        "/reports": "/reports",
        "attack-surface": "/attack-surface",
        "port-hardening": "/port-hardening",
        vulnerabilities: "/vulnerabilities",
        activity: "/activity",
        analytics: "/analytics",
        reports: "/reports"
    };
    const explicitDestination = [finding.destination, finding.target_destination, finding.page]
        .find(value => typeof value === "string" && routes[value.trim().toLowerCase()]);
    if (explicitDestination) return routes[explicitDestination.trim().toLowerCase()];

    const normalize = value => typeof value === "string" ? value.trim().toLowerCase() : "";
    const categoryDestinations = {
        "cve vulnerabilities": "/vulnerabilities",
        vulnerability: "/vulnerabilities",
        "network exposure": "/port-hardening",
        firewall: "/port-hardening",
        "remediation defect": "/port-hardening",
        "remediation verification defects": "/port-hardening",
        "monitoring event": "/activity",
        "unrepresented monitoring events": "/activity",
        "system configuration": "/attack-surface"
    };
    const targetDestinations = {
        software: "/vulnerabilities",
        vulnerability: "/vulnerabilities",
        port: "/port-hardening",
        service: "/port-hardening",
        firewall: "/port-hardening",
        network: "/port-hardening",
        policy: "/attack-surface",
        configuration: "/attack-surface",
        monitoring: "/activity",
        monitoring_event: "/activity"
    };
    const category = normalize(finding.finding_category) || normalize(finding.category);
    if (categoryDestinations[category]) return categoryDestinations[category];

    const targetType = normalize(finding.target_type) || normalize(finding.target_kind);
    if (targetDestinations[targetType]) return targetDestinations[targetType];

    return "/attack-surface";
}

function findingEvidencePresentation(value) {
    let structured = null;
    let raw = "";
    if (typeof value === "string") {
        raw = value;
        const trimmed = value.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                structured = JSON.parse(trimmed);
            } catch (error) {
                structured = null;
            }
        }
    } else if (value && typeof value === "object") {
        structured = value;
    }

    if (!structured || typeof structured !== "object") {
        return { summary: raw, details: "" };
    }

    const entries = Array.isArray(structured)
        ? structured.map((item, index) => [`Evidence ${index + 1}`, item])
        : Object.entries(structured);
    const preferredKeys = ["summary", "message", "reason", "event_type", "target", "component", "verification_status"];
    const orderedEntries = [
        ...preferredKeys.filter(key => Object.prototype.hasOwnProperty.call(structured, key)).map(key => [key, structured[key]]),
        ...entries.filter(([key]) => !preferredKeys.includes(key))
    ];
    const summaryParts = orderedEntries
        .filter(([, item]) => typeof item === "string" || typeof item === "number" || typeof item === "boolean")
        .slice(0, 3)
        .map(([key, item]) => {
            const label = String(key).replace(/_/g, " ").replace(/\b\w/g, character => character.toUpperCase());
            const displayValue = key === "event_type" && typeof item === "string"
                ? item.replace(/_/g, " ").toLowerCase()
                : String(item);
            return `${label}: ${displayValue}`;
        });
    const details = JSON.stringify(structured, null, 2);
    return {
        summary: summaryParts.join(" · ") || "Structured evidence recorded.",
        details
    };
}

function renderAttentionFindings(findings, hasAssessment) {
    const container = document.getElementById("attention-list");
    if (!container) return;
    if (!hasAssessment) {
        container.innerHTML = `<p class="empty-state">No saved assessment is available yet. Run an assessment to see findings.</p>`;
        return;
    }
    if (!Array.isArray(findings)) {
        container.innerHTML = `<p class="empty-state">Priority findings could not be determined from the saved assessment data.</p>`;
        return;
    }
    const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4, P5: 5 };
    const active = findings
        .filter(finding => finding && typeof finding === "object" && !Array.isArray(finding))
        .filter(finding =>
            ["P1", "P2"].includes(finding.priority_code) &&
            !["Resolved", "Accepted Risk"].includes(finding.status)
        )
        .sort((a, b) =>
            (priorityOrder[a.priority_code] || 99) - (priorityOrder[b.priority_code] || 99) ||
            severityRank(b.severity) - severityRank(a.severity)
        )
        .slice(0, 3);
    if (active.length === 0) {
        container.innerHTML = `<p class="empty-state">No open P1 or P2 findings were recorded in the latest assessment.</p>`;
        return;
    }
    container.innerHTML = active.map(finding => {
        const text = value => typeof value === "string" || typeof value === "number" ? String(value) : "";
        const title = text(finding.title) || text(finding.id) || "Untitled finding";
        const evidence = findingEvidencePresentation(finding.evidence);
        const explanation = text(finding.risk_explanation) || text(finding.detail) || evidence.summary;
        const severity = (text(finding.severity) || "Unknown").toUpperCase();
        const status = text(finding.status) || "Status not recorded";
        const action = text(finding.recommended_action);
        return `
            <article class="attention-item">
                <div class="attention-item-main">
                    <div class="attention-title-row">
                        <h3>${escapeHTML(title)}</h3>
                        <span class="risk-tag ${riskLevelClass(severity)}">${escapeHTML(severity)}</span>
                    </div>
                    <p>${escapeHTML(explanation || "No additional explanation was recorded.")}</p>
                    ${action ? `<p class="attention-action"><strong>Suggested next step:</strong> ${escapeHTML(action)}</p>` : ""}
                    <span class="attention-status">Assessment status: ${escapeHTML(status)}</span>
                    ${evidence.details ? `<details class="finding-evidence-details"><summary>View evidence</summary><pre>${escapeHTML(evidence.details)}</pre></details>` : ""}
                </div>
                <a class="btn-secondary" href="${findingDestination(finding)}">View Details</a>
            </article>
        `;
    }).join("");
}

function severityRank(severity) {
    return ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1 })[
        String(severity || "").toUpperCase()
    ] || 0;
}

function renderOverviewSeverityChart(distribution) {
    const canvas = document.getElementById("overview-severity-chart");
    if (!canvas) return;
    if (analyticsChartInstances["overview-severity-chart"]) {
        analyticsChartInstances["overview-severity-chart"].destroy();
        delete analyticsChartInstances["overview-severity-chart"];
    }
    const keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
    if (!window.Chart) {
        setChartMessage("overview-severity-chart", "Chart library is unavailable; severity details remain available in the assessment findings.");
        return;
    }
    if (!distribution || typeof distribution !== "object" || Array.isArray(distribution)) {
        setChartMessage("overview-severity-chart", "No severity data is available in the latest assessment.");
        return;
    }
    if (!keys.every(key => Number.isSafeInteger(distribution[key]) && distribution[key] >= 0)) {
        setChartMessage("overview-severity-chart", "Severity data is incomplete in the latest assessment.");
        return;
    }
    const labels = ["Critical", "High", "Medium", "Low", "Informational"];
    const values = keys.map(key => distribution[key]);
    if (values.every(value => value === 0)) {
        setChartMessage("overview-severity-chart", "No findings were recorded in the latest assessment.");
        return;
    }
    setChartMessage("overview-severity-chart", "");
    analyticsChartInstances["overview-severity-chart"] = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: ["#f85149", "#ff7b72", "#d29922", "#3fb950", "#58a6ff"],
                borderColor: "#161b22",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            maintainAspectRatio: false,
            plugins: { legend: { position: "bottom", labels: { color: "#c9d1d9", padding: 14 } } }
        }
    });
}

function renderRecentActivity(events) {
    const body = document.getElementById("dashboard-recent-activity-body");
    if (!body) return;
    if (!Array.isArray(events)) {
        body.innerHTML = `<tr><td colspan="4">Recent activity is currently unavailable.</td></tr>`;
        return;
    }
    if (events.length === 0) {
        body.innerHTML = `<tr><td colspan="4">No monitoring events have been recorded.</td></tr>`;
        return;
    }
    body.innerHTML = events.map(event => {
        const description = event.description || event.event_type || "Monitoring event";
        const target = event.target ? ` · ${event.target}` : "";
        const state = event.is_resolved ? "Resolved" : "Unresolved";
        const workflow = [
            event.is_acknowledged ? "Acknowledged" : "",
            event.is_reviewed ? "Reviewed" : ""
        ].filter(Boolean).join(" · ");
        const status = workflow ? `${state} · ${workflow}` : state;
        const severity = String(event.severity || "Info").toUpperCase();
        return `<tr>
            <td>${escapeHTML(event.timestamp || "Time unavailable")}</td>
            <td>${escapeHTML(`${description}${target}`)}</td>
            <td><span class="risk-tag ${riskLevelClass(severity)}">${escapeHTML(severity)}</span></td>
            <td>${escapeHTML(status)}</td>
        </tr>`;
    }).join("");
}

async function refreshMonitoringSummary(scanData = null) {
    try {
        const response = await fetch("/api/monitoring/status");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const status = await response.json();
        if (!status || typeof status !== "object" || status.error) {
            throw new Error("Invalid monitoring status response.");
        }
        updateLiveStatusBar(status);
        if (scanData) {
            scanData.monitoring_unresolved_count = Number.isInteger(status.unresolved_events_count)
                ? status.unresolved_events_count
                : null;
        }
        return status;
    } catch (error) {
        dashboardMonitoringStatus = null;
        const statusText = document.getElementById("live-monitor-text");
        const lastCheck = document.getElementById("live-last-check");
        const pill = document.getElementById("live-unresolved-pill");
        if (statusText) statusText.textContent = "Monitoring status unavailable";
        if (lastCheck) lastCheck.textContent = "Unavailable";
        if (pill) {
            pill.textContent = "Alert count unavailable";
            pill.className = "badge-pill warning";
        }
        if (scanData) scanData.monitoring_unresolved_count = null;
        return null;
    }
}

async function loadRecentActivity() {
    try {
        const response = await fetch("/api/monitoring/events?limit=5");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const events = await response.json();
        if (!Array.isArray(events)) throw new Error("Invalid monitoring events response.");
        renderRecentActivity(events);
    } catch (error) {
        renderRecentActivity(null);
    }
}

async function loadLatestAssessment() {
    const historyResponse = await fetch("/api/history?limit=20");
    if (!historyResponse.ok) throw new Error(`Assessment history is unavailable (HTTP ${historyResponse.status}).`);
    const history = await historyResponse.json();
    if (!Array.isArray(history)) throw new Error("Assessment history returned an invalid response.");
    renderTrendChart(history);
    if (history.length === 0) {
        latestDashboardScanId = null;
        renderAttentionFindings([], false);
        renderOverviewSeverityChart(null);
        const riskNote = document.getElementById("summary-risk-note");
        if (riskNote) riskNote.textContent = "No saved assessment";
        const completeness = document.getElementById("scan-completeness-status");
        if (completeness) {
            completeness.textContent = "No saved assessment yet. Run an assessment to see the current security overview.";
            completeness.classList.add("warning");
        }
        return;
    }

    const response = await fetch(`/api/scan/${encodeURIComponent(history[0].id)}`);
    if (!response.ok) throw new Error(`The latest saved assessment could not be loaded (HTTP ${response.status}).`);
    const savedScan = await response.json();
    if (!savedScan || typeof savedScan !== "object" || !savedScan.full_results || typeof savedScan.full_results !== "object") {
        throw new Error("The latest saved assessment has an invalid response.");
    }
    const data = savedScan.full_results;
    data.scan_id = savedScan.id;
    data.assessment_timestamp = savedScan.scan_time;
    latestDashboardScanId = Number.isSafeInteger(savedScan.id) ? savedScan.id : null;
    renderDashboard(data);
}

async function refreshSavedAssessmentIfChanged() {
    if (assessmentRunning || dashboardAssessmentRefreshInProgress) return;
    dashboardAssessmentRefreshInProgress = true;
    try {
        const response = await fetch("/api/history?limit=1");
        if (!response.ok) throw new Error(`Assessment history is unavailable (HTTP ${response.status}).`);
        const history = await response.json();
        if (!Array.isArray(history)) throw new Error("Assessment history returned an invalid response.");
        const latestId = history[0] && Number.isSafeInteger(history[0].id) ? history[0].id : null;
        if (latestId !== null && latestId !== latestDashboardScanId) {
            await loadLatestAssessment();
        } else if (latestId === null && latestDashboardScanId !== null) {
            await loadLatestAssessment();
        }
    } catch (error) {
        console.warn("Unable to synchronize the latest saved assessment:", error);
    } finally {
        dashboardAssessmentRefreshInProgress = false;
    }
}

async function refreshLivePortCount() {
    try {
        const response = await fetch("/api/port-analysis");
        if (!response.ok) throw new Error(`Port analysis failed (HTTP ${response.status}).`);
        const analysis = await response.json();
        if (!analysis || !Array.isArray(analysis.ports) || !Number.isSafeInteger(analysis.total)) {
            throw new Error("Port analysis returned incomplete data.");
        }
        const count = document.getElementById("summary-listening-sockets");
        const note = count && count.parentElement.querySelector(".summary-note");
        if (count) count.textContent = String(analysis.total);
        if (note) note.textContent = "Current listening sockets; review exposure in Port Hardening";
    } catch (error) {
        console.warn("Unable to refresh the live listening-port count:", error);
    }
}

async function initializeDashboard() {
    const loading = document.getElementById("loading");
    const content = document.getElementById("dashboard-content");
    await refreshMonitoringSummary();
    const results = await Promise.allSettled([
        loadRecentActivity(),
        loadLatestAssessment(),
        loadSchedule()
    ]);
    const failed = results.find(result => result.status === "rejected");
    if (failed && loading) {
        loading.textContent = "Some saved dashboard data could not be loaded. Retry or run a new assessment.";
        loading.classList.remove("hidden");
        const completeness = document.getElementById("scan-completeness-status");
        if (completeness) {
            completeness.textContent = "Assessment data could not be loaded.";
            completeness.classList.add("warning");
        }
        renderAttentionFindings([], false);
    } else if (loading) {
        loading.classList.add("hidden");
    }
    if (content) content.classList.remove("hidden");
    initLiveMonitoring();
    refreshLivePortCount();
}

function renderSystemInfo(info) {
    const container = document.getElementById("system-info-grid");
    if (!container) return;
    if (!info || typeof info !== "object" || info.error) {
        container.innerHTML = `<div class="info-item">Unable to load system information${info && info.error ? `: ${escapeHTML(info.error)}` : "."}</div>`;
        return;
    }

    const os = info.os && typeof info.os === "object" ? info.os : {};
    const cpu = info.cpu && typeof info.cpu === "object" ? info.cpu : {};
    const ram = info.ram && typeof info.ram === "object" ? info.ram : {};
    const ramSummary = ram.error
        ? ram.error
        : `${ram.used_gb ?? "?"} GB / ${ram.total_gb ?? "?"} GB (${ram.usage_percent ?? "?"}%)`;
    const items = [
        ["Hostname", info.hostname],
        ["OS", `${os.os_name ?? "?"} ${os.os_release ?? ""}`.trim()],
        ["Architecture", os.architecture],
        ["CPU Cores", `${cpu.physical_cores ?? "?"} physical / ${cpu.logical_cores ?? "?"} logical`],
        ["CPU Usage", cpu.cpu_usage_percent == null ? "Unavailable" : `${cpu.cpu_usage_percent}%`],
        ["RAM", ramSummary],
        ["Uptime", info.uptime],
        ["Scan Time", info.scan_time],
    ];
    container.innerHTML = items.map(([label, value]) => `
        <div class="info-item">
            <span class="label">${escapeHTML(label)}</span>
            <span class="value">${escapeHTML(value ?? "Unavailable")}</span>
        </div>
    `).join("");
}

function renderFirewall(firewall) {
    const container = document.getElementById("firewall-status");
    if (!container) return;
    if (!firewall || typeof firewall !== "object" || firewall.error || !firewall.profiles) {
        const error = firewall && firewall.error ? `: ${escapeHTML(firewall.error)}` : ".";
        container.innerHTML = `<div class="info-item">Firewall status unknown${error}</div>`;
        return;
    }

    container.innerHTML = Object.entries(firewall.profiles).map(([profile, details]) => {
        const state = details && details.state ? String(details.state) : "UNKNOWN";
        const stateClass = state === "ON" ? "low" : state === "OFF" ? "high" : "medium";
        return `
            <div class="info-item">
                <span class="label">${escapeHTML(profile)} Profile</span>
                <span class="value risk-tag ${stateClass}">${escapeHTML(state)}</span>
            </div>
        `;
    }).join("");
}

function renderPorts(ports) {
    const tbody = document.querySelector("#ports-table tbody");
    const count = document.getElementById("ports-count");
    if (!tbody || !count) return;
    if (!Array.isArray(ports)) {
        count.textContent = "0";
        const error = ports && ports.error ? `: ${escapeHTML(ports.error)}` : ".";
        tbody.innerHTML = `<tr><td colspan="6">Unable to load ports${error}</td></tr>`;
        return;
    }

    count.textContent = String(ports.length);
    if (ports.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6">No listening ports found.</td></tr>`;
        return;
    }
    tbody.innerHTML = ports.map(port => `
        <tr>
            <td>${escapeHTML(port.port ?? "-")}</td>
            <td>${escapeHTML(port.protocol ?? "-")}</td>
            <td>${escapeHTML(port.local_address ?? "-")}</td>
            <td>${escapeHTML(port.process_name ?? "-")}</td>
            <td>${escapeHTML(port.pid ?? "-")}</td>
            <td>${escapeHTML(port.risk_note ?? "-")}</td>
        </tr>
    `).join("");
}

function renderServices(services) {
    const tbody = document.querySelector("#services-table tbody");
    const count = document.getElementById("services-count");
    if (!tbody || !count) return;
    if (!Array.isArray(services)) {
        count.textContent = "0";
        const error = services && services.error ? `: ${escapeHTML(services.error)}` : ".";
        tbody.innerHTML = `<tr><td colspan="5">Unable to load flagged services${error}</td></tr>`;
        return;
    }

    count.textContent = String(services.length);
    if (services.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5">No flagged services.</td></tr>`;
        return;
    }
    tbody.innerHTML = services.map(service => `
        <tr>
            <td>${escapeHTML(service.name ?? "-")}</td>
            <td>${escapeHTML(service.pid ?? "-")}</td>
            <td>${escapeHTML(service.status ?? "-")}</td>
            <td>${escapeHTML(Array.isArray(service.listening_ports) ? service.listening_ports.join(", ") : "-")}</td>
            <td>${escapeHTML(service.review_reason ?? "-")}</td>
        </tr>
    `).join("");
}

function riskLevelClass(level) {
    const normalized = String(level || "").toLowerCase();
    return ["low", "medium", "high", "critical", "safe", "info", "informational", "unknown"].includes(normalized)
        ? normalized
        : "unknown";
}

let currentFindingsList = [];
let activeFindingFilter = "ALL";

function renderRiskScore(risk) {
    if (!risk || typeof risk !== "object" || Array.isArray(risk) || risk.error) return;

    const score = typeof risk.total_score === "number" && Number.isFinite(risk.total_score)
        ? risk.total_score
        : null;
    const scoreElement = document.getElementById("risk-score-number");
    if (scoreElement) scoreElement.textContent = score === null ? "—" : String(score);

    const badge = document.getElementById("risk-level-badge");
    if (badge) {
        badge.textContent = risk.risk_level ? `${risk.risk_level} Risk` : "Risk level unavailable";
        badge.className = "badge " + riskLevelClass(risk.risk_level);
    }

    const bar = document.getElementById("risk-progress-bar");
    if (bar) bar.style.width = score === null ? "0%" : `${Math.max(0, Math.min(100, score))}%`;

    // Update Severity Distribution Pills
    const distribution = risk.severity_distribution;
    for (const [id, key, label] of [
        ["pill-critical", "CRITICAL", "Critical"],
        ["pill-high", "HIGH", "High"],
        ["pill-medium", "MEDIUM", "Medium"],
        ["pill-low", "LOW", "Low"],
        ["pill-info", "INFORMATIONAL", "Info"]
    ]) {
        const pill = document.getElementById(id);
        const count = distribution && Number.isSafeInteger(distribution[key]) && distribution[key] >= 0
            ? distribution[key]
            : null;
        if (pill) pill.textContent = count === null ? `${label}: unavailable` : `${count} ${label}`;
    }

    // Top Findings List
    const topListEl = document.getElementById("top-findings-list");
    if (topListEl) {
        if (!Array.isArray(risk.top_findings)) {
            topListEl.innerHTML = `<p class="empty-state">Priority concerns are unavailable for this assessment.</p>`;
        } else if (risk.top_findings.length === 0) {
            topListEl.innerHTML = `<p style="color: var(--low); font-size: 13px;">✓ No critical or high-risk attack-surface concerns identified.</p>`;
        } else {
            topListEl.innerHTML = risk.top_findings.map(item => `
                <div style="display:flex; align-items:flex-start; gap:8px; margin-bottom:8px; font-size:13px; color:#ff7b72;">
                    <span><strong>${escapeHTML(item && typeof item === "object" ? item.title || item.category || item.id || "Untitled finding" : item)}</strong></span>
                </div>
            `).join("");
        }
    }

    // Active Mitigations & Defenses
    const mitListEl = document.getElementById("mitigating-factors-list");
    if (mitListEl) {
        if (!Array.isArray(risk.mitigating_factors)) {
            mitListEl.innerHTML = `<li class="mitigation-item" style="color:var(--muted);">Mitigating controls are unavailable for this assessment.</li>`;
        } else if (risk.mitigating_factors.length === 0) {
            mitListEl.innerHTML = `<li class="mitigation-item" style="color:var(--muted);">No specific baseline mitigating controls recorded.</li>`;
        } else {
            mitListEl.innerHTML = risk.mitigating_factors.map(m => `
                <li class="mitigation-item">
                    <span class="icon">✓</span>
                    <span>${escapeHTML(m)}</span>
                </li>
            `).join("");
        }
    }

}

function filterAndRenderFindings() {
    const container = document.getElementById("findings-list");
    if (!container) return;

    if (!currentFindingsList || currentFindingsList.length === 0) {
        container.innerHTML = `<div class="finding-item">No security findings recorded.</div>`;
        return;
    }

    const text = value => typeof value === "string" || typeof value === "number" ? String(value) : "";
    const filtered = currentFindingsList
        .filter(f => f && typeof f === "object" && !Array.isArray(f))
        .filter(f => {
        const sev = (text(f.severity) || "INFORMATIONAL").toUpperCase();
        if (activeFindingFilter === "HIGH_CRITICAL") return sev === "CRITICAL" || sev === "HIGH";
        if (activeFindingFilter === "MEDIUM") return sev === "MEDIUM";
        if (activeFindingFilter === "LOW") return sev === "LOW";
        if (activeFindingFilter === "INFORMATIONAL") return sev === "INFORMATIONAL";
        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = `<div style="padding:16px; text-align:center; color:var(--muted); font-size:13px;">No findings match the selected filter.</div>`;
        return;
    }

    container.innerHTML = filtered.map(f => {
        const severity = text(f.severity) || "INFORMATIONAL";
        const sev = riskLevelClass(severity);
        const confidence = text(f.confidence) || "CONFIRMED";
        const confValue = confidence.toLowerCase();
        const conf = ["confirmed", "high", "medium", "potential", "unknown", "low"].includes(confValue) ? confValue : "unknown";
        const title = text(f.title) || [text(f.area), text(f.detail)].filter(Boolean).join(": ") || "Untitled finding";
        const evidence = findingEvidencePresentation(f.evidence);
        const reason = text(f.risk_explanation) || text(f.detail) || evidence.summary;
        const action = text(f.recommended_action);
        const impact = text(f.operational_impact);

        return `
            <div class="finding-card severity-${sev}">
                <div class="finding-header">
                    <div>
                        <span class="finding-title">${escapeHTML(title)}</span>
                        <span class="confidence-badge confidence-${conf}">${escapeHTML(confidence)}</span>
                    </div>
                    <span class="risk-tag ${sev}">${escapeHTML(severity.toUpperCase())}</span>
                </div>
                <div class="finding-body">${escapeHTML(reason || "No additional explanation was recorded.")}</div>
                <div class="finding-meta-grid">
                    ${evidence.details
                        ? `<details class="evidence-box finding-evidence-details"><summary>View structured evidence</summary><pre>${escapeHTML(evidence.details)}</pre></details>`
                        : evidence.summary ? `<div class="evidence-box"><span class="evidence-label">Observed Evidence</span>${escapeHTML(evidence.summary)}</div>` : ""}
                    ${impact ? `<div class="operational-impact-box"><span class="evidence-label" style="color:#d29922;">Operational Impact</span>${escapeHTML(impact)}</div>` : ""}
                </div>
                ${action ? `<div style="margin-top:8px; font-size:12px; color:var(--muted);"><strong>Recommended Action:</strong> ${escapeHTML(action)}</div>` : ""}
            </div>
        `;
    }).join("");
}

function renderFindings(findings) {
    currentFindingsList = Array.isArray(findings) ? findings : [];
    filterAndRenderFindings();

    // Hook up filter buttons once
    const filterGroup = document.getElementById("findings-filter-group");
    if (filterGroup && !filterGroup.dataset.initialized) {
        filterGroup.dataset.initialized = "true";
        filterGroup.querySelectorAll(".filter-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                filterGroup.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                activeFindingFilter = btn.dataset.filter || "ALL";
                filterAndRenderFindings();
            });
        });
    }
}

function renderRecommendations(recs) {
    const tbody = document.querySelector("#recommendations-table tbody");
    if (!tbody) return;

    if (!Array.isArray(recs) || recs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5">No recommendations available.</td></tr>`;
        return;
    }

    tbody.innerHTML = recs.map(r => {
        const priorityValue = Number(r.priority);
        const priority = Number.isInteger(priorityValue) && priorityValue >= 1 && priorityValue <= 5 ? priorityValue : 3;
        const sevClass = riskLevelClass(r.risk || "medium");
        const title = r.title || r.finding || "-";
        const impact = r.operational_impact || "Minimal operational disruption.";

        return `
            <tr>
                <td><span class="priority-pill priority-${priority}">P${priority}</span></td>
                <td>
                    <strong>${escapeHTML(title)}</strong>
                    <div style="font-size:11px; color:var(--muted); margin-top:2px;">${escapeHTML(r.finding || "")}</div>
                </td>
                <td><span class="risk-tag ${sevClass}">${escapeHTML(r.risk)}</span></td>
                <td>
                    <div>${escapeHTML(r.recommended_action)}</div>
                    <div style="font-size:11px; color:var(--muted); margin-top:4px;">${escapeHTML(r.reason || "")}</div>
                </td>
                <td style="font-size:12px; color:#e3b341;">${escapeHTML(impact)}</td>
            </tr>
        `;
    }).join("");
}

async function loadHistory() {
    try {
        const response = await fetch("/api/history?limit=20");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const history = await response.json();
        if (!Array.isArray(history)) throw new Error("Invalid scan history response.");
        renderTrendChart(history);
    } catch (err) {
        setChartMessage("trendChart", `Scan history unavailable: ${err.message}`);
    }
}

function renderTrendChart(history) {
    const ordered = Array.isArray(history)
        ? [...history].reverse().filter(scan =>
            scan && scan.risk_score !== null && scan.risk_score !== undefined && Number.isFinite(Number(scan.risk_score))
        )
        : [];
    if (ordered.length < 2) {
        if (trendChartInstance) {
            trendChartInstance.destroy();
            trendChartInstance = null;
        }
        setChartMessage("trendChart", Array.isArray(history) && history.length === 0
            ? "No stored assessment history is available yet."
            : "A historical trend will appear after at least two assessments with saved risk scores.");
        return;
    }
    if (!window.Chart) {
        setChartMessage("trendChart", "Chart library is unavailable; saved risk scores remain available in Assessment History.");
        return;
    }
    setChartMessage("trendChart", "");

    // Reverse so oldest is first (left) and newest is last (right) on the chart
    const labels = ordered.map(h => `#${h.id}`);
    const scores = ordered.map(h => h.risk_score);

    const ctx = document.getElementById("trendChart");

    if (trendChartInstance) {
        trendChartInstance.destroy();
    }

    trendChartInstance = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: "Risk score (0-100)",
                data: scores.map(Number),
                borderColor: "#58a6ff",
                backgroundColor: "rgba(88, 166, 255, 0.15)",
                fill: true,
                tension: 0.3,
                pointRadius: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, position: "bottom", labels: { color: "#c9d1d9" } },
                tooltip: { callbacks: { label: context => `Risk score: ${context.parsed.y}/100` } }
            },
            scales: {
                x: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } },
                y: {
                    min: 0, max: 100,
                    ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" }
                }
            }
        }
    });
}

// --- Real-Time Monitoring & SSE Event Handling ---
let eventSource = null;
let liveChangesData = [];
let monitoringPollTimer = null;
let liveMonitoringHealth = "STARTING";

function changeTypeClass(type) {
    if (type === "NEW") return "change-new";
    if (type === "REMOVED") return "change-removed";
    return "change-changed";
}

function updateLiveStatusBar(status) {
    if (!status) return;
    dashboardMonitoringStatus = status;
    liveMonitoringHealth = status.monitoring_health || (status.monitoring_active ? "UNKNOWN" : "STOPPED");
    const intervalDisplay = document.getElementById("live-interval-display");
    const lastCheck = document.getElementById("live-last-check");
    const unresolvedPill = document.getElementById("live-unresolved-pill");
    const monitorText = document.getElementById("live-monitor-text");

    if (intervalDisplay && status.interval_seconds) {
        intervalDisplay.textContent = status.interval_seconds + "s";
    }
    if (lastCheck) {
        lastCheck.textContent = status.last_successful_check_time || "No successful check yet";
    }
    if (unresolvedPill) {
        const count = status.unresolved_events_count;
        unresolvedPill.textContent = Number.isInteger(count) ? `${count} Unresolved Alerts` : "Alert count unavailable";
        unresolvedPill.className = "badge-pill " + (count === 0 ? "success" : (count > 3 ? "danger" : "warning"));
    }
    if (monitorText) {
        const labels = {
            HEALTHY: "Live Monitoring Healthy",
            DEGRADED: "Monitoring Degraded",
            STALE: "Monitoring Stale",
            STOPPED: "Monitoring Paused",
            STARTING: "Monitoring Starting",
        };
        monitorText.textContent = labels[status.monitoring_health] ||
            (status.monitoring_active ? "Monitoring Health Unknown" : "Monitoring Paused");
    }
}

function setChartMessage(canvasId, message) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const messageId = `${canvasId}-message`;
    let element = document.getElementById(messageId);
    if (!element) {
        element = document.createElement("p");
        element.id = messageId;
        element.className = "hint-text";
        canvas.insertAdjacentElement("afterend", element);
    }
    element.textContent = message;
    element.classList.toggle("hidden", !message);
}

function drawAnalyticsChart(canvasId, type, values, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !window.Chart) return;
    if (analyticsChartInstances[canvasId]) {
        analyticsChartInstances[canvasId].destroy();
        delete analyticsChartInstances[canvasId];
    }
    const labels = values && typeof values === "object" && !Array.isArray(values)
        ? Object.keys(values)
        : [];
    if (labels.length === 0) {
        setChartMessage(canvasId, "No stored data is available for this chart.");
        return;
    }
    setChartMessage(canvasId, "");
    analyticsChartInstances[canvasId] = new Chart(canvas, {
        type,
        data: {
            labels,
            datasets: [{
                label: "Stored records",
                data: labels.map(label => values[label]),
                backgroundColor: colors,
                borderColor: "#58a6ff",
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: type === "doughnut" } },
            scales: type === "bar" ? {
                x: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } },
                y: { beginAtZero: true, ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } }
            } : {}
        }
    });
}

async function loadAnalytics() {
    try {
        const response = await fetch("/api/analytics");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data || typeof data !== "object" || data.error) {
            throw new Error(data && data.error ? data.error : "Invalid analytics response.");
        }
        drawAnalyticsChart("analytics-severity-chart", "doughnut", data.severity_distribution);
        drawAnalyticsChart("analytics-category-chart", "bar", data.finding_categories);
        drawAnalyticsChart("analytics-remediation-chart", "doughnut", data.remediation_outcomes);
        drawAnalyticsChart("analytics-attack-chart", "bar", data.attack_surface_changes);
        drawAnalyticsChart("analytics-vulnerability-chart", "bar", data.vulnerability_findings_by_day);
        renderVulnerabilitySummary(data.vulnerability_summary);
        const method = document.getElementById("analytics-methodology");
        if (method) method.textContent = data.methodology?.limitations || "No historical assessment data is currently available.";
    } catch (error) {
        for (const canvasId of [
            "analytics-severity-chart",
            "analytics-category-chart",
            "analytics-remediation-chart",
            "analytics-attack-chart",
            "analytics-vulnerability-chart",
        ]) {
            if (analyticsChartInstances[canvasId]) {
                analyticsChartInstances[canvasId].destroy();
                delete analyticsChartInstances[canvasId];
            }
            setChartMessage(canvasId, `Analytics unavailable: ${error.message}`);
        }
        const method = document.getElementById("analytics-methodology");
        if (method) method.textContent = `Analytics could not be loaded: ${error.message}`;
    }
}

function renderVulnerabilitySummary(summary) {
    const container = document.getElementById("vulnerability-analytics-summary");
    if (!container) return;
    if (!summary || typeof summary !== "object") {
        container.textContent = "Vulnerability metrics are unavailable.";
        return;
    }
    const currentActive = summary.currently_active_findings == null
        ? "Unavailable (latest assessment is missing or incomplete)"
        : summary.currently_active_findings;
    container.textContent =
        `Unique CVEs: ${summary.unique_cves ?? 0} · ` +
        `Affected software/CVE pairs: ${summary.unique_affected_software_cve_pairs ?? 0} · ` +
        `Stored observations: ${summary.stored_observations ?? 0} ` +
        `(${summary.repeated_observations ?? 0} repeated) · ` +
        `Confirmed pairs: ${summary.confirmed_software_cve_pairs ?? 0} · ` +
        `Potential pairs: ${summary.potential_software_cve_pairs ?? 0} · ` +
        `Currently active: ${currentActive} · ` +
        `Latest assessment: ${summary.current_assessment_state || "NO_ASSESSMENT"}`;
}

async function loadAlerts() {
    const body = document.getElementById("alerts-body");
    if (!body) return;
    const severity = document.getElementById("alert-severity-filter")?.value || "";
    try {
        const response = await fetch(`/api/monitoring/events?limit=100${severity ? `&severity=${encodeURIComponent(severity)}` : ""}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const events = await response.json();
        if (!events.length) {
            body.innerHTML = `<tr><td colspan="7">No stored alerts match this filter.</td></tr>`;
            return;
        }
        body.innerHTML = events.map(event => `
            <tr>
                <td>${escapeHTML(event.timestamp)}</td>
                <td>${escapeHTML(event.severity)}</td>
                <td>${escapeHTML(event.event_type)}</td>
                <td>${escapeHTML(event.target)}</td>
                <td>${escapeHTML(event.details_parsed ? JSON.stringify(event.details_parsed) : event.details)}</td>
                <td>${event.is_resolved ? "Resolved" : "Active"}${event.is_acknowledged ? " · Acknowledged" : ""}${event.is_reviewed ? " · Reviewed" : ""}</td>
                <td>
                    <a href="#findings-list">Open findings</a>
                    ${event.is_acknowledged ? "" : `<button type="button" data-alert-action="acknowledge" data-event-id="${Number(event.id)}">Acknowledge</button>`}
                    ${event.is_reviewed ? "" : `<button type="button" data-alert-action="review" data-event-id="${Number(event.id)}">Mark reviewed</button>`}
                </td>
            </tr>
        `).join("");
    } catch (error) {
        body.innerHTML = `<tr><td colspan="7">Unable to load alerts: ${escapeHTML(error.message)}</td></tr>`;
    }
}

async function loadSchedule() {
    const status = document.getElementById("schedule-status");
    try {
        const response = await fetch("/api/schedule");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const schedule = await response.json();
        document.getElementById("schedule-enabled").checked = schedule.enabled;
        document.getElementById("schedule-interval").value = schedule.interval_minutes;
        document.getElementById("schedule-refresh-vulns").checked = schedule.refresh_vulnerabilities;
        document.getElementById("schedule-report").checked = schedule.generate_report;
        document.querySelectorAll("[name='schedule-category']").forEach(input => {
            input.checked = (schedule.categories || []).includes(input.value);
        });
        status.textContent = schedule.enabled
            ? `Next assessment: ${schedule.next_run || "pending"} · Last run: ${schedule.last_run || "not run"}${schedule.last_error ? ` · Last error: ${schedule.last_error}` : ""}`
            : "Scheduling is disabled.";
    } catch (error) {
        status.textContent = `Schedule settings could not be loaded: ${error.message}`;
    }
}

document.getElementById("refresh-alerts-btn")?.addEventListener("click", loadAlerts);
document.getElementById("alert-severity-filter")?.addEventListener("change", loadAlerts);
document.getElementById("alerts-body")?.addEventListener("click", async event => {
    const button = event.target.closest("button[data-alert-action]");
    if (!button) return;
    const eventId = Number(button.dataset.eventId);
    const action = button.dataset.alertAction;
    try {
        const response = await fetch(`/api/monitoring/events/${eventId}/${action}`, { method: "POST" });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
        loadAlerts();
    } catch (error) {
        window.alert(`Alert update failed: ${error.message}`);
    }
});

document.getElementById("schedule-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const categories = Array.from(document.querySelectorAll("[name='schedule-category']:checked"), input => input.value);
    const status = document.getElementById("schedule-status");
    try {
        const response = await fetch("/api/schedule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                enabled: document.getElementById("schedule-enabled").checked,
                interval_minutes: Number(document.getElementById("schedule-interval").value),
                categories,
                refresh_vulnerabilities: document.getElementById("schedule-refresh-vulns").checked,
                generate_report: document.getElementById("schedule-report").checked
            })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
        status.textContent = result.enabled
            ? `Schedule saved. Next assessment: ${result.next_run}`
            : "Schedule disabled.";
    } catch (error) {
        status.textContent = `Schedule update failed: ${error.message}`;
    }
});

function showLiveAlert(change) {
    const container = document.getElementById("live-alert-container");
    if (!container) return;

    const banner = document.createElement("div");
    const isWarning = change.severity === "HIGH" || change.severity === "CRITICAL";
    banner.className = `live-alert-banner ${isWarning ? "" : (change.severity === "MEDIUM" ? "warning" : "info")}`;

    banner.innerHTML = `
        <div style="display:flex; align-items:center; gap:12px;">
            <span style="font-size:18px;">${isWarning ? "⚠️" : "🔔"}</span>
            <div>
                <strong>${escapeHTML(change.title || "Attack Surface Event")}</strong>
                <div style="font-size:12px; opacity:0.9;">${escapeHTML(change.description || "")}</div>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:10px;">
            <span style="font-size:11px; opacity:0.7;">${escapeHTML(change.timestamp || "Just now")}</span>
            <button onclick="this.parentElement.parentElement.remove()" style="background:none; border:none; color:inherit; cursor:pointer; font-weight:bold; font-size:16px;">&times;</button>
        </div>
    `;

    container.prepend(banner);

    // Auto-dismiss mild alerts after 10s, keep critical alerts
    if (!isWarning) {
        setTimeout(() => {
            if (banner.parentElement) banner.remove();
        }, 10000);
    }
}

function renderLiveChangesTable(changes) {
    const tbody = document.getElementById("live-changes-body");
    if (!tbody) return;

    if (liveMonitoringHealth !== "HEALTHY") {
        const message = liveMonitoringHealth === "DEGRADED"
            ? "Monitoring is degraded; current changes are not shown as complete."
            : liveMonitoringHealth === "STALE"
                ? "Monitoring is stale; current changes are unavailable."
                : liveMonitoringHealth === "STOPPED"
                    ? "Monitoring is paused; current changes are unavailable."
                    : "Monitoring has not produced a healthy sample; current changes are unavailable.";
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:16px;">${escapeHTML(message)}</td></tr>`;
        return;
    }

    if (!changes || changes.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:16px;">Baseline established. No new changes detected.</td></tr>`;
        return;
    }

    tbody.innerHTML = changes.map(c => {
        const resolved = Boolean(c.is_resolved) || c.change_type === "REMOVED";
        return `
            <tr>
                <td>${escapeHTML(c.timestamp || "-")}</td>
                <td><span class="change-tag ${changeTypeClass(c.change_type)}">${escapeHTML(c.change_type)}</span></td>
                <td><strong>${escapeHTML(c.component ? c.component.toUpperCase() : "-")}</strong></td>
                <td><code>${escapeHTML(c.target || "-")}</code></td>
                <td><span class="risk-tag ${riskLevelClass(c.severity || "info")}">${escapeHTML(c.severity || "INFO")}</span></td>
                <td>${escapeHTML(c.description || (c.details ? JSON.stringify(c.details) : "-"))}</td>
                <td><span class="status-badge ${resolved ? "status-open" : "status-blocked"}">${resolved ? "Resolved" : "Active"}</span></td>
            </tr>
        `;
    }).join("");
}

async function fetchLiveChangesManually() {
    try {
        const response = await fetch("/api/attack-surface/changes");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data || typeof data !== "object" || data.error) {
            throw new Error(data && data.error ? data.error : "Invalid monitoring response.");
        }
        updateLiveStatusBar({
            monitoring_active: data.monitoring_active,
            monitoring_health: data.monitoring_health,
            interval_seconds: data.interval_seconds,
            last_check_time: data.last_check_time,
            last_successful_check_time: data.last_successful_check_time,
            unresolved_events_count: data.unresolved_count,
        });
        liveChangesData = liveMonitoringHealth === "HEALTHY" && Array.isArray(data.changes)
            ? data.changes
            : [];
        renderLiveChangesTable(liveChangesData);
    } catch (error) {
        const monitorText = document.getElementById("live-monitor-text");
        if (monitorText) monitorText.textContent = `Monitoring unavailable: ${error.message}`;
        liveChangesData = [];
        const tbody = document.getElementById("live-changes-body");
        if (tbody) tbody.innerHTML = `<tr><td colspan="7">Monitoring data unavailable. Last successful check: ${escapeHTML(document.getElementById("live-last-check")?.textContent || "unknown")}.</td></tr>`;
    }
}

function initLiveMonitoring() {
    if (!!window.EventSource) {
        try {
            eventSource = new EventSource("/api/monitoring/stream");

            eventSource.onmessage = function(e) {
                try {
                    const payload = JSON.parse(e.data);
                    if (payload.type === "init") {
                        updateLiveStatusBar(payload.data);
                        if (liveMonitoringHealth === "HEALTHY" && payload.data && payload.data.recent_changes) {
                            liveChangesData = payload.data.recent_changes;
                        } else {
                            liveChangesData = [];
                        }
                        renderLiveChangesTable(liveChangesData);
                    } else if (payload.type === "heartbeat") {
                        updateLiveStatusBar({
                            monitoring_active: true,
                            monitoring_health: payload.monitoring_health || "HEALTHY",
                            last_check_time: payload.last_check_time,
                            last_successful_check_time: payload.last_successful_check_time,
                            unresolved_events_count: payload.unresolved_count,
                        });
                        renderLiveChangesTable(liveChangesData);
                    } else if (payload.type === "change") {
                        const change = payload.data;
                        showLiveAlert(change);
                        liveChangesData.unshift(change);
                        renderLiveChangesTable(liveChangesData);
                        updateLiveStatusBar({
                            monitoring_active: true,
                            monitoring_health: payload.monitoring_health || "HEALTHY",
                            last_check_time: payload.last_check_time,
                            last_successful_check_time: payload.last_successful_check_time,
                            unresolved_events_count: payload.unresolved_count,
                        });
                        if (payload.unresolved_count !== undefined) {
                            const unresolvedPill = document.getElementById("live-unresolved-pill");
                            if (unresolvedPill) {
                                unresolvedPill.textContent = `${payload.unresolved_count} Unresolved Alerts`;
                                unresolvedPill.className = "badge-pill " + (payload.unresolved_count === 0 ? "success" : "warning");
                            }
                        }
                        loadRecentActivity();
                        refreshLivePortCount();
                    } else if (payload.type === "remediation") {
                        refreshMonitoringSummary();
                        loadRecentActivity();
                        refreshLivePortCount();
                        refreshSavedAssessmentIfChanged();
                    }
                } catch (err) {
                    console.error("Error parsing SSE stream message:", err);
                }
            };

            eventSource.onerror = function() {
                // If SSE drops, fallback to periodic polling
                console.warn("SSE connection dropped, falling back to polling");
                eventSource.close();
                if (!monitoringPollTimer) {
                    fetchLiveChangesManually();
                    monitoringPollTimer = setInterval(fetchLiveChangesManually, 5000);
                }
            };
        } catch (err) {
            console.warn("EventSource initialization failed:", err);
            if (!monitoringPollTimer) {
                fetchLiveChangesManually();
                monitoringPollTimer = setInterval(fetchLiveChangesManually, 5000);
            }
        }
    } else {
        if (!monitoringPollTimer) {
            fetchLiveChangesManually();
            monitoringPollTimer = setInterval(fetchLiveChangesManually, 5000);
        }
    }

    const refreshBtn = document.getElementById("live-refresh-btn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", fetchLiveChangesManually);
    }
}

// --- Phase 3: Verified Remediation Dashboard ---
async function loadDashboardRemediations() {
    const tableBody = document.getElementById("dashboard-remediation-body");
    if (!tableBody) return;

    try {
        const response = await fetch("/api/remediation-history?limit=25");
        const history = await response.json();

        if (!Array.isArray(history) || history.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--muted); padding:16px;">No remediation actions taken yet.</td></tr>`;
            return;
        }

        let resolved = 0;
        let partial = 0;
        let unresolved = 0;
        let totalReduction = 0;

        history.forEach(h => {
            const vStatus = (h.verification_status || "").toUpperCase();
            if (vStatus === "RESOLVED") resolved++;
            else if (vStatus === "PARTIALLY_RESOLVED") partial++;
            else if (vStatus === "UNRESOLVED" || h.status === "FAILED") unresolved++;

            if (h.before_risk_score != null && h.after_risk_score != null) {
                const diff = h.before_risk_score - h.after_risk_score;
                if (diff > 0) totalReduction += diff;
            }
        });

        const elResolved = document.getElementById("rem-resolved-count");
        const elPartial = document.getElementById("rem-partial-count");
        const elUnresolved = document.getElementById("rem-unresolved-count");
        const elReduction = document.getElementById("rem-score-reduction");

        if (elResolved) elResolved.textContent = resolved;
        if (elPartial) elPartial.textContent = partial;
        if (elUnresolved) elUnresolved.textContent = unresolved;
        if (elReduction) elReduction.textContent = `${totalReduction} pts`;

        tableBody.innerHTML = history.map(h => {
            const vStatus = h.verification_status || "UNVERIFIED";
            let verClass = "low";
            if (vStatus === "RESOLVED") verClass = "safe";
            else if (vStatus === "PARTIALLY_RESOLVED") verClass = "medium";
            else if (vStatus === "UNRESOLVED") verClass = "high";

            let scoreDiff = "-";
            if (h.before_risk_score != null && h.after_risk_score != null) {
                const diff = h.before_risk_score - h.after_risk_score;
                const sign = diff > 0 ? `-${diff}` : `+${Math.abs(diff)}`;
                scoreDiff = `${h.before_risk_score} → ${h.after_risk_score} (${sign})`;
            } else if (h.before_risk_score != null) {
                scoreDiff = `${h.before_risk_score} → ?`;
            }

            let exposureNote = "-";
            if (h.port) {
                if (vStatus === "PARTIALLY_RESOLVED") {
                    exposureNote = `<span style="color:#58a6ff;">Traffic Blocked</span> (Socket Listening)`;
                } else if (vStatus === "RESOLVED") {
                    exposureNote = `<span style="color:#3fb950;">Closed / Neutralized</span>`;
                } else {
                    exposureNote = `Network Accessible`;
                }
            } else if (h.action_type && h.action_type.includes("SERVICE")) {
                exposureNote = h.new_state ? `Service ${escapeHTML(h.new_state)}` : "Service Controlled";
            }

            return `
                <tr>
                    <td style="font-size:12px;">${escapeHTML(h.timestamp)}</td>
                    <td><strong>${escapeHTML(h.action_type)}</strong></td>
                    <td>${escapeHTML(h.target_name || h.target || "-")}</td>
                    <td><code>${escapeHTML(h.previous_state ?? "-")}</code> → <code>${escapeHTML(h.new_state ?? "-")}</code></td>
                    <td style="font-size:12px;">${exposureNote}</td>
                    <td style="font-size:12px;">${escapeHTML(scoreDiff)}</td>
                    <td><span class="risk-tag ${riskLevelClass(verClass)}">${escapeHTML(vStatus)}</span></td>
                    <td><span class="risk-tag ${h.status === "SUCCESS" ? "safe" : "high"}">${escapeHTML(h.status)}</span></td>
                </tr>
            `;
        }).join("");

    } catch (err) {
        console.error("Failed to load dashboard remediations:", err);
        tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--high); padding:16px;">Failed to load remediation records: ${escapeHTML(err.message)}</td></tr>`;
    }
}

document.getElementById("rescan-btn").addEventListener("click", runScan);
initializeDashboard();
window.setInterval(() => {
    refreshMonitoringSummary();
    loadRecentActivity();
    refreshSavedAssessmentIfChanged();
    refreshLivePortCount();
}, 30000);
