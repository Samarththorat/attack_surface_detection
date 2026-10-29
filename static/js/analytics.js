const analyticsCharts = {};
const analyticsColors = ["#f85149", "#ff7b72", "#d29922", "#3fb950", "#58a6ff", "#a371f7"];

function showChartMessage(canvasId, message) {
    const element = document.getElementById(`${canvasId}-message`);
    if (element) element.textContent = message;
}

function renderObjectChart(canvasId, values, type = "bar") {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const labels = values && typeof values === "object" && !Array.isArray(values)
        ? Object.keys(values)
        : [];
    if (!window.Chart) {
        showChartMessage(canvasId, "Charts are unavailable in this browser session.");
        return;
    }
    if (!labels.length || labels.every(label => Number(values[label]) === 0)) {
        showChartMessage(canvasId, "No stored data is available for this chart.");
        return;
    }
    showChartMessage(canvasId, "");
    analyticsCharts[canvasId] = new Chart(canvas, {
        type,
        data: {
            labels,
            datasets: [{
                label: "Stored records",
                data: labels.map(label => Number(values[label]) || 0),
                backgroundColor: labels.map((_, index) => analyticsColors[index % analyticsColors.length]),
                borderColor: "#30363d",
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: type === "doughnut", position: "bottom", labels: { color: "#c9d1d9" } } },
            scales: type === "bar" ? {
                x: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } },
                y: { beginAtZero: true, ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } }
            } : {}
        }
    });
}

function renderRiskTrend(records) {
    const canvas = document.getElementById("analytics-risk-chart");
    if (!canvas) return;
    if (!Array.isArray(records) || records.length < 2) {
        showChartMessage("analytics-risk-chart", "A historical risk trend appears after at least two saved assessments.");
        return;
    }
    if (!window.Chart) {
        showChartMessage("analytics-risk-chart", "Charts are unavailable in this browser session.");
        return;
    }
    const points = records.filter(record =>
        record && record.score !== null && record.score !== undefined && Number.isFinite(Number(record.score))
    );
    if (points.length < 2) {
        showChartMessage("analytics-risk-chart", "There are not enough saved risk scores to show a trend.");
        return;
    }
    showChartMessage("analytics-risk-chart", "");
    analyticsCharts["analytics-risk-chart"] = new Chart(canvas, {
        type: "line",
        data: {
            labels: points.map(point => point.timestamp || `Assessment #${point.scan_id}`),
            datasets: [{
                label: "Risk score",
                data: points.map(point => Number(point.score)),
                borderColor: "#58a6ff",
                backgroundColor: "rgba(88, 166, 255, .16)",
                fill: true,
                tension: 0.2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: "#c9d1d9" } } },
            scales: {
                x: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } },
                y: { min: 0, max: 100, ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } }
            }
        }
    });
}

function renderAssessmentHistory(history) {
    const body = document.getElementById("assessment-history-body");
    const message = document.getElementById("assessment-history-message");
    if (!body) return;
    if (!Array.isArray(history)) {
        body.innerHTML = `<tr><td colspan="7">Saved assessment history is unavailable.</td></tr>`;
        if (message) message.textContent = "History could not be loaded.";
        return;
    }
    if (history.length === 0) {
        body.innerHTML = `<tr><td colspan="7">No saved assessments are available yet.</td></tr>`;
        if (message) message.textContent = "";
        return;
    }
    if (message) message.textContent = "";

    body.innerHTML = history.map(record => {
        if (!record || typeof record !== "object" || Array.isArray(record)) return "";
        const level = typeof record.risk_level === "string" ? record.risk_level : "Unknown";
        const levelClass = ["low", "medium", "high", "critical", "informational"]
            .includes(level.toLowerCase()) ? level.toLowerCase() : "unknown";
        return `<tr>
            <td>${escapeHTML(record.id ?? "Unavailable")}</td>
            <td>${escapeHTML(record.scan_time ?? "Unavailable")}</td>
            <td>${escapeHTML(record.listening_ports_count ?? "Unavailable")}</td>
            <td>${escapeHTML(record.findings_count ?? "Unavailable")}</td>
            <td>${escapeHTML(record.firewall_status ?? "Unavailable")}</td>
            <td>${escapeHTML(record.risk_score ?? "Unavailable")}</td>
            <td><span class="risk-tag ${levelClass}">${escapeHTML(level)}</span></td>
        </tr>`;
    }).join("");
    if (!body.innerHTML) body.innerHTML = `<tr><td colspan="7">No valid assessment records were returned.</td></tr>`;
}

function getRiskBreakdownItems(risk) {
    if (!risk || typeof risk !== "object" || Array.isArray(risk)) {
        return { items: null, error: "Risk breakdown data is unavailable." };
    }

    let items;
    if (Object.prototype.hasOwnProperty.call(risk, "breakdown_items")) {
        items = risk.breakdown_items;
        if (!Array.isArray(items)) {
            return { items: null, error: "Risk breakdown data has an unexpected format." };
        }
        if (risk.breakdown_error) {
            return { items, error: String(risk.breakdown_error) };
        }
    } else if (Array.isArray(risk.breakdown)) {
        items = risk.breakdown;
    } else if (risk.breakdown && typeof risk.breakdown === "object" && Array.isArray(risk.breakdown.items)) {
        items = risk.breakdown.items;
    } else {
        return { items: null, error: "Risk breakdown data is missing or invalid." };
    }

    if (items.some(item =>
        !item || typeof item !== "object" || Array.isArray(item) ||
        typeof item.category !== "string" ||
        !Number.isFinite(Number(item.points_awarded))
    )) {
        return { items: null, error: "Risk breakdown contains an invalid category entry." };
    }
    return { items, error: null };
}

function renderLatestRiskDetails(risk) {
    const riskAvailable = risk && typeof risk === "object" && !Array.isArray(risk);
    const score = typeof risk?.total_score === "number" && Number.isFinite(risk.total_score)
        ? risk.total_score
        : null;
    const scoreElement = document.getElementById("analytics-risk-score");
    const levelElement = document.getElementById("analytics-risk-level");
    const progress = document.getElementById("analytics-risk-progress");
    if (scoreElement) scoreElement.textContent = score === null ? "Unavailable" : String(score);
    if (levelElement) {
        const level = typeof risk?.risk_level === "string" ? risk.risk_level : "Unknown";
        const levelClass = ["low", "medium", "high", "critical", "informational"]
            .includes(level.toLowerCase()) ? level.toLowerCase() : "unknown";
        levelElement.textContent = level === "Unknown" ? "Risk level unavailable" : `${level} Risk`;
        levelElement.className = `badge ${levelClass}`;
    }
    if (progress) progress.style.width = score === null ? "0%" : `${Math.max(0, Math.min(100, score))}%`;

    const distribution = risk && typeof risk === "object" ? risk.severity_distribution : null;
    const pills = [
        ["analytics-pill-critical", "CRITICAL", "Critical"],
        ["analytics-pill-high", "HIGH", "High"],
        ["analytics-pill-medium", "MEDIUM", "Medium"],
        ["analytics-pill-low", "LOW", "Low"],
        ["analytics-pill-info", "INFORMATIONAL", "Info"]
    ];
    for (const [id, key, label] of pills) {
        const element = document.getElementById(id);
        const count = distribution && Number.isSafeInteger(distribution[key]) && distribution[key] >= 0
            ? distribution[key]
            : null;
        if (element) element.textContent = count === null ? `${label}: unavailable` : `${count} ${label}`;
    }

    const topFindings = document.getElementById("analytics-risk-top-findings");
    if (topFindings) {
        const findings = Array.isArray(risk?.top_findings) ? risk.top_findings : [];
        topFindings.innerHTML = !riskAvailable
            ? `<p class="empty-state">No saved assessment risk details are available yet.</p>`
            : findings.length
            ? findings.map(finding => {
                if (!finding || typeof finding !== "object" || Array.isArray(finding)) return "";
                const title = finding.title || finding.category || finding.id || "Untitled finding";
                const severity = typeof finding.severity === "string" ? finding.severity : "Unknown";
                return `<div class="finding-item"><strong>${escapeHTML(title)}</strong> <span class="risk-tag ${["low", "medium", "high", "critical"].includes(severity.toLowerCase()) ? severity.toLowerCase() : "unknown"}">${escapeHTML(severity)}</span></div>`;
            }).join("") || `<p class="empty-state">No priority findings were recorded.</p>`
            : `<p class="empty-state">No priority findings were recorded.</p>`;
    }

    const mitigations = document.getElementById("analytics-risk-mitigations");
    if (mitigations) {
        const factors = Array.isArray(risk?.mitigating_factors) ? risk.mitigating_factors : [];
        mitigations.innerHTML = !riskAvailable
            ? `<li class="mitigation-item">No saved assessment risk details are available yet.</li>`
            : factors.length
            ? factors.map(factor => `<li class="mitigation-item"><span>${escapeHTML(factor)}</span></li>`).join("")
            : `<li class="mitigation-item">No mitigating controls were recorded.</li>`;
    }

    const chartId = "analytics-risk-breakdown-chart";
    const canvas = document.getElementById(chartId);
    if (!canvas) return;
    if (analyticsCharts[chartId] && typeof analyticsCharts[chartId].destroy === "function") {
        analyticsCharts[chartId].destroy();
    }
    delete analyticsCharts[chartId];
    const message = document.getElementById(`${chartId}-message`);
    if (!riskAvailable) {
        if (message) message.textContent = "No saved assessment risk details are available yet.";
        return;
    }
    const breakdown = getRiskBreakdownItems(risk);
    if (breakdown.error || !breakdown.items.length) {
        if (message) message.textContent = breakdown.error || "No risk category breakdown was recorded.";
        return;
    }
    if (!window.Chart) {
        if (message) message.textContent = "Charts are unavailable in this browser session.";
        return;
    }
    if (message) message.textContent = "";
    const items = breakdown.items;
    const values = items.map(item => Number(item.points_awarded));
    analyticsCharts[chartId] = new Chart(canvas, {
        type: "bar",
        data: {
            labels: items.map(item => item.category),
            datasets: [{
                label: "Points awarded",
                data: values,
                backgroundColor: values.map(value => value >= 15 ? "#f85149" : value >= 8 ? "#d29922" : value > 0 ? "#58a6ff" : "#30363d"),
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: context => {
                            const item = items[context.dataIndex];
                            return item
                                ? `Points: ${item.points_awarded}/${item.max_points ?? "?"} — ${item.reason || item.category}`
                                : "Risk breakdown details are unavailable.";
                        }
                    }
                }
            },
            scales: {
                x: { ticks: { color: "#c9d1d9", font: { size: 11 } }, grid: { color: "#30363d" } },
                y: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" }, beginAtZero: true, max: 30 }
            }
        }
    });
}

async function loadAssessmentHistory() {
    const body = document.getElementById("assessment-history-body");
    const message = document.getElementById("assessment-history-message");
    if (!body) return;
    try {
        const response = await fetch("/api/history?limit=100");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const history = await response.json();
        renderAssessmentHistory(history);
        return history;
    } catch (error) {
        body.innerHTML = `<tr><td colspan="7">Saved assessment history could not be loaded.</td></tr>`;
        if (message) message.textContent = `History unavailable: ${error.message}`;
        return null;
    }
}

async function loadLatestAssessmentDetails(history) {
    if (!Array.isArray(history) || history.length === 0 || !Number.isSafeInteger(Number(history[0]?.id))) {
        renderLatestRiskDetails(null);
        return;
    }
    try {
        const response = await fetch(`/api/scan/${encodeURIComponent(history[0].id)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const savedScan = await response.json();
        if (!savedScan || typeof savedScan !== "object" || !savedScan.full_results || typeof savedScan.full_results !== "object") {
            throw new Error("Invalid saved assessment response.");
        }
        renderLatestRiskDetails(savedScan.full_results.risk);
    } catch (error) {
        renderLatestRiskDetails(null);
        const message = document.getElementById("analytics-risk-breakdown-chart-message");
        if (message) message.textContent = `Latest risk details unavailable: ${error.message}`;
    }
}

function deltaClass(value, lowerIsBetter = true) {
    if (value === null || value === undefined || value === 0) return "unchanged";
    return (lowerIsBetter ? value < 0 : value > 0) ? "improved" : "worsened";
}

function renderComparison(data) {
    const container = document.getElementById("compare-results");
    if (!container) return;
    if (!data || typeof data !== "object" || !data.before || !data.after || !data.delta) {
        container.textContent = "Assessment comparison data is unavailable.";
        return;
    }
    const { before, after, delta } = data;
    const findingComparison = delta.findings;
    const findingSummary = findingComparison && findingComparison.comparable
        ? `<p>Finding changes: ${findingComparison.new.length} new, ${findingComparison.persistent.length} persistent, ${findingComparison.resolved.length} absent in comparable complete scans, ${findingComparison.reopened.length} reopened.</p>`
        : `<p>Finding comparison unavailable: incomplete scan data cannot establish resolution.</p>`;
    container.innerHTML = `
        <div class="compare-card">
            <h3>Before — Scan #${escapeHTML(before.id)} (${escapeHTML(before.scan_time)})</h3>
            <p>Ports: <strong>${escapeHTML(before.listening_ports_count)}</strong></p>
            <p>Findings: <strong>${escapeHTML(before.findings_count)}</strong></p>
            <p>Firewall: <strong>${escapeHTML(before.firewall_status)}</strong></p>
            <p>Risk Score: <strong>${escapeHTML(before.risk_score)}</strong> (${escapeHTML(before.risk_level)})</p>
        </div>
        <div class="compare-card">
            <h3>After — Scan #${escapeHTML(after.id)} (${escapeHTML(after.scan_time)})</h3>
            <p>Ports: <strong>${escapeHTML(after.listening_ports_count)}</strong></p>
            <p>Findings: <strong>${escapeHTML(after.findings_count)}</strong></p>
            <p>Firewall: <strong>${escapeHTML(after.firewall_status)}</strong></p>
            <p>Risk Score: <strong>${escapeHTML(after.risk_score)}</strong> (${escapeHTML(after.risk_level)})</p>
        </div>
        <div class="delta-summary">
            ${findingSummary}
            <div class="delta-item">
                <span class="delta-label">Ports Change</span>
                <span class="delta-value ${deltaClass(delta.ports_change)}">${escapeHTML(delta.ports_change ?? "N/A")}</span>
            </div>
            <div class="delta-item">
                <span class="delta-label">Findings Change</span>
                <span class="delta-value ${deltaClass(delta.findings_change)}">${escapeHTML(delta.findings_change ?? "N/A")}</span>
            </div>
            <div class="delta-item">
                <span class="delta-label">Risk Score Change</span>
                <span class="delta-value ${deltaClass(delta.risk_score_change)}">${escapeHTML(delta.risk_score_change ?? "N/A")}</span>
            </div>
        </div>
    `;
}

document.getElementById("compare-btn")?.addEventListener("click", async () => {
    const beforeId = document.getElementById("before-id").value;
    const afterId = document.getElementById("after-id").value;
    const container = document.getElementById("compare-results");
    if (!beforeId || !afterId) {
        container.textContent = "Enter both assessment IDs above.";
        return;
    }

    try {
        const response = await fetch(`/api/compare?before=${encodeURIComponent(beforeId)}&after=${encodeURIComponent(afterId)}`);
        const data = await response.json();
        if (!response.ok || data.error) {
            container.textContent = data.error || `Comparison failed (HTTP ${response.status}).`;
            return;
        }
        renderComparison(data);
    } catch (error) {
        container.textContent = `Comparison failed: ${error.message}`;
    }
});

function renderVulnerabilitySummary(summary) {
    const output = document.getElementById("vulnerability-analytics-summary");
    if (!output) return;
    if (!summary || typeof summary !== "object") {
        output.textContent = "Vulnerability assessment data is unavailable.";
        return;
    }
    const active = summary.currently_active_findings == null
        ? "Unavailable (latest assessment missing or incomplete)"
        : summary.currently_active_findings;
    output.textContent =
        `Unique CVEs: ${summary.unique_cves ?? 0} · ` +
        `Affected software/CVE pairs: ${summary.unique_affected_software_cve_pairs ?? 0} · ` +
        `Stored observations: ${summary.stored_observations ?? 0} · ` +
        `Confirmed pairs: ${summary.confirmed_software_cve_pairs ?? 0} · ` +
        `Potential pairs: ${summary.potential_software_cve_pairs ?? 0} · ` +
        `Currently active: ${active} · ` +
        `Latest assessment: ${summary.current_assessment_state || "NO_ASSESSMENT"}`;
}

async function loadAnalyticsPage() {
    const errorBanner = document.getElementById("analytics-error");
    const history = await loadAssessmentHistory();
    await loadLatestAssessmentDetails(history);
    try {
        const response = await fetch("/api/analytics");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data || typeof data !== "object" || data.error) throw new Error("Invalid analytics response.");
        renderRiskTrend(data.risk_trend);
        renderObjectChart("analytics-severity-chart", data.severity_distribution, "doughnut");
        renderObjectChart("analytics-category-chart", data.finding_categories);
        renderObjectChart("analytics-remediation-chart", data.remediation_outcomes, "doughnut");
        renderObjectChart("analytics-attack-chart", data.attack_surface_changes);
        renderObjectChart("analytics-vulnerability-chart", data.vulnerability_findings_by_day);
        renderVulnerabilitySummary(data.vulnerability_summary);
        const methodology = document.getElementById("analytics-methodology");
        if (methodology) {
            const details = data.methodology || {};
            methodology.textContent = Object.entries(details)
                .map(([topic, explanation]) => `${topic.replace(/_/g, " ")}: ${explanation}`)
                .join(" ");
        }
        if (errorBanner) errorBanner.classList.add("hidden");
    } catch (error) {
        if (errorBanner) {
            errorBanner.textContent = "Historical analytics could not be loaded. Retry later or review application logs.";
            errorBanner.classList.remove("hidden");
        }
        for (const id of [
            "analytics-risk-chart",
            "analytics-severity-chart",
            "analytics-category-chart",
            "analytics-remediation-chart",
            "analytics-attack-chart",
            "analytics-vulnerability-chart"
        ]) {
            showChartMessage(id, "Analytics are currently unavailable.");
        }
        renderVulnerabilitySummary(null);
    }
}

loadAnalyticsPage();
