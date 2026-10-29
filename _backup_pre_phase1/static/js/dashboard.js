let riskChartInstance = null;
let trendChartInstance = null;

async function runScan() {
    const loading = document.getElementById("loading");
    const content = document.getElementById("dashboard-content");

    loading.classList.remove("hidden");
    content.classList.add("hidden");

    try {
        const response = await fetch("/api/scan");
        const data = await response.json();
        renderDashboard(data);
    } catch (err) {
        loading.textContent = "Scan failed: " + err.message;
        return;
    }

    loading.classList.add("hidden");
    content.classList.remove("hidden");
}

function renderDashboard(data) {
    renderRiskScore(data.risk);
    renderSystemInfo(data.system_info);
    renderFirewall(data.firewall);
    renderPorts(data.ports);
    renderServices(data.flagged_services);
    renderFindings(data.security_findings);
    renderRecommendations(data.recommendations);
    loadHistory();
}

function riskLevelClass(level) {
    if (!level) return "medium";
    return level.toLowerCase();
}

function renderRiskScore(risk) {
    if (!risk || risk.error) return;

    document.getElementById("risk-score-number").textContent = risk.total_score;

    const badge = document.getElementById("risk-level-badge");
    badge.textContent = risk.risk_level + " Risk";
    badge.className = "badge " + riskLevelClass(risk.risk_level);

    const bar = document.getElementById("risk-progress-bar");
    bar.style.width = risk.total_score + "%";

    // Chart.js breakdown bar chart
    const ctx = document.getElementById("riskChart");
    const labels = risk.breakdown.map(b => b.category);
    const values = risk.breakdown.map(b => b.points_awarded);

    if (riskChartInstance) {
        riskChartInstance.destroy();
    }

    riskChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Points Awarded",
                data: values,
                backgroundColor: "#58a6ff",
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } },
                y: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } }
            }
        }
    });
}

function renderSystemInfo(info) {
    const container = document.getElementById("system-info-grid");
    if (!info || info.error) {
        container.innerHTML = `<div class="info-item">Unable to load system info</div>`;
        return;
    }

    const items = [
        ["Hostname", info.hostname],
        ["OS", `${info.os.os_name} ${info.os.os_release}`],
        ["Architecture", info.os.architecture],
        ["CPU Cores", `${info.cpu.physical_cores} physical / ${info.cpu.logical_cores} logical`],
        ["CPU Usage", `${info.cpu.cpu_usage_percent}%`],
        ["RAM", `${info.ram.used_gb} GB / ${info.ram.total_gb} GB (${info.ram.usage_percent}%)`],
        ["Uptime", info.uptime],
        ["Scan Time", info.scan_time],
    ];

    container.innerHTML = items.map(([label, value]) => `
        <div class="info-item">
            <span class="label">${label}</span>
            <span class="value">${value}</span>
        </div>
    `).join("");
}

function renderFirewall(fw) {
    const container = document.getElementById("firewall-status");
    if (!fw || fw.error || !fw.profiles) {
        container.innerHTML = `<div class="info-item">Firewall status unknown</div>`;
        return;
    }

    let html = "";
    for (const [profile, details] of Object.entries(fw.profiles)) {
        const cls = details.state === "ON" ? "low" : "high";
        html += `
            <div class="info-item">
                <span class="label">${profile} Profile</span>
                <span class="value risk-tag ${cls}">${details.state}</span>
            </div>
        `;
    }
    container.innerHTML = html;
}

function renderPorts(ports) {
    const tbody = document.querySelector("#ports-table tbody");
    document.getElementById("ports-count").textContent = ports && !ports.error ? ports.length : 0;

    if (!ports || ports.error) {
        tbody.innerHTML = `<tr><td colspan="6">Unable to load ports</td></tr>`;
        return;
    }

    tbody.innerHTML = ports.map(p => `
        <tr>
            <td>${p.port ?? "-"}</td>
            <td>${p.protocol ?? "-"}</td>
            <td>${p.local_address ?? "-"}</td>
            <td>${p.process_name ?? "-"}</td>
            <td>${p.pid ?? "-"}</td>
            <td>${p.risk_note ?? "-"}</td>
        </tr>
    `).join("");
}

function renderServices(services) {
    const tbody = document.querySelector("#services-table tbody");
    document.getElementById("services-count").textContent = services ? services.length : 0;

    if (!services || services.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5">No flagged services</td></tr>`;
        return;
    }

    tbody.innerHTML = services.map(s => `
        <tr>
            <td>${s.name}</td>
            <td>${s.pid}</td>
            <td>${s.status}</td>
            <td>${s.listening_ports.join(", ")}</td>
            <td>${s.review_reason}</td>
        </tr>
    `).join("");
}

function renderFindings(findings) {
    const container = document.getElementById("findings-list");
    if (!findings || findings.error) {
        container.innerHTML = `<div class="finding-item">Unable to load findings</div>`;
        return;
    }

    container.innerHTML = findings.map(f => `
        <div class="finding-item ${f.category}">
            <span class="finding-tag">${f.category.replace("_", " ")}</span>
            <strong>${f.area}:</strong> ${f.detail}
        </div>
    `).join("");
}

function renderRecommendations(recs) {
    const tbody = document.querySelector("#recommendations-table tbody");
    if (!recs || recs.error) {
        tbody.innerHTML = `<tr><td colspan="4">Unable to load recommendations</td></tr>`;
        return;
    }

    tbody.innerHTML = recs.map(r => `
        <tr>
            <td>${r.finding}</td>
            <td><span class="risk-tag ${r.risk.toLowerCase().replace(/[^a-z]/g, "")}">${r.risk}</span></td>
            <td>${r.reason}</td>
            <td>${r.recommended_action}</td>
        </tr>
    `).join("");
}

async function loadHistory() {
    try {
        const response = await fetch("/api/history?limit=20");
        const history = await response.json();
        renderHistoryTable(history);
        renderTrendChart(history);
    } catch (err) {
        console.error("Failed to load history:", err);
    }
}

function renderHistoryTable(history) {
    const tbody = document.querySelector("#history-table tbody");
    if (!history || history.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7">No scan history yet</td></tr>`;
        return;
    }

    tbody.innerHTML = history.map(h => `
        <tr>
            <td>${h.id}</td>
            <td>${h.scan_time}</td>
            <td>${h.listening_ports_count}</td>
            <td>${h.findings_count}</td>
            <td>${h.firewall_status}</td>
            <td>${h.risk_score}</td>
            <td><span class="risk-tag ${riskLevelClass(h.risk_level)}">${h.risk_level}</span></td>
        </tr>
    `).join("");
}

function renderTrendChart(history) {
    if (!history || history.length === 0) return;

    // Reverse so oldest is first (left) and newest is last (right) on the chart
    const ordered = [...history].reverse();
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
                label: "Risk Score",
                data: scores,
                borderColor: "#58a6ff",
                backgroundColor: "rgba(88, 166, 255, 0.15)",
                fill: true,
                tension: 0.3,
                pointRadius: 4,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
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

function deltaClass(value, lowerIsBetter = true) {
    if (value === 0) return "unchanged";
    const isImprovement = lowerIsBetter ? value < 0 : value > 0;
    return isImprovement ? "improved" : "worsened";
}

function renderComparison(data) {
    const { before, after, delta } = data;
    const container = document.getElementById("compare-results");

    container.innerHTML = `
        <div class="compare-card">
            <h3>Before — Scan #${before.id} (${before.scan_time})</h3>
            <p>Ports: <strong>${before.listening_ports_count}</strong></p>
            <p>Findings: <strong>${before.findings_count}</strong></p>
            <p>Firewall: <strong>${before.firewall_status}</strong></p>
            <p>Risk Score: <strong>${before.risk_score}</strong> (${before.risk_level})</p>
        </div>
        <div class="compare-card">
            <h3>After — Scan #${after.id} (${after.scan_time})</h3>
            <p>Ports: <strong>${after.listening_ports_count}</strong></p>
            <p>Findings: <strong>${after.findings_count}</strong></p>
            <p>Firewall: <strong>${after.firewall_status}</strong></p>
            <p>Risk Score: <strong>${after.risk_score}</strong> (${after.risk_level})</p>
        </div>
        <div class="delta-summary">
            <div class="delta-item">
                <span class="delta-label">Ports Change</span>
                <span class="delta-value ${deltaClass(delta.ports_change)}">${delta.ports_change > 0 ? "+" : ""}${delta.ports_change}</span>
            </div>
            <div class="delta-item">
                <span class="delta-label">Findings Change</span>
                <span class="delta-value ${deltaClass(delta.findings_change)}">${delta.findings_change > 0 ? "+" : ""}${delta.findings_change}</span>
            </div>
            <div class="delta-item">
                <span class="delta-label">Risk Score Change</span>
                <span class="delta-value ${deltaClass(delta.risk_score_change)}">${delta.risk_score_change > 0 ? "+" : ""}${delta.risk_score_change}</span>
            </div>
        </div>
    `;
}

document.getElementById("compare-btn").addEventListener("click", async () => {
    const beforeId = document.getElementById("before-id").value;
    const afterId = document.getElementById("after-id").value;
    const container = document.getElementById("compare-results");

    if (!beforeId || !afterId) {
        container.innerHTML = `<p style="color: var(--muted);">Enter both scan IDs above.</p>`;
        return;
    }

    try {
        const response = await fetch(`/api/compare?before=${beforeId}&after=${afterId}`);
        const data = await response.json();

        if (data.error) {
            container.innerHTML = `<p style="color: var(--high);">${data.error}</p>`;
            return;
        }

        renderComparison(data);
    } catch (err) {
        container.innerHTML = `<p style="color: var(--high);">Comparison failed: ${err.message}</p>`;
    }
});

document.getElementById("rescan-btn").addEventListener("click", runScan);

// Run scan automatically on page load
runScan();
