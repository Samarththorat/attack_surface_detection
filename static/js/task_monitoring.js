let taskSnapshot = null;
let visibleProcesses = [];
let resourceChart = null;
let throughputChart = null;
let taskRefreshTimer = null;
let taskRefreshInProgress = false;

function taskElement(id) {
    return document.getElementById(id);
}

function taskSetText(id, value) {
    const element = taskElement(id);
    if (element) element.textContent = value;
}

function formatPercent(value) {
    return Number.isFinite(value) ? `${value.toFixed(1)}%` : "Unavailable";
}

function formatBytes(value) {
    if (!Number.isFinite(value) || value < 0) return "Unavailable";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let amount = value;
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) {
        amount /= 1024;
        unit += 1;
    }
    return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatRate(value) {
    if (!Number.isFinite(value) || value < 0) return "Unavailable";
    return `${formatBytes(value)}/s`;
}

function renderTaskSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
        throw new Error("The task-monitoring snapshot has an invalid format.");
    }
    taskSnapshot = snapshot;
    const availability = snapshot.availability && typeof snapshot.availability === "object"
        ? snapshot.availability
        : {};
    const memoryValue = Number.isFinite(snapshot.memory_usage_percent)
        ? formatPercent(snapshot.memory_usage_percent)
        : "Unavailable";
    taskSetText("task-cpu", Number.isFinite(snapshot.cpu_usage_percent)
        ? formatPercent(snapshot.cpu_usage_percent)
        : snapshot.availability_notes?.cpu
            ? "Sampling…"
            : "Unavailable");
    taskSetText("task-memory", memoryValue);
    taskSetText("task-memory-detail", Number.isFinite(snapshot.memory_used_bytes) && Number.isFinite(snapshot.memory_total_bytes)
        ? `${formatBytes(snapshot.memory_used_bytes)} of ${formatBytes(snapshot.memory_total_bytes)}`
        : "");
    taskSetText("task-disk-capacity", formatPercent(snapshot.disk_usage_percent));
    taskSetText("task-disk-detail", Number.isFinite(snapshot.disk_used_bytes) && Number.isFinite(snapshot.disk_total_bytes)
        ? `${formatBytes(snapshot.disk_used_bytes)} used of ${formatBytes(snapshot.disk_total_bytes)}`
        : "");

    const diskRatesAvailable = availability.disk_io !== false;
    taskSetText("task-disk-io", diskRatesAvailable
        ? `${formatRate(snapshot.disk_read_bytes_per_sec)} read · ${formatRate(snapshot.disk_write_bytes_per_sec)} write`
        : "Unavailable");
    taskSetText("task-disk-io-detail", diskRatesAvailable
        ? "System disk I/O throughput; separate from capacity usage."
        : "Disk I/O counters are unavailable on this system.");
    const networkRatesAvailable = availability.network_io !== false;
    taskSetText("task-network", networkRatesAvailable
        ? `${formatRate(snapshot.network_received_bytes_per_sec)} receive · ${formatRate(snapshot.network_sent_bytes_per_sec)} send`
        : "Unavailable");
    taskSetText("task-network-detail", networkRatesAvailable
        ? "System-wide throughput; not a utilization percentage."
        : "Network I/O counters are unavailable on this system.");
    taskSetText("task-gpu", Number.isFinite(snapshot.gpu_usage_percent)
        ? formatPercent(snapshot.gpu_usage_percent)
        : "Unavailable");
    taskSetText("task-gpu-detail", snapshot.availability_notes?.gpu || "");
    taskSetText("task-process-count", Number.isSafeInteger(snapshot.running_processes)
        ? String(snapshot.running_processes)
        : "Unavailable");
    taskSetText("task-process-access", snapshot.process_access_denied
        ? `${snapshot.process_access_denied} process records have restricted details.`
        : "");
    taskSetText("task-monitor-updated", snapshot.sampled_at || "Unavailable");
    const errors = Array.isArray(snapshot.collection_errors) ? snapshot.collection_errors : [];
    taskSetText("task-monitor-health", errors.length
        ? `Partial telemetry · ${errors.length} unavailable details`
        : "Monitoring available");
    taskSetText("task-monitor-status-note", errors.length
        ? errors.join(" ")
        : "Read-only process and system-resource measurements.");
    renderTaskProcesses(snapshot.processes);
}

function renderTaskProcesses(processes) {
    const body = taskElement("task-process-body");
    if (!body) return;
    taskSnapshot = taskSnapshot || {};
    taskSnapshot.processes = Array.isArray(processes) ? processes : [];
    filterTaskProcesses();
}

function filterTaskProcesses() {
    if (!taskSnapshot) return;
    const query = String(taskElement("task-process-search")?.value || "").trim().toLowerCase();
    const stateFilter = String(taskElement("task-process-state")?.value || "").toLowerCase();
    const sortBy = String(taskElement("task-process-sort")?.value || "cpu");
    const items = (Array.isArray(taskSnapshot.processes) ? taskSnapshot.processes : [])
        .filter(process => process && typeof process === "object" && !Array.isArray(process))
        .filter(process => {
            const searchText = `${process.name || ""} ${process.pid ?? ""}`.toLowerCase();
            return (!query || searchText.includes(query)) &&
                (!stateFilter || String(process.state || "").toLowerCase() === stateFilter);
        });
    items.sort((left, right) => {
        if (sortBy === "name") return String(left.name || "").localeCompare(String(right.name || ""));
        if (sortBy === "pid") return (left.pid ?? Number.MAX_SAFE_INTEGER) - (right.pid ?? Number.MAX_SAFE_INTEGER);
        const key = sortBy === "memory" ? "memory_percent" : "cpu_percent";
        const a = left[key];
        const b = right[key];
        if (!Number.isFinite(a)) return Number.isFinite(b) ? 1 : 0;
        if (!Number.isFinite(b)) return -1;
        return b - a;
    });
    visibleProcesses = items;
    taskSetText("task-process-summary", `Showing ${items.length} of ${
        Number.isSafeInteger(taskSnapshot.running_processes) ? taskSnapshot.running_processes : taskSnapshot.processes.length
    } observable processes.`);
    const body = taskElement("task-process-body");
    if (!body) return;
    if (!items.length) {
        const message = taskSnapshot.processes.length
            ? "No processes match the current search and filters."
            : "No process details are available for this snapshot.";
        body.innerHTML = `<tr><td colspan="10">${escapeHTML(message)}</td></tr>`;
        return;
    }
    body.innerHTML = items.map((process, index) => `
        <tr>
            <td>${escapeHTML(process.pid ?? "Unavailable")}</td>
            <td>${escapeHTML(process.name || "Unavailable")}</td>
            <td>${Number.isFinite(process.cpu_percent) ? escapeHTML(formatPercent(process.cpu_percent)) : "Sampling…"}</td>
            <td>${Number.isFinite(process.memory_rss_bytes) ? escapeHTML(formatBytes(process.memory_rss_bytes)) : "Unavailable"}${
                Number.isFinite(process.memory_percent) ? ` (${escapeHTML(formatPercent(process.memory_percent))})` : ""
            }</td>
            <td>${escapeHTML(formatBytes(process.disk_read_bytes))} / ${escapeHTML(formatBytes(process.disk_write_bytes))}</td>
            <td>Unavailable</td>
            <td>${escapeHTML(process.start_time || "Unavailable")}</td>
            <td>${escapeHTML(process.state || "Unavailable")}</td>
            <td>${escapeHTML(process.username || "Unavailable")}</td>
            <td><button class="btn-secondary task-process-details" type="button" data-process-index="${index}">Details</button></td>
        </tr>
    `).join("");
}

function showTaskProcessDetails(index) {
    const process = visibleProcesses[index];
    if (!process) return;
    const fields = [
        ["Name", process.name || "Unavailable"],
        ["PID", process.pid ?? "Unavailable"],
        ["Stable process identity", process.identity || "Unavailable"],
        ["CPU usage", Number.isFinite(process.cpu_percent)
            ? `${formatPercent(process.cpu_percent)} (${taskSnapshot.process_cpu_basis || "basis unavailable"})`
            : "Sampling…"],
        ["Memory", Number.isFinite(process.memory_rss_bytes) ? formatBytes(process.memory_rss_bytes) : "Unavailable"],
        ["Disk read / write totals", `${formatBytes(process.disk_read_bytes)} / ${formatBytes(process.disk_write_bytes)}`],
        ["Network attribution", "Unavailable from the configured operating-system telemetry source."],
        ["Started", process.start_time || "Unavailable"],
        ["State", process.state || "Unavailable"],
        ["User", process.username || "Unavailable"],
        ["Available actions", "Read-only; no process termination or modification is provided."]
    ];
    taskElement("task-details-body").innerHTML = fields.map(([label, value]) =>
        `<p><strong>${escapeHTML(label)}:</strong> ${escapeHTML(value)}</p>`
    ).join("");
    taskElement("task-process-details").classList.remove("hidden");
}

function renderTaskCharts(history) {
    const ordered = Array.isArray(history) ? [...history].reverse() : [];
    const labels = ordered.map(sample => sample.sampled_at || "Time unavailable");
    const resourceMessage = taskElement("task-resource-chart-message");
    const throughputMessage = taskElement("task-throughput-chart-message");
    if (resourceChart) resourceChart.destroy();
    if (throughputChart) throughputChart.destroy();
    resourceChart = null;
    throughputChart = null;
    const resourceSeries = [
        ["CPU", "cpu_usage_percent", "#58a6ff"],
        ["Memory", "memory_usage_percent", "#d29922"],
        ["Disk capacity", "disk_usage_percent", "#3fb950"]
    ];
    const throughputSeries = [
        ["Disk read", "disk_read_bytes_per_sec", "#58a6ff"],
        ["Disk write", "disk_write_bytes_per_sec", "#d29922"],
        ["Network receive", "network_received_bytes_per_sec", "#3fb950"],
        ["Network send", "network_sent_bytes_per_sec", "#f85149"]
    ];
    const resourcesAvailable = ordered.some(sample =>
        resourceSeries.some(([, key]) => Number.isFinite(sample[key]))
    );
    const throughputAvailable = ordered.some(sample =>
        throughputSeries.some(([, key]) => Number.isFinite(sample[key]))
    );
    if (!ordered.length) {
        if (resourceMessage) resourceMessage.textContent = "No stored resource samples are available yet.";
        if (throughputMessage) throughputMessage.textContent = "No stored throughput samples are available yet.";
        return;
    }
    if (!window.Chart) {
        if (resourceMessage) resourceMessage.textContent = "Chart library unavailable; stored samples remain accessible in the API and Excel report.";
        if (throughputMessage) throughputMessage.textContent = "Chart library unavailable; stored samples remain accessible in the API and Excel report.";
        return;
    }
    if (resourcesAvailable) {
        if (resourceMessage) resourceMessage.textContent = "";
        resourceChart = new window.Chart(taskElement("task-resource-chart"), {
            type: "line",
            data: {
                labels,
                datasets: resourceSeries.map(([label, key, color]) => ({
                    label,
                    data: ordered.map(sample => Number.isFinite(sample[key]) ? sample[key] : null),
                    borderColor: color,
                    backgroundColor: color,
                    spanGaps: false,
                    tension: 0.25
                }))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 100, ticks: { color: "#8b949e", callback: value => `${value}%` } },
                    x: { ticks: { color: "#8b949e", maxTicksLimit: 6 } }
                },
                plugins: { legend: { position: "bottom", labels: { color: "#c9d1d9" } } }
            }
        });
    } else if (resourceMessage) {
        resourceMessage.textContent = "Stored samples do not contain available CPU, memory, or disk-capacity values.";
    }
    if (throughputAvailable) {
        if (throughputMessage) throughputMessage.textContent = "";
        throughputChart = new window.Chart(taskElement("task-throughput-chart"), {
            type: "line",
            data: {
                labels,
                datasets: throughputSeries.map(([label, key, color]) => ({
                    label,
                    data: ordered.map(sample => Number.isFinite(sample[key]) ? sample[key] : null),
                    borderColor: color,
                    backgroundColor: color,
                    spanGaps: false,
                    tension: 0.25
                }))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, ticks: { color: "#8b949e", callback: value => formatRate(value) } },
                    x: { ticks: { color: "#8b949e", maxTicksLimit: 6 } }
                },
                plugins: { legend: { position: "bottom", labels: { color: "#c9d1d9" } } }
            }
        });
    } else if (throughputMessage) {
        throughputMessage.textContent = "Stored samples do not contain available disk or network throughput measurements.";
    }
}

async function loadTaskMonitoring() {
    if (taskRefreshInProgress) return;
    taskRefreshInProgress = true;
    const button = taskElement("task-refresh-button");
    if (button) button.disabled = true;
    const errorBanner = taskElement("task-monitor-error");
    if (errorBanner) errorBanner.classList.add("hidden");
    try {
        const response = await fetch("/api/task-monitoring/snapshot");
        const data = await response.json();
        if (!response.ok || !data || typeof data !== "object" || data.error) {
            throw new Error(data?.error || `Task monitoring failed (HTTP ${response.status}).`);
        }
        renderTaskSnapshot(data);
        if (data.history_error) {
            taskSetText("task-monitor-history-note", data.history_error);
        } else {
            const historyResponse = await fetch("/api/task-monitoring/history?hours=24");
            const history = await historyResponse.json();
            if (!historyResponse.ok || !Array.isArray(history)) {
                throw new Error(history?.error || `Stored resource history failed (HTTP ${historyResponse.status}).`);
            }
            renderTaskCharts(history);
            taskSetText("task-monitor-history-note", `Samples are stored at most once per minute and retained for ${data.history_retention_days || 7} days.`);
        }
    } catch (error) {
        if (errorBanner) {
            errorBanner.textContent = `Unable to refresh task monitoring: ${error.message}`;
            errorBanner.classList.remove("hidden");
        }
        taskSetText("task-monitor-health", "Telemetry unavailable");
    } finally {
        taskRefreshInProgress = false;
        if (button) button.disabled = false;
    }
}

function configureTaskRefresh() {
    if (taskRefreshTimer) window.clearInterval(taskRefreshTimer);
    const intervalSeconds = Number(taskElement("task-refresh-interval")?.value);
    const safeInterval = [5, 10, 30, 60].includes(intervalSeconds) ? intervalSeconds : 5;
    taskRefreshTimer = window.setInterval(loadTaskMonitoring, safeInterval * 1000);
}

taskElement("task-refresh-button").addEventListener("click", loadTaskMonitoring);
taskElement("task-refresh-interval").addEventListener("change", configureTaskRefresh);
taskElement("task-process-search").addEventListener("input", filterTaskProcesses);
taskElement("task-process-state").addEventListener("change", filterTaskProcesses);
taskElement("task-process-sort").addEventListener("change", filterTaskProcesses);
taskElement("task-process-body").addEventListener("click", event => {
    const button = event.target.closest(".task-process-details");
    if (button) showTaskProcessDetails(Number(button.dataset.processIndex));
});
taskElement("task-details-close").addEventListener("click", () => {
    taskElement("task-process-details").classList.add("hidden");
});
taskElement("task-process-details").addEventListener("click", event => {
    if (event.target === taskElement("task-process-details")) {
        taskElement("task-process-details").classList.add("hidden");
    }
});
taskElement("task-process-details").addEventListener("keydown", event => {
    if (event.key === "Escape") taskElement("task-process-details").classList.add("hidden");
});

configureTaskRefresh();
loadTaskMonitoring();
