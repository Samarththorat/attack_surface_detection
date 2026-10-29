let currentInventory = null;
let liveMonitoringHealth = "STARTING";

function riskClass(level) {
    const normalized = String(level || "unknown").toLowerCase();
    return ["safe", "low", "medium", "high", "critical", "unknown", "info"].includes(normalized)
        ? normalized
        : "unknown";
}

function categoryClass(category) {
    const normalized = String(category || "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
    return normalized || "unknown";
}

async function loadInventory() {
    const loading = document.getElementById("loading");
    const content = document.getElementById("as-content");
    loading.classList.remove("hidden");
    content.classList.add("hidden");

    try {
        const response = await fetch("/api/attack-surface");
        const data = await response.json();

        if (data.error) {
            loading.textContent = "Failed to build inventory: " + data.error;
            return;
        }

        currentInventory = data;
        renderInterfaces(data.network_interfaces);
        renderFirewall(data.firewall);
        renderExposed(data.potentially_exposed_services);
        renderServices(data.running_services);
        renderFindings(data.security_configuration);
        applyFiltersAndRenderPorts();
    } catch (err) {
        loading.textContent = "Failed to build inventory: " + err.message;
        return;
    }

    loading.classList.add("hidden");
    content.classList.remove("hidden");
}

function renderInterfaces(interfaces) {
    const container = document.getElementById("interfaces-grid");
    if (!interfaces || interfaces.error || Object.keys(interfaces).length === 0) {
        container.innerHTML = `<div class="info-item">No network interfaces found</div>`;
        return;
    }
    container.innerHTML = Object.entries(interfaces).map(([name, ips]) => `
        <div class="info-item">
            <span class="label">${escapeHTML(name)}</span>
            <span class="value">${escapeHTML(Array.isArray(ips) ? ips.join(", ") : ips)}</span>
        </div>
    `).join("");
}

function renderFirewall(fw) {
    const container = document.getElementById("firewall-grid");
    if (!fw || fw.error || !fw.profiles) {
        container.innerHTML = `<div class="info-item">Firewall status unknown</div>`;
        return;
    }
    let html = "";
    for (const [profile, details] of Object.entries(fw.profiles)) {
        const cls = details.state === "ON" ? "low" : "high";
        html += `
            <div class="info-item">
                <span class="label">${escapeHTML(profile)} Profile</span>
                <span class="value risk-tag ${cls}">${escapeHTML(details.state)}</span>
            </div>
        `;
    }
    container.innerHTML = html;
}

function applyFiltersAndRenderPorts() {
    if (!currentInventory) return;
    const search = document.getElementById("search-input").value.toLowerCase();
    const riskFilter = document.getElementById("risk-filter").value;
    const protoFilter = document.getElementById("protocol-filter").value;

    const ports = currentInventory.listening_ports || [];
    const filtered = ports.filter(p => {
        if (riskFilter && p.risk_level !== riskFilter) return false;
        if (protoFilter && p.protocol !== protoFilter) return false;
        if (search) {
            const haystack = [
                p.port, p.process_name, p.service_name, p.service_display_name,
                p.local_address, p.risk_reason, p.recommended_status
            ].join(" ").toLowerCase();
            if (!haystack.includes(search)) return false;
        }
        return true;
    });

    renderPortsTable(filtered);
}

function renderPortsTable(ports) {
    const tbody = document.querySelector("#ports-table tbody");
    document.getElementById("ports-count").textContent = ports.length;

    if (ports.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8">No ports match the current filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = ports.map(p => `
        <tr>
            <td>${escapeHTML(p.port ?? "-")}</td>
            <td>${escapeHTML(p.protocol ?? "-")}</td>
            <td>${escapeHTML(p.process_name ?? "-")}</td>
            <td>${escapeHTML(p.service_display_name || p.service_name || "-")}</td>
            <td>${escapeHTML(p.local_address ?? "-")}</td>
            <td>${escapeHTML(p.interface ?? "-")}</td>
            <td><span class="risk-tag ${riskClass(p.risk_level)}">${escapeHTML(p.risk_level ?? "UNKNOWN")}</span></td>
            <td class="reason-cell">${escapeHTML(p.risk_reason ?? "-")}</td>
        </tr>
    `).join("");
}

function renderExposed(exposed) {
    const tbody = document.querySelector("#exposed-table tbody");
    document.getElementById("exposed-count").textContent = exposed ? exposed.length : 0;

    if (!exposed || exposed.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6">No potentially exposed services found - good sign.</td></tr>`;
        return;
    }

    tbody.innerHTML = exposed.map(p => `
        <tr>
            <td>${escapeHTML(p.port ?? "-")}</td>
            <td>${escapeHTML(p.protocol ?? "-")}</td>
            <td>${escapeHTML(p.process_name ?? "-")}</td>
            <td>${escapeHTML(p.service_display_name || p.service_name || "-")}</td>
            <td><span class="risk-tag ${riskClass(p.risk_level)}">${escapeHTML(p.risk_level ?? "UNKNOWN")}</span></td>
            <td class="reason-cell">${escapeHTML(p.risk_reason ?? "-")}</td>
        </tr>
    `).join("");
}

function renderServices(services) {
    const tbody = document.querySelector("#services-table tbody");
    const list = Array.isArray(services) ? services : [];
    document.getElementById("services-count").textContent = list.length;

    if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5">No services found</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map(s => `
        <tr>
            <td>${escapeHTML(s.name)}</td>
            <td>${escapeHTML(s.pid)}</td>
            <td>${escapeHTML(s.status)}</td>
            <td>${escapeHTML((s.listening_ports || []).join(", ") || "-")}</td>
            <td>${escapeHTML(s.review_reason ?? "-")}</td>
        </tr>
    `).join("");
}

function renderFindings(findings) {
    const container = document.getElementById("findings-list");
    if (!findings || findings.error || !Array.isArray(findings)) {
        container.innerHTML = `<div class="finding-item">Unable to load security configuration findings</div>`;
        return;
    }

    container.innerHTML = findings.map(f => `
        <div class="finding-item ${categoryClass(f.category)}">
            <span class="finding-tag">${escapeHTML((f.category || "").replace("_", " "))}</span>
            <strong>${escapeHTML(f.area)}:</strong> ${escapeHTML(f.detail)}
        </div>
    `).join("");
}

async function loadLiveChanges() {
    try {
        const response = await fetch("/api/attack-surface/changes");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data || typeof data !== "object" || Array.isArray(data) || data.error) {
            throw new Error(data && data.error ? data.error : "Invalid monitoring response.");
        }

        liveMonitoringHealth = data.monitoring_health ||
            (data.monitoring_active ? "UNKNOWN" : "STOPPED");
        const healthLabels = {
            HEALTHY: "Continuous Attack Surface Monitor: Healthy",
            DEGRADED: "Continuous Attack Surface Monitor: Degraded",
            STALE: "Continuous Attack Surface Monitor: Stale",
            STOPPED: "Continuous Attack Surface Monitor: Paused",
            STARTING: "Continuous Attack Surface Monitor: Starting",
        };
        const statusEl = document.getElementById("as-live-status");
        const lastCheckEl = document.getElementById("as-last-check");
        const intervalEl = document.getElementById("as-interval");
        const lastSuccessEl = document.getElementById("as-last-successful-check");
        const pillEl = document.getElementById("as-unresolved-pill");
        const tbody = document.getElementById("as-changes-body");

        if (statusEl) statusEl.textContent = healthLabels[liveMonitoringHealth] || "Continuous Attack Surface Monitor: Health Unknown";
        if (lastCheckEl && data.last_check_time) lastCheckEl.textContent = data.last_check_time;
        if (intervalEl && data.interval_seconds) intervalEl.textContent = data.interval_seconds + "s";
        if (lastSuccessEl) lastSuccessEl.textContent = data.last_successful_check_time || "No successful check yet";
        if (pillEl) {
            const count = data.unresolved_count || 0;
            pillEl.textContent = `${count} Unresolved Events`;
            pillEl.className = "badge-pill " + (count === 0 ? "success" : "warning");
        }

        if (tbody) {
            const changes = liveMonitoringHealth === "HEALTHY" && Array.isArray(data.changes)
                ? data.changes
                : [];
            if (liveMonitoringHealth !== "HEALTHY") {
                const message = liveMonitoringHealth === "DEGRADED"
                    ? "Monitoring is degraded; current changes are not shown as complete."
                    : liveMonitoringHealth === "STALE"
                        ? "Monitoring is stale; current changes are unavailable."
                        : liveMonitoringHealth === "STOPPED"
                            ? "Monitoring is paused; current changes are unavailable."
                            : "Monitoring has not produced a healthy sample; current changes are unavailable.";
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:12px;">${escapeHTML(message)}</td></tr>`;
            } else if (changes.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:12px;">Baseline snapshot active. No attack surface drift detected.</td></tr>`;
            } else {
                tbody.innerHTML = changes.map(c => `
                    <tr>
                        <td>${escapeHTML(c.timestamp || "-")}</td>
                        <td><span class="change-tag ${categoryClass(`change-${c.change_type || "changed"}`)}">${escapeHTML(c.change_type)}</span></td>
                        <td><strong>${escapeHTML((c.component || "").toUpperCase())}</strong></td>
                        <td><code>${escapeHTML(c.target || "-")}</code></td>
                        <td><span class="risk-tag ${riskClass(c.severity || "info")}">${escapeHTML(c.severity || "INFO")}</span></td>
                        <td>${escapeHTML(c.description || (c.details ? JSON.stringify(c.details) : "-"))}</td>
                    </tr>
                `).join("");
            }
        }
    } catch (err) {
        liveMonitoringHealth = "UNKNOWN";
        const statusEl = document.getElementById("as-live-status");
        const tbody = document.getElementById("as-changes-body");
        if (statusEl) statusEl.textContent = `Monitoring unavailable: ${err.message}`;
        if (tbody) tbody.innerHTML = `<tr><td colspan="6">Monitoring data unavailable. Last successful check: ${escapeHTML(document.getElementById("as-last-successful-check")?.textContent || "unknown")}.</td></tr>`;
    }
}

document.getElementById("refresh-btn").addEventListener("click", () => {
    loadInventory();
    loadLiveChanges();
});
document.getElementById("search-input").addEventListener("input", applyFiltersAndRenderPorts);
document.getElementById("risk-filter").addEventListener("change", applyFiltersAndRenderPorts);
document.getElementById("protocol-filter").addEventListener("change", applyFiltersAndRenderPorts);

loadInventory();
loadLiveChanges();
setInterval(loadLiveChanges, 5000);
