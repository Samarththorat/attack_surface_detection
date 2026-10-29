let currentPorts = [];
let pendingAction = null;
let toastTimeout = null;

function riskClass(level) {
    const normalized = String(level || "unknown").toLowerCase();
    return ["safe", "low", "medium", "high", "critical", "unknown"].includes(normalized)
        ? normalized
        : "unknown";
}

function exposureLabel(scope) {
    return ({
        LOOPBACK: "Localhost only",
        SPECIFIC_INTERFACE: "Specific interface",
        ALL_INTERFACES: "All interfaces",
        UNKNOWN: "Unknown"
    })[scope] || "Unknown";
}

async function loadPortAnalysis() {
    const loading = document.getElementById("loading");
    loading.classList.remove("hidden");
    loading.setAttribute("role", "status");
    document.getElementById("loading-message").textContent = "Scanning ports, please wait...";
    const retryButton = document.getElementById("retry-btn");
    retryButton.classList.add("hidden");

    try {
        const response = await fetch("/api/port-analysis");
        let data;
        try {
            data = await response.json();
        } catch {
            throw new Error(`Port analysis returned an invalid response (HTTP ${response.status}).`);
        }

        if (!data || typeof data !== "object" || Array.isArray(data)) {
            throw new Error("Port analysis returned an invalid data format. Please retry.");
        }
        if (!response.ok || data.error) {
            throw new Error(data.error || `Port analysis failed (HTTP ${response.status}).`);
        }
        if (!Array.isArray(data.ports) || !data.summary || typeof data.summary !== "object") {
            throw new Error("Port analysis returned incomplete data. Please retry.");
        }

        currentPorts = data.ports || [];
        const total = Number.isFinite(data.total) ? data.total : currentPorts.length;
        renderSummary(data.summary, total);

        const adminBanner = document.getElementById("admin-warning");
        if (adminBanner) {
            if (data.is_admin === false) {
                adminBanner.classList.remove("hidden");
            } else {
                adminBanner.classList.add("hidden");
            }
        }

        applyFiltersAndRender();
        loading.classList.add("hidden");
    } catch (error) {
        console.error("Failed to load port analysis:", error);
        loading.setAttribute("role", "alert");
        document.getElementById("loading-message").textContent =
            `Unable to load port analysis: ${error.message}`;
        retryButton.classList.remove("hidden");
        if (currentPorts.length === 0) {
            document.querySelector("#ports-table tbody").innerHTML =
                `<tr><td colspan="13">Port analysis is unavailable. Use Retry to try again.</td></tr>`;
        }
    } finally {
        loadRemediationHistory();
    }
}

function renderSummary(summary, total) {
    const container = document.getElementById("risk-summary-grid");
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"];
    let html = `
        <div class="info-item">
            <span class="label">Total Listening Ports</span>
            <span class="value">${escapeHTML(total)}</span>
        </div>
    `;
    for (const level of order) {
        html += `
            <div class="info-item">
                <span class="label">${escapeHTML(level)}</span>
                <span class="value risk-tag ${riskClass(level)}">${escapeHTML(summary[level] ?? 0)}</span>
            </div>
        `;
    }
    container.innerHTML = html;
}

function applyFiltersAndRender() {
    const search = document.getElementById("search-input").value.toLowerCase();
    const riskFilter = document.getElementById("risk-filter").value;
    const protoFilter = document.getElementById("protocol-filter").value;
    const exposureFilter = document.getElementById("exposure-filter").value;

    const filtered = currentPorts.filter(p => {
        if (riskFilter && p.risk_level !== riskFilter) return false;
        if (protoFilter && p.protocol !== protoFilter) return false;
        const exposure = p.exposure_type || p.binding_scope || "UNKNOWN";
        if (exposureFilter && exposure !== exposureFilter) return false;
        if (search) {
            const haystack = [
                p.port, p.process_name, p.service_name, p.service_display_name,
                p.local_address, p.interface, p.exposure_type, p.binding_scope, p.risk_reason
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
        const message = currentPorts.length === 0
            ? "No listening ports detected."
            : "No ports match the current filters.";
        tbody.innerHTML = `<tr><td colspan="13">${message}</td></tr>`;
        return;
    }

    tbody.innerHTML = ports.map((p) => {
        const isBlocked = p.firewall_rule_status === "ACTIVE" || !!p.is_blocked;
        const ruleStatus = p.firewall_rule_status || (isBlocked ? "ACTIVE" : "UNKNOWN");
        const socketStatus = p.socket_status || (p.is_listening === true ? "LISTENING" : "UNKNOWN");
        const statusBadge = `
            <strong>Firewall rule:</strong> ${escapeHTML(ruleStatus)}<br>
            <strong>Socket:</strong> ${escapeHTML(socketStatus)}<br>
            <strong>Traffic test:</strong> ${escapeHTML(p.traffic_block_verification || "NOT_PERFORMED")}
        `;

        let portActionBtn = isBlocked
            ? `<button class="btn-tiny btn-unblock" data-port="${escapeHTML(p.port)}" data-protocol="${escapeHTML(p.protocol)}">Unblock Port</button>`
            : `<button class="btn-tiny btn-block" data-port="${escapeHTML(p.port)}" data-protocol="${escapeHTML(p.protocol)}">Block Port</button>`;

        let serviceActionBtns = "";
        if (p.service_name) {
            if (p.is_protected_service) {
                serviceActionBtns = `<button class="btn-tiny btn-protected" disabled title="Protected Windows service: cannot be modified by ASR">Protected</button>`;
            } else {
                serviceActionBtns = `
                    <button class="btn-tiny btn-stop" data-service="${escapeHTML(p.service_name)}">Stop Service</button>
                    <button class="btn-tiny btn-disable" data-service="${escapeHTML(p.service_name)}">Disable Service</button>
                `;
            }
        }

        return `
            <tr>
                <td><strong>${escapeHTML(p.port ?? "-")}</strong></td>
                <td>${escapeHTML(p.protocol ?? "-")}</td>
                <td>${escapeHTML(p.process_name ?? "-")}</td>
                <td>${escapeHTML(p.pid ?? "-")}</td>
                <td>${escapeHTML(p.service_display_name || p.service_name || "-")}</td>
                <td><code>${escapeHTML(p.local_address ?? "-")}</code></td>
                <td>${escapeHTML(exposureLabel(p.exposure_type || p.binding_scope || "UNKNOWN"))}</td>
                <td><span class="risk-tag ${riskClass(p.risk_level)}">${escapeHTML(p.risk_level ?? "UNKNOWN")}</span></td>
                <td>${escapeHTML(p.confidence ?? "Unknown")}</td>
                <td class="reason-cell">${escapeHTML(p.risk_reason ?? "-")}</td>
                <td>${escapeHTML(p.recommended_status ?? "-")}</td>
                <td>${statusBadge}</td>
                <td class="actions-cell">
                    <button class="btn-tiny btn-keep" title="No action">Keep</button>
                    ${portActionBtn}
                    ${serviceActionBtns}
                </td>
            </tr>
        `;
    }).join("");

    tbody.querySelectorAll(".btn-block").forEach(btn => {
        btn.addEventListener("click", () => confirmBlockPort(btn.dataset.port, btn.dataset.protocol));
    });
    tbody.querySelectorAll(".btn-unblock").forEach(btn => {
        btn.addEventListener("click", () => confirmUnblockPort(btn.dataset.port, btn.dataset.protocol));
    });
    tbody.querySelectorAll(".btn-stop").forEach(btn => {
        btn.addEventListener("click", () => confirmStopService(btn.dataset.service));
    });
    tbody.querySelectorAll(".btn-disable").forEach(btn => {
        btn.addEventListener("click", () => confirmDisableService(btn.dataset.service));
    });
    tbody.querySelectorAll(".btn-keep").forEach(btn => {
        btn.addEventListener("click", () => showToast("No action taken - port left as-is.", true));
    });
}

// ---------------- Confirmation modal ----------------

function showModal(title, bodyHtml, onConfirm) {
    document.getElementById("modal-title").innerHTML = title;
    document.getElementById("modal-body").innerHTML = bodyHtml;
    document.getElementById("confirm-modal").classList.remove("hidden");
    pendingAction = onConfirm;
}

function hideModal() {
    document.getElementById("confirm-modal").classList.add("hidden");
    pendingAction = null;
}

document.getElementById("modal-cancel").addEventListener("click", hideModal);
document.getElementById("modal-confirm").addEventListener("click", async () => {
    if (pendingAction) {
        const action = pendingAction;
        hideModal();
        await action();
    }
});

// Close modal when clicking outside box or pressing Escape
document.getElementById("confirm-modal").addEventListener("click", (e) => {
    if (e.target === document.getElementById("confirm-modal")) {
        hideModal();
    }
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !document.getElementById("confirm-modal").classList.contains("hidden")) {
        hideModal();
    }
});

function confirmBlockPort(port, protocol) {
    const p = currentPorts.find(x => String(x.port) === String(port) && (x.protocol || "TCP").toUpperCase() === (protocol || "TCP").toUpperCase()) || {};
    const impact = escapeHTML(p.operational_impact || "Blocking network access may disable network features of this process.");
    const reason = escapeHTML(p.risk_reason || p.risk_explanation || "Listening port exposed on the network.");
    const serviceName = escapeHTML(p.service_display_name || p.service_name || "None");
    const localAddr = escapeHTML(p.local_address || "0.0.0.0");
    const procName = p.process_name ? `${escapeHTML(p.process_name)} (PID: ${escapeHTML(p.pid ?? "-")})` : "Unknown process";

    showModal(
        "&#9888; Create Windows Firewall Block Rule",
        `<div style="font-size: 13px; line-height: 1.5;">
            <p>You are requesting creation of an application-managed Windows Firewall rule blocking <strong>inbound ${escapeHTML(protocol)} port ${escapeHTML(port)}</strong>.</p>
            <div style="background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                <div style="display:grid; grid-template-columns: 140px 1fr; gap: 6px;">
                    <strong>Port &amp; Protocol:</strong> <span>${escapeHTML(port)} / ${escapeHTML(protocol)}</span>
                    <strong>Local Binding:</strong> <code>${localAddr}</code> (${escapeHTML(p.binding_scope || p.exposure || "Network")})
                    <strong>Process / Service:</strong> <span>${procName} / ${serviceName}</span>
                    <strong>Risk Classification:</strong> <span class="risk-tag ${riskClass(p.risk_level)}">${escapeHTML(p.risk_level || "UNKNOWN")}</span>
                    <strong>Finding Evidence:</strong> <span>${reason}</span>
                    <strong>Recommended Action:</strong> <span>${escapeHTML(p.recommended_status || p.action_required || "Review & Restrict")}</span>
                    <strong>Operational Impact:</strong> <span style="color:#e3b341;">${impact}</span>
                </div>
            </div>
            <p style="color: var(--muted); font-size: 12px; margin-bottom: 0;">
                ℹ️ <em>Important Distinction:</em> Creating this firewall rule blocks external network connections. It does <strong>not</strong> kill the process or close the local listening socket.
            </p>
        </div>`,
        () => doBlockPort(port, protocol)
    );
}

function confirmUnblockPort(port, protocol) {
    showModal(
        "&#9888; Remove Windows Firewall Rule",
        `<div style="font-size: 13px;">
            <p>You are about to remove the application-managed firewall block rule for <strong>${escapeHTML(protocol)} port ${escapeHTML(port)}</strong>.</p>
            <p>This will safely delete rule <code>ASR_Block_${escapeHTML(protocol)}_${escapeHTML(port)}</code> and restore inbound access according to default firewall policy.</p>
            <p style="color:var(--muted); font-size:12px;">ASR will never remove or modify non-application firewall rules.</p>
        </div>`,
        () => doUnblockPort(port, protocol)
    );
}

async function confirmStopService(serviceName) {
    let meta = null;
    try {
        const resp = await fetch(`/api/service/info?name=${encodeURIComponent(serviceName)}`);
        if (resp.ok) meta = await resp.json();
    } catch (e) {
        console.error("Could not fetch service info", e);
    }

    const dispName = escapeHTML(meta?.display_name || serviceName);
    const safeServiceName = escapeHTML(serviceName);
    const curState = escapeHTML(meta?.current_state || "running");
    const impact = escapeHTML(meta?.operational_impact || "Stopping this service may disable associated features until restarted.");
    const deps = escapeHTML((meta?.dependencies && meta.dependencies.length > 0) ? meta.dependencies.join(", ") : "None reported");

    showModal(
        "&#9888; Stop Windows Service",
        `<div style="font-size: 13px; line-height: 1.5;">
            <p>You are requesting to immediately stop Windows service <strong>${dispName}</strong> (<code>${safeServiceName}</code>).</p>
            <div style="background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                <div style="display:grid; grid-template-columns: 140px 1fr; gap: 6px;">
                    <strong>Service Name:</strong> <code>${safeServiceName}</code>
                    <strong>Current State:</strong> <span>${curState}</span>
                    <strong>Dependencies:</strong> <span>${deps}</span>
                    <strong>Operational Impact:</strong> <span style="color:#e3b341;">${impact}</span>
                </div>
            </div>
            <p style="color: var(--muted); font-size: 12px; margin-bottom: 0;">
                The service will remain configured and may start again on next reboot or when requested by a dependent process.
            </p>
        </div>`,
        () => doStopService(serviceName)
    );
}

async function confirmDisableService(serviceName) {
    let meta = null;
    try {
        const resp = await fetch(`/api/service/info?name=${encodeURIComponent(serviceName)}`);
        if (resp.ok) meta = await resp.json();
    } catch (e) {
        console.error("Could not fetch service info", e);
    }

    const dispName = escapeHTML(meta?.display_name || serviceName);
    const safeServiceName = escapeHTML(serviceName);
    const curState = escapeHTML(meta?.current_state || "running");
    const startType = escapeHTML(meta?.start_type || "auto/manual");
    const impact = escapeHTML(meta?.operational_impact || "Disabling this service prevents it from starting on reboot and may break dependent networking or features.");
    const deps = escapeHTML((meta?.dependencies && meta.dependencies.length > 0) ? meta.dependencies.join(", ") : "None reported");

    showModal(
        "&#9888; Disable Windows Service (Startup Type)",
        `<div style="font-size: 13px; line-height: 1.5;">
            <p>You are requesting to set the startup type of service <strong>${dispName}</strong> (<code>${safeServiceName}</code>) to <strong>Disabled</strong>.</p>
            <div style="background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                <div style="display:grid; grid-template-columns: 140px 1fr; gap: 6px;">
                    <strong>Service Name:</strong> <code>${safeServiceName}</code>
                    <strong>Current State:</strong> <span>${curState} (Startup: ${startType})</span>
                    <strong>Dependencies:</strong> <span>${deps}</span>
                    <strong>Operational Impact:</strong> <span style="color:#f85149;">${impact}</span>
                </div>
            </div>
            <div style="margin-top: 12px; padding: 10px; background: rgba(218,54,51,0.15); border: 1px solid rgba(218,54,51,0.4); border-radius: 6px;">
                <label style="display: flex; align-items: flex-start; gap: 8px; cursor: pointer; color: #ff7b72; font-weight: 500;">
                    <input type="checkbox" id="confirm-disable-checkbox" style="margin-top: 3px;">
                    <span>I explicitly confirm that I want to disable this service. I have verified that neither operating system components nor essential applications depend on it.</span>
                </label>
            </div>
        </div>`,
        () => {
            const chk = document.getElementById("confirm-disable-checkbox");
            if (!chk || !chk.checked) {
                showToast("Service disable cancelled: Secondary confirmation checkbox must be checked.", false);
                return;
            }
            return doDisableService(serviceName, true);
        }
    );
}

// ---------------- Action calls ----------------

async function doBlockPort(port, protocol) {
    try {
        const response = await fetch("/api/port/block", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ port: Number(port), protocol, confirm: true }),
        });
        const result = await response.json();
        const msg = result.message || (result.success ? "Port blocked and verified." : "Failed to block port.");
        showToast(msg, result.success);
        await loadPortAnalysis();
    } catch (err) {
        showToast("Request failed: " + err.message, false);
    }
}

async function doUnblockPort(port, protocol) {
    try {
        const response = await fetch("/api/port/unblock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ port: Number(port), protocol, confirm: true }),
        });
        const result = await response.json();
        const msg = result.message || (result.success ? "Port unblocked and verified." : "Failed to unblock port.");
        showToast(msg, result.success);
        await loadPortAnalysis();
    } catch (err) {
        showToast("Request failed: " + err.message, false);
    }
}

async function doStopService(serviceName) {
    try {
        const response = await fetch("/api/service/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ service_name: serviceName, confirm: true }),
        });
        const result = await response.json();
        const msg = result.message || (result.success ? "Service stop command verified." : "Failed to stop service.");
        showToast(msg, result.success);
        await loadPortAnalysis();
    } catch (err) {
        showToast("Request failed: " + err.message, false);
    }
}

async function doDisableService(serviceName, confirmDisable = false) {
    try {
        const response = await fetch("/api/service/disable", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                service_name: serviceName,
                confirm: true,
                confirm_disable: confirmDisable
            }),
        });
        const result = await response.json();
        const msg = result.message || (result.success ? "Service disabled and verified." : "Failed to disable service.");
        showToast(msg, result.success);
        await loadPortAnalysis();
    } catch (err) {
        showToast("Request failed: " + err.message, false);
    }
}

function showToast(message, success) {
    const toast = document.getElementById("toast");
    if (toastTimeout) {
        clearTimeout(toastTimeout);
    }
    toast.textContent = message;
    toast.className = "toast " + (success ? "toast-success" : "toast-error");
    toast.classList.remove("hidden");
    toastTimeout = setTimeout(() => toast.classList.add("hidden"), 5000);
}

// ---------------- Remediation history ----------------

async function loadRemediationHistory() {
    try {
        const response = await fetch("/api/remediation-history?limit=50");
        let history;
        try {
            history = await response.json();
        } catch {
            throw new Error(`Remediation history returned an invalid response (HTTP ${response.status}).`);
        }
        if (!response.ok || !Array.isArray(history)) {
            throw new Error(history?.error || `Unable to load remediation history (HTTP ${response.status}).`);
        }
        renderRemediationTable(history);
    } catch (error) {
        console.error("Failed to load remediation history:", error);
        const tbody = document.querySelector("#remediation-table tbody");
        tbody.innerHTML = `
            <tr><td colspan="9" class="ph-error-cell">
                Unable to load remediation history: ${escapeHTML(error.message)}
                <button id="remediation-retry-btn" class="btn-secondary" type="button">Retry</button>
            </td></tr>
        `;
        document.getElementById("remediation-retry-btn")
            .addEventListener("click", loadRemediationHistory);
    }
}

function renderRemediationTable(history) {
    const tbody = document.querySelector("#remediation-table tbody");
    if (!history || history.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:var(--muted); padding:16px;">No remediation actions taken yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = history.map(h => {
        const verStatus = h.verification_status || "UNVERIFIED";
        let verClass = "unknown";
        if (verStatus === "RESOLVED") verClass = "safe";
        else if (verStatus === "PARTIALLY_RESOLVED") verClass = "medium";
        else if (verStatus === "UNRESOLVED") verClass = "high";
        else if (verStatus === "INCONCLUSIVE") verClass = "low";

        let scoreDeltaStr = "-";
        if (h.before_risk_score != null && h.after_risk_score != null) {
            const diff = h.before_risk_score - h.after_risk_score;
            const diffSign = diff > 0 ? `-${diff}` : `+${Math.abs(diff)}`;
            scoreDeltaStr = `${h.before_risk_score} → ${h.after_risk_score} (${diffSign})`;
        } else if (h.before_risk_score != null) {
            scoreDeltaStr = `${h.before_risk_score} → ?`;
        }

        return `
            <tr>
                <td style="font-size:12px;">${escapeHTML(h.timestamp)}</td>
                <td><strong>${escapeHTML(h.action_type)}</strong></td>
                <td>${escapeHTML(h.target_name ?? h.target ?? "-")}</td>
                <td>${escapeHTML(h.port ? h.port + "/" + (h.protocol ?? "") : "-")}</td>
                <td><code>${escapeHTML(h.previous_state ?? "-")}</code></td>
                <td><code>${escapeHTML(h.new_state ?? "-")}</code></td>
                <td><span class="risk-tag ${verClass}">${escapeHTML(verStatus)}</span></td>
                <td style="font-size:12px;">${escapeHTML(scoreDeltaStr)}</td>
                <td><span class="risk-tag ${h.status === "SUCCESS" ? "safe" : "high"}">${escapeHTML(h.status)}</span></td>
            </tr>
        `;
    }).join("");
}

// ---------------- Wiring ----------------

document.getElementById("refresh-btn").addEventListener("click", loadPortAnalysis);
document.getElementById("retry-btn").addEventListener("click", loadPortAnalysis);
document.getElementById("search-input").addEventListener("input", applyFiltersAndRender);
document.getElementById("risk-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("protocol-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("exposure-filter").addEventListener("change", applyFiltersAndRender);

loadPortAnalysis();
