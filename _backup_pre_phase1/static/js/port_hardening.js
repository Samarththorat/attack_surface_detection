let currentPorts = [];
let pendingAction = null;
let toastTimeout = null;

function riskClass(level) {
    return (level || "unknown").toLowerCase();
}

async function loadPortAnalysis() {
    const loading = document.getElementById("loading");
    const content = document.getElementById("ph-content");
    loading.classList.remove("hidden");
    content.classList.add("hidden");

    try {
        const response = await fetch("/api/port-analysis");
        const data = await response.json();

        if (data.error) {
            loading.textContent = "Scan failed: " + data.error;
            return;
        }

        currentPorts = data.ports || [];
        renderSummary(data.summary || {}, data.total || 0);

        const adminBanner = document.getElementById("admin-warning");
        if (adminBanner) {
            if (data.is_admin === false) {
                adminBanner.classList.remove("hidden");
            } else {
                adminBanner.classList.add("hidden");
            }
        }

        applyFiltersAndRender();
        loadRemediationHistory();
    } catch (err) {
        loading.textContent = "Scan failed: " + err.message;
        return;
    }

    loading.classList.add("hidden");
    content.classList.remove("hidden");
}

function renderSummary(summary, total) {
    const container = document.getElementById("risk-summary-grid");
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"];
    let html = `
        <div class="info-item">
            <span class="label">Total Listening Ports</span>
            <span class="value">${total}</span>
        </div>
    `;
    for (const level of order) {
        html += `
            <div class="info-item">
                <span class="label">${level}</span>
                <span class="value risk-tag ${riskClass(level)}">${summary[level] ?? 0}</span>
            </div>
        `;
    }
    container.innerHTML = html;
}

function applyFiltersAndRender() {
    const search = document.getElementById("search-input").value.toLowerCase();
    const riskFilter = document.getElementById("risk-filter").value;
    const protoFilter = document.getElementById("protocol-filter").value;

    const filtered = currentPorts.filter(p => {
        if (riskFilter && p.risk_level !== riskFilter) return false;
        if (protoFilter && p.protocol !== protoFilter) return false;
        if (search) {
            const haystack = [
                p.port, p.process_name, p.service_name, p.service_display_name,
                p.local_address, p.risk_reason
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
        tbody.innerHTML = `<tr><td colspan="12">No ports match the current filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = ports.map((p) => {
        const isBlocked = !!p.is_blocked;
        const statusBadge = isBlocked
            ? `<span class="status-badge status-blocked">Blocked (ASR)</span>`
            : `<span class="status-badge status-open">Listening</span>`;

        let portActionBtn = isBlocked
            ? `<button class="btn-tiny btn-unblock" data-port="${p.port}" data-protocol="${p.protocol}">Unblock Port</button>`
            : `<button class="btn-tiny btn-block" data-port="${p.port}" data-protocol="${p.protocol}">Block Port</button>`;

        let serviceActionBtns = "";
        if (p.service_name) {
            if (p.is_protected_service) {
                serviceActionBtns = `<button class="btn-tiny btn-protected" disabled title="Protected Windows service: cannot be modified by ASR">Protected</button>`;
            } else {
                serviceActionBtns = `
                    <button class="btn-tiny btn-stop" data-service="${p.service_name}">Stop Service</button>
                    <button class="btn-tiny btn-disable" data-service="${p.service_name}">Disable Service</button>
                `;
            }
        }

        return `
            <tr>
                <td><strong>${p.port ?? "-"}</strong></td>
                <td>${p.protocol ?? "-"}</td>
                <td>${p.process_name ?? "-"}</td>
                <td>${p.pid ?? "-"}</td>
                <td>${p.service_display_name || p.service_name || "-"}</td>
                <td><code>${p.local_address ?? "-"}</code></td>
                <td>${p.interface ?? "-"}</td>
                <td><span class="risk-tag ${riskClass(p.risk_level)}">${p.risk_level ?? "UNKNOWN"}</span></td>
                <td class="reason-cell">${p.risk_reason ?? "-"}</td>
                <td>${p.recommended_status ?? "-"}</td>
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
    showModal(
        "&#9888; Block Port",
        `<p>You are about to create a Windows Firewall rule blocking <strong>inbound ${protocol} port ${port}</strong>.</p>
         <p>This will prevent new connections to this port from other machines. The process may still run and the
         port may still appear as listening locally — this only restricts network access to it.</p>
         <p>You can undo this anytime by clicking <strong>Unblock Port</strong>.</p>`,
        () => doBlockPort(port, protocol)
    );
}

function confirmUnblockPort(port, protocol) {
    showModal(
        "&#9888; Unblock Port",
        `<p>You are about to remove the Windows Firewall block rule for <strong>${protocol} port ${port}</strong>.</p>
         <p>This will restore normal network accessibility to this port according to standard firewall rules.</p>`,
        () => doUnblockPort(port, protocol)
    );
}

function confirmStopService(serviceName) {
    showModal(
        "&#9888; Stop Service",
        `<p>You are about to immediately stop Windows service <strong>${serviceName}</strong>.</p>
         <p>The service will remain configured on the machine, but will stop running until restarted or rebooted.</p>`,
        () => doStopService(serviceName)
    );
}

function confirmDisableService(serviceName) {
    showModal(
        "&#9888; Disable Service",
        `<p>You are about to set the startup type of service <strong>${serviceName}</strong> to <strong>Disabled</strong>.</p>
         <p>This prevents the service from starting automatically (including after system reboot) until manually re-enabled.</p>
         <p><strong>Warning:</strong> Ensure this service is not needed by your workflow before proceeding.</p>`,
        () => doDisableService(serviceName)
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
        showToast(result.message || (result.success ? "Port blocked." : "Failed to block port."), result.success);
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
        showToast(result.message || (result.success ? "Port unblocked." : "Failed to unblock port."), result.success);
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
        showToast(result.message || (result.success ? "Service stopped." : "Failed to stop service."), result.success);
        await loadPortAnalysis();
    } catch (err) {
        showToast("Request failed: " + err.message, false);
    }
}

async function doDisableService(serviceName) {
    try {
        const response = await fetch("/api/service/disable", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ service_name: serviceName, confirm: true }),
        });
        const result = await response.json();
        showToast(result.message || (result.success ? "Service disabled." : "Failed to disable service."), result.success);
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
        const history = await response.json();
        renderRemediationTable(history);
    } catch (err) {
        console.error("Failed to load remediation history:", err);
    }
}

function renderRemediationTable(history) {
    const tbody = document.querySelector("#remediation-table tbody");
    if (!history || history.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7">No remediation actions taken yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = history.map(h => `
        <tr>
            <td>${h.timestamp}</td>
            <td><strong>${h.action_type}</strong></td>
            <td>${h.target_name ?? "-"}</td>
            <td>${h.port ? h.port + "/" + (h.protocol ?? "") : "-"}</td>
            <td>${h.previous_state ?? "-"}</td>
            <td>${h.new_state ?? "-"}</td>
            <td><span class="risk-tag ${h.status === "SUCCESS" ? "low" : "high"}">${h.status}</span></td>
        </tr>
    `).join("");
}

// ---------------- Wiring ----------------

document.getElementById("refresh-btn").addEventListener("click", loadPortAnalysis);
document.getElementById("search-input").addEventListener("input", applyFiltersAndRender);
document.getElementById("risk-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("protocol-filter").addEventListener("change", applyFiltersAndRender);

loadPortAnalysis();
