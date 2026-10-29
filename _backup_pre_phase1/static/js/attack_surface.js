let currentInventory = null;

function riskClass(level) {
    return (level || "unknown").toLowerCase();
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
            <span class="label">${name}</span>
            <span class="value">${Array.isArray(ips) ? ips.join(", ") : ips}</span>
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
                <span class="label">${profile} Profile</span>
                <span class="value risk-tag ${cls}">${details.state}</span>
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
            <td>${p.port ?? "-"}</td>
            <td>${p.protocol ?? "-"}</td>
            <td>${p.process_name ?? "-"}</td>
            <td>${p.service_display_name || p.service_name || "-"}</td>
            <td>${p.local_address ?? "-"}</td>
            <td>${p.interface ?? "-"}</td>
            <td><span class="risk-tag ${riskClass(p.risk_level)}">${p.risk_level ?? "UNKNOWN"}</span></td>
            <td class="reason-cell">${p.risk_reason ?? "-"}</td>
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
            <td>${p.port ?? "-"}</td>
            <td>${p.protocol ?? "-"}</td>
            <td>${p.process_name ?? "-"}</td>
            <td>${p.service_display_name || p.service_name || "-"}</td>
            <td><span class="risk-tag ${riskClass(p.risk_level)}">${p.risk_level ?? "UNKNOWN"}</span></td>
            <td class="reason-cell">${p.risk_reason ?? "-"}</td>
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
            <td>${s.name}</td>
            <td>${s.pid}</td>
            <td>${s.status}</td>
            <td>${(s.listening_ports || []).join(", ") || "-"}</td>
            <td>${s.review_reason ?? "-"}</td>
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
        <div class="finding-item ${f.category}">
            <span class="finding-tag">${(f.category || "").replace("_", " ")}</span>
            <strong>${f.area}:</strong> ${f.detail}
        </div>
    `).join("");
}

document.getElementById("refresh-btn").addEventListener("click", loadInventory);
document.getElementById("search-input").addEventListener("input", applyFiltersAndRenderPorts);
document.getElementById("risk-filter").addEventListener("change", applyFiltersAndRenderPorts);
document.getElementById("protocol-filter").addEventListener("change", applyFiltersAndRenderPorts);

loadInventory();
