/**
 * Frontend controller for vulnerability findings and the read-only software inventory.
 */

let allSoftware = [];
let allFindings = [];
let overviewMetrics = null;
let softwareSort = { key: "software_name", direction: "asc" };
let softwarePage = 0;
let inventoryError = "";
let findingsError = "";

document.addEventListener("DOMContentLoaded", () => {
    initVulnerabilitiesPage();
});

async function initVulnerabilitiesPage() {
    setupEventListeners();
    await Promise.all([loadSoftwareInventory(), loadVulnerabilities()]);
    hideLoading();
}

function setupEventListeners() {
    document.getElementById("refresh-inv-btn")?.addEventListener("click", refreshInventory);
    document.getElementById("run-cve-scan-btn")?.addEventListener("click", triggerCveScan);
    document.getElementById("vuln-search")?.addEventListener("input", filterFindings);
    document.getElementById("vuln-severity-filter")?.addEventListener("change", filterFindings);
    document.getElementById("vuln-status-filter")?.addEventListener("change", filterFindings);
    document.getElementById("software-search")?.addEventListener("input", () => {
        softwarePage = 0;
        filterSoftware();
    });
    document.getElementById("software-page-size")?.addEventListener("change", () => {
        softwarePage = 0;
        filterSoftware();
    });
    document.getElementById("software-page-prev")?.addEventListener("click", () => {
        softwarePage = Math.max(0, softwarePage - 1);
        filterSoftware();
    });
    document.getElementById("software-page-next")?.addEventListener("click", () => {
        softwarePage += 1;
        filterSoftware();
    });
    document.querySelectorAll(".sort-button").forEach(button => {
        button.addEventListener("click", () => sortSoftware(button.dataset.sort));
    });
}

function showLoading(message) {
    const loading = document.getElementById("loading");
    if (loading) {
        loading.textContent = message;
        loading.classList.remove("hidden");
    }
}

function hideLoading() {
    document.getElementById("loading")?.classList.add("hidden");
    document.getElementById("vuln-content")?.classList.remove("hidden");
}

function showFeedback(message, kind) {
    const feedback = document.getElementById("scan-feedback");
    if (!feedback) return;
    feedback.textContent = message;
    feedback.className = `scan-feedback ${kind}`;
}

async function fetchJson(url, options) {
    const response = await fetch(url, options);
    let data;
    try {
        data = await response.json();
    } catch (error) {
        throw new Error("The server returned an invalid response. Try again or check application logs.");
    }
    if (!response.ok) {
        throw new Error(data && typeof data.error === "string"
            ? data.error
            : `Request failed with status ${response.status}.`);
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
        throw new Error("The server returned an unexpected response.");
    }
    return data;
}

async function refreshInventory() {
    const button = document.getElementById("refresh-inv-btn");
    if (button) button.disabled = true;
    showLoading("Refreshing the supported Windows Registry inventory...");
    try {
        await loadSoftwareInventory(true);
    } finally {
        hideLoading();
        if (button) button.disabled = false;
    }
}

async function loadSoftwareInventory(forceFresh = false) {
    try {
        const url = forceFresh ? "/api/software-inventory?fresh=true" : "/api/software-inventory";
        const data = await fetchJson(url);
        if (!Array.isArray(data.software)) {
            throw new Error("The inventory response did not contain a software list.");
        }
        allSoftware = data.software;
        inventoryError = "";
        filterSoftware();
        updateKpis();
        return true;
    } catch (error) {
        inventoryError = error.message || "Unable to load the software inventory.";
        allSoftware = [];
        renderSoftwareTable([]);
        updateKpis();
        return false;
    }
}

async function loadVulnerabilities() {
    try {
        const data = await fetchJson("/api/vulnerabilities?limit=1000");
        if (!Array.isArray(data.findings)) {
            throw new Error("The findings response did not contain a findings list.");
        }
        allFindings = data.findings;
        overviewMetrics = data.overview && typeof data.overview === "object"
            ? data.overview
            : null;
        findingsError = "";
        renderNvdStatus(data.nvd_status);
        filterFindings();
        updateKpis();
        return true;
    } catch (error) {
        findingsError = error.message || "Unable to load vulnerability findings.";
        allFindings = [];
        overviewMetrics = null;
        renderFindingsTable([]);
        updateKpis();
        renderNvdStatus(null);
        return false;
    }
}

async function triggerCveScan() {
    const button = document.getElementById("run-cve-scan-btn");
    if (button?.disabled) return;
    if (button) {
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
    }
    showFeedback("Assessment running. The backend does not report incremental progress.", "warning");
    showLoading("Assessing installed software against NIST NVD data. This may take several seconds...");
    try {
        const data = await fetchJson("/api/vulnerabilities/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ offline_mode: false, max_items: 20 })
        });
        if (data.success !== true || !data.statuses || typeof data.statuses !== "object") {
            throw new Error(typeof data.error === "string" ? data.error : "The assessment did not return a valid result.");
        }

        const refreshed = await Promise.all([loadVulnerabilities(), loadSoftwareInventory()]);
        const confirmed = Number(data.statuses["Confirmed Version Match"] || 0);
        const potential = Number(data.statuses["Potential Match"] || 0);
        const incomplete = [
            "Insufficient Information",
            "Assessment Incomplete",
            "Vulnerability Source Unavailable"
        ].reduce((total, status) => total + Number(data.statuses[status] || 0), 0);
        const isComplete = data.assessment_complete === true;
        const evaluated = Number(data.software_evaluated) || 0;
        const total = Number(data.software_total);
        const coverage = Number.isFinite(total) ? `${evaluated} of ${total}` : `${evaluated}`;
        const resultMessage = `Assessment ${isComplete ? "complete" : "partial"}: ${confirmed} confirmed version match(es), ${potential} potential match(es), ${incomplete} incomplete result(s); evaluated ${coverage} application(s).`;
        showFeedback(refreshed.every(Boolean)
            ? resultMessage
            : `${resultMessage} Some page data could not be refreshed.`,
        isComplete && refreshed.every(Boolean) ? "success" : "warning");
    } catch (error) {
        showFeedback(error.message || "Unable to complete the CVE assessment.", "error");
    } finally {
        hideLoading();
        if (button) {
            button.disabled = false;
            button.removeAttribute("aria-busy");
        }
    }
}

function findingStatus(finding) {
    return finding.effective_assessment_status || finding.assessment_status || "Assessment Incomplete";
}

function isTestFixture(finding) {
    return finding.is_test_fixture === true;
}

function isIncompleteStatus(status) {
    return [
        "Insufficient Information",
        "Assessment Incomplete",
        "Vulnerability Source Unavailable",
        "Test Fixture - Not Verified"
    ].includes(status);
}

function updateKpis() {
    const productionFindings = allFindings.filter(f => !isTestFixture(f));
    const actualMatches = productionFindings.filter(f =>
        f.cve_id && f.cve_id !== "N/A" &&
        ["Confirmed Version Match", "Potential Match"].includes(findingStatus(f))
    );
    const metric = (key, fallback) => {
        const value = Number(overviewMetrics?.[key]);
        return Number.isFinite(value) && value >= 0 ? value : fallback;
    };
    setText("kpi-total-software", allSoftware.length);
    setText("kpi-total-cves", metric("total_cve_matches", actualMatches.length));
    setText("kpi-crit-high", metric("critical_high_cves", actualMatches.filter(f =>
        ["CRITICAL", "HIGH"].includes(String(f.severity || "").toUpperCase())
    ).length));
    setText("kpi-confirmed-matches", metric("confirmed_version_matches", actualMatches.filter(f =>
        findingStatus(f) === "Confirmed Version Match"
    ).length));
    setText("vuln-count-tag", `${metric("finding_records", allFindings.length)} Recorded`);
    setText("software-count-tag", `${allSoftware.length} Applications`);
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = String(value);
}

function renderNvdStatus(status) {
    if (!status || typeof status !== "object") {
        setText("nvd-source-state", findingsError || "Source and assessment status unavailable.");
        setText("nvd-cache-badge", "Cache status unavailable");
        setText("nvd-last-success", "Not recorded");
        setText("nvd-rate-limit", "Unknown");
        setText("nvd-assessment-time", "No assessment recorded");
        setText("nvd-assessment-completeness", "Unknown");
        return;
    }
    setText("nvd-source-state", status.source_state || "Source state not reported");
    setText("nvd-cache-badge", status.cached_data_available
        ? `Cached data available (${Number(status.cached_data_entries) || 0} current entr${status.cached_data_entries === 1 ? "y" : "ies"})`
        : "No current cached data");
    setText("nvd-last-success", status.last_successful_source_request || "Not recorded");
    setText("nvd-rate-limit", status.rate_limited ? "Rate limited" : "No rate limit reported");
    setText("nvd-assessment-time", status.assessment_timestamp || "No assessment recorded");
    const completeness = status.assessment_complete === true
        ? "Complete"
        : status.assessment_complete === false
            ? `Partial (${Number(status.software_evaluated) || 0} of ${Number(status.software_total) || Number(status.software_evaluated) || 0})`
            : "Not assessed";
    setText("nvd-assessment-completeness", completeness);
}

function renderFindingsTable(findings) {
    const tbody = document.getElementById("vuln-table-body");
    if (!tbody) return;
    if (!findings.length) {
        const message = findingsError || "No vulnerability findings recorded. Run an assessment to create a new snapshot.";
        tbody.innerHTML = `<tr><td colspan="10" class="table-empty">${escapeHtml(message)}</td></tr>`;
        return;
    }

    tbody.innerHTML = findings.map(finding => {
        const status = findingStatus(finding);
        const severity = String(finding.severity || "UNKNOWN").toUpperCase();
        const severityClass = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity)
            ? `severity-${severity.toLowerCase()}`
            : "severity-unknown";
        const cvss = finding.cvss_score !== null && finding.cvss_score !== undefined
            && finding.cvss_score !== ""
            && Number.isFinite(Number(finding.cvss_score))
            ? Number(finding.cvss_score).toFixed(1)
            : "N/A";
        const completeness = finding.assessment_completeness
            || (isIncompleteStatus(status) ? "Incomplete" : "Complete");
        const identityMatch = finding.software_identity_match || (
            ["Confirmed Version Match", "Potential Match"].includes(status)
                ? "Matched in assessment"
                : "Not established"
        );
        const versionConfidence = finding.version_match_confidence || (
            status === "Confirmed Version Match" ? "Confirmed by version criteria"
                : status === "Potential Match" ? "Unconfirmed"
                    : isIncompleteStatus(status) ? "Not assessable" : "No version match"
        );
        const version = finding.version || finding.software_version;
        const product = `${escapeHtml(finding.software_name || "Unknown product")}${finding.publisher
            ? `<span class="publisher-name">${escapeHtml(finding.publisher)}</span>` : ""}`;
        const references = safeReferences(finding);
        const referenceMarkup = references.length
            ? references.map(reference => `<a href="${escapeHtml(reference)}" target="_blank" rel="noopener noreferrer">Open ↗</a>`).join("<br>")
            : validCveId(finding.cve_id)
                ? `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.cve_id)}" target="_blank" rel="noopener noreferrer">NVD record ↗</a>`
                : "Not available";
        const affected = affectedVersionText(finding.affected_versions);
        const details = [
            detailField("Description", finding.description),
            affected ? detailField("Affected version criteria", affected) : "",
            detailField("Matching evidence", finding.evidence),
            detailField("Source", finding.source),
            detailField("Assessment timestamp", finding.detected_time),
            detailField("Recommended mitigation", finding.recommended_mitigation)
        ].filter(Boolean).join("");
        const evidence = finding.evidence || "No matching evidence recorded.";
        const detailPanel = details
            ? `<details class="finding-details"><summary>Details</summary><div class="finding-detail-content">${details}${references.length ? `<h3>References</h3><ul>${references.map(url => `<li><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a></li>`).join("")}</ul>` : ""}</div></details>`
            : `<span class="match-chip match-neutral">No additional details</span>`;

        return `<tr>
            <td><strong class="cve-id">${escapeHtml(finding.cve_id || "N/A")}</strong></td>
            <td class="product-name">${product}</td>
            <td><span class="mono-badge">${escapeHtml(version || "Not reported")}</span></td>
            <td><span class="severity-chip ${severityClass}">${escapeHtml(severity)}</span><div>CVSS ${escapeHtml(cvss)}</div></td>
            <td><span class="match-chip ${matchClass(status)}">${escapeHtml(identityMatch)}</span></td>
            <td><span class="match-chip ${matchClass(status)}">${escapeHtml(versionConfidence)}</span></td>
            <td><span class="completeness-chip ${completeness === "Complete" ? "complete-yes" : "complete-no"}">${escapeHtml(completeness)}</span></td>
            <td><details class="evidence-summary"><summary>Evidence</summary><div>${escapeHtml(evidence)}</div></details></td>
            <td>${referenceMarkup}</td>
            <td>${detailPanel}</td>
        </tr>`;
    }).join("");
}

function matchClass(status) {
    if (status === "Confirmed Version Match") return "match-confirmed";
    if (status === "Potential Match") return "match-potential";
    if (status === "Test Fixture - Not Verified") return "match-fixture";
    if (isIncompleteStatus(status)) return "match-incomplete";
    return "match-neutral";
}

function detailField(label, value) {
    if (value === null || value === undefined || String(value).trim() === "") return "";
    return `<h3>${escapeHtml(label)}</h3><p>${escapeHtml(value)}</p>`;
}

function affectedVersionText(entries) {
    if (!Array.isArray(entries)) return "";
    return entries.map(entry => {
        if (typeof entry === "string") return entry;
        if (!entry || typeof entry !== "object") return "";
        const bounds = [
            entry.versionStartIncluding && `from ${entry.versionStartIncluding} (inclusive)`,
            entry.versionStartExcluding && `after ${entry.versionStartExcluding}`,
            entry.versionEndIncluding && `through ${entry.versionEndIncluding} (inclusive)`,
            entry.versionEndExcluding && `before ${entry.versionEndExcluding}`,
            entry.version && entry.version !== "*" && `exact version ${entry.version}`,
            entry.version === "*" && "CPE wildcard version"
        ].filter(Boolean);
        return bounds.length ? bounds.join("; ") : "";
    }).filter(Boolean).join(" | ");
}

function validCveId(value) {
    return /^CVE-\d{4}-\d{4,}$/i.test(String(value || ""));
}

function safeReferences(finding) {
    let references = finding.references;
    if (!Array.isArray(references) && typeof finding.references_json === "string") {
        try {
            references = JSON.parse(finding.references_json);
        } catch (error) {
            references = [];
        }
    }
    if (!Array.isArray(references)) return [];
    return references.filter(value => {
        if (typeof value !== "string") return false;
        try {
            return new URL(value).protocol === "https:";
        } catch (error) {
            return false;
        }
    });
}

function filterFindings() {
    const query = (document.getElementById("vuln-search")?.value || "").toLowerCase().trim();
    const severity = document.getElementById("vuln-severity-filter")?.value || "";
    const status = document.getElementById("vuln-status-filter")?.value || "";
    const filtered = allFindings.filter(finding => {
        const effectiveStatus = findingStatus(finding);
        if (severity && String(finding.severity || "").toUpperCase() !== severity.toUpperCase()) return false;
        if (status && effectiveStatus !== status) return false;
        if (!query) return true;
        return [
            finding.cve_id,
            finding.software_name,
            finding.publisher,
            finding.description,
            finding.evidence
        ].some(value => String(value || "").toLowerCase().includes(query));
    });
    renderFindingsTable(filtered);
}

function sortSoftware(key) {
    if (!["software_name", "publisher", "version"].includes(key)) return;
    softwareSort = {
        key,
        direction: softwareSort.key === key && softwareSort.direction === "asc" ? "desc" : "asc"
    };
    softwarePage = 0;
    document.querySelectorAll(".sort-button").forEach(button => {
        const th = button.closest("th");
        if (th) th.setAttribute("aria-sort", button.dataset.sort === key
            ? (softwareSort.direction === "asc" ? "ascending" : "descending")
            : "none");
    });
    filterSoftware();
}

function filterSoftware() {
    const query = (document.getElementById("software-search")?.value || "").toLowerCase().trim();
    const filtered = allSoftware.filter(software => {
        return !query || [software.software_name, software.publisher]
            .some(value => String(value || "").toLowerCase().includes(query));
    });
    filtered.sort((a, b) => {
        const left = String(a[softwareSort.key] || "").toLowerCase();
        const right = String(b[softwareSort.key] || "").toLowerCase();
        return left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" })
            * (softwareSort.direction === "asc" ? 1 : -1);
    });
    const pageSize = Number(document.getElementById("software-page-size")?.value) || 25;
    const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
    softwarePage = Math.min(softwarePage, pageCount - 1);
    const start = softwarePage * pageSize;
    renderSoftwareTable(filtered.slice(start, start + pageSize));

    const summary = document.getElementById("software-page-summary");
    if (summary) {
        summary.textContent = filtered.length
            ? `Showing ${start + 1}-${Math.min(start + pageSize, filtered.length)} of ${filtered.length} results`
            : inventoryError || "No applications match this search.";
    }
    const previous = document.getElementById("software-page-prev");
    const next = document.getElementById("software-page-next");
    if (previous) previous.disabled = softwarePage <= 0 || filtered.length === 0;
    if (next) next.disabled = softwarePage >= pageCount - 1 || filtered.length === 0;
}

function renderSoftwareTable(software) {
    const tbody = document.getElementById("software-table-body");
    if (!tbody) return;
    if (!software.length) {
        const message = inventoryError || "No installed applications match this search.";
        tbody.innerHTML = `<tr><td colspan="6" class="table-empty">${escapeHtml(message)}</td></tr>`;
        return;
    }
    tbody.innerHTML = software.map(item => `<tr>
        <td><strong>${escapeHtml(item.software_name || "Unknown application")}</strong></td>
        <td>${escapeHtml(item.publisher || "Unknown publisher")}</td>
        <td><span class="mono-badge">${escapeHtml(item.version || "Not reported")}</span></td>
        <td>${escapeHtml(item.install_date || "Unknown")}</td>
        <td>${escapeHtml(item.detected_time || "Not recorded")}</td>
        <td><details><summary>Registry details</summary><div><strong>Source:</strong> ${escapeHtml(item.source || "Not recorded")}<br><strong>Install location:</strong> ${escapeHtml(item.install_location || "Not recorded")}</div></details></td>
    </tr>`).join("");
}

function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
