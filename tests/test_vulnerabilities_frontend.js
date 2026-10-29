const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createPageContext() {
    const elements = new Map();
    const document = {
        addEventListener() {},
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                textContent: "",
                innerHTML: "",
                value: "",
                disabled: false,
                className: "",
                classList: { add() {}, remove() {} },
                addEventListener() {},
                setAttribute() {},
                removeAttribute() {}
            });
            return elements.get(id);
        },
        querySelectorAll() { return []; }
    };
    const context = vm.createContext({ document, URL, console });
    const sourcePath = path.join(__dirname, "..", "static", "js", "vulnerabilities.js");
    vm.runInContext(fs.readFileSync(sourcePath, "utf8"), context, { filename: sourcePath });
    return { context, element: id => document.getElementById(id) };
}

test("inventory search, sorting, pagination, missing versions, and HTML escaping work", () => {
    const { context, element } = createPageContext();
    element("software-page-size").value = "2";
    vm.runInContext(`allSoftware = [
        {software_name: "<Alpha>", publisher: "Publisher Z", version: "", source: "HKLM_64\\\\Unsafe"},
        {software_name: "Beta", publisher: "Publisher A", version: "2.0"},
        {software_name: "Gamma", publisher: "Publisher M", version: "10.0"}
    ]`, context);

    vm.runInContext("filterSoftware()", context);
    assert.match(element("software-table-body").innerHTML, /&lt;Alpha&gt;/);
    assert.match(element("software-table-body").innerHTML, /Not reported/);
    assert.equal(element("software-page-summary").textContent, "Showing 1-2 of 3 results");
    assert.equal(element("software-page-next").disabled, false);

    vm.runInContext("softwarePage = 1; filterSoftware()", context);
    assert.match(element("software-table-body").innerHTML, /Gamma/);
    assert.equal(element("software-page-summary").textContent, "Showing 3-3 of 3 results");
    assert.equal(element("software-page-next").disabled, true);

    vm.runInContext("sortSoftware('publisher')", context);
    assert.ok(element("software-table-body").innerHTML.indexOf("Beta") <
        element("software-table-body").innerHTML.indexOf("Gamma"));

    element("software-search").value = "publisher z";
    vm.runInContext("filterSoftware()", context);
    assert.match(element("software-table-body").innerHTML, /&lt;Alpha&gt;/);
    assert.equal(element("software-page-summary").textContent, "Showing 1-1 of 1 results");
});

test("inventory empty state and name/version sorting are available", () => {
    const { context, element } = createPageContext();
    element("software-page-size").value = "10";
    vm.runInContext(`allSoftware = [
        {software_name: "Zulu", publisher: "Publisher", version: "10.0"},
        {software_name: "Alpha", publisher: "Publisher", version: "2.0"},
        {software_name: "Middle", publisher: "Publisher", version: ""}
    ]; filterSoftware()`, context);
    vm.runInContext("sortSoftware('software_name')", context);
    assert.ok(element("software-table-body").innerHTML.indexOf("Zulu") <
        element("software-table-body").innerHTML.indexOf("Alpha"));
    vm.runInContext("sortSoftware('version')", context);
    const sortedByVersion = element("software-table-body").innerHTML;
    assert.ok(sortedByVersion.indexOf("Middle") < sortedByVersion.indexOf("Alpha"));
    assert.ok(sortedByVersion.indexOf("Alpha") < sortedByVersion.indexOf("Zulu"));

    vm.runInContext("allSoftware = []; filterSoftware()", context);
    assert.match(element("software-table-body").innerHTML, /No installed applications/);
    assert.equal(element("software-page-summary").textContent, "No applications match this search.");
});

test("findings render separate confidence, details, safe references, and escaped data", () => {
    const { context, element } = createPageContext();
    vm.runInContext(`renderFindingsTable([{
        cve_id: "CVE-2025-1234",
        software_name: "<img src=x onerror=alert(1)>",
        publisher: "Example <Publisher>",
        version: "Unknown",
        cvss_score: 8.0,
        severity: "HIGH",
        assessment_status: "Confirmed Version Match",
        effective_assessment_status: "Insufficient Information",
        software_identity_match: "Not fully assessed",
        version_match_confidence: "Not assessable",
        assessment_completeness: "Incomplete",
        description: "<script>alert(1)</script>",
        affected_versions: [{versionStartIncluding: "1.0", versionEndExcluding: "2.0"}],
        source: "NIST NVD API 2.0",
        detected_time: "2026-10-27 10:00:00",
        evidence: "No installed version",
        references: ["javascript:alert(1)", "https://nvd.nist.gov/vuln/detail/CVE-2025-1234"]
    }])`, context);

    const html = element("vuln-table-body").innerHTML;
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.doesNotMatch(html, /<img src=x|<script>alert/);
    assert.doesNotMatch(html, /javascript:/);
    assert.match(html, /Not assessable/);
    assert.match(html, /Incomplete/);
    assert.match(html, /NIST NVD API 2\.0/);
    assert.match(html, /from 1\.0 \(inclusive\)/);
    assert.match(html, /before 2\.0/);
    assert.match(html, /https:\/\/nvd\.nist\.gov/);
});

test("finding search and severity/status filters retain the right classifications", () => {
    const { context, element } = createPageContext();
    vm.runInContext(`allFindings = [
        {cve_id: "CVE-2025-0001", software_name: "High App", severity: "HIGH",
         assessment_status: "Confirmed Version Match"},
        {cve_id: "CVE-2025-0002", software_name: "Potential App", severity: "LOW",
         assessment_status: "Potential Match", description: "Searchable advisory text"},
        {cve_id: "N/A", software_name: "Unknown App", severity: "UNKNOWN",
         assessment_status: "Insufficient Information"}
    ]`, context);
    element("vuln-severity-filter").value = "HIGH";
    vm.runInContext("filterFindings()", context);
    assert.match(element("vuln-table-body").innerHTML, /CVE-2025-0001/);
    assert.doesNotMatch(element("vuln-table-body").innerHTML, /CVE-2025-0002/);

    element("vuln-severity-filter").value = "";
    element("vuln-status-filter").value = "Potential Match";
    element("vuln-search").value = "searchable advisory";
    vm.runInContext("filterFindings()", context);
    assert.match(element("vuln-table-body").innerHTML, /CVE-2025-0002/);
    assert.doesNotMatch(element("vuln-table-body").innerHTML, /CVE-2025-0001|Unknown App/);
});

test("test fixtures and incomplete findings do not inflate confirmed overview metrics", () => {
    const { context, element } = createPageContext();
    vm.runInContext(`allSoftware = [{software_name: "Example"}]; allFindings = [
        {cve_id: "CVE-2024-9999", software_name: "MockApp", is_test_fixture: true,
         effective_assessment_status: "Test Fixture - Not Verified", severity: "HIGH"},
        {cve_id: "CVE-2025-1234", software_name: "Unknown Version App",
         effective_assessment_status: "Insufficient Information", severity: "CRITICAL"}
    ]; updateKpis()`, context);
    assert.equal(element("kpi-total-software").textContent, "1");
    assert.equal(element("kpi-total-cves").textContent, "0");
    assert.equal(element("kpi-crit-high").textContent, "0");
    assert.equal(element("kpi-confirmed-matches").textContent, "0");
});

test("malformed API payloads surface an explicit error", async () => {
    const { context } = createPageContext();
    context.fetch = async () => ({ ok: true, json: async () => ({ findings: {} }) });
    assert.equal(await vm.runInContext("loadVulnerabilities()", context), false);
    assert.match(vm.runInContext("findingsError", context), /findings list/);
});
