const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createAnalyticsContext() {
    const elements = new Map();
    const chartCalls = [];
    class FakeChart {
        constructor(canvas, config) { chartCalls.push(config); }
    }
    const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[character]);
    const document = {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                textContent: "",
                innerHTML: "",
                value: "",
                style: {},
                className: "",
                addEventListener() {},
                classList: { add() {}, remove() {} }
            });
            return elements.get(id);
        }
    };
    const context = vm.createContext({
        document,
        window: { Chart: FakeChart },
        Chart: FakeChart,
        console,
        escapeHTML
    });
    const sourcePath = path.join(__dirname, "..", "static", "js", "analytics.js");
    vm.runInContext(fs.readFileSync(sourcePath, "utf8"), context, { filename: sourcePath });
    return { context, element: id => document.getElementById(id), chartCalls };
}

test("analytics charts render stored values and omit synthetic trend data", () => {
    const { context, element, chartCalls } = createAnalyticsContext();
    vm.runInContext(`renderRiskTrend([{scan_id: 1, timestamp: "2025-01-01", score: 40}])`, context);
    assert.equal(chartCalls.length, 0);
    assert.match(element("analytics-risk-chart-message").textContent, /at least two saved assessments/);

    vm.runInContext(`renderRiskTrend([
        {scan_id: 1, timestamp: "2025-01-01", score: 40},
        {scan_id: 2, timestamp: "2025-01-02", score: 33}
    ])`, context);
    vm.runInContext(`renderObjectChart("analytics-severity-chart", {HIGH: 2, LOW: 1}, "doughnut")`, context);
    assert.equal(chartCalls.length, 2);
    assert.deepEqual(Array.from(chartCalls[0].data.datasets[0].data), [40, 33]);
    assert.deepEqual(Array.from(chartCalls[1].data.datasets[0].data), [2, 1]);
});

test("analytics reports incomplete current vulnerability data as unavailable", () => {
    const { context, element } = createAnalyticsContext();
    vm.runInContext(`renderVulnerabilitySummary({
        unique_cves: 2, unique_affected_software_cve_pairs: 3, currently_active_findings: null,
        current_assessment_state: "INCOMPLETE"
    })`, context);
    assert.match(element("vulnerability-analytics-summary").textContent, /Currently active: Unavailable/);
});

test("analytics history uses saved rows and escapes dynamic values", () => {
    const { context, element } = createAnalyticsContext();
    vm.runInContext(`renderAssessmentHistory([
        {id: 5, scan_time: "<time>", listening_ports_count: 2, findings_count: 1,
         firewall_status: "ON", risk_score: 38, risk_level: "MEDIUM"},
        null
    ])`, context);
    assert.match(element("assessment-history-body").innerHTML, /&lt;time&gt;/);
    assert.match(element("assessment-history-body").innerHTML, /class="risk-tag medium"/);
    assert.doesNotMatch(element("assessment-history-body").innerHTML, /<time>/);

    vm.runInContext("renderAssessmentHistory([])", context);
    assert.match(element("assessment-history-body").innerHTML, /No saved assessments/);
    vm.runInContext("renderAssessmentHistory(null)", context);
    assert.match(element("assessment-history-message").textContent, /could not be loaded/);
});

test("assessment comparison retains stored deltas and escapes record data", () => {
    const { context, element } = createAnalyticsContext();
    vm.runInContext(`renderComparison({
        before: {id: 1, scan_time: "<before>", listening_ports_count: 2, findings_count: 3, firewall_status: "ON", risk_score: 50, risk_level: "HIGH"},
        after: {id: 2, scan_time: "after", listening_ports_count: 1, findings_count: 2, firewall_status: "ON", risk_score: 40, risk_level: "MEDIUM"},
        delta: {ports_change: -1, findings_change: -1, risk_score_change: -10,
            findings: {comparable: true, new: [], persistent: [], resolved: [], reopened: []}}
    })`, context);
    assert.match(element("compare-results").innerHTML, /&lt;before&gt;/);
    assert.match(element("compare-results").innerHTML, /Risk Score Change/);
    assert.doesNotMatch(element("compare-results").innerHTML, /<before>/);
});

test("latest assessment details use recorded scores, categories, and controls", () => {
    const { context, element, chartCalls } = createAnalyticsContext();
    vm.runInContext(`renderLatestRiskDetails({
        total_score: 38, risk_level: "MEDIUM",
        severity_distribution: {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 0, INFORMATIONAL: 0},
        top_findings: [{title: "<unsafe>", severity: "HIGH"}],
        mitigating_factors: ["<control>"],
        breakdown_items: [{category: "Firewall", points_awarded: 5, max_points: 20, reason: "Recorded score"}]
    })`, context);
    assert.equal(element("analytics-risk-score").textContent, "38");
    assert.equal(element("analytics-risk-progress").style.width, "38%");
    assert.equal(element("analytics-pill-high").textContent, "1 High");
    assert.match(element("analytics-risk-top-findings").innerHTML, /&lt;unsafe&gt;/);
    assert.match(element("analytics-risk-mitigations").innerHTML, /&lt;control&gt;/);
    assert.equal(chartCalls.length, 1);
    assert.deepEqual(Array.from(chartCalls[0].data.datasets[0].data), [5]);
    assert.equal(chartCalls[0].options.responsive, true);

    vm.runInContext(`renderLatestRiskDetails({breakdown_items: [], breakdown_error: "Recorded breakdown unavailable"})`, context);
    assert.match(element("analytics-risk-breakdown-chart-message").textContent, /Recorded breakdown unavailable/);
    vm.runInContext("renderLatestRiskDetails(null)", context);
    assert.match(element("analytics-risk-breakdown-chart-message").textContent, /No saved assessment/);
});
