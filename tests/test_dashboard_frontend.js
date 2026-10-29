const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createDashboardContext() {
    const elements = new Map();
    const chartCalls = [];
    const eventSources = [];
    class FakeChart {
        constructor(canvas, config) {
            this.canvas = canvas;
            this.config = config;
            chartCalls.push(config);
        }
        destroy() {}
    }
    class FakeEventSource {
        constructor(url) {
            this.url = url;
            this.closed = false;
            eventSources.push(this);
        }
        close() {
            this.closed = true;
        }
    }
    const document = {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                id,
                textContent: "",
                innerHTML: "",
                value: "",
                disabled: false,
                className: "",
                style: {},
                dataset: {},
                classList: { add() {}, remove() {}, toggle() {} },
                parentElement: { querySelector() { return null; } },
                addEventListener() {},
                querySelectorAll() { return []; },
                setAttribute() {},
                removeAttribute() {},
                insertAdjacentElement() {}
            });
            return elements.get(id);
        },
        querySelectorAll() { return []; },
        querySelector() { return null; }
    };
    const window = { Chart: FakeChart, EventSource: FakeEventSource, setInterval() {} };
    const context = vm.createContext({
        document,
        window,
        EventSource: FakeEventSource,
        Chart: FakeChart,
        console: { warn() {}, error() {}, log() {} },
        fetch: async () => ({ ok: false, status: 503, json: async () => ({}) }),
        setTimeout() {},
        setInterval() {},
        URLSearchParams,
        escapeHTML(value) {
            return String(value ?? "").replace(/[&<>"']/g, character => ({
                "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
            })[character]);
        }
    });
    const sourcePath = path.join(__dirname, "..", "static", "js", "dashboard.js");
    vm.runInContext(fs.readFileSync(sourcePath, "utf8"), context, { filename: sourcePath });
    return { context, element: id => document.getElementById(id), chartCalls, eventSources };
}

test("overview counts use saved scan and unresolved-count data", () => {
    const { context, element } = createDashboardContext();
    vm.runInContext(`renderExecutiveSummary({
        risk: {total_score: 38, risk_level: "MEDIUM", unified_findings: [
            {priority_code: "P1", status: "New"},
            {priority_code: "P2", status: "Resolved"},
            {priority_code: "P3", status: "New"}
        ]},
        ports: [{port: 80}, {port: 443}],
        monitoring_unresolved_count: 7
    })`, context);
    assert.equal(element("summary-risk-score").textContent, "38/100");
    assert.equal(element("summary-listening-sockets").textContent, "2");
    assert.equal(element("summary-active-findings").textContent, "1");
    assert.equal(element("summary-unresolved-alerts").textContent, "7");
});

test("summary cards handle missing and partial assessment data", () => {
    const { context, element } = createDashboardContext();
    vm.runInContext("renderDashboard(null)", context);
    assert.equal(element("summary-risk-score").textContent, "—");
    assert.equal(element("summary-listening-sockets").textContent, "—");
    assert.equal(element("summary-active-findings").textContent, "—");
    assert.match(element("scan-completeness-status").textContent, /No saved assessment/);
    assert.match(element("pill-critical").textContent, /unavailable/);

    vm.runInContext(`renderDashboard({
        assessment_status: "PARTIAL",
        risk: {total_score: 12, unified_findings: [null, {priority_code: "P1"}]},
        ports: []
    })`, context);
    assert.equal(element("summary-risk-score").textContent, "12/100");
    assert.equal(element("summary-listening-sockets").textContent, "0");
    assert.equal(element("summary-active-findings").textContent, "1");
    assert.match(element("scan-completeness-status").textContent, /Partial assessment/);
    assert.equal(element("pill-critical").textContent, "Critical: unavailable");
});

test("attention area limits output to open P1/P2 items and escapes dynamic content", () => {
    const { context, element } = createDashboardContext();
    vm.runInContext(`renderAttentionFindings([
        {id: "one", title: "<img src=x>", priority_code: "P2", severity: "HIGH", status: "New", recommended_action: "Review <service>"},
        {id: "two", title: "Resolved", priority_code: "P1", severity: "CRITICAL", status: "Resolved"},
        {id: "three", title: "Accepted", priority_code: "P1", severity: "HIGH", status: "Accepted Risk"},
        {id: "four", title: "Critical open", priority_code: "P1", severity: "CRITICAL", status: "In Progress"},
        {id: "five", title: "High open", priority_code: "P2", severity: "HIGH", status: "New"},
        {id: "six", title: "Not prioritized", priority_code: "P3", severity: "MEDIUM", status: "New"}
    ], true)`, context);
    const html = element("attention-list").innerHTML;
    assert.equal((html.match(/class="attention-item"/g) || []).length, 3);
    assert.match(html, /&lt;img src=x&gt;/);
    assert.match(html, /Review &lt;service&gt;/);
    assert.doesNotMatch(html, /<img src=x>/);
    assert.doesNotMatch(html, /Resolved<\/h3>|Accepted<\/h3>|Not prioritized/);
});

test("priority findings use structured destinations and safely handle malformed items", () => {
    const { context, element } = createDashboardContext();
    assert.equal(vm.runInContext(`findingDestination({destination: "/activity", category: "Vulnerability"})`, context), "/activity");
    assert.equal(vm.runInContext(`findingDestination({category: "Vulnerability"})`, context), "/vulnerabilities");
    assert.equal(vm.runInContext(`findingDestination({target_type: "port"})`, context), "/port-hardening");
    assert.equal(vm.runInContext(`findingDestination({category: "Network Exposure"})`, context), "/port-hardening");
    assert.equal(vm.runInContext(`findingDestination({category: "Monitoring Event"})`, context), "/activity");
    assert.equal(vm.runInContext(`findingDestination({destination: "javascript:alert(1)", target_type: "software"})`, context), "/vulnerabilities");
    assert.equal(vm.runInContext(`findingDestination({category: "Unrecognized"})`, context), "/attack-surface");
    assert.equal(vm.runInContext(`findingDestination(null)`, context), "/attack-surface");

    vm.runInContext(`renderAttentionFindings([
        null, [], {priority_code: "P1", status: "New", title: "<unsafe>", category: "Vulnerability"}
    ], true)`, context);
    assert.match(element("attention-list").innerHTML, /href="\/vulnerabilities"/);
    assert.match(element("attention-list").innerHTML, /&lt;unsafe&gt;/);
});

test("structured finding evidence has a readable summary and escaped expandable details", () => {
    const { context, element } = createDashboardContext();
    vm.runInContext(`renderAttentionFindings([{
        id: "monitor-event",
        title: "Firewall change",
        priority_code: "P1",
        severity: "HIGH",
        status: "New",
        evidence: JSON.stringify({
            event_type: "FIREWALL_CHANGED",
            target: "<script>alert(1)</script>",
            component: "firewall"
        })
    }], true)`, context);
    const attention = element("attention-list").innerHTML;
    assert.match(attention, /Event Type: firewall changed/);
    assert.match(attention, /<details class="finding-evidence-details">/);
    assert.match(attention, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.doesNotMatch(attention, /<script>alert/);
    assert.doesNotMatch(attention, /\{"event_type"/);

    vm.runInContext(`renderFindings([null, [], {
        title: "<unsafe>",
        severity: {},
        confidence: {},
        evidence: {unfamiliar: {nested: true}}
    }])`, context);
    const findings = element("findings-list").innerHTML;
    assert.match(findings, /Untitled finding|&lt;unsafe&gt;/);
    assert.match(findings, /Structured evidence recorded/);
    assert.doesNotMatch(findings, /<unsafe>/);
});

test("severity chart uses real counts and trend requires two stored scores", () => {
    const { context, element, chartCalls } = createDashboardContext();
    vm.runInContext(`renderOverviewSeverityChart({
        CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 1, INFORMATIONAL: 0
    })`, context);
    assert.equal(chartCalls.length, 1);
    assert.deepEqual(Array.from(chartCalls[0].data.datasets[0].data), [1, 2, 0, 1, 0]);
    assert.equal(chartCalls[0].options.responsive, true);
    assert.equal(chartCalls[0].options.plugins.legend.position, "bottom");

    vm.runInContext(`renderTrendChart([{id: 1, risk_score: 42}])`, context);
    assert.equal(chartCalls.length, 1);
    assert.match(element("trendChart-message").textContent, /at least two assessments/);

    vm.runInContext(`renderTrendChart([
        {id: 1, risk_score: 42}, {id: 2, risk_score: 37}
    ])`, context);
    assert.equal(chartCalls.length, 2);
    assert.equal(chartCalls[1].options.plugins.legend.display, true);
    assert.equal(chartCalls[1].data.datasets[0].data.length, 2);

    vm.runInContext("renderTrendChart([])", context);
    assert.match(element("trendChart-message").textContent, /No stored assessment history/);
});

test("missing severity data and incomplete findings are not presented as zero findings", () => {
    const { context, element } = createDashboardContext();
    vm.runInContext(`renderExecutiveSummary({risk: {total_score: null}})`, context);
    assert.equal(element("summary-risk-score").textContent, "—");
    assert.equal(element("summary-active-findings").textContent, "—");
    vm.runInContext("renderAttentionFindings(undefined, true)", context);
    assert.match(element("attention-list").innerHTML, /could not be determined/);
    vm.runInContext("renderOverviewSeverityChart(null)", context);
    assert.match(element("overview-severity-chart-message").textContent, /No severity data/);
    vm.runInContext("renderOverviewSeverityChart({CRITICAL: 1})", context);
    assert.match(element("overview-severity-chart-message").textContent, /incomplete/);
    vm.runInContext("renderOverviewSeverityChart({CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0})", context);
    assert.match(element("overview-severity-chart-message").textContent, /No findings were recorded/);
    assert.equal(vm.runInContext(`riskLevelClass("INFORMATIONAL")`, context), "informational");
    assert.equal(vm.runInContext(`riskLevelClass("UNRECOGNIZED")`, context), "unknown");
});

test("recent activity remains compact and reports empty or unavailable event data", () => {
    const { context, element } = createDashboardContext();
    vm.runInContext("renderRecentActivity([])", context);
    assert.match(element("dashboard-recent-activity-body").innerHTML, /No monitoring events/);
    vm.runInContext("renderRecentActivity(null)", context);
    assert.match(element("dashboard-recent-activity-body").innerHTML, /currently unavailable/);
});

test("live remediation events refresh status, activity, ports, and the saved assessment", async () => {
    const { context, eventSources } = createDashboardContext();
    const requests = [];
    const scan = {
        id: 8,
        scan_time: "2026-03-01 10:00:00",
        full_results: {
            assessment_status: "COMPLETE",
            risk: { total_score: 18, risk_level: "Low", unified_findings: [] },
            ports: [{ port: 443 }],
            system_info: {}
        }
    };
    context.fetch = async url => {
        requests.push(url);
        const data = url === "/api/monitoring/status"
            ? { monitoring_active: true, monitoring_health: "HEALTHY", unresolved_events_count: 0 }
            : url === "/api/monitoring/events?limit=5"
                ? []
                : url === "/api/port-analysis"
                    ? { total: 1, ports: [{ port: 443 }] }
                    : url === "/api/history?limit=1" || url === "/api/history?limit=20"
                        ? [{ id: 8 }]
                        : url === "/api/scan/8"
                            ? scan
                            : {};
        return { ok: true, status: 200, json: async () => data };
    };

    vm.runInContext("initLiveMonitoring()", context);
    const source = eventSources.at(-1);
    assert.equal(source.url, "/api/monitoring/stream");
    source.onmessage({ data: JSON.stringify({ type: "remediation", data: {} }) });
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));

    assert.ok(requests.includes("/api/monitoring/status"));
    assert.ok(requests.includes("/api/monitoring/events?limit=5"));
    assert.ok(requests.includes("/api/port-analysis"));
    assert.ok(requests.includes("/api/history?limit=1"));
    assert.ok(requests.includes("/api/scan/8"));
});
