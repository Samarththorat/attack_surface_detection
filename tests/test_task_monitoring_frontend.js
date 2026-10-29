const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createTaskMonitoringContext(fetchImplementation = async () => ({ ok: false, status: 503, json: async () => ({ error: "offline" }) })) {
    const elements = new Map();
    const chartCalls = [];
    class FakeChart {
        constructor(canvas, config) {
            this.canvas = canvas;
            this.config = config;
            chartCalls.push(config);
        }
        destroy() {}
    }
    const document = {
        getElementById(id) {
            if (!elements.has(id)) {
                const element = {
                    id,
                    textContent: "",
                    innerHTML: "",
                    value: "",
                    disabled: false,
                    dataset: {},
                    className: "",
                    listeners: {},
                    classList: {
                        add(name) { element.className = `${element.className} ${name}`.trim(); },
                        remove(name) { element.className = element.className.split(/\s+/).filter(item => item !== name).join(" "); }
                    },
                    addEventListener(event, callback) { this.listeners[event] = callback; },
                    querySelectorAll() { return []; }
                };
                elements.set(id, element);
            }
            return elements.get(id);
        }
    };
    const window = {
        Chart: FakeChart,
        setInterval() { return 1; },
        clearInterval() {}
    };
    const context = vm.createContext({
        document,
        window,
        console: { error() {} },
        fetch: fetchImplementation,
        escapeHTML(value) {
            return String(value ?? "").replace(/[&<>"']/g, character => ({
                "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
            })[character]);
        },
        Number,
        URL
    });
    const sourcePath = path.join(__dirname, "..", "static", "js", "task_monitoring.js");
    vm.runInContext(fs.readFileSync(sourcePath, "utf8"), context, { filename: sourcePath });
    return { context, element: id => document.getElementById(id), chartCalls };
}

test("resource rendering distinguishes unavailable telemetry from numeric measurements", () => {
    const { context, element } = createTaskMonitoringContext();
    vm.runInContext(`renderTaskSnapshot({
        sampled_at: "2026-10-29T00:00:00+00:00",
        cpu_usage_percent: 28.5,
        memory_usage_percent: 65,
        memory_used_bytes: 650,
        memory_total_bytes: 1000,
        disk_usage_percent: 70,
        disk_used_bytes: 700,
        disk_total_bytes: 1000,
        disk_read_bytes_per_sec: 100,
        disk_write_bytes_per_sec: 200,
        network_received_bytes_per_sec: null,
        network_sent_bytes_per_sec: null,
        gpu_usage_percent: null,
        running_processes: 1,
        process_access_denied: 0,
        process_cpu_basis: "Percent of one logical CPU",
        availability: {disk_io: true, network_io: true},
        availability_notes: {gpu: "GPU telemetry unsupported."},
        collection_errors: [],
        processes: [{
            identity: "5:100.0", pid: 5, name: "<unsafe>", cpu_percent: 120,
            memory_rss_bytes: 2048, memory_percent: 2, disk_read_bytes: 1024,
            disk_write_bytes: null, start_time: "today", state: "running",
            username: "test-user"
        }]
    })`, context);
    assert.equal(element("task-cpu").textContent, "28.5%");
    assert.equal(element("task-disk-capacity").textContent, "70.0%");
    assert.match(element("task-disk-io").textContent, /100 B\/s read/);
    assert.match(element("task-network").textContent, /Unavailable receive/);
    assert.equal(element("task-gpu").textContent, "Unavailable");
    assert.match(element("task-process-body").innerHTML, /&lt;unsafe&gt;/);
    assert.doesNotMatch(element("task-process-body").innerHTML, /<unsafe>/);

    element("task-process-search").value = "999";
    vm.runInContext("filterTaskProcesses()", context);
    assert.match(element("task-process-body").innerHTML, /No processes match/);
});

test("process sorting, filters, details, and stored charts use measured values", () => {
    const { context, element, chartCalls } = createTaskMonitoringContext();
    vm.runInContext(`renderTaskSnapshot({
        running_processes: 2, processes: [
            {pid: 2, name: "Beta", cpu_percent: 10, memory_percent: 30, state: "running"},
            {pid: 1, name: "Alpha", cpu_percent: 80, memory_percent: 20, state: "sleeping"}
        ],
        collection_errors: [], availability: {}, availability_notes: {}
    });
    taskElement("task-process-sort").value = "memory";
    filterTaskProcesses()`, context);
    assert.ok(element("task-process-body").innerHTML.indexOf("Beta") < element("task-process-body").innerHTML.indexOf("Alpha"));

    element("task-process-search").value = "Alpha";
    element("task-process-state").value = "sleeping";
    vm.runInContext("filterTaskProcesses()", context);
    assert.match(element("task-process-body").innerHTML, /Alpha/);
    assert.doesNotMatch(element("task-process-body").innerHTML, /Beta/);
    vm.runInContext("showTaskProcessDetails(0)", context);
    assert.match(element("task-details-body").innerHTML, /Read-only/);
    assert.doesNotMatch(element("task-details-body").innerHTML, /kill|terminate process/i);

    vm.runInContext(`renderTaskCharts([
        {sampled_at: "t2", cpu_usage_percent: 40, memory_usage_percent: 50, disk_usage_percent: 60,
            disk_read_bytes_per_sec: 120, network_received_bytes_per_sec: 300},
        {sampled_at: "t1", cpu_usage_percent: 20, memory_usage_percent: 30, disk_usage_percent: 40,
            disk_read_bytes_per_sec: null, network_received_bytes_per_sec: 100}
    ])`, context);
    assert.equal(chartCalls.length, 2);
    assert.deepEqual(Array.from(chartCalls[0].data.datasets[0].data), [20, 40]);
    assert.deepEqual(Array.from(chartCalls[1].data.datasets[0].data), [null, 120]);
    vm.runInContext("renderTaskCharts([])", context);
    assert.match(element("task-resource-chart-message").textContent, /No stored resource samples/);
});

test("a failed task-monitoring API response remains visible as an error", async () => {
    const { element } = createTaskMonitoringContext();
    await new Promise(resolve => setImmediate(resolve));
    assert.match(element("task-monitor-error").textContent, /Unable to refresh task monitoring: offline/);
    assert.equal(element("task-monitor-health").textContent, "Telemetry unavailable");
});
