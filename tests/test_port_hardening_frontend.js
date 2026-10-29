const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createPortPage(responses) {
    const elements = new Map();
    const tables = new Map([
        ["#ports-table tbody", { innerHTML: "", querySelectorAll: () => [] }],
        ["#remediation-table tbody", { innerHTML: "", querySelectorAll: () => [] }]
    ]);
    function classListFor(element) {
        return {
            add(name) {
                const classes = new Set(element.className.split(/\s+/).filter(Boolean));
                classes.add(name);
                element.className = [...classes].join(" ");
            },
            remove(name) {
                element.className = element.className.split(/\s+/).filter(value => value !== name).join(" ");
            }
        };
    }
    const document = {
        getElementById(id) {
            if (!elements.has(id)) {
                const element = {
                    id,
                    textContent: "",
                    innerHTML: "",
                    value: "",
                    className: "",
                    attributes: {},
                    listeners: {},
                    classList: null,
                    addEventListener(event, callback) {
                        this.listeners[event] = callback;
                    },
                    setAttribute(name, value) {
                        this.attributes[name] = value;
                    },
                    appendChild(child) {
                        this.child = child;
                    }
                };
                element.classList = classListFor(element);
                elements.set(id, element);
            }
            return elements.get(id);
        },
        querySelector(selector) {
            return tables.get(selector) || null;
        },
        addEventListener() {}
    };
    const context = vm.createContext({
        document,
        console: { error() {} },
        setTimeout() {},
        fetch: async () => {
            const response = responses.shift();
            if (response instanceof Error) throw response;
            return response;
        },
        escapeHTML(value) {
            return String(value ?? "").replace(/[&<>"']/g, character => ({
                "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
            })[character]);
        }
    });
    const sourcePath = path.join(__dirname, "..", "static", "js", "port_hardening.js");
    vm.runInContext(fs.readFileSync(sourcePath, "utf8"), context, { filename: sourcePath });
    return {
        context,
        element: id => document.getElementById(id),
        table: selector => tables.get(selector)
    };
}

function jsonResponse(data, status = 200) {
    return { ok: status >= 200 && status < 300, status, json: async () => data };
}

async function settleInitialLoad() {
    await new Promise(resolve => setImmediate(resolve));
}

test("summary uses API counts and port search, risk, and protocol filters work", async () => {
    const page = createPortPage([
        jsonResponse({
            total: 2,
            summary: { CRITICAL: 1, HIGH: 0, MEDIUM: 1, LOW: 0, SAFE: 0, UNKNOWN: 0 },
            is_admin: false,
            ports: [
                { port: 3389, protocol: "TCP", process_name: "Remote Desktop", local_address: "0.0.0.0", risk_level: "CRITICAL", exposure_type: "ALL_INTERFACES" },
                { port: 123, protocol: "UDP", process_name: "Windows Time", local_address: "127.0.0.1", risk_level: "MEDIUM", exposure_type: "LOOPBACK" }
            ]
        }),
        jsonResponse([])
    ]);
    await settleInitialLoad();

    assert.match(page.element("risk-summary-grid").innerHTML, />2</);
    assert.match(page.element("risk-summary-grid").innerHTML, />1</);
    assert.match(page.table("#ports-table tbody").innerHTML, /Remote Desktop/);
    assert.match(page.table("#ports-table tbody").innerHTML, /All interfaces/);
    assert.match(page.table("#ports-table tbody").innerHTML, /Localhost only/);
    assert.equal(page.element("ports-count").textContent, 2);
    assert.ok(!page.element("ph-content").className.includes("hidden"));
    assert.ok(!page.element("admin-warning").className.includes("hidden"));

    page.element("search-input").value = "Windows Time";
    page.element("search-input").listeners.input();
    assert.match(page.table("#ports-table tbody").innerHTML, /Windows Time/);
    assert.doesNotMatch(page.table("#ports-table tbody").innerHTML, /Remote Desktop/);

    page.element("search-input").value = "";
    page.element("risk-filter").value = "CRITICAL";
    page.element("risk-filter").listeners.change();
    assert.match(page.table("#ports-table tbody").innerHTML, /Remote Desktop/);
    assert.doesNotMatch(page.table("#ports-table tbody").innerHTML, /Windows Time/);

    page.element("risk-filter").value = "";
    page.element("protocol-filter").value = "UDP";
    page.element("protocol-filter").listeners.change();
    assert.match(page.table("#ports-table tbody").innerHTML, /Windows Time/);
    assert.doesNotMatch(page.table("#ports-table tbody").innerHTML, /Remote Desktop/);

    page.element("protocol-filter").value = "";
    page.element("exposure-filter").value = "LOOPBACK";
    page.element("exposure-filter").listeners.change();
    assert.match(page.table("#ports-table tbody").innerHTML, /Windows Time/);
    assert.doesNotMatch(page.table("#ports-table tbody").innerHTML, /Remote Desktop/);
});

test("empty API response displays a no-listening-ports state", async () => {
    const page = createPortPage([
        jsonResponse({ total: 0, summary: {}, ports: [], is_admin: true }),
        jsonResponse([])
    ]);
    await settleInitialLoad();

    assert.match(page.table("#ports-table tbody").innerHTML, /No listening ports detected/);
    assert.equal(page.element("ports-count").textContent, 0);
    assert.ok(page.element("loading").className.includes("hidden"));
});

test("failed analysis remains visible and exposes a retry action", async () => {
    const page = createPortPage([
        jsonResponse({ error: "Unable to analyze ports." }, 500),
        jsonResponse([]),
        jsonResponse({
            total: 0,
            summary: {},
            ports: [],
            is_admin: true
        }),
        jsonResponse([])
    ]);
    await settleInitialLoad();

    assert.match(page.element("loading-message").textContent, /Unable to load port analysis/);
    assert.ok(!page.element("retry-btn").className.includes("hidden"));
    assert.match(page.table("#ports-table tbody").innerHTML, /Use Retry/);
    assert.match(page.table("#remediation-table tbody").innerHTML, /No remediation actions taken yet/);
    assert.ok(!page.element("ph-content").className.includes("hidden"));

    await page.element("retry-btn").listeners.click();
    assert.match(page.table("#ports-table tbody").innerHTML, /No listening ports detected/);
    assert.ok(page.element("loading").className.includes("hidden"));
});
