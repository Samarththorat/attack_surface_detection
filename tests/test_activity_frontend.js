const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function createActivityContext() {
    const elements = new Map();
    const document = {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                textContent: "",
                innerHTML: "",
                value: "",
                checked: false,
                disabled: false,
                className: "",
                classList: { add() {}, remove() {} },
                addEventListener() {}
            });
            return elements.get(id);
        }
    };
    const context = vm.createContext({
        document,
        URLSearchParams,
        console,
        escapeHTML(value) {
            return String(value ?? "").replace(/[&<>"']/g, character => ({
                "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
            })[character]);
        },
        riskLevelClass(value) {
            return ["critical", "high", "medium", "low", "info"].includes(String(value).toLowerCase())
                ? String(value).toLowerCase()
                : "unknown";
        }
    });
    const sourcePath = path.join(__dirname, "..", "static", "js", "activity.js");
    vm.runInContext(fs.readFileSync(sourcePath, "utf8"), context, { filename: sourcePath });
    return { context, element: id => document.getElementById(id) };
}

test("activity history escapes event fields and preserves resolved and workflow states", () => {
    const { context, element } = createActivityContext();
    vm.runInContext(`renderActivityEvents([{
        id: 5, timestamp: "2026-01-02", severity: "HIGH",
        event_type: "<script>alert(1)</script>", target: "<host>",
        details_parsed: {evidence: "<img src=x>"},
        is_resolved: false, is_acknowledged: true, is_reviewed: false
    }])`, context);
    const html = element("activity-events-body").innerHTML;
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(html, /&lt;host&gt;/);
    assert.match(html, /&lt;img src=x&gt;/);
    assert.match(html, /Unresolved · Acknowledged/);
    assert.doesNotMatch(html, /<script>|<img src=x>/);
    assert.match(html, /Mark reviewed/);
    assert.doesNotMatch(html, />Acknowledge</);
});
