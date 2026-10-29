const activityPageSize = 50;
let activityOffset = 0;
let activityHasNext = false;

function activityValue(value, fallback = "—") {
    return value === null || value === undefined || value === "" ? fallback : String(value);
}

function renderActivityEvents(events) {
    const body = document.getElementById("activity-events-body");
    if (!body) return;
    if (!Array.isArray(events) || events.length === 0) {
        body.innerHTML = `<tr><td colspan="7">No monitoring events match these filters.</td></tr>`;
        return;
    }
    body.innerHTML = events.map(event => {
        const severity = String(event.severity || "INFO").toUpperCase();
        const details = event.details_parsed
            ? JSON.stringify(event.details_parsed, null, 2)
            : activityValue(event.details, "No additional evidence recorded.");
        const state = event.is_resolved ? "Resolved" : "Unresolved";
        const acknowledged = Boolean(event.is_acknowledged);
        const reviewed = Boolean(event.is_reviewed);
        const workflow = [
            acknowledged ? "Acknowledged" : "",
            reviewed ? "Reviewed" : ""
        ].filter(Boolean).join(" · ");
        const status = workflow ? `${state} · ${workflow}` : state;
        const eventId = Number(event.id);
        const actionButtons = [
            !acknowledged
                ? `<button type="button" class="btn-secondary" data-event-action="acknowledge" data-event-id="${eventId}">Acknowledge</button>`
                : "",
            !reviewed
                ? `<button type="button" class="btn-secondary" data-event-action="review" data-event-id="${eventId}">Mark reviewed</button>`
                : ""
        ].filter(Boolean).join(" ");
        return `<tr>
            <td>${escapeHTML(activityValue(event.timestamp))}</td>
            <td><span class="risk-tag ${riskLevelClass(severity)}">${escapeHTML(severity)}</span></td>
            <td>${escapeHTML(activityValue(event.event_type, "Monitoring event"))}</td>
            <td>${escapeHTML(activityValue(event.target))}</td>
            <td><details class="event-evidence"><summary>View evidence</summary><pre>${escapeHTML(details)}</pre></details></td>
            <td>${escapeHTML(status)}</td>
            <td class="activity-actions">${actionButtons || "—"}</td>
        </tr>`;
    }).join("");
}

async function loadActivityEvents() {
    const body = document.getElementById("activity-events-body");
    const feedback = document.getElementById("activity-feedback");
    const next = document.getElementById("activity-next");
    const previous = document.getElementById("activity-previous");
    const pageLabel = document.getElementById("activity-page-label");
    if (body) body.innerHTML = `<tr><td colspan="7">Loading monitoring events…</td></tr>`;
    if (feedback) feedback.classList.add("hidden");

    const params = new URLSearchParams({
        limit: String(activityPageSize + 1),
        offset: String(activityOffset)
    });
    const severity = document.getElementById("activity-severity").value;
    if (severity) params.set("severity", severity);
    if (document.getElementById("activity-unresolved").checked) params.set("unresolved", "1");

    try {
        const response = await fetch(`/api/monitoring/events?${params.toString()}`);
        const events = await response.json();
        if (!response.ok) throw new Error("The event history could not be loaded.");
        if (!Array.isArray(events)) throw new Error("The event history returned an invalid response.");
        activityHasNext = events.length > activityPageSize;
        const pageEvents = events.slice(0, activityPageSize);
        renderActivityEvents(pageEvents);
        if (previous) previous.disabled = activityOffset === 0;
        if (next) next.disabled = !activityHasNext;
        if (pageLabel) {
            pageLabel.textContent = pageEvents.length
                ? `Showing events ${activityOffset + 1}–${activityOffset + pageEvents.length}${activityHasNext ? " · more available" : ""}`
                : activityOffset === 0
                    ? "No events"
                    : "No additional events";
        }
    } catch (error) {
        if (body) body.innerHTML = `<tr><td colspan="7">Event history is unavailable. Retry or review application logs.</td></tr>`;
        if (feedback) {
            feedback.textContent = error.message || "Event history is unavailable.";
            feedback.classList.remove("hidden");
        }
        activityHasNext = false;
        if (next) next.disabled = true;
    }
}

async function loadActivityStatus() {
    try {
        const response = await fetch("/api/monitoring/status");
        if (!response.ok) throw new Error("Monitoring status is unavailable.");
        const status = await response.json();
        const labels = {
            HEALTHY: "Healthy",
            DEGRADED: "Degraded",
            STALE: "Stale",
            STOPPED: "Paused",
            STARTING: "Starting"
        };
        document.getElementById("activity-monitor-health").textContent =
            labels[status.monitoring_health] || "Status unavailable";
        document.getElementById("activity-last-check").textContent =
            status.last_successful_check_time || "No successful check yet";
        const unresolved = document.getElementById("activity-unresolved-count");
        if (Number.isInteger(status.unresolved_events_count)) {
            unresolved.textContent = `${status.unresolved_events_count} unresolved alerts`;
            unresolved.className = `badge-pill ${status.unresolved_events_count === 0 ? "success" : "warning"}`;
        } else {
            unresolved.textContent = "Alert count unavailable";
            unresolved.className = "badge-pill warning";
        }
    } catch (error) {
        document.getElementById("activity-monitor-health").textContent = "Status unavailable";
        document.getElementById("activity-last-check").textContent = "Unavailable";
        document.getElementById("activity-unresolved-count").textContent = "Alert count unavailable";
    }
}

document.getElementById("activity-refresh").addEventListener("click", () => {
    loadActivityEvents();
    loadActivityStatus();
});
document.getElementById("activity-severity").addEventListener("change", () => {
    activityOffset = 0;
    loadActivityEvents();
});
document.getElementById("activity-unresolved").addEventListener("change", () => {
    activityOffset = 0;
    loadActivityEvents();
});
document.getElementById("activity-previous").addEventListener("click", () => {
    activityOffset = Math.max(0, activityOffset - activityPageSize);
    loadActivityEvents();
});
document.getElementById("activity-next").addEventListener("click", () => {
    if (!activityHasNext) return;
    activityOffset += activityPageSize;
    loadActivityEvents();
});
document.getElementById("activity-events-body").addEventListener("click", async event => {
    const button = event.target.closest("button[data-event-action]");
    if (!button) return;
    const eventId = Number(button.dataset.eventId);
    const action = button.dataset.eventAction;
    if (!Number.isSafeInteger(eventId) || !["acknowledge", "review"].includes(action)) return;
    button.disabled = true;
    try {
        const response = await fetch(`/api/monitoring/events/${eventId}/${action}`, { method: "POST" });
        if (!response.ok) throw new Error("The event could not be updated.");
        await loadActivityEvents();
        await loadActivityStatus();
    } catch (error) {
        button.disabled = false;
        const feedback = document.getElementById("activity-feedback");
        feedback.textContent = error.message || "The event could not be updated.";
        feedback.classList.remove("hidden");
    }
});

loadActivityEvents();
loadActivityStatus();
