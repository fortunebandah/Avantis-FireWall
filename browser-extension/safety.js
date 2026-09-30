const retention = document.getElementById("retention");
const summary = document.getElementById("summary");
const eventsList = document.getElementById("events");
const clearButton = document.getElementById("clear");

function loadEvents() {
  chrome.storage.local.get({ retentionHours: 24, events: [] }, (stored) => {
    retention.value = String(stored.retentionHours || 24);
    const cutoff = Date.now() - Number(retention.value) * 60 * 60 * 1000;
    const events = (Array.isArray(stored.events) ? stored.events : [])
      .filter((event) => event && Date.parse(event.timestamp) >= cutoff)
      .slice(-500);
    chrome.storage.local.set({ retentionHours: Number(retention.value), events });
    render(events);
  });
}

function render(events) {
  eventsList.replaceChildren();
  summary.textContent = `${events.length} blocked record${events.length === 1 ? "" : "s"} stored locally`;
  if (!events.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No blocked visits in the selected period.";
    eventsList.append(empty);
    return;
  }

  [...events].reverse().forEach((event) => {
    const item = document.createElement("li");
    const domain = document.createElement("strong");
    domain.textContent = event.domain || "Unknown domain";
    const time = new Date(event.timestamp).toLocaleString();
    item.append(domain, `${time} | ${event.reason || "Blocked by rule"}`);
    eventsList.append(item);
  });
}

retention.addEventListener("change", () => {
  chrome.storage.local.get({ events: [] }, (stored) => {
    chrome.storage.local.set({ retentionHours: Number(retention.value), events: stored.events || [] }, loadEvents);
  });
});

clearButton.addEventListener("click", () => {
  chrome.storage.local.set({ events: [] }, loadEvents);
});

loadEvents();
