"use strict";

// Trusted templates; API and user values are escaped before insertion.
const $ = (id) => document.getElementById(id);
const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
const ICONS = {
  overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  cases: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h5",
  apps: "M3 5h7l2 2h9v13H3z M3 5V3h7l2 2",
  patch: "m8 4-5 8 5 8 M16 4l5 8-5 8 M14 3l-4 18",
  check: "m9 12 2 2 4-4 M12 3l8 4v6c0 5-8 9-8 9s-8-4-8-9V7z",
  approval: "M9 11l3 3L22 4 M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11",
  audit: "M9 3H4v18h16V8 M9 3v5h11 M8 12h8 M8 16h8",
  plug: "M8 7h8 M9 7v5a3 3 0 0 0 6 0V7 M12 15v4a3 3 0 0 1-3 3 M8 2v5 M16 2v5",
  settings: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2",
  search: "M11 3a8 8 0 1 0 0 16 8 8 0 0 0 0-16 m6 14 4 4",
  arrow: "M5 12h14 m-5-5 5 5-5 5", back: "M19 12H5 m5-5-5 5 5 5",
  plus: "M12 5v14 M5 12h14", refresh: "M20 7v5h-5 M4 17v-5h5 M6 6a8 8 0 0 1 13 2 M18 18a8 8 0 0 1-13-2",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 7v5l3 2",
  lock: "M5 10h14v11H5z M8 10V6a4 4 0 0 1 8 0v4", info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 11v6 M12 7v1",
  signal: "M3 12h4l3-7 4 14 3-7h4", download: "M12 3v12 m-4-4 4 4 4-4 M5 17v4h14v-4",
  layers: "m12 3 10 5-10 5L2 8z M2 12l10 5 10-5 M2 16l10 5 10-5",
};
const icon = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${ICONS[name] || ICONS.info}"/></svg>`;
const CONNECTOR_ASSETS = {
  github: "github.svg", osv: "osv.png", "osv-scanner": "osv.png", nvd: "nvd.ico",
  syft: "syft.svg", trivy: "trivy.png", meterless: "meterless.svg", hmem: "meterless.svg",
  nvidia: "nvidia.svg", zetaris: "zetaris.svg",
};
const AGENT_AVATARS = {
  warden: "ink", cartographer: "turquoise", scout: "blue", mnemonic: "rose",
  arbiter: "amber", planner: "turquoise", evaluator: "rose", scribe: "blue",
  patchwright: "red", verifier: "amber", guardian: "ink",
};
const AGENT_ROLE_ICONS = { warden: "layers", cartographer: "apps", scout: "search", mnemonic: "clock", arbiter: "check", planner: "cases", evaluator: "audit", scribe: "download", patchwright: "patch", verifier: "signal", guardian: "lock" };
let agentMotionPaused = false;
const timelineOptions = { attentionOnly: false, order: "recent" };
function connectorIcon(id) {
  const file = CONNECTOR_ASSETS[id];
  return file ? `<img class="connector-logo connector-logo-${escapeHTML(id)}" src="/static/assets/connectors/${file}" alt="" width="20" height="20" decoding="async">` : icon("check");
}
function agentAvatar(id, compact = false) {
  const name = AGENT_AVATARS[id] || "ink";
  const still = `/static/assets/agents/${name}-still.svg`;
  const animated = agentMotionPaused ? still : `/static/assets/agents/${name}.svg`;
  const picture = `<picture class="agent-avatar${compact ? " agent-avatar-compact" : ""}" aria-hidden="true"><source media="(prefers-reduced-motion: reduce)" srcset="${still}"><img src="${animated}" width="${compact ? 36 : 56}" height="${compact ? 36 : 56}" alt="" decoding="async"></picture>`;
  return compact ? `<span class="agent-portrait">${picture}<span class="agent-role-symbol" aria-hidden="true">${icon(AGENT_ROLE_ICONS[id] || "info")}</span></span>` : picture;
}
function motionControl() {
  return `<button class="button" type="button" data-action="toggle-agent-motion" aria-pressed="${agentMotionPaused}">${icon("layers")}${agentMotionPaused ? "Resume avatars" : "Pause avatars"}</button>`;
}
const NAV = [
  ["overview", "Operations center", "overview", "OPERATIONS"],
  ["applications", "Applications", "apps"],
  ["integrations", "Integrations", "plug", "WORKSPACE"], ["settings", "Settings", "settings"],
];
const CATALOG = [
  ["github", "GitHub Security", "GH", "source", "mvp", "Security advisories tied to repositories and dependencies."],
  ["osv", "OSV", "O", "source", "mvp", "Vulnerabilities and affected ranges by package and version."],
  ["nvd", "NVD", "N", "source", "mvp", "CVE details, severity, and technical references."],
  ["cisa-kev", "CISA KEV", "K", "source", "mvp", "Signal for vulnerabilities with known exploitation."],
  ["syft", "Syft", "S", "inventory", "mvp", "Component inventory and SBOM generation."],
  ["trivy", "Trivy", "T", "scanner", "mvp", "Dependency and authorized artifact scanning."],
  ["osv-scanner", "OSV-Scanner", "OS", "scanner", "mvp", "Cross-check dependencies against OSV advisories."],
  ["meterless", "Nightshift", "N", "model-access", "hackathon", "Primary AI via the Nightshift hotspot (Meterless Runtime)."],
  ["hmem", "H-MEM", "H", "engine", "hackathon", "Local memory engine. Proof is the official suite, not the network."],
  ["nvidia", "NVIDIA", "NV", "model", "candidate", "Configure Nemotron in Nightshift Providers, not in Warden."],
  ["zetaris", "Zetaris", "Z", "data", "hackathon", "Data layer for investigations. Local mode is not a verified Zetaris read."],
].map(([id, name, mark, kind, scope, description]) => ({ id, name, mark, kind, scope, description, verified: false, status: "not_implemented" }));
const STATUS = { detected: "To investigate", investigating: "In progress", awaiting_review: "Under review", requires_intervention: "Needs intervention", closed: "Closed", cancelled: "Cancelled" };
const RUN_TERMINAL = new Set(["cancelled", "budget_exhausted", "awaiting_review"]);
const LABELS = { budget_exhausted: "Budget exhausted", awaiting_review: "Awaiting review", not_executed: "Not executed", not_affected: "Not affected" };
function label(value) { if (value === null || value === undefined || value === "") return "—"; const text = String(value); return LABELS[text] || (text.charAt(0).toUpperCase() + text.slice(1)).replace(/[_-]+/g, " "); }
const EXPOSURE = { undetermined: "Undetermined", not_affected: "Not affected", potential: "Potential", confirmed: "Confirmed" };
const ADVISORY = /(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|CVE-\d{4}-\d{4,})/i;
const state = { token: "", authenticated: false, api: false, database: false, applications: null, investigations: null, integrations: null, context: null, snapshots: [], crew: [], activity: [], appError: "", caseError: "", loading: false, search: "", filter: "all", settingsTab: "general", selectedCase: "", contextFor: "", operationView: "panorama", deployments: [], inventoryError: "", contextError: "", preview: null, updated: null, inventory: {}, pending: new Set() };
const SYNC_ACTIONS = new Set(["nav-toggle", "close-modal", "settings-tab", "integration-filter", "timeline-attention", "toggle-agent-motion"]);
let toastTimer;
let searchTimer;
let refreshSequence = 0;

function badge(text, variant = "") { return `<span class="badge ${variant}">${escapeHTML(text)}</span>`; }
function button(text, action, glyph = "", primary = false, disabled = false, title = "") { const busy = state.pending.has(action); return `<button type="button" class="button${primary ? " primary" : ""}" data-action="${action}"${disabled || busy ? " disabled" : ""}${busy ? ' aria-busy="true" data-busy' : ""}${title ? ` title="${escapeHTML(title)}"` : ""}>${glyph ? icon(glyph) : ""}${escapeHTML(text)}</button>`; }
function heading(title, description, actions = "") { return `<div class="page-header"><div><h1>${escapeHTML(title)}</h1>${description ? `<p>${escapeHTML(description)}</p>` : ""}</div><div class="page-actions">${actions}</div></div>`; }
function empty(title, description, glyph = "cases", action = "", large = false) { return `<div class="empty-state${large ? " large" : ""}"><div class="empty-illustration">${icon(glyph)}</div><h3>${escapeHTML(title)}</h3><p>${escapeHTML(description)}</p>${action}</div>`; }
function panel(title, body, trailing = "", caption = "") { return `<section class="section-panel"><div class="section-heading"><h2>${escapeHTML(title)}</h2>${trailing}</div>${body}${caption ? `<div class="section-caption">${icon("info")}${escapeHTML(caption)}</div>` : ""}</section>`; }
function note(title, body) { return `<div class="module-note">${icon("info")}<p><strong>${escapeHTML(title)}</strong> ${escapeHTML(body)}</p></div>`; }
function route() {
  const parts = location.hash.slice(1).split("/");
  if (parts[0] === "investigations") { state.operationView = "case"; if (parts[1]) state.selectedCase = parts[1]; }
  if (parts[0] === "agents") state.operationView = "crew";
  return { page: NAV.some((item) => item[0] === parts[0]) ? parts[0] : "overview", id: parts[1] || "", tab: parts[2] || "overview" };
}
function navigate(page) { if (location.hash === `#${page}`) render(); else location.hash = page; closeNavigation(); }
function date(value) { return value ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "No record"; }
function count(rows) { return rows === null ? "—" : rows.length; }
function announce(message, type = "") { clearTimeout(toastTimer); $("toast").textContent = message; $("toast").className = `toast ${type}`; $("toast").hidden = false; toastTimer = setTimeout(() => { $("toast").hidden = true; }, 7000); }
function table(headers, rows) { return `<div class="table-wrap" tabindex="0" role="region" aria-label="Table of ${escapeHTML(headers[0].toLowerCase())}"><table><thead><tr>${headers.map((label) => `<th scope="col">${escapeHTML(label)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div>`; }

function renderNavigation() {
  const current = route().page;
  $("navigation").innerHTML = NAV.map(([id, label, glyph, group]) => `${group ? `<p class="nav-group-label">${group}</p>` : ""}<a class="nav-item" href="#${id}"${current === id ? ' aria-current="page"' : ""}>${icon(glyph)}<span>${label}</span>${id === "investigations" && state.investigations?.length ? `<span class="nav-count">${state.investigations.length}</span>` : ""}</a>`).join("");
  $("breadcrumb-current").textContent = NAV.find((item) => item[0] === current)?.[1] || "Overview";
}
function renderChrome() {
  $("connection-label").textContent = state.authenticated ? (state.database ? "Environment connected" : "Partial connection") : "Connect environment";
  $("connection-dot").classList.toggle("online", state.authenticated && state.database);
  $("profile-status").textContent = state.authenticated ? "Session active" : "Not connected";
  $("api-health").textContent = state.api ? "API available" : "API unavailable";
  const warning = $("environment-message");
  warning.hidden = !state.authenticated || state.database;
  warning.innerHTML = `<span>The database is unavailable. You can browse all sections; saving data requires reconnecting it.</span><button type="button" data-action="refresh">Retry</button>`;
}
function metric(label, value, foot, glyph) { return `<article class="metric"><div class="metric-head"><span>${label}</span>${icon(glyph)}</div><div class="metric-value${value === "—" ? " pending" : ""}">${value}</div><div class="metric-foot">${foot}</div></article>`; }
function statusBadge(value) { return badge(STATUS[value] || value || "To investigate", value === "detected" || !value ? "sand" : value === "awaiting_review" ? "green" : ""); }
function exposureBadge(value) { return badge(EXPOSURE[value] || value || "Undetermined", value === "confirmed" ? "accent" : value === "potential" ? "sand" : value === "not_affected" ? "green" : ""); }
function isSampleCase(item) {
  const app = state.applications?.find((entry) => entry.id === item?.application_id);
  return item?.description?.startsWith("Guided agent demo. Synthetic sources.") || app?.repository?.startsWith("demo-org/") || false;
}
function caseRows(rows) { return rows.map((item) => `<tr><td><button class="row-link" data-action="case-detail" data-id="${escapeHTML(item.id)}">${escapeHTML(item.title)}</button>${isSampleCase(item) ? badge("Synthetic sample", "sand") : ""}<small>${escapeHTML(state.applications?.find((app) => app.id === item.application_id)?.name || "Registered application")}</small></td><td>${statusBadge(item.status)}</td><td>${exposureBadge(item.exposure)}</td><td class="row-arrow">↗</td></tr>`).join(""); }
async function loadInventory(id) {
  try { const body = await api(`/api/applications/${id}/inventory`); state.inventory[id] = { snapshots: body.snapshots || [], deployments: body.deployments || [] }; state.snapshots = body.snapshots || []; state.deployments = body.deployments || []; state.inventoryError = ""; }
  catch (error) { state.inventory[id] = null; state.inventoryError = error.message; state.snapshots = []; state.deployments = []; }
  return state.inventory[id];
}
async function loadInventories() {
  await Promise.allSettled((state.applications || []).slice(0, 25).map((app) => loadInventory(app.id)));
  const current = route();
  if (current.page === "applications" && !current.id) refreshResults();
  else if (current.page === "overview" || current.page === "applications") render();
}
function inventoryBadge(id) {
  const inventory = state.inventory[id];
  if (inventory === undefined) return badge("Checking…");
  if (!inventory) return badge("Unavailable");
  if (!inventory.snapshots.length) return badge("Not built", "sand");
  return badge(`Ready · ${date(inventory.snapshots[0].observed_at)}`, "green");
}
function setupSteps() {
  const apps = state.applications || [];
  const steps = [
    ["Connect environment", "Use your individual access credential.", state.authenticated, button("Connect environment", "connect", "plug", true)],
    ["Register an application", "Add the npm repository you want to protect.", apps.length > 0, button("Register application", "new-app", "plus", true)],
    ["Generate inventory", "Resolve the lockfile for a verifiable commit.", apps.some((app) => state.inventory[app.id]?.snapshots?.length), apps[0] ? `<a class="button primary" href="#applications/${escapeHTML(apps[0].id)}/inventory">${icon("refresh")}Open inventory</a>` : ""],
    ["Open an investigation", "Register an advisory and link it to the application.", (state.investigations || []).length > 0, button("New investigation", "new-case", "plus", true)],
    ["Start a run", "The crew gathers evidence one stage at a time.", false, ""],
  ];
  const next = steps.findIndex(([, , done]) => !done);
  return `<section class="setup-steps" aria-labelledby="setup-title"><h2 id="setup-title">Get started</h2><ol>${steps.map(([title, sub, done, action], index) => `<li class="${done ? "done" : index === next ? "current" : ""}"${index === next ? ' aria-current="step"' : ""}><span class="setup-mark" aria-hidden="true">${done ? "✓" : index + 1}</span><div><strong>${title}</strong><small>${sub}</small>${done ? '<span class="sr-only">Done.</span>' : ""}${index === next && !state.loading ? action : ""}</div></li>`).join("")}</ol></section>`;
}
function timelineEvents(page = route().page) { return page === "overview" ? (state.activity?.length ? state.activity : (state.context?.agents || [])) : (state.activity || []); }
function timelineRegion(events) { return `<div id="crew-timeline">${agentTimeline(events)}</div><p id="timeline-status" class="sr-only" aria-live="polite"></p>`; }
function activityKey(rows) { return (rows || []).map((row) => row.id || row.created_at).join("|"); }
function refreshTimeline(added) {
  const region = $("crew-timeline");
  if (!region) return;
  const events = timelineEvents();
  const opened = new Set([...region.querySelectorAll("details.activity-agent[open]")].map((entry) => entry.dataset.agent));
  const runs = new Map([...region.querySelectorAll("details.activity-run")].map((entry) => [entry.dataset.run, entry.open]));
  region.innerHTML = agentTimeline(events);
  for (const entry of region.querySelectorAll("details.activity-agent")) entry.open = opened.has(entry.dataset.agent);
  for (const entry of region.querySelectorAll("details.activity-run")) if (runs.has(entry.dataset.run)) entry.open = runs.get(entry.dataset.run);
  const counter = $("timeline-count");
  if (counter) counter.innerHTML = route().page === "overview" ? badge(events.length ? `${events.length} events` : "No activity") : badge(String(events.length));
  if (added > 0) $("timeline-status").textContent = `${added} new agent ${added === 1 ? "act" : "acts"}.`;
}
function accessEmpty(type = "investigations") {
  const isApp = type === "applications";
  if (state.loading) return `<div class="loading-line"></div>${empty("Loading environment", "Fetching available data…", "refresh")}`;
  const error = isApp ? state.appError : state.caseError;
  if (error) return empty("Data unavailable", "Check the database connection and try again.", "signal", button("Retry", "refresh", "refresh"));
  if (!state.authenticated) return empty("Connect your workspace", "Use your individual access credential to load applications and investigations.", isApp ? "apps" : "cases", button("Connect environment", "connect", "plug", true));
  return empty(isApp ? "Add your first application" : "No investigations yet", isApp ? "Register a repository to start building security context." : "Register a manual advisory and link it to an application.", isApp ? "apps" : "cases", button(isApp ? "Register application" : "New investigation", isApp ? "new-app" : "new-case", "plus", true));
}
function crewStrip() {
  const crew = state.crew || [];
  if (!crew.length) return "";
  return `<div class="crew-strip" aria-label="Agent crew">${crew.map((agent) => `<article class="crew-chip"><strong>${escapeHTML(agent.name)}</strong><small>${escapeHTML(agent.role)}</small></article>`).join("")}</div>`;
}
const AGENT_EVENT_STATUS = {
  started: ["Started", "running"], decided: ["Decision recorded", "complete"],
  handed_off: ["Handed off", "complete"], failed: ["Failed", "error"],
  skipped: ["Skipped", "neutral"], blocked: ["Needs attention", "attention"],
};
const AGENT_STAGE_LABELS = {
  inventory: "Inventory", sources: "Evidence collection", correlation: "Exposure assessment",
  memory: "Memory recall", plan: "Response planning", critique: "Plan review",
  engineering: "Proposed change", validation: "Validation", approval: "Human review",
  synthesis: "Investigation synthesis", closure: "Case closure",
};
function activityTime(value, now = Date.now()) {
  const instant = new Date(value), elapsed = instant.getTime() - now;
  if (!value || !Number.isFinite(elapsed)) return '<span class="activity-time">Time unavailable</span>';
  const units = Math.abs(elapsed) < 60000 ? [0, "second"] : Math.abs(elapsed) < 3600000 ? [Math.round(elapsed / 60000), "minute"] : Math.abs(elapsed) < 86400000 ? [Math.round(elapsed / 3600000), "hour"] : [Math.round(elapsed / 86400000), "day"];
  const relative = units[1] === "second" ? "Just now" : new Intl.RelativeTimeFormat("en", { numeric: "auto" }).format(...units);
  const exact = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "long" }).format(instant);
  return `<time class="activity-time" datetime="${escapeHTML(instant.toISOString())}" title="${escapeHTML(exact)}">${escapeHTML(relative)}</time>`;
}
function activityDay(value) {
  const day = new Date(value), now = new Date(), yesterday = new Date();
  yesterday.setDate(now.getDate() - 1);
  if (!Number.isFinite(day.getTime())) return "Date unavailable";
  return day.toDateString() === now.toDateString() ? "Today" : day.toDateString() === yesterday.toDateString() ? "Yesterday" : new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" }).format(day);
}
const LEGACY_ACTIVITY_MESSAGES = {
  "Consulta GitHub, OSV, NVD y KEV.": "Querying GitHub, OSV, NVD, and KEV.",
  "Crítica fail-open. La exposición no cambió.": "Plan critique was unavailable. Exposure was not changed.",
  "Evidencia persistida.": "Evidence saved.",
  "Exposición determinista registrada. El modelo no la asigna.": "Deterministic exposure assessment saved. The model does not assign exposure.",
  "Inventario incompleto o Zetaris falló cerrado.": "Inventory is incomplete or Zetaris could not be verified. Investigation remains blocked.",
  "Lee el snapshot fijado.": "Reading the pinned inventory snapshot.",
  "Recall H-MEM listo.": "H-MEM recall is ready.",
  "Snapshot listo. Entrega al Explorador.": "Inventory snapshot is ready. Handing off to Scout.",
};
function activityMessage(event) {
  return LEGACY_ACTIVITY_MESSAGES[event.summary] || event.summary || "No summary recorded.";
}
function activityScope(event) {
  if (event.run_id) return { key: `run:${event.run_id}`, kind: "run" };
  if (event.activity_group) return { key: `public:${event.activity_group}`, kind: event.activity_group_kind === "run" ? "run" : "case" };
  if (event.investigation_id) return { key: `case:${event.investigation_id}`, kind: "case" };
  const day = String(event.created_at || "unknown").slice(0, 10);
  return { key: `unscoped:${day}`, kind: "unscoped" };
}
function groupActivityByRun(events) {
  const groups = new Map();
  const ordered = [...events].sort((a, b) => (Date.parse(a.created_at) || 0) - (Date.parse(b.created_at) || 0));
  for (const event of ordered) {
    const scope = activityScope(event);
    if (!groups.has(scope.key)) groups.set(scope.key, { ...scope, first: event, latest: event, events: [] });
    const group = groups.get(scope.key); group.events.push(event); group.latest = event;
  }
  return [...groups.values()].sort((a, b) => (Date.parse(b.latest.created_at) || 0) - (Date.parse(a.latest.created_at) || 0));
}

function groupAgentActivity(events) {
  const ordered = events.map((event, index) => ({ ...event, inputOrder: index }))
    .sort((a, b) => (Date.parse(a.created_at) || 0) - (Date.parse(b.created_at) || 0) || a.inputOrder - b.inputOrder);
  const groups = [], active = new Map(), seen = new Set();
  for (const event of ordered) {
    if (event.id && seen.has(event.id)) continue;
    if (event.id) seen.add(event.id);
    // Public activity omits case/run IDs: never combine unrelated cases by agent name.
    const scope = event.run_id || event.investigation_id || event.activity_group;
    const key = scope && `${scope}:${event.agent}:${event.stage}`;
    let group = key && active.get(key);
    if (!group || event.status === "started") {
      group = { events: [], first: event, latest: event };
      groups.push(group);
      if (key) active.set(key, group);
    }
    group.events.push(event); group.latest = event;
  }
  return groups.sort((a, b) => (Date.parse(b.latest.created_at) || 0) - (Date.parse(a.latest.created_at) || 0));
}
function activityCard(group, runKey = "activity") {
  const event = group.latest, agent = state.crew.find((entry) => entry.id === event.agent);
  const [label, tone] = AGENT_EVENT_STATUS[event.status] || [event.status || "Recorded", "neutral"];
  const stage = AGENT_STAGE_LABELS[event.stage] || event.stage || "Investigation";
  const latestTask = group.tasks?.[0] || group;
  const started = latestTask.events.find((entry) => entry.status === "started");
  const elapsed = started && event.status !== "started" ? Date.parse(event.created_at) - Date.parse(started.created_at) : NaN;
  const duration = Number.isFinite(elapsed) && elapsed >= 0 ? `${(elapsed / 1000).toFixed(1)}s elapsed` : "";
  const synthetic = latestTask.events.some((entry) => entry.synthetic || entry.detail?.synthetic);
  const taskCount = group.tasks?.length || 1;
  const scoped = (group.tasks || [group]).every((task) => task.latest.run_id || task.latest.investigation_id || task.latest.activity_group);
  const workload = scoped ? `${taskCount} ${taskCount === 1 ? "task" : "tasks"}` : `${group.events.length} events`;
  const investigation = state.investigations?.find((entry) => entry.id === event.investigation_id);
  const caseLink = investigation ? `<button class="text-link activity-case" type="button" data-action="case-detail" data-id="${escapeHTML(investigation.id)}">Open ${escapeHTML(investigation.title)} ${icon("arrow")}</button>` : "";
  const history = (group.tasks || [group]).map((task) => {
    const context = task.latest.run_id ? `Run ${String(task.latest.run_id).slice(0, 8)}` : "Recorded case activity";
    const steps = task.events.map((entry) => {
      const message = activityMessage(entry);
      const original = message !== (entry.summary || "") && entry.summary ? `<details class="activity-original"><summary>Original record (source language)</summary><p lang="es">${escapeHTML(entry.summary)}</p></details>` : "";
      const detail = entry.detail || {};
      const meta = [typeof detail.model === "string" && `Model: ${detail.model.slice(0, 160)}`, typeof detail.tool === "string" && `Tool: ${detail.tool.slice(0, 80)}`, Number.isInteger(detail.exit_code) && `Exit: ${detail.exit_code}`].filter(Boolean).join(" · ");
      return `<li><span class="activity-step-status">${escapeHTML(AGENT_EVENT_STATUS[entry.status]?.[0] || entry.status)}</span>${activityTime(entry.created_at)}<p>${escapeHTML(message)}</p>${meta ? `<small>${escapeHTML(meta)}</small>` : ""}${original}</li>`;
    }).join("");
    return `<section class="activity-task"><h4>${escapeHTML(AGENT_STAGE_LABELS[task.latest.stage] || task.latest.stage || "Investigation")}</h4><span class="activity-task-context">${escapeHTML(context)}</span><ol>${steps}</ol></section>`;
  }).join("");
  const name = agent?.name || (event.agent ? event.agent[0].toUpperCase() + event.agent.slice(1) : "Agent");
  return `<li class="activity-item activity-${tone}"><details class="activity-agent" data-agent="${escapeHTML(runKey)}|${escapeHTML(event.agent || "unknown")}"><summary class="activity-row">${agentAvatar(event.agent, true)}<span class="activity-identity"><span class="activity-topline"><strong>${escapeHTML(name)}</strong> <span class="activity-stage">${escapeHTML(stage)}</span> ${activityTime(event.created_at)}</span><span class="activity-preview">${escapeHTML(activityMessage(event))}</span><span class="activity-metadata"><span class="activity-status activity-status-${tone}">${escapeHTML(label)}</span> <span>${workload}</span>${duration ? ` <span>${duration}</span>` : ""}${synthetic ? ' <span class="activity-sample">Sample</span>' : ""}</span></span><span class="activity-expand"><span>View more</span><span class="activity-chevron" aria-hidden="true">⌄</span></span></summary><div class="activity-history"><div class="activity-history-heading">${scoped ? `${taskCount} ${taskCount === 1 ? "task" : "tasks"} · ` : ""}${group.events.length} recorded events</div>${caseLink}${history}</div></details></li>`;
}

function groupActivityByAgent(events) {
  const agents = new Map();
  for (const task of groupAgentActivity(events)) {
    const id = task.latest.agent || "unknown";
    if (!agents.has(id)) agents.set(id, { first: task.first, latest: task.latest, events: [], tasks: [] });
    const agent = agents.get(id);
    agent.tasks.push(task);
    agent.events.push(...task.events);
  }
  return [...agents.values()];
}
function agentTimeline(events) {
  if (!events?.length) return empty("No agent activity yet", "Start an investigation to see evidence collection, decisions, and handoffs here.", "layers", state.authenticated ? "" : button("Connect environment", "connect", "plug", true));
  let runs = groupActivityByRun(events).map((run) => ({ ...run, agents: groupActivityByAgent(run.events) }));
  const attention = runs.reduce((count, run) => count + run.agents.filter((agent) => ["blocked", "failed"].includes(agent.latest.status)).length, 0);
  const uniqueAgents = new Set(events.map((event) => event.agent)).size;
  if (timelineOptions.order === "oldest") runs.reverse();
  let lastDay = "";
  const markup = runs.map((run, index) => {
    let agents = run.agents;
    if (timelineOptions.attentionOnly) agents = agents.filter((agent) => ["blocked", "failed"].includes(agent.latest.status));
    if (!agents.length) return "";
    agents.sort((a, b) => (Date.parse(a.first.created_at) || 0) - (Date.parse(b.first.created_at) || 0));
    const day = activityDay(run.first.created_at), dayLabel = day !== lastDay ? `<h3 class="activity-day">${escapeHTML(day)}</h3>` : ""; lastDay = day;
    const stamp = new Date(run.first.created_at);
    const clock = Number.isFinite(stamp.getTime()) ? new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", hour12: false }).format(stamp) : "";
    const label = run.kind === "run" ? `Run ${clock}` : run.kind === "case" ? `Case activity ${clock}` : "Activity without a run reference";
    return `${dayLabel}<details class="activity-run" data-run="${escapeHTML(run.key)}"${index === 0 || timelineOptions.attentionOnly ? " open" : ""}><summary class="activity-run-heading"><span><strong>${escapeHTML(label)}</strong> <span>${run.agents.length} ${run.agents.length === 1 ? "agent" : "agents"} · ${run.events.length} events</span></span>${activityTime(run.latest.created_at)}<span class="activity-chevron" aria-hidden="true">⌄</span></summary><ol class="activity-timeline" aria-label="Agents within this activity group">${agents.map((agent) => activityCard(agent, run.key)).join("")}</ol></details>`;
  }).join("");
  return `<div class="activity-toolbar"><div class="activity-count">${uniqueAgents} ${uniqueAgents === 1 ? "agent" : "agents"} · ${events.length} events</div><label class="activity-sort">Order <select data-timeline-sort aria-label="Activity order"><option value="recent"${timelineOptions.order === "recent" ? " selected" : ""}>Most recent</option><option value="oldest"${timelineOptions.order === "oldest" ? " selected" : ""}>Oldest first</option></select></label></div><div class="activity-filters"><button type="button" data-action="timeline-attention" aria-pressed="${timelineOptions.attentionOnly}" class="activity-filter${timelineOptions.attentionOnly ? " selected" : ""}">Needs attention <span>(${attention})</span></button></div><div class="activity-groups">${markup || '<p class="activity-empty">No agents need attention in this activity window.</p>'}</div>`;
}

function panorama() {
  const cases = state.investigations;
  const events = timelineEvents("overview");
  const onboarding = !state.authenticated || !state.applications?.length || !cases?.length;
  return heading("Operations center", "", button("Refresh", "refresh", "refresh") + button("New investigation", "new-case", "plus")) + operationViews() +
    (onboarding ? setupSteps() : `<div class="metrics">${metric("Registered applications", count(state.applications), state.applications ? "In workspace" : "Connect your environment", "apps")}${metric("Investigations", count(cases), cases ? "Advisories recorded" : "No environment data", "cases")}${metric("Confirmed exposure", cases ? String(cases.filter((item) => item.exposure === "confirmed").length) : "—", cases ? "Per deterministic correlation" : '<span class="tiny-dot"></span>No environment data', "check")}${metric("Data layer", state.context?.data_layer === "zetaris" ? "Zetaris" : cases ? "Local" : "—", state.context?.sponsor_data_layer_verified ? "Zetaris read verified" : "Local mode; Zetaris not verified", "layers")}</div>`) +
    `<div class="content-grid"><div>${panel("Crew timeline", timelineRegion(events), `<span id="timeline-count">${badge(events.length ? `${events.length} events` : "No activity")}</span>`, "Warden orchestrates. The Arbiter classifies. Nightshift proposes. Merge is prohibited.")}${panel("Recent investigations", cases?.length ? table(["Investigation", "Status", "Exposure", ""], caseRows(cases.slice(0, 5))) : accessEmpty(), `<a class="text-link" href="#investigations">Open investigations ${icon("arrow")}</a>`)}</div><aside class="overview-aside">${flowPanel()}</aside></div>` +
    `<div class="bottom-sources"><span>Intelligence sources</span>${CATALOG.slice(0, 4).map((item) => `<a href="#integrations" class="source-chip"><span class="source-icon">${connectorIcon(item.id)}</span>${item.name}</a>`).join("")}<a class="text-link" href="#integrations">View integrations ${icon("arrow")}</a></div>`;
}
function operationViews() {
  return `<div class="operation-views"><div class="view-presets" aria-label="Operations center view"><button type="button" data-action="operation-view" data-view="panorama" class="view-preset${state.operationView === "panorama" ? " active" : ""}" aria-pressed="${state.operationView === "panorama"}">${icon("overview")}Overview</button><button type="button" data-action="operation-view" data-view="case" class="view-preset${state.operationView === "case" ? " active" : ""}" aria-pressed="${state.operationView === "case"}">${icon("cases")}Investigation and response</button><button type="button" data-action="operation-view" data-view="crew" class="view-preset${state.operationView === "crew" ? " active" : ""}" aria-pressed="${state.operationView === "crew"}">${icon("layers")}Crew</button></div></div>`;
}
function overview() { return state.operationView === "crew" ? agentsPage() : state.operationView === "case" ? operationsCase() : panorama(); }
function responseStage(number, name, description, body, status = "Pending") {
  return `<section class="response-stage"><div class="response-stage-heading"><span class="stage-number">${number}</span><div><h3>${name}</h3><p>${description}</p></div>${badge(status)}</div><div class="response-stage-content">${body}</div></section>`;
}
function selectedInvestigation() {
  const rows = state.investigations || [];
  const current = route();
  const wanted = current.page === "investigations" && current.id ? current.id : state.selectedCase;
  const item = rows.find((entry) => entry.id === wanted) || rows[0] || null;
  if (item) state.selectedCase = item.id;
  return item;
}
function operationsCase() {
  const rows = state.investigations || [];
  const item = selectedInvestigation();
  const app = item && state.applications?.find((entry) => entry.id === item.application_id);
  const ctx = state.context?.investigation_id && state.context.investigation_id !== item?.id ? null : state.context;
  const sampleNotice = isSampleCase(item) ? note("Synthetic sample", "This case uses controlled data. It does not prove live sponsor integrations or a deployed correction.") : "";
  const evidenceRows = ctx?.evidence || [];
  const assessments = ctx?.assessments || [];
  const runs = ctx?.runs || [];
  const critique = ctx?.critiques?.[0]?.payload;
  const memory = ctx?.memory;
  const latestRun = runs[0];
  const findings = assessments.flatMap((entry) => entry.payload?.findings || []);
  const queue = `<div class="case-queue"><div class="queue-heading"><h2>Investigations</h2>${badge(state.investigations === null ? "—" : String(rows.length))}</div>${state.loading ? '<div class="loading-line"></div>' : ""}${rows.length ? rows.map((entry) => `<button class="case-queue-item${item?.id === entry.id ? " selected" : ""}" data-action="case-detail" data-id="${escapeHTML(entry.id)}" type="button" aria-pressed="${item?.id === entry.id}"><span class="queue-item-icon">${icon("cases")}</span><span><strong>${escapeHTML(entry.title)}</strong><small>${escapeHTML(state.applications?.find((entryApp) => entryApp.id === entry.application_id)?.name || "Registered application")}</small><span class="queue-state">${statusBadge(entry.status)}</span></span></button>`).join("") : `<div class="queue-empty">${icon("cases")}<p>${state.authenticated ? "No investigations available." : "Connect the environment to query advisories."}</p>${button(state.authenticated ? "New advisory" : "Connect", state.authenticated ? "new-case" : "connect", "plus")}</div>`}</div>`;
  const context = `<div class="case-context"><div><span class="context-label">Application</span><strong>${escapeHTML(app?.name || "Not selected")}</strong><small>${escapeHTML(app?.repository || "Repository pending")}</small></div><div><span class="context-label">Advisory status</span>${item ? statusBadge(item.status) : badge("Not selected")}</div><div><span class="context-label">Exposure</span>${item ? exposureBadge(item.exposure) : badge("Undetermined")}</div><div><span class="context-label">Data layer</span><span>${escapeHTML(ctx?.data_layer || "Not loaded")}${ctx?.sponsor_data_layer_verified ? " · Zetaris verified" : ""}</span></div></div>`;
  const evidence = `<section class="case-block"><div class="case-block-heading"><h3>${icon("search")}Evidence and context</h3>${badge(evidenceRows.length ? `${evidenceRows.length} records` : "Uncorroborated", evidenceRows.length ? "green" : "sand")}</div><div class="case-block-body">${item ? `<p>${escapeHTML(item.description)}</p><div class="source-reference"><span class="source-icon">↗</span><div><small>Reference provided</small><a href="${escapeHTML(item.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.source_url)}</a></div></div>${evidenceRows.length ? `<ul class="timeline">${evidenceRows.slice(0, 6).map((row) => `<li>${escapeHTML(row.source || "source")} · ${escapeHTML(row.source_identifier || "")}<small>${escapeHTML((row.excerpt || "").slice(0, 180))}</small></li>`).join("")}</ul>` : ""}` : '<p>Select an advisory to gather sources, description, and application data here.</p>'}<p class="inline-pending">A version match does not confirm compromise.</p></div></section>`;
  const exposure = `<section class="case-block"><div class="case-block-heading"><h3>${icon("check")}Exposure assessment</h3>${item ? exposureBadge(item.exposure) : badge("Not assessed")}</div><div class="case-block-body"><div class="exposure-checks">${(findings.length ? findings.slice(0, 6).map((finding) => `<div><span>${escapeHTML(finding.package_name || "component")} ${escapeHTML(finding.resolved_version || "")}</span><span>${escapeHTML(finding.exposure || "undetermined")}</span></div>`) : ["Affected version", "Presence in environment", "Historical deployment", "Exploitation conditions"].map((label) => `<div><span>${label}</span><span>No evidence</span></div>`)).join("")}</div><p class="inline-pending">H-MEM reinjects context and does not assign exposure. ${memory?.available ? "Recall available." : "No recall yet."}</p></div></section>`;
  const planRow = ctx?.plans?.[0];
  const patchRow = ctx?.patches?.[0];
  const validationRow = ctx?.validations?.[0];
  const approvalRow = (ctx?.approvals || []).find((row) => row.valid) || ctx?.approvals?.[0];
  const planPayload = planRow?.payload || {};
  const patchPayload = patchRow?.payload || {};
  const validationPayload = validationRow?.payload || {};
  const plan = responseStage("01", "Response plan", "Action, evidence, compatibility, validation, and rollback.", planRow ? `<div class="stage-placeholders"><div><span>Action</span><p>${escapeHTML(planPayload.action || "—")}</p></div><div><span>Packages</span><p>${escapeHTML((planPayload.packages || []).join(", ") || "None")}</p></div><div><span>Rollback</span><p>${escapeHTML(planPayload.rollback || "—")}</p></div></div><p>${escapeHTML(planPayload.justification || "")}</p><p class="inline-pending">${escapeHTML(planPayload.compromise_follow_up || "")}</p>` : `<div class="stage-placeholders"><div><span>Strategy</span><p>No recommendation until exposure is assessed.</p></div><div><span>Compatibility</span><p>No analysis recorded.</p></div><div><span>Rollback</span><p>Will be defined with the proposal.</p></div></div>`, planRow ? String(planPayload.action || "Ready") : "Pending");
  const patch = responseStage("02", "Proposed change", "Recorded changes and their execution status.", patchRow ? `<div class="diff-scaffold"><div class="diff-file-list">${icon("cases")}<span>${escapeHTML((patchPayload.files || []).join(", ") || "No files")}</span></div><pre class="code-panel">${escapeHTML(patchPayload.diff || patchPayload.note || "")}</pre></div><div class="stage-footer"><span>${escapeHTML(patchPayload.note || "Labeled diff")}</span></div>` : `<div class="diff-scaffold"><div class="diff-file-list">${icon("cases")}<span>No changed files</span></div><div class="diff-empty">${icon("patch")}<span>The diff appears when Patchwright prepares an isolated change.</span></div></div><div class="stage-footer"><span>No pull request recorded</span></div>`, patchRow ? (patchPayload.synthetic ? "Synthetic example" : "Recorded change") : "Not prepared");
  const validation = responseStage("03", "Validation", "A missing tool does not approve.", `<div class="validation-checks">${(validationPayload.results || [["Functional tests", "Project install and tests"], ["Syft", "Updated inventory"], ["Trivy", "Dependency scan"], ["OSV-Scanner", "Advisory cross-check"]].map(([name, detail]) => ({ tool: name, reason: detail, status: "not_executed" }))).map((row) => `<div><span class="validation-icon">${icon("check")}</span><div><strong>${escapeHTML(row.tool || row[0] || "tool")}</strong><small>${escapeHTML(row.reason || row[1] || "")}</small></div>${badge(row.status === "not_executed" ? "Not executed" : String(row.status || "Pending"))}</div>`).join("")}</div>`, validationPayload.overall || "Pending");
  const approval = responseStage("04", "Review and approval", "A human decision on a specific artifact.", `<div class="approval-summary"><p>${approvalRow ? `${escapeHTML(approvalRow.decision)} · ${escapeHTML(approvalRow.artifact_kind || "plan")}. ${escapeHTML(approvalRow.justification || "")}` : "Review the plan and record your decision with a justification. Approval applies only to the selected artifact."}</p><div class="actions">${button("Close case", "close-case", "", false, !item)}${button("Approve plan", "approve-plan", "approval", true, !planRow)}</div></div>`, approvalRow ? String(approvalRow.decision) : "Pending");
  const runPanel = `<section class="case-block"><div class="case-block-heading"><h3>${icon("layers")}Investigation run</h3>${latestRun ? badge(latestRun.status) : badge("No run", "sand")}</div><div class="case-block-body"><p>${latestRun ? `Stage ${escapeHTML(String(latestRun.stage))} · attempts ${escapeHTML(String(latestRun.attempts))}/${escapeHTML(String(latestRun.max_attempts))}` : "Inventory → sources → correlation. One stage per advance. Critique does not change exposure."}</p><div class="case-actions">${button("Refresh inventory", "refresh-inventory", "refresh", false, !item)}${button("Start run", "start-run", "plus", true, !item)}${button("Advance stage", "advance-run", "arrow", false, !latestRun)}${button("Pause", "pause-run", "clock", false, !latestRun)}${button("Cancel", "cancel-run", "", false, !latestRun)}${button("Compose plan", "compose-plan", "patch", false, !assessments.length)}${button("Synthesis", "synthesis", "signal", false, !assessments.length)}${button("Export report", "export-report", "download", false, !item)}${button("Close case", "close-case", "", false, !item)}</div>${runs.length ? `<ul class="timeline">${runs.slice(0, 4).map((run) => `<li>${escapeHTML(run.status)} · ${escapeHTML(String(run.stage))}<small>${escapeHTML(date(run.updated_at || run.started_at))}</small></li>`).join("")}</ul>` : ""}</div></section>`;
  const memoryPanel = `<section class="case-block"><div class="case-block-heading"><h3>${icon("info")}H-MEM and critique</h3>${badge(memory?.available ? "Recall" : "No recall", memory?.available ? "green" : "sand")}</div><div class="case-block-body"><p>${escapeHTML((memory?.context || "The engine reinjects prior evidence when recall exists. It does not assign exposure.").slice(0, 400))}</p>${critique ? `<p><strong>Critique ${escapeHTML(critique.status)}</strong> ${escapeHTML((typeof critique.evaluator === "string" ? critique.evaluator : critique.evaluator?.reason || critique.reason || critique.decision || "Review recorded").slice(0, 280))}</p>` : "<p class=\"inline-pending\">Planner/evaluator critique is skipped if Nightshift is not configured.</p>"}</div></section>`;
  const history = `<section class="case-block history-block"><div class="case-block-heading"><h3>${icon("clock")}History and traceability</h3>${badge(runs.length ? "Runs" : "Partial query")}</div><div class="case-block-body">${item ? `<ul class="timeline"><li>Advisory recorded<small>${escapeHTML(date(item.created_at))} · persisted record</small></li>${latestRun ? `<li>Last run ${escapeHTML(latestRun.status)}<small>${escapeHTML(date(latestRun.updated_at))}</small></li>` : ""}</ul>` : '<p>Actions will appear here once an investigation exists.</p>'}</div></section>`;
  const actions = item ? `<div class="page-actions">${button("Refresh", "refresh", "refresh")}${button("New investigation", "new-case", "plus", true)}</div>` : button("New investigation", "new-case", "plus", true);
  const crewLog = `<section class="case-block history-block"><div class="case-block-heading"><h3>${icon("layers")}Agent acts</h3>${badge((ctx?.agents || []).length ? String(ctx.agents.length) : "0")}</div><div class="case-block-body">${agentTimeline(ctx?.agents || [])}</div></section>`;
  return heading("Investigation and response", "", motionControl() + actions) + operationViews() + `<div class="operations-layout">${queue}<article class="case-workspace"><div class="case-workspace-heading"><div><h2>${escapeHTML(item?.title || "Choose an investigation to begin")}</h2></div>${item ? "" : badge("Not selected")}</div>${state.contextError ? note("Investigation details unavailable", state.contextError) : ""}${sampleNotice}${context}<div class="case-intelligence-grid">${evidence}${exposure}</div><div class="case-intelligence-grid">${runPanel}${memoryPanel}</div>${crewLog}<div class="response-flow-heading"><h2>Response flow</h2><span>No pull request recorded</span></div><div class="response-flow">${plan}${patch}${validation}${approval}</div>${history}</article></div>`;
}
function agentsPage() {
  const crew = state.crew || [];
  const roster = crew.length ? `<div class="integration-grid">${crew.map((agent) => `<article class="integration-card"><div class="integration-card-header">${agentAvatar(agent.id)}<div><h3>${escapeHTML(agent.name)}</h3><small>${escapeHTML(agent.role)}</small></div></div><p>${escapeHTML(agent.mission)}</p><p><strong>Decides:</strong> ${escapeHTML(agent.decides)}</p><p><strong>Never:</strong> ${escapeHTML(agent.never)}</p><div class="integration-card-footer">${(agent.tools || []).map((tool) => badge(tool)).join(" ")}</div></article>`).join("")}</div>` : empty("Loading crew", "The public roster does not require a token. Retry if the API is still starting.", "layers", button("Refresh", "refresh", "refresh"));
  return heading("Crew", "", motionControl()) + operationViews() +
    roster +
    panel("Activity", timelineRegion(state.activity || []));
}
function flowPanel() {
  const steps = [["Detection", "Sources and advisories", "signal"], ["Investigation", "Evidence and exposure", "search"], ["Remediation", "Plan and proposed change", "patch"], ["Validation", "Tests and analysis", "check"], ["Human review", "Decision and PR handoff", "approval"]];
  return panel("Response flow", `<ol class="flow-list">${steps.map(([name, sub, glyph]) => `<li><span class="flow-step">${icon(glyph)}</span><div><strong>${name}</strong><small>${sub}</small></div></li>`).join("")}</ol>`, "");
}
function listToolbar(kind) { return `<div class="toolbar"><label class="search-field" for="list-search">${icon("search")}<input id="list-search" type="search" placeholder="${kind === "applications" ? "Search application or repository" : "Search by investigation title"}" value="${escapeHTML(state.search)}" aria-label="Search ${kind}"></label><div class="filters"><span class="badge">${kind === "applications" ? "Node.js / npm" : "All advisories"}</span></div></div>`; }
function applicationResults() {
  const rows = state.applications?.filter((item) => `${item.name} ${item.repository}`.toLowerCase().includes(state.search.toLowerCase()));
  return rows?.length ? table(["Application", "Ecosystem", "Inventory", ""], rows.map((item) => `<tr><td><button class="row-link" data-action="app-detail" data-id="${escapeHTML(item.id)}">${escapeHTML(item.name)}</button><small>${escapeHTML(item.repository)}</small></td><td>${badge("npm")}</td><td>${inventoryBadge(item.id)}</td><td class="row-arrow" aria-hidden="true">›</td></tr>`).join("")) : state.search && state.applications?.length ? empty("No matches", "Try another name or repository.", "search") : accessEmpty("applications");
}
function refreshResults() { const results = $("list-results"); if (results) results.innerHTML = applicationResults(); }
function applicationsPage(id, tab) {
  if (id) return applicationDetail(id, tab);
  return heading("Applications", "Technology context that links each threat to your environment.", button("Register application", "new-app", "plus", true)) +
    panel("Workspace repositories", listToolbar("applications") + `<div id="list-results">${applicationResults()}</div>`) +
    `<div class="feature-columns"><div class="feature-description"><h3>Versioned inventory</h3><p>Direct and transitive dependencies tied to a verifiable commit.</p></div><div class="feature-description"><h3>Deployment context</h3><p>Environments and history to investigate past exposure.</p></div><div class="feature-description"><h3>Explicit coverage</h3><p>Partial or stale inventories will be shown as such.</p></div></div>`;
}
function tabs(items, selected, prefix) { return `<nav class="tabs" aria-label="Detail sections">${items.map(([key, label]) => `<a class="tab" href="#${prefix}/${key}"${selected === key ? ' aria-current="page"' : ""}>${label}</a>`).join("")}</nav>`; }
function applicationDetail(id, tab) {
  const app = state.applications?.find((item) => item.id === id);
  const cachedInventory = state.inventory[id];
  if (cachedInventory) {
    state.snapshots = cachedInventory.snapshots || [];
    state.deployments = cachedInventory.deployments || [];
    state.inventoryError = "";
  }
  if (!app) return heading("Application detail", "Select a registered application to view its context.") + panel("Application unavailable", accessEmpty("applications"));
  const selected = ["overview", "inventory", "deployments"].includes(tab) ? tab : "overview";
  let body = "";
  if (selected === "overview") body = panel("Application information", `<div class="section-body"><dl class="properties"><dt>Name</dt><dd>${escapeHTML(app.name)}</dd><dt>Repository</dt><dd>${escapeHTML(app.repository)}</dd><dt>Ecosystem</dt><dd>Node.js / npm</dd><dt>Registered</dt><dd>${escapeHTML(date(app.created_at))}</dd><dt>Inventory</dt><dd>${badge(state.snapshots.length ? `${state.snapshots.length} snapshot${state.snapshots.length === 1 ? "" : "s"}` : "Not generated", state.snapshots.length ? "green" : "sand")}</dd><dt>Deployments</dt><dd>${state.inventoryError ? "Unavailable" : `${state.deployments.length} imported`}</dd></dl></div>`);
  if (selected === "inventory") {
    const snapshots = state.snapshots || [];
    body = snapshots.length
      ? panel("Components and dependencies", table(["Commit", "Observed", "Warnings"], snapshots.map((row) => `<tr><td><code>${escapeHTML((row.commit_ref || row.commit_sha || "").slice(0, 12))}</code></td><td>${escapeHTML(date(row.observed_at))}</td><td>${badge(Array.isArray(row.warnings) && row.warnings.length ? String(row.warnings.length) : "None")}</td></tr>`).join("")), button("Refresh inventory", "refresh-inventory", "refresh"), "Snapshot resolves via GitHub. Real Syft is still pending.")
      : panel("Components and dependencies", empty("Inventory not built yet", "Resolve the commit lockfile to correlate versions.", "layers", button("Generate inventory", "refresh-inventory", "refresh"), true), badge("Pending"), "Real Syft is still pending; this snapshot does not assert a container SBOM.");
  }
  if (selected === "deployments") body = panel("Deployment history", state.inventoryError ? note("Unable to load deployments", state.inventoryError) : state.deployments.length ? table(["Environment", "Commit", "Deployed", "Retired"], state.deployments.map((row) => `<tr><td>${escapeHTML(row.environment)}</td><td><code>${escapeHTML((row.commit_sha || row.commit_ref || row.artifact_ref || "Unknown").slice(0, 16))}</code></td><td>${escapeHTML(date(row.deployed_at))}</td><td>${row.retired_at ? escapeHTML(date(row.retired_at)) : "Not recorded"}</td></tr>`).join("")) : empty("No deployment records", "Exposure history requires deployment records with a period and source. No deployment has been inferred from repository contents.", "clock"));
  if (selected !== "deployments" && state.inventoryError) body = note("Inventory unavailable", state.inventoryError) + body;
  return `<a class="back-link" href="#applications">${icon("back")}All applications</a>` + heading(app.name, app.repository, button("Generate inventory", "refresh-inventory", "refresh")) + tabs([["overview", "General"], ["inventory", "Inventory"], ["deployments", "Deployments"]], selected, `applications/${escapeHTML(id)}`) + body;
}
function integrationsPage() {
  const rows = CATALOG.filter((item) => state.filter === "all" || (state.filter === "sources" ? item.kind === "source" : state.filter === "tools" ? ["scanner", "inventory"].includes(item.kind) : ["model", "model-access", "research", "data", "engineering", "engine"].includes(item.kind)));
  const scopes = { mvp: "MVP", hackathon: "Partner", candidate: "Candidate", conditional: "Conditional" };
  return heading("Integrations", "", button("Refresh status", "refresh", "refresh")) +
    note("Configuration is not verification.", "A credential or URL only marks configuration. Nightshift, Zetaris, and H-MEM are verified by the named operation, not by secret presence.") +
    `<div class="tabs" aria-label="Filter integrations">${[["all", "All"], ["sources", "Intelligence"], ["tools", "Analysis"], ["models", "Models and services"]].map(([key, label]) => `<button class="tab${state.filter === key ? " active" : ""}" type="button" data-action="integration-filter" data-filter="${key}" aria-pressed="${state.filter === key}">${label}</button>`).join("")}</div><div class="integration-grid">${rows.map((item) => {
      const live = state.integrations?.find((entry) => entry.id === item.id);
      const verified = live?.verified === true;
      const status = live?.status || item.status;
      return `<article class="integration-card"><div class="integration-card-header"><span class="integration-symbol connector-symbol">${connectorIcon(item.id)}</span><div><h3>${item.name}</h3><small>${scopes[item.scope] || item.scope}</small></div></div><p>${item.description}</p><div class="integration-card-footer">${badge(verified ? "Verified" : status === "implemented_unverified" ? "Connected, unverified" : "Pending", verified ? "green" : "sand")}<span class="muted">${live?.verified_operation ? escapeHTML(live.verified_operation) : live?.auth?.configured ? "Configured" : live?.auth?.mode === "none" ? "No credential" : "Unverified"}</span></div>${["meterless", "zetaris", "hmem"].includes(item.id) ? `<div class="case-actions"><button type="button" class="button" data-action="check-integration" data-id="${escapeHTML(item.id)}">${icon("check")}Check</button></div>` : ""}</article>`;
    }).join("")}</div>`;
}
function settingRow(name, description, value) { return `<div class="settings-row"><div><h3>${escapeHTML(name)}</h3><p>${escapeHTML(description)}</p></div><div class="setting-value">${value}</div></div>`; }
function settingsPage() {
  const values = {
    general: [settingRow("Workspace", "One organization for the first product version.", "Local environment"), settingRow("Supported ecosystem", "Supported application dependencies.", "Node.js / npm"), settingRow("Connection", "Individual credential stored in browser memory only.", button(state.authenticated ? "Manage" : "Connect", "connect", "plug"))],
    access: [settingRow("Current session", "Individual credentials; permissions are enforced by the server.", state.authenticated ? badge("Active", "green") : badge("Not connected")), settingRow("Authorization", "Server-assigned roles and application scope govern every request.", "Server enforced")],
    policy: [settingRow("Human oversight", "Sensitive proposals will require specific authorization.", "Artifact-specific review"), settingRow("Execution budgets", "Runs retain time and attempt budgets across restarts.", "Per run"), settingRow("Production actions", "Merge, deploy, and real secrets are outside the MVP.", "Excluded")],
    data: [settingRow("Database", "Persistence for applications and investigations.", state.database ? badge("Available", "green") : badge("Not connected", "sand")), settingRow("Operations", "Retention and backups are managed by the operator; this screen does not change them.", "Read only")],
  };
  return heading("Settings", "Workspace preferences, access, and policies.") + `<div class="settings-layout"><nav class="settings-nav" aria-label="Settings categories">${[["general", "General"], ["access", "Access and roles"], ["policy", "Autonomy and limits"], ["data", "Data and retention"]].map(([key, label]) => `<button type="button" class="${state.settingsTab === key ? "active" : ""}" data-action="settings-tab" data-tab="${key}" aria-pressed="${state.settingsTab === key}">${label}</button>`).join("")}</nav>${panel("Workspace settings", `<div class="section-body">${values[state.settingsTab].join("")}</div>`, badge("Read only"))}</div>`;
}
function render() {
  const current = route();
  renderNavigation(); renderChrome();
  const views = { overview, investigations: operationsCase, agents: agentsPage, applications: () => applicationsPage(current.id, current.tab), integrations: integrationsPage, settings: settingsPage };
  $("view").innerHTML = views[current.page]();
  $("view").setAttribute("aria-busy", String(state.loading));
}

function requestTimeout(path, method = "GET") {
  if (/\/(advance|synthesis|inventory\/refresh|memory\/sleep|integrations\/.+\/check|demo\/run|plan|patch|validate)$/.test(path) && method !== "GET") return 120000;
  if (/\/(context|memory|inventory)$/.test(path)) return 20000;
  return 8000;
}
async function api(path, options = {}) {
  let response;
  const method = (options.method || "GET").toUpperCase();
  try { response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), ...(options.headers || {}) }, cache: "no-store", signal: AbortSignal.timeout(requestTimeout(path, method)) }); }
  catch (error) { throw new Error(error.name === "TimeoutError" ? "The request took too long. Check the connection again." : "Could not reach the local API."); }
  if (!response.ok) {
    const messages = { 401: "The token is invalid. Check the environment connection.", 403: "The crew rejected that action. Merge, deploy, and secrets are prohibited.", 404: "The requested record is no longer available.", 409: "Complete the previous stage before continuing.", 422: "Check the fields. Use org/repo and a valid http or https URL.", 503: "The service is not ready. Check the database and migrations." };
    const error = new Error(messages[response.status] || `The request failed (${response.status}).`); error.status = response.status; throw error;
  }
  return response.json();
}
async function refreshHealth() {
  const publicGet = (path) => fetch(path, { cache: "no-store", signal: AbortSignal.timeout(5000) }).then((response) => response.json());
  const [live, ready, roster, activity] = await Promise.allSettled([
    api("/health/live"),
    api("/health/ready"),
    publicGet("/agents"),
    publicGet("/agents/activity"),
  ]);
  state.api = live.status === "fulfilled" && live.value.status === "ok";
  state.database = ready.status === "fulfilled" && ready.value.status === "ready";
  if (roster.status === "fulfilled") state.crew = roster.value.crew || [];
  if (activity.status === "fulfilled" && !state.token) state.activity = activity.value.events || [];
  renderChrome();
  render();
}
async function refreshData(silent = false) {
  const sequence = ++refreshSequence;
  state.loading = true; render();
  try {
    if (!state.token) { await refreshHealth(); return; }
    try { state.integrations = await api("/api/integrations"); }
    catch (error) {
      if (error.status === 401) throw error;
      state.integrations = Array.isArray(state.integrations) ? state.integrations : [];
    }
    if (sequence !== refreshSequence) return;
    state.authenticated = true;
    const results = await Promise.allSettled([api("/api/applications"), api("/api/investigations"), api("/api/agents/activity"), refreshHealth()]);
    if (sequence !== refreshSequence) return;
    state.applications = results[0].status === "fulfilled" ? results[0].value : null;
    state.investigations = results[1].status === "fulfilled" ? results[1].value : null;
    state.activity = results[2].status === "fulfilled" ? results[2].value : [];
    state.appError = results[0].status === "rejected" ? results[0].reason.message : "";
    state.caseError = results[1].status === "rejected" ? results[1].reason.message : "";
    state.updated = new Date();
    loadInventories();
    const current = selectedInvestigation();
    if (current) await loadCaseExtras(current, sequence);
    if (!silent) announce(state.appError || state.caseError ? "Partial connection: adapters were queried, but environment data is missing." : "Data updated.", state.appError ? "" : "success");
  } catch (error) {
    if (sequence !== refreshSequence) return;
    if (error.status === 401) { state.authenticated = false; state.token = ""; state.applications = null; state.investigations = null; state.integrations = null; state.context = null; state.snapshots = []; }
    if (!silent) announce(error.message, "error");
    throw error;
  } finally { if (sequence === refreshSequence) { state.loading = false; render(); } }
}
function openModal(title, content) { $("modal-content").innerHTML = `<div class="dialog-header"><h2 id="modal-title">${title}</h2><button class="dialog-close" type="button" data-action="close-modal" aria-label="Close dialog">×</button></div><div class="dialog-body">${content}</div>`; if (!$("modal").open) $("modal").showModal(); }
function field(id, label, input, hint = "") { return `<div class="field"><label for="${id}">${label}</label>${input}${hint ? `<p class="field-hint" id="${id}-hint">${hint}</p>` : ""}</div>`; }
function formActions(text) { return `<p id="form-error" class="form-error" role="alert" hidden></p><div class="dialog-actions">${button("Cancel", "close-modal")}<button class="button primary" type="submit">${text}</button></div>`; }
function connectionDialog() {
  openModal("Connect your environment", `<p>Use the token configured for this local environment. It is kept in memory until you close or reload the page.</p><div class="connection-summary"><span>API</span>${badge(state.api ? "Available" : "Unavailable", state.api ? "green" : "sand")}</div><div class="connection-summary"><span>Database</span>${badge(state.database ? "Available" : "Pending", state.database ? "green" : "sand")}</div><hr><form id="connect-form" method="post" action="/api/integrations">${field("connection-token", "Development token (required)", '<div class="password-row"><input id="connection-token" name="token" type="password" required autocomplete="off" spellcheck="false" aria-describedby="connection-token-hint"><button class="button" type="button" data-action="toggle-token" aria-pressed="false">Show</button></div>', "Matches WARDEN_API_TOKEN in your local configuration.")}${formActions("Connect")}</form>${state.authenticated ? `<hr>${button("Disconnect this session", "logout")}` : ""}`);
}
function requireWritable() {
  if (!state.authenticated) { connectionDialog(); return false; }
  if (!state.database) { announce("The database is not ready. Reconnect the environment to save records.", "error"); return false; }
  return true;
}
function newAppDialog() {
  if (!requireWritable()) return;
  openModal("Register application", `<p>Add a repository to prepare your application security context.</p><form id="application-form" method="post" action="/api/applications">${field("application-name", "Name (required)", '<input id="application-name" name="name" required maxlength="120" autocomplete="off">')}${field("application-repository", "GitHub repository (required)", '<input id="application-repository" name="repository" required maxlength="201" placeholder="org/repository" autocapitalize="off" spellcheck="false" aria-describedby="application-repository-hint">', "For now only the reference is registered. Inventory is pending.")}${formActions("Register application")}</form>`);
}
function newCaseDialog() {
  if (!requireWritable()) return;
  if (!state.applications?.length) { navigate("applications"); announce("Register an application before creating an investigation."); return; }
  openModal("New investigation", `<p>Link a security advisory to an application. Exposure stays undetermined until assessed.</p><form id="investigation-form" method="post" action="/api/investigations">${field("case-application", "Application (required)", `<select id="case-application" name="application_id" required><option value="">Select an application</option>${state.applications.map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)}</option>`).join("")}</select>`)}${field("case-title", "Title (required)", '<input id="case-title" name="title" required maxlength="200">')}${field("case-source", "Source URL (required)", '<input id="case-source" name="source_url" type="url" required placeholder="https://…" autocapitalize="off" spellcheck="false">')}${field("case-description", "Description (required)", '<textarea id="case-description" name="description" required maxlength="10000" rows="3"></textarea>')}${formActions("Register advisory")}</form>`);
}
function closeNavigation() {
  const wasOpen = document.body.classList.contains("nav-open");
  document.body.classList.remove("nav-open");
  $("nav-scrim").hidden = true;
  $("sidebar").inert = window.matchMedia("(max-width:720px)").matches;
  document.querySelector(".main-column").inert = false;
  document.querySelector(".mobile-menu").setAttribute("aria-expanded", "false");
  if (wasOpen) document.querySelector(".mobile-menu").focus();
}
async function loadCaseExtras(item, sequence = refreshSequence) {
  if (!item) { state.context = null; state.contextFor = ""; state.snapshots = []; return; }
  const results = await Promise.allSettled([
    api(`/api/investigations/${item.id}/context`),
    api(`/api/applications/${item.application_id}/inventory`),
  ]);
  if (sequence !== refreshSequence) return;
  state.context = results[0].status === "fulfilled" ? results[0].value : null;
  state.contextFor = item.id;
  state.contextError = results[0].status === "rejected" ? results[0].reason.message : "";
  state.inventoryError = results[1].status === "rejected" ? results[1].reason.message : "";
  state.deployments = results[1].status === "fulfilled" ? (results[1].value.deployments || []) : [];
  state.snapshots = results[1].status === "fulfilled" ? (results[1].value.snapshots || []) : [];
}
function helpDialog() { openModal("About Warden", `<p>Investigate advisories, assess exposure, and review proposed responses in one case. Models propose; evidence and deterministic checks support conclusions.</p>${note("Sample mode", "Creates a labeled synthetic application and investigation in this workspace. It does not contact Nightshift, Zetaris, or NVIDIA, and does not prove those integrations.")}<div class="dialog-actions">${button("Create sample investigation", "sample-run", "signal")}${button("Close", "close-modal", "", true)}</div>`); }

async function performAction(action, target) {
  if (action === "operation-view") { state.operationView = target.dataset.view; navigate("overview"); return; }
  if (NAV.some((item) => item[0] === action)) { navigate(action); return; }
  if (action === "connect") connectionDialog();
  if (action === "help") helpDialog();
  if (action === "close-modal") $("modal").close();
  if (action === "new-app") newAppDialog();
  if (action === "new-case") newCaseDialog();
  if (action === "refresh") { try { await refreshData(); } catch { /* refreshData announces the error. */ } }
  if (action === "case-detail") { state.selectedCase = target.dataset.id; navigate(`investigations/${target.dataset.id}`); }
  if (action === "refresh-inventory") {
    const item = selectedInvestigation();
    const appId = route().page === "applications" && route().id ? route().id : item?.application_id;
    if (!requireWritable()) return;
    if (!appId) { announce("Open an application to refresh its inventory.", "error"); return; }
    await api(`/api/applications/${appId}/inventory/refresh`, { method: "POST", body: JSON.stringify({}) });
    announce("Updated inventory.", "success");
    await refreshData(true);
  }
  if (action === "start-run") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const snapshot = state.snapshots[0];
    if (!snapshot) { announce("Generate inventory before starting the run.", "error"); return; }
    const match = `${item.title} ${item.source_url} ${item.description}`.match(ADVISORY);
    if (!match) { announce("The advisory must include a GHSA or CVE to start the run.", "error"); return; }
    const run = await api(`/api/investigations/${item.id}/runs`, { method: "POST", body: JSON.stringify({ snapshot_id: snapshot.id, advisory_identifier: match[0].toUpperCase().startsWith("CVE") ? match[0].toUpperCase() : match[0], request_key: crypto.randomUUID() }) });
    announce("Run created. Advance each stage separately.", "success");
    await refreshData(true);
    state.selectedCase = item.id;
  }
  if (action === "advance-run") {
    const item = selectedInvestigation();
    const run = state.context?.runs?.[0];
    if (!item || !run || !requireWritable()) return;
    const result = await api(`/api/investigations/${item.id}/runs/${run.id}/advance`, { method: "POST" });
    announce(`Stage ${result.stage || run.stage}: ${result.status}.`, result.status === "requires_intervention" ? "error" : "success");
    await refreshData(true);
  }
  if (action === "synthesis") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const result = await api(`/api/investigations/${item.id}/synthesis`, { method: "POST" });
    announce(result.nightshift_deployment_verified ? "Nightshift synthesis recorded." : "Proposal recorded. Nightshift is not verified by this submission alone.", "success");
    await refreshData(true);
  }
  if (action === "check-integration") {
    if (!requireWritable()) return;
    const result = await api(`/api/integrations/${target.dataset.id}/check`, { method: "POST" });
    announce(`${target.dataset.id}: ${result.status}${result.verified ? " (verified)" : ""}.`, result.verified ? "success" : "");
    await refreshData(true);
  }
  if (action === "timeline-attention") { timelineOptions.attentionOnly = !timelineOptions.attentionOnly; render(); $("view").querySelector('[data-action="timeline-attention"]')?.focus(); return; }
  if (action === "toggle-agent-motion") { agentMotionPaused = !agentMotionPaused; render(); return; }
  if (action === "sample-run") {
    $("modal").close();
    if (!requireWritable()) return;
    announce("The crew is working with synthetic sources…");
    const result = await api("/api/demo/run", { method: "POST" });
    state.selectedCase = result.investigation_id;
    announce("Demo complete. Agents acted; Nightshift was not contacted.", "success");
    await refreshData(true);
    state.selectedCase = result.investigation_id;
    navigate(`investigations/${result.investigation_id}`);
  }
  if (action === "pause-run" || action === "cancel-run") {
    const item = selectedInvestigation();
    const run = state.context?.runs?.[0];
    if (!item || !run || !requireWritable()) return;
    const verb = action === "pause-run" ? "pause" : "cancel";
    await api(`/api/investigations/${item.id}/runs/${run.id}/${verb}`, { method: "POST" });
    announce(verb === "pause" ? "Warden paused the run." : "Warden cancelled new stages.", "success");
    await refreshData(true);
  }
  if (action === "close-case") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    openModal("Close investigation", `<p>Closing keeps evidence and does not merge code. Choose the outcome and justify the decision.</p><form id="close-form">${field("close-outcome", "Outcome", '<select id="close-outcome" name="outcome" required><option value="discarded">Discarded</option><option value="not_affected">Not affected</option><option value="risk_accepted">Risk accepted</option><option value="cancelled">Cancelled</option></select>')}${field("close-justification", "Justification (at least 10 characters)", '<textarea id="close-justification" name="justification" required minlength="10" maxlength="2000" rows="3" placeholder="Why is this the right outcome? Cite the evidence you reviewed."></textarea>')}${formActions("Close case")}</form>`);
  }
  if (action === "forbid-merge") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    try {
      await api(`/api/investigations/${item.id}/merge`, { method: "POST" });
      announce("Unexpected: the API accepted a merge request. Report this immediately.", "error");
    } catch (error) {
      announce(error.status === 403 ? "Guardrail held: Warden refused the merge and logged the attempt." : error.message, error.status === 403 ? "success" : "error");
      await refreshData(true);
    }
  }
  if (action === "approve-plan") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const planRow = state.context?.plans?.[0];
    if (!planRow) { announce("Compose a plan before reviewing it.", "error"); return; }
    const plan = planRow.payload || {};
    openModal("Review plan", `<p>You are deciding on this exact version of the plan. If the plan or its diff changes, this decision is void. Approval never merges code.</p><dl class="approval-artifact"><div><dt>Action</dt><dd>${escapeHTML(plan.action || "—")}</dd></div><div><dt>Packages</dt><dd>${escapeHTML((plan.packages || []).join(", ") || "None")}</dd></div><div><dt>Rollback</dt><dd>${escapeHTML(plan.rollback || "—")}</dd></div><div><dt>Composed</dt><dd>${escapeHTML(date(planRow.created_at))}</dd></div><div><dt>Version</dt><dd><code>${escapeHTML(String(planRow.content_hash || "—").slice(0, 16))}</code></dd></div></dl>${plan.justification ? `<p class="field-hint">Agent rationale: ${escapeHTML(plan.justification)}</p>` : ""}<form id="approval-form" data-hash="${escapeHTML(planRow.content_hash || "")}">${field("approval-decision", "Decision", '<select id="approval-decision" name="decision" required><option value="" selected disabled>Choose a decision</option><option value="approved">Approve this plan</option><option value="rejected">Reject this plan</option></select>')}${field("approval-justification", "Your justification (at least 10 characters)", '<textarea id="approval-justification" name="justification" required minlength="10" maxlength="2000" rows="4" placeholder="What did you check, and why is this the right call?"></textarea>', "Recorded with your identity in the audit trail.")}${formActions("Record decision")}</form>`);
  }
  if (action === "compose-plan" || action === "export-report") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const routes = {
      "compose-plan": ["/api/investigations/" + item.id + "/plan", { method: "POST" }],
      "prepare-patch": ["/api/investigations/" + item.id + "/patch", { method: "POST" }],
      "validate-patch": ["/api/investigations/" + item.id + "/validate", { method: "POST" }],
      "export-report": ["/api/investigations/" + item.id + "/report", { method: "GET" }],
    };
    const [path, options] = routes[action];
    const result = await api(path, options);
    if (action === "export-report") {
      const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = `warden-investigation-${item.id}.json`;
      document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      announce("Investigation report downloaded.", "success");
    } else {
      announce("The crew recorded the next act.", "success");
      await refreshData(true);
    }
  }
  if (action === "app-detail") {
    state.snapshots = (await loadInventory(target.dataset.id))?.snapshots || [];
    navigate(`applications/${target.dataset.id}`);
  }
  if (action === "settings-tab") { state.settingsTab = target.dataset.tab; render(); }
  if (action === "integration-filter") { state.filter = target.dataset.filter; render(); }
  if (action === "logout") { ++refreshSequence; state.token = ""; state.authenticated = false; state.applications = null; state.investigations = null; state.integrations = null; state.preview = null; state.appError = ""; state.caseError = ""; state.loading = false; $("modal").close(); render(); announce("Local session disconnected."); }
  if (action === "toggle-token") { const input = $("connection-token"); const visible = input.type === "password"; input.type = visible ? "text" : "password"; target.textContent = visible ? "Hide" : "Show"; target.setAttribute("aria-pressed", String(visible)); }
  if (action === "nav-toggle") {
    if (document.body.classList.contains("nav-open")) closeNavigation();
    else {
      document.body.classList.add("nav-open"); $("nav-scrim").hidden = false;
      $("sidebar").inert = false; document.querySelector(".main-column").inert = true;
      document.querySelector(".mobile-menu").setAttribute("aria-expanded", "true");
      $("sidebar").querySelector("a").focus();
    }
  }
  if (action === "preview") {
    target.disabled = true; target.setAttribute("aria-busy", "true");
    try { state.preview = await api(`/api/investigations/${target.dataset.id}/preview`, { method: "POST" }); state.selectedCase = target.dataset.id; navigate(`investigations/${target.dataset.id}`); announce("The flow stopped at pending inventory. No changes were executed."); }
    catch (error) { announce(error.message, "error"); }
    finally { target.disabled = false; target.setAttribute("aria-busy", "false"); }
  }
}
async function runAction(action, target) {
  if (state.pending.has(action)) return;
  const tracked = target.matches("button") && !SYNC_ACTIONS.has(action);
  let slow;
  if (tracked) {
    state.pending.add(action); target.disabled = true; target.setAttribute("aria-busy", "true");
    slow = setTimeout(() => announce("Still working. Long steps can take up to two minutes.", "busy"), 2500);
  }
  try { await performAction(action, target); }
  catch (error) { announce(error.message, "error"); }
  finally {
    if (tracked) {
      clearTimeout(slow); state.pending.delete(action);
      if ($("toast").classList.contains("busy")) $("toast").hidden = true;
      document.querySelectorAll(`[data-action="${action}"][data-busy]`).forEach((node) => { node.disabled = false; node.removeAttribute("aria-busy"); node.removeAttribute("data-busy"); });
      if (target.isConnected) { target.disabled = false; target.removeAttribute("aria-busy"); }
    }
  }
}
document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (target && !target.disabled) runAction(target.dataset.action, target);
  if (event.target.closest(".nav-item")) closeNavigation();
});
document.addEventListener("change", (event) => {
  if (event.target.matches("[data-timeline-sort]")) {
    timelineOptions.order = event.target.value === "oldest" ? "oldest" : "recent";
    render(); $("view").querySelector("[data-timeline-sort]")?.focus();
  }
});
document.addEventListener("input", (event) => {
  if (event.target.validity?.valid) event.target.removeAttribute("aria-invalid");
  if (event.target.id === "list-search") {
    state.search = event.target.value;
    clearTimeout(searchTimer); searchTimer = setTimeout(refreshResults, 150);
  }
});
document.addEventListener("invalid", (event) => { event.target.setAttribute("aria-invalid", "true"); }, true);
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!["connect-form", "application-form", "investigation-form", "close-form", "approval-form"].includes(form.id)) return;
  event.preventDefault();
  const payload = Object.fromEntries(new FormData(form));
  const submit = form.querySelector("button[type=submit]");
  const originalText = submit.textContent;
  submit.disabled = true; submit.textContent = "Saving…"; form.setAttribute("aria-busy", "true"); form.dataset.state = "submitting";
  $("form-error").hidden = true;
  try {
    if (form.id === "connect-form") {
      state.token = payload.token; submit.textContent = "Connecting…";
      await refreshData(true); $("modal").close(); announce(state.database ? "Environment connected." : "API connected. The database is not ready yet.", state.database ? "success" : "");
    } else if (form.id === "close-form") {
      const item = selectedInvestigation();
      if (!item) throw new Error("Select an investigation.");
      await api(`/api/investigations/${item.id}/close`, { method: "POST", body: JSON.stringify(payload) });
      $("modal").close(); await refreshData(true);
      announce("Case closed. Evidence is preserved and merge remains prohibited.", "success");
    } else if (form.id === "approval-form") {
      const item = selectedInvestigation();
      if (!item) throw new Error("Select an investigation.");
      const latest = (await api(`/api/investigations/${item.id}/context`))?.plans?.[0];
      if (!latest || latest.content_hash !== form.dataset.hash) throw Object.assign(new Error("The plan changed while you were reviewing it. Close this dialog and review the new version."), { final: true });
      await api(`/api/investigations/${item.id}/approval`, { method: "POST", body: JSON.stringify({ artifact_kind: "plan", decision: payload.decision, justification: payload.justification }) });
      $("modal").close(); await refreshData(true);
      announce(payload.decision === "approved" ? "Approval recorded for this plan version. Merge remains prohibited." : "Rejection recorded. The plan stays unapproved.", "success");
    } else {
      const endpoint = form.id === "application-form" ? "/api/applications" : "/api/investigations";
      const result = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
      $("modal").close(); await refreshData(true);
      if (form.id === "application-form") navigate(`applications/${result.id}`);
      else { state.selectedCase = result.id; navigate(`investigations/${result.id}`); }
      announce(form.id === "application-form" ? "Registered application." : "Advisory recorded. Exposure remains undetermined.", "success");
    }
  } catch (error) {
    const message = form.id === "connect-form" || error.final ? error.message : `${error.message} If the submission lost connection, refresh the list before retrying.`;
    if ($("modal").open && $("form-error")) { $("form-error").textContent = message; $("form-error").hidden = false; }
    else announce(message, "error");
  } finally { submit.disabled = false; submit.textContent = originalText; form.setAttribute("aria-busy", "false"); form.dataset.state = "idle"; }
});
window.addEventListener("hashchange", () => {
  state.search = "";
  const current = route();
  if (current.page === "applications" && current.id && state.token) {
    loadInventory(current.id).then((inventory) => { state.snapshots = inventory?.snapshots || []; render(); });
  }
  if (current.page === "overview" && state.operationView === "case") {
    const item = selectedInvestigation();
    if (item && state.token && state.contextFor !== item.id) loadCaseExtras(item).then(render).catch(render);
  }
  render();
  $("main-content").focus({ preventScroll: true });
  window.scrollTo({ top: 0 });
});
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeNavigation();
  if (event.key === "Tab" && document.body.classList.contains("nav-open")) {
    const focusable = Array.from($("sidebar").querySelectorAll("a, button:not(:disabled)"));
    const first = focusable[0]; const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});
window.matchMedia("(max-width:720px)").addEventListener("change", closeNavigation);
closeNavigation();
render();
refreshHealth();
setInterval(() => {
  if (document.hidden || $("modal").open) return;
  const apply = (rows) => {
    const before = new Set((state.activity || []).map((row) => row.id || row.created_at));
    if (activityKey(rows) === activityKey(state.activity)) return;
    state.activity = rows;
    refreshTimeline(rows.filter((row) => !before.has(row.id || row.created_at)).length);
  };
  if (state.token) {
    api("/api/agents/activity").then(apply).catch(() => {});
    return;
  }
  fetch("/agents/activity", { cache: "no-store", signal: AbortSignal.timeout(5000) })
    .then((response) => response.json())
    .then((body) => apply(body.events || []))
    .catch(() => {});
}, 8000);
