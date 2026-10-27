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
const NAV = [
  ["overview", "Centro de operaciones", "overview", "OPERACIÓN"], ["agents", "Tripulación", "layers"],
  ["applications", "Aplicaciones", "apps"],
  ["integrations", "Integraciones", "plug", "ESPACIO DE TRABAJO"], ["settings", "Configuración", "settings"],
];
const CATALOG = [
  ["github", "GitHub Security", "GH", "source", "mvp", "Avisos de seguridad asociados con repositorios y dependencias."],
  ["osv", "OSV", "O", "source", "mvp", "Vulnerabilidades y rangos afectados por paquete y versión."],
  ["nvd", "NVD", "N", "source", "mvp", "Información CVE, severidad y referencias técnicas."],
  ["cisa-kev", "CISA KEV", "K", "source", "mvp", "Señal de vulnerabilidades con explotación conocida."],
  ["syft", "Syft", "S", "inventory", "mvp", "Inventario de componentes y generación de SBOM."],
  ["trivy", "Trivy", "T", "scanner", "mvp", "Análisis de dependencias y artefactos autorizados."],
  ["osv-scanner", "OSV-Scanner", "OS", "scanner", "mvp", "Contraste de dependencias con avisos de OSV."],
  ["meterless", "Nightshift", "N", "model-access", "hackathon", "IA principal vía el hotspot de Nightshift (Meterless Runtime)."],
  ["hmem", "H-MEM", "H", "engine", "hackathon", "Engine de memoria local. La prueba es la suite oficial, no la red."],
  ["nvidia", "NVIDIA", "NV", "model", "candidate", "Nemotron se configura en Providers de Nightshift, no en Warden."],
  ["grok", "Grok / X", "G", "research", "conditional", "Investigación de reportes y publicaciones técnicas."],
  ["zetaris", "Zetaris", "Z", "data", "hackathon", "Capa de datos obligatoria. El modo local no acredita el patrocinador."],
  ["cursor", "Cursor", "C", "engineering", "conditional", "Automatización de cambios, sujeta a interfaz disponible."],
].map(([id, name, mark, kind, scope, description]) => ({ id, name, mark, kind, scope, description, verified: false, status: "not_implemented" }));
const STATUS = { detected: "Por investigar", investigating: "En curso", awaiting_review: "En revisión", requires_intervention: "Requiere intervención", closed: "Cerrada", cancelled: "Cancelada" };
const EXPOSURE = { undetermined: "Indeterminada", not_affected: "No afectada", potential: "Potencial", confirmed: "Confirmada" };
const ADVISORY = /(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|CVE-\d{4}-\d{4,})/i;
const state = { token: "", authenticated: false, api: false, database: false, applications: null, investigations: null, integrations: null, context: null, snapshots: [], crew: [], activity: [], appError: "", caseError: "", loading: false, search: "", filter: "all", settingsTab: "general", operationView: "panorama", selectedCase: "", preview: null, updated: null };
let toastTimer;
let refreshSequence = 0;

function badge(text, variant = "") { return `<span class="badge ${variant}">${escapeHTML(text)}</span>`; }
function button(text, action, glyph = "", primary = false, disabled = false, title = "") { return `<button type="button" class="button${primary ? " primary" : ""}" data-action="${action}"${disabled ? " disabled" : ""}${title ? ` title="${escapeHTML(title)}"` : ""}>${glyph ? icon(glyph) : ""}${escapeHTML(text)}</button>`; }
function heading(title, description, actions = "") { return `<div class="page-header"><div><h1>${escapeHTML(title)}</h1><p>${escapeHTML(description)}</p></div><div class="page-actions">${actions}</div></div>`; }
function empty(title, description, glyph = "cases", action = "", large = false) { return `<div class="empty-state${large ? " large" : ""}"><div class="empty-illustration">${icon(glyph)}</div><h3>${escapeHTML(title)}</h3><p>${escapeHTML(description)}</p>${action}</div>`; }
function panel(title, body, trailing = "", caption = "") { return `<section class="section-panel"><div class="section-heading"><h2>${escapeHTML(title)}</h2>${trailing}</div>${body}${caption ? `<div class="section-caption">${icon("info")}${escapeHTML(caption)}</div>` : ""}</section>`; }
function note(title, body) { return `<div class="module-note">${icon("info")}<p><strong>${escapeHTML(title)}</strong> ${escapeHTML(body)}</p></div>`; }
function route() { const parts = location.hash.slice(1).split("/"); return { page: NAV.some((item) => item[0] === parts[0]) ? parts[0] : "overview", id: parts[1] || "", tab: parts[2] || "overview" }; }
function navigate(page) { if (location.hash === `#${page}`) render(); else location.hash = page; closeNavigation(); }
function date(value) { return value ? new Intl.DateTimeFormat("es", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "Sin registro"; }
function count(rows) { return rows === null ? "—" : rows.length; }
function announce(message, type = "") { clearTimeout(toastTimer); $("toast").textContent = message; $("toast").className = `toast ${type}`; $("toast").hidden = false; toastTimer = setTimeout(() => { $("toast").hidden = true; }, 7000); }
function table(headers, rows) { return `<div class="table-wrap" tabindex="0" role="region" aria-label="Tabla de ${escapeHTML(headers[0].toLowerCase())}"><table><thead><tr>${headers.map((label) => `<th scope="col">${escapeHTML(label)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div>`; }

function renderNavigation() {
  const current = route().page;
  $("navigation").innerHTML = NAV.map(([id, label, glyph, group]) => `${group ? `<p class="nav-group-label">${group}</p>` : ""}<a class="nav-item" href="#${id}"${current === id ? ' aria-current="page"' : ""}>${icon(glyph)}<span>${label}</span>${id === "investigations" && state.investigations?.length ? `<span class="nav-count">${state.investigations.length}</span>` : ""}</a>`).join("");
  $("breadcrumb-current").textContent = NAV.find((item) => item[0] === current)?.[1] || "Resumen";
}
function renderChrome() {
  $("connection-label").textContent = state.authenticated ? (state.database ? "Entorno conectado" : "Conexión parcial") : "Conectar entorno";
  $("connection-dot").classList.toggle("online", state.authenticated && state.database);
  $("profile-status").textContent = state.authenticated ? "Sesión activa" : "Sin conexión";
  $("api-health").textContent = state.api ? "API disponible" : "API no disponible";
  const warning = $("environment-message");
  warning.hidden = !state.authenticated || state.database;
  warning.innerHTML = `<span>La base de datos no está disponible. Puedes explorar todas las secciones; guardar datos requiere reconectarla.</span><button type="button" data-action="refresh">Reintentar</button>`;
}
function metric(label, value, foot, glyph) { return `<article class="metric"><div class="metric-head"><span>${label}</span>${icon(glyph)}</div><div class="metric-value${value === "—" ? " pending" : ""}">${value}</div><div class="metric-foot">${foot}</div></article>`; }
function statusBadge(value) { return badge(STATUS[value] || value || "Por investigar", value === "detected" || !value ? "sand" : value === "awaiting_review" ? "green" : ""); }
function exposureBadge(value) { return badge(EXPOSURE[value] || value || "Indeterminada", value === "confirmed" ? "accent" : value === "potential" ? "sand" : value === "not_affected" ? "green" : ""); }
function caseRows(rows) { return rows.map((item) => `<tr><td><button class="row-link" data-action="case-detail" data-id="${escapeHTML(item.id)}">${escapeHTML(item.title)}</button><small>${escapeHTML(state.applications?.find((app) => app.id === item.application_id)?.name || "Aplicación registrada")}</small></td><td>${statusBadge(item.status)}</td><td>${exposureBadge(item.exposure)}</td><td class="row-arrow">↗</td></tr>`).join(""); }
function accessEmpty(type = "investigations") {
  const isApp = type === "applications";
  if (state.loading) return `<div class="loading-line"></div>${empty("Cargando el entorno", "Consultando los datos disponibles…", "refresh")}`;
  const error = isApp ? state.appError : state.caseError;
  if (error) return empty("Datos no disponibles", "Revisa la conexión a la base de datos y vuelve a intentarlo.", "signal", button("Reintentar", "refresh", "refresh"));
  if (!state.authenticated) return empty(isApp ? "Conoce tu entorno" : "Tu próxima investigación empieza aquí", isApp ? "Conecta tu entorno para registrar aplicaciones y preparar su inventario." : "Conecta el entorno para reunir los avisos que requieren una revisión.", isApp ? "apps" : "cases", button("Conectar entorno", "connect", "plug", true));
  return empty(isApp ? "Agrega tu primera aplicación" : "Sin investigaciones registradas", isApp ? "Registra un repositorio para empezar a construir el contexto de seguridad." : "Registra un aviso manual y relaciónalo con una aplicación.", isApp ? "apps" : "cases", button(isApp ? "Registrar aplicación" : "Nueva investigación", isApp ? "new-app" : "new-case", "plus", true));
}
function crewStrip() {
  const crew = state.crew || [];
  if (!crew.length) return "";
  return `<div class="crew-strip" aria-label="Tripulación de agentes">${crew.map((agent) => `<article class="crew-chip"><strong>${escapeHTML(agent.name)}</strong><small>${escapeHTML(agent.role)}</small></article>`).join("")}</div>`;
}
function agentTimeline(events) {
  if (!events?.length) return empty("Los agentes aún no han actuado", "Lanza la demo guiada o inicia una corrida. Cada decisión queda en esta línea de tiempo.", "layers", state.authenticated ? button("Correr demo de agentes", "demo-run", "signal", true) : button("Conectar entorno", "connect", "plug", true));
  return `<ol class="agent-timeline">${events.map((event) => `<li class="agent-event ${escapeHTML(event.status)}"><div><strong>${escapeHTML((state.crew.find((item) => item.id === event.agent) || { name: event.agent }).name)}</strong><small>${escapeHTML(event.stage)} · ${escapeHTML(event.status)}</small></div><p>${escapeHTML(event.summary)}</p><time>${escapeHTML(date(event.created_at))}</time></li>`).join("")}</ol>`;
}
function panorama() {
  const cases = state.investigations;
  const events = state.activity?.length ? state.activity : (state.context?.agents || []);
  return heading("Los agentes investigan. Tú decides.", "Once roles, una orquestación con estado y ninguna conclusión de modelo como evidencia.", button("Actualizar", "refresh", "refresh") + button("Correr demo de agentes", "demo-run", "signal", true) + button("Nueva investigación", "new-case", "plus")) + crewStrip() + operationViews() +
    `<div class="metrics">${metric("Aplicaciones registradas", count(state.applications), state.applications ? "En el espacio de trabajo" : "Conecta tu entorno", "apps")}${metric("Investigaciones", count(cases), cases ? "Avisos registrados" : "Sin datos del entorno", "cases")}${metric("Exposición confirmada", cases ? String(cases.filter((item) => item.exposure === "confirmed").length) : "—", cases ? "Según la correlación determinista" : '<span class="tiny-dot"></span>Sin datos del entorno', "check")}${metric("Capa de datos", state.context?.data_layer === "zetaris" ? "Zetaris" : cases ? "Local" : "—", state.context?.sponsor_data_layer_verified ? "Lectura Zetaris comprobada" : "El modo local no acredita el patrocinador", "layers")}</div>` +
    `<div class="content-grid"><div>${panel("Línea de tiempo de la tripulación", agentTimeline(events), badge(events.length ? `${events.length} actos` : "En vivo"), "Warden orquesta. El Árbitro clasifica. Nightshift propone. El merge está prohibido.")}${panel("Investigaciones recientes", cases?.length ? table(["Investigación", "Estado", "Exposición", ""], caseRows(cases.slice(0, 5))) : accessEmpty(), `<button type="button" class="text-link" data-action="operation-view" data-view="case">Abrir investigación ${icon("arrow")}</button>`)}</div><aside class="overview-aside">${flowPanel()}<section class="next-step"><div class="eyebrow">DEMO EN 3 MINUTOS</div><h3>Mira a los agentes colaborar sin APIs de patrocinador.</h3><p>La demo usa fuentes sintéticas etiquetadas y un mock de Nightshift. H-MEM y la correlación npm son código real.</p>${button("Correr demo de agentes", "demo-run", "signal", true)}</section></aside></div>` +
    `<div class="bottom-sources"><span>Fuentes de inteligencia</span>${CATALOG.slice(0, 4).map((item) => `<a href="#integrations" class="source-chip"><span class="source-icon">${item.mark}</span>${item.name}<span class="status-dot" title="Pendiente de implementar"></span></a>`).join("")}<a class="text-link" href="#integrations">Ver integraciones ${icon("arrow")}</a></div>`;
}
function operationViews() {
  return `<div class="operation-views"><div class="view-presets" aria-label="Vista del centro de operaciones"><button type="button" data-action="operation-view" data-view="panorama" class="view-preset${state.operationView === "panorama" ? " active" : ""}" aria-pressed="${state.operationView === "panorama"}">${icon("overview")}Panorama</button><button type="button" data-action="operation-view" data-view="case" class="view-preset${state.operationView === "case" ? " active" : ""}" aria-pressed="${state.operationView === "case"}">${icon("cases")}Investigación y respuesta</button></div><span class="view-range">${icon("clock")}Todo el historial</span></div>`;
}
function overview() { return state.operationView === "case" ? operationsCase() : panorama(); }
function responseStage(number, name, description, body, status = "Pendiente") {
  return `<section class="response-stage"><div class="response-stage-heading"><span class="stage-number">${number}</span><div><h3>${name}</h3><p>${description}</p></div>${badge(status)}</div><div class="response-stage-content">${body}</div></section>`;
}
function selectedInvestigation() {
  const rows = state.investigations || [];
  const item = rows.find((entry) => entry.id === state.selectedCase) || rows[0] || null;
  if (item) state.selectedCase = item.id;
  return item;
}
function operationsCase() {
  const rows = state.investigations || [];
  const item = selectedInvestigation();
  const app = item && state.applications?.find((entry) => entry.id === item.application_id);
  const ctx = state.context;
  const evidenceRows = ctx?.evidence || [];
  const assessments = ctx?.assessments || [];
  const runs = ctx?.runs || [];
  const critique = ctx?.critiques?.[0]?.payload;
  const memory = ctx?.memory;
  const latestRun = runs[0];
  const findings = assessments.flatMap((entry) => entry.payload?.findings || []);
  const queue = `<div class="case-queue"><div class="queue-heading"><h2>Investigaciones</h2>${badge(state.investigations === null ? "—" : String(rows.length))}</div>${state.loading ? '<div class="loading-line"></div>' : ""}${rows.length ? rows.map((entry) => `<button class="case-queue-item${item?.id === entry.id ? " selected" : ""}" data-action="case-detail" data-id="${escapeHTML(entry.id)}" type="button" aria-pressed="${item?.id === entry.id}"><span class="queue-item-icon">${icon("cases")}</span><span><strong>${escapeHTML(entry.title)}</strong><small>${escapeHTML(state.applications?.find((entryApp) => entryApp.id === entry.application_id)?.name || "Aplicación registrada")}</small><span class="queue-state">${statusBadge(entry.status)}</span></span></button>`).join("") : `<div class="queue-empty">${icon("cases")}<p>${state.authenticated ? "No hay investigaciones disponibles." : "Conecta el entorno para consultar los avisos."}</p>${button(state.authenticated ? "Nuevo aviso" : "Conectar", state.authenticated ? "new-case" : "connect", "plus")}</div>`}</div>`;
  const context = `<div class="case-context"><div><span class="context-label">Aplicación</span><strong>${escapeHTML(app?.name || "Sin seleccionar")}</strong><small>${escapeHTML(app?.repository || "Repositorio pendiente")}</small></div><div><span class="context-label">Estado del aviso</span>${item ? statusBadge(item.status) : badge("Sin seleccionar")}</div><div><span class="context-label">Exposición</span>${item ? exposureBadge(item.exposure) : badge("Indeterminada")}</div><div><span class="context-label">Capa de datos</span><span>${escapeHTML(ctx?.data_layer || "local")}${ctx?.sponsor_data_layer_verified ? " · Zetaris verificado" : ""}</span></div></div>`;
  const evidence = `<section class="case-block"><div class="case-block-heading"><h3>${icon("search")}Evidencia y contexto</h3>${badge(evidenceRows.length ? `${evidenceRows.length} registros` : "Sin corroborar", evidenceRows.length ? "green" : "sand")}</div><div class="case-block-body">${item ? `<p>${escapeHTML(item.description)}</p><div class="source-reference"><span class="source-icon">↗</span><div><small>Referencia aportada</small><a href="${escapeHTML(item.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.source_url)}</a></div></div>${evidenceRows.length ? `<ul class="timeline">${evidenceRows.slice(0, 6).map((row) => `<li>${escapeHTML(row.source || "fuente")} · ${escapeHTML(row.source_identifier || "")}<small>${escapeHTML((row.excerpt || "").slice(0, 180))}</small></li>`).join("")}</ul>` : ""}` : '<p>Selecciona un aviso para reunir aquí fuentes, descripción y datos de la aplicación.</p>'}<p class="inline-pending">Una coincidencia de versión no confirma un compromiso.</p></div></section>`;
  const exposure = `<section class="case-block"><div class="case-block-heading"><h3>${icon("check")}Evaluación de exposición</h3>${item ? exposureBadge(item.exposure) : badge("Sin evaluar")}</div><div class="case-block-body"><div class="exposure-checks">${(findings.length ? findings.slice(0, 6).map((finding) => `<div><span>${escapeHTML(finding.package_name || "componente")} ${escapeHTML(finding.resolved_version || "")}</span><span>${escapeHTML(finding.exposure || "undetermined")}</span></div>`) : ["Versión afectada", "Presencia en el entorno", "Despliegue histórico", "Condiciones de explotación"].map((label) => `<div><span>${label}</span><span>Sin evidencia</span></div>`)).join("")}</div><p class="inline-pending">H-MEM reinyecta contexto y no asigna exposición. ${memory?.available ? "Recall disponible." : "Sin recall todavía."}</p></div></section>`;
  const planRow = ctx?.plans?.[0];
  const patchRow = ctx?.patches?.[0];
  const validationRow = ctx?.validations?.[0];
  const approvalRow = (ctx?.approvals || []).find((row) => row.valid) || ctx?.approvals?.[0];
  const planPayload = planRow?.payload || {};
  const patchPayload = patchRow?.payload || {};
  const validationPayload = validationRow?.payload || {};
  const plan = responseStage("01", "Plan de respuesta", "Acción, evidencia, compatibilidad, validación y reversión.", planRow ? `<div class="stage-placeholders"><div><span>Acción</span><p>${escapeHTML(planPayload.action || "—")}</p></div><div><span>Paquetes</span><p>${escapeHTML((planPayload.packages || []).join(", ") || "Ninguno")}</p></div><div><span>Reversión</span><p>${escapeHTML(planPayload.rollback || "—")}</p></div></div><p>${escapeHTML(planPayload.justification || "")}</p><p class="inline-pending">${escapeHTML(planPayload.compromise_follow_up || "")}</p>` : `<div class="stage-placeholders"><div><span>Estrategia</span><p>Sin recomendación hasta evaluar la exposición.</p></div><div><span>Compatibilidad</span><p>Sin análisis registrado.</p></div><div><span>Reversión</span><p>Se definirá junto con la propuesta.</p></div></div>`, planRow ? String(planPayload.action || "Listo") : "Pendiente");
  const patch = responseStage("02", "Cambio propuesto", "Diff aislado. El merge permanece prohibido.", patchRow ? `<div class="diff-scaffold"><div class="diff-file-list">${icon("cases")}<span>${escapeHTML((patchPayload.files || []).join(", ") || "Sin archivos")}</span></div><pre class="code-panel">${escapeHTML(patchPayload.diff || patchPayload.note || "")}</pre></div><div class="stage-footer"><span>${escapeHTML(patchPayload.note || "Diff etiquetado")}</span>${button("Intentar merge", "forbid-merge", "lock", false, false, "RF-37: el Guardián rechaza merge, despliegue y secretos.")}</div>` : `<div class="diff-scaffold"><div class="diff-file-list">${icon("cases")}<span>Sin archivos modificados</span></div><div class="diff-empty">${icon("patch")}<span>El diff aparece cuando el Parcheador prepara un cambio aislado.</span></div></div><div class="stage-footer"><span>No se publica un PR en el MVP</span>${button("Intentar merge", "forbid-merge", "lock", false, !item)}</div>`, patchRow ? "Aislado" : "Pendiente");
  const validation = responseStage("03", "Validación", "Una herramienta ausente no aprueba.", `<div class="validation-checks">${(validationPayload.results || [["Pruebas funcionales", "Instalación y pruebas del proyecto"], ["Syft", "Inventario actualizado"], ["Trivy", "Análisis de dependencias"], ["OSV-Scanner", "Contraste de avisos"]].map(([name, detail]) => ({ tool: name, reason: detail, status: "not_executed" }))).map((row) => `<div><span class="validation-icon">${icon("check")}</span><div><strong>${escapeHTML(row.tool || row[0] || "herramienta")}</strong><small>${escapeHTML(row.reason || row[1] || "")}</small></div>${badge(row.status === "not_executed" ? "No ejecutada" : String(row.status || "Pendiente"))}</div>`).join("")}</div>`, validationPayload.overall || "Pendiente");
  const approval = responseStage("04", "Revisión y aprobación", "Una decisión humana sobre un artefacto concreto.", `<div class="approval-summary"><p>${approvalRow ? `${escapeHTML(approvalRow.decision)} · ${escapeHTML(approvalRow.artifact_kind || "plan")}. ${escapeHTML(approvalRow.justification || "")}` : "Aprueba el plan etiquetado. Si el diff cambia, la aprobación anterior deja de valer. El merge sigue prohibido."}</p><div class="actions">${button("Cerrar caso", "close-case", "", false, !item)}${button("Aprobar plan", "approve-plan", "approval", true, !planRow)}${button("Intentar merge", "forbid-merge", "lock", false, !item)}</div></div>`, approvalRow ? String(approvalRow.decision) : "Pendiente");
  const runPanel = `<section class="case-block"><div class="case-block-heading"><h3>${icon("layers")}Corrida de investigación</h3>${latestRun ? badge(latestRun.status) : badge("Sin corrida", "sand")}</div><div class="case-block-body"><p>${latestRun ? `Etapa ${escapeHTML(String(latestRun.stage))} · intentos ${escapeHTML(String(latestRun.attempts))}/${escapeHTML(String(latestRun.max_attempts))}` : "Inventario → fuentes → correlación. Una etapa por avance. La crítica no cambia la exposición."}</p><div class="case-actions">${button("Actualizar inventario", "refresh-inventory", "refresh", false, !item)}${button("Iniciar corrida", "start-run", "plus", true, !item)}${button("Avanzar etapa", "advance-run", "arrow", false, !latestRun)}${button("Pausar", "pause-run", "clock", false, !latestRun)}${button("Cancelar", "cancel-run", "", false, !latestRun)}${button("Componer plan", "compose-plan", "patch", false, !assessments.length)}${button("Preparar diff", "prepare-patch", "patch", false, !assessments.length)}${button("Validar", "validate-patch", "check", false, !assessments.length)}${button("Aprobar plan", "approve-plan", "approval", false, !assessments.length)}${button("Síntesis", "synthesis", "signal", false, !assessments.length)}${button("Exportar reporte", "export-report", "download", false, !item)}${button("Cerrar caso", "close-case", "", false, !item)}</div>${runs.length ? `<ul class="timeline">${runs.slice(0, 4).map((run) => `<li>${escapeHTML(run.status)} · ${escapeHTML(String(run.stage))}<small>${escapeHTML(date(run.updated_at || run.started_at))}</small></li>`).join("")}</ul>` : ""}</div></section>`;
  const memoryPanel = `<section class="case-block"><div class="case-block-heading"><h3>${icon("info")}H-MEM y crítica</h3>${badge(memory?.available ? "Recall" : "Sin recall", memory?.available ? "green" : "sand")}</div><div class="case-block-body"><p>${escapeHTML((memory?.context || "El Engine reinyecta evidencia previa cuando hay recall. No asigna exposición.").slice(0, 400))}</p>${critique ? `<p><strong>Crítica ${escapeHTML(critique.status)}</strong> ${escapeHTML((critique.evaluator || critique.reason || "").slice(0, 280))}</p>` : "<p class=\"inline-pending\">La crítica planner/evaluator se omite si Nightshift no está configurado.</p>"}</div></section>`;
  const history = `<section class="case-block history-block"><div class="case-block-heading"><h3>${icon("clock")}Historial y trazabilidad</h3>${badge(runs.length ? "Corridas" : "Consulta parcial")}</div><div class="case-block-body">${item ? `<ul class="timeline"><li>Aviso registrado<small>${escapeHTML(date(item.created_at))} · dato persistido</small></li>${latestRun ? `<li>Última corrida ${escapeHTML(latestRun.status)}<small>${escapeHTML(date(latestRun.updated_at))}</small></li>` : ""}</ul>` : '<p>Las acciones aparecerán aquí cuando exista una investigación.</p>'}${state.preview && item && state.preview.case_id === item.id ? `<details class="preview-details"><summary>Resultado de la vista previa</summary><p>El flujo de ejemplo no sustituye las corridas reales.</p><pre class="code-panel">${escapeHTML(JSON.stringify(state.preview, null, 2))}</pre></details>` : ""}</div></section>`;
  const actions = item ? `<div class="page-actions">${button("Actualizar", "refresh", "refresh")}${button("Nueva investigación", "new-case", "plus", true)}</div>` : button("Nueva investigación", "new-case", "plus", true);
  const crewLog = `<section class="case-block history-block"><div class="case-block-heading"><h3>${icon("layers")}Actos de agentes</h3>${badge((ctx?.agents || []).length ? String(ctx.agents.length) : "0")}</div><div class="case-block-body">${agentTimeline(ctx?.agents || [])}</div></section>`;
  return heading("Investigación con tripulación", "Cada acto tiene responsable, herramienta y decisión. El merge sigue prohibido.", actions) + operationViews() + `<div class="operations-layout">${queue}<article class="case-workspace"><div class="case-workspace-heading"><div><span class="case-eyebrow">INVESTIGACIÓN SELECCIONADA</span><h2>${escapeHTML(item?.title || "Elige una investigación para comenzar")}</h2></div>${item ? `<button type="button" class="button small" data-action="preview" data-id="${escapeHTML(item.id)}">${icon("signal")}Vista previa</button>` : badge("Sin seleccionar")}</div>${context}<div class="case-intelligence-grid">${evidence}${exposure}</div><div class="case-intelligence-grid">${runPanel}${memoryPanel}</div>${crewLog}<div class="response-flow-heading"><h2>Flujo de respuesta</h2><span>El PR no se publica en el MVP</span></div><div class="response-flow">${plan}${patch}${validation}${approval}</div>${history}</article></div>`;
}
function agentsPage() {
  const crew = state.crew || [];
  const roster = crew.length ? `<div class="integration-grid">${crew.map((agent) => `<article class="integration-card"><div class="integration-card-header"><span class="integration-symbol">${escapeHTML(agent.id.slice(0, 2).toUpperCase())}</span><div><h3>${escapeHTML(agent.name)}</h3><small>${escapeHTML(agent.role)}</small></div></div><p>${escapeHTML(agent.mission)}</p><p><strong>Decide:</strong> ${escapeHTML(agent.decides)}</p><p><strong>Nunca:</strong> ${escapeHTML(agent.never)}</p><div class="integration-card-footer">${(agent.tools || []).map((tool) => badge(tool)).join(" ")}</div></article>`).join("")}</div>` : empty("Cargando tripulación", "El roster público no requiere token. Reintenta si la API aún arranca.", "layers", button("Actualizar", "refresh", "refresh"));
  return heading("Tripulación", "Responsabilidades lógicas, no ocho procesos. El SRS permite compartir servicios si se conservan permisos y trazas.", button("Correr demo de agentes", "demo-run", "signal", true)) +
    note("Los mocks están etiquetados.", "La demo no contacta Nightshift, Zetaris ni NVIDIA. H-MEM y la correlación npm sí son reales.") +
    roster +
    panel("Actividad en vivo", agentTimeline(state.activity || []), badge(state.activity?.length ? String(state.activity.length) : "0"), "Cada acto tiene agente, etapa, decisión y marca de tiempo. La bitácora es de solo adición.");
}
function flowPanel() {
  const steps = [["Detección", "Fuentes y avisos", "signal"], ["Investigación", "Evidencia y exposición", "search"], ["Remediación", "Plan y propuesta de cambio", "patch"], ["Validación", "Pruebas y análisis", "check"], ["Revisión humana", "Decisión y entrega del PR", "approval"]];
  return panel("Flujo de respuesta", `<ol class="flow-list">${steps.map(([name, sub, glyph]) => `<li><span class="flow-step">${icon(glyph)}</span><div><strong>${name}</strong><small>${sub}</small></div></li>`).join("")}</ol><div class="aside-note">${icon("lock")}Warden orquesta. El Árbitro clasifica. Nightshift, si está presente, solo propone. El merge está prohibido.</div>`, badge("Agentes"));
}
function listToolbar(kind) { return `<div class="toolbar"><label class="search-field" for="list-search">${icon("search")}<input id="list-search" type="search" placeholder="${kind === "applications" ? "Buscar aplicación o repositorio" : "Buscar por título de investigación"}" value="${escapeHTML(state.search)}" aria-label="Buscar ${kind === "applications" ? "aplicaciones" : "investigaciones"}"></label><div class="filters"><span class="badge">${kind === "applications" ? "Node.js / npm" : "Todos los avisos"}</span></div></div>`; }
function applicationsPage(id, tab) {
  if (id) return applicationDetail(id, tab);
  const rows = state.applications?.filter((item) => `${item.name} ${item.repository}`.toLowerCase().includes(state.search.toLowerCase()));
  return heading("Aplicaciones", "El contexto tecnológico que conecta cada amenaza con tu entorno.", button("Registrar aplicación", "new-app", "plus", true)) +
    panel("Repositorios del espacio de trabajo", listToolbar("applications") + (rows?.length ? table(["Aplicación", "Ecosistema", "Inventario", ""], rows.map((item) => `<tr><td><button class="row-link" data-action="app-detail" data-id="${escapeHTML(item.id)}">${escapeHTML(item.name)}</button><small>${escapeHTML(item.repository)}</small></td><td>${badge("npm")}</td><td>${badge("Pendiente")}</td><td class="row-arrow">↗</td></tr>`).join("")) : state.search && state.applications?.length ? empty("Sin coincidencias", "Prueba con otro nombre o repositorio.", "search") : accessEmpty("applications"))) +
    `<div class="feature-columns"><div class="feature-description"><h3>Inventario por versión</h3><p>Dependencias directas y transitivas vinculadas a un commit verificable.</p></div><div class="feature-description"><h3>Contexto de despliegue</h3><p>Entornos e historial para investigar exposiciones pasadas.</p></div><div class="feature-description"><h3>Cobertura explícita</h3><p>Inventarios parciales o desactualizados se mostrarán como tales.</p></div></div>`;
}
function tabs(items, selected, prefix) { return `<nav class="tabs" aria-label="Secciones del detalle">${items.map(([key, label]) => `<a class="tab" href="#${prefix}/${key}"${selected === key ? ' aria-current="page"' : ""}>${label}</a>`).join("")}</nav>`; }
function applicationDetail(id, tab) {
  const app = state.applications?.find((item) => item.id === id);
  if (!app) return heading("Detalle de aplicación", "Selecciona una aplicación registrada para ver su contexto.") + panel("Aplicación no disponible", accessEmpty("applications"));
  const selected = ["overview", "inventory", "deployments"].includes(tab) ? tab : "overview";
  let body = "";
  if (selected === "overview") body = panel("Información de la aplicación", `<div class="section-body"><dl class="properties"><dt>Nombre</dt><dd>${escapeHTML(app.name)}</dd><dt>Repositorio</dt><dd>${escapeHTML(app.repository)}</dd><dt>Ecosistema</dt><dd>Node.js / npm</dd><dt>Registro</dt><dd>${escapeHTML(date(app.created_at))}</dd><dt>Inventario</dt><dd>${badge(state.snapshots.length ? `${state.snapshots.length} snapshot${state.snapshots.length === 1 ? "" : "s"}` : "Sin generar", state.snapshots.length ? "green" : "sand")}</dd><dt>Despliegues</dt><dd>Sin datos importados</dd></dl></div>`);
  if (selected === "inventory") {
    const snapshots = state.snapshots || [];
    body = snapshots.length
      ? panel("Componentes y dependencias", table(["Commit", "Observado", "Advertencias"], snapshots.map((row) => `<tr><td><code>${escapeHTML((row.commit_ref || row.commit_sha || "").slice(0, 12))}</code></td><td>${escapeHTML(date(row.observed_at))}</td><td>${badge(Array.isArray(row.warnings) && row.warnings.length ? String(row.warnings.length) : "Ninguna")}</td></tr>`).join("")), button("Actualizar inventario", "refresh-inventory", "refresh"), "El snapshot se resuelve por GitHub. Syft real sigue pendiente.")
      : panel("Componentes y dependencias", empty("El inventario está por construir", "Resuelve el lockfile del commit para correlacionar versiones.", "layers", button("Generar inventario", "refresh-inventory", "refresh"), true), badge("Pendiente"), "Syft real sigue pendiente; este snapshot no afirma un SBOM de contenedor.");
  }
  if (selected === "deployments") body = panel("Historial de despliegues", empty("Sin despliegues importados", "Cada registro identificará entorno, artefacto, periodo y fuente para evaluar exposición histórica.", "clock", button("Importar despliegues", "none", "download", false, true, "La importación histórica está pendiente."), true), badge("Pendiente"));
  return `<a class="back-link" href="#applications">${icon("back")}Todas las aplicaciones</a>` + heading(app.name, app.repository, button("Generar inventario", "refresh-inventory", "refresh")) + tabs([["overview", "General"], ["inventory", "Inventario"], ["deployments", "Despliegues"]], selected, `applications/${escapeHTML(id)}`) + body;
}
function integrationsPage() {
  const rows = CATALOG.filter((item) => state.filter === "all" || (state.filter === "sources" ? item.kind === "source" : state.filter === "tools" ? ["scanner", "inventory"].includes(item.kind) : ["model", "model-access", "research", "data", "engineering", "engine"].includes(item.kind)));
  const scopes = { mvp: "MVP", hackathon: "Requerida por hackathon", candidate: "Candidata", conditional: "Condicional" };
  return heading("Integraciones", "Fuentes, herramientas y modelos que darán contexto a cada investigación.", button("Actualizar estado", "refresh", "refresh")) +
    note("Configuración no es verificación.", "Una credencial o URL solo marca configuración. Nightshift, Zetaris y H-MEM se comprueban con la operación nombrada, no con la presencia del secreto.") +
    `<div class="tabs" aria-label="Filtrar integraciones">${[["all", "Todas"], ["sources", "Inteligencia"], ["tools", "Análisis"], ["models", "Modelos y servicios"]].map(([key, label]) => `<button class="tab${state.filter === key ? " active" : ""}" type="button" data-action="integration-filter" data-filter="${key}" aria-pressed="${state.filter === key}">${label}</button>`).join("")}</div><div class="integration-grid">${rows.map((item) => {
      const live = state.integrations?.find((entry) => entry.id === item.id);
      const verified = live?.verified === true;
      const status = live?.status || item.status;
      return `<article class="integration-card"><div class="integration-card-header"><span class="integration-symbol">${item.mark}</span><div><h3>${item.name}</h3><small>${scopes[item.scope] || item.scope}</small></div></div><p>${item.description}</p><div class="integration-card-footer">${badge(verified ? "Comprobado" : status === "implemented_unverified" ? "Conectado, no verificado" : "Pendiente", verified ? "green" : "sand")}<span class="muted">${live?.verified_operation ? escapeHTML(live.verified_operation) : live?.auth?.configured ? "Configurado" : live?.auth?.mode === "none" ? "Sin credencial" : "Sin verificar"}</span></div>${["meterless", "zetaris", "hmem"].includes(item.id) ? `<div class="case-actions"><button type="button" class="button" data-action="check-integration" data-id="${escapeHTML(item.id)}">${icon("check")}Comprobar</button></div>` : ""}</article>`;
    }).join("")}</div>`;
}
function settingRow(name, description, value) { return `<div class="settings-row"><div><h3>${escapeHTML(name)}</h3><p>${escapeHTML(description)}</p></div><div class="setting-value">${value}</div></div>`; }
function settingsPage() {
  const values = {
    general: [settingRow("Espacio de trabajo", "Una organización para la primera versión del producto.", "Entorno local"), settingRow("Ecosistema inicial", "Aplicaciones y dependencias admitidas en el MVP.", "Node.js / npm"), settingRow("Conexión", "Token de desarrollo guardado únicamente en memoria.", button(state.authenticated ? "Administrar" : "Conectar", "connect", "plug"))],
    access: [settingRow("Sesión de desarrollo", "Acceso local mediante un token compartido.", state.authenticated ? badge("Activa", "green") : badge("Sin conexión")), settingRow("Usuarios y roles", "Administrador, analista, desarrollador, aprobador y auditor.", badge("Pendiente")), settingRow("Permisos por proyecto", "Autorización de datos y acciones según el ámbito asignado.", badge("Pendiente"))],
    policy: [settingRow("Supervisión humana", "Las propuestas sensibles requerirán autorización específica.", "Definida en el SRS"), settingRow("Presupuestos de ejecución", "Límites de tiempo, intentos y solicitudes a modelos.", badge("Por implementar")), settingRow("Acciones de producción", "Merge, despliegue y secretos reales están fuera del MVP.", "Excluidas")],
    data: [settingRow("Base de datos", "Persistencia de aplicaciones e investigaciones.", state.database ? badge("Disponible", "green") : badge("Sin conexión", "sand")), settingRow("Retención", "Política de conservación y eliminación de datos y artefactos.", badge("Por definir")), settingRow("Respaldo y restauración", "Procedimientos operativos y evidencia de recuperación.", badge("Pendiente"))],
  };
  return heading("Configuración", "Preferencias, acceso y políticas del espacio de trabajo.") + `<div class="settings-layout"><nav class="settings-nav" aria-label="Categorías de configuración">${[["general", "General"], ["access", "Acceso y roles"], ["policy", "Autonomía y límites"], ["data", "Datos y retención"]].map(([key, label]) => `<button type="button" class="${state.settingsTab === key ? "active" : ""}" data-action="settings-tab" data-tab="${key}" aria-pressed="${state.settingsTab === key}">${label}</button>`).join("")}</nav>${panel("Configuración del espacio", `<div class="section-body">${values[state.settingsTab].join("")}</div>`, badge("Desarrollo"))}</div>`;
}
function render() {
  const current = route();
  renderNavigation(); renderChrome();
  const views = { overview, agents: agentsPage, applications: () => applicationsPage(current.id, current.tab), integrations: integrationsPage, settings: settingsPage };
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
  catch (error) { throw new Error(error.name === "TimeoutError" ? "La solicitud tardó demasiado. Vuelve a comprobar la conexión." : "No se pudo contactar con la API local."); }
  if (!response.ok) {
    const messages = { 401: "El token no es válido. Revisa la conexión del entorno.", 403: "La tripulación rechazó esa acción. Merge, despliegue y secretos están prohibidos.", 404: "El registro solicitado ya no está disponible.", 409: "Completa la etapa anterior antes de continuar.", 422: "Revisa los campos. Usa organización/repositorio y una URL http o https válida.", 503: "El servicio no está listo. Comprueba la base de datos y las migraciones." };
    const error = new Error(messages[response.status] || `La solicitud falló (${response.status}).`); error.status = response.status; throw error;
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
    const current = selectedInvestigation();
    if (current) await loadCaseExtras(current, sequence);
    if (!silent) announce(state.appError || state.caseError ? "Conexión parcial: los adaptadores se consultaron, pero faltan los datos del entorno." : "Datos actualizados.", state.appError ? "" : "success");
  } catch (error) {
    if (sequence !== refreshSequence) return;
    if (error.status === 401) { state.authenticated = false; state.token = ""; state.applications = null; state.investigations = null; state.integrations = null; state.context = null; state.snapshots = []; }
    if (!silent) announce(error.message, "error");
    throw error;
  } finally { if (sequence === refreshSequence) { state.loading = false; render(); } }
}
function openModal(title, content) { $("modal-content").innerHTML = `<div class="dialog-header"><h2 id="modal-title">${title}</h2><button class="dialog-close" type="button" data-action="close-modal" aria-label="Cerrar diálogo">×</button></div><div class="dialog-body">${content}</div>`; if (!$("modal").open) $("modal").showModal(); }
function field(id, label, input, hint = "") { return `<div class="field"><label for="${id}">${label}</label>${input}${hint ? `<p class="field-hint" id="${id}-hint">${hint}</p>` : ""}</div>`; }
function formActions(text) { return `<p id="form-error" class="form-error" role="alert" hidden></p><div class="dialog-actions">${button("Cancelar", "close-modal")}<button class="button primary" type="submit">${text}</button></div>`; }
function connectionDialog() {
  openModal("Conectar tu entorno", `<p>Usa el token configurado para este entorno local. Se conserva en memoria hasta cerrar o recargar la página.</p><div class="connection-summary"><span>API</span>${badge(state.api ? "Disponible" : "No disponible", state.api ? "green" : "sand")}</div><div class="connection-summary"><span>Base de datos</span>${badge(state.database ? "Disponible" : "Pendiente", state.database ? "green" : "sand")}</div><hr><form id="connect-form" method="post" action="/api/integrations">${field("connection-token", "Token de desarrollo (obligatorio)", '<div class="password-row"><input id="connection-token" name="token" type="password" required autocomplete="off" spellcheck="false" aria-describedby="connection-token-hint"><button class="button" type="button" data-action="toggle-token" aria-pressed="false">Mostrar</button></div>', "Corresponde a WARDEN_API_TOKEN en tu configuración local.")}${formActions("Conectar")}</form>${state.authenticated ? `<hr>${button("Desconectar esta sesión", "logout")}` : ""}`);
}
function requireWritable() {
  if (!state.authenticated) { connectionDialog(); return false; }
  if (!state.database) { announce("La base de datos no está lista. Reconecta el entorno para guardar registros.", "error"); return false; }
  return true;
}
function newAppDialog() {
  if (!requireWritable()) return;
  openModal("Registrar aplicación", `<p>Agrega un repositorio para preparar el contexto de seguridad de tu aplicación.</p><form id="application-form" method="post" action="/api/applications">${field("application-name", "Nombre (obligatorio)", '<input id="application-name" name="name" required maxlength="120" autocomplete="off">')}${field("application-repository", "Repositorio GitHub (obligatorio)", '<input id="application-repository" name="repository" required maxlength="201" placeholder="organización/repositorio" autocapitalize="off" spellcheck="false" aria-describedby="application-repository-hint">', "Por ahora se registra la referencia. El inventario está pendiente.")}${formActions("Registrar aplicación")}</form>`);
}
function newCaseDialog() {
  if (!requireWritable()) return;
  if (!state.applications?.length) { navigate("applications"); announce("Registra una aplicación antes de crear una investigación."); return; }
  openModal("Nueva investigación", `<p>Relaciona un aviso de seguridad con una aplicación. La exposición permanecerá indeterminada hasta evaluarse.</p><form id="investigation-form" method="post" action="/api/investigations">${field("case-application", "Aplicación (obligatoria)", `<select id="case-application" name="application_id" required><option value="">Selecciona una aplicación</option>${state.applications.map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)}</option>`).join("")}</select>`)}${field("case-title", "Título (obligatorio)", '<input id="case-title" name="title" required maxlength="200">')}${field("case-source", "URL de la fuente (obligatoria)", '<input id="case-source" name="source_url" type="url" required placeholder="https://…" autocapitalize="off" spellcheck="false">')}${field("case-description", "Descripción (obligatoria)", '<textarea id="case-description" name="description" required maxlength="10000" rows="3"></textarea>')}${formActions("Registrar aviso")}</form>`);
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
  if (!item) { state.context = null; state.snapshots = []; return; }
  const results = await Promise.allSettled([
    api(`/api/investigations/${item.id}/context`),
    api(`/api/applications/${item.application_id}/inventory`),
  ]);
  if (sequence !== refreshSequence) return;
  state.context = results[0].status === "fulfilled" ? results[0].value : null;
  state.snapshots = results[1].status === "fulfilled" ? (results[1].value.snapshots || []) : [];
}
function helpDialog() { openModal("Los agentes investigan. Tú decides.", `<p>Once roles lógicos colaboran en una sola orquestación. El Árbitro clasifica con reglas npm. Nightshift, si existe, solo propone. El Guardián registra la decisión humana y rechaza el merge.</p>${note("Demo en 3 minutos.", "Conecta el entorno y pulsa Correr demo de agentes. Verás inventario, evidencia, exposición, plan, diff etiquetado y la línea de tiempo.")}${note("Sin acreditar patrocinadores.", "La demo no llama a Nightshift, Zetaris ni NVIDIA. H-MEM y la correlación son código real.")}<div class="dialog-actions"><a class="button" href="/docs" target="_blank" rel="noopener">Documentación API ↗</a>${button("Entendido", "close-modal", "", true)}</div>`); }

async function performAction(action, target) {
  if (NAV.some((item) => item[0] === action)) { navigate(action); return; }
  if (action === "connect") connectionDialog();
  if (action === "help") helpDialog();
  if (action === "close-modal") $("modal").close();
  if (action === "new-app") newAppDialog();
  if (action === "new-case") newCaseDialog();
  if (action === "refresh") { try { await refreshData(); } catch { /* refreshData announces the error. */ } }
  if (action === "case-detail") { state.selectedCase = target.dataset.id; state.operationView = "case"; const selected = (state.investigations || []).find((entry) => entry.id === state.selectedCase); if (selected) await loadCaseExtras(selected); navigate("overview"); }
  if (action === "refresh-inventory") {
    const item = selectedInvestigation();
    const appId = route().page === "applications" && route().id ? route().id : item?.application_id;
    if (!requireWritable()) return;
    if (!appId) { announce("Abre una aplicación para actualizar su inventario.", "error"); return; }
    await api(`/api/applications/${appId}/inventory/refresh`, { method: "POST", body: JSON.stringify({}) });
    announce("Inventario actualizado.", "success");
    await refreshData(true);
  }
  if (action === "start-run") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const snapshot = state.snapshots[0];
    if (!snapshot) { announce("Genera un inventario antes de iniciar la corrida.", "error"); return; }
    const match = `${item.title} ${item.source_url} ${item.description}`.match(ADVISORY);
    if (!match) { announce("El aviso debe incluir un GHSA o CVE para iniciar la corrida.", "error"); return; }
    const run = await api(`/api/investigations/${item.id}/runs`, { method: "POST", body: JSON.stringify({ snapshot_id: snapshot.id, advisory_identifier: match[0].toUpperCase().startsWith("CVE") ? match[0].toUpperCase() : match[0], request_key: crypto.randomUUID() }) });
    announce("Corrida creada. Avanza cada etapa por separado.", "success");
    await refreshData(true);
    state.selectedCase = item.id;
  }
  if (action === "advance-run") {
    const item = selectedInvestigation();
    const run = state.context?.runs?.[0];
    if (!item || !run || !requireWritable()) return;
    const result = await api(`/api/investigations/${item.id}/runs/${run.id}/advance`, { method: "POST" });
    announce(`Etapa ${result.stage || run.stage}: ${result.status}.`, result.status === "requires_intervention" ? "error" : "success");
    await refreshData(true);
  }
  if (action === "synthesis") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const result = await api(`/api/investigations/${item.id}/synthesis`, { method: "POST" });
    announce(result.nightshift_deployment_verified ? "Síntesis de Nightshift registrada." : "Propuesta registrada. Nightshift no queda verificado solo por este envío.", "success");
    await refreshData(true);
  }
  if (action === "check-integration") {
    if (!requireWritable()) return;
    const result = await api(`/api/integrations/${target.dataset.id}/check`, { method: "POST" });
    announce(`${target.dataset.id}: ${result.status}${result.verified ? " (comprobado)" : ""}.`, result.verified ? "success" : "");
    await refreshData(true);
  }
  if (action === "demo-run") {
    if (!requireWritable()) return;
    announce("La tripulación está trabajando con fuentes sintéticas…");
    const result = await api("/api/demo/run", { method: "POST" });
    state.selectedCase = result.investigation_id;
    state.operationView = "case";
    announce("Demo lista. Los agentes actuaron; Nightshift no fue contactado.", "success");
    await refreshData(true);
    state.selectedCase = result.investigation_id;
    state.operationView = "case";
    navigate("overview");
  }
  if (action === "pause-run" || action === "cancel-run") {
    const item = selectedInvestigation();
    const run = state.context?.runs?.[0];
    if (!item || !run || !requireWritable()) return;
    const verb = action === "pause-run" ? "pause" : "cancel";
    await api(`/api/investigations/${item.id}/runs/${run.id}/${verb}`, { method: "POST" });
    announce(verb === "pause" ? "Warden pausó la corrida." : "Warden canceló nuevas etapas.", "success");
    await refreshData(true);
  }
  if (action === "close-case") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    openModal("Cerrar investigación", `<p>El cierre conserva evidencia y no fusiona código. Elige el resultado y justifica la decisión.</p><form id="close-form">${field("close-outcome", "Resultado", '<select id="close-outcome" name="outcome" required><option value="discarded">Descartada</option><option value="not_affected">No afectada</option><option value="risk_accepted">Riesgo aceptado</option><option value="cancelled">Cancelada</option></select>')}${field("close-justification", "Justificación (mínimo 10 caracteres)", '<textarea id="close-justification" name="justification" required minlength="10" maxlength="2000" rows="3">Cierre desde el centro de operaciones. El merge permanece prohibido.</textarea>')}${formActions("Cerrar caso")}</form>`);
  }
  if (action === "forbid-merge") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    try {
      await api(`/api/investigations/${item.id}/merge`, { method: "POST" });
    } catch (error) {
      announce(error.message, "error");
      await refreshData(true);
    }
  }
  if (action === "compose-plan" || action === "prepare-patch" || action === "validate-patch" || action === "approve-plan" || action === "export-report") {
    const item = selectedInvestigation();
    if (!item || !requireWritable()) return;
    const routes = {
      "compose-plan": ["/api/investigations/" + item.id + "/plan", { method: "POST" }],
      "prepare-patch": ["/api/investigations/" + item.id + "/patch", { method: "POST" }],
      "validate-patch": ["/api/investigations/" + item.id + "/validate", { method: "POST" }],
      "approve-plan": ["/api/investigations/" + item.id + "/approval", { method: "POST", body: JSON.stringify({ artifact_kind: "plan", decision: "approved", justification: "Demo review of the labeled plan artifact." }) }],
      "export-report": ["/api/investigations/" + item.id + "/report", { method: "GET" }],
    };
    const [path, options] = routes[action];
    const result = await api(path, options);
    if (action === "export-report") {
      openModal("Reporte exportable", `<pre class="code-panel">${escapeHTML(JSON.stringify(result, null, 2).slice(0, 8000))}</pre><div class="dialog-actions">${button("Cerrar", "close-modal", "", true)}</div>`);
    } else {
      announce(action === "approve-plan" ? "Aprobación humana registrada. El merge sigue prohibido." : "La tripulación registró el siguiente acto.", "success");
      await refreshData(true);
    }
  }
  if (action === "app-detail") {
    try {
      const inventory = await api(`/api/applications/${target.dataset.id}/inventory`);
      state.snapshots = inventory.snapshots || [];
    } catch { state.snapshots = []; }
    navigate(`applications/${target.dataset.id}`);
  }
  if (action === "settings-tab") { state.settingsTab = target.dataset.tab; render(); }
  if (action === "integration-filter") { state.filter = target.dataset.filter; render(); }
  if (action === "operation-view") { state.operationView = target.dataset.view; navigate("overview"); }
  if (action === "logout") { ++refreshSequence; state.token = ""; state.authenticated = false; state.applications = null; state.investigations = null; state.integrations = null; state.preview = null; state.appError = ""; state.caseError = ""; state.loading = false; $("modal").close(); render(); announce("Sesión local desconectada."); }
  if (action === "toggle-token") { const input = $("connection-token"); const visible = input.type === "password"; input.type = visible ? "text" : "password"; target.textContent = visible ? "Ocultar" : "Mostrar"; target.setAttribute("aria-pressed", String(visible)); }
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
    try { state.preview = await api(`/api/investigations/${target.dataset.id}/preview`, { method: "POST" }); state.selectedCase = target.dataset.id; state.operationView = "case"; navigate("overview"); announce("El flujo se detuvo en el inventario pendiente. No se ejecutaron cambios."); }
    catch (error) { announce(error.message, "error"); }
    finally { target.disabled = false; target.setAttribute("aria-busy", "false"); }
  }
}
document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (target && !target.disabled) performAction(target.dataset.action, target).catch((error) => announce(error.message, "error"));
  if (event.target.closest(".nav-item")) closeNavigation();
});
document.addEventListener("input", (event) => {
  if (event.target.validity?.valid) event.target.removeAttribute("aria-invalid");
  if (event.target.id === "list-search") {
    const input = event.target; state.search = input.value; const position = input.selectionStart; render();
    const replacement = $("list-search"); replacement.focus(); if (position !== null) replacement.setSelectionRange(position, position);
  }
});
document.addEventListener("invalid", (event) => { event.target.setAttribute("aria-invalid", "true"); }, true);
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!["connect-form", "application-form", "investigation-form", "close-form"].includes(form.id)) return;
  event.preventDefault();
  const payload = Object.fromEntries(new FormData(form));
  const submit = form.querySelector("button[type=submit]");
  const originalText = submit.textContent;
  submit.disabled = true; submit.textContent = "Guardando…"; form.setAttribute("aria-busy", "true"); form.dataset.state = "submitting";
  $("form-error").hidden = true;
  try {
    if (form.id === "connect-form") {
      state.token = payload.token; submit.textContent = "Conectando…";
      await refreshData(true); $("modal").close(); announce(state.database ? "Entorno conectado." : "API conectada. La base de datos aún no está lista.", state.database ? "success" : "");
    } else if (form.id === "close-form") {
      const item = selectedInvestigation();
      if (!item) throw new Error("Selecciona una investigación.");
      await api(`/api/investigations/${item.id}/close`, { method: "POST", body: JSON.stringify(payload) });
      $("modal").close(); await refreshData(true);
      announce("Caso cerrado. La evidencia se conserva y el merge sigue prohibido.", "success");
    } else {
      const endpoint = form.id === "application-form" ? "/api/applications" : "/api/investigations";
      const result = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
      $("modal").close(); await refreshData(true);
      if (form.id === "application-form") navigate(`applications/${result.id}`);
      else { state.selectedCase = result.id; state.operationView = "case"; navigate("overview"); }
      announce(form.id === "application-form" ? "Aplicación registrada." : "Aviso registrado. La exposición sigue indeterminada.", "success");
    }
  } catch (error) {
    const message = form.id === "connect-form" ? error.message : `${error.message} Si el envío perdió conexión, actualiza la lista antes de repetirlo.`;
    if ($("modal").open && $("form-error")) { $("form-error").textContent = message; $("form-error").hidden = false; }
    else announce(message, "error");
  } finally { submit.disabled = false; submit.textContent = originalText; form.setAttribute("aria-busy", "false"); form.dataset.state = "idle"; }
});
window.addEventListener("hashchange", () => {
  state.search = "";
  const current = route();
  if (current.page === "applications" && current.id && state.token) {
    api(`/api/applications/${current.id}/inventory`).then((inventory) => {
      state.snapshots = inventory.snapshots || [];
      render();
    }).catch(() => { render(); });
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
    state.activity = rows;
    const page = route().page;
    if (page === "overview" || page === "agents") render();
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
