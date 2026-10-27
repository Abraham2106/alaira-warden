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
  ["overview", "Centro de operaciones", "overview", "OPERACIÓN"], ["applications", "Aplicaciones", "apps"],
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
  ["meterless", "Meterless", "M", "model-access", "hackathon", "Acceso a modelos según el contrato del hackathon."],
  ["nvidia", "NVIDIA", "NV", "model", "candidate", "Análisis y síntesis técnica con evidencia verificable."],
  ["grok", "Grok / X", "G", "research", "conditional", "Investigación de reportes y publicaciones técnicas."],
  ["zetaris", "Zetaris", "Z", "data", "conditional", "Consulta e integración de información distribuida."],
  ["cursor", "Cursor", "C", "engineering", "conditional", "Automatización de cambios, sujeta a interfaz disponible."],
].map(([id, name, mark, kind, scope, description]) => ({ id, name, mark, kind, scope, description, verified: false, status: "not_implemented" }));
const state = { token: "", authenticated: false, api: false, database: false, applications: null, investigations: null, integrations: null, appError: "", caseError: "", loading: false, search: "", filter: "all", settingsTab: "general", operationView: "panorama", selectedCase: "", preview: null, updated: null };
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
function caseRows(rows) { return rows.map((item) => `<tr><td><button class="row-link" data-action="case-detail" data-id="${escapeHTML(item.id)}">${escapeHTML(item.title)}</button><small>${escapeHTML(state.applications?.find((app) => app.id === item.application_id)?.name || "Aplicación registrada")}</small></td><td>${badge("Por investigar", "sand")}</td><td>${badge("Indeterminada")}</td><td class="row-arrow">↗</td></tr>`).join(""); }
function accessEmpty(type = "investigations") {
  const isApp = type === "applications";
  if (state.loading) return `<div class="loading-line"></div>${empty("Cargando el entorno", "Consultando los datos disponibles…", "refresh")}`;
  const error = isApp ? state.appError : state.caseError;
  if (error) return empty("Datos no disponibles", "Revisa la conexión a la base de datos y vuelve a intentarlo.", "signal", button("Reintentar", "refresh", "refresh"));
  if (!state.authenticated) return empty(isApp ? "Conoce tu entorno" : "Tu próxima investigación empieza aquí", isApp ? "Conecta tu entorno para registrar aplicaciones y preparar su inventario." : "Conecta el entorno para reunir los avisos que requieren una revisión.", isApp ? "apps" : "cases", button("Conectar entorno", "connect", "plug", true));
  return empty(isApp ? "Agrega tu primera aplicación" : "Sin investigaciones registradas", isApp ? "Registra un repositorio para empezar a construir el contexto de seguridad." : "Registra un aviso manual y relaciónalo con una aplicación.", isApp ? "apps" : "cases", button(isApp ? "Registrar aplicación" : "Nueva investigación", isApp ? "new-app" : "new-case", "plus", true));
}
function panorama() {
  const cases = state.investigations;
  return heading("Centro de operaciones", "El entorno, las amenazas y su respuesta, reunidos en un mismo espacio.", button("Actualizar", "refresh", "refresh") + button("Nueva investigación", "new-case", "plus", true)) + operationViews() +
    `<div class="metrics">${metric("Aplicaciones registradas", count(state.applications), state.applications ? "En el espacio de trabajo" : "Conecta tu entorno", "apps")}${metric("Investigaciones", count(cases), cases ? "Avisos registrados" : "Sin datos del entorno", "cases")}${metric("Exposición confirmada", "—", '<span class="tiny-dot"></span>Correlación pendiente', "check")}${metric("Propuestas de corrección", "—", "Remediación pendiente", "patch")}</div>` +
    `<div class="content-grid"><div>${panel("Investigaciones recientes", cases?.length ? table(["Investigación", "Estado", "Exposición", ""], caseRows(cases.slice(0, 5))) : accessEmpty(), `<button type="button" class="text-link" data-action="operation-view" data-view="case">Abrir espacio de investigación ${icon("arrow")}</button>`, "Selecciona un aviso para ver evidencia, exposición y respuesta en conjunto.")}${panel("Actividad del entorno", empty("La trazabilidad empieza con una acción", "El historial de cada investigación reunirá las acciones y sus evidencias.", "clock"), badge("Consulta pendiente"))}</div><aside class="overview-aside">${flowPanel()}<section class="next-step"><div class="eyebrow">PRIMEROS PASOS</div><h3>El contexto empieza por tus aplicaciones.</h3><p>Registra tu repositorio y relaciona el primer aviso. El inventario y la correlación se incorporarán al flujo.</p>${button("Ver aplicaciones", "applications", "arrow")}</section></aside></div>` +
    `<div class="bottom-sources"><span>Fuentes de inteligencia</span>${CATALOG.slice(0, 4).map((item) => `<a href="#integrations" class="source-chip"><span class="source-icon">${item.mark}</span>${item.name}<span class="status-dot" title="Pendiente de implementar"></span></a>`).join("")}<a class="text-link" href="#integrations">Ver integraciones ${icon("arrow")}</a></div>`;
}
function operationViews() {
  return `<div class="operation-views"><div class="view-presets" aria-label="Vista del centro de operaciones"><button type="button" data-action="operation-view" data-view="panorama" class="view-preset${state.operationView === "panorama" ? " active" : ""}" aria-pressed="${state.operationView === "panorama"}">${icon("overview")}Panorama</button><button type="button" data-action="operation-view" data-view="case" class="view-preset${state.operationView === "case" ? " active" : ""}" aria-pressed="${state.operationView === "case"}">${icon("cases")}Investigación y respuesta</button></div><span class="view-range">${icon("clock")}Todo el historial</span></div>`;
}
function overview() { return state.operationView === "case" ? operationsCase() : panorama(); }
function responseStage(number, name, description, body, glyph) {
  return `<section class="response-stage"><div class="response-stage-heading"><span class="stage-number">${number}</span><div><h3>${name}</h3><p>${description}</p></div>${badge("Pendiente")}</div><div class="response-stage-content">${body}</div></section>`;
}
function operationsCase() {
  const rows = state.investigations || [];
  const item = rows.find((entry) => entry.id === state.selectedCase) || rows[0] || null;
  if (item) state.selectedCase = item.id;
  const app = item && state.applications?.find((entry) => entry.id === item.application_id);
  const queue = `<div class="case-queue"><div class="queue-heading"><h2>Investigaciones</h2>${badge(state.investigations === null ? "—" : String(rows.length))}</div>${state.loading ? '<div class="loading-line"></div>' : ""}${rows.length ? rows.map((entry) => `<button class="case-queue-item${item?.id === entry.id ? " selected" : ""}" data-action="case-detail" data-id="${escapeHTML(entry.id)}" type="button" aria-pressed="${item?.id === entry.id}"><span class="queue-item-icon">${icon("cases")}</span><span><strong>${escapeHTML(entry.title)}</strong><small>${escapeHTML(state.applications?.find((entryApp) => entryApp.id === entry.application_id)?.name || "Aplicación registrada")}</small><span class="queue-state">${badge("Por investigar", "sand")}</span></span></button>`).join("") : `<div class="queue-empty">${icon("cases")}<p>${state.authenticated ? "No hay investigaciones disponibles." : "Conecta el entorno para consultar los avisos."}</p>${button(state.authenticated ? "Nuevo aviso" : "Conectar", state.authenticated ? "new-case" : "connect", "plus")}</div>`}</div>`;
  const context = `<div class="case-context"><div><span class="context-label">Aplicación</span><strong>${escapeHTML(app?.name || "Sin seleccionar")}</strong><small>${escapeHTML(app?.repository || "Repositorio pendiente")}</small></div><div><span class="context-label">Estado del aviso</span>${item ? badge("Registrado", "sand") : badge("Sin seleccionar")}</div><div><span class="context-label">Exposición</span>${badge("Indeterminada")}</div><div><span class="context-label">Registro</span><span>${item ? escapeHTML(date(item.created_at)) : "—"}</span></div></div>`;
  const evidence = `<section class="case-block"><div class="case-block-heading"><h3>${icon("search")}Evidencia y contexto</h3>${badge("Sin corroborar", "sand")}</div><div class="case-block-body">${item ? `<p>${escapeHTML(item.description)}</p><div class="source-reference"><span class="source-icon">↗</span><div><small>Referencia aportada manualmente</small><a href="${escapeHTML(item.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.source_url)}</a></div></div>` : '<p>Selecciona un aviso para reunir aquí fuentes, descripción y datos de la aplicación.</p>'}<p class="inline-pending">La corroboración y las referencias adicionales están pendientes.</p></div></section>`;
  const exposure = `<section class="case-block"><div class="case-block-heading"><h3>${icon("check")}Evaluación de exposición</h3>${badge("Sin evaluar")}</div><div class="case-block-body"><div class="exposure-checks">${["Versión afectada", "Presencia en el entorno", "Despliegue histórico", "Condiciones de explotación"].map((label) => `<div><span>${label}</span><span>Sin evidencia</span></div>`).join("")}</div><p class="inline-pending">Una coincidencia de versión no confirma un compromiso.</p></div></section>`;
  const plan = responseStage("01", "Plan de respuesta", "Alternativas, compatibilidad y riesgo residual.", `<div class="stage-placeholders"><div><span>Estrategia</span><p>Sin recomendación hasta evaluar la exposición.</p></div><div><span>Compatibilidad</span><p>Sin análisis registrado.</p></div><div><span>Reversión</span><p>Se definirá junto con la propuesta.</p></div></div>`, "patch");
  const patch = responseStage("02", "Cambio propuesto", "Archivos, diff y versión exacta de la corrección.", `<div class="diff-scaffold"><div class="diff-file-list">${icon("cases")}<span>Sin archivos modificados</span></div><div class="diff-empty">${icon("patch")}<span>El diff aparecerá cuando exista una propuesta de corrección.</span></div></div><div class="stage-footer"><span>Commit y destino pendientes</span>${button("Ver pull request", "none", "arrow", false, true, "Todavía no existe una propuesta publicada.")}</div>`, "patch");
  const validation = responseStage("03", "Validación", "Pruebas y análisis vinculados al commit propuesto.", `<div class="validation-checks">${[["Pruebas funcionales", "Instalación y pruebas del proyecto"], ["Syft", "Inventario actualizado"], ["Trivy", "Análisis de dependencias"], ["OSV-Scanner", "Contraste de avisos"]].map(([name, detail]) => `<div><span class="validation-icon">${icon("check")}</span><div><strong>${name}</strong><small>${detail}</small></div>${badge("No ejecutada")}</div>`).join("")}</div>`, "check");
  const approval = responseStage("04", "Revisión y aprobación", "Una decisión humana sobre un artefacto concreto.", `<div class="approval-summary"><p>La revisión se habilitará al disponer de un plan, un diff y resultados de validación. Si cambia el artefacto, la aprobación deberá renovarse.</p><div class="actions">${button("Solicitar cambios", "none", "", false, true, "No hay una propuesta lista para revisar.")}${button("Aprobar propuesta", "none", "approval", true, true, "No hay una propuesta lista para revisar.")}</div></div>`, "approval");
  const history = `<section class="case-block history-block"><div class="case-block-heading"><h3>${icon("clock")}Historial y trazabilidad</h3>${badge("Consulta parcial")}</div><div class="case-block-body">${item ? `<ul class="timeline"><li>Aviso registrado manualmente<small>${escapeHTML(date(item.created_at))} · dato persistido</small></li></ul>` : '<p>Las acciones aparecerán aquí cuando exista una investigación.</p>'}<p class="inline-pending">La consulta de eventos adicionales está pendiente.</p>${state.preview && item && state.preview.case_id === item.id ? `<details class="preview-details"><summary>Resultado de la vista previa</summary><p>El flujo se detuvo ante los adaptadores pendientes, sin escanear ni modificar el caso.</p><pre class="code-panel">${escapeHTML(JSON.stringify(state.preview, null, 2))}</pre></details>` : ""}</div></section>`;
  return heading("Centro de operaciones", "Selecciona una investigación y sigue su evidencia, exposición y respuesta en conjunto.", button("Actualizar", "refresh", "refresh") + button("Nueva investigación", "new-case", "plus", true)) + operationViews() + `<div class="operations-layout">${queue}<article class="case-workspace"><div class="case-workspace-heading"><div><span class="case-eyebrow">INVESTIGACIÓN SELECCIONADA</span><h2>${escapeHTML(item?.title || "Elige una investigación para comenzar")}</h2></div>${item ? `<button type="button" class="button small" data-action="preview" data-id="${escapeHTML(item.id)}">${icon("signal")}Ver flujo inicial</button>` : badge("Sin seleccionar")}</div>${context}<div class="case-intelligence-grid">${evidence}${exposure}</div><div class="response-flow-heading"><h2>Flujo de respuesta</h2><span>De la estrategia a la revisión humana</span></div><div class="response-flow">${plan}${patch}${validation}${approval}</div>${history}</article></div>`;
}
function flowPanel() {
  const steps = [["Detección", "Fuentes y avisos", "signal"], ["Investigación", "Evidencia y exposición", "search"], ["Remediación", "Plan y propuesta de cambio", "patch"], ["Validación", "Pruebas y análisis", "check"], ["Revisión humana", "Decisión y entrega del PR", "approval"]];
  return panel("Flujo de respuesta", `<ol class="flow-list">${steps.map(([name, sub, glyph]) => `<li><span class="flow-step">${icon(glyph)}</span><div><strong>${name}</strong><small>${sub}</small></div></li>`).join("")}</ol><div class="aside-note">${icon("lock")}Las etapas avanzadas están pendientes. La vista previa no ejecuta cambios.</div>`, badge("MVP"));
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
  if (selected === "overview") body = panel("Información de la aplicación", `<div class="section-body"><dl class="properties"><dt>Nombre</dt><dd>${escapeHTML(app.name)}</dd><dt>Repositorio</dt><dd>${escapeHTML(app.repository)}</dd><dt>Ecosistema</dt><dd>Node.js / npm</dd><dt>Registro</dt><dd>${escapeHTML(date(app.created_at))}</dd><dt>Inventario</dt><dd>${badge("Sin generar")}</dd><dt>Despliegues</dt><dd>Sin datos importados</dd></dl></div>`);
  if (selected === "inventory") body = panel("Componentes y dependencias", empty("El inventario está por construir", "Aquí verás versiones resueltas, dependencias transitivas y su relación con un commit.", "layers", button("Generar inventario", "none", "refresh", false, true, "El adaptador de inventario está pendiente."), true), badge("Pendiente"), "Syft y el lockfile respaldarán la composición del software.");
  if (selected === "deployments") body = panel("Historial de despliegues", empty("Sin despliegues importados", "Cada registro identificará entorno, artefacto, periodo y fuente para evaluar exposición histórica.", "clock", button("Importar despliegues", "none", "download", false, true, "La importación histórica está pendiente."), true), badge("Pendiente"));
  return `<a class="back-link" href="#applications">${icon("back")}Todas las aplicaciones</a>` + heading(app.name, app.repository, button("Generar inventario", "none", "refresh", false, true, "El inventario no está implementado.")) + tabs([["overview", "General"], ["inventory", "Inventario"], ["deployments", "Despliegues"]], selected, `applications/${escapeHTML(id)}`) + body;
}
function integrationsPage() {
  const rows = CATALOG.filter((item) => state.filter === "all" || (state.filter === "sources" ? item.kind === "source" : state.filter === "tools" ? ["scanner", "inventory"].includes(item.kind) : ["model", "model-access", "research", "data", "engineering"].includes(item.kind)));
  const scopes = { mvp: "MVP", hackathon: "Requerida por hackathon", candidate: "Candidata", conditional: "Condicional" };
  return heading("Integraciones", "Fuentes, herramientas y modelos que darán contexto a cada investigación.", button("Actualizar estado", "refresh", "refresh")) +
    note("Conexiones pendientes.", "La presencia de una credencial solo indica configuración. Ningún adaptador está implementado o verificado todavía.") +
    `<div class="tabs" aria-label="Filtrar integraciones">${[["all", "Todas"], ["sources", "Inteligencia"], ["tools", "Análisis"], ["models", "Modelos y servicios"]].map(([key, label]) => `<button class="tab${state.filter === key ? " active" : ""}" type="button" data-action="integration-filter" data-filter="${key}" aria-pressed="${state.filter === key}">${label}</button>`).join("")}</div><div class="integration-grid">${rows.map((item) => {
      const live = state.integrations?.find((entry) => entry.id === item.id);
      return `<article class="integration-card"><div class="integration-card-header"><span class="integration-symbol">${item.mark}</span><div><h3>${item.name}</h3><small>${scopes[item.scope]}</small></div></div><p>${item.description}</p><div class="integration-card-footer">${badge("Pendiente", "sand")}<span class="muted">${live?.auth?.configured ? "Credencial configurada" : live?.auth?.mode === "none" ? "Sin credencial requerida" : "Sin verificar"}</span></div></article>`;
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
  const views = { overview, applications: () => applicationsPage(current.id, current.tab), integrations: integrationsPage, settings: settingsPage };
  $("view").innerHTML = views[current.page]();
  $("view").setAttribute("aria-busy", String(state.loading));
}

async function api(path, options = {}) {
  let response;
  try { response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}) }, cache: "no-store", signal: AbortSignal.timeout(8000) }); }
  catch (error) { throw new Error(error.name === "TimeoutError" ? "La solicitud tardó demasiado. Vuelve a comprobar la conexión." : "No se pudo contactar con la API local."); }
  if (!response.ok) {
    const messages = { 401: "El token no es válido. Revisa la conexión del entorno.", 404: "El registro solicitado ya no está disponible.", 422: "Revisa los campos. Usa organización/repositorio y una URL http o https válida.", 503: "El servicio no está listo. Comprueba la base de datos y las migraciones." };
    const error = new Error(messages[response.status] || `La solicitud falló (${response.status}).`); error.status = response.status; throw error;
  }
  return response.json();
}
async function refreshHealth() {
  try { const live = await api("/health/live"); state.api = live.status === "ok"; } catch { state.api = false; }
  try { const ready = await api("/health/ready"); state.database = ready.status === "ready"; } catch { state.database = false; }
  renderChrome();
}
async function refreshData(silent = false) {
  const sequence = ++refreshSequence;
  state.loading = true; render();
  try {
    if (!state.token) { await refreshHealth(); return; }
    const integrations = await api("/api/integrations");
    if (sequence !== refreshSequence) return;
    state.authenticated = true; state.integrations = integrations;
    const results = await Promise.allSettled([api("/api/applications"), api("/api/investigations"), refreshHealth()]);
    if (sequence !== refreshSequence) return;
    state.applications = results[0].status === "fulfilled" ? results[0].value : null;
    state.investigations = results[1].status === "fulfilled" ? results[1].value : null;
    state.appError = results[0].status === "rejected" ? results[0].reason.message : "";
    state.caseError = results[1].status === "rejected" ? results[1].reason.message : "";
    state.updated = new Date();
    if (!silent) announce(state.appError || state.caseError ? "Conexión parcial: los adaptadores se consultaron, pero faltan los datos del entorno." : "Datos actualizados.", state.appError ? "" : "success");
  } catch (error) {
    if (sequence !== refreshSequence) return;
    if (error.status === 401) { state.authenticated = false; state.token = ""; state.applications = null; state.investigations = null; state.integrations = null; }
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
function helpDialog() { openModal("Tu espacio de seguridad", `<p>El MVP conecta inteligencia de amenazas, conocimiento del entorno y propuestas de corrección bajo revisión humana.</p>${note("Disponible ahora.", "Registro de aplicaciones y avisos manuales, consulta de adaptadores y vista previa del flujo.")}${note("En preparación.", "Inventario, correlación, evidencia, parches, validaciones, aprobaciones y auditoría completa.")}<div class="dialog-actions"><a class="button" href="/docs" target="_blank" rel="noopener">Documentación API ↗</a>${button("Entendido", "close-modal", "", true)}</div>`); }

async function performAction(action, target) {
  if (NAV.some((item) => item[0] === action)) { navigate(action); return; }
  if (action === "connect") connectionDialog();
  if (action === "help") helpDialog();
  if (action === "close-modal") $("modal").close();
  if (action === "new-app") newAppDialog();
  if (action === "new-case") newCaseDialog();
  if (action === "refresh") { try { await refreshData(); } catch { /* refreshData announces the error. */ } }
  if (action === "case-detail") { state.selectedCase = target.dataset.id; state.operationView = "case"; navigate("overview"); }
  if (action === "app-detail") navigate(`applications/${target.dataset.id}`);
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
  if (!["connect-form", "application-form", "investigation-form"].includes(form.id)) return;
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
window.addEventListener("hashchange", () => { state.search = ""; render(); $("main-content").focus({ preventScroll: true }); window.scrollTo({ top: 0 }); });
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
