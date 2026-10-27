# Roadmap de ejecución y entrega de los cuatro frentes

## 1. Acuerdo de trabajo

El integrador de este chat desarrolla los bundles de manera **secuencial, personalmente y sin subagentes**. Los cuatro prompts enlazados permiten asignar los frentes a otros ejecutores o chats por decisión del usuario; este documento no inicia agentes, chats ni worktrees.

**Base común del código:** commit `6bb1828`, rama `master`. Este commit contiene el scaffold, SRS, WBS y evaluación de factibilidad. Este roadmap y los prompts se entregan después: deben acompañar la asignación y no se supone que existan dentro de un checkout que solo tenga el commit base.

El objetivo conserva todo el MVP del SRS. Los contratos de este documento coordinan el desarrollo; no acreditan implementaciones que todavía no existen.

## 2. Contexto del producto y situación actual

ALAIRA Warden relaciona inteligencia pública con aplicaciones npm para investigar exposición y preparar una corrección con evidencia, pruebas y aprobación humana. La UI consolida el caso y sus etapas de respuesta; no debe fragmentarse en páginas independientes de plan, validación y aprobación.

La base actual utiliza Python 3.12, FastAPI, Pydantic, psycopg, PostgreSQL, LangGraph, OpenTelemetry y Docker Compose. La UI es HTML/CSS/JS servida por FastAPI. Existen altas/consultas de aplicaciones y avisos manuales, auditoría inicial, migraciones de dominio, trazas y un grafo de vista previa que se detiene ante inventario pendiente.

Hay 19 pruebas del scaffold aprobadas en la revisión anterior. Los adaptadores externos siguen pendientes. Una sonda pública obtuvo HTTP 200 de GitHub Advisories, OSV, NVD y CISA KEV; no constituye su integración con el producto. No hay credenciales de patrocinadores configuradas en esta base.

Documentos normativos y de contexto:

- `SRS-Alaira-Warden.md`: requisitos y aceptación.
- `WBS-MVP-Alaira-Warden.md`: paquetes, dependencias y cierre.
- `docs/architecture.md`, `docs/decisions.md`: arquitectura actual.
- `docs/feasibility-assessment.md`: evidencia, riesgos y objetivo completo de entrega.
- `docs/integrations.md`: tratamiento de proveedores y límites.
- `docs/ui-scaffold.md`: UI implementada y verificación pendiente.

## 3. Propiedad de archivos

| Responsable | Archivos de su propiedad | Entrega |
|---|---|---|
| Fuentes | `src/alaira_warden/intelligence/**`, `tests/intelligence/**`, `docs/handoffs/intelligence.md` | Clientes, normalización, agrupación de avisos, pruebas y notas de integración. |
| Inventario | `src/alaira_warden/inventory/**`, `tests/inventory/**`, `docs/handoffs/inventory.md` | Lectura por commit, lockfile/Syft, snapshots e importación histórica. |
| Modelos/patrocinadores | `src/alaira_warden/providers/**`, `tests/providers/**`, `docs/handoffs/providers.md` | Clientes verificados documentalmente, pruebas de contrato y evidencia real cuando exista acceso. |
| Identidad/autorización | `src/alaira_warden/identity/**`, `tests/identity/**`, `docs/handoffs/identity.md` | Principal, permisos, autenticación, persistencia propia y contrato de auditoría. |
| Integrador de este chat | Archivos compartidos, montaje API/UI, cambios SQL, dependencias, configuración, ejecutor, correlación, orquestación, remediación y entrega | Integración secuencial, controles completos y versión aceptada. |

Los frentes no editan `main.py`, `models.py`, `config.py`, `db.py`, `repository.py`, `adapters.py`, `integrations.py`, `workflow.py`, `observability.py`, `static/**`, `pyproject.toml`, `uv.lock`, `migrations/**`, archivos Compose/Docker, CI, SRS, WBS o documentos compartidos. Las necesidades de cambios se especifican en su handoff.

No se añade un adaptador de producción a un archivo global desde un frente: el integrador registra el adaptador y monta sus endpoints al recibirlo. Los routers pueden existir dentro del paquete del frente, sin montarse en la aplicación global. La selección de tecnologías se limita al conjunto autorizado y componentes open source necesarios.

## 4. Contratos de intercambio v1

Estos son acuerdos documentales mínimos. Cada frente puede definir sus modelos dentro de su paquete usando Pydantic. Los nombres y significados siguientes deben conservarse al serializar; un cambio incompatible se propone al integrador antes de expandirlo a otros frentes. No crear una biblioteca genérica ni un bus de eventos para cumplir este contrato.

### 4.1 Reglas transversales

- Identificadores internos UUID; identificadores externos conservados sin reinterpretarlos.
- Fechas ISO 8601 con zona, normalizadas a UTC al persistir.
- `None` significa desconocido, no negativo ni ausente comprobado.
- Errores por categoría: `configuration`, `unauthorized`, `forbidden`, `rate_limited`, `unavailable`, `timeout`, `invalid_response`, `unsupported`, `budget_exceeded`.
- No devolver valores de secretos, cuerpos de error privados ni URLs que incluyan credenciales.
- Los intentos y tiempo de espera tienen límites finitos; el presupuesto se comparte a lo largo de paginación/reintentos, no se reinicia por página.
- Un resultado parcial conserva datos utilizables y advertencias sin declararse completo.
- Las llamadas de lectura y análisis no deben producir modificaciones externas implícitas.

### 4.2 Salida del frente Fuentes

`SourceBatch`: `source`, `retrieved_at`, `records`, `complete`, `next_cursor`, `warnings`.

Cada registro contiene:

- `source`: `github`, `osv`, `nvd` o `cisa-kev`.
- `source_id`, `aliases`, `title`, `summary`.
- `source_url`, `published_at` opcional, `modified_at` opcional y `retrieved_at`.
- `content_hash`: huella de la representación del registro de origen bajo una política documentada.
- `references`: URLs de referencia sin descargar su contenido automáticamente.
- `affected`: entradas con `ecosystem`, `package_name` y rangos/versiones de origen, sin asumir que todos usan SemVer.
- `severity`: datos originales y sistema que los produjo; no inventar una puntuación común.
- `known_exploited`: señal opcional con fuente; ausencia en KEV deja desconocida la explotación fuera del catálogo.
- `license` opcional y metadatos de atribución/procedencia.
- `affected_complete`: indicador semántico explícito para evaluar conclusiones negativas; por defecto `False`. No equivale al `complete` de un lote/página descargada.

NVD o KEV pueden carecer de identidad npm y devolver `affected=[]` con advertencia, sin fabricar un paquete. Se conserva suficiente información del registro original para inspeccionar y repetir su normalización. El matching definitivo pertenece al integrador.

La agrupación devuelve grupos y evidencia de las relaciones por identificadores/alias. No elimina fuentes ni sus revisiones. Un identificador ambiguo se declara; no se agrupa por similitud de título.

### 4.3 Salida del frente Inventario

`InventorySnapshot`: `application_id`, `repository`, `commit_sha`, `observed_at`, `tool_name`, `tool_version`, `completeness`, `components`, `warnings`, `artifact_path` opcional, `artifact_hash` opcional.

Cada componente conserva `name`, `ecosystem`, `resolved_version` opcional, `direct`, `dependency_paths` y metadatos pertinentes. Las rutas son cadenas de componentes o estructuras claramente documentadas; no pueden perder el contexto que distingue dos versiones del mismo paquete.

`DeploymentRecord`: `application_id`, `environment`, `artifact_ref`, `commit_sha` o snapshot explícito, `deployed_at`, `retired_at` opcional y `source_reference`. Si la procedencia solo demuestra despliegue, no etiquetar ejecución real de código.

Un commit debe resolverse a identidad inmutable; un branch es una entrada de resolución, no la identidad de la instantánea. La salida no declara vulnerabilidades ni toma decisiones de prioridad.

### 4.4 Salida del frente Modelos/patrocinadores

`ProviderCheck`: `provider`, `checked_at`, `status`, `operation`, `capabilities`, `reason` redactada y `verified`.

Estados: `unconfigured`, `unauthorized`, `forbidden`, `offline`, `available`, `unsupported`. `available` solo acredita la operación probada; listar modelos no prueba generación y un health no prueba autenticación.

`ModelResult`: `provider`, `model`, `request_id` opcional, `text`, `structured_output` opcional validada, `usage` opcional y `warnings`. El uso desconocido queda `None`, no cero. Una propuesta del modelo no se convierte en evidencia técnica.

Para Zetaris: resultado tabular con columnas, filas, identificadores de fuentes y momento de consulta cuando estén disponibles. Una consulta real se limita a fuentes/operaciones autorizadas. Una respuesta no debe convertirse automáticamente en un hallazgo o mutación de PostgreSQL.

### 4.5 Contrato del frente Identidad

`Principal`: `subject_id`, `roles`, `application_ids`, `is_active`, `authentication_method`.

`authorize(principal, action, application_id)` permite explícitamente o deniega; ausencia de asignación deniega. Roles del SRS: administrador, analista, desarrollador/DevSecOps, aprobador y auditor. Un administrador global debe ser una atribución explícita, no consecuencia de tener cualquier token válido.

Acciones mínimas: `application.read`, `application.create`, `inventory.read`, `inventory.refresh`, `investigation.read`, `investigation.create`, `investigation.review`, `patch.prepare`, `approval.decide`, `pull_request.publish`, `audit.read`, `settings.manage`.

`audit_actor(principal)` produce identidad atribuible para eventos. La auditoría no guarda tokens ni prueba pertenencia a un ámbito por el nombre del usuario. Al aprobar, comprobar identidad, ámbito y autorización del actor actual; la integridad del artefacto y la invalidación se implementan en el bundle del integrador.

## 5. Secuencia personal del integrador

| Orden | Bundle | Qué desarrollaré junto | Entrada para cerrar el bundle |
|---|---|---|---|
| B0 | Contratos y coordinación | Acuerdos de este documento, propiedad de archivos, integración y criterios. | Commit base y prompts entregados. No implica que los módulos existan. |
| B1 | Ejecutor seguro | Trabajos efímeros, herramientas permitidas, límites, red, artefactos, cancelación y limpieza. | Contrato de identidad para la entrada real; tareas sintéticas permitidas para desarrollar el ejecutor. |
| B2 | Correlación y hallazgos | Semántica npm, relación componente/aviso, exposición, prioridad, reevaluación e historial. | Contratos de fuentes e inventario; implementación inicial con fixtures, cierre con datos reales. |
| B3 | Orquestación persistente | Integración de frentes, investigación, checkpoints, transición, reanudación, presupuestos y trazas. | Frentes integrados, B1/B2 y operaciones reales de proveedores. |
| B4 | Corrección validada | Plan, parche, pruebas, Syft/Trivy/OSV-Scanner, reescaneo y ciclos limitados. | Hallazgo reproducible, modelo y ejecutor. |
| B5 | Aprobación y publicación | Artefacto exacto, actor autorizado, invalidación, escritura GitHub idempotente y auditoría. | Identidad integrada y B4 validado. |
| B6 | Contexto operativo completo | Endpoints/UI consolidada, reporte, retención y observabilidad por caso. | B3–B5 y datos reales; se conectan vistas durante la integración sin otro responsable concurrente de UI. |
| B7 | Aceptación y entrega | CA-01–CA-13, RNF aplicables, regresión, versión, documentación y artefactos de presentación. | Flujo completo en un mismo commit. |

El desarrollo puede avanzar usando fixtures cuando el contrato esté definido. El cierre de cada bundle requiere su integración real y evidencia. El integrador ejecuta un solo bundle de implementación a la vez; el trabajo de los cuatro frentes es independiente y se asigna únicamente si el usuario decide ejecutarlos por separado.

## 6. Worktrees sin interferencias

1. Todos parten de `6bb1828`; recibir además este roadmap y el prompt de su frente. No mezclar bases diferentes silenciosamente.
2. Una rama por frente: `codex/front-intelligence`, `codex/front-inventory`, `codex/front-providers`, `codex/front-identity`. El usuario/integrador crea o asigna los worktrees; el prompt no autoriza operar en checkouts ajenos.
3. Un entorno `.venv` por worktree. La instalación editable de otro checkout puede apuntar a código distinto; no reutilizarla para acreditar pruebas.
4. Las pruebas aisladas del módulo no requieren servicios de otros frentes. Utilizar fixtures y transporte/controladores inyectados cuando haga falta.
5. No usar el PostgreSQL ni el stack de demostración de otro worktree. Si se necesita integración local, usar proyecto Compose distinto, puertos distintos y base que termine en `_test`.
6. `compose.yaml` define un nombre fijo: no ejecutar `docker compose up/down` sin especificar el proyecto de trabajo cuando haya stacks concurrentes. La configuración de ese entorno la coordina el integrador.
7. No copiar `.env`, claves, credenciales SQL ni artefactos privados entre worktrees. Las pruebas no deben cargar por defecto `.env` del workspace principal.
8. No editar migraciones aplicadas ni crear números nuevos en `migrations/` desde un frente. Entregar propuestas SQL y requisitos de permisos en el handoff; el integrador crea la migración secuencial.
9. No ejecutar reset, limpieza, stash, merge, cherry-pick o rebase sobre ramas ajenas. Entregar cambios y commit de la rama; el integrador resuelve integración.

No se crean worktrees desde esta entrega documental. Los comandos concretos dependen de los directorios asignados; no se inventan rutas ni se borran checkouts existentes.

## 7. Entrega y recepción de cada frente

Cada handoff debe incluir:

- Objetivo implementado, WBS y requisitos cubiertos; límites pendientes.
- Archivos modificados, commit de entrega y comparación con el commit base.
- Funciones públicas y ejemplos de entrada/salida conformes con v1.
- Pruebas ejecutadas, resultado y evidencia; distinguir mocks de llamadas reales.
- Dependencias nuevas solicitadas, configuración necesaria sin valores de secretos y errores posibles.
- Propuesta SQL/permisos si corresponde, sin editar las migraciones base.
- Cambios concretos que debe realizar el integrador en archivos compartidos.
- Limitaciones de privacidad, licencias, cuotas y casos no soportados.

El integrador revisa propiedad de archivos y secretos; ejecuta pruebas del frente; verifica los contratos; incorpora dependencias/SQL/rutas; ejecuta regresión de los consumidores y registra el commit integrado. Integrar los cambios en una sola rama no sustituye probar su interacción.

Un frente puede estar **listo para integración** con sus pruebas aisladas y tener **verificación externa pendiente** por credenciales. No se declarará completado el requisito de llamada real hasta acreditarlo.

## 8. Prompts listos para entregar

- [Frente 1: fuentes de inteligencia](prompts/01-intelligence.md).
- [Frente 2: inventario](prompts/02-inventory.md).
- [Frente 3: modelos y patrocinadores](prompts/03-providers.md).
- [Frente 4: identidad y autorización](prompts/04-identity.md).

Cada archivo contiene un encargo copiable. Debe acompañarse del presente roadmap como contrato común. Los prompts no añaden servicios cerrados ni requieren agentes adicionales.

## 9. Ejecución iniciada

**B1:** núcleo offline del ejecutor implementado personalmente por el integrador, sin subagentes. 28 pruebas del módulo aprobadas, incluidas 6 de Docker real con tareas sintéticas. Autorización real, worker persistente e imágenes npm/escáneres siguen pendientes de integración. Evidencia y límites: `docs/bundle-execution.md`.

**B2:** núcleo determinista implementado después de B1. Usa el motor oficial npm para rangos, intervalos OSV separados, contexto histórico y reglas conservadoras ante datos incompletos. Prueba diferencial de 224 combinaciones y p95 local de 0,8915 s para 10 000 componentes en 20 ejecuciones. Persistencia, ciclo de revisión y conexiones con los frentes siguen pendientes. Evidencia y límites: `docs/bundle-correlation.md`.

**B3:** base de checkpoints PostgreSQL, reanudación entre etapas, exclusión por run, cuotas persistentes, controles y trazas implementada después de B2. Se prueba con handlers sintéticos y el rol SQL de runtime. Falta conectar los frentes, configurar sus llamadas reales y montar el worker autorizado. Evidencia y límites: `docs/bundle-orchestration.md`.

## 10. Recepción e integración posterior

Los cuatro frentes ya se fusionaron en la rama de bundles y están montados mediante `integration/`, identidad individual y migraciones 005–007. El recorrido HTTP hasta evaluación/revisión se prueba con PostgreSQL real y respuestas externas controladas. Los clientes GitHub, OSV, NVD y KEV también se probaron contra sus servicios públicos. El despacho es explícito por API, no un worker automático. B1–B3 siguen sujetos a sus condiciones de cierre; la guía de estado actual es `docs/front-integration.md`.

Las reglas completas proporcionadas por el usuario corrigen B0: Zetaris es obligatorio; Meterless requiere un Engine funcional **y** Nightshift como proveedor principal. No se monta NVIDIA directo. `docs/hackathon-alignment.md` y SRS 1.1 prevalecen sobre las condiciones antiguas de los prompts/handoffs, conservados como historial. El siguiente bloqueo de aceptación es setup real de Zetaris/Nightshift, seguido del Engine y del ciclo de agentes; B4–B7 permanecen pendientes.
