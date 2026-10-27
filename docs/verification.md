# Verificación del scaffold

**Fecha local:** 26 de octubre de 2026. **Nivel:** scaffold ejecutable; no equivale a aceptación del MVP completo.

## Ran — Infraestructura y backend

| Comprobación ejecutada | Resultado |
|---|---|
| Ruff, análisis y formato | Sin errores de análisis; archivos Python formateados. |
| Pytest con PostgreSQL real en `warden_test` | **16 pruebas aprobadas**, ninguna omitida en esa ejecución. |
| `docker compose config --quiet` | Configuración base válida; variantes de desarrollo y observabilidad también válidas. |
| Construcción de imagen y `up --wait api` | API y PostgreSQL saludables; migrador finalizado con código 0. |
| `/health/ready` en los puertos 8000 y 8001 | Ambas APIs devolvieron `200` y `database: ok`. |
| Migraciones | Tres migraciones aplicadas; la prueba comprueba repetición sin reaplicar cambios. |
| Permisos de `warden_app` | Puede agregar auditoría; no puede actualizarla ni escribir en `schema_migrations`. |
| Persistencia por API | Alta y lectura de aplicación/aviso, auditoría y vista previa contra PostgreSQL real. |
| Respaldo y restauración | Volcado de `warden` restaurado en una base nueva `warden_restore_test`; se recuperaron las tres migraciones. No se sobrescribió la base activa. |
| OpenTelemetry Collector | Colector local iniciado y recepción de spans confirmada mediante su exportador de diagnóstico. |

Revisión posterior de factibilidad: **19 pruebas aprobadas** con PostgreSQL real. El roundtrip se ejecuta ahora con los privilegios efectivos de `warden_app`; se prueba rechazo real de modificación de auditoría y readiness ante migraciones ausentes, cambiadas o inesperadas. OSV, GitHub Advisories, NVD y CISA KEV respondieron HTTP 200 en pruebas públicas independientes; esto no cambia el estado pendiente de sus adaptadores en el producto. Alcance, fuentes y condiciones en `docs/feasibility-assessment.md`.

La evidencia local de contenedores, migraciones y trazas se guarda en `artifacts/compose-status.json`, `artifacts/migrations.log`, `artifacts/otel-collector.log` y los registros de construcción. Esos artefactos están excluidos de Git.

Las pruebas unitarias incluyen rechazo de acceso sin token, fallo cerrado si no se configuró autenticación, redacción de secretos, rechazo de rutas locales como repositorio y detención del grafo antes de simular un análisis. La preparación del entorno comprueba que no se sobrescriban ni impriman credenciales.

## UI

La validación visual y los flujos de interfaz se documentan en `docs/ui-scaffold.md`. El resultado del análisis estático de marcadores de estado no sustituye una prueba de navegación o una comprobación visual.

La revisión visual de la navegación consolidada final no se pudo repetir después del cambio de cuenta: el navegador local quedó deshabilitado en los ajustes de Work. Las comprobaciones previas de escritorio/móvil corresponden a la versión anterior a la última consolidación; no acreditan por sí solas la disposición final de todas las etapas.

## Incremento de bundles B1–B3

Regresión final local: **97 pruebas aprobadas en 42,87 s**, sin omisiones, con PostgreSQL aislado `warden_test`, el rol efectivo `warden_app`, Docker real habilitado y prueba diferencial npm. Desglose: 19 del scaffold, 28 del ejecutor (6 con contenedores reales), 40 de correlación y 10 de orquestación PostgreSQL. Ruff check y format check aprobados, 54 archivos Python verificados. Son pruebas de estos componentes, no CA-01–CA-13 del producto integrado.

El ejecutor prueba aislamiento, límites, cancelación, artefactos y limpieza con tareas sintéticas. Correlación incluye 224 combinaciones diferenciales npm y una medición separada de 10 000 componentes/20 ejecuciones: p95 0,8915 s. Orquestación prueba recuperación entre etapas, idempotencia, ámbito, cuotas conservadas, pausa/cancelación, exclusión concurrente, permisos SQL y descarte de resultados tardíos o sin evidencia. El fallo abrupto durante una etapa sigue pendiente de una prueba con terminación real del proceso.

La imagen se reconstruye con Node/node-semver y el checkpointer oficial PostgreSQL. La migración 004 añade el ledger de control; el setup propietario prepara el esquema separado de checkpoints. Las migraciones 001–003 permanecen intactas. Los módulos son internos, sin nuevas rutas HTTP ni capacidades de ejecución expuestas mediante el token de desarrollo.

Detalles, comandos y límites: `docs/bundle-execution.md`, `docs/bundle-correlation.md`, `docs/bundle-orchestration.md` y `docs/implementation-roadmap.md`. La integración de los cuatro frentes y la implementación B4–B7 siguen pendientes; los núcleos B1–B3 no equivalen al cierre de sus bundles completos.

## Planned — Implementación del MVP

- Lectura real de GitHub, OSV, NVD y CISA KEV.
- Inventario Syft y análisis Trivy/OSV-Scanner.
- Contrato y llamadas reales de Meterless, NVIDIA y conectores condicionales.
- Integración del ejecutor aislado con identidades, worker e imágenes de herramientas reales; red de instalación controlada.
- Usuarios, autorización por proyecto y aprobación humana real.
- Integración de checkpoints/reanudación y correlación con los frentes, persistencia de hallazgos y generación de parches.
- Los criterios CA-01–CA-13 completos del SRS.

La configuración de un secreto mantiene el adaptador como `not_implemented` y `verified: false`. No se han realizado llamadas a proveedores externos para acreditar integraciones que siguen pendientes.

## Skipped — CI remoto

El workflow está preparado para PostgreSQL efímero, pruebas, análisis y construcción Docker. No se afirma una ejecución en GitHub Actions: el proyecto no se ha publicado desde esta sesión.
