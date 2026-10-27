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

## Planned — Implementación del MVP

- Lectura real de GitHub, OSV, NVD y CISA KEV.
- Inventario Syft y análisis Trivy/OSV-Scanner.
- Contrato y llamadas reales de Meterless, NVIDIA y conectores condicionales.
- Ejecutor de código de repositorios con aislamiento, red y presupuestos por trabajo.
- Usuarios, autorización por proyecto y aprobación humana real.
- Checkpoints/reanudación LangGraph, correlación y generación de parches.
- Los criterios CA-01–CA-13 completos del SRS.

La configuración de un secreto mantiene el adaptador como `not_implemented` y `verified: false`. No se han realizado llamadas a proveedores externos para acreditar integraciones que siguen pendientes.

## Skipped — CI remoto

El workflow está preparado para PostgreSQL efímero, pruebas, análisis y construcción Docker. No se afirma una ejecución en GitHub Actions: el proyecto no se ha publicado desde esta sesión.
