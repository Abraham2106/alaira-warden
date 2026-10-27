# Integración de los cuatro frentes

## Código recibido y conexión

Se fusionaron, sin conflictos, `codex/front-identity` (`94c1501`), `codex/front-inventory` (`30157e2`), `codex/front-intelligence` (`0867509`) y `codex/front-providers` (`2ff6b69`) sobre `codex/bundles-foundations`. Los worktrees de origen no se modificaron. Los handoffs documentan la entrega original; este documento y `hackathon-alignment.md` describen el montaje y requisitos actuales.

La composición está en `src/alaira_warden/integration/`. Se conservan los módulos recibidos y se usan sus clientes, parsers, autorización y persistencia; no se sustituyeron por otro conjunto de stubs. Se corrigió el acceso posicional a filas SQL de fuentes para soportar `dict_row`; se añadió completitud explícita del alcance afectado y se tradujeron los rangos GitHub/OSV al contrato del motor. Pytest usa `--import-mode=importlib` para evitar la colisión entre los dos archivos `test_clients.py`.

Migraciones nuevas: 005 identidad, 006 persistencia/control de la integración, 007 propuestas y vistas de datos. No se reescribieron 001–004. El runtime no puede reescribir inventarios, revisiones, hallazgos ni auditoría. El grupo SQL `warden_data_reader` solo puede consultar las dos vistas limitadas; no tiene login ni acceso a identidades. Una instalación Zetaris debe usar un login dedicado con esa membresía, nunca el propietario de Warden.

## Identidad y arranque

La aplicación usa credenciales individuales opacas. El antiguo `WARDEN_API_TOKEN` compartido es rechazado; no confiere privilegios administrativos. `WARDEN_IDENTITY_PEPPER` debe mantenerse estable y fuera de PostgreSQL. `scripts/bootstrap.py` lo genera para instalaciones nuevas y no sobrescribe `.env` existentes.

Tras migrar, ejecutar una sola vez:

```powershell
uv run python scripts/provision_identity.py
```

La identidad administradora solo puede crearse con el almacén vacío. Su credencial se escribe una vez en `artifacts/private/administrator.token`, excluido de Git; no sale por stdout. Se puede introducir en el formulario de acceso actual o en Authorize de Swagger. Las altas y revocaciones posteriores usan `/api/identity/` y requieren `settings.manage`. Las mutaciones se auditan con el principal autenticado y su misma transacción.

El comando anterior corresponde al desarrollo host con Postgres publicado en loopback mediante `compose.dev.yaml`. Para Docker sin publicar la base, el README muestra el módulo empaquetado `alaira_warden.identity.bootstrap`, que genera el archivo dentro de `/tmp`; se copia al host y se elimina antes de reiniciar. No se entrega la clave por stdout ni se monta un directorio del host en trabajos de repositorios.

Las listas se filtran en SQL por las aplicaciones autorizadas. Una aplicación ajena devuelve 404; un actor con ámbito pero sin la acción recibe 403. Los roles enviados por el cliente no afectan la decisión. Todas las nuevas rutas requieren identidad y autorización.

## Recorrido operativo por API

Swagger en `/docs` permite ejecutar esta secuencia:

1. `POST /api/applications`: registrar repositorio GitHub, responsable, criticidad y entornos.
2. `POST /api/applications/{id}/inventory/refresh` con `{"ref":"HEAD"}`: resolver a SHA, leer los manifiestos mediante transporte HTTPS acotado y guardar el snapshot. Requiere `inventory.refresh`. No ejecuta scripts npm ni afirma haber corrido Syft.
3. `POST /api/investigations`: registrar aviso con URL y descripción.
4. `POST /api/investigations/{id}/runs` con `snapshot_id`, `advisory_identifier` (CVE o GHSA) y `request_key` UUID. La selección queda incluida en la solicitud persistente y su huella de idempotencia.
5. `POST /api/investigations/{id}/runs/{run}/advance`: una etapa por solicitud. Inventario → consulta de fuentes → correlación. Puede reanudarse desde el checkpoint; una ejecución concurrente recibe 409. No hay worker que despache automáticamente este recorrido todavía.
6. `GET /api/investigations/{id}/context`: evidencia, consultas y errores, revisiones humanas, evaluaciones, procedencia de datos y runs en un mismo recurso. La evaluación no afirma compromiso.
7. `POST /api/investigations/{id}/evidence/{revision}/review`: analista autorizado clasifica la evidencia y justifica. Se conserva la decisión; la conclusión anterior se invalida. Crear otro run reevalúa sin borrar el historial. No existe promoción automática de evidencia preliminar por repetir un CVE en dos fuentes.
8. Controles: `/runs/{run}/pause`, `/resume`, `/cancel`. Se autorizan por caso y aplicación.

`GET /api/applications/{id}/inventory` devuelve snapshots/despliegues. `POST /api/applications/{id}/deployments` importa el documento histórico v1 y verifica aplicación, entorno y snapshot; registrar un despliegue no prueba ejecución del código. El cálculo completo de exposición histórica sigue pendiente de selección de contexto en el flujo.

El preview antiguo se mantiene como ejemplo explícito sin efectos; la investigación operativa usa `/runs`. El scaffold visual conserva sus pantallas actuales: los controles nuevos aún se operan mediante Swagger/API y deben incorporarse al flujo consolidado de UI en B6.

## Patrocinadores: configuración y límites

Prevalece [el ajuste del hackathon](hackathon-alignment.md): Zetaris + Nightshift + un Engine operativo son obligatorios. La conexión de bibliotecas no acredita esos tres requisitos.

`WARDEN_DATA_MODE=local` permite desarrollar la integración con PostgreSQL y declara el modo en el contexto. No cuenta como capa de datos Zetaris. Con `WARDEN_DATA_MODE=zetaris`, la correlación debe leer por Zetaris las vistas registradas que se indiquen en `WARDEN_ZETARIS_INVENTORY_TABLE` y `WARDEN_ZETARIS_EVIDENCE_TABLE`. Se necesitan instancia, organización y token. Se usan consultas limitadas por UUID y se comprueba que los datos correspondan al snapshot y revisión fijados. No hay fallback a datos locales si la consulta falla.

Las vistas Postgres `warden_inventory_data` y `warden_evidence_data` ofrecen la forma `payload` requerida. Deben registrarse en Zetaris con un usuario de lectura limitado. El cliente recibido implementa el perfil cloud documentado en su handoff; aún debe verificarse contra la distribución concreta obtenida en HackOS. La guía reciente de Zetaris distingue UI proxy y API raw: no se supone que una URL de UI sirva como URL de ese cliente. No se inventaron rutas ni credenciales del bundle local.

`POST /api/integrations/meterless/check` comprueba modelos y `.../zetaris/check` autenticación. Esa verificación solo acredita la operación nombrada, no generación ni capa de datos del caso. El catálogo distingue cliente conectado, configuración y operación realmente comprobada. No acredita Engines.

`POST /api/investigations/{id}/synthesis` conecta las evaluaciones con el cliente Meterless para una propuesta estructurada. Por defecto se deniega enviar datos. Requiere `WARDEN_MODEL_DISPATCH_POLICY=allow_minimized`, `WARDEN_METERLESS_MODEL` y un origen/credencial aprobados de Nightshift. Solo se envían IDs, nombres de paquetes y versiones en un contexto acotado; no código, descripción privada ni secretos. No se altera la clasificación determinista. La propuesta y su huella se conservan; el modelo devuelto no se sustituye por el nombre de un backend que no haya sido identificado.

No se monta NVIDIA directo. Su clave se configura en Providers de Nightshift; `.env.example` y Compose ya no la solicitan para Warden. Ninguna llamada autenticada de patrocinador se ha ejecutado. H-MEM/otro Engine aún no está implementado; el grafo actual tampoco acredita la interacción dinámica planner/evaluator exigida por el evento.

## Evidencia

- Regresión final: 339 pruebas aprobadas con PostgreSQL, identidad SQL y Docker reales, 1 sonda opcional omitida; esa sonda se ejecutó aparte y pasó. El desglose final se registra en `verification.md`.
- Prueba HTTP integrada: registro → snapshot por commit → clientes de fuentes con respuestas controladas → persistencia → evaluación → revisión → reevaluación; autorización por aplicación, importación histórica, revocación real y rechazo de sustitución del inventario en la capa Zetaris inyectada.
- `scripts/probe_integrated_sources.py` ejecutó clientes reales sin credenciales: GitHub 1 aviso, OSV 5, NVD 1, KEV 1758. Todos devolvieron lotes completos; NVD y KEV conservaron advertencias de identidad npm desconocida. Evidencia: `artifacts/integration/public-clients.json`. Esto no constituye aceptación completa de un caso real ni prueba de patrocinadores.
- El servicio host (8000) y Docker (8001 en esta sesión) respondieron 200 a readiness, sesión individual y listado autenticado de aplicaciones.
- `scripts/sample_case.py` ejecuta tres casos sintéticos sin Postgres ni claves: potencial, no afectado e indeterminado. Usa el motor npm real, necesita `npm ci`, y declara que no ejecuta IA ni patrocinadores. Es un primer modo de ejemplo, no la demostración completa del MVP.

Para cerrar el producto faltan el setup y las operaciones reales de patrocinadores, un Engine conforme, el ciclo de agentes con crítica/feedback, herramientas Syft/Trivy/OSV-Scanner en el ejecutor, remediación/aprobación/PR y las verificaciones de aceptación pendientes.
