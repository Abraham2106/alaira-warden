# Handoff — Inventario y despliegues

Frente listo para integración en pruebas aisladas. La lectura real de GitHub y la ejecución real de Syft quedan pendientes: este entorno no tiene Syft y las pruebas no abren red, Node ni Docker.

## Objetivo y cobertura

El paquete `alaira_warden.inventory` construye `InventorySnapshot` y `DeploymentRecord` del contrato v1. Cubre la extracción npm, la forma de invocación de Syft, la reconciliación con el lockfile, la importación histórica de despliegues y la clasificación de completitud y vencimiento.

| Referencia | Estado en este frente |
|---|---|
| RF-01 | La lectura exige una aplicación autorizada (`application_id`, `repository`, entornos, responsable y criticidad). Esos tres últimos no se persisten aquí. `registration_gaps` indica los que falten. |
| RF-03 | Lockfile npm 2 y 3: directas, transitivas, alias y varias versiones del mismo paquete. Un rango de `package.json` no se convierte en versión instalada. |
| RF-04 | La instantánea queda ligada al commit inmutable. Guardar otra no borra la anterior. |
| RF-05 | La importación añade despliegues. Una fila no afirma que el código se ejecutó (`execution_evidence = not_asserted`). |
| RF-06 | `complete`, `partial` y `failed` se calculan al observar. El vencimiento se evalúa después, con un plazo explícito, y no reescribe la instantánea guardada. |
| WBS 1.3.1 | Allowlist, resolución de ref a SHA y límites de lectura. Falta la llamada real. |
| WBS 1.3.2 | Parser de lockfile y de CycloneDX, más runner inyectado. Falta Syft 1.55.0 sobre un checkout autorizado. |
| WBS 1.3.3 | Esquema JSON versión 1 e inserción append-only. Falta aplicar el SQL propuesto. |
| WBS 1.3.4 | Clasificación, vencimiento y retención de instantáneas. El refresco manual es otra llamada que inserta; no hay un endpoint montado. |

No hay conclusiones de vulnerabilidad ni de prioridad.

## Comparación con la base

Base: `6bb1828` en `codex/front-inventory`.

Archivos de este frente:

- `src/alaira_warden/inventory/**`
- `tests/inventory/**`
- `docs/handoffs/inventory.md`

No se modificaron migraciones, `models.py`, `repository.py`, `config.py`, Compose ni el checkout `Alaira Warden`. El commit de entrega es el HEAD de `codex/front-inventory` cuyo mensaje es `feat: add npm inventory and deployment import`. No está publicado.

## Funciones públicas

El transporte GitHub y el runner de Syft se inyectan. El paquete no lee `Settings`, no abre sockets y no lanza procesos.

```python
from datetime import UTC, datetime, timedelta
from uuid import UUID

from alaira_warden.inventory import (
    AuthorizedApplication,
    InventoryLimits,
    assess_snapshot,
    insert_snapshot,
    parse_deployment_document,
    snapshot_from_github,
    snapshot_from_manifests,
)

application = AuthorizedApplication(
    application_id=UUID("11111111-1111-1111-1111-111111111111"),
    repository="octo/registry-app",
    environments=("production", "staging"),
    owner="ada",
    criticality="high",
)
limits = InventoryLimits(timeout_seconds=30, max_file_bytes=5_000_000)
snapshot = snapshot_from_github(
    application=application,
    ref="main",
    transport=github_transport,
    allowed_repositories={"octo/registry-app"},
    token=github_token,
    observed_at=datetime.now(UTC),
    limits=limits,
    syft_runner=executor_runner,
)
assessment = assess_snapshot(snapshot, now=datetime.now(UTC), max_age=timedelta(days=7))
```

`snapshot.commit_sha` es el SHA devuelto por GitHub, aunque `ref` haya sido `main`. `snapshot.metadata["requested_ref"]` conserva la entrada. Una ref mutable no es la identidad de la instantánea.

Sin Syft, `snapshot_from_manifests(...)` puede quedar `complete` si el lockfile resuelve todos los componentes de registro. Si se pasa un `SyftCapture` fallido, el resultado no es `complete` y no aparece ningún componente sacado de un SBOM ficticio. `tool_name` queda `npm-lockfile` cuando Syft no produjo documento, y `syft` / `1.55.0` solo si el runner terminó bien.

### Componente

`dependency_paths` es una lista de cadenas. Cada cadena va de una dependencia directa hasta el componente. Un paso es `nombre@version` o `nombre@unresolved`. Dos versiones del mismo paquete son dos componentes; `metadata.lock_path` distingue el nodo del lockfile. Un alias npm usa el nombre real del paquete y guarda el nombre pedido en `metadata.alias`.

Ejemplo sintético de `tests/inventory/fixtures/registry_app`:

- `left-pad@1.3.0` directa, ruta `[["left-pad@1.3.0"]]`. El manifiesto dice `^1.0.0`.
- `lodash@4.17.21` directa, alias `alias-lodash`.
- `qs@6.5.3` transitiva: `[["express@4.18.2", "qs@6.5.3"]]`.
- `qs@6.11.0` transitiva: `[["express@4.18.2", "body-parser@1.20.1", "qs@6.11.0"]]`.

### Despliegue

Documento `schema_version` 1. Cada elemento exige `application_id`, `environment`, `artifact_ref`, `deployed_at`, `source_reference` y al menos `commit_sha` o `snapshot_id`. Las fechas llevan zona y se normalizan a UTC. `retired_at` no puede ser anterior a `deployed_at`. Un `application_id` distinto, un entorno no registrado o un snapshot de otra aplicación se rechazan. No existe un campo de ejecución de código; `code_executed` es un campo extra y el documento se rechaza.

```json
{
  "schema_version": 1,
  "deployments": [
    {
      "application_id": "11111111-1111-1111-1111-111111111111",
      "environment": "production",
      "artifact_ref": "registry.example/app@sha256:abc",
      "commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
      "snapshot_id": null,
      "deployed_at": "2024-01-01T00:00:00Z",
      "retired_at": "2024-06-01T00:00:00Z",
      "source_reference": "change-ticket:CHG-1"
    }
  ]
}
```

`import_deployments` valida todo el documento y después inserta. No borra filas anteriores. `retire_deployment` solo escribe `retired_at`. `append_deployments` hace lo mismo en memoria.

## Syft

Versión fijada: **1.55.0**. Formato fijado: CycloneDX JSON 1.5 y 1.6. El comando no usa shell, ni `--enrich`, ni un archivo de configuración del repositorio:

```text
syft version -o json
syft scan dir:<checkout absoluto> --base-path <el mismo checkout> -o cyclonedx-json@1.6
```

El ejecutor del integrador debe imponer el timeout recibido, capturar stdout/stderr y devolver el código de salida. Si el comando de versión no es exactamente `1.55.0`, si el proceso falta, si el código no es 0 o si el JSON no es CycloneDX 1.5/1.6, `execute_syft` deja el documento en `None`. Un stdout con pinta de SBOM y código distinto de 0 se descarta.

La reconciliación no borra discrepancias. Si el SBOM y el lockfile tienen el mismo nombre y versión, se conservan las rutas del lockfile cuando el SBOM no las trae (`metadata.paths_recovered_from_lockfile`). Versiones distintas, paquetes solo del SBOM y paquetes solo del lockfile generan advertencias y completitud `partial`.

## Política de resolución

Soportado:

- `lockfileVersion` 2 y 3 con objeto `packages`.
- Dependencias de producción, desarrollo y opcionales presentes en el lockfile.
- Alias `npm:` mediante el `name` real del nodo.
- Workspaces: el enlace local al propio repositorio no es un componente de registro y no impide `complete`.
- CycloneDX JSON 1.5 y 1.6 con `purl` `pkg:npm/...`.

No soportado, sin inventar versión:

- `lockfileVersion` 1, Yarn y pnpm.
- Rangos, especificadores git (`git+`, `git://`, `github:`, `git@`) y `file:` / enlaces externos. Quedan componentes con `resolved_version = null`, origen `git` o `local`, y completitud distinta de `complete`. La versión escrita por el autor del paquete git se guarda en `metadata.lock_version`, no como versión resuelta.
- SPDX y CycloneDX fuera de 1.5/1.6.
- `package.json` `overrides`: se ignoran porque la versión sale del lockfile.
- Peer dependencies instaladas pero no enlazadas desde la raíz: `orphan_lock_node`, completitud `partial`.
- Lockfile anidado y manifiestos dentro de `node_modules`: no se mezclan.
- Árbol Git truncado o por encima del límite: error `budget_exceeded`, sin instantánea parcial que parezca completa.

Completitud:

- `failed`: no hay componentes utilizables (lockfile ausente, ilegible o no soportado, y Syft tampoco aportó datos).
- `partial`: hay datos, pero existe una advertencia con `blocks_completeness`, una versión sin resolver o Syft fue pedido y falló.
- `complete`: todo componente de registro tiene versión concreta y no hay advertencias que bloqueen. Syft, si se pidió, terminó sin discrepancias.

El vencimiento usa `assess_snapshot(..., max_age=...)`. Si la edad es mayor o igual al plazo, añade `inventory_expired` y `limits_conclusion`. El campo `completeness` guardado no cambia. Un lockfile ausente ya deja `failed` y también limita la conclusión.

## Límites explícitos

`InventoryLimits` por defecto: 100 archivos, 5_000_000 bytes por archivo, 20_000_000 bytes en total y por respuesta, 20_000 entradas de árbol, 30 segundos, profundidad 25, 20 rutas por componente y 5_000 componentes. El presupuesto de tiempo no se reinicia entre la resolución del commit, el árbol y los blobs.

La materialización rechaza rutas absolutas, `\`, `:`, segmentos vacíos, `.` y `..`, y un symlink de destino. No se sigue un manifiesto con modo git `120000`.

## Pruebas

```text
uv sync --group dev
uv run pytest tests/inventory -q
uv run ruff check src/alaira_warden/inventory tests/inventory
```

Resultado de esta entrega: 16 pruebas aprobadas y ruff limpio, con el `.venv` de este worktree. Todas usan fixtures sintéticos o dobles inyectados. No hubo red, `npm`, Node ni Docker.

Syft no está en el `PATH` de esta máquina. La prueba real del binario 1.55.0 queda pendiente; leer `tests/inventory/fixtures/syft_discrepancy.cdx.json` no cierra ese requisito.

## Configuración que debe añadir el integrador

No se editó `config.py`. Pasar los valores como argumentos, sin cargarlos dentro del paquete:

| Variable | Uso |
|---|---|
| `WARDEN_GITHUB_TOKEN` | Ya existe. Va en `Authorization: Bearer`. Nunca en la URL. Vacío solo para un repositorio público que además esté en la allowlist. |
| `WARDEN_INVENTORY_REPOSITORIES` | Lista `owner/repo` separada por comas. Vacía significa que no hay repositorios autorizados. |
| `WARDEN_INVENTORY_MAX_AGE_SECONDS` | Plazo de vencimiento. Propuesta inicial: `604800`. |
| `WARDEN_INVENTORY_TIMEOUT_SECONDS` | Presupuesto de la lectura y de Syft. Propuesta: `30`. |
| `WARDEN_INVENTORY_MAX_FILE_BYTES` | Propuesta: `5000000`. |
| `WARDEN_SYFT_VERSION` | Debe ser `1.55.0`. El código rechaza otra versión. |

El ejecutor instala Syft 1.55.0 por un mecanismo verificable del integrador. Este frente no lo descarga. El contenedor de análisis no recibe el socket Docker ni credenciales de escritura de GitHub.

Errores posibles, por categoría: `configuration`, `unauthorized`, `forbidden`, `rate_limited`, `unavailable`, `timeout`, `invalid_response`, `unsupported`, `budget_exceeded`. Los mensajes no incluyen el token, `Bearer` ni userinfo de una URL.

## SQL propuesto

No está aplicado. `insert_snapshot`, `insert_deployment`, `import_deployments` y `retire_deployment` escriben columnas que hoy no existen (`warnings`, `artifact_hash`, `metadata`, `commit_sha`). No montar estas funciones hasta crear la migración siguiente, por ejemplo `004_inventory_provenance.sql`. El llamador abre la transacción; estas funciones no hacen `commit` ni `DELETE`.

`commit_ref` guarda el SHA inmutable. `repository` sigue viviendo en `applications` y se comprueba antes de insertar.

```sql
ALTER TABLE inventory_snapshots
    ADD COLUMN warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN artifact_hash TEXT,
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE inventory_snapshots
    ADD CONSTRAINT inventory_snapshots_commit_sha_chk
        CHECK (commit_ref ~ '^[0-9a-f]{40}$'),
    ADD CONSTRAINT inventory_snapshots_warnings_chk
        CHECK (jsonb_typeof(warnings) = 'array'),
    ADD CONSTRAINT inventory_snapshots_metadata_chk
        CHECK (jsonb_typeof(metadata) = 'object'),
    ADD CONSTRAINT inventory_snapshots_artifact_hash_chk
        CHECK (artifact_hash IS NULL OR artifact_hash ~ '^[0-9a-f]{64}$');

COMMENT ON COLUMN inventory_snapshots.commit_ref IS
    'SHA de commit en minúsculas. Una rama no identifica la instantánea.';

ALTER TABLE deployments
    ADD COLUMN commit_sha TEXT;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_commit_sha_chk
        CHECK (commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{40}$'),
    ADD CONSTRAINT deployments_commit_or_snapshot_chk
        CHECK (snapshot_id IS NOT NULL OR commit_sha IS NOT NULL);

COMMENT ON TABLE deployments IS
    'Observación de despliegue. La fila no demuestra ejecución de código.';

ALTER TABLE applications
    ADD COLUMN organization TEXT,
    ADD COLUMN owner TEXT,
    ADD COLUMN criticality TEXT,
    ADD COLUMN environments JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE applications
    ADD CONSTRAINT applications_criticality_chk
        CHECK (
            criticality IS NULL
            OR criticality IN ('low', 'medium', 'high', 'critical')
        ),
    ADD CONSTRAINT applications_environments_chk
        CHECK (jsonb_typeof(environments) = 'array');
```

Permisos, después de esa migración y solo si el rol `warden_app` existe:

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON inventory_snapshots, components FROM warden_app;
REVOKE DELETE, TRUNCATE ON deployments FROM warden_app;
GRANT SELECT, INSERT ON inventory_snapshots, components, deployments TO warden_app;
GRANT UPDATE (retired_at) ON deployments TO warden_app;
```

La inserción de auditoría usa `inventory.snapshot_recorded`, `deployment.imported` y `deployment.retired` con el actor que pase el frente de identidad. No guarda el token.

## Montaje para el integrador

1. Aplicar el SQL anterior como migración nueva. No reescribir `001` ni `002`.
2. Añadir las variables de configuración. Construir `AuthorizedApplication` desde la fila de `applications` más los campos nuevos.
3. Implementar el transporte GET hacia `https://api.github.com` con los encabezados `Accept`, `User-Agent: alaira-warden-inventory` y `X-GitHub-Api-Version: 2022-11-28`. El token va solo en `Authorization`.
4. En el ejecutor, materializar el checkout con `materialize_files` o entregar un directorio ya confinado, y llamar a `execute_syft` con el runner que ejecuta el argv exacto.
5. Dentro de la transacción existente de `psycopg`, llamar a `insert_snapshot` y `import_deployments`. Pasar la misma conexión; no abrir el Postgres del checkout principal.
6. Exponer el refresco manual como otra inserción. `retain_snapshots` y el `INSERT` conservan las instantáneas previas.
7. Antes de correlacionar, consultar `assess_snapshot`. Si `limits_conclusion` es verdadero, la conclusión de exposición no puede tratarse como completa.
8. No registrar un adaptador en `adapters.py` desde este paquete. No hace falta un router aquí: las funciones ya son el contrato hasta que el integrador las publique en `main.py`.

`artifact_hash` es el SHA-256 del stdout del SBOM cuando Syft tuvo éxito y, si no, el del texto del lockfile. `artifact_path` solo se rellena si el integrador pasa una clave relativa sin `..`.
