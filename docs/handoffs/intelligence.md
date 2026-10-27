# Handoff — Frente 1, fuentes de inteligencia

## Objetivo

Clientes de lectura para GitHub Advisory Database, OSV, NVD CVE API 2.0 (incluido el historial de cambios) y el catálogo CISA KEV. Normalizan a `SourceBatch`, agrupan por identificadores verificables y pueden escribir revisiones en las tablas ya existentes si el llamador entrega una conexión.

Cubierto: WBS 1.4.1–1.4.5 y el contrato v1 de fuentes (RF-08 a RF-14 en la parte de obtención, normalización, agrupación, evidencia preliminar y huella). La correlación con inventario, la programación dentro de la aplicación y el caso de investigación siguen en el integrador.

No está cubierto aquí: matching npm, exposición, prioridad, descarga de URLs de referencia, repositorios privados, escritura en GitHub, el export masivo `modified_id.csv` de OSV, ni una conexión real acreditada. La sonda pública es opcional y no forma parte de la suite que debe pasar sin red.

## Archivos

Solo este frente, sobre `6bb1828` en `codex/front-intelligence`:

- `src/alaira_warden/intelligence/**`
- `tests/intelligence/**`
- `docs/handoffs/intelligence.md`

No se tocó `main.py`, modelos compartidos, configuración, base de datos, adaptadores, migraciones, Compose, CI ni documentos normativos.

## Contrato

`SourceBatch`: `source`, `retrieved_at`, `records`, `complete`, `next_cursor`, `warnings`.

Cada `SourceRecord` conserva `source`, `source_id`, `aliases`, `title`, `summary`, `source_url`, `published_at`, `modified_at`, `retrieved_at`, `content_hash`, `references`, `affected`, `severity`, `known_exploited`, `license` y `attribution`. `known_exploited is None` significa desconocido, no “no explotado”. `severity` es una lista con el sistema que produjo cada dato; no hay una puntuación común. Los rangos quedan en la forma de la fuente.

Campos añadidos, compatibles con el v1: `origin` (JSON de origen, suficiente para repetir la normalización), `warnings`, `advisory_kind`, `source_status`, `changes` (historial NVD, fuera del hash), `received_at`.

Extensión pedida: `source="manual"` para RF-09. No está en la lista cerrada del roadmap. El integrador debe aceptarlo donde valide el origen.

`content_hash` es SHA-256 hexadecimal de la JSON canónica de `origin`: claves ordenadas, separadores `( ",", ":" )`, UTF-8. No incluye `retrieved_at` ni `changes`. Dos lecturas del mismo documento son la misma revisión.

## Funciones públicas

Importar `alaira_warden.intelligence`. No abre red ni base al importar. El transporte por defecto es HTTPS de la biblioteca estándar y no sigue redirecciones.

| Función | Uso |
|---|---|
| `fetch_github_advisories` | Listado público. Por defecto `ecosystem="npm"` y tipos `reviewed` y `malware` en peticiones distintas. El listado sin `type` no incluye malware. |
| `fetch_github_advisory` | Un GHSA. 404 es lote vacío; 401/403 se propagan. |
| `query_osv` | Paquete/versión o commit, con `page_token`. |
| `query_osv_batch` | Lote. Las filas iniciales pueden traer solo `id` y `modified` (`detail_not_loaded`). `resolve_details=True` pide el detalle hasta agotar el presupuesto. |
| `fetch_osv_vulnerability` | Detalle por id, también si está withdrawn. |
| `fetch_nvd_cve` | Un CVE. `include_changes=True` adjunta `cveChanges`. La clave va en la cabecera `apiKey`. |
| `fetch_nvd_modified` | Ventana `lastMod`. Se parte en tramos de 119 días. |
| `fetch_kev_catalog` | Catálogo completo. Si el cursor trae el mismo `catalogVersion`, devuelve cero registros y `catalog_unchanged`. |
| `lookup_kev` / `index_kev` | Búsqueda en un lote ya descargado. Un fallo deja `known_exploited=None`. |
| `group_advisories` | Une por CVE/GHSA/otros ids. No usa el título. No emite `confirmed`. |
| `manual_advisory` | Aviso con URL, descripción y fecha de recepción, con o sin CVE. No descarga la URL. |
| `consultation_report` | Resume lotes y errores que el llamador ya obtuvo. |
| `default_sync_plan` | Intervalos sugeridos. No arranca un scheduler. |
| `resume` | Continúa un `next_cursor` de este paquete. |
| `persist_records` | `INSERT` en `advisories` y `advisory_revisions`. El llamador hace commit. |
| `content_hash` | Huella documentada arriba. |
| `WorkBudget` | `max_requests`, `max_retries`, `timeout_seconds`, `max_wait_seconds`, `deadline_seconds`. Se comparte entre páginas y reintentos. |
| `SourceError` | `category` en el vocabulario v1. `str(error)` no incluye cuerpos ni secretos. |

Ejemplo real del normalizador (GitHub + NVD, mismo CVE, sin red):

```json
{
  "source_id": "GHSA-abcd-efgh-ijkl",
  "aliases": ["CVE-2024-1111"],
  "affected": {
    "ecosystem": "npm",
    "package_name": "left-pad",
    "ranges": [{
      "type": "github_vulnerable_version_range",
      "vulnerable_version_range": "< 1.2.3",
      "patched_versions": null
    }]
  },
  "content_hash": "f134e4c3de977d6c8f195ba3282fda086a16951cc67b1d1f3f028c7a6112c7b3",
  "group_id": "grp_aa665676d50ebc59",
  "evidence_class": "preliminary",
  "independent_report_count": 1,
  "nvd_affected": []
}
```

NVD no fabricó un paquete npm. El grupo es preliminar: repetir el CVE no es una corroboración independiente. Un CVE compartido por dos GHSA distintos queda en `ambiguous_identifiers` y no se parte el grupo. Una revisión es otro `content_hash` del mismo `source` + `source_id`.

Cursor de ejemplo: `{"v":1,"source":"github","next_url":"https://api.github.com/advisories?...","queued_urls":[]}`. No admite otro host, otra ruta ni parámetros `apiKey`, `token` o `key`.

## Errores y presupuesto

Categorías: `configuration`, `unauthorized`, `forbidden`, `rate_limited`, `unavailable`, `timeout`, `invalid_response`, `unsupported`, `budget_exceeded`.

401 no se reintenta. 403 de cupo (`x-ratelimit-remaining: 0`, `Retry-After` o texto interno de rate limit) es `rate_limited`; otro 403 es `forbidden`. 429, 502, 503 y el timeout se reintentan como máximo `max_retries` veces. Si `Retry-After` supera `max_wait_seconds` (2 s por defecto), la llamada no duerme ese plazo: devuelve `rate_limited` y `retry_after_seconds` para que el scheduler espere fuera. Un fallo posterior conserva los registros ya obtenidos, `complete=false` y el cursor. Un cursor repetido corta el bucle.

## Pruebas

Entorno propio del worktree (`.venv`), sin `.env` del checkout principal y sin Docker.

```text
uv run pytest tests/intelligence -q --tb=short
33 passed, 1 skipped in 0.54s
uv run ruff check src/alaira_warden/intelligence tests/intelligence
All checks passed
```

La prueba omitida es `tests/intelligence/test_live_probe.py`. Solo corre con `WARDEN_INTELLIGENCE_PROBE=1` y consulta OSV público (`lodash` 4.17.20). No se ejecutó en esta entrega. No hay llamada real acreditada.

Las 33 pruebas usan transporte inyectado: respuesta válida y campos opcionales ausentes, JSON inválido, forma inesperada, timeout, 401/403, 429 corto y 429 demasiado largo, 503 con reintento, paginación, presupuesto agotado, cursor repetido, alias entre fuentes, revisiones, ambigüedad, NVD/KEV sin paquete npm, ausencia en KEV con `known_exploited=None`, y un secreto o cuerpo de error que no aparece en la excepción ni en el volcado.

## Dependencias y configuración

No hace falta mover `httpx` a runtime: este módulo no lo importa. No hay dependencia nueva ni cambio de `uv.lock`.

El integrador debe pasar los secretos como argumentos, no dejar que el módulo lea `Settings` ni `.env`:

- `github_token`: opcional. Cabecera `Authorization: Bearer`. Sin token, el cupo público es 60 peticiones/hora.
- `nvd_api_key`: opcional. Cabecera `apiKey`. Sin clave, 5 peticiones por ventana de 30 s; con clave, 50. Nunca va en la URL.

Variables ya previstas: `WARDEN_GITHUB_TOKEN`, `WARDEN_NVD_API_KEY`. OSV y KEV no usan clave.

## Documentación y cuotas consultadas el 2026-10-26

Estas cifras salen de la documentación oficial leída ese día. Configurar una clave no verifica la conexión.

- GitHub Global Advisories, API `2022-11-28`: <https://docs.github.com/en/rest/security-advisories/global-advisories>. Sin `type`, solo avisos revisados; el malware exige `type=malware`. `per_page` máximo 100. Paginación por `Link` / `after`.
- Cupos REST: <https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>. 60/h sin autenticar; 5 000/h con token personal. Hay límites secundarios que también responden 403 o 429.
- OSV API v1: <https://google.github.io/osv.dev/post-v1-query/>, <https://google.github.io/osv.dev/post-v1-querybatch/> y <https://google.github.io/osv.dev/faq/>. El FAQ dice que no hay rate limit y que HTTP/1.1 corta a 32 MiB. `querybatch` devuelve id y `modified`. La paginación usa `next_page_token`.
- NVD: <https://nvd.nist.gov/developers/start-here> y <https://nvd.nist.gov/developers/vulnerabilities>. API 2.0. Ventanas de fechas de como máximo 120 días consecutivos. Recomiendan no mantener el repositorio local más de una vez cada dos horas y dormir unos seis segundos entre peticiones. La clave va en cabecera. Texto obligatorio: “This product uses data from the NVD API but is not endorsed or certified by the NVD.”
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> y el feed JSON público. No hay API de delta.

## SQL propuesto

Las tablas `advisories` y `advisory_revisions` bastan. `persist_records` no crea tablas. El rol `warden_app` ya tiene `INSERT`/`SELECT` sobre ellas en `003_runtime_permissions.sql`. No hace falta un `GRANT` nuevo para esa escritura.

El cursor no se guarda solo. Propuesta opcional, para que el integrador la numere en `migrations/`; este frente no la aplica:

```sql
CREATE TABLE intelligence_cursors (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Si el rol warden_app ya existe cuando se aplique la migración:
GRANT SELECT, INSERT, UPDATE ON intelligence_cursors TO warden_app;
```

`ON CONFLICT (advisory_id, content_hash) DO NOTHING` no actualiza un payload ya guardado. `changes` no entra en el hash: persistir un CVE antes de completar el historial deja esa revisión sin los eventos posteriores. Persistir cuando `complete` es verdadero, o guardar el historial en otra revisión solo si el origen cambió.

La fila `advisories.aliases` se sustituye por los alias del registro más reciente. El historial sigue en `advisory_revisions.payload`.

## Qué debe montar el integrador

1. Llamar a estas funciones desde el worker o la ruta de consulta manual. No registrar un adaptador de producción dentro de `integrations.py` desde este frente: el catálogo puede seguir en `not_implemented` hasta que el integrador conecte estos clientes y deje `verified` en falso hasta una llamada real.
2. Pasar `github_token` y `nvd_api_key` desde `Settings` sin devolverlos en la API.
3. Programar `default_sync_plan`: GitHub cada hora con `updated>=` y ambos tipos; NVD como máximo cada dos horas, con espera de unos seis segundos entre peticiones; KEV cada hora comparando `catalog_unchanged`; OSV bajo demanda por paquete/versión del inventario, no como volcado. Respetar 60 peticiones/hora si GitHub va sin token.
4. Encadenar `next_cursor` con `resume` dentro del mismo `WorkBudget` del caso. Un `Retry-After` largo se espera fuera de la llamada.
5. `persist_records(connection, batch.records)` dentro de la transacción del repositorio. No abrir otra base en el import.
6. Aceptar `source="manual"` y un aviso sin CVE.
7. Mostrar el aviso de NIST junto a los datos NVD. No presentar la licencia de OSV como SPDX de cada registro: el FAQ consultado no trae una licencia por registro y `license` queda null salvo que el JSON la traiga.
8. Tratar `evidence_class="preliminary"` y `independent_report_count=1` como una sola línea de reporte aunque haya varias fuentes. No promover eso a evidencia confirmada ni a exposición.
9. No convertir CPE ni `vendorProject`/`product` de KEV en nombre npm. `affected=[]` con advertencia es el resultado correcto.
10. Una ausencia en KEV, un 404 o un lote vacío no significan que no haya vulnerabilidad ni explotación. `consultation_report` ya lo deja en `unverified`.
11. No descargar `references`. La UI puede mostrarlas como enlaces.
12. Opcional: crear `intelligence_cursors` con el SQL de arriba.

## Límites

- Lectura pública únicamente. Una URL de cursor hacia `/repos/...` o hacia otro host se rechaza.
- OSV no tiene cursor `modified_since` en la API de consulta. El CSV de cambios del bucket no se descarga.
- KEV se baja entero. Filtrar por `dateAdded` no es un delta: un cambio de `dueDate` en un CVE antiguo no aparece.
- Los redirects se rechazan para no reenviar `Authorization`.
- Un identificador ambiguo se declara y el grupo se conserva. No hay fusión por título parecido.
- `group_advisories` no devuelve `confirmed`.
- La sonda pública no se ejecutó. No declarar las fuentes como verificadas en el catálogo de adaptadores.
