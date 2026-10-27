# Handoff — Modelos y patrocinadores

## Objetivo

Clientes tipados para Meterless, NVIDIA y Zetaris bajo `ProviderCheck` / `ModelResult` v1. Cubren WBS 1.1.2 (contrato identificado, acceso real pendiente), 1.5.2 y 1.5.3 (adaptadores y validación de salida, sin operación real) y 1.12.2 (consulta de lectura acotada, sin instancia). Grok y Cursor programático no se activan.

La integración obligatoria no está completa: en este entorno no había credenciales y no se ejecutó ninguna llamada a un proveedor.

## Contrato elegido

Se implementa el contrato publicado en el repositorio oficial, documento `docs/agent-ready/add-meterless-provider.md`, etiquetado **Meterless Runtime 0.90.0** (consulta 2026-10-26). La licencia del repositorio es Apache 2.0. Nightshift es un producto aparte; este cliente no lo descarga ni lo arranca.

`https://meterless.ai/engines.html` embebe un prompt posterior etiquetado Runtime 1.4 / contract v4. Las reglas comunes coinciden: base `<origen>/v1`, bearer, `meterless-app`, `meterless-scope: user` solo en chat, modos `meterless/*`, `GET /healthz` no acredita autenticación y `GET /v1/models` decide el acceso. No se implementaron las piezas que solo aparecen en ese prompt: autodetección de puertos, enlace `/connect#k=`, rutas `/v1/meterless/*`, medios y 3D.

NVIDIA usa solo el host documentado `https://integrate.api.nvidia.com` y `POST /v1/chat/completions`, con bearer HTTP (`securitySchemes.Token` del OpenAPI de NIM). El índice de LLM APIs no documenta `GET /v1/models` en ese host, así que no se llama. El candidato documentado el 2026-10-26 es `meta/llama-3.1-8b-instruct` (índice y página `meta-llama-3_1-8b-infer`). El llamador debe pasarlo; no hay modelo por defecto ni sustitución. Su tarjeta indica Llama 3.1 Community License. La API de NVIDIA sigue las condiciones de NVIDIA.

Zetaris queda condicionado. El SRS lo condiciona al desafío y al acceso; la evaluación de factibilidad pide confirmar el track antes de volverlo obligatorio y, mientras tanto, tratar el acceso como dependencia preventiva. Wildcard lo cita como exigido. Este cliente no declara esa obligación cerrada.

La API verificada es:

- Login: `GET /api/v1.0/auth/login`, Basic, `X-Request-ID`, `X-Org-ID`. Fuente: guía oficial “Accessing Zetaris using API”.
- Lectura: `POST /api/v1.0/sql-editor/sqls/run-query` con `{"sql": "..."}` y bearer. Fuente: ejemplo oficial de “Pipeline Scheduling”, que describe la respuesta con `headers` y `data`.
- Redoc `https://api.saas.enterprise.zetaris.com/redoc/index.html` respondió solo “Loading…” y no aportó un esquema utilizable. No se inventó otra ruta. El nombre `OpenSqlQuery` de la colección Postman antigua no incluye path en la página recuperada, así que no se llama.

No hay una edición ni una URI única. La guía SaaS apunta a `api.saas.enterprise.zetaris.com`, el ejemplo de pipeline a `api.enterprise.zetaris.com`, y la guía Postman a una URI de instancia. El cliente exige el origen explícito y HTTPS.

`WARDEN_ZETARIS_API_KEY` corresponde al bearer de consola de la guía actual. No sustituye la URL, el org id, el usuario ni la contraseña. El `idToken` del login no se reutiliza como clave de consulta ni se devuelve.

## Evidencia

| Proveedor | Documentación verificada | Mock ejecutado | Operación real |
|---|---|---|---|
| Meterless | Sí, contrato 0.90.0 y contraste con engines.html | Sí, transporte inyectado y redirect local sin seguimiento | Pendiente. `WARDEN_METERLESS_API_KEY` y `WARDEN_METERLESS_BASE_URL` ausentes en el entorno del proceso. No se leyó ningún `.env`. |
| NVIDIA | Sí, índice LLM APIs, infer de Llama 3.1 8B y esquema bearer | Sí, transporte inyectado | Pendiente. `WARDEN_NVIDIA_API_KEY` y `WARDEN_NVIDIA_BASE_URL` ausentes. No se hizo inferencia facturable. |
| Zetaris | Parcial: login y `run-query` en la base de conocimiento; Redoc sin esquema | Sí, transporte inyectado | Pendiente. No hay URL, org id ni clave en el entorno. |

Bloqueo exacto de la prueba real: el proceso no tiene esas variables. Una clave presente en otro proyecto no se buscó ni se copió.

## Archivos y base

- Base: `6bb1828`. Rama: `codex/front-providers`.
- `src/alaira_warden/providers/**`
- `tests/providers/test_clients.py`
- Este handoff.

No se editaron `pyproject.toml`, `.env.example`, configuración, adaptadores, API, UI, migraciones ni LangGraph. No hace falta `httpx` en runtime: el transporte real es `http.client` y no sigue redirecciones. `httpx` puede seguir en el grupo dev del scaffold; este frente no lo usa.

## API pública

`MeterlessClient(base_url, api_key, transport=None, max_attempts=1)`

- `check(operation="models"|"health") -> ProviderCheck`
- `generate_text(model, prompt, max_output_tokens, timeout=180) -> ModelResult`
- `generate_investigation(model, task, evidence, max_output_tokens, timeout=180) -> ModelResult`

`NvidiaClient(base_url, api_key, transport=None, max_attempts=1)`

- `check(model, timeout) -> ProviderCheck`. Es una completion acotada, facturable contra la API real, porque no hay health documentado en ese host.
- `generate_text` y `generate_investigation` exigen `model` y `timeout`.

`ZetarisClient(base_url, org_id, api_key="", username="", password="")`

- `check() -> ProviderCheck` para `auth.login`. No demuestra SQL.
- `query(statement, timeout=30) -> ZetarisQueryResult`. Solo un `SELECT` o `WITH` sin comentarios, con un único `LIMIT` de 1 a 100. No escribe PostgreSQL ni estado de Warden.

Ejemplo de descubrimiento Meterless, sin generación:

```python
check = MeterlessClient(base_url="http://127.0.0.1:8088", api_key=token).check("models")
# status available, capabilities ["meterless/auto", ...], verified True
# operation "models"; no acredita generate_text
```

Ejemplo de texto NVIDIA. El uso ausente queda `None`, no cero:

```python
result = NvidiaClient(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=key,
).generate_text(
    model="meta/llama-3.1-8b-instruct",
    prompt="Reply with the single word pong.",
    max_output_tokens=16,
    timeout=30,
)
# result.usage is None cuando el proveedor no envía usage
```

Ejemplo de lectura Zetaris:

```python
rows = ZetarisClient(
    base_url="https://instance.example",
    org_id="org",
    api_key=key,
).query("SELECT id FROM synthetic.events LIMIT 2")
# rows.sources == ["synthetic.events"]; no es un hallazgo
```

Estados de `ProviderCheck`: `unconfigured`, `unauthorized`, `forbidden`, `offline`, `available`, `unsupported`. `available` solo cubre la operación nombrada y exige `verified=True`. El placeholder publicado `rt-local` se rechaza localmente como `unauthorized`. 401 y 403 no se colapsan: el prompt de Meterless los muestra igual en la UI, pero aquí siguen siendo estados distintos y ninguno es `offline`. Un 200 de modelos sin ids `meterless/*` es `unsupported`, no `offline`.

`ModelResult.warnings` recuerda que el texto es una propuesta, no evidencia. La investigación acepta hechos, hipótesis, referencias, limitaciones y propuestas. Una URL que no esté en la evidencia entregada se rechaza. Un campo `exposure`, un veredicto explícito de exposición confirmada o `tool_calls` producen `invalid_output`.

Errores que no son un `ProviderCheck`: `timeout`, `rate_limited`, `invalid_response`, `redirect_blocked`, `invalid_output`. 429 se reintenta como máximo 3 veces y por defecto 1, sin esperas de 2/4/8 s. 5xx y timeout no se reintentan. `max_output_tokens` admite de 1 a 1024. El timeout de Meterless no pasa de 180 s; NVIDIA, 120 s; Zetaris, 60 s.

## Pruebas

`PYTHONPATH=src python -m pytest tests/providers -q` → 13 passed. Son offline. El transporte de stdlib se probó contra un `302` en `127.0.0.1`; no siguió el `Location` hacia NVIDIA. No hubo llamada a Meterless, NVIDIA ni Zetaris.

## Configuración pedida, sin valores

Ya existentes en el scaffold: `WARDEN_METERLESS_BASE_URL`, `WARDEN_METERLESS_API_KEY`, `WARDEN_NVIDIA_BASE_URL`, `WARDEN_NVIDIA_API_KEY`, `WARDEN_ZETARIS_API_KEY`.

Hay que añadir en `config.py` y `.env.example`, que este frente no puede editar:

- `WARDEN_ZETARIS_BASE_URL`
- `WARDEN_ZETARIS_ORG_ID`
- `WARDEN_ZETARIS_USERNAME`
- `WARDEN_ZETARIS_PASSWORD`

`WARDEN_NVIDIA_BASE_URL`, cuando exista acceso, debe ser `https://integrate.api.nvidia.com` o la misma URL con `/v1`. La clave de NVIDIA solo se envía a `integrate.api.nvidia.com`. Meterless acepta HTTP únicamente en loopback; el default documentado del runtime es `http://127.0.0.1:8088/v1`, pero el cliente no lo asume si la URL viene vacía. El token sale de `<stateDir>/proxy-token`, no de `rt-local`.

No hay propuesta SQL ni migración.

## Cambios para el integrador

1. No marcar Meterless, NVIDIA ni Zetaris como verificados en `integrations.py` ni habilitar `adapters.invoke` hasta repetir una operación real con texto o SQL sintético. Un secreto configurado sigue sin ser una conexión.
2. Añadir los cuatro nombres Zetaris anteriores. No copiar `.env` de otro checkout.
3. No mover `httpx` a las dependencias de runtime por este frente.
4. Dejar Grok y Cursor programático condicionales.
5. Presupuesto sugerido para el primer probe real: una completion, `max_output_tokens` 16, prompt sintético, sin código privado. Para Zetaris, un `SELECT` con `LIMIT` sobre una fuente de prueba autorizada. No publicar PostgreSQL.
6. Registrar el modelo NVIDIA que la cuenta pueda usar. Si `meta/llama-3.1-8b-instruct` responde 404 o 422, el cliente devuelve `unsupported` y no cambia de modelo.
7. Confirmar en el portal del hackathon si el track principal exige Zetaris. Este handoff no cierra esa decisión.

## Límites

No hay autodetección de red, streaming, herramientas, medios, 3D ni polling de HTTP 202. Una parte de contenido que no sea un string se rechaza. La ruta Meterless no se usa para llegar a NVIDIA. La forma `headers`/`data` de Zetaris depende del ejemplo de la base de conocimiento; si la instancia responde otro esquema, la llamada falla como `invalid_response` en lugar de inventar columnas.
