# Handoff — Identidad y autorización

## Objetivo y límites

El paquete `alaira_warden.identity` decide quién es el actor y si una acción está permitida. Cubre la base de WBS 1.2.3 y el contrato v1 del roadmap (`Principal`, `authorize`, `audit_actor`). No cierra RF-35: no ata la aprobación a un artefacto, no invalida una aprobación (RF-36) y no publica el pull request. Esas comprobaciones siguen en el bundle del integrador; este módulo solo responde si el actor actual puede `approval.decide` en esa aplicación.

Tampoco monta rutas en `main.py`, no aplica DDL y no sustituye el literal `local-developer` en `repository.py`. Esas tres conexiones están especificadas abajo.

Roles del SRS, con identificador estable:

| SRS | Identificador |
|---|---|
| Administrador | `administrador` |
| Analista de seguridad | `analista` |
| Desarrollador / DevSecOps | `desarrollador` |
| Aprobador | `aprobador` |
| Auditor | `auditor` |

Una persona puede acumular varias asignaciones. La autoridad es la lista `assignments` cargada en el servidor. Los campos `roles`, `application_ids` y `platform_roles` se derivan de esa lista y no conceden nada por sí solos. Una asignación con `application_id` nulo es ámbito de plataforma explícito: no es la consecuencia de presentar un token válido.

## Matriz v1

Denegar es el resultado de toda acción desconocida, de una identidad inactiva y de una asignación ausente. Un administrador de una sola aplicación no administra la plataforma ni otra aplicación.

| Acción | Ámbito | administrador | analista | desarrollador | aprobador | auditor |
|---|---|---|---|---|---|---|
| `application.read` | aplicación | sí | sí | sí | sí | sí |
| `inventory.read` | aplicación | sí | sí | sí | sí | sí |
| `inventory.refresh` | aplicación | sí | no | sí | no | no |
| `investigation.read` | aplicación | sí | sí | sí | sí | sí |
| `investigation.create` | aplicación | sí | sí | no | no | no |
| `investigation.review` | aplicación | sí | sí | no | no | no |
| `patch.prepare` | aplicación | sí | no | sí | no | no |
| `approval.decide` | aplicación | sí | no | no | sí | no |
| `pull_request.publish` | aplicación | sí | no | no | sí | no |
| `audit.read` | aplicación, o plataforma si `application_id` es nulo | sí | no | no | no | sí |
| `application.create` | plataforma | sí | no | no | no | no |
| `settings.manage` | plataforma | sí | no | no | no | no |

`settings.manage` es también la puerta de alta, emisión y revocación de identidades. No hay registro público.

Estas acciones quedan prohibidas para todos los roles, incluido el administrador de plataforma (RF-37). El integrador debe consultarlas antes de cualquier herramienta que pudiera fusionar, desplegar, cambiar infraestructura o leer secretos:

- `change.merge`
- `change.deploy`
- `infrastructure.change`
- `secret.manipulate`

`authorize(principal, action, application_id)` devuelve `Decision.allowed` verdadero solo con `reason="allowed"`. `fail_closed` convierte cualquier excepción en denegación.

### Ámbito que ve el cliente

| Situación | HTTP | Cuerpo |
|---|---|---|
| Sin credencial, credencial mal formada, desconocida o revocada | 401 | `Authentication required.` |
| Identidad inactiva, o rol asignado a esa aplicación pero sin la acción | 403 | `Forbidden.` |
| La aplicación no está en las asignaciones del actor, exista o no el registro | 404 | `Not found.` |
| El actor podría actuar, pero el registro no existe | 404 | `Not found.` |
| El actor podría actuar y el callback de existencia falla o no se proporcionó | 503 | `Identity store unavailable.` o `Identity policy is incomplete.` |
| Acción de plataforma denegada | 403 | `Forbidden.` |

`enforce_application` solo llama al callback de existencia después de un permiso explícito. Un actor de la aplicación A no provoca la lectura de B. El identificador de ruta es el recurso: `application_scope_id` ignora un `application_id` repetido en el cuerpo. Los campos `roles`, `subject_id` y `actor` del cliente no se consultan.

Las listas deben usar `select_visible`. `ApplicationScope.unrestricted` es verdadero solo cuando un rol de plataforma permite esa acción. Una lista vacía de `application_ids` con `unrestricted=False` significa cero filas, no todas las filas.

## Credenciales

Cada credencial es `wdn_` más `secrets.token_urlsafe(32)` (256 bits). Se guarda solo el HMAC-SHA256 en hexadecimal, con un pepper de al menos 16 bytes que no vive en PostgreSQL. La comparación usa `hmac.compare_digest`. El texto completo sale una vez, en el valor de retorno de la emisión; `IssuedCredential.model_dump()` lo enmascara. Revocar escribe `revoked_at` y la credencial deja de autenticar. No hay contraseñas, OAuth ni JWT.

`provision_initial_administrator` solo funciona con el almacén vacío. Exige un nombre y genera la credencial; no tiene secreto fijo ni ruta HTTP. En cuanto existe un sujeto, queda cerrada. Las altas posteriores exigen un principal con `settings.manage`.

## Token compartido de desarrollo

`IdentitySettings.mode` vale `individual` por defecto.

- En `individual`, un bearer igual a `shared_development_token` responde 401 y no consulta el almacén, aunque ese mismo secreto esté guardado como credencial de un administrador.
- `development_shared` solo se construye si `environment` es `development` o `test`, el token tiene al menos 16 caracteres y las asignaciones son de aplicación y no incluyen `administrador`. Sin asignaciones, el token autentica y no autoriza nada.
- Si el modo de desarrollo está activo y el bearer es una credencial individual distinta, se resuelve esa credencial. El token compartido no hereda los roles encontrados en la base.
- Los dos modos no se apilan. No dejes `require_token` como dependencia exterior del router: un token compartido válido satisfaría esa capa y no llegaría a esta decisión.

Sujeto fijo del modo de desarrollo: `00000000-0000-4000-8000-0000000000d1`. `authentication_method` es `development_shared_token`. No es un administrador.

## Auditoría

`audit_actor(principal)` devuelve `subject:<uuid>`. No incluye el token, el digest, el nombre ni los roles: el nombre no demuestra ámbito. `operation_actor` ignora el actor enviado por el cliente, incluido `local-developer`. `audit_event` elimina claves sensibles y cualquier cadena que contenga `wdn_`.

Cambio requerido en `repository.py`, sin valor por defecto:

```python
def create_application(self, application: ApplicationCreate, *, actor: str) -> dict:
    if not actor.startswith("subject:"):
        raise RuntimeError("Audit actor must come from audit_actor(principal).")
    ...
    connection.execute(
        "INSERT INTO audit_events (entity_id, actor, action) VALUES (%s, %s, %s)",
        (row["id"], actor, "application.created"),
    )
```

El mismo parámetro `actor` sustituye `"local-developer"` en `create_investigation`. La ruta calcula `actor=audit_actor(principal)` después de autorizar. No añadas `actor` a `ApplicationCreate` ni a `InvestigationCreate`. No escribas el cuerpo de la petición ni cabeceras en `audit_events`.

La bitácora sigue siendo de solo inserción para `warden_app` (RF-44 queda para el integrador: este frente aporta el actor, no la prueba de que nadie reescribe eventos).

## Envío a modelos (RNF-05)

`authorize_model_dispatch` no llama a ningún proveedor. La política por defecto es `deny`, también para el administrador de plataforma. Para permitir hacen falta, a la vez:

- `policy="allow_minimized"`;
- `destination` dentro de `approved_destinations` (un conjunto vacío deniega);
- campos no vacíos y solo entre `case_id`, `finding_ids`, `package_names` y `versions`;
- `investigation.read` sobre esa `application_id`.

Si se deniega, `permitted_fields` queda vacío. Un fallo de la función también deniega. El integrador debe abortar el envío salvo `allowed is True` y no debe añadir código, diff ni secretos al contexto.

## Propuesta SQL

El texto normativo es `PROPOSED_IDENTITY_DDL` en `src/alaira_warden/identity/sql.py`. Importarlo no abre conexiones ni ejecuta DDL. Aplicarlo como migración nueva, posterior a `003`; esa migración ya no se reejecuta, así que los `GRANT` tienen que ir en la migración nueva. El bloqueo de provisión inicial es `817403`, distinto del `817402` de las migraciones.

```sql
-- Identity and authorization (WBS 1.2.3). Apply as a new migration after 003.
-- Do not store API credentials in plaintext. token_hash is HMAC-SHA256 (hex).
-- The pepper stays outside PostgreSQL. Importing the identity package does not run this script.

CREATE TABLE identity_subjects (
    id UUID PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity_assignments (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES identity_subjects (id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (
        role IN ('administrador', 'analista', 'desarrollador', 'aprobador', 'auditor')
    ),
    application_id UUID NULL REFERENCES applications (id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NULL application_id is an explicit platform-wide assignment, not "any token".
CREATE UNIQUE INDEX identity_assignments_application_uidx
    ON identity_assignments (subject_id, role, application_id)
    WHERE application_id IS NOT NULL;

CREATE UNIQUE INDEX identity_assignments_platform_uidx
    ON identity_assignments (subject_id, role)
    WHERE application_id IS NULL;

CREATE INDEX identity_assignments_subject_idx ON identity_assignments (subject_id);
CREATE INDEX identity_assignments_application_idx ON identity_assignments (application_id);

CREATE TABLE identity_credentials (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES identity_subjects (id) ON DELETE RESTRICT,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    label TEXT NOT NULL CHECK (length(trim(label)) BETWEEN 1 AND 120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ NULL,
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX identity_credentials_subject_idx ON identity_credentials (subject_id);

REVOKE ALL ON identity_subjects, identity_assignments, identity_credentials FROM PUBLIC;

-- 003 already ran, so new tables need their own grants. Do not grant UPDATE on token_hash.
REVOKE ALL ON identity_subjects, identity_assignments, identity_credentials FROM warden_app;
GRANT SELECT, INSERT ON identity_subjects TO warden_app;
GRANT UPDATE (is_active) ON identity_subjects TO warden_app;
GRANT SELECT, INSERT, DELETE ON identity_assignments TO warden_app;
GRANT SELECT, INSERT ON identity_credentials TO warden_app;
GRANT UPDATE (revoked_at) ON identity_credentials TO warden_app;
```

`warden_app` puede leer el digest porque tiene que buscarlo. Sin el pepper, el digest no autentica. No concedas `UPDATE` de `token_hash` ni `DELETE` de credenciales: la revocación conserva la fila.

`PostgresIdentityStore` recibe una conexión ya abierta con `row_factory=dict_row`. No llama a `psycopg.connect` ni crea tablas. Un error de PostgreSQL se traduce a un fallo cerrado; la respuesta HTTP no incluye el mensaje del driver.

## Configuración que hay que añadir

No hay dependencias nuevas. El integrador puede extender `Settings` así, sin inventar un valor por defecto del pepper:

- `WARDEN_IDENTITY_MODE`: `individual` (despliegue) o `development_shared` (solo entorno local).
- `WARDEN_IDENTITY_PEPPER`: secreto de al menos 16 bytes, distinto de la contraseña de la base. Rotarlo invalida todas las credenciales.
- `WARDEN_API_TOKEN`: solo se consulta si el modo es `development_shared`. En `individual` se ignora.
- `WARDEN_ENV`: `development_shared` rechaza cualquier valor que no sea `development` o `test`.

Construcción:

```python
from pydantic import SecretStr
from alaira_warden.identity import IdentitySettings

identity_settings = IdentitySettings(
    mode=settings.warden_identity_mode,
    environment=settings.warden_env,
    credential_pepper=settings.warden_identity_pepper,
    shared_development_token=settings.warden_api_token,
)
```

Si el modo individual no tiene pepper, `IdentitySettings` no se construye. Eso debe tumbar el arranque, no abrir la API.

Alta inicial, una vez, desde un proceso de operación y no desde una ruta:

```python
from alaira_warden.db import connect
from alaira_warden.identity import PostgresIdentityStore, provision_initial_administrator

with connect(settings) as connection:
    issued = provision_initial_administrator(
        PostgresIdentityStore(connection),
        display_name="Nombre del administrador",
        pepper=settings.warden_identity_pepper.get_secret_value().encode(),
    )
token = issued.reveal_token()  # entregar una vez; no registrar este valor
```

Hay que hacerlo después de la migración y antes de exponer la API. La función deja de operar en cuanto existe cualquier sujeto.

## Montaje FastAPI

Quita `dependencies=[Depends(require_token)]` del `APIRouter` de `/api`. Conserva `/health/live` y `/health/ready` sin identidad. El router `create_identity_router` no está incluido en `create_app`; móntalo tú bajo el mismo proceso, después de poder abrir la conexión:

```python
from fastapi import Depends, HTTPException
from alaira_warden.db import connect
from alaira_warden.identity import (
    IdentityAuth,
    PostgresIdentityStore,
    audit_actor,
    authorize,
    enforce_application,
    enforce_platform,
    select_visible,
)
from alaira_warden.identity.http import create_identity_router


def get_identity_auth(request: Request):
    with connect(request.app.state.settings) as connection:
        yield IdentityAuth(PostgresIdentityStore(connection), request.app.state.identity_settings)


Identity = Annotated[IdentityAuth, Depends(get_identity_auth)]
```

Incluye `create_identity_router(auth)` solo con esa dependencia de conexión, no detrás del token compartido. Sus mutaciones ya exigen `settings.manage`. Respuestas de identidad: `Cache-Control: no-store`.

Sustitución de los endpoints actuales:

```python
@api.get("/applications")
def applications(auth: Identity, store: Store):
    principal = auth.require_principal(...)  # o Depends(auth.require_principal)
    rows = store.applications()
    return select_visible(rows, principal, "application.read", key="id")

@api.post("/applications", status_code=201)
def create_application(payload: ApplicationCreate, auth: Identity, store: Store, principal=Depends(...)):
    enforce_platform(principal, "application.create")
    return store.create_application(payload, actor=audit_actor(principal))

@api.get("/investigations")
def investigations(...):
    rows = store.investigations()
    return select_visible(rows, principal, "investigation.read", key="application_id")

@api.post("/investigations", status_code=201)
def create_investigation(payload: InvestigationCreate, ...):
    def exists(application_id):
        return store.application(application_id) is not None  # método nuevo del integrador
    enforce_application(principal, "investigation.create", payload.application_id, exists)
    return store.create_investigation(payload, actor=audit_actor(principal))

@api.get("/investigations/{identifier}")
def investigation(identifier: UUID, ...):
    case = store.investigation(identifier)
    if case is None:
        raise HTTPException(404, "Not found.")
    enforce_application(principal, "investigation.read", case["application_id"], lambda _id: True)
    return case

@api.post("/investigations/{identifier}/preview")
def preview(...):
    case = store.investigation(identifier)
    if case is None:
        raise HTTPException(404, "Not found.")
    enforce_application(principal, "investigation.read", case["application_id"], lambda _id: True)
    return app.state.workflow.invoke(...)
```

`GET /api/integrations` describe configuración de conectores: protégelo con `enforce_platform(principal, "settings.manage")`. No devuelvas secretos.

En el preview, autoriza antes de invocar el grafo. En una aprobación futura, `authorize(principal, "approval.decide", application_id)` es necesario y no suficiente: el integrador sigue teniendo que comparar el digest del artefacto, guardar justificación y fecha, y rechazar la decisión si el diff, el commit o el destino cambiaron.

Cualquier herramienta de merge, despliegue, infraestructura o secretos debe llamar `authorize` con la acción prohibida correspondiente y abortar. Un `allowed is False` o una excepción es denegación.

## Pruebas

Ejecutadas con `PYTHONPATH=src` y `python -m pytest tests/identity -q` en este worktree. Resultado: 171 passed, 1 skipped. El almacén es memoria controlada. No se usó el PostgreSQL de demostración. La prueba SQL queda omitida salvo que exista `WARDEN_IDENTITY_TEST_DATABASE_URL` y el nombre de la base termine en `_test`; en ese caso crea y borra el esquema `identity_front_trial`.

Cubren la matriz de cada rol, la aplicación ajena, la identidad inactiva, la asignación ausente, el auditor sin altas ni aprobaciones, el desarrollador sin `approval.decide`, credencial desconocida o revocada, ausencia del secreto en respuestas y auditoría, el actor `subject:<uuid>`, el fallo de almacén como 503 y el token de desarrollo que no salta el modo individual.

## Archivos

- `src/alaira_warden/identity/` — decisión, credenciales, almacén, provisión, HTTP y DDL propuesto.
- `tests/identity/` — pruebas negativas.
- `docs/handoffs/identity.md` — este documento.

No se modificaron `main.py`, `repository.py`, `migrations/` ni la configuración global.
