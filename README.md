# ALAIRA Warden

Scaffold del sistema multiagente de inteligencia y respuesta defensiva ante vulnerabilidades.

**Estado:** integración local operativa por API: identidad individual y permisos por aplicación, inventario npm por commit, clientes GitHub/OSV/NVD/KEV, evidencia persistente, correlación determinista y reanudación LangGraph. La UI conserva el scaffold consolidado; las operaciones nuevas están en Swagger. Todavía no genera parches ni cumple las integraciones reales de patrocinadores.

[Guía del flujo integrado](docs/front-integration.md) · [Requisitos corregidos del hackathon](docs/hackathon-alignment.md)

## Requisitos

- Python 3.12 y `uv` para desarrollo local.
- Docker con su motor iniciado para PostgreSQL o para ejecutar toda la aplicación.
- Node.js 22 y npm para el motor de rangos del backend. La interfaz usa HTML/CSS/JS nativos y no requiere compilación de frontend.

Las dependencias Python se encuentran en `pyproject.toml`; `uv.lock` fija las versiones resueltas. Los componentes nuevos de implementación son open source. Los proveedores externos siguen el alcance acordado en el SRS.

El ejecutor Docker offline, la correlación y los checkpoints PostgreSQL están implementados. La composición de los cuatro frentes se encuentra en `integration/`; la investigación usa las rutas `/runs`, conserva la revisión humana y falla de forma explícita ante información incompleta. Evidencia y límites en [B1](docs/bundle-execution.md), [B2](docs/bundle-correlation.md) y [B3](docs/bundle-orchestration.md).

## Arranque con Docker

Desde la raíz del repositorio, en PowerShell:

```powershell
python scripts/bootstrap.py
```

El script crea `.env` con credenciales aleatorias y conserva cualquier archivo existente. Incluye `WARDEN_IDENTITY_PEPPER`; las instalaciones existentes deben configurarlo sin cambiar otros secretos. El token compartido ya no da acceso a la API. Luego:

```powershell
docker compose up -d --build --wait api
```

Provisiona la identidad administradora una sola vez y copia su credencial sin mostrarla:

```powershell
docker compose exec -T api python -m alaira_warden.identity.bootstrap /tmp/warden-admin.token
New-Item -ItemType Directory -Force artifacts/private | Out-Null
docker compose cp api:/tmp/warden-admin.token artifacts/private/administrator.token
docker compose exec -T api python -c "from pathlib import Path; Path('/tmp/warden-admin.token').unlink()"
```

Abre [la aplicación](http://localhost:8000) e introduce la credencial del archivo en el formulario de acceso. El almacén de identidades debe estar vacío para este primer aprovisionamiento; no lo repitas si ya lo realizaste. PostgreSQL utiliza un volumen local y `migrate` aplica las migraciones antes de arrancar la API. El migrador usa `warden_owner` y la API `warden_app`, que no puede editar auditoría ni ejecutar migraciones.

Si cambias contraseñas manualmente, usa valores aptos para una URL PostgreSQL o codifícalos. Cambiar una variable después de crear el volumen no cambia la contraseña del usuario existente. Consulta [la guía de infraestructura](docs/infrastructure.md) para puertos alternativos, roles, respaldo y operación.

## Desarrollo local

Completa primero `.env` como se indica arriba.

```powershell
uv sync --frozen
npm ci --ignore-scripts
docker compose -f compose.yaml -f compose.dev.yaml up -d db
uv run python -m alaira_warden.db
uv run python scripts/provision_identity.py  # una sola vez, almacén de identidades vacío
uv run uvicorn alaira_warden.main:app --reload --host 127.0.0.1 --port 8000
```

Las migraciones son explícitas; importar o arrancar la API no crea ni altera tablas. Ejecuta el comando de migración desde la raíz. Una migración aplicada no debe editarse: agrega el siguiente archivo numerado. Se comprueba su huella y se serializa la ejecución mediante un bloqueo transaccional.

Sin PostgreSQL, la página inicial y `/health/live` funcionan; `/health/ready` y las operaciones persistentes responden `503`. No se usan datos ficticios ni una base alternativa silenciosa.

## Comprobaciones

```powershell
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
node --check src/alaira_warden/static/app.js
docker compose config --quiet
```

Las pruebas actuales cubren autenticación, degradación sin base de datos, validación de repositorios, estados de integraciones, preparación de configuración y detención segura del flujo de ejemplo. La prueba de integración requiere `WARDEN_TEST_DATABASE_URL` hacia una base independiente cuyo nombre termine en `_test`; comprueba migraciones, persistencia y permisos SQL. CI proporciona PostgreSQL efímero para ejecutarla y construye la imagen. Los criterios completos de aceptación del MVP siguen pendientes.

## Estructura

```text
src/alaira_warden/
  main.py                 API, rutas y archivos estáticos
  config.py               configuración desde variables/.env
  db.py                   conexión y ejecutor de migraciones
  models.py               contratos de entrada/salida
  repository.py           consultas PostgreSQL y transacciones
  integrations.py         inventario de adaptadores y referencias a secretos
  adapters.py             stubs que rechazan la invocación aunque haya credencial
  workflow.py             grafo inicial sin efectos externos
  observability.py        instrumentación FastAPI y exportación OTLP opcional
  execution/              ejecución offline con límites y artefactos no confiables
  correlation/            semántica npm/OSV y evaluación determinista de exposición
  static/                 interfaz inicial sin dependencias de frontend
migrations/               cambios SQL versionados
infra/                    inicialización PostgreSQL y configuración del colector
scripts/                  preparación local sin exponer secretos
tests/                    comprobaciones del scaffold
docs/                     arquitectura, contratos y verificación
.github/workflows/        comprobaciones CI
Dockerfile
compose.yaml
compose.dev.yaml
compose.observability.yaml
```

## API inicial

La documentación interactiva está en [Swagger](http://localhost:8000/docs). Las rutas `/api/` requieren `Authorization: Bearer <credencial individual>` y permiso para la acción/aplicación. El token compartido legado es rechazado.

| Método | Ruta | Función |
|---|---|---|
| GET | `/health/live` | Comprueba que la API responde. |
| GET | `/health/ready` | Comprueba conectividad y tablas requeridas. |
| GET | `/api/integrations` | Lista el alcance y estado pendiente de adaptadores. |
| GET / POST | `/api/applications` | Lista las últimas 100 aplicaciones o registra una. |
| GET / POST | `/api/investigations` | Lista los últimos 100 avisos o registra uno manualmente. |
| GET | `/api/investigations/{id}` | Recupera un aviso registrado. |
| POST | `/api/investigations/{id}/preview` | Ejecuta el grafo inicial sin escanear ni modificar el caso. |

La vista previa conserva su detención inicial y no representa el flujo operativo nuevo. La investigación integrada se ejecuta con `/runs`, documentado en la guía de integración. No cambia el estado persistido, no clasifica exposición, no llama modelos ni ejecuta código de repositorios.

## Integraciones y límites

Las variables se detallan en `.env.example`. GitHub y NVD admiten credenciales opcionales; OSV y KEV son públicos. Un secreto presente no demuestra una operación exitosa.

- **Obligatorios del hackathon:** Zetaris como capa de datos, Nightshift como proveedor principal y al menos un Meterless Engine funcional. Setup y aceptación real pendientes.
- **NVIDIA:** mediante Nightshift donde aporte; para el premio, Nemotron en una función operativa con el modelo identificado. La clave se configura en Nightshift Providers.
- **Cursor:** herramienta opcional de desarrollo; no se exige su API. Grok no es un requisito del evento suministrado.
- **Pendientes del producto:** Engine, interacción dinámica de agentes, Syft/Trivy/OSV-Scanner reales, corrección validada, aprobación y PR.

Modo de ejemplo sin credenciales ni Postgres: `uv run python scripts/sample_case.py` después de `npm ci`. Declara datos sintéticos y ausencia de uso de patrocinadores. No reemplaza sus pruebas reales.

## Documentos del proyecto

- [SRS](SRS-Alaira-Warden.md)
- [WBS del MVP](WBS-MVP-Alaira-Warden.md)
- [Arquitectura y próximos paquetes](docs/architecture.md)
- [Infraestructura y operación](docs/infrastructure.md)
- [Decisiones de arquitectura](docs/decisions.md)
- [Contratos de integración](docs/integrations.md)
- [Interfaz y flujo consolidado del MVP](docs/ui-scaffold.md)
- [Estado de verificación](docs/verification.md)
- [Aseguramiento de factibilidad y plan de entrega completa](docs/feasibility-assessment.md)
- [Roadmap secuencial y prompts de los cuatro frentes](docs/implementation-roadmap.md)
- [Bundle B1: ejecutor seguro](docs/bundle-execution.md)
- [Bundle B2: correlación](docs/bundle-correlation.md)


- [Conexión de los cuatro frentes y endpoints](docs/front-integration.md)
- [Ajuste de obligaciones del hackathon](docs/hackathon-alignment.md)
