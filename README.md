# ALAIRA Warden

Scaffold del sistema multiagente de inteligencia y respuesta defensiva ante vulnerabilidades.

**Estado:** estructura inicial ejecutable. Incluye API, interfaz local, persistencia de aplicaciones y avisos manuales, migración SQL, vista previa LangGraph, autenticación de desarrollo y conexión opcional a un colector OpenTelemetry. Los adaptadores de inteligencia, modelos, escaneo y generación de parches aún no están implementados.

## Requisitos

- Python 3.12 y `uv` para desarrollo local.
- Docker con su motor iniciado para PostgreSQL o para ejecutar toda la aplicación.
- Un navegador; la interfaz utiliza HTML, CSS y JavaScript nativos y no requiere un proceso Node de compilación.

Las dependencias Python se encuentran en `pyproject.toml`; `uv.lock` fija las versiones resueltas. Los componentes nuevos de implementación son open source. Los proveedores externos siguen el alcance acordado en el SRS.

## Arranque con Docker

Desde la raíz del repositorio, en PowerShell:

```powershell
python scripts/bootstrap.py
```

El script crea `.env` con credenciales aleatorias y conserva cualquier archivo existente. Consulta `WARDEN_API_TOKEN` localmente para acceder a la UI. Luego:

```powershell
docker compose up -d --build --wait api
```

Abre [la aplicación](http://localhost:8000) e introduce ese token en el formulario de acceso. PostgreSQL utiliza un volumen local; el servicio `migrate` aplica las migraciones antes de arrancar la API. Los puertos publicados solo escuchan en localhost. El migrador usa `warden_owner` y la API `warden_app`, que no puede editar auditoría ni ejecutar migraciones.

Si cambias contraseñas manualmente, usa valores aptos para una URL PostgreSQL o codifícalos. Cambiar una variable después de crear el volumen no cambia la contraseña del usuario existente. Consulta [la guía de infraestructura](docs/infrastructure.md) para puertos alternativos, roles, respaldo y operación.

## Desarrollo local

Completa primero `.env` como se indica arriba.

```powershell
uv sync --frozen
docker compose -f compose.yaml -f compose.dev.yaml up -d db
uv run python -m alaira_warden.db
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

La documentación interactiva está en [Swagger](http://localhost:8000/docs). Las rutas `/api/` requieren `Authorization: Bearer <WARDEN_API_TOKEN>`.

| Método | Ruta | Función |
|---|---|---|
| GET | `/health/live` | Comprueba que la API responde. |
| GET | `/health/ready` | Comprueba conectividad y tablas requeridas. |
| GET | `/api/integrations` | Lista el alcance y estado pendiente de adaptadores. |
| GET / POST | `/api/applications` | Lista las últimas 100 aplicaciones o registra una. |
| GET / POST | `/api/investigations` | Lista los últimos 100 avisos o registra uno manualmente. |
| GET | `/api/investigations/{id}` | Recupera un aviso registrado. |
| POST | `/api/investigations/{id}/preview` | Ejecuta el grafo inicial sin escanear ni modificar el caso. |

La vista previa termina en `requires_intervention` porque faltan los adaptadores de inventario y fuentes. No cambia el estado persistido, no clasifica exposición, no llama modelos ni ejecuta código de repositorios.

## Integraciones y límites

Las variables `WARDEN_GITHUB_TOKEN`, `WARDEN_NVD_API_KEY`, `WARDEN_METERLESS_*`, `WARDEN_NVIDIA_*`, `WARDEN_GROK_API_KEY`, `WARDEN_ZETARIS_API_KEY` y `WARDEN_CURSOR_API_KEY` aceptan credenciales reales cuando existan. Un valor no vacío solo indica que el secreto está presente; no habilita el conector ni lo marca como verificado. OSV, CISA KEV, Syft, Trivy y OSV-Scanner no usan secreto en este scaffold.

- **Pendientes del MVP:** GitHub Security, OSV, NVD, CISA KEV, Syft, Trivy y OSV-Scanner.
- **Requerida por el hackathon:** Meterless; su contrato técnico y acceso todavía deben verificarse.
- **Candidata de modelos:** NVIDIA, condicionada a acceso e interfaz verificados.
- **Condicionales:** Grok/X, Zetaris y Cursor programático. Cursor puede utilizarse como herramienta del equipo desde ahora.
- **Base implementada:** PostgreSQL mediante SQL, LangGraph para la vista previa y OpenTelemetry para trazas HTTP. El contenedor de la API funciona sin privilegios, pero todavía no existe un ejecutor de código no confiable.

Para habilitar trazas, configura `OTEL_EXPORTER_OTLP_ENDPOINT` con la URL base OTLP/HTTP de un colector de confianza. Se agrega `/v1/traces`. Sin esa variable no se exportan trazas. No se envían cabeceras de autenticación ni cuerpos de aplicación como atributos. No se añade un proveedor de observabilidad cerrado.

El token compartido identifica un único desarrollador local; no implementa usuarios, roles de aplicación ni separación entre proyectos. El rol SQL del runtime tiene auditoría de solo adición; el propietario administrativo conserva sus facultades de mantenimiento. Se requiere implementar los demás controles del SRS antes de usar el sistema con datos reales o exponerlo fuera de localhost.

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

