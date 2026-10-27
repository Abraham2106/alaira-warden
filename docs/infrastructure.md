# Infraestructura del scaffold

## Servicios y límites

| Servicio | Función implementada | Identidad y acceso |
|---|---|---|
| `db` | PostgreSQL 17 con volumen persistente. | `warden_owner` administra el esquema; `warden_app` es el rol de la API. Sin puertos publicados en el entorno base. |
| `migrate` | Ejecuta archivos SQL ordenados y comprueba sus huellas. Finaliza antes del arranque de la API. | Recibe la conexión del propietario; no recibe token de la API ni claves de conectores. |
| `api` | FastAPI, interfaz estática, operaciones iniciales y vista previa LangGraph. | Usuario Linux sin privilegios, sistema de archivos de solo lectura y rol SQL limitado. No recibe la conexión del migrador. |
| `otel-collector` | Receptor OTLP/HTTP y salida de diagnóstico local. Se activa con un archivo Compose adicional. | Sin puertos publicados ni proveedores externos; recibe únicamente trazas de la API. |

La red `database` es interna y comunica PostgreSQL con API/migrador. La red `services` permite comunicación de la API con el colector y futuras fuentes autorizadas. Esta separación no constituye todavía un ejecutor de código no confiable: los adaptadores de análisis siguen pendientes y la API no tiene acceso al socket Docker.

## Preparar el entorno

```powershell
python scripts/bootstrap.py
docker compose up -d --build --wait api
```

El primer comando crea `.env` con tres credenciales aleatorias, sin imprimirlas. Si existe el archivo, lo conserva. Revisa `WARDEN_API_TOKEN` localmente para entrar a la UI. `.env` está excluido de Git y de la imagen Docker.

Por defecto la UI escucha en `http://localhost:8000` y PostgreSQL solo es accesible desde los contenedores de su red interna. `WARDEN_HTTP_PORT` permite cambiar el puerto de la UI. Para ejecutar Uvicorn fuera de Docker, habilita expresamente el acceso local a PostgreSQL:

```powershell
docker compose -f compose.yaml -f compose.dev.yaml up -d db
uv run python -m alaira_warden.db
uv run uvicorn alaira_warden.main:app --reload --host 127.0.0.1 --port 8000
```

`compose.dev.yaml` añade una red de desarrollo y publica PostgreSQL únicamente en `localhost:5432`. `WARDEN_DB_PORT` permite cambiar ese puerto; actualiza también las URLs locales de `.env` si lo cambias. Las conexiones entre contenedores conservan `db:5432`. Ejecutar solo `docker compose up db` no expone la base al host.

Si el puerto 8000 está ocupado, puedes verificar un segundo arranque:

```powershell
$env:WARDEN_HTTP_PORT = '8001'
docker compose up -d --build --wait api
```

La configuración generada es local de desarrollo. Las variables de conectores son opcionales y no activan sus adaptadores. No se usan claves reales para construir imágenes ni para las pruebas.

## Migraciones e identidades SQL

1. PostgreSQL inicializa `warden_owner` y el rol de ejecución `warden_app` mediante `infra/postgres/init-runtime.sh` en un volumen nuevo.
2. `migrate` aplica `001_initial.sql`, `002_domain_foundations.sql` y `003_runtime_permissions.sql` en una transacción, con bloqueo para evitar dos migradores simultáneos.
3. `warden_app` puede operar sobre tablas de dominio; puede insertar/consultar auditoría, pero no actualizarla, borrarla o truncarla. No puede escribir en `schema_migrations` ni crear tablas del esquema.
4. La API verifica conectividad, tablas iniciales y coincidencia exacta de nombres/huellas de migraciones mediante `/health/ready` antes de declararse lista. Devuelve 503 si falta una migración, cambió su contenido o hay una versión inesperada del esquema.

`WARDEN_DATABASE_URL` corresponde al runtime local. `WARDEN_MIGRATION_DATABASE_URL` es una conexión opcional de propietario que solo utiliza el comando de migración. Compose entrega al servicio `migrate` la conexión del propietario directamente en `WARDEN_DATABASE_URL`, sin compartirla con la API.

No edites migraciones aplicadas. Crea el siguiente archivo numerado y concede explícitamente al rol de ejecución los permisos de sus tablas. La tabla de dominio `workflow_runs` no reemplaza los checkpoints de LangGraph: la persistencia y reanudación del grafo todavía no están implementadas.

Los scripts de inicialización de PostgreSQL se ejecutan solo al crear el volumen. Si utilizas un volumen previo con otro propietario o sin `warden_app`, debes revisar y provisionar sus roles antes de aplicar esta configuración. Cambiar una contraseña en `.env` no cambia automáticamente la contraseña almacenada en una base existente. No se elimina el volumen para actualizarlo.

## Observabilidad local

```powershell
docker compose -f compose.yaml -f compose.observability.yaml up -d --build --wait api
docker compose -f compose.yaml -f compose.observability.yaml logs otel-collector
```

El archivo adicional apunta las trazas a `http://otel-collector:4318`. El colector procesa lotes con límite de memoria y usa el exportador de diagnóstico. No incluye almacenamiento histórico ni tablero de métricas. Las trazas no capturan cuerpos de aplicación ni cabeceras de autenticación.

Sin ese archivo, la exportación queda deshabilitada salvo que configures explícitamente un destino OTLP autorizado. `LANGSMITH_TRACING=false` evita habilitar un servicio de trazas adicional por las dependencias de LangGraph.

## Estado y operación

```powershell
docker compose ps
docker compose logs --tail 100 api migrate
docker compose exec -T db pg_isready -U warden_owner -d warden
docker compose stop
```

`stop` detiene servicios conservando el volumen. Para arrancarlos nuevamente usa `docker compose up -d --wait api`. Al cambiar código debes reconstruir la imagen; los estáticos dentro de ella corresponden al momento de construcción. El servidor local con Uvicorn sirve los archivos del workspace directamente.

## Respaldo y restauración

Los comandos de respaldo se ejecutan dentro de PostgreSQL para evitar que PowerShell transforme un archivo binario. Para obtener una copia de desarrollo:

```powershell
New-Item -ItemType Directory -Force artifacts/backups | Out-Null
docker compose exec -T db pg_dump -U warden_owner -d warden -Fc -f /tmp/warden.dump
docker compose cp db:/tmp/warden.dump artifacts/backups/warden.dump
```

El volcado contiene datos de la aplicación y debe conservarse como un artefacto privado. Para ensayar una restauración, utiliza una **base nueva y vacía** distinta de la base activa. Nunca se restaura automáticamente sobre `warden` ni se ejecutan comandos de limpieza destructiva desde el scaffold. `pg_dump` no incluye roles: el entorno de destino debe provisionarlos y ejecutar los permisos adecuados.

Ejemplo de restauración de ensayo, eligiendo un nombre que todavía no exista:

```powershell
docker compose exec -T db createdb -U warden_owner warden_restore_test
docker compose cp artifacts/backups/warden.dump db:/tmp/restore-test.dump
docker compose exec -T db pg_restore -U warden_owner -d warden_restore_test --exit-on-error /tmp/restore-test.dump
docker compose exec -T db psql -U warden_owner -d warden_restore_test -c 'SELECT count(*) FROM schema_migrations;'
```

Si la base destino existe, el procedimiento se detiene para elegir otra; no incluye borrado ni sobrescritura de bases.

## CI y alcance de la verificación

GitHub Actions instala dependencias desde `uv.lock`, ejecuta Ruff, pruebas y sintaxis JavaScript, valida ambos archivos Compose y construye la imagen. Para las pruebas de integración crea un PostgreSQL efímero con la base `warden_test`.

Localmente, `tests/test_postgres.py` solo se ejecuta si se define `WARDEN_TEST_DATABASE_URL` y el nombre de la base termina en `_test`. Comprueba migraciones repetibles, persistencia por API, auditoría transaccional y permisos de `warden_app`. Esa base debe ser independiente del entorno de demostración; la prueba agrega datos sintéticos.

Las pruebas de controles completos del MVP, los checkpoints, los adaptadores externos y el ejecutor aislado permanecen en los paquetes correspondientes del WBS. El esquema prepara las entidades sin declarar implementados sus servicios.
