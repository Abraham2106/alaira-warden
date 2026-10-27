# B3 — Base de orquestación persistente

## Estado y alcance

Implementación interna en `src/alaira_warden/orchestration/`. Usa el `PostgresSaver` oficial de LangGraph, fijado a 3.2.0 en `uv.lock`. El flujo procesa inventario, fuentes y correlación, una etapa por despacho, y termina en `awaiting_review`. Las etapas se conectan mediante handlers confiables; si falta uno, queda en `requires_intervention` sin inventar evidencia.

La integración posterior monta rutas autenticadas `/runs` con despacho de una etapa por solicitud; no hay worker automático todavía. El grafo `/preview` conserva su comportamiento inicial independiente. Los diez escenarios del núcleo usan PostgreSQL real y handlers sintéticos; la prueba HTTP de `tests/test_product_integration.py` añade los handlers conectados a los frentes con respuestas controladas. No acreditan operaciones reales de patrocinadores ni el cierre completo de B3. Estado actual en `docs/front-integration.md`.

## Persistencia y operación

- `workflow_runs` conserva solicitud, actor, idempotencia, intentos, cuota temporal y controles. La migración nueva `004_workflow_control.sql` no modifica las migraciones anteriores.
- Los checkpoints se guardan en el esquema separado `warden_workflow`. `python -m alaira_warden.db` aplica las migraciones de dominio y luego ejecuta el setup oficial con el propietario. También existe `python -m alaira_warden.orchestration.checkpoints` para el setup explícito del esquema.
- El rol `warden_app` puede usar los checkpoints, pero no crear sus tablas ni escribir su historial de migraciones. `advance()` verifica la versión del esquema; no ejecuta DDL.
- Un bloqueo asesor de sesión excluye a un segundo worker del mismo run durante el despacho. Otros runs conservan independencia. La desconexión libera el bloqueo.
- Se reconstruye el grafo con el último checkpoint, nunca con una etapa o resultado enviado por el usuario. El reinicio de una instancia conserva etapas completadas, cuotas y controles.
- La solicitud se deduplica por caso y UUID de petición. Reutilizar la clave con un actor, ámbito o presupuesto diferente produce conflicto.
- Los spans incluyen IDs de caso/run y etapa. Los checkpoints solo admiten estado primitivo y referencias UUID; no guardan cuerpos de proveedores ni texto de excepciones. La serialización no habilita pickle ni módulos arbitrarios.

## Límites, recuperación y confianza

Antes de llamar un handler se consume un intento y se reserva su tiempo máximo en PostgreSQL. Se devuelve el tiempo no usado al terminar. Un proceso muerto conserva la reserva consumida: reiniciar no regala presupuesto. Las pausas entre despachos no consumen tiempo activo.

La ejecución después de una caída es **al menos una vez**. Cada handler recibe una clave estable `run:stage:v1` para recuperar su resultado persistido o deduplicar una operación repetida. La prueba de reinicio comprueba recuperación entre etapas; el consumo conservador tras caída se prueba simulando la reserva no devuelta. Falta probar una terminación forzada del proceso durante cada punto crítico. Este flujo no publica PRs ni realiza escrituras externas.

La cancelación es irreversible y la pausa se aplica antes del siguiente despacho. Durante una llamada, `context.cancelled()` permite cancelación cooperativa y consulta el plazo monotónico. Un handler debe usar tiempos de espera reales en sus clientes y el ejecutor B1 para procesos no confiables. Un callback Python que ignore el contrato no se interrumpe por fuerza; al volver, su resultado tardío se descarta. No se admite código de repositorios como handler del host.

El integrador debe autenticar y autorizar antes de `start`, `advance` y `control`. Un `subject_id` y un UUID de aplicación no prueban autorización. Los handlers deben persistir y comprobar procedencia/ámbito de los UUID de evidencia devueltos. Estas comprobaciones se integrarán al recibir los cuatro frentes.

Pendiente para cerrar B3: montar los handlers reales, snapshot y revisiones inmutables, autorizaciones, política de reintentos del worker, recuperación de contenedores huérfanos, llamadas de proveedores con presupuesto compartido, retención de checkpoints y flujo completo con las integraciones. Revisión/aprobación del parche corresponde a B5, no al estado `awaiting_review` de este núcleo.

## Evidencia

`tests/orchestration/test_runtime.py`: reinicio entre etapas sin repetir las completadas; conflicto de idempotencia/ámbito; fallo cerrado por handler ausente; pausa/reanudación/cancelación; cuota de intentos y redacción de errores; reserva temporal no devuelta; exclusión concurrente y cancelación cooperativa; rechazo de DDL y modificación de migraciones con el rol efectivo del runtime; descarte de resultados tardíos; rechazo de etapa lista sin evidencia.

En este equipo Windows se utilizó `127.0.0.1` explícito para la conexión de las pruebas: el acceso concurrente mediante `localhost` quedó esperando durante la resolución/conexión. No se atribuye esa espera al motor de correlación ni se acredita con ella una recuperación de red. Docker utiliza el hostname interno `db`.

Base del mecanismo: [persistencia de LangGraph](https://docs.langchain.com/oss/python/langgraph/persistence) y código instalado del checkpointer fijado por el lockfile.
