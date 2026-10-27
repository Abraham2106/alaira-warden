# B1 — Ejecutor local de trabajos aislados

## Estado

Núcleo implementado y probado con tareas sintéticas. La integración con identidades verificadas, el worker persistente y herramientas npm/Syft/Trivy/OSV-Scanner corresponde a los siguientes bundles y frentes. No existe un endpoint HTTP que permita ejecutar comandos y el token de desarrollo no habilita esta capacidad.

Archivos: `src/alaira_warden/execution/` y `tests/execution/`. No se modificaron los paquetes reservados a los cuatro frentes.

## Contrato

Un proceso **confiable del host** construye `ExecutionPolicy` con:

- Raíz de snapshots preparados y raíz separada de artefactos.
- IDs de aplicaciones autorizadas para ese ejecutor.
- Catálogo de herramientas: imagen local por ID completo `sha256:...`, ejecutable absoluto y prefijo fijo.
- Límites de tiempo, memoria, CPU, procesos, tmpfs, entrada, salida y artefactos.
- Socket de un daemon Docker local Linux. No acepta hosts TCP ni hereda contexto remoto de Docker.

`Job` contiene aplicación, actor ya autenticado por el llamador, snapshot, nombre de herramienta y argumentos. El actor no se autentica por escribir un string: la futura capa de identidad debe emitir el permiso y comprobar ámbito antes de llamar al ejecutor. La política jamás se construye desde JSON enviado por un usuario o modelo.

El trabajo devuelve `JobResult` con estado, código de salida, salida acotada, artefactos con huella, tiempo, identidad de imagen y confirmación de limpieza. Los estados distinguen éxito, fallo, timeout, cancelación, exceso de salida/artefactos, entrada rechazada y fallo de infraestructura. Un fallo de limpieza impide declarar éxito.

## Aislamiento implementado

- Usuario 10001:10001, raíz de solo lectura, capacidades eliminadas y `no-new-privileges`.
- Sin red ni IPC compartido; no recibe dispositivos, bind mounts ni socket Docker.
- Memoria y swap acotadas, CPU, PIDs y descriptores limitados.
- Espacio de trabajo y temporal en tmpfs con tamaño limitado; el trabajo no modifica el snapshot del host.
- Imagen aprobada e inmutable, sin descarga automática; se rechazan volúmenes declarados en la imagen.
- Inspección del contenedor antes de ejecutar para comprobar imagen, usuario, restricciones y recursos aplicados.
- Sin reenvío del entorno del host: claves de modelos, token de API y configuración de Docker remoto no se pasan al trabajo.
- Entrada por archivo TAR generado desde ficheros regulares validados; se rechazan enlaces, reparse points, escapes y archivos sensibles conocidos. El snapshot debe estar autorizado y depurado: esto no reemplaza un análisis de secretos incrustados en código.
- Artefactos tratados como datos no confiables: extracción manual acotada, sin `extractall`, sin enlaces, rutas absolutas, escapes ni nombres de dispositivos Windows.
- Salida drenada con límite de memoria; al agotar presupuesto se detiene la ejecución y se elimina el contenedor en `finally`.

Docker `cp` rechazó la transferencia sobre la combinación de raíz read-only y tmpfs durante una prueba real. Se mantuvieron los controles y se cambió a TAR por stdin mediante `docker exec` sin privilegios. La imagen de herramientas necesita `/bin/sh`, `/bin/sleep` y `/bin/tar` además de los ejecutables aprobados.

## Verificación

Se ejecutaron **28 pruebas del bundle**, incluidas **6 pruebas reales Docker**:

- Usuario no root, lectura del snapshot, raíz no escribible, red no disponible y ausencia del socket/token del host.
- Artefacto real recuperado y huella calculada.
- Código de salida fallido, timeout, cancelación y salida excesiva.
- Rechazo de enlace simbólico creado como artefacto.
- Confirmación de que cada contenedor de prueba fue eliminado.
- Pruebas unitarias de rutas, secretos conocidos, límites, IDs de imagen, política y archivos TAR maliciosos.

Comandos:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/execution -q
$env:WARDEN_RUN_DOCKER_TESTS = '1'
.\.venv\Scripts\python.exe -m pytest tests/execution -q
```

Las pruebas Docker usan la imagen local `alaira-warden-api`, resuelven su ID inmutable y ejecutan exclusivamente scripts sintéticos Python. No instalan paquetes ni analizan repositorios externos. CI construye la imagen y ejecuta después estas pruebas. No se afirma que CI remoto haya corrido desde esta sesión.

## Límites de integración

La API de Compose sigue sin acceso al daemon. El runner se invocará desde un worker confiable del host o servicio administrativo separado; no se debe añadir el socket Docker a la API para conectar este módulo rápidamente. La arquitectura de worker y checkpoints se conecta en B3.

El perfil actual es **offline**. Una instalación npm que necesite Internet requiere un aprovisionamiento previo de dependencias autorizado o una política adicional de salida controlada, con sus pruebas. No se habilita red general para hacer pasar una instalación. El root filesystem, la red y los secretos no pueden relajarse por petición del modelo.

La limpieza se confirma al devolver un resultado. Si el proceso del host o daemon muere abruptamente, no hay todavía un reconciliador persistente de trabajos huérfanos; B3 debe registrar y reconciliar ejecuciones. Los contenedores llevan nombres únicos y etiqueta `alaira.warden.job=true`; no se deben borrar contenedores de otros trabajos indiscriminadamente.

La garantía es de contenedores con aislamiento y límites configurados, no de resistencia certificada ante exploits del kernel/daemon. No se utiliza malware activo para aceptar el MVP.

## WBS y siguiente paso

Este núcleo aporta implementación verificable a 1.2.4 y al bundle B1. El cierre integrado requiere autorización real del llamador, imágenes de herramientas y ciclo persistente de trabajos. B2 puede avanzar de forma secuencial con fixtures de contratos: correlación determinista de inventario y avisos.

Documentación de referencia: [Docker create](https://docs.docker.com/reference/cli/docker/container/create/), [límites de recursos](https://docs.docker.com/engine/containers/resource_constraints/) y [tmpfs](https://docs.docker.com/engine/storage/tmpfs/).
