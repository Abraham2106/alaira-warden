# Scaffold de interfaz — ALAIRA Warden

## Referencia y decisiones visuales

Se inspeccionó de forma local el proyecto `C:\Users\solan\Documents\Personal\Startup\Alaira Harness\deepseek-harness`. No existe `.codegraph` en esa raíz ni en su directorio contenedor. Se leyeron los tokens `packages/client/ui-theme/src/styles/alaira.css`, las fuentes de marca, el shell y el sidebar, sin modificar el proyecto de referencia ni acceder a sus secretos.

La adaptación utiliza la base `#fafaf7`, lateral `#f0f0eb`, superficie blanca, texto `#191919`, acento terracota `#b15f46`, selección arena `#ebd9bc`, bordes neutros y Montserrat local. Los dos archivos de fuente se distribuyen con su licencia SIL OFL. El logotipo de ALAIRA se tomó del recurso local aportado como referencia. Los iconos de la interfaz son SVG sencillos propios, sin dependencias externas.

Skills aplicadas: `senior-ui-ux-orchestrator`, `webapp-ui-skill`, `frontend-design`; se respetaron las guías `forms` y `accessible-error-announcement` obtenidas mediante `modern-web-guidance` por el agente principal. Todo el trabajo se mantuvo local.

## Arquitectura de información final

El menú lateral tiene cuatro destinos, siguiendo la corrección del solicitante para consolidar la información:

1. **Centro de operaciones:** vista predeterminada de panorama y vista de investigación/respuesta sobre el mismo espacio.
2. **Aplicaciones:** repositorios, información del activo, inventario y despliegues.
3. **Integraciones:** catálogo, categorías y estado de configuración/verificación.
4. **Configuración:** entorno, acceso, límites de autonomía y tratamiento de datos.

En el centro, la vista **Investigación y respuesta** presenta una cola seleccionable de avisos junto al contexto de la aplicación. La evidencia, evaluación de exposición, plan de respuesta, cambio/diff, validaciones, aprobación e historial permanecen en una sola vista. No hay páginas laterales separadas para recolectar cada etapa de la respuesta.

Las métricas desconocidas muestran `—`, las comprobaciones no realizadas muestran su estado y los controles futuros están deshabilitados con su motivo. No se generaron vulnerabilidades, escaneos, evidencias o resultados simulados para llenar la interfaz.

## Funciones conectadas

- Conexión al entorno con token solo en memoria; no utiliza almacenamiento de navegador.
- Estado de API y disponibilidad de PostgreSQL.
- Listado y registro de aplicaciones.
- Listado y registro de avisos manuales, vinculados a una aplicación.
- Consulta real del catálogo de adaptadores, diferenciando credencial configurada de conexión verificada.
- Vista previa de LangGraph desde el caso seleccionado: se detiene ante el inventario pendiente y conserva exposición indeterminada.
- Búsqueda de aplicaciones, navegación de vistas, filtros de integraciones, diálogos y menú móvil con cierre Escape y contención de foco.

La navegación y las estructuras futuras son accesibles sin autenticación o base de datos. La escritura exige conexión autenticada y disponibilidad del servicio persistente.

## Verificación ejecutada

**Ran:** `node --check src/alaira_warden/static/app.js`; sintaxis aprobada después de la consolidación de navegación.

**Ran:** comprobación local de las funciones de plantilla mediante Node `vm`: confirma cuatro destinos y renderiza el estado sin investigación con evidencia, exposición, plan, diff, validación, aprobación e historial. Comprueba que no se muestra un resultado de vista previa inexistente. Esta comprobación no utiliza un navegador ni valida el diseño visual final.

**Ran:** comprobación heurística `check_state_coverage.ts` sobre los estáticos. Reporte en `reports/local/ui-state-coverage.json`; encuentra marcadores de carga, vacío, error, deshabilitado, foco, selección, envío y éxito. Es una inspección de código, no prueba de accesibilidad ni ejecución exhaustiva.

**Ran, antes de la última consolidación:** revisión en el navegador local a 1280×800 y 390×844, alta real de una aplicación y un aviso sintéticos en PostgreSQL, consulta de detalles, ejecución de la vista previa y navegación móvil. No se observaron errores de consola. La anchura del documento coincidió con el viewport disponible en las vistas medidas (1280 y 375 píxeles de contenido respectivamente, excluyendo la reserva del scrollbar).

Los registros utilizados se identifican explícitamente como `Demo UI — Aplicación sintética` y `Demo UI — Aviso sintético de revisión`; no corresponden a una vulnerabilidad real. El repositorio registrado es una referencia sintética; nunca se clonó ni escaneó.

Las capturas `reports/local/ui-overview-desktop.png` y `reports/local/ui-overview-mobile.png` corresponden al diseño previo a la reducción de nueve a cuatro destinos. No deben presentarse como capturas de la arquitectura de información final.

**Skipped:** nueva revisión visual/capturas de la última consolidación. Al retomar tras el cambio de cuenta, la herramienta devolvió que el uso local de navegador está deshabilitado en Work settings. No se alteró esa preferencia. La vista final requiere revisión visual cuando vuelva a estar disponible.

**Skipped:** formatter externo. Una ejecución combinada que proponía quitar funciones mediante una expresión regular y ejecutar Prettier descargado fue rechazada por revisión automática. Se abandonó ese comando y se eliminaron las funciones antiguas con un parche explícito. No se añadió ninguna dependencia ni se insiste en el comando rechazado.

**Manual:** se revisó que la navegación final tiene cuatro entradas y que las etapas de respuesta están en un mismo contexto. La compatibilidad de los endpoints existentes se conserva. Backend, infraestructura, SRS y WBS no fueron modificados por este trabajo de UI.

## Integración futura requerida

Los bloques de inventario, despliegue, correlación, evidencia corroborada, planes, parches/diff, validaciones, aprobaciones y consulta de auditoría todavía requieren endpoints y servicios del backend. Los controles de esa parte del MVP permanecen deshabilitados o muestran estados pendientes. El token local sigue siendo un único acceso de desarrollo; usuarios y roles individuales aún no están conectados.

La configuración muestra estado planificado para políticas sin exponer secretos. Antes de conectar los servicios se deben reemplazar los textos pendientes por datos y resultados reales del caso seleccionado, manteniendo sus fechas, identidad del commit y referencias.
