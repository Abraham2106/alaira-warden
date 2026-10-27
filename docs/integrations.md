# Contratos de integración

## Estado

Los cuatro frentes están fusionados y montados mediante `integration/`. El catálogo distingue clientes conectados sin verificar de operaciones comprobadas; un secreto presente nunca equivale a una conexión. Las pruebas y rutas actuales están en [la guía de integración](front-integration.md). `adapters.invoke` es un stub legado del scaffold y no despacha el flujo nuevo.

**Requisitos vigentes:** Zetaris es obligatorio como capa de datos y Nightshift como proveedor principal; también se exige un Engine Meterless operativo. NVIDIA se conecta a Nightshift y Cursor es opcional. [El ajuste del hackathon](hackathon-alignment.md) prevalece sobre decisiones anteriores.

## Contrato mínimo de cada adaptador

Antes de implementarlo deben fijarse:

1. Identificador, finalidad, alcance MVP/condicional y versión del contrato.
2. Fuente oficial de documentación y operación real que acredita la integración.
3. Autenticación mediante referencia a secreto y permisos mínimos.
4. Entrada validada, salida estructurada y representación de datos desconocidos.
5. Procedencia: identificador/URL, fecha de publicación/consulta y huella cuando aplique.
6. Paginación, cuotas, tiempo de espera y presupuesto de reintentos.
7. Errores diferenciados de autenticación, límite, indisponibilidad y datos no soportados.
8. Idempotencia y conciliación de operaciones con efectos externos.
9. Licencia/atribución de datos y restricciones de envío de información interna.
10. Caso de prueba con una respuesta verificable y uno de fallo.

## Adaptadores acordados

| Integración | Entrada y salida previstas | Control principal |
|---|---|---|
| GitHub Security | Identificador de aviso/repositorio → referencias y datos disponibles. | Permisos y alcance del plan; falta de acceso no equivale a ausencia de vulnerabilidades. |
| OSV | Ecosistema, paquete y versión → avisos y rangos con origen. | Conservar licencia y atribución de la fuente de cada registro cuando estén disponibles. |
| NVD | CVE → enriquecimiento y referencias. | No inferir correspondencia npm desde un CPE ambiguo. |
| CISA KEV | Catálogo/CVE → señal de explotación reportada. | Ausencia del catálogo no demuestra ausencia de explotación. |
| Syft | Checkout autorizado por commit → SBOM. | Versión fija, aislamiento y comprobación de relaciones con el lockfile. |
| Trivy | Checkout/SBOM permitido → resultados de análisis. | Capturar resultado, código de salida y herramienta; un error no aprueba el escaneo. |
| OSV-Scanner | Lockfile/SBOM soportado → resultados de análisis. | Conservar diferencias respecto de Trivy y explicar discrepancias. |
| Meterless | Operación requerida por el hackathon → salida según contrato real. | Verificar API y alcance antes de definir el adaptador. Integración obligatoria pendiente. |
| NVIDIA | Modelo atendido a través de Nightshift. | No montar la API directa como proveedor principal ni guardar su clave en Warden. Identificar el modelo real para el premio Nemotron. |
| Grok/X | Consulta autorizada → publicaciones y referencias. | Condicional; verificar autoría, procedencia y corroboración. |
| Zetaris | Capa de datos con inventario y evidencia autorizados → datos para correlación/investigación. | Obligatoria. El modo Zetaris falla cerrado; hay que registrar las vistas y comprobar consultas reales. |
| Cursor programático | Tarea acotada → diff y artefactos. | Condicional; interfaz disponible y validación en aislamiento. |

Los adaptadores de modelos no podrán invocar herramientas arbitrarias. Un servicio autorizado validará la acción, ámbito y presupuesto antes de ejecutar. No se montará el socket Docker ni se entregarán credenciales de producción a un trabajo de análisis.

