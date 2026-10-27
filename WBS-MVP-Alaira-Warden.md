# WBS / EDT — Desarrollo del MVP de ALAIRA Warden

| Campo | Valor |
|---|---|
| Versión | 1.0 |
| Fecha | 26 de octubre de 2026 |
| Estado | Plan de trabajo propuesto; desarrollo pendiente |
| Documento base | SRS-Alaira-Warden.md, con las integraciones acordadas en esta conversación |
| Producto final | MVP ejecutable que transforma un aviso de seguridad en una evaluación de exposición y una propuesta de corrección validada y revisable |
| Unidad de estimación | Horas-persona de trabajo efectivo |

## 1. Alcance y reglas de planificación

Esta estructura de desglose del trabajo (WBS, o EDT) define entregables y paquetes de trabajo para construir el MVP del SRS. No describe funcionalidades ya implementadas. Los identificadores permiten convertir cada paquete en una tarea del tablero de desarrollo y relacionarlo con requisitos y evidencia de cierre.

### 1.1 Resultado comprometido por este plan

El MVP permitirá registrar aplicaciones Node.js/npm de una organización, obtener dependencias directas y transitivas, importar despliegues históricos, consultar GitHub Security, OSV, NVD y CISA KEV, investigar y correlacionar amenazas, preparar un parche en aislamiento, validarlo con pruebas y análisis, y entregar un reporte y un PR autorizado.

También incluirá persistencia de estados, acceso por roles, límites de ejecución, pausa y cancelación, trazabilidad y una interfaz de revisión humana. Meterless forma parte del alcance por indicación del solicitante como requisito del hackathon.

### 1.2 Supuestos de trabajo

- Se mantiene Node.js/npm como ecosistema inicial propuesto en el SRS.
- Se utilizarán repositorios de prueba autorizados y registros históricos importados, con resultados esperados conocidos.
- PostgreSQL, Docker, LangGraph y OpenTelemetry se adoptan como base de implementación propuesta dentro del conjunto tecnológico autorizado.
- Syft generará el inventario/SBOM; Trivy y OSV-Scanner producirán resultados de análisis que se conservarán por separado y se correlacionarán.
- Los ocho agentes de la propuesta se implementarán como responsabilidades del flujo; pueden compartir proceso y proveedor de modelos.
- Cursor se utilizará como herramienta del equipo de desarrollo. Su automatización dentro del producto es una extensión condicional.
- La función y API concretas de Meterless se verificarán al comienzo. Su integración no se considerará terminada por incluir un nombre o una simulación en la demostración.
- Grok/X, Zetaris y la automatización programática de Cursor conservan las condiciones del SRS; cuentan con paquetes opcionales separados. Si las reglas del hackathon exigen alguno, ese paquete pasa al alcance obligatorio.
- No se han definido integrantes, fecha de entrega ni horas disponibles. Las estimaciones no constituyen un calendario ni una promesa de terminar en un fin de semana.

### 1.3 Límites del MVP

Se excluyen merge y despliegue automáticos, cambios reales de infraestructura, manipulación de secretos de producción, pruebas ofensivas, soporte general de múltiples ecosistemas, conectores completos de despliegue y notificaciones externas. CodeRabbit permanece excluido.

La generación básica de SBOM con Syft sí pertenece al MVP por RF-30. La importación general de SBOM, el análisis amplio de imágenes/configuraciones y otros escenarios de RF-07 permanecen en evolución. Esta distinción evita ampliar el alcance por incorporar la herramienta.

### 1.4 Cómo leer los paquetes

- El nivel **1.0** representa el MVP completo; **1.x**, un entregable principal; **1.x.y**, un paquete ejecutable.
- Las dependencias indican qué debe estar disponible para cerrar el paquete. Los contratos definidos permiten adelantar implementación sin esperar la integración final.
- Cada paquete tiene un responsable principal por rol, aunque una persona puede asumir varios roles.
- El esfuerzo incluye implementación, revisión y comprobaciones específicas del paquete. La aceptación completa del sistema se estima separadamente en 1.11.
- Un paquete termina con evidencia de su criterio de cierre. Un porcentaje subjetivo o una pantalla con datos simulados no acredita una integración real.

## 2. Estructura jerárquica

```text
1.0 MVP ALAIRA Warden
├── 1.1 Alcance, contratos y datos de demostración
├── 1.2 Plataforma base y control de acceso
├── 1.3 Inventario y despliegues históricos
├── 1.4 Fuentes de inteligencia y evidencia
├── 1.5 Orquestación multiagente y modelos
├── 1.6 Correlación, exposición y prioridad
├── 1.7 Remediación y validación aislada
├── 1.8 Aprobaciones y entrega del pull request
├── 1.9 Interfaz y reportes
├── 1.10 Observabilidad y operación
├── 1.11 Aceptación y entrega del MVP
└── 1.12 Integraciones condicionales del hackathon
```

**Roles:** LT = líder técnico; BE = desarrollo backend; IA = ingeniería de agentes/modelos; SEC = seguridad/DevSecOps; FE = desarrollo frontend; QA = calidad. Son responsabilidades propuestas, no asignaciones a personas ni órdenes de delegación.

## 3. Diccionario de paquetes de trabajo

### 1.1 Alcance, contratos y datos de demostración

**Entregable:** línea base operativa que permita implementar sin suponer APIs, permisos o resultados de la demostración.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.1.1 | Alcance y decisiones: registrar escenarios, ecosistema, roles, prioridades, límites, política de riesgo y exclusiones. | Lista de requisitos MVP y decisiones pendientes con responsable; regla de priorización y límites iniciales definidos. | LT + SEC | — | 4–6 |
| 1.1.2 | Viabilidad de integraciones: comprobar acceso a GitHub, fuentes y servicios del hackathon; identificar función, autenticación y operaciones de Meterless. | Matriz de accesos y contratos con evidencia de conexión; Meterless tiene un uso concreto verificable. Accesos faltantes quedan como bloqueos, no como capacidades supuestas. | LT + IA | 1.1.1 | 4–8 |
| 1.1.3 | Diseño de solución: definir módulos, modelo de datos, contratos API/eventos, estados y límites entre agentes y herramientas. Definir uso de Cursor para el desarrollo. | Diagramas y esquemas de entrada/salida versionados; herramientas sensibles ejecutadas por servicios con permisos, fuera del control directo del texto del modelo. | LT + BE | 1.1.1, 1.1.2 | 4–8 |
| 1.1.4 | Datos de demostración: preparar repositorio npm, versiones afectadas/seguras, dependencia transitiva, avisos sin CVE y registros históricos. | Conjunto de datos reproducible con resultados esperados para CA-01 a CA-05; datos sintéticos identificados y sin secretos reales. | QA + SEC | 1.1.1 | 2–4 |

**Esfuerzo:** 14–26 horas-persona.

### 1.2 Plataforma base y control de acceso

**Entregable:** aplicación base ejecutable con persistencia, identidad y ejecución aislada.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.2.1 | Proyecto y entorno: estructura de código, configuración, arranque con Docker, proceso de compilación y comprobaciones automatizadas. | Un equipo limpio puede iniciar backend, frontend y PostgreSQL con instrucciones documentadas y datos de prueba. | BE + SEC | 1.1.3 | 6–10 |
| 1.2.2 | Persistencia: esquema y migraciones de aplicaciones, inventarios, despliegues, amenazas, evidencias, hallazgos, ejecuciones, parches, pruebas, aprobaciones y auditoría. | Relaciones y restricciones implementadas; historial preservado; transacciones evitan estados parciales en operaciones críticas. | BE | 1.2.1 | 6–10 |
| 1.2.3 | Acceso y secretos: autenticación, roles por proyecto, referencias protegidas a credenciales, redacción y política de datos enviados a modelos. | El servidor bloquea accesos fuera de ámbito y envíos no permitidos; secretos de prueba no aparecen en logs, respuestas ni prompts persistidos. | BE + SEC | 1.2.2 | 8–12 |
| 1.2.4 | Ejecutor Docker: espacio de trabajo efímero, ejecución sin privilegios, límites de CPU/memoria/disco/tiempo, red controlada, recogida de artefactos y limpieza. | Una tarea de prueba se ejecuta y termina sin acceder a credenciales de producción ni al host fuera del espacio permitido; el contenedor de trabajo no recibe el socket Docker. | SEC + BE | 1.2.1, 1.2.3 | 6–10 |

**Esfuerzo:** 26–42 horas-persona.

### 1.3 Inventario y despliegues históricos

**Entregable:** representación verificable de lo que contiene cada aplicación y de lo que se desplegó.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.3.1 | Registro de activos y lectura GitHub: aplicaciones, entornos, responsables, repositorios autorizados y extracción por commit. | Una aplicación queda vinculada a un commit identificable; repositorios no autorizados son rechazados. | BE | 1.2.2, 1.2.3 | 4–8 |
| 1.3.2 | Inventario npm y Syft: extraer versiones resueltas, dependencias directas/transitivas y rutas desde manifiestos, lockfile y SBOM; reconciliar diferencias. | El inventario coincide con los casos conocidos; conserva commit, herramienta, versión y SBOM. Si la salida de Syft no contiene una relación necesaria, se obtiene del lockfile sin inventarla. | SEC + BE | 1.3.1, 1.2.4, 1.1.4 | 8–12 |
| 1.3.3 | Historial de despliegues: importador con esquema validado para entorno, periodo, commit/artefacto y procedencia. | Dos despliegues históricos se recuperan por separado y una versión retirada sigue siendo evaluable. | BE | 1.3.2 | 6–10 |
| 1.3.4 | Calidad y actualización del inventario: completitud, antigüedad, estados de fallo, actualización manual y nuevas instantáneas. | Un lockfile ausente o vencido limita la conclusión; una actualización preserva la instantánea anterior. | BE | 1.3.2 | 4–8 |

**Esfuerzo:** 22–38 horas-persona.

### 1.4 Fuentes de inteligencia y evidencia

**Entregable:** ingesta real de las cuatro fuentes y un registro común de avisos con procedencia.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.4.1 | Conector GitHub Security: obtener avisos y referencias disponibles con los permisos acordados. | Recupera un aviso real, conserva identificadores y procedencia, y diferencia falta de permisos de ausencia de resultados. | BE | 1.1.2, 1.2.2, 1.2.3 | 4–8 |
| 1.4.2 | Conector OSV: consultar por paquete/versión o identificador, normalizar rangos y alias, preservar origen. | Un paquete de prueba devuelve registros utilizables por la correlación; una respuesta vacía no equivale a inventario completo o ausencia universal de riesgo. | BE | 1.1.2, 1.2.2, 1.2.3 | 4–8 |
| 1.4.3 | Conector NVD: recuperar y enriquecer información por CVE, severidad y productos afectados; manejar cuotas y respuestas incompletas. | Un CVE se incorpora con procedencia y datos desconocidos explícitos. No se convierte automáticamente un CPE en una identidad npm. | BE + SEC | 1.1.2, 1.2.2, 1.2.3 | 4–8 |
| 1.4.4 | Conector CISA KEV: sincronizar catálogo y relacionar entradas por CVE. | Una entrada conocida aporta una señal de explotación reportada; su ausencia no se interpreta como prueba de que no existe explotación. | BE | 1.1.2, 1.2.2, 1.2.3 | 2–4 |
| 1.4.5 | Ingesta común: programación, consulta manual, avisos sin CVE, normalización, deduplicación, revisiones, evidencia y condiciones de uso de datos. | Las cuatro fuentes usan el esquema común; duplicados se agrupan sin perder referencias; cambios conservan historial; fallos y tiempo de consulta quedan registrados. | BE + SEC | 1.4.1–1.4.4 | 8–12 |

**Esfuerzo:** 22–40 horas-persona. Los conectores 1.4.1–1.4.4 pueden desarrollarse de manera independiente sobre el contrato de 1.1.3.

### 1.5 Orquestación multiagente y modelos

**Entregable:** flujo con estado persistente, investigación asistida por modelos y control efectivo de herramientas.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.5.1 | Flujo LangGraph: estados, transiciones, entradas/salidas estructuradas, persistencia y coordinación de responsabilidades de agentes. | El flujo básico se reanuda desde la última etapa confirmada tras un reinicio y enlaza todas las etapas con un identificador de ejecución. | IA + BE | 1.1.3, 1.2.2 | 8–12 |
| 1.5.2 | Integración Meterless: implementar el adaptador correspondiente al contrato verificado, autenticación, errores y registro de llamadas/resultados. | Al menos una operación real cumple el uso requerido por el hackathon y tiene evidencia en una ejecución; no se presupone que Meterless sea el orquestador o que soporte cualquier proveedor. | IA | 1.1.2, 1.2.3 | 6–12 |
| 1.5.3 | Adaptador de modelo: integrar un modelo permitido, con NVIDIA como candidato del SRS; validar respuestas estructuradas, tiempos de espera y errores. | El modelo ejecuta una tarea técnica real con su identidad registrada; solo se conecta mediante Meterless si esa ruta está soportada. | IA | 1.1.2, 1.2.3, 1.5.2 | 6–10 |
| 1.5.4 | Investigación y explicación: reunir referencias, detectar contradicciones, separar hechos/supuestos y producir una síntesis con evidencia. | Un caso insuficiente sigue siendo preliminar/indeterminado; las afirmaciones verificables remiten a evidencia y la salida no determina por sí sola la vulnerabilidad. | IA + SEC | 1.4.5, 1.5.1, 1.5.3 | 8–12 |
| 1.5.5 | Control de ejecución: permisos de herramientas, instrucciones externas no confiables, idempotencia, pausa, cancelación y presupuestos. | Un contenido malicioso no amplía permisos; cancelar impide nuevas acciones; agotar intentos o presupuesto lleva a intervención humana; se reconcilian efectos inciertos antes de reintentarlos. | IA + BE + SEC | 1.5.1, 1.2.3, 1.2.4 | 6–10 |

**Esfuerzo:** 34–56 horas-persona.

### 1.6 Correlación, exposición y prioridad

**Entregable:** hallazgos reproducibles que relacionan evidencia externa con activos actuales e históricos.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.6.1 | Motor determinista de versiones: identidad npm, rangos, límites, exclusiones, prereleases y versiones no interpretables. | Casos etiquetados producen el resultado esperado; un rango no soportado genera indeterminación; quedan registradas regla y entradas. | BE + SEC | 1.3.2, 1.4.5 | 8–12 |
| 1.6.2 | Evaluación de exposición: versión, presencia, despliegue histórico, condiciones de explotación y estado de compromiso separado. | Distingue potencial, confirmada, no afectada e indeterminada; detecta exposición histórica sin inferir compromiso por coincidencia de versión. | BE + SEC | 1.6.1, 1.3.3, 1.3.4, 1.5.4 | 6–10 |
| 1.6.3 | Política de prioridad: combinar severidad disponible, KEV, exposición y criticidad; separar confianza de prioridad. | Mismas entradas y política producen la misma prioridad; factores ausentes y versión de política son visibles. | SEC + BE | 1.6.2, 1.1.1 | 4–8 |
| 1.6.4 | Ciclo del hallazgo: reevaluación por cambios, cierre justificado, descarte, aceptación de riesgo con revisión y reapertura. | Un cambio de aviso o inventario reevalúa el caso sin borrar la conclusión previa; toda decisión manual tiene autor y motivo. | BE | 1.6.3, 1.5.1 | 4–8 |

**Esfuerzo:** 22–38 horas-persona.

### 1.7 Remediación y validación aislada

**Entregable:** cambio técnico aplicable, con pruebas y reescaneo vinculados al commit exacto.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.7.1 | Plan de respuesta: alternativas, versión de destino comprobada, compatibilidad, riesgo residual, validación, reversión y recomendaciones por exposición histórica. | El plan justifica actualización, mitigación o abstención. No inventa versiones seguras ni cierra posible compromiso por actualizar un paquete. | IA + SEC | 1.6.4, 1.5.3 | 6–10 |
| 1.7.2 | Generador de parche: rama aislada desde commit conocido, cambios acotados en código/manifiesto/lockfile y pruebas pertinentes. | Produce un diff reproducible dentro del alcance; modificaciones no autorizadas bloquean la propuesta; la rama protegida no cambia. | IA + BE | 1.7.1, 1.2.4, 1.5.5 | 8–16 |
| 1.7.3 | Validación funcional: instalación y pruebas del proyecto, comparación base/corrección cuando sea posible y captura de artefactos. | Resultados aprobados, fallidos, incompletos o no ejecutados son distinguibles y referencian commit, comandos y herramientas. | SEC + QA | 1.7.2 | 6–10 |
| 1.7.4 | Validación de seguridad: regenerar SBOM con Syft, ejecutar Trivy y OSV-Scanner, correlacionar de nuevo y controlar ciclos de corrección. | Las tres herramientas tienen evidencia de ejecución; resultados discrepantes se conservan y explican; la corrección demuestra eliminación del hallazgo o riesgo residual; fallos repetidos respetan el presupuesto. | SEC + IA | 1.7.3, 1.3.2, 1.6.1, 1.5.5 | 8–12 |

**Esfuerzo:** 28–48 horas-persona. El generador podrá utilizar el modelo integrado y operaciones Git permitidas; la automatización programática de Cursor no es una dependencia implícita de este entregable.

### 1.8 Aprobaciones y entrega del pull request

**Entregable:** propuesta revisable con autorización vinculada a la acción y al artefacto.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.8.1 | Aprobación humana: solicitar, aceptar o rechazar acción, repositorio, destino, diff y commit, con identidad y justificación. | Un cambio de commit, destino o diff invalida la aprobación anterior y obliga a revisar la nueva propuesta. | BE + SEC | 1.7.4, 1.2.3 | 6–10 |
| 1.8.2 | Publicador GitHub: publicar rama y PR autorizado, incluir evidencia y resultados, y reconciliar reintentos. | Se crea un único PR por propuesta; una respuesta perdida no duplica la operación; se registra el enlace y estado de entrega. | BE | 1.8.1, 1.5.5 | 6–10 |
| 1.8.3 | Restricciones y auditoría: bloquear merge, despliegues, infraestructura y secretos; registrar decisiones y efectos en una bitácora de solo adición. | Intentos de operaciones excluidas son rechazados; cada acción de entrega puede reconstruirse y no puede editarse desde la aplicación. | SEC + BE | 1.8.2 | 4–8 |

**Esfuerzo:** 16–28 horas-persona. El permiso para publicar una rama o PR debe estar establecido por la política del repositorio; el ejecutor aislado no recibe por ello credenciales generales de escritura.

### 1.9 Interfaz y reportes

**Entregable:** aplicación web utilizable por administrador, analista, desarrollador, aprobador y auditor según su ámbito.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.9.1 | Acceso, activos y configuración: aplicaciones, repositorios, inventario, importación histórica, conectores y límites. | El usuario autorizado configura una aplicación y consulta completitud del inventario; los secretos permanecen ocultos y los errores son comprensibles. | FE + BE | 1.2.3, 1.3.4, 1.3.3, 1.4.5 | 6–10 |
| 1.9.2 | Investigaciones y hallazgos: filtros, detalle, fuentes, versiones, prioridad/confianza, historial y controles de pausa/cancelación. | El analista encuentra un caso y reconstruye la conclusión desde evidencia accesible; distingue hechos, incertidumbre y datos faltantes. | FE | 1.6.4, 1.5.5 | 8–12 |
| 1.9.3 | Revisión de propuesta: plan, diff, pruebas, aprobación/rechazo y enlace del PR. | El aprobador ve el artefacto exacto y los riesgos antes de decidir; un cambio invalida la aprobación en la interfaz y en el servidor. | FE | 1.8.3 | 6–10 |
| 1.9.4 | Reporte exportable y estados de interfaz: reporte completo, vistas vacías/cargando/error, etiquetas, teclado y foco visible. | Un auditor obtiene un reporte con fuentes, versiones, cambios, resultados y decisiones; el recorrido esencial se realiza con teclado. | FE + QA | 1.9.1–1.9.3 | 6–10 |

**Esfuerzo:** 26–42 horas-persona. Las pantallas pueden adelantarse con los contratos de 1.1.3; su cierre requiere los servicios reales indicados.

### 1.10 Observabilidad y operación

**Entregable:** ejecución observable, recuperable y repetible del entorno de demostración.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.10.1 | Instrumentación OpenTelemetry: trazas por caso/etapa, errores de conectores, duración, límites y consumo disponible; consulta de estado operativo. | Una investigación enlaza sus etapas y llamadas; un consumo no informado aparece como desconocido; no hay secretos en la telemetría. | SEC + BE | 1.4.5, 1.5.5 | 6–10 |
| 1.10.2 | Retención, respaldo y restauración: políticas configurables y procedimientos sobre PostgreSQL y artefactos. | Se restaura una copia de prueba y se recuperan registros y referencias; se documenta el tratamiento de artefactos vencidos. | SEC | 1.2.2 | 4–8 |
| 1.10.3 | Paquete operativo: versiones fijadas, configuración de ejemplo sin secretos, arranque/parada, limpieza de trabajos y guía de resolución de fallos. | La versión candidata arranca con configuración documentada y permite reproducir una investigación; herramientas y datos externos usados quedan identificados. | SEC + BE | 1.8.3, 1.9.4, 1.10.1, 1.10.2 | 4–8 |

**Esfuerzo:** 14–26 horas-persona. La instrumentación se incorpora durante el desarrollo; 1.10.1 verifica su cobertura completa.

### 1.11 Aceptación y entrega del MVP

**Entregable:** versión demostrable acompañada de resultados de aceptación y documentación de límites.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.11.1 | Aceptación funcional completa: ejecutar CA-01–CA-07 y CA-12, comprobar inventario, correlación, exposición histórica, parche, fallo controlado y reporte. | Evidencia por escenario, con entradas y resultados reproducibles; los defectos quedan identificados por paquete y severidad. | QA + SEC | 1.1.4, 1.10.3 | 8–12 |
| 1.11.2 | Aceptación de controles: ejecutar CA-08–CA-11 y CA-13; comprobar permisos, aprobación obsoleta, reinicio, idempotencia, degradación y contenido malicioso. | Los controles actúan en servidor/ejecutor y no dependen de obediencia del modelo; quedan artefactos de cada comprobación. | QA + SEC | 1.10.3 | 8–12 |
| 1.11.3 | Metas no funcionales y estabilización: medir correlación y frecuencia de consulta, revisar accesibilidad, privacidad, recursos y recuperación; corregir defectos de aceptación y repetir comprobaciones afectadas. | RNF aplicables con evidencia, condiciones del ensayo y resultado; la versión candidata no tiene bloqueos funcionales o de control de acceso pendientes. | QA + equipo | 1.11.1, 1.11.2 | 8–16 |
| 1.11.4 | Entrega: guía de instalación/uso, arquitectura final, matriz de requisitos, registro de decisiones, guion de demostración y versión identificada. | Se demuestra un caso completo y un caso histórico; se entregan reporte, PR, evidencia real de Meterless y resultados CA-01–CA-13. Simulaciones y limitaciones quedan explícitas. | LT + QA | 1.11.3 | 4–8 |

**Esfuerzo:** 28–48 horas-persona. La corrección prevista en 1.11.3 cubre incidencias acotadas; un rediseño por una API incompatible requiere reestimar los paquetes afectados.

### 1.12 Integraciones condicionales del hackathon

Estos paquetes pertenecen al conjunto tecnológico autorizado, pero no se incluyen en la suma base mientras conserve vigencia su condición en el SRS. La decisión de 1.1.2 identifica cuáles pasan a ser obligatorios y actualiza esfuerzo y criterios de entrega.

| ID | Paquete y trabajo incluido | Criterio de cierre | Responsable | Dependencias | Horas |
|---|---|---|---|---|---|
| 1.12.1 | Grok/X: incorporar investigación de publicaciones mediante capacidades autorizadas y verificadas; conservar autoría, URL y evidencia. | Una consulta real enriquece un caso; la publicación sigue las mismas reglas de verificación y no se toma automáticamente como hecho confirmado. | IA + BE | 1.1.2, 1.4.5, 1.5.4 | 8–16 |
| 1.12.2 | Zetaris: incorporar una consulta real sobre los datos autorizados necesarios para la demostración. | La consulta combina las fuentes acordadas con trazabilidad y control de acceso; se registra qué valor aporta al escenario del hackathon. | BE | 1.1.2, 1.3.3, 1.4.5 | 8–16 |
| 1.12.3 | Cursor programático: integrar únicamente una interfaz de automatización disponible y permitida para generar parches. | Produce un cambio real en el mismo entorno y con las mismas restricciones y validaciones de 1.7; su uso por el desarrollador no se presenta como integración del producto. | IA + SEC | 1.1.2, 1.7.4 | 8–16 |

**Esfuerzo adicional si se activan los tres:** 24–48 horas-persona. Los requisitos del hackathon deben verificarse antes de seleccionar paquetes por suposiciones sobre patrocinadores.

## 4. Secuencia de implementación e hitos

Los hitos indican resultados demostrables. No equivalen a días ni se contabilizan como trabajo adicional a los paquetes.

| Hito | Resultado verificable | Paquetes que lo habilitan |
|---|---|---|
| H0 — Alcance viable | Contratos, accesos, uso real previsto de Meterless y datos de demostración definidos. | 1.1.1–1.1.4 |
| H1 — Activo inventariado | Una aplicación npm tiene dependencias, SBOM y despliegue histórico consultables. | 1.2 y 1.3 |
| H2 — Amenaza evaluada | Un aviso de las fuentes conectadas produce un hallazgo con exposición, prioridad y evidencia. | 1.4, 1.5 y 1.6 |
| H3 — Corrección validada | Una rama contiene una corrección con pruebas, Syft, Trivy y OSV-Scanner vinculados al commit. | 1.7 |
| H4 — Propuesta entregada | Un usuario revisa y autoriza la propuesta; se genera un PR único y un reporte auditable. | 1.8 y 1.9 |
| H5 — MVP aceptado | Entorno reproducible, CA-01–CA-13 y RNF aplicables con evidencia; demostración final preparada. | 1.10 y 1.11; 1.12 si se activa |

**Secuencia técnica dominante:** contratos → plataforma → inventario y fuentes → investigación/correlación → plan y parche → validación → aprobación/PR → aceptación. La disponibilidad de Meterless y del modelo debe resolverse desde H0 para evitar descubrir el bloqueo al llegar a la remediación.

Después de definir los contratos pueden avanzar en paralelo las fuentes, el inventario, el esqueleto del flujo y la interfaz. Los permisos, el aislamiento y la persistencia son dependencias de los paquetes que los necesitan, no actividades que se añaden al terminar la demostración. La ruta crítica de calendario deberá calcularse cuando se asignen personas y disponibilidad.

## 5. Estimación de esfuerzo

| Entregable | Horas-persona |
|---|---:|
| 1.1 Alcance y contratos | 14–26 |
| 1.2 Plataforma base | 26–42 |
| 1.3 Inventario | 22–38 |
| 1.4 Fuentes de inteligencia | 22–40 |
| 1.5 Agentes y modelos | 34–56 |
| 1.6 Correlación | 22–38 |
| 1.7 Remediación y validación | 28–48 |
| 1.8 Aprobaciones y PR | 16–28 |
| 1.9 Interfaz y reportes | 26–42 |
| 1.10 Operación | 14–26 |
| 1.11 Aceptación y entrega | 28–48 |
| **Total base: 44 paquetes** | **252–432** |
| 1.12 Tres integraciones condicionales | 24–48 adicionales |
| **Total si se activan las tres: 47 paquetes** | **276–480** |

Son estimaciones iniciales de ingeniería para el alcance completo del SRS, incluidas las comprobaciones descritas. No incluyen esperas por credenciales, cuotas, aprobaciones de terceros ni cambios de alcance. Tampoco incluyen una reserva de calendario adicional.

Como referencia de capacidad, 252–432 horas equivalen a 31,5–54 jornadas-persona de ocho horas. Dividir esa cifra entre el número de integrantes no produce un plazo garantizado: existen dependencias y disponibilidad desigual por especialidad. La estimación deberá revisarse después de H0 y tras completar el primer caso de extremo a extremo.

Si el tiempo disponible resulta menor, deberá acordarse un recorte explícito del SRS o una entrega parcial. No debe declararse terminado el MVP completo por presentar únicamente el flujo exitoso con conectores simulados.

## 6. Cobertura del SRS

### 6.1 Requisitos funcionales

| Requisitos | Paquetes responsables |
|---|---|
| RF-01–RF-02: activos y conectores | 1.2.3, 1.3.1, 1.4.1–1.4.5, 1.9.1 |
| RF-03–RF-06: inventario e historial | 1.3.2–1.3.4 |
| RF-08–RF-11: monitoreo y normalización | 1.4.1–1.4.5 |
| RF-12–RF-14: investigación y evidencia | 1.4.5, 1.5.4 |
| RF-16–RF-22: correlación y ciclo del hallazgo | 1.6.1–1.6.4 |
| RF-23–RF-25: planificación de remediación | 1.7.1 |
| RF-26–RF-28: generación de cambios | 1.7.2 |
| RF-29: propuesta de PR | 1.8.2 |
| RF-30–RF-33: validación y límites | 1.7.3–1.7.4, 1.5.5 |
| RF-35–RF-37: aprobación y restricciones | 1.8.1–1.8.3 |
| RF-39–RF-41: estado, reintentos y cancelación | 1.5.1, 1.5.5, 1.8.2 |
| RF-42–RF-43: consulta y reporte | 1.9.1–1.9.4 |
| RF-44: auditoría | 1.2.2, 1.5.1, 1.8.3 |
| RF-45: estado operativo y consumo | 1.10.1 |
| RF-15: X, condicional | 1.12.1, si se activa |

RF-07, RF-34, RF-38 y RF-46 permanecen fuera del MVP como evolución, según el SRS. La generación básica de SBOM de RF-30 no activa automáticamente todo RF-07.

### 6.2 Requisitos no funcionales

| Requisitos | Implementación y evidencia principal |
|---|---|
| RNF-01–RNF-02: acceso y secretos | 1.2.3, 1.8.3, 1.11.2 |
| RNF-03: aislamiento | 1.2.4, 1.7.2–1.7.4, 1.11.2 |
| RNF-04–RNF-05: contenido no confiable y privacidad | 1.2.3, 1.5.5, 1.11.2 |
| RNF-06: consistencia | 1.6.1, 1.6.3, 1.11.1 |
| RNF-07–RNF-08: recuperación y degradación | 1.4.5, 1.5.1, 1.5.5, 1.8.2, 1.11.2 |
| RNF-09–RNF-10: rendimiento y actualización | 1.4.5, 1.6.1, 1.11.3 |
| RNF-11–RNF-12: presupuestos y observabilidad | 1.5.5, 1.10.1, 1.11.3 |
| RNF-13–RNF-14: usabilidad y accesibilidad | 1.9.1–1.9.4, 1.11.3 |
| RNF-15–RNF-16: modularidad y reproducibilidad | 1.1.3, 1.7.3–1.7.4, 1.10.3 |
| RNF-17–RNF-18: retención y respaldo | 1.10.2, 1.11.3 |

### 6.3 Criterios de aceptación

| Criterios | Evidencia que debe entregarse |
|---|---|
| CA-01–CA-03 | Casos directos/transitivos y fuera de rango, con inventario, reglas y resultados esperados. |
| CA-04–CA-05 | Caso indeterminado y exposición histórica, con registros que explican la conclusión. |
| CA-06–CA-07 | Un parche que supera validación y un ciclo fallido que se detiene por límites. |
| CA-08–CA-09 | Rechazo de acciones no permitidas y anulación de aprobación por cambio de artefacto. |
| CA-10–CA-11 | Recuperación tras reinicio, eventos repetidos, creación idempotente de PR y fallos/contradicciones de fuentes. |
| CA-12–CA-13 | Reporte completo y prueba de que instrucciones externas no amplían permisos. |

La evidencia funcional se consolida en 1.11.1; la de controles y resiliencia, en 1.11.2. Las integraciones obligatorias deben acreditar uso real además de los escenarios reproducibles con datos controlados.

## 7. Definición de terminado y seguimiento

Cada paquete tendrá los estados **Pendiente, En curso, Bloqueado, En revisión o Terminado**. Al iniciar el desarrollo se le asignarán persona responsable, esfuerzo real, enlaces a cambios y evidencia. La planificación original partió con todos los paquetes pendientes; la fotografía de avance posterior figura en la sección 9.

Para cerrar un paquete deben estar disponibles:

1. Entregable descrito y dependencias de cierre satisfechas.
2. Código o configuración versionados cuando corresponda, con revisión.
3. Criterio de cierre comprobado y evidencia enlazada al commit evaluado.
4. Documentación de límites, errores y decisiones que afecten su uso.
5. Requisitos relacionados actualizados en la matriz de cobertura.

El MVP se entrega al completar H5, cerrar los 44 paquetes base y cualquier paquete condicional que haya pasado a ser obligatorio, y presentar evidencia de CA-01–CA-13 y de los RNF aplicables. Una integración obligatoria inaccesible debe resolverse o tratarse mediante un cambio explícito de alcance; una simulación no satisface ese requisito.

## 8. Decisiones que deben resolverse al inicio

| Decisión | Paquete | Impacto |
|---|---|---|
| Función y contrato técnico de Meterless | 1.1.2 | Define la implementación real de 1.5.2 y su evidencia de uso. |
| Modelo NVIDIA u otro proveedor permitido y ruta compatible | 1.1.2 | Define 1.5.3 sin suponer compatibilidad de APIs. |
| Obligatoriedad de Grok, Zetaris o Cursor programático | 1.1.2 | Activa paquetes de 1.12 y modifica el esfuerzo total. |
| Equipo, horas disponibles y plazo del hackathon | 1.1.1 | Permite calendarizar los hitos y comprobar si el alcance cabe. |
| Repositorios y permisos GitHub disponibles | 1.1.2 | Condiciona inventario y entrega real del PR. |
| Política de prioridad, presupuestos y aprobadores | 1.1.1 | Fija reglas comprobables para correlación, ejecución y revisión. |
| Framework de aplicación y autenticación | 1.1.3 | Elegir componentes open source necesarios, sin añadir proveedores cerrados fuera del conjunto autorizado. |

Estas decisiones forman parte del trabajo inicial del proyecto. El WBS permite comenzar por ellas sin convertir supuestos de integración en compromisos no comprobados.

## 9. Avance contrastado con la implementación

**Revisión:** 26 de octubre de 2026. Fuente de evidencia: `docs/verification.md`, `docs/ui-scaffold.md` y `docs/feasibility-assessment.md`. Esta tabla resume avance técnico; no sustituye el cierre individual de los paquetes ni estima un porcentaje de esfuerzo consumido.

| Entregable | Estado técnico | Evidencia disponible | Trabajo necesario para cerrarlo |
|---|---|---|---|
| 1.1 Alcance y contratos | Parcial; accesos externos pendientes | SRS, WBS, arquitectura, contratos preliminares y evaluación de factibilidad. Las cuatro fuentes públicas respondieron a sondas reales. | Cerrar decisiones operativas, accesos Meterless/modelo/GitHub y necesidad de Zetaris; crear repositorio y dataset reproducibles para CA-01–CA-05. |
| 1.2 Plataforma base | Base operativa; paquete completo parcial | 1.2.1 está implementado y probado localmente: Docker, API, PostgreSQL, migraciones, bloqueo de dependencias y CI preparado. Esquema de dominio y rol SQL de runtime disponibles. | Completar invariantes/operaciones de dominio, identidades y permisos por proyecto, política de datos y ejecutor aislado. Formalizar versión/commit de cierre de 1.2.1. |
| 1.3 Inventario | Parcial en registro; análisis pendiente | Alta y consulta persistentes de aplicaciones y repositorios. Tablas de inventario y despliegue preparadas. | Lectura autorizada por commit, Syft/lockfile, rutas transitivas, snapshots, importación histórica y control de antigüedad/completitud. |
| 1.4 Fuentes y evidencia | Adaptadores pendientes; conectividad prevalidada | Sondas públicas OSV/GitHub/NVD/KEV con HTTP 200 y respuesta JSON. Avisos manuales persistentes. | Implementar los cuatro adaptadores e ingesta con programación, normalización, alias, deduplicación, revisiones y procedencia. |
| 1.5 Agentes y modelos | Esqueleto parcial | LangGraph compila y ejecuta una vista previa que se detiene ante inventario faltante. | Meterless y modelo reales, investigación, checkpoints, reanudación, permisos de herramientas, presupuestos, pausa/cancelación e idempotencia. |
| 1.6 Correlación | Pendiente | Esquema y presentación futura disponibles. | Matching npm determinista, condiciones de exposición, prioridad, historial, cierre y reevaluación. |
| 1.7 Remediación y validación | Pendiente | Tablas y espacios de interfaz preparados. | Plan, cambio aislado, instalación/pruebas, Syft/Trivy/OSV-Scanner, reescaneo y ciclos acotados. |
| 1.8 Aprobaciones y PR | Pendiente; auditoría inicial parcial | Las altas se auditan transaccionalmente y el runtime no puede reescribir esos eventos. | Aprobador atribuible, artefacto exacto, invalidación, publicación única del PR y restricciones explícitas de herramientas/acciones. |
| 1.9 Interfaz y reportes | Scaffold completo; funcionalidad parcial | Cuatro destinos y flujo consolidado del caso. Altas/consultas básicas, estado y vista previa conectados. | Conectar inventario, evidencia, hallazgos, diff, validaciones, aprobaciones y exportación; revisar visualmente la disposición final. |
| 1.10 Operación | Parcial | Trazas HTTP/colector local, arranque documentado y respaldo/restauración comprobados. | Trazas por caso/etapa, consumo, retención configurable, limpieza de trabajos y reproducción de una investigación real completa. |
| 1.11 Aceptación y entrega | Pendiente | 19 pruebas del scaffold aprobadas y controles locales comprobados. | Ejecutar CA-01–CA-13, medir RNF aplicables, resolver fallos y preparar release, guion y artefactos del portal. Las 19 pruebas no equivalen a los CA completos. |
| 1.12 Integraciones condicionales | Pendientes de activación/implementación | Conjunto autorizado y contratos preliminares. | Confirmar obligación de Zetaris según track/reglas; ejecutar consulta real si aplica. Grok y Cursor programático conservan condición del SRS. |

### Orden inmediato de ejecución

1. **Cerrar accesos y caso de prueba** — 1.1.1–1.1.4, 1.5.2–1.5.3 y 1.12.2 si se exige: operación sintética real de patrocinadores y repositorio de prueba autorizado.
2. **Obtener datos confiables** — 1.2.2–1.2.4, 1.3.1–1.3.4 y 1.4.1–1.4.5: identidad/ámbito, inventario, despliegues y fuentes con evidencia.
3. **Producir el primer hallazgo** — 1.5.1, 1.5.4–1.5.5 y 1.6.1–1.6.4: conclusión determinista, prioridad, justificación y estado persistente.
4. **Preparar una respuesta comprobada** — 1.7.1–1.7.4 y 1.8.1–1.8.3: parche, validación, aprobación vigente y PR único.
5. **Completar el contexto operativo** — 1.9 y 1.10 durante los incrementos: servicios reales en la UI consolidada, reporte, auditoría, consumo y operación.
6. **Aceptar y entregar** — 1.11: CA-01–CA-13, comprobaciones RNF, commit/release y entrega completa verificable.

### Estado de los hitos

**H0 todavía no está cerrado** por los accesos/contratos y el dataset. La base de ejecución que soporta H1 está disponible; falta el inventario real. H2–H5 permanecen pendientes. La secuencia completa y las ventanas objetivo de entrega se detallan en `docs/feasibility-assessment.md`.

La entrega completa sigue siendo el objetivo. Los paquetes en estado parcial deben cerrarse por sus criterios originales; no se contabiliza un panel vacío, una tabla o una sonda de conectividad como el servicio terminado.
