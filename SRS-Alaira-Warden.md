# Especificación de requisitos de software (SRS)
## ALAIRA Warden — Sistema multiagente de inteligencia y respuesta ante vulnerabilidades

| Campo | Valor |
|---|---|
| Versión | 1.1 |
| Fecha | 27 de octubre de 2026 |
| Estado | Borrador para revisión y aprobación |
| Fuente | Propuesta de proyecto suministrada por el solicitante |
| Nombre de trabajo | ALAIRA Warden; pendiente de confirmación |
| Alcance del documento | Visión del producto y línea base propuesta para el MVP del hackathon |

Este documento transforma la propuesta en requisitos verificables. No afirma que las integraciones estén implementadas ni que sus proveedores dispongan de interfaces específicas. Las decisiones añadidas para concretar el alcance se identifican como propuestas y requieren validación antes de convertir este borrador en una línea base contractual.

**Actualización normativa 1.1:** las reglas completas suministradas por el solicitante hacen obligatorios Zetaris como capa de datos, Nightshift como proveedor principal y al menos un Meterless Engine operativo. [El ajuste del hackathon](docs/hackathon-alignment.md) incorpora RF-46–RF-49 y CA-14–CA-17, incluido modo de ejemplo sin credenciales, y prevalece sobre cualquier mención condicional anterior. CA-01–CA-13 siguen vigentes. NVIDIA se conecta mediante Nightshift; Cursor es opcional.

## 1. Introducción

### 1.1 Propósito

Definir el comportamiento, las interfaces, los datos, las restricciones y los criterios de aceptación de una plataforma que identifica amenazas de ciberseguridad, determina su relevancia para una organización y prepara remediaciones verificables bajo supervisión humana.

El SRS está dirigido al equipo de desarrollo, responsables de seguridad, DevSecOps, revisores, administradores y evaluadores del proyecto.

### 1.2 Problema que resuelve

La información sobre vulnerabilidades e incidentes se encuentra distribuida entre avisos oficiales, repositorios, bases de datos y publicaciones técnicas. Los equipos necesitan relacionarla con sus componentes y despliegues, determinar la exposición real y preparar correcciones compatibles. El sistema debe conectar esas actividades y conservar la evidencia que justifica sus resultados.

### 1.3 Objetivo del producto

Reducir el tiempo entre la disponibilidad de información sobre una amenaza y la preparación de una respuesta técnica revisable, mediante investigación, inventario, correlación, planificación, generación de parches y validación.

### 1.4 Convenciones

- **RF:** requisito funcional.
- **RNF:** requisito no funcional.
- **RN:** regla de negocio.
- **CA:** criterio de aceptación del sistema.
- **MVP:** requisito obligatorio para la primera demostración funcional propuesta.
- **Evolución:** requisito del producto posterior al MVP.
- **Debe:** comportamiento obligatorio dentro del alcance indicado.
- **Pendiente:** decisión que la propuesta original no permite cerrar.

Los criterios incluidos en las tablas describen evidencia observable de aceptación; no sustituyen los casos de prueba detallados de implementación.

### 1.5 Glosario

| Término | Definición operativa |
|---|---|
| Amenaza | Información sobre una vulnerabilidad, incidente, paquete malicioso o actualización de seguridad potencialmente relevante. Puede carecer de CVE. |
| Hallazgo | Resultado de relacionar una amenaza con una aplicación, componente, entorno y evidencia. |
| SBOM | Inventario de componentes de software y sus relaciones. |
| Exposición potencial | Existe coincidencia con un componente afectado, pero faltan datos para comprobar las condiciones de explotación. |
| Exposición confirmada | La evidencia comprueba presencia o ejecución del componente afectado y las condiciones de exposición conocidas aplicables. No implica compromiso. |
| Compromiso | Conclusión respaldada por evidencia específica de actividad maliciosa o acceso no autorizado; no se deduce únicamente de una versión vulnerable. |
| No afectado | La evidencia disponible permite descartar la afectación para el alcance y momento evaluados. |
| Indeterminado | Los datos son insuficientes, contradictorios o no interpretables para emitir una conclusión. |
| Remediación | Acción destinada a eliminar la causa de una exposición. |
| Mitigación | Acción que reduce el riesgo sin necesariamente eliminar la causa. |
| Evidencia | Dato con procedencia, momento de obtención y relación con una afirmación verificable. |

## 2. Descripción general y alcance

### 2.1 Perspectiva del producto

La plataforma coordina agentes especializados mediante un orquestador con estado persistente. Consume fuentes externas e inventarios autorizados, utiliza herramientas deterministas para comprobar componentes y versiones, y emplea modelos de IA para investigar, sintetizar y proponer acciones.

Los agentes representan responsabilidades lógicas. El SRS no exige ocho procesos, ocho modelos ni ejecución simultánea: la implementación puede compartir servicios siempre que preserve responsabilidades, permisos y trazabilidad.

### 2.2 Alcance del MVP propuesto

1. Una organización y repositorios de prueba expresamente autorizados en GitHub.
2. Un ecosistema inicial: Node.js/npm, con manifiesto y lockfile. La elección es una propuesta de implementación.
3. Inventario de dependencias directas y transitivas, asociado a un commit, y registro de despliegues actuales e históricos mediante importación explícita.
4. GitHub Security, OSV, NVD y CISA KEV como fuentes de avisos y señales de vulnerabilidad, además de la carga manual de reportes con referencias verificables.
5. Investigación, correlación determinista y clasificación de incertidumbre.
6. Propuestas de actualización de dependencias y cambios de código acotados, ejecutadas en aislamiento.
7. Pruebas, reescaneo, reporte y preparación de un pull request para revisión humana.
8. Interfaz para consultar investigaciones, evidencia, resultados y decisiones.
9. Persistencia de estados, límites de ejecución, control de acceso y auditoría.

Para demostrar exposición histórica, el MVP puede usar registros importados de despliegues. La presencia de una dependencia en un repositorio no se considerará prueba de que fue desplegada o ejecutada.

### 2.3 Evolución prevista

Monitoreo de X mediante una integración autorizada; múltiples ecosistemas; generación y consumo avanzado de SBOM; inspección de imágenes e infraestructura; conectores de despliegue; consultas federadas; notificaciones externas; despliegues controlados y flujos operativos para secretos. Las extensiones deberán usar tecnologías open source o servicios requeridos expresamente por el hackathon.

### 2.4 Fuera del alcance del MVP

- Explotación ofensiva, pruebas intrusivas o escaneo de activos no autorizados.
- Despliegue, merge o cambios automáticos en producción.
- Rotación, revocación o extracción de credenciales reales.
- Garantizar ausencia total de vulnerabilidades o detectar todos los ataques desconocidos.
- Sustituir la investigación forense, la respuesta organizacional a incidentes o la aprobación del responsable de seguridad.
- Certificar cumplimiento de una regulación específica.

### 2.5 Actores y permisos

| Actor | Facultades previstas |
|---|---|
| Administrador | Configurar organización, usuarios, activos, conectores, políticas y límites. |
| Analista de seguridad | Investigar, revisar evidencia, clasificar hallazgos y justificar descartes o reaperturas. |
| Desarrollador / DevSecOps | Consultar hallazgos de sus proyectos, preparar y revisar propuestas de código y validaciones. |
| Aprobador | Autorizar o rechazar una acción concreta dentro de su ámbito. |
| Auditor | Consultar y exportar registros autorizados sin modificar investigaciones ni aprobaciones. |
| Agente / servicio | Ejecutar únicamente las herramientas y acciones concedidas por la política de la ejecución. |

Una persona puede acumular roles en el MVP. La autorización se verifica en el servidor y nunca depende exclusivamente de la interfaz o de instrucciones al modelo.

### 2.6 Supuestos y dependencias

- La organización proporciona permisos, repositorios y datos de despliegue pertinentes.
- Los proyectos de prueba disponen de instrucciones reproducibles de instalación y validación.
- Las cuotas, disponibilidad, licencias y capacidades de proveedores deben comprobarse antes de integrarlos.
- Las fuentes externas pueden contener errores, cambios retroactivos o instrucciones maliciosas.
- La precisión de la correlación depende de la integridad y antigüedad del inventario.
- La ausencia de evidencia de explotación no demuestra ausencia de compromiso.

## 3. Requisitos funcionales

### 3.1 Configuración e inventario

| ID | Alcance | Requisito | Verificación |
|---|---|---|---|
| RF-01 | MVP | El sistema debe registrar aplicaciones, repositorios, entornos, responsables y criticidad, dentro de una organización. | Crear una aplicación y recuperar sus relaciones y responsable. |
| RF-02 | MVP | Debe configurar conectores, frecuencia de consulta, permisos y referencias a credenciales sin exponer sus valores. | Guardar un conector y consultar su configuración con el secreto oculto. |
| RF-03 | MVP | Debe construir un inventario desde manifiestos y lockfiles del ecosistema soportado, identificando versiones resueltas y dependencias directas y transitivas. | Comparar el inventario con un proyecto de prueba de composición conocida. |
| RF-04 | MVP | Debe vincular cada instantánea de inventario con repositorio, commit, fecha, herramienta y resultado de extracción. | Recuperar dos instantáneas de commits distintos sin sobrescribir la anterior. |
| RF-05 | MVP | Debe registrar despliegues actuales e históricos, con entorno, intervalo temporal, referencia al artefacto o commit y procedencia. | Importar un despliegue anterior y correlacionarlo aunque la versión actual sea segura. |
| RF-06 | MVP | Debe señalar inventarios incompletos, fallidos o vencidos según un umbral configurable, y permitir su actualización manual. | Un lockfile ausente o un inventario vencido produce una advertencia y limita la conclusión. |
| RF-07 | Evolución | Debe importar SBOM y analizar imágenes y configuraciones mediante adaptadores que preserven identidad, versión y procedencia. | Contrastar una imagen o SBOM conocida con su inventario resultante. |

### 3.2 Detección e investigación

| ID | Alcance | Requisito | Verificación |
|---|---|---|---|
| RF-08 | MVP | Debe consultar periódicamente GitHub Security, OSV, NVD y CISA KEV, y permitir iniciar una consulta manual o registrar un aviso. | Un aviso de prueba disponible en cualquiera de las fuentes genera una investigación. |
| RF-09 | MVP | Debe admitir avisos manuales con URL, descripción y fecha de recepción, incluso sin identificador CVE. | Registrar e investigar un incidente sin CVE. |
| RF-10 | MVP | Debe normalizar identificadores, alias, productos, ecosistemas, versiones y fechas, conservando la referencia original. | Un aviso con alias conserva todos los identificadores y su procedencia. |
| RF-11 | MVP | Debe agrupar duplicados mediante identificadores y relaciones verificables, conservando referencias, y versionar cambios materiales del aviso. | Dos entregas del mismo aviso no generan dos casos independientes; una actualización conserva el historial. |
| RF-12 | MVP | Debe distinguir evidencia confirmada, preliminar, contradictoria e insuficiente, e indicar la justificación de esa clasificación. | Una fuente aislada no corroborada aparece como preliminar, no como hecho confirmado. |
| RF-13 | MVP | Debe contrastar cada amenaza con los avisos y referencias disponibles en GitHub Security, OSV, NVD y CISA KEV, además de las referencias incluidas en el caso, registrando fuentes consultadas y limitaciones. | El reporte muestra referencias, intentos fallidos y hechos que no pudieron verificarse. |
| RF-14 | MVP | Debe conservar para cada evidencia URL o identificador de origen, fecha de publicación cuando exista, fecha de consulta y contenido pertinente o referencia verificable con huella. | Una afirmación del reporte permite recuperar su evidencia y momento de obtención. |
| RF-15 | Evolución | Debe incorporar publicaciones de X mediante un conector autorizado, conservando autoría y enlace original y aplicando las mismas reglas de verificación. | Una publicación inicia una investigación sin eludir RF-12 y RF-13. |

### 3.3 Correlación y priorización

| ID | Alcance | Requisito | Verificación |
|---|---|---|---|
| RF-16 | MVP | Debe comparar identidad de paquete, ecosistema y versión resuelta con rangos afectados mediante reglas deterministas del ecosistema soportado. | Casos en límites inferiores, superiores, versiones excluidas y prereleases producen los resultados esperados. |
| RF-17 | MVP | Debe evaluar por separado coincidencia de versión, presencia en el entorno, ejecución histórica y condiciones conocidas de explotación. | Un caso muestra el resultado y evidencia de cada dimensión, incluidos valores desconocidos. |
| RF-18 | MVP | Debe clasificar cada relación amenaza–activo como no afectada, potencial, exposición confirmada o indeterminada, y registrar por separado el estado de compromiso. | Una coincidencia de versión por sí sola no se etiqueta como compromiso confirmado. |
| RF-19 | MVP | Debe explicar cada conclusión con versiones comparadas, instantánea utilizada, reglas aplicadas y condiciones comprobadas o desconocidas. | El revisor reproduce la comparación a partir del reporte. |
| RF-20 | MVP | Debe priorizar hallazgos mediante una política versionada que considere severidad disponible, explotación reportada, exposición y criticidad del activo, separando prioridad de confianza. | Los mismos datos y política producen la misma prioridad y muestran factores faltantes. |
| RF-21 | MVP | Debe reevaluar hallazgos cuando cambien el aviso, inventario o datos de despliegue, preservando conclusiones anteriores. | Una nueva versión afectada reabre o actualiza el caso y deja registro del motivo. |
| RF-22 | MVP | Debe permitir cerrar una investigación sin cambios cuando exista evidencia de no afectación, o descartarla manualmente con justificación atribuible. | El cierre conserva evidencia, autor, fecha y motivo y puede reabrirse. |

### 3.4 Planificación e ingeniería

| ID | Alcance | Requisito | Verificación |
|---|---|---|---|
| RF-23 | MVP | Debe elaborar un plan que incluya acción, evidencia, archivos o componentes afectados, compatibilidad, riesgos, validación y reversión. | El plan contiene todos los campos antes de habilitar la generación del parche. |
| RF-24 | MVP | Debe considerar actualización, reversión, configuración, mitigación o abstención según la evidencia, y justificar la alternativa seleccionada. | Si no existe versión corregida verificada, el sistema no inventa una y documenta la limitación. |
| RF-25 | MVP | Ante posible compromiso histórico o exposición de secretos, debe recomendar investigación de accesos y revisión o rotación autorizada de credenciales, sin ejecutarla. | Actualizar un paquete no cierra automáticamente el hallazgo de posible compromiso. |
| RF-26 | MVP | Debe generar cambios en una rama independiente vinculada al caso y al commit base, dentro de un entorno aislado. | La ejecución produce un diff sin modificar la rama protegida. |
| RF-27 | MVP | Debe actualizar manifiestos y lockfiles de forma coherente y añadir o adaptar pruebas cuando la corrección altere comportamiento. | La instalación reproduce las versiones propuestas y se inspeccionan los cambios de pruebas. |
| RF-28 | MVP | Debe registrar los archivos modificados y detectar cambios fuera del alcance autorizado antes de publicar una propuesta. | Un cambio en un archivo no permitido bloquea la publicación y solicita revisión. |
| RF-29 | MVP | Debe preparar un pull request con amenaza, evidencia, alcance, diff, resultados y limitaciones; su creación requiere la autorización configurada para el repositorio. | El PR enlaza el caso y no se fusiona automáticamente. |

### 3.5 Validación y control humano

| ID | Alcance | Requisito | Verificación |
|---|---|---|---|
| RF-30 | MVP | Debe generar o actualizar el inventario SBOM con Syft y ejecutar análisis de dependencias con Trivy y OSV-Scanner sobre el commit corregido, además de las pruebas pertinentes; debe registrar comando, versión de herramientas, resultado y artefactos. | Cada resultado se vincula al commit exacto que se propone revisar. |
| RF-31 | MVP | Debe distinguir validación aprobada, fallida, incompleta y no ejecutada, y señalar fallos preexistentes cuando exista una ejecución base comparable. | Una herramienta indisponible no produce un resultado aprobado. |
| RF-32 | MVP | Debe comprobar que la corrección elimina la coincidencia afectada o documentar el riesgo residual cuando solo sea una mitigación. | El reescaneo y la correlación final justifican el resultado. |
| RF-33 | MVP | Debe devolver fallos al agente de ingeniería respetando límites configurados de intentos, tiempo y consumo; agotarlos deriva el caso a intervención humana. | Una prueba que falla repetidamente no genera un ciclo ilimitado. |
| RF-34 | Evolución | Debe incorporar revisión de código mediante una tecnología aprobada y disponible para el hackathon, distinguiéndola de pruebas y análisis de seguridad. | La ausencia de revisión adicional queda visible y no altera resultados de pruebas. |
| RF-35 | MVP | Debe mostrar la acción exacta, destino, commit o artefacto y evidencia al solicitar aprobación; la decisión incluye usuario, fecha y justificación. | Un aprobador autorizado puede aceptar o rechazar una propuesta concreta. |
| RF-36 | MVP | Debe invalidar aprobaciones si cambia el diff, commit, destino o alcance autorizado antes de ejecutar la acción. | Un commit posterior obliga a revisar y aprobar nuevamente. |
| RF-37 | MVP | Debe impedir merge, despliegue, cambios de infraestructura y manipulación de secretos durante el MVP, incluso si un agente los solicita. | Las pruebas de permisos rechazan esas operaciones. |
| RF-38 | Evolución | Si se habilitan acciones operativas sensibles, debe exigir autorización explícita por acción y ámbito, comprobarla al ejecutar y registrar resultado y reversión disponible. | Una autorización para un entorno no permite actuar sobre otro. |

### 3.6 Orquestación, consulta y auditoría

| ID | Alcance | Requisito | Verificación |
|---|---|---|---|
| RF-39 | MVP | Debe persistir estado, entradas, salidas estructuradas, identificador de ejecución y agente responsable por etapa. | Tras un reinicio se recupera la última etapa confirmada. |
| RF-40 | MVP | Debe aplicar reintentos acotados e idempotencia a operaciones externas, reconciliando resultados inciertos antes de repetir efectos. | Una respuesta perdida al crear un PR no genera un segundo PR. |
| RF-41 | MVP | Debe permitir pausar o cancelar una investigación y detener nuevas acciones; las tareas en curso se terminan de forma controlada y se registran efectos ya realizados. | La cancelación impide nuevas escrituras y deja un estado final visible. |
| RF-42 | MVP | Debe ofrecer consultas por aplicación, amenaza, prioridad, estado y fecha, con acceso al detalle de evidencia, cambios y pruebas. | Un usuario encuentra un hallazgo y navega hasta sus evidencias autorizadas. |
| RF-43 | MVP | Debe generar un reporte exportable con resumen, activos evaluados, metodología, evidencia, incertidumbres, plan, pruebas y decisiones humanas. | El reporte permite reconstruir el caso sin depender del historial de conversación de un modelo. |
| RF-44 | MVP | Debe registrar cambios de configuración, accesos relevantes, decisiones y acciones en una bitácora atribuible, de solo adición para usuarios y agentes. | Un usuario o agente no puede sobrescribir ni borrar un evento mediante la aplicación. |
| RF-45 | MVP | Debe mostrar fallos de conectores y tareas, duración y consumo disponible; cuando el proveedor no informe consumo, debe indicarlo como desconocido. | Un error de proveedor aparece en el caso y en la vista operativa. |
| RF-46 | Evolución | Debe enviar notificaciones configurables por canales autorizados, evitando duplicados para un mismo evento. | Reintentar la entrega no genera alertas repetidas para el mismo destinatario y evento. |

## 4. Reglas de negocio

| ID | Regla |
|---|---|
| RN-01 | Una salida de un modelo es una propuesta o interpretación; no constituye por sí sola evidencia de afectación, explotación o éxito de una corrección. |
| RN-02 | Una comparación no soportada o un dato ausente produce un resultado indeterminado; nunca se interpreta como ausencia de vulnerabilidad. |
| RN-03 | La cantidad de referencias no garantiza independencia: fuentes que repiten el mismo reporte deben identificarse cuando sea posible. |
| RN-04 | Severidad de la vulnerabilidad, prioridad operativa y confianza de la conclusión son campos independientes. |
| RN-05 | Los agentes solo actúan sobre activos y herramientas autorizados; el contenido de repositorios y fuentes externas no puede ampliar permisos. |
| RN-06 | Los cambios de producción y secretos permanecen fuera del MVP. En una fase posterior, su aprobación no puede inferirse de la aprobación de un plan o PR. |
| RN-07 | Un parche preparado, validado, aprobado o fusionado no equivale a una corrección desplegada. |
| RN-08 | La exposición actual solo puede cerrarse como remediada con evidencia del entorno objetivo; la exposición histórica y el posible compromiso conservan seguimiento separado. |
| RN-09 | Descartar, aceptar un riesgo o anular una conclusión exige identidad y justificación; la aceptación de riesgo debe incluir fecha de revisión. |
| RN-10 | Las explicaciones registran hechos, reglas, supuestos y justificaciones resumidas; no se requiere almacenar razonamiento interno privado del modelo. |

## 5. Flujo y estados

### 5.1 Flujo principal

1. Registrar o actualizar inventario y datos de despliegue.
2. Detectar o ingresar una amenaza y normalizar sus referencias.
3. Investigar evidencia, contradicciones y condiciones de afectación.
4. Correlacionar con componentes y despliegues.
5. Cerrar con evidencia si no existe afectación; solicitar información si el resultado es indeterminado.
6. Elaborar un plan cuando exista exposición que requiera acción.
7. Generar un parche autorizado en aislamiento.
8. Ejecutar validación y repetir la corrección únicamente dentro del presupuesto.
9. Presentar reporte y propuesta para revisión humana.
10. Registrar decisión y, si está autorizado, publicar el PR. El MVP finaliza en la entrega de la propuesta, no en su despliegue.

### 5.2 Estados de investigación

| Estado | Condición o transición principal |
|---|---|
| Detectada | Aviso registrado; pasa a investigación. |
| En investigación | Se reúne evidencia; pasa a correlación o a espera de información. |
| En correlación | Se evalúa el inventario; pasa a planificación, espera de información o cierre justificado. |
| En planificación | Se prepara una respuesta; pasa a ingeniería o revisión humana si no puede automatizarse. |
| En ingeniería | Se genera el cambio; pasa a validación. |
| En validación | Se comprueba el cambio; pasa a revisión, vuelve a ingeniería dentro de límites o requiere intervención. |
| En revisión humana | Se presenta una propuesta; se aprueba, rechaza o solicita una modificación. |
| Propuesta entregada | Reporte y artefacto disponibles; no implica remediación del entorno. |
| En espera de información | Faltan datos o servicios; se conserva la etapa que debe reanudarse. |
| Requiere intervención | Se agotaron límites o existe un fallo que no permite continuar automáticamente. |
| Cerrada | Conclusión y motivo registrados: no afectado, descartado, riesgo aceptado o remediación verificada. |
| Cancelada | Se impiden nuevas acciones y se documenta lo ya ejecutado. |

La pausa es un control adicional que conserva el estado anterior. Toda transición debe registrar fecha, actor, motivo y versión de datos. La clasificación de afectación y el estado de aprobación son dimensiones separadas del estado de la investigación.

## 6. Requisitos de datos

| Entidad | Datos mínimos |
|---|---|
| Organización y usuario | Identificadores, roles, alcance de acceso y estado. |
| Aplicación y entorno | Responsable, criticidad, repositorios y relaciones entre servicios. |
| Instantánea de inventario | Commit o artefacto, fecha, herramienta, completitud, componentes y relaciones de dependencia. |
| Componente | Nombre normalizado, ecosistema, versión resuelta, origen y ruta de dependencia. |
| Despliegue | Aplicación, entorno, artefacto o commit, periodo conocido y evidencia de procedencia. |
| Amenaza | Identificadores y alias, tipo, descripción, versiones, condiciones, fechas y revisiones. |
| Evidencia | Fuente, autor si se conoce, fechas, extracto o referencia, huella y clasificación. |
| Hallazgo | Amenaza, activo, inventario, clasificación, condiciones, prioridad, confianza y justificación. |
| Plan y parche | Alternativas, selección, riesgos, reversión, commit base y propuesto, diff, rama y PR. |
| Validación | Commit evaluado, comandos, herramientas, resultados, duración y artefactos. |
| Aprobación | Acción, destino, artefacto, aprobador, decisión, fecha y vigencia o invalidación. |
| Ejecución | Estado, agente, herramientas, configuración, modelo identificado, presupuesto y errores. |
| Evento de auditoría | Actor, acción, fecha, entidad, resultado e identificador de correlación. |

Los identificadores deben ser únicos; las fechas deben almacenarse con referencia UTC y mostrarse con zona horaria. Las revisiones de avisos, inventarios y decisiones deben conservar vínculos históricos. Una eliminación de datos debe seguir una política explícita de retención y registrar su alcance, sin prometer retención indefinida.

Los valores de secretos no forman parte del inventario ni del reporte. Cuando un análisis detecte un posible secreto, debe guardar una referencia y metadatos redactados, no reproducir el valor.

## 7. Interfaces externas y decisiones tecnológicas

### 7.1 Interfaces de usuario

La interfaz del MVP debe ofrecer acceso autenticado a aplicaciones e inventarios, listado de investigaciones, detalle de hallazgos, evidencia enlazada, plan y diff, resultados de validación, decisiones humanas y estado de conectores. Debe distinguir visualmente datos confirmados, hipótesis y datos faltantes sin depender únicamente del color.

### 7.2 Contratos de integración

Cada adaptador debe definir autenticación, operaciones permitidas, esquema de entrada y salida, paginación si aplica, tiempos de espera, cuotas, estrategia de reintentos, versión y tratamiento de errores. Las notificaciones entrantes deben autenticarse cuando el proveedor permita hacerlo y protegerse frente a repetición de eventos.

| Integración candidata | Función prevista | Condición de incorporación |
|---|---|---|
| GitHub Security | Avisos de seguridad y señales de vulnerabilidad asociadas con repositorios y dependencias. | MVP; usar únicamente funciones disponibles en el plan y permisos aprobados. |
| OSV | Fuente estructurada de avisos de vulnerabilidad para correlación con paquetes y versiones. | MVP; los registros pueden tener licencias distintas según su fuente original; conservar atribución y metadatos de procedencia. |
| NVD | Datos de vulnerabilidades, identificadores CVE y señales de severidad/producto. | MVP; tratarlo como fuente de datos pública, conservar atribución NIST y revisar condiciones de registros de terceros. |
| CISA KEV | Catálogo de vulnerabilidades conocidas como explotadas, usado como señal de priorización. | MVP; datos del catálogo bajo CC0 1.0. |
| Grok | Investigación de publicaciones y reportes relacionados con amenazas. | Solo si el acceso provisto por el hackathon está disponible; toda salida se verifica con evidencia. |
| Zetaris | Capa de datos para consultar inventario y evidencia de la investigación. | Obligatorio para toda entrega según las reglas del evento suministradas por el solicitante. PostgreSQL puede conservar estado transaccional, checkpoints y auditoría; la ruta operativa de investigación debe usar Zetaris. |
| NVIDIA | Razonamiento y síntesis mediante modelos conectados a Nightshift. | Integrar donde contribuya. El premio NVIDIA exige al menos un Nemotron vía Nightshift en una función operativa y mostrar qué modelo procesó la solicitud. No sustituye comprobaciones deterministas. |
| Cursor | Asistencia de desarrollo para preparar cambios y pruebas. | Uso dentro del flujo de desarrollo; integración programática solo si el hackathon la requiere y está disponible. |
| Meterless | Nightshift como proveedor principal de IA y al menos un Engine en una función operativa. | Son dos obligaciones distintas: un cliente HTTP o listar modelos no demuestra un Engine. H-MEM, Markovian, World Model o Scout Intent requieren implementación y prueba de su función. |
| PostgreSQL | Persistencia de inventarios, investigaciones y auditoría. | Usar si la persistencia relacional es necesaria para el MVP. |
| OpenTelemetry | Trazas y métricas, con redacción de datos sensibles. | Usar para observabilidad cuando sea necesario durante el hackathon. |
| Docker | Entornos aislados para instalación y pruebas. | Usar para ejecutar código de repositorios de prueba con límites de permisos, red y recursos. |
| LangGraph | Orquestación con estado de las etapas del flujo. | Usar solo si facilita el flujo requerido por el hackathon; la arquitectura no depende de él. |
| Syft | Generación de SBOM e inventario de componentes. | MVP; open source Apache 2.0 ([licencia](https://github.com/anchore/syft/blob/main/LICENSE)). |
| Trivy | Análisis de dependencias y artefactos. | MVP; open source Apache 2.0 ([licencia](https://github.com/aquasecurity/trivy/blob/main/LICENSE)). |
| OSV-Scanner | Análisis de dependencias contra avisos OSV. | MVP; open source Apache 2.0 ([licencia](https://github.com/google/osv-scanner/blob/main/LICENSE)). |

La implementación debe limitarse a las tecnologías de esta tabla que sean open source o que el hackathon requiera expresamente. Para proveedores o productos cerrados incluidos por requerimiento del hackathon, se usará solo el acceso proporcionado y no se añadirá otro servicio de terceros. Una función no disponible se documentará como pendiente y no se presentará como integración real. Los adaptadores simulados deben identificarse en la interfaz, reporte y demostración. OSV, NVD y CISA KEV son fuentes de datos; su inclusión no implica que todos sus registros compartan una única licencia. El sistema debe conservar procedencia y atribución, respetar la licencia específica del registro cuando esté indicada y no redistribuir datos si sus condiciones no lo permiten.

## 8. Requisitos no funcionales

Los umbrales numéricos de esta sección son metas propuestas para el MVP y deberán ajustarse con mediciones. No representan compromisos aportados por la propuesta original.

| ID | Categoría | Requisito y criterio verificable |
|---|---|---|
| RNF-01 | Acceso | Toda operación sobre datos o acciones debe validar identidad, rol y ámbito en el servidor. Pruebas negativas deben impedir acceso entre proyectos no autorizados. |
| RNF-02 | Secretos | Credenciales almacenadas mediante un mecanismo protegido y referenciadas por identificador; comunicaciones externas cifradas; logs, reportes y prompts no deben contener secretos de prueba usados para verificar redacción. |
| RNF-03 | Aislamiento | Código, instalación y pruebas deben ejecutarse sin credenciales de producción, sin montajes del host ajenos al trabajo, sin privilegios administrativos y con límites de CPU, memoria, disco, duración y red. Verificar que un proceso de prueba no accede a recursos prohibidos. |
| RNF-04 | Contenido no confiable | Fuentes, archivos y salidas de herramientas deben tratarse como datos no confiables. Un aviso con instrucciones para extraer información o ejecutar herramientas no autorizadas debe ser rechazado por controles de ejecución. |
| RNF-05 | Privacidad | El envío de código o datos internos a modelos externos debe estar permitido por la política de la organización y limitarse al contexto necesario. Una política de denegación debe bloquear ese envío. |
| RNF-06 | Consistencia | Comparaciones de versiones y decisiones de política deben ser reproducibles para las mismas entradas y versión de regla. Se verificará con un conjunto de casos etiquetados. |
| RNF-07 | Recuperación | Reiniciar el orquestador no debe perder etapas confirmadas ni duplicar efectos externos. Verificar con interrupción antes y después de una escritura. |
| RNF-08 | Degradación | La caída de una fuente o modelo no debe producir una conclusión falsa de no afectación o validación exitosa; debe dejar una limitación visible y permitir reintento controlado. |
| RNF-09 | Rendimiento | Meta propuesta: correlacionar hasta 10 000 registros de componentes contra un aviso normalizado en ≤60 s en el percentil 95 de 20 ejecuciones, excluyendo consultas externas y generación por modelos. Registrar hardware y datos del ensayo. |
| RNF-10 | Actualización | Meta propuesta: consulta cada 15 minutos; con una fuente accesible, registrar un aviso elegible antes de 20 minutos desde que la API lo haga consultable. La fecha de publicación no equivale a disponibilidad en API. |
| RNF-11 | Presupuesto | Antes de ejecutar, deben existir límites finitos de intentos, tiempo y llamadas a modelos. Valor inicial propuesto: tres ciclos de corrección y 30 minutos de ejecución activa por caso, excluyendo espera humana. Alcanzar cualquier límite debe detener nuevas acciones. |
| RNF-12 | Observabilidad | Cada etapa debe emitir estado, duración y correlación con el caso; los errores deben permitir identificar proveedor o herramienta sin revelar secretos. |
| RNF-13 | Usabilidad | Un analista debe poder consultar desde el detalle del hallazgo su evidencia, versiones y validaciones sin acceder a logs técnicos. Probar el recorrido con un caso completo. |
| RNF-14 | Accesibilidad | Las funciones esenciales deben operarse con teclado, tener foco visible, etiquetas comprensibles y estados expresados con texto. Verificar navegación y uso de formularios sin ratón. |
| RNF-15 | Mantenibilidad | Los conectores y proveedores de modelos deben estar desacoplados de las reglas de correlación. Sustituir un adaptador de prueba no debe requerir cambiar esas reglas. |
| RNF-16 | Reproducibilidad | Toda validación debe registrar commit, entorno, herramientas y comandos suficientes para repetirla. No se exige que un modelo genere texto idéntico en ejecuciones distintas. |
| RNF-17 | Retención | Inventarios, evidencia, auditoría y artefactos deben tener políticas configurables de conservación y eliminación. Duraciones y excepciones quedan pendientes de aprobación antes de usar datos reales. |
| RNF-18 | Respaldo | Debe existir respaldo de datos persistentes y una prueba de restauración. RPO, RTO y disponibilidad de producción quedan pendientes y no se infieren de la demostración. |

## 9. Casos de uso principales

### CU-01 — Incorporar una aplicación

**Actor:** administrador. **Precondición:** repositorio autorizado y conector disponible.

1. Registra aplicación, entorno y responsable.
2. Autoriza el repositorio y solicita el inventario.
3. El sistema resuelve dependencias y guarda la instantánea vinculada al commit.
4. El administrador importa o vincula la evidencia de despliegue.

**Resultado:** inventario consultable con su cobertura. Si faltan datos, el sistema registra el fallo o inventario parcial y no supone versiones ni despliegues.

### CU-02 — Investigar una amenaza relevante

**Actor:** analista o evento programado. **Precondición:** fuente habilitada o aviso manual.

1. El sistema registra el aviso, referencias y alias.
2. Investiga y clasifica evidencia.
3. Compara componentes y versiones con inventarios y despliegues.
4. Produce hallazgos por activo y explica prioridad e incertidumbre.

**Resultado:** exposición justificada, conclusión de no afectación o solicitud de información. Un conflicto entre fuentes se conserva explícitamente.

### CU-03 — Preparar y revisar una corrección

**Actores:** desarrollador y aprobador. **Precondición:** hallazgo y repositorio autorizados para preparación de cambios.

1. El sistema propone alternativas y selecciona un plan con justificación.
2. Genera un parche aislado y ejecuta validaciones.
3. Si falla, corrige dentro del presupuesto o requiere intervención.
4. Presenta diff, resultados y riesgos para revisión.
5. Publica un PR si la política y autorización vigente lo permiten.

**Resultado:** propuesta trazable entregada; no hay merge ni despliegue automático. Un cambio posterior invalida la aprobación asociada al artefacto anterior.

### CU-04 — Investigar exposición histórica

**Actor:** analista. **Precondición:** registros históricos de despliegue.

1. Se registra un incidente de una versión comprometida.
2. El sistema identifica una ejecución o despliegue anterior afectado, aunque la versión actual sea segura.
3. Separa el estado actual del riesgo histórico y señala qué demuestra cada evidencia.
4. Recomienda investigación adicional y revisión autorizada de credenciales cuando corresponda.

**Resultado:** caso histórico abierto o derivado; el sistema no declara compromiso sin evidencia específica ni lo cierra únicamente por una actualización.

## 10. Criterios de aceptación del MVP

La demostración debe usar repositorios de prueba y datos etiquetados, sin requerir paquetes maliciosos activos ni secretos reales. Los avisos sintéticos y conectores simulados deben estar identificados.

| ID | Escenario | Resultado exigido | Requisitos vinculados |
|---|---|---|---|
| CA-01 | Dependencia directa afectada | Identifica versión, activo y referencia; explica la comparación y genera un hallazgo. | RF-03, RF-16–RF-19 |
| CA-02 | Dependencia transitiva afectada | Muestra la ruta de dependencia y no depende de que el paquete aparezca directamente en el manifiesto. | RF-03, RF-19 |
| CA-03 | Versiones fuera del rango | Clasifica los activos de prueba como no afectados con evidencia y sin generar un parche innecesario. | RF-16, RF-22 |
| CA-04 | Evidencia o inventario insuficiente | Muestra resultado indeterminado o preliminar y detalla datos faltantes. | RF-06, RF-12, RF-18 |
| CA-05 | Exposición histórica | Detecta el despliegue anterior afectado y mantiene seguimiento pese a la versión actual segura. | RF-05, RF-17, RF-25 |
| CA-06 | Corrección válida | Genera rama y diff coherentes; pruebas y reescaneo se vinculan al commit propuesto; entrega reporte y PR autorizado. | RF-23, RF-26–RF-32, RF-43 |
| CA-07 | Corrección fallida | Registra fallos y detiene el ciclo al alcanzar el límite, sin declarar validación exitosa. | RF-31, RF-33 |
| CA-08 | Acción no permitida | Un agente no logra fusionar, desplegar ni acceder a secretos de producción; el rechazo queda registrado. | RF-37, RNF-01–RNF-04 |
| CA-09 | Aprobación obsoleta | Modificar el commit o destino invalida la autorización previa. | RF-35, RF-36 |
| CA-10 | Reinicio y eventos repetidos | Recupera el caso y evita investigaciones o PR duplicados; una actualización material conserva historial. | RF-11, RF-39, RF-40 |
| CA-11 | Fuente caída o contradictoria | Conserva el estado y comunica la limitación, sin declarar ausencia de vulnerabilidades. | RF-12, RF-45, RNF-08 |
| CA-12 | Auditoría completa | Un revisor reconstruye detección, evidencia, correlación, cambios, pruebas y decisión desde el reporte. | RF-14, RF-19, RF-43, RF-44 |
| CA-13 | Instrucciones maliciosas en una fuente | La ingesta no amplía permisos ni ejecuta instrucciones del contenido externo. | RN-05, RNF-04 |

**Condición de aceptación propuesta:** aprobar CA-01 a CA-13, los requisitos MVP correspondientes y las comprobaciones RNF aplicables. Las excepciones deben quedar documentadas y aprobadas; una función simulada no cuenta como integración implementada.

## 11. Trazabilidad con los objetivos de la propuesta

| Objetivo original | Cobertura principal |
|---|---|
| 1. Monitorear fuentes | RF-08–RF-15 |
| 2. Mantener inventario | RF-01–RF-07 |
| 3. Correlacionar amenazas | RF-16–RF-22 |
| 4. Investigar mediante evidencia | RF-12–RF-14, RF-19 |
| 5. Determinar condiciones e impacto | RF-17–RF-20, RF-25 |
| 6. Generar estrategias | RF-23–RF-25 |
| 7. Implementar y probar | RF-26–RF-34 |
| 8. Explicar y auditar | RF-39, RF-42–RF-45 |
| 9. Mantener aprobación humana | RF-35–RF-38, RN-05–RN-09 |

## 12. Riesgos y decisiones pendientes

| Tema | Riesgo o decisión | Tratamiento previsto |
|---|---|---|
| Nombre y alcance inicial | Nombre, ecosistema y número de repositorios no confirmados. | Validar ALAIRA Warden y el recorte Node.js/npm propuesto. |
| Proveedores | APIs, costos o permisos podrían impedir una integración requerida por el hackathon. | Verificar acceso y contrato antes de incorporarla; limitarse a la lista autorizada y a requisitos explícitos del hackathon. |
| Cobertura | Un inventario parcial puede omitir componentes desplegados. | Mostrar completitud y antigüedad; no emitir garantías generales de ausencia de riesgo. |
| Versiones y procedencia | Forks, paquetes renombrados y versiones no estándar pueden producir ambigüedad. | Declarar no soportado o indeterminado y requerir revisión. |
| Datos privados | Código e infraestructura pueden tener restricciones de tratamiento. | Definir proveedores permitidos, residencia, retención y redacción antes de conectar datos reales. |
| Ejecución de dependencias | Instalaciones y pruebas pueden ejecutar código no confiable. | Aislamiento, acceso mínimo y controles de salida de red. |
| Priorización | No se ha acordado fórmula ni niveles de criticidad. | Aprobar una política determinista versionada antes de medir resultados. |
| Presupuesto | No se ha fijado costo monetario máximo por caso o periodo. | Definirlo por proveedor y complementarlo con límites de tiempo y llamadas. |
| Producción | No se han definido disponibilidad, RPO, RTO ni topología. | Resolverlos antes de un despliegue productivo; no bloquear por ello la demostración aislada. |
| Aprobaciones | Falta asignar quién puede autorizar cada acción. | Aprobar matriz de roles y permisos antes de habilitar escrituras externas. |
| Calidad de detección | No existe un conjunto representativo para medir precisión y cobertura. | Preparar casos etiquetados; no extrapolar resultados del demo a eficacia universal. |

## 13. Entregables previstos

1. MVP ejecutable y configuración reproducible de la demostración.
2. Inventarios y registros de despliegue de prueba, con procedencia explícita.
3. Conjunto de avisos y resultados esperados para aceptación.
4. Reportes de investigaciones con evidencia y decisiones.
5. Al menos una propuesta de corrección con rama, diff, pruebas y PR autorizado.
6. Evidencia de ejecución de CA-01 a CA-13 y de las verificaciones no funcionales aplicables.
7. Guía de instalación, operación, límites conocidos y manejo de errores.
8. Registro de decisiones que actualice este SRS al aprobar alcance, métricas e integraciones.

## 14. Referencia documental

**SRC-01.** «Propuesta de proyecto: Sistema multiagente de inteligencia y respuesta ante vulnerabilidades de ciberseguridad», texto facilitado por el solicitante. Fuente de objetivos, responsabilidades de agentes, flujo, tecnologías candidatas y visión del producto.

Este SRS no verifica incidentes citados en la propuesta ni capacidades actuales de proveedores. Esos ejemplos no se utilizan como evidencia factual de seguridad ni como compromisos técnicos de integración.
