# Decisiones de arquitectura

| ID | Decisión | Motivo y límite |
|---|---|---|
| ADR-001 | Backend Python 3.12 con FastAPI y LangGraph. | Usar el flujo Python de LangGraph y contratos validados. El ecosistema analizado del MVP continúa siendo npm. |
| ADR-002 | Una aplicación sirve API y UI en el mismo origen. | Arranque sencillo y sin CORS ni otro proveedor. La UI puede evolucionar sin añadir por ahora una cadena de compilación de frontend. |
| ADR-003 | PostgreSQL con SQL y migraciones versionadas. | Persistencia explícita, historial y transacciones. No se incorpora ORM ni cola externa al scaffold. |
| ADR-004 | Separar rol SQL de migración y rol de runtime. | La API no debe alterar el esquema ni editar auditoría. Las identidades por usuario/proyecto son una fase posterior. |
| ADR-005 | Grafo inicial que se detiene ante funcionalidad faltante. | Permite comprobar el contrato sin fabricar escaneos, evidencia o parches. Los checkpoints se incorporan al implementar el flujo real. |
| ADR-006 | Solo integraciones acordadas o componentes open source necesarios. | Meterless es requisito confirmado por el usuario; no se inventan endpoints, compatibilidad ni credenciales de proveedores. |
| ADR-007 | Observabilidad OTLP opcional y local por defecto. | OpenTelemetry no necesita un servicio cerrado. El colector de diagnóstico no equivale a un sistema histórico de métricas. |
| ADR-008 | Variables/archivo .env para desarrollo, fuera de Git e imágenes. | Facilitar el entorno local con credenciales aleatorias. Un despliegue real requiere su política de secretos, autenticación y residencia de datos. |
| ADR-009 | Docker Compose para el entorno de desarrollo. | API, migración, PostgreSQL y colector opcional. El ejecutor de repositorios no confiables sigue pendiente y tendrá otra frontera de permisos. |
| ADR-010 | Readiness exige coincidencia exacta de las migraciones distribuidas y aplicadas. | Detecta esquema atrasado, alterado o más nuevo. El MVP no admite mezclas de versiones ni despliegues graduales sobre esquemas incompatibles; migrar y publicar la versión correspondiente. |
| ADR-011 | Dependencias Docker en una capa anterior al código. | Cambiar UI/backend no debe repetir instalación de dependencias si `uv.lock` no cambia. uv se fija a 0.11.3 en construcción y CI. |

Las decisiones describen el scaffold actual. Un cambio que agregue servicios, proveedores cerrados o privilegios debe documentar qué requisito lo exige antes de incorporarlo.
