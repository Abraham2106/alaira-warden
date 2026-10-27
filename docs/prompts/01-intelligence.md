# Prompt — Fuentes de inteligencia

Copia el siguiente encargo completo al ejecutor asignado. Adjunta también `docs/implementation-roadmap.md`, porque es posterior al commit base.

---

Actúa como ingeniero backend para el MVP de ALAIRA Warden. Implementa personalmente este frente, sin subagentes. Trabaja únicamente en el worktree que el usuario te asigne, sobre una rama propia derivada del commit `6bb1828`. No cambies el checkout principal ni lances servicios compartidos.

## Contexto

Warden investiga amenazas de ciberseguridad y las relaciona con aplicaciones npm. El integrador desarrollará correlación, orquestación, remediación y aprobación. Tu responsabilidad es obtener y normalizar fuentes; no decidir si una aplicación está afectada.

La base es Python 3.12/FastAPI/Pydantic/psycopg/PostgreSQL/LangGraph. Las fuentes son GitHub Security Advisories, OSV, NVD y CISA KEV. Existen tablas `advisories`, `advisory_revisions`, `evidence` y `findings`, pero sus servicios no están implementados. Las sondas públicas anteriores tuvieron éxito; los adaptadores de producción siguen siendo stubs.

Lee `SRS-Alaira-Warden.md` (RF-08–RF-14), WBS 1.4.1–1.4.5, `docs/integrations.md`, `docs/feasibility-assessment.md` y el contrato v1 de `docs/implementation-roadmap.md`. Revisa AGENTS.md aplicables; si existe `.codegraph/`, úsalo antes de localizar código. Lee las skills de implementación pertinentes si están disponibles.

## Propiedad y límites

Puedes modificar únicamente:

- `src/alaira_warden/intelligence/**`.
- `tests/intelligence/**`, incluidas fixtures sintéticas.
- `docs/handoffs/intelligence.md`.

No edites archivos globales, migraciones, dependencias, Docker, UI ni documentos compartidos. Solicita sus cambios en el handoff. No añadas una jerarquía de plugins, servicios externos ni paquetes para necesidades especulativas. La estandarización pertenece a este frente completo; no dejar cuatro estructuras incompatibles.

`httpx` está actualmente en dependencias de desarrollo, no de runtime. Si lo utilizas en el módulo, solicita expresamente al integrador moverlo a runtime y actualizar el lock. No confundas estar instalado en tu venv con estar disponible en la imagen de producción.

## Roadmap y tareas

1. Implementa el modelo local `SourceBatch` y registros según el contrato v1. Conserva el formato y procedencia original de rangos, severidades y referencias.
2. Implementa CISA KEV: descarga JSON, validación, consulta por CVE y señal de explotación. Un CVE ausente no demuestra que no sea explotado.
3. Implementa OSV por paquete/versión y recuperación de detalle por ID. Si implementas querybatch, respeta que sus resultados iniciales pueden contener solo IDs y fechas. Soporta páginas con límite total de trabajo.
4. Implementa GitHub Advisories público: filtros npm, páginas, alias GHSA/CVE y diferencias entre avisos revisados y malware. Las operaciones de repositorios privados o escritura no pertenecen a este cliente.
5. Implementa NVD por CVE: referencias, datos originales de severidad, cambios e información incompleta. No convertir CPE en nombre npm sin evidencia explícita.
6. Añade normalización y agrupación por identificadores/alias verificables. Conserva cada origen y revisión; un reporte copiado por tres catálogos no es tres corroboraciones independientes. No fusionar por título similar.
7. Define sincronización incremental y cursor cuando la fuente lo soporte, con reintentos acotados, `Retry-After` cuando aplique y resultados parciales. Si propones persistencia, usa operaciones locales que acepten una conexión/almacenamiento proporcionado por el llamador, sin arrancar la base ni crear tablas al importar.
8. Entrega pruebas y una nota de integración que especifique las rutas/registro/persistencia que el integrador debe montar.

## Pruebas requeridas

- Respuesta válida de cada fuente y campos opcionales ausentes.
- JSON inválido, estructura inesperada, timeout, 401/403, 429 y fallo de servidor.
- Paginación y presupuesto agotado sin bucle ilimitado.
- Mismo aviso con alias entre fuentes; revisiones distintas y ambigüedad.
- Datos NVD/KEV sin paquete npm; no fabricar identidad ni resultado de exposición.
- Secreto o cuerpo privado de error no aparece en salidas/logs.

Las pruebas ordinarias usan respuestas controladas y no requieren red ni credenciales. Separa una sonda real opcional de acceso público con datos sintéticos; no exijas disponibilidad de Internet para que toda la suite pase. No descargues automáticamente URLs de referencia arbitrarias.

## Cierre

El módulo debe poder importarse y probarse sin inventario, modelos, UI o base de otro frente. Incluye funciones públicas tipadas, comandos de prueba, muestras de salida, evidencia y cambios solicitados al integrador. Documenta documentación oficial consultada, versiones y cuotas verificadas, sin declarar conexión verificada por configurar una clave.

Entrega código implementado, pruebas y handoff. No cierres con solo un plan ni alteres el estado global de los adaptadores desde tu rama.
