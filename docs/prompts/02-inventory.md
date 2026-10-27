# Prompt — Inventario y despliegues

Copia el siguiente encargo completo al ejecutor asignado. Adjunta también `docs/implementation-roadmap.md`, porque es posterior al commit base.

---

Actúa como ingeniero backend/DevSecOps para el MVP de ALAIRA Warden. Implementa personalmente este frente sin subagentes, en el worktree asignado por el usuario y sobre una rama derivada de `6bb1828`. No modifiques el proyecto original ni otro checkout.

## Contexto

Warden necesita conocer componentes npm, versiones resueltas y despliegues para que otro módulo determine exposición. El backend está escrito en Python; el ecosistema analizado es Node.js/npm. Ya existen registro de aplicaciones y tablas de snapshots, componentes y despliegues. No hay clonado, inventario ni importador histórico operativo.

Lee SRS RF-01 y RF-03–RF-06, WBS 1.3.1–1.3.4, `migrations/001_initial.sql`, `migrations/002_domain_foundations.sql`, `docs/architecture.md` y el contrato v1 de `docs/implementation-roadmap.md`. Sigue AGENTS.md y CodeGraph si hay índice. Aplica las skills pertinentes sin introducir un proceso de agentes.

## Propiedad y límites

Puedes modificar únicamente:

- `src/alaira_warden/inventory/**`.
- `tests/inventory/**`, con proyectos npm pequeños y sintéticos.
- `docs/handoffs/inventory.md`.

Los archivos globales, migraciones aplicadas, configuración, dependencias y ejecutor Docker pertenecen al integrador. Entrega propuestas concretas para ellos. No edites `models.py` ni `repository.py` para facilitar tu módulo.

Este frente no ejecuta instalaciones, scripts npm, código de un repositorio, hooks Git ni pruebas de la aplicación. Syft es una herramienta de análisis confiable cuya versión y comando deben fijarse; no se descarga/ejecuta una herramienta arbitraria que indique el repositorio. No montes el socket Docker ni uses credenciales de escritura GitHub.

## Roadmap y tareas

1. Define los modelos locales `InventorySnapshot`, componentes y `DeploymentRecord` del contrato v1. No agregues conclusiones de vulnerabilidad.
2. Implementa lectura GitHub autorizada por repositorio y referencia, resolviendo la referencia a un commit inmutable. Mantén el transporte y credenciales explícitos. Limita tamaños, cantidad de archivos y tiempo. Una referencia mutable no identifica la instantánea final.
3. Implementa extracción de `package.json` y `package-lock.json`. Declara versiones de lockfile soportadas. Obtén nombres, versiones resueltas, directas/transitivas y rutas, preservando múltiples versiones del mismo paquete. Declara no soportados los casos que no puedas interpretar con seguridad.
4. Maneja alias, dependencias locales/git, workspaces, opcionales y enlaces mediante una política explícita. No marques un inventario completo si existen componentes que no pudiste resolver. No reconstruyas versiones desde rangos declarados como si fueran instaladas.
5. Implementa integración de Syft: construcción segura de argumentos, captura de versión/resultado, lectura y normalización de SBOM y artefactos. La ejecución real de análisis sobre material no confiable pasa por el ejecutor autorizado del integrador. Puedes probar tu parser con SBOM controlado y tu invocación con un runner inyectado.
6. Reconcilia SBOM y lockfile sin borrar discrepancias. Recupera rutas que falten en SBOM desde el lockfile cuando sean verificables. Conserva herramienta, fecha, commit y estado de completitud.
7. Implementa importación histórica de despliegues desde un esquema JSON documentado. Valida fechas, aplicación/entorno, procedencia y relación con commit/snapshot. Una actualización no elimina el despliegue anterior. Un registro de despliegue no demuestra ejecución de código.
8. Implementa clasificación de inventario completo/parcial/fallido y vencimiento configurable mediante parámetros explícitos. Conserva snapshots anteriores; entregar operaciones de persistencia o propuestas que el integrador pueda montar con la conexión transaccional existente.

## Controles y pruebas

- Fixtures de dependencia directa, transitiva y dos versiones del mismo paquete.
- Archivo faltante, JSON inválido, versión lockfile no soportada y discrepancia Syft/lockfile.
- Snapshot ligado a commit y conservación de dos instantáneas.
- Dos despliegues históricos, fechas inválidas y referencia de otra aplicación rechazada.
- Dependencia git/local no resuelta se representa como limitación.
- Si materializas archivos: rechaza escapes `..`, rutas absolutas, symlinks fuera del checkout y archivos por encima del límite. No extraigas archivos externos sin estas comprobaciones.
- Runner Syft fallido o ausente no produce éxito ni un SBOM ficticio.
- Ningún secreto aparece en URLs, argumentos registrados, errores o artefactos.

Pruebas unitarias sin red, sin Node ejecutando scripts y sin Docker real. Una prueba real opcional puede utilizar un repositorio/checkout de prueba expresamente autorizado; documenta qué se leyó y qué no se ejecutó. No necesitas las fuentes de vulnerabilidad ni sus modelos para completar el módulo.

## Cierre

Entrega funciones tipadas, fixtures reproducibles, pruebas y `docs/handoffs/inventory.md` con comandos, formatos soportados, límites y cambios de SQL/configuración/rutas que deba hacer el integrador. Si falta Syft, declara pendiente la prueba real; no instales herramientas por vías no verificadas ni declares cerrado el requisito por leer un fixture.
