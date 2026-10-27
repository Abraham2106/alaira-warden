# Prompt — Identidad y autorización

Copia el siguiente encargo completo al ejecutor asignado. Adjunta también `docs/implementation-roadmap.md`, porque es posterior al commit base.

---

Actúa como ingeniero backend responsable de acceso para el MVP ALAIRA Warden. Trabaja personalmente y sin subagentes, en un worktree asignado sobre una rama derivada del commit `6bb1828`. Aplica controles explícitos y pruebas negativas. No modifiques archivos de otros responsables.

## Contexto

La API actual utiliza un token compartido de desarrollo y atribuye eventos a `local-developer`. PostgreSQL separa propietario y runtime; el runtime agrega/lee auditoría pero no la reescribe. Eso no implementa usuarios, roles ni acceso por aplicación. El flujo de aprobación necesita una identidad individual y autorización comprobada en servidor.

Este frente cubre WBS 1.2.3 y la base de 1.8; SRS roles, RF-35–RF-37, RF-44 y RNF-01/RNF-02/RNF-05 según corresponda. La aprobación del artefacto exacto, su invalidación y la publicación de PR pertenecen a bundles del integrador: tu módulo aporta principal y decisión de permisos.

Lee los documentos del SRS/WBS, `docs/architecture.md`, migraciones actuales, `main.py`, `repository.py` y el contrato de identidad v1 del roadmap adjunto. No supongas que el token actual de desarrollo equivale a un administrador autorizado para cualquier aplicación.

## Propiedad y límites

Puedes modificar únicamente:

- `src/alaira_warden/identity/**`.
- `tests/identity/**`.
- `docs/handoffs/identity.md`.

No edites `main.py`, configuración, repositorio global, UI, dependencias, Docker ni archivos `migrations/`. Propón SQL y cambios de montaje en el handoff. Un router/dependencia reutilizable puede definirse dentro de tu paquete y entregarse sin montarlo globalmente.

No incorpores un proveedor cerrado de identidad ni un sistema empresarial completo. Para el MVP propone un mecanismo mínimo: credenciales de API individuales opacas, revocables y vinculadas a identidad/roles/ámbito. No implementes contraseñas, OAuth y JWT a la vez. Una dependencia adicional requiere necesidad concreta y propuesta al integrador.

## Roadmap y tareas

1. Define `Principal` y la matriz rol/acción/ámbito v1. Distingue administrador, analista, desarrollador, aprobador y auditor. Deniega por defecto; evita que el auditor pueda mutar o que tener acceso a una aplicación autorice otra.
2. Implementa decisiones puras de autorización que puedan probarse sin base ni API global. Acciones de plataforma y acciones de una aplicación deben tener una semántica explícita. La identidad/ámbito se obtiene del servidor, nunca del rol enviado en el body del cliente.
3. Implementa autenticación por credencial individual opaca de alta entropía, con representación segura en almacenamiento, comparación apropiada y revocación. La credencial completa se entrega solo en su emisión autorizada y no se guarda en texto claro en la base. Usa primitives estándar; no diseñes criptografía propia.
4. Define repositorio local del módulo para usuarios/asignaciones/credenciales con SQL parametrizado y transacciones sobre una conexión proporcionada. Entrega propuesta de tablas/índices/constraints/permisos, sin ejecutar DDL ni editar migraciones al importar.
5. Implementa provisión administrativa explícita para una identidad inicial; no generes una puerta trasera, contraseña conocida o registro público de administradores. El integrador conectará el mecanismo a una operación de administración autorizada, fuera del acceso público.
6. Define dependencia FastAPI o funciones que permitan al integrador montar autenticación/autorización. Devuelve 401 para ausencia/invalidez de autenticación y 403 para actor autenticado sin permiso, evitando revelar datos ajenos. El comportamiento para entidades inexistentes/fuera de ámbito debe acordarse y probarse.
7. Implementa `audit_actor(principal)` y propagación de identidad a operaciones. Documenta exactamente qué cambios necesita el repositorio actual para reemplazar `local-developer` sin permitir spoofing del actor.
8. Define transición del token compartido: conservarlo, si es necesario, como modo de desarrollo explícito y acotado. Nunca debe habilitar silenciosamente autorización global cuando está activo el mecanismo individual. Propón la política al integrador y prueba el fallo cerrado.
9. Propón el control previo de envío de datos a modelos: ámbito del caso, política de destino y minimización. Este frente aporta la decisión autorizada; no llama modelos ni filtra código privado de prueba a proveedores reales.

## Pruebas requeridas

- Cada rol en acciones permitidas y denegadas; identidad inactiva y asignación ausente.
- Usuario con acceso a aplicación A no obtiene acceso a B, ni cambiando el ID del body/ruta.
- Credencial inexistente, revocada o inválida rechazada; credencial y representación almacenada no se exponen en respuestas ni auditoría.
- Auditor no crea aplicaciones, parches ni aprobaciones; desarrollador sin rol aprobador no decide una aprobación.
- Roles/subject enviados por el cliente no cambian la identidad verificada.
- Actor de auditoría coincide con el principal autenticado.
- Fallo de almacenamiento/política no se interpreta como autorización.
- Modo token de desarrollo no crea un bypass del modo individual.

Las pruebas iniciales usan store controlado y no dependen de módulos de fuentes, inventario o proveedores. Si agregas pruebas SQL, deben usar base aislada terminada en `_test`, con tablas/permisos explícitos de ensayo y sin tocar el PostgreSQL de demostración. No ejecutes instalaciones/migraciones sobre otras bases por conveniencia.

## Cierre

Entrega implementación, matriz de permisos, pruebas negativas y `docs/handoffs/identity.md` con propuesta SQL, dependencias/configuración solicitadas y montaje exacto en los endpoints existentes. El integrador conectará esos cambios y verificará nuevamente el flujo completo. No declares cerrado RF-35 solo por autenticar al usuario: la aprobación y artefacto exacto se acreditan en otro bundle.
