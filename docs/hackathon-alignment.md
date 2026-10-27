# Ajuste obligatorio al Open Agent Hackathon 2026

Fuente normativa de este ajuste: texto completo del evento entregado por el usuario el 27 de octubre de 2026. Sustituye la interpretación condicional anterior sobre Zetaris y la interpretación de Meterless como simple acceso a modelos. Los handoffs originales se conservan como evidencia de lo que entregó cada frente, no como requisitos vigentes.

## Arquitectura exigida

- **Zetaris es la capa de datos de investigación**, no un health check añadido a un producto que solo consulta Postgres. Debe intervenir en las consultas que alimentan la investigación. Postgres conserva las transacciones de la aplicación, identidad, auditoría y checkpoints; sus fuentes/vistas de inventario y evidencia pueden registrarse en Zetaris con acceso de lectura limitado.
- **Meterless Nightshift es el proveedor principal de IA.** El modelo se configura en Nightshift. La aplicación guarda solo el origen y la credencial de acceso a Nightshift en variables de entorno. La clave NVIDIA se configura en Providers de Nightshift, no en Warden.
- **Un Meterless Engine debe operar dentro de una función real**, con prueba. Recomendación inicial: H-MEM para recuperar contexto y evidencia de investigaciones anteriores con su fuente y confianza. Implementar según la especificación oficial y sus comprobaciones; el historial SQL existente no constituye H-MEM por llamarlo memoria.
- **NVIDIA contribuye a través de Nightshift.** Para el premio específico, usar Nemotron en una función y registrar el modelo que atendió realmente la solicitud. Una selección `auto` o el nombre del proveedor no acredita por sí sola ese modelo.
- **Cursor es opcional.** No se necesita un cliente programático de Cursor ni Grok para satisfacer estas reglas.

## Requisitos adicionales de aceptación

| ID | Obligación | Prueba de cierre |
|---|---|---|
| RF-46 / CA-14 | Investigación utiliza Zetaris como capa de datos. | Consulta real de inventario/evidencia, fuentes identificadas, resultado consumido por el agente y limitación visible si falla. `SELECT 1` solo verifica conectividad. |
| RF-47 / CA-15 | Al menos un Engine Meterless aporta una función operativa. | Caso repetible antes/después o comportamiento comprobable y prueba de la especificación elegida; no basta copiar un prompt. |
| RF-48 / CA-16 | Nightshift atiende la función principal de IA. | Solicitud real, resultado utilizable, proveedor/modelo trazables; sin fallback silencioso a NVIDIA directo. |
| RF-49 / CA-17 | Modo de ejemplo reproducible sin credenciales. | Casos controlados claramente identificados, comportamiento real del código y cero llamadas a patrocinadores. No acredita CA-14–CA-16. |

Para la entrega aplican CA-01–CA-17 y los RNF correspondientes. El modo de ejemplo facilita evaluación offline; no elimina las obligaciones de patrocinadores. Se requiere un track primario, repositorio público, README reproducible, demo de 1–4 minutos, slides, explicación de los Engines y de la ruta Zetaris/Nightshift, trazas y declaración de componentes preexistentes. Cierre suministrado: 27 de octubre de 2026, 23:45 UTC, **17:45 Costa Rica**.

## Acceso y secuencia recomendada

1. Abrir Participant Setup Guide y grabaciones DATA/POWER/BUILD en Resource Center de HackOS. El acceso de participante y los canales de soporte pertenecen al usuario; no se han abierto cuentas ni aceptado términos desde este proyecto.
2. Preparar Zetaris con la distribución e instrucciones de ese acceso, crear una credencial de lectura y registrar las fuentes/vistas del caso. No se puede inventar una URL de instancia ni un token.
3. Instalar/iniciar Nightshift conforme a su edición y configurar una ruta de modelo en Providers. Puede atender modelos locales o proveedores configurados por el usuario; falta determinar qué acceso y hardware están disponibles. Una clave NVIDIA directa de Warden no es necesaria para esta ruta.
4. Configurar las variables locales, verificar consultas y una solicitud sintética pequeña, e integrar el Engine elegido con una prueba funcional.
5. Ejecutar el caso real con la capa de datos patrocinada y registrar evidencia de uso. Mantener un caso offline distinto para reproducción sin credenciales.

El cliente Meterless Runtime recibido puede aportar transporte hacia el runtime de Nightshift, pero aún falta verificar esa compatibilidad contra la edición instalada. El cliente NVIDIA directo se conserva como código recibido y no se monta como ruta principal del producto. No se afirma que la combinación de clientes recibidos satisfaga el evento.

Referencias técnicas primarias: [Meterless Engines](https://www.meterless.ai/engines.html), [H-MEM](https://github.com/Meterless/Meterless/tree/main/engines/hmem), [Nightshift](https://www.meterless.ai/). Las páginas públicas del patrocinador consultadas muestran fechas anteriores del evento; para esta planificación se usa el programa actualizado pegado por el usuario.
