# B2 — Correlación determinista

## Estado

Núcleo de evaluación implementado en `src/alaira_warden/correlation/`. Funciona sobre contratos validados y datos de prueba, sin llamadas a fuentes o modelos. No se ha conectado todavía a los módulos de fuentes/inventario ni a endpoints de escritura de hallazgos. El ciclo persistente de reevaluación, cierre y aceptación de riesgo de 1.6.4 queda pendiente junto a la integración del caso.

## Contratos

- `Snapshot`: ID, aplicación, commit inmutable, fecha, completitud y componentes con sus versiones y rutas transitivas.
- `Advisory`: ID/origen, huella de revisión, paquetes/rangos/versiones, estado de evidencia y señales de severidad/explotación conocidas.
- `Context`: aplicación/snapshot, despliegue y referencia, condiciones con evidencia, criticidad y marca histórica. `deployed_at` permite evaluar una instantánea histórica respecto de su despliegue, sin exigir que un documento antiguo describa la producción actual.
- `Assessment`: ámbito y revisiones evaluadas, versión de política, fecha, resumen y conclusiones por componente con razones, prioridad y confianza separadas.

`affected_complete` es un campo explícito del aviso y comienza en `False`. Un lote descargado completamente no prueba por sí solo que se conoce toda la afectación del producto. La información incompleta no permite descartar una versión que parece segura. Una coincidencia positiva verificable puede conservarse como exposición potencial.

Los contratos rechazan contexto de otra aplicación/snapshot, versiones de commit mutables y IDs de componentes duplicados. Un resultado del LLM no es una entrada con autoridad para confirmar evidencia ni condiciones de ejecución.

## Semántica de versiones

La comparación diferencial encontró desacuerdos de `semantic_version.NpmSpec` con npm en prereleases y rangos con build metadata. Por ello se utiliza **node-semver 7.7.4**, instalado desde `package-lock.json`, para los rangos npm. La biblioteca Python `semantic-version` se conserva únicamente para lectura/comparación de versiones SemVer estrictas en intervalos OSV; no interpreta rangos npm.

El motor invoca Node con un script fijo y datos JSON por stdin, sin evaluar texto del aviso como código ni heredar `NODE_OPTIONS` u otras configuraciones del host. Evalúa las combinaciones en lote para evitar arrancar un proceso por componente. Hay timeout y límite de combinaciones. Una biblioteca Node ausente, un rango no válido o un error de proceso produce estado desconocido, nunca un resultado negativo.

Los intervalos OSV `SEMVER` contemplan `introduced`, `fixed`, `last_affected`, `limit` y el valor inicial `0`. Se rechazan límites invertidos, eventos mal formados y tipos no soportados. Se preservan tipos desconocidos como limitaciones: no se interpreta un rango GIT como SemVer. Build metadata no cambia precedencia. Una versión no resuelta o no interpretable queda indeterminada.

Referencia: [motor oficial de npm](https://github.com/npm/node-semver) y [documentación de semantic-version](https://python-semanticversion.readthedocs.io/en/stable/).

## Conclusiones de exposición

- Coincidir con una versión afectada produce exposición **potencial**, si la evidencia del aviso está confirmada.
- Confirmar exposición requiere despliegue referenciado, condiciones conocidas completas con evidencia y contexto de inventario válido.
- La falta de datos, el inventario incompleto/vencido, la afectación parcial, un aviso retirado o la evidencia contradictoria limitan las conclusiones negativas.
- La clasificación de compromiso permanece **desconocida**: ninguna comparación de versiones demuestra acceso malicioso.
- Una evaluación histórica conserva su resultado independientemente de que otra instantánea actual sea segura.
- Los hallazgos conservan rutas transitivas, commit, revisión y razones. El resumen prioriza exposición confirmada/potencial sobre componentes no afectados, manteniendo resultados desconocidos cuando no existe evidencia suficiente.

La política `warden-priority-v1` considera severidad disponible, explotación reportada y criticidad; su implementación es determinista. Confianza y prioridad son campos distintos. Esta política inicial es una propuesta implementada que debe revisarse con el responsable de seguridad antes de usar datos reales; no se presenta como fórmula oficial del SRS o de un proveedor.

## Evidencia

Se validaron casos de rangos npm, límites/prereleases, intervalos OSV, datos desconocidos, dependencia transitiva, contexto histórico, evidencia de condiciones, ámbito y repetibilidad. La prueba diferencial cubre **224 combinaciones** frente al paquete de referencia npm del entorno.

El módulo tiene **40 pruebas aprobadas** en la regresión final de **97 pruebas**, incluidas PostgreSQL y Docker reales para los otros componentes. Incluye aviso parcial, contexto histórico y fallo cerrado si falta el motor npm. El desglose y alcance de la ejecución final se registran en `docs/verification.md`.

Se ejecutó `scripts/benchmark_correlation.py`: 10 000 componentes sintéticos con versiones distintas, un aviso y 20 evaluaciones locales. **p95: 0,8915 s**, mediana 0,7670 s, en Windows AMD64 / Python 3.12.2. Cada evaluación identificó 5 000 coincidencias y 5 000 versiones fuera de rango. Evidencia: `artifacts/correlation/benchmark.json`.

La medición incluye el motor npm local y la evaluación; excluye consultas externas, modelos y persistencia. No demuestra rendimiento de todas las cargas, precisión sobre avisos reales ni aceptación completa del MVP.

## Uso local

```powershell
npm ci --ignore-scripts
.\.venv\Scripts\python.exe -m pytest tests/correlation -q
.\.venv\Scripts\python.exe scripts/benchmark_correlation.py
```

Para la prueba diferencial opcional, `WARDEN_NODE_SEMVER_MODULE` apunta al módulo de referencia local autorizado. CI lo fija al paquete instalado en su workspace. No se descarga un módulo durante la prueba. El Dockerfile incluye Node y node-semver para que la biblioteca no dependa accidentalmente del entorno de desarrollo.

## Pendientes para cierre integrado de B2

1. Convertir las salidas de fuentes e inventario a estos contratos desde una capa de integración; no modificar sus paquetes reservados sin recibir la entrega.
2. Persistir resultados y revisiones con consistencia entre aplicación, snapshot, componentes y aviso.
3. Implementar reevaluación ante cambios y decisiones manuales atribuibles con su historial.
4. Conectar el caso/servicios al worker con checkpoints de B3 y a la UI consolidada.
5. Ejecutar CA-01–CA-05 con inventario y evidencia reales/autorizados; los fixtures actuales no acreditan ese flujo completo.
