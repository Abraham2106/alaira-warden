"""Named crew. One process, distinct responsibilities and tools."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentSpec:
    id: str
    name: str
    role: str
    mission: str
    tools: tuple[str, ...]
    decides: str
    never: str


ROSTER: tuple[AgentSpec, ...] = (
    AgentSpec(
        "warden",
        "Warden",
        "orquestador",
        "Distribuye etapas, presupuestos, pausa y cancelación.",
        ("workflow.advance", "workflow.control"),
        "Qué etapa corre y cuándo parar.",
        "No clasifica exposición ni fusiona código.",
    ),
    AgentSpec(
        "cartographer",
        "Cartógrafo",
        "inventario",
        "Fija el snapshot npm al commit autorizado.",
        ("github.contents", "lockfile.parse"),
        "Si el inventario es usable o incompleto.",
        "No afirma despliegue ni ejecuta Syft por sí solo.",
    ),
    AgentSpec(
        "scout",
        "Explorador",
        "fuentes",
        "Consulta GitHub, OSV, NVD y KEV con presupuesto acotado.",
        ("github.advisories", "osv.query", "nvd.cve", "cisa.kev"),
        "Qué evidencia se conservó y qué fuente falló.",
        "No asigna exposición ni trata una fuente caída como ausencia de riesgo.",
    ),
    AgentSpec(
        "mnemonic",
        "Mnemónico",
        "memoria",
        "Opera H-MEM: minería, recall, ledger, sleep y conflictos.",
        ("hmem.recall", "hmem.mine", "hmem.ledger"),
        "Qué recuerdos reinyectar como contexto.",
        "No cambia la exposición determinista.",
    ),
    AgentSpec(
        "arbiter",
        "Árbitro",
        "correlación",
        "Compara versiones con reglas npm reproducibles.",
        ("correlation.evaluate",),
        "Exposición y prioridad a partir de evidencia e inventario.",
        "No usa al modelo para decidir afectación.",
    ),
    AgentSpec(
        "planner",
        "Planificador",
        "plan",
        "Propone la siguiente acción y nombra lagunas de evidencia.",
        ("plan.compose", "nightshift.generate"),
        "Actualizar, abstenerse o pedir datos.",
        "No inventa una versión corregida ni ejecuta el parche.",
    ),
    AgentSpec(
        "evaluator",
        "Evaluador",
        "crítica",
        "Revisa el plan y confirma que la exposición no cambia.",
        ("nightshift.generate",),
        "Si la crítica es usable o debe omitirse.",
        "No reescribe hallazgos del Árbitro.",
    ),
    AgentSpec(
        "scribe",
        "Escriba",
        "síntesis",
        "Pide a Nightshift (o al mock etiquetado) una propuesta acotada.",
        ("nightshift.generate_investigation",),
        "El texto propuesto y el modelo que respondió.",
        "No trata la salida del modelo como evidencia.",
    ),
    AgentSpec(
        "patchwright",
        "Parcheador",
        "ingeniería",
        "Prepara un diff aislado vinculado al plan.",
        ("execution.sandbox",),
        "Qué archivos cambiarían. El merge está prohibido.",
        "No publica PR ni toca la rama protegida.",
    ),
    AgentSpec(
        "verifier",
        "Verificador",
        "validación",
        "Registra Syft, Trivy y OSV-Scanner. Una herramienta ausente no aprueba.",
        ("syft", "trivy", "osv-scanner"),
        "Aprobado, fallido, incompleto o no ejecutado.",
        "No declara éxito si el análisis no corrió.",
    ),
    AgentSpec(
        "guardian",
        "Guardián",
        "aprobación",
        "Conserva la decisión humana sobre un artefacto concreto.",
        ("approval.record",),
        "Aprobar o rechazar el hash presentado.",
        "No fusiona, no despliega y no manipula secretos.",
    ),
)


def public_roster() -> list[dict]:
    return [
        {
            "id": item.id,
            "name": item.name,
            "role": item.role,
            "mission": item.mission,
            "tools": list(item.tools),
            "decides": item.decides,
            "never": item.never,
        }
        for item in ROSTER
    ]


def require_agent(identifier: str) -> AgentSpec:
    for item in ROSTER:
        if item.id == identifier:
            return item
    raise KeyError(identifier)
