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
        "orchestrator",
        "Distributes stages, budgets, pause, and cancellation.",
        ("workflow.advance", "workflow.control"),
        "Which stage runs and when to stop.",
        "Does not classify exposure or merge code.",
    ),
    AgentSpec(
        "cartographer",
        "Cartographer",
        "inventory",
        "Pins the npm snapshot to the authorized commit.",
        ("github.contents", "lockfile.parse"),
        "Whether the inventory is usable or incomplete.",
        "Does not claim deployment or run Syft on its own.",
    ),
    AgentSpec(
        "scout",
        "Scout",
        "sources",
        "Queries GitHub, OSV, NVD, and KEV within a bounded budget.",
        ("github.advisories", "osv.query", "nvd.cve", "cisa.kev"),
        "Which evidence was kept and which source failed.",
        "Does not assign exposure or treat a down source as absence of risk.",
    ),
    AgentSpec(
        "mnemonic",
        "Mnemonic",
        "memory",
        "Runs H-MEM: mining, recall, ledger, sleep, and conflicts.",
        ("hmem.recall", "hmem.mine", "hmem.ledger"),
        "Which memories to reinject as context.",
        "Does not change deterministic exposure.",
    ),
    AgentSpec(
        "arbiter",
        "Arbiter",
        "correlation",
        "Compares versions with reproducible npm rules.",
        ("correlation.evaluate",),
        "Exposure and priority from evidence and inventory.",
        "Does not use a model to decide impact.",
    ),
    AgentSpec(
        "planner",
        "Planner",
        "plan",
        "Proposes the next action and names evidence gaps.",
        ("plan.compose", "nightshift.generate"),
        "Update, abstain, or request data.",
        "Does not invent a fixed version or execute the patch.",
    ),
    AgentSpec(
        "evaluator",
        "Evaluator",
        "critique",
        "Reviews the plan and confirms exposure does not change.",
        ("nightshift.generate",),
        "Whether the critique is usable or should be skipped.",
        "Does not rewrite the Arbiter's findings.",
    ),
    AgentSpec(
        "scribe",
        "Scribe",
        "synthesis",
        "Asks Nightshift (or the labeled mock) for a bounded proposal.",
        ("nightshift.generate_investigation",),
        "The proposed text and the model that responded.",
        "Does not treat model output as evidence.",
    ),
    AgentSpec(
        "patchwright",
        "Patchwright",
        "engineering",
        "Prepares an isolated diff tied to the plan.",
        ("execution.sandbox",),
        "Which files would change. Merge is prohibited.",
        "Does not open a PR or touch the protected branch.",
    ),
    AgentSpec(
        "verifier",
        "Verifier",
        "validation",
        "Records Syft, Trivy, and OSV-Scanner. A missing tool is not approval.",
        ("syft", "trivy", "osv-scanner"),
        "Approved, failed, incomplete, or not executed.",
        "Does not declare success if the scan did not run.",
    ),
    AgentSpec(
        "guardian",
        "Guardian",
        "approval",
        "Keeps the human decision on a specific artifact.",
        ("approval.record",),
        "Approve or reject the presented hash.",
        "Does not merge, deploy, or handle secrets.",
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
