from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph


class InvestigationState(TypedDict):
    case_id: str
    mode: Literal["scaffold_preview"]
    status: str
    stages: list[str]
    blockers: list[str]


def intake(state: InvestigationState) -> dict:
    return {"stages": ["intake"], "status": "awaiting_inventory"}


def inventory_gate(state: InvestigationState) -> dict:
    # Deliberate stop: a preview must not fabricate a scan or assert exposure.
    return {
        "stages": [*state["stages"], "inventory_gate"],
        "status": "requires_intervention",
        "blockers": ["Inventory, source and remediation adapters are not implemented."],
    }


def build_workflow():
    graph = StateGraph(InvestigationState)
    graph.add_node("intake", intake)
    graph.add_node("inventory_gate", inventory_gate)
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "inventory_gate")
    graph.add_edge("inventory_gate", END)
    # No checkpoint persistence yet. This graph is only a side-effect-free preview.
    return graph.compile()
