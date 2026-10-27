"""Acquisition pipeline. Model-free fallback is the default."""

from __future__ import annotations

import json
import re

from alaira_warden.hmem.memory_store import MemoryStoreService
from alaira_warden.hmem.types import ClockFn, MemoryRecord, MinerFn

EVENT_TYPE_MAP = {
    "chat_message": "general",
    "user_correction": "preference",
    "file_save": "factual",
    "file_open": "general",
    "file_edit": "factual",
    "model_response": "factual",
    "plan_completion": "factual",
}
SIGNAL = re.compile(
    r"\b(prefer|always|never|decided|chose|choose|use|because|instead|must|should|"
    r"important|remember)\b",
    re.I,
)
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


class MemoryMiningService:
    def __init__(
        self,
        store: MemoryStoreService,
        clock: ClockFn,
        miner_fn: MinerFn | None = None,
    ):
        self._store = store
        self._clock = clock
        self._miner_fn = miner_fn

    def mine_interaction(
        self, event: str, text: str, opts: dict | None = None
    ) -> list[MemoryRecord]:
        options = opts or {}
        candidates = (
            self._mine_with_model(event, text) if self._miner_fn else self.mine_model_free(text)
        )
        layer = options.get("layer") or ("working" if self._miner_fn else "short_term")
        return [
            self._store.add(
                {
                    "content": content,
                    "type": EVENT_TYPE_MAP[event],
                    "layer": layer,
                    "tags": [f"event:{event}"],
                    "source": f"interaction:{event}",
                    "provenance": {
                        "origin": event,
                        "learnedAt": self._clock(),
                        "label": f"mined from {event}",
                    },
                    "chatId": options.get("chatId"),
                }
            )
            for content in candidates
        ]

    def mine_document(self, file_name: str, text: str) -> list[MemoryRecord]:
        truncated = text[:8000]
        candidates = (
            self._mine_with_model("file_save", truncated)
            if self._miner_fn
            else self.mine_model_free(truncated)
        )
        return [
            self._store.add(
                {
                    "content": content,
                    "type": "factual",
                    "layer": "working",
                    "tags": ["document", f"file:{file_name}"],
                    "source": f"document:{file_name}",
                }
            )
            for content in candidates
        ]

    def mine_model_free(self, text: str) -> list[str]:
        return [
            sentence.strip()
            for sentence in _SPLIT.split(text)
            if 20 <= len(sentence.strip()) <= 300 and SIGNAL.search(sentence)
        ][:10]

    def _mine_with_model(self, event: str, text: str) -> list[str]:
        assert self._miner_fn is not None
        prompt = (
            "Extract durable memories from this "
            f"{event} as a strict JSON array of strings:\n\n{text}"
        )
        return parse_strict_json_array(self._miner_fn(prompt))


def parse_strict_json_array(raw: str) -> list[str]:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.I)
    cleaned = re.sub(r"```\s*$", "", cleaned).strip()
    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start != -1 and end > start:
        cleaned = cleaned[start : end + 1]
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, str) and len(item.strip()) >= 5]
