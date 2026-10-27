"""Revision fingerprint for a source document.

The hash is SHA-256 over canonical JSON of the origin object: UTF-8, object keys
sorted recursively, separators ``(",", ":")``, and ``ensure_ascii=False``. List order
is significant and is preserved. ``retrieved_at`` is not part of the origin, so a
second retrieval of the same document keeps the same revision. The hash is of the
parsed JSON value, not the raw bytes, so key order and insignificant whitespace do
not create a new revision.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def content_hash(origin: Mapping[str, Any]) -> str:
    encoded = json.dumps(origin, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
