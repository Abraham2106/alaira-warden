"""Deterministic FNV-1a mock embedder. Pure function of the input text."""

from __future__ import annotations

import re

DIM = 64
_TOKEN = re.compile(r"[^a-z0-9\s]")


def tokenize(text: str) -> list[str]:
    cleaned = _TOKEN.sub(" ", text.lower())
    return [token for token in re.split(r"\s+", cleaned) if len(token) > 1]


def fnv1a(value: str) -> int:
    h = 0x811C9DC5
    for char in value:
        h ^= ord(char)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def embed(text: str) -> list[float]:
    vec = [0.0] * DIM
    for token in tokenize(text):
        hashed = fnv1a(token)
        idx = hashed % DIM
        sign = 1 if ((hashed >> 8) % 2) == 0 else -1
        mag = 1 + ((hashed >> 16) % 8) / 8
        vec[idx] += sign * mag
    norm = sum(value * value for value in vec) ** 0.5
    if norm == 0:
        return vec
    return [value / norm for value in vec]


def cosine(left: list[float], right: list[float]) -> float:
    return sum(left[i] * right[i] for i in range(len(left)))


def jaccard(left, right) -> float:
    first = set(left)
    second = set(right)
    if not first or not second:
        return 0.0
    inter = len(first & second)
    return inter / (len(first) + len(second) - inter)
