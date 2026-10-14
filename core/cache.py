"""
core/cache.py — Per-run in-memory tool output cache.

Keyed by (tool_name, frozen args dict). Enabled via --cache-reads flag.
"""

from __future__ import annotations

import hashlib
import json
import logging

logger = logging.getLogger(__name__)


class ToolCache:
    def __init__(self, enabled: bool = False):
        self._enabled = enabled
        self._store: dict[str, str] = {}
        self._hits = 0
        self._misses = 0

    def _key(self, tool_name: str, tool_input: dict) -> str:
        serialised = json.dumps({"tool": tool_name, "input": tool_input}, sort_keys=True)
        return hashlib.sha256(serialised.encode()).hexdigest()

    def get(self, tool_name: str, tool_input: dict) -> str | None:
        if not self._enabled:
            return None
        k = self._key(tool_name, tool_input)
        result = self._store.get(k)
        if result is not None:
            self._hits += 1
            logger.debug(f"[cache] HIT  {tool_name}({list(tool_input.keys())})")
        else:
            self._misses += 1
        return result

    def set(self, tool_name: str, tool_input: dict, output: str) -> None:
        if not self._enabled:
            return
        k = self._key(tool_name, tool_input)
        self._store[k] = output
        logger.debug(f"[cache] SET  {tool_name}({list(tool_input.keys())})")

    def stats(self) -> str:
        total = self._hits + self._misses
        rate = (self._hits / total * 100) if total else 0
        return f"[cache] hits={self._hits} misses={self._misses} rate={rate:.0f}%"
