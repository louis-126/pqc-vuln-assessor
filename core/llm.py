"""core/llm.py — LLM backends for PQC Assessor v2.

v1: AnthropicBackend (LLMClient) — unchanged API so all agents keep working.
v2: OllamaBackend, TokenTracker, make_backend factory.

The v1 LLMClient class is preserved exactly so existing agents
(ResearcherAgent, ReviewerAgent, ResolutionAgent, phase agents) work without
modification. The v2 backends implement the same .complete() / .complete_json()
/ .run_with_tools() interface.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

# ---------------------------------------------------------------------------
# v1 constants (preserved)
# ---------------------------------------------------------------------------
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-opus-4-8"
_SALVAGE_USES = 0  # count of JSON-salvage fallbacks (structured-output misses)
COST_SAVER_MODEL = "claude-sonnet-4-6"


@dataclass
class LLMConfig:
    model: str = DEFAULT_MODEL
    temperature: float = 0.2
    max_tokens: int = 2048
    max_retries: int = 4
    timeout_s: float = 180.0
    api_key_env: str = "ANTHROPIC_API_KEY"
    # The flagship models (Opus 4.8, Sonnet 4.x, …) DEPRECATED the `temperature`
    # parameter — sending it returns HTTP 400 "temperature is deprecated for this
    # model". So it is omitted from the request body by default. Set True only for
    # an older model (via --model) that still accepts it.
    send_temperature: bool = False


@dataclass
class ToolLoopResult:
    text: str
    tool_calls: list[dict] = field(default_factory=list)
    turns: int = 0
    stopped_reason: str = ""


class LLMError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# v2: Token usage tracker
# ---------------------------------------------------------------------------
class TokenTracker:
    def __init__(self, budget: int):
        self.budget = budget
        self.used = 0
        self._halted = False

    def add(self, input_tokens: int, output_tokens: int) -> None:
        self.used += input_tokens + output_tokens

    def check(self) -> bool:
        return self.used < self.budget

    @property
    def halted(self) -> bool:
        return self._halted

    def halt(self) -> None:
        self._halted = True
        import logging
        logging.getLogger("pqc").warning(
            "[token-budget] %s / %s tokens — halting after current turn.",
            f"{self.used:,}", f"{self.budget:,}"
        )

    def display(self) -> str:
        pct = (self.used / self.budget * 100) if self.budget else 0
        return f"[tokens] {self.used:,} / {self.budget:,} ({pct:.1f}%)"


# ---------------------------------------------------------------------------
# v1 Anthropic client — preserved exactly, extended with prompt caching
# ---------------------------------------------------------------------------
class LLMClient:
    """v1-compatible Anthropic client. Used by all existing agents."""

    def __init__(self, config: LLMConfig | None = None,
                 tracker: TokenTracker | None = None):
        self.config = config or LLMConfig()
        self.tracker = tracker
        self._key = os.environ.get(self.config.api_key_env)
        if not self._key:
            raise LLMError(
                f"No API key in ${self.config.api_key_env}. "
                "Export it before running."
            )
        self._client = httpx.Client(timeout=self.config.timeout_s)

    def _post(self, body: dict) -> dict:
        headers = {
            "x-api-key": self._key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
            # v2: enable prompt caching beta
            "anthropic-beta": "prompt-caching-2024-07-31",
        }
        last_err: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                r = self._client.post(ANTHROPIC_URL, headers=headers, json=body)
            except httpx.HTTPError as e:
                # transport-level error (connection/timeout) — retry
                last_err = e
                time.sleep(min(2 ** attempt, 30))
                continue
            if r.status_code == 429 or r.status_code >= 500:
                # rate limit / server error — retryable; keep the body for context
                last_err = LLMError(f"retryable status {r.status_code}: {r.text[:300]}")
                time.sleep(min(2 ** attempt, 30))
                continue
            if r.status_code >= 400:
                # client error (400/401/403/404) — NOT retryable. Surface the
                # actual Anthropic error message so the cause is visible instead
                # of a bare "400 Bad Request" (bad model id, low credit balance,
                # invalid key, unsupported beta header, …).
                raise LLMError(f"Anthropic API {r.status_code}: {r.text[:500]}")
            data = r.json()
            # v2: track tokens
            if self.tracker and "usage" in data:
                u = data["usage"]
                inp = u.get("input_tokens", 0)
                out = u.get("output_tokens", 0)
                self.tracker.add(inp, out)
                if not self.tracker.check() and not self.tracker.halted:
                    self.tracker.halt()
            return data
        raise LLMError(f"request failed after {self.config.max_retries} attempts: {last_err}")

    def complete(self, system: str, user: str,
                 temperature: float | None = None,
                 max_tokens: int | None = None,
                 cache_system: bool = False,
                 format: str | None = None) -> str:
        # `format` accepted for interface parity with OllamaBackend; the
        # Anthropic path (dormant) ignores it.
        # v2: optionally mark system prompt for caching
        sys_content: Any
        if cache_system:
            sys_content = [{"type": "text", "text": system,
                            "cache_control": {"type": "ephemeral"}}]
        else:
            sys_content = system

        body = {
            "model": self.config.model,
            "max_tokens": max_tokens or self.config.max_tokens,
            "system": sys_content,
            "messages": [{"role": "user", "content": user}],
        }
        # Only send temperature for models that still accept it (see LLMConfig).
        if self.config.send_temperature:
            body["temperature"] = (self.config.temperature
                                   if temperature is None else temperature)
        data = self._post(body)
        return "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text").strip()

    def complete_json(self, system: str, user: str, **kw) -> dict | list:
        strict = system.rstrip() + (
            "\n\nRespond with ONLY valid JSON. No prose, no markdown fences, "
            "no preamble. If you cannot answer, return {}."
        )
        # Structured outputs: grammar-constrain the decode to valid JSON.
        kw.setdefault("format", "json")
        return _extract_json(self.complete(strict, user, **kw))

    def run_with_tools(self, system: str, user: str,
                       tools: list[dict],
                       dispatch: Callable[[str, dict], str],
                       max_turns: int = 24,
                       max_tokens: int = 4096,
                       on_event: Callable[[str, Any], None] | None = None,
                       cache_system: bool = False) -> ToolLoopResult:
        # v2: optionally mark system prompt for caching
        sys_content: Any
        if cache_system:
            sys_content = [{"type": "text", "text": system,
                            "cache_control": {"type": "ephemeral"}}]
        else:
            sys_content = system

        messages: list[dict] = [{"role": "user", "content": user}]
        result = ToolLoopResult(text="")
        texts: list[str] = []

        for turn in range(max_turns):
            # Check token budget before each turn
            if self.tracker and self.tracker.halted:
                break

            turn_body = {
                "model": self.config.model,
                "max_tokens": max_tokens,
                "system": sys_content,
                "messages": messages,
                "tools": tools,
            }
            if self.config.send_temperature:
                turn_body["temperature"] = self.config.temperature
            data = self._post(turn_body)
            result.turns = turn + 1
            content = data.get("content", [])
            messages.append({"role": "assistant", "content": content})
            stop = data.get("stop_reason", "")
            result.stopped_reason = stop

            for b in content:
                if b.get("type") == "text" and b.get("text"):
                    texts.append(b["text"])
                    if on_event:
                        on_event("text", b["text"])

            tool_uses = [b for b in content if b.get("type") == "tool_use"]
            if not tool_uses or stop != "tool_use":
                break

            tool_results = []
            for tu in tool_uses:
                name, tin, tid = tu.get("name"), tu.get("input", {}), tu.get("id")
                if on_event:
                    on_event("tool_call", {"name": name, "input": tin})
                try:
                    out = dispatch(name, tin)
                except Exception as e:
                    out = f"[tool error] {e}"
                result.tool_calls.append({"name": name, "input": tin,
                                          "output": out[:1000]})
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tid,
                    "content": out,
                })
            messages.append({"role": "user", "content": tool_results})

        result.text = "\n".join(texts).strip()
        return result


# ---------------------------------------------------------------------------
# v2: Ollama backend — same interface as LLMClient
# ---------------------------------------------------------------------------
class OllamaBackend:
    """Local Ollama backend. Implements complete/complete_json/run_with_tools."""

    def __init__(self, model: str = "qwen3-coder:30b",
                 base_url: str = "http://localhost:11434",
                 tracker: TokenTracker | None = None):
        from config import PROMPT_TOOL_MODELS, OLLAMA_TIMEOUT, model_settings
        self._PROMPT_TOOL_MODELS = PROMPT_TOOL_MODELS
        self._TIMEOUT = OLLAMA_TIMEOUT
        self.model = model
        # Per-model generation defaults (temperature, num_predict, top_p/top_k,
        # system_addendum). Empty dict for models without an entry.
        self._gen = dict(model_settings(model))
        self._system_addendum = self._gen.pop("system_addendum", "")
        self.base_url = base_url.rstrip("/")
        self.tracker = tracker
        self._check_connection()

    def _check_connection(self) -> None:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException):
            raise RuntimeError(
                f"Cannot connect to Ollama at {self.base_url}.\n"
                "Start Ollama: https://ollama.com/download\n"
                f"Then pull: ollama pull {self.model}"
            )

    def _needs_sim(self) -> bool:
        base = self.model.split(":")[0]
        return base in self._PROMPT_TOOL_MODELS or self.model in self._PROMPT_TOOL_MODELS

    def _sim_suffix(self, tools: list[dict]) -> str:
        descs = []
        for t in tools:
            params = json.dumps(t.get("input_schema", {}), indent=2)
            descs.append(f"- {t['name']}: {t.get('description','')}\n  Parameters: {params}")
        return (
            "\n\n## Available Tools\nTo call a tool output ONLY:\n"
            'TOOL_CALL: {"tool": "<name>", "input": {<params>}}\n\n'
            "Available tools:\n" + "\n".join(descs)
        )

    def _extract_tool_call(self, text: str) -> dict | None:
        m = re.search(r"TOOL_CALL:\s*(\{.*\})", text)
        if not m:
            return None
        try:
            d = json.loads(m.group(1))
            return {"name": d["tool"], "input": d.get("input", {})}
        except (json.JSONDecodeError, KeyError):
            return None

    def _chat(self, messages: list[dict], tools: list[dict] | None = None,
              fmt: str | None = None, temperature: float | None = None,
              num_predict: int | None = None) -> dict:
        # Build options from per-model defaults, then apply explicit overrides.
        # (Previously temperature/max_tokens passed by callers were dropped on the
        # floor — every call ran at Ollama's default 0.8 with a hardcoded 8192
        # output cap, which wrecked structured/code output on small models.)
        options: dict[str, Any] = {"num_ctx": 32768, "num_predict": 8192}
        # num_ctx is overridable per-model: a smaller window shrinks the KV cache
        # so an 8B model fits VRAM instead of offloading (e.g. Foundation-Sec-8B
        # cold-loaded in 334s at the forced 32K ctx; matching its 24K trained
        # window cuts that dramatically). Don't set it above a model's trained
        # context — it can't use the extra and just pays the memory.
        for k in ("temperature", "top_p", "top_k", "repeat_penalty",
                  "num_predict", "num_ctx"):
            if k in self._gen:
                options[k] = self._gen[k]
        if temperature is not None:
            options["temperature"] = temperature
        if num_predict:
            options["num_predict"] = num_predict
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        # Structured outputs: constrain decoding to valid JSON (or a schema).
        # Fix for the reviewer/resolution "JSON parse failed -> prose salvage"
        # failures — the model can no longer emit prose where we need JSON.
        if fmt:
            payload["format"] = fmt
        if tools and not self._needs_sim():
            payload["tools"] = [
                {"type": "function", "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                }}
                for t in tools
            ]
        try:
            r = httpx.post(f"{self.base_url}/api/chat", json=payload,
                           timeout=float(self._TIMEOUT))
            r.raise_for_status()
        except httpx.TimeoutException:
            raise TimeoutError(f"Ollama {self.model} timed out after {self._TIMEOUT}s")
        except httpx.HTTPStatusError as e:
            import logging as _lg
            resp = getattr(e, "response", None)
            body = resp.text[:400] if resp is not None else ""
            # Some models reject the JSON `format` constraint (or num_predict)
            # with HTTP 400. Retry once WITHOUT format; the salvage layer recovers
            # the object from the free-text reply.
            if fmt and resp is not None and resp.status_code == 400:
                _lg.getLogger("pqc").warning(
                    "[ollama] %s rejected request (400: %s) — retrying free-text",
                    self.model, body)
                payload.pop("format", None)
                try:
                    r = httpx.post(f"{self.base_url}/api/chat", json=payload,
                                   timeout=float(self._TIMEOUT))
                    r.raise_for_status()
                except httpx.TimeoutException:
                    raise TimeoutError(
                        f"Ollama {self.model} timed out after {self._TIMEOUT}s")
                except httpx.HTTPStatusError as e2:
                    b2 = e2.response.text[:400] if getattr(e2, "response", None) is not None else ""
                    raise LLMError(f"Ollama {self.model} HTTP 400 (no format): {b2}")
            else:
                raise LLMError(f"Ollama {self.model} HTTP error: {body}")
        data = r.json()
        if self.tracker:
            inp = data.get("prompt_eval_count", 0)
            out = data.get("eval_count", 0)
            self.tracker.add(inp, out)
            if not self.tracker.check() and not self.tracker.halted:
                self.tracker.halt()
        return data

    def complete(self, system: str, user: str,
                 temperature: float | None = None,
                 max_tokens: int | None = None,
                 cache_system: bool = False,
                 format: str | None = None) -> str:
        if self._system_addendum:
            system = f"{system}\n\n{self._system_addendum}"
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": user}]
        data = self._chat(messages, fmt=format, temperature=temperature,
                          num_predict=max_tokens)
        return data.get("message", {}).get("content", "").strip()

    def complete_json(self, system: str, user: str, **kw) -> dict | list:
        strict = system.rstrip() + (
            "\n\nRespond with ONLY valid JSON. No prose, no markdown fences, "
            "no preamble. If you cannot answer, return {}."
        )
        # Structured outputs: grammar-constrain the decode to valid JSON.
        kw.setdefault("format", "json")
        return _extract_json(self.complete(strict, user, **kw))

    def run_with_tools(self, system: str, user: str,
                       tools: list[dict],
                       dispatch: Callable[[str, dict], str],
                       max_turns: int = 24,
                       max_tokens: int = 4096,
                       on_event: Callable[[str, Any], None] | None = None,
                       cache_system: bool = False) -> ToolLoopResult:
        self._forced_once = False  # v3: reset findings-forcing flag per run
        sys_text = system
        if self._needs_sim() and tools:
            sys_text += self._sim_suffix(tools)

        messages = [{"role": "system", "content": sys_text},
                    {"role": "user", "content": user}]
        result = ToolLoopResult(text="")
        texts: list[str] = []

        for turn in range(max_turns):
            if self.tracker and self.tracker.halted:
                break

            data = self._chat(messages, tools)
            result.turns = turn + 1
            msg = data.get("message", {})
            text = msg.get("content", "")
            stop = "tool_use" if msg.get("tool_calls") else "end_turn"

            # Prompt-simulated tool call extraction
            if self._needs_sim() and tools:
                tc = self._extract_tool_call(text)
                if tc:
                    stop = "tool_use"
                    text = re.sub(r"TOOL_CALL:\s*\{.*\}", "", text).strip()
                    if on_event:
                        on_event("tool_call", {"name": tc["name"], "input": tc["input"]})
                    try:
                        out = dispatch(tc["name"], tc["input"])
                    except Exception as e:
                        out = f"[tool error] {e}"
                    result.tool_calls.append({"name": tc["name"], "input": tc["input"],
                                              "output": out[:1000]})
                    if text:
                        texts.append(text)
                        if on_event:
                            on_event("text", text)
                    messages.append({"role": "assistant", "content": msg.get("content", "")})
                    messages.append({"role": "user", "content": f"[tool result]\n{out}"})
                    result.turns = turn + 1
                    continue

            if text:
                texts.append(text)
                if on_event:
                    on_event("text", text)

            messages.append({"role": "assistant", "content": text})

            # Native tool calls
            tool_uses = msg.get("tool_calls", [])
            if not tool_uses or stop != "tool_use":
                result.stopped_reason = stop
                # v3: forcing pass — if the model stopped without emitting any
                # finding tags or a findings JSON block, demand them explicitly
                # once. MoE instruct models often "lose the thread" after tool
                # turns and start chatting; this snaps them back to the contract.
                joined = "\n".join(texts)
                if ("<finding>" not in joined and '"findings"' not in joined
                        and not getattr(self, "_forced_once", False)):
                    self._forced_once = True
                    messages.append({"role": "assistant", "content": text})
                    messages.append({"role": "user", "content": (
                        "STOP. You are a PQC security investigator, not a chat "
                        "assistant. Based on the code you just read, output your "
                        "findings NOW using ONLY this format, nothing else:\n\n"
                        '<finding>\n{"title": "...", "cwe": "CWE-...", '
                        '"file": "...", "line": <int>, "severity": '
                        '"INFO|LOW|MEDIUM|HIGH|CRITICAL", "description": "...", '
                        '"replication": "...", "proposed_fix": "...", '
                        '"evidence_refs": ["file:line"]}\n</finding>\n\n'
                        "Emit one <finding> block per bug you confirmed. "
                        "If you genuinely found no bugs, output exactly: "
                        '{"findings": []}\n'
                        "Do NOT explain, do NOT chat, do NOT describe what you "
                        "see. Output findings or the empty array only."
                    )})
                    continue
                break

            tool_results_text = []
            for tc in tool_uses:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                if on_event:
                    on_event("tool_call", {"name": name, "input": args})
                try:
                    out = dispatch(name, args)
                except Exception as e:
                    out = f"[tool error] {e}"
                result.tool_calls.append({"name": name, "input": args, "output": out[:1000]})
                tool_results_text.append(f"[{name}]\n{out}")

            messages.append({"role": "user", "content": "\n\n".join(tool_results_text)})

        result.text = "\n".join(texts).strip()
        return result


# ---------------------------------------------------------------------------
# v2: Factory
# ---------------------------------------------------------------------------
def make_backend(backend: str,
                 config: LLMConfig | None = None,
                 ollama_model: str | None = None,
                 tracker: TokenTracker | None = None):
    """Return the right backend. v1 callers can ignore this and use LLMClient directly."""
    if backend == "anthropic":
        return LLMClient(config, tracker=tracker)
    elif backend == "ollama":
        return OllamaBackend(model=ollama_model or "qwen3-coder:30b", tracker=tracker)
    else:
        raise ValueError(f"Unknown backend: {backend!r}")


# ---------------------------------------------------------------------------
# Shared JSON extraction (used by all backends + v1)
# ---------------------------------------------------------------------------
def _extract_json(raw: str) -> dict | list:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.MULTILINE).strip()
    # Windows path repair: models copy evidence paths like ".\core\src\main\..."
    # into JSON string values, where "\c", "\s", "\m" etc. are INVALID JSON escape
    # sequences. json.loads then fails and a REAL finding is silently dropped
    # ("could not parse investigator findings"). Double any LONE backslash that
    # doesn't begin a valid JSON escape; already-escaped "\\" pairs and valid
    # escapes (\n \t \" \/ \uXXXX ...) are matched by the look-around and left as-is.
    text = re.sub(r'(?<!\\)\\(?![\\"/bfnrtu])', r'\\\\', text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    # Salvage path: the model often emits a findings/bugs array that gets
    # truncated mid-generation (max_tokens), leaving invalid JSON. Extract every
    # COMPLETE {...} object we can — including objects nested inside an
    # unterminated wrapper like {"bugs":[{...},{...},  — and return them.
    salvaged = []
    stack: list[int] = []   # stack of '{' positions
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            stack.append(i)
        elif ch == "}":
            if stack:
                obj_start = stack.pop()
                chunk = text[obj_start:i + 1]
                try:
                    obj = json.loads(chunk)
                    if isinstance(obj, dict):
                        salvaged.append(obj)
                except json.JSONDecodeError:
                    pass
    if salvaged:
        global _SALVAGE_USES
        _SALVAGE_USES += 1
        import logging as _lg
        _lg.getLogger("pqc").warning(
            "[json] structured-output miss #%d — recovered %d object(s) via salvage",
            _SALVAGE_USES, len(salvaged))
        # Prefer a fully-salvaged wrapper object if present.
        for obj in salvaged:
            for key in ("findings", "bugs", "vulnerabilities", "issues", "results"):
                if isinstance(obj.get(key), list) and obj[key]:
                    return obj
        # Otherwise treat salvaged dicts that look like findings as the entries.
        entries = [o for o in salvaged
                   if any(k in o for k in ("title", "name", "type", "description",
                                           "cwe", "file", "summary", "id"))]
        if entries:
            return {"findings": entries}
        return {"findings": salvaged}
    raise LLMError(f"could not parse JSON from model output: {raw[:300]!r}")
