"""core/telemetry.py — live, human-readable progress display.

Prints clean, BOXED status to stderr as agents work and tools fire, so a long
local-model run is watchable instead of silent. Stage banners and the final
summary are drawn as boxes; the streamed tool/finding/verdict lines hang under
the current stage with a vertical bar so each phase reads as one section.

Box-drawing characters render even when output is piped (e.g. `| tee run.log`);
ANSI colour is auto-disabled off a tty. Pure presentation — no pipeline effect.
"""
from __future__ import annotations

import re
import sys
import time

# ANSI colours (no-op if not a tty)
_TTY = sys.stderr.isatty()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s


_DIM = lambda s: _c("2", s)
_BOLD = lambda s: _c("1", s)
_CYAN = lambda s: _c("36", s)
_GREEN = lambda s: _c("32", s)
_YELLOW = lambda s: _c("33", s)
_RED = lambda s: _c("31", s)
_MAGENTA = lambda s: _c("35", s)

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _strip(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _fmt_dur(sec: float) -> str:
    """Human-friendly duration: '57.0s', '2m 57s', '1h 03m 09s'."""
    sec = max(0.0, float(sec))
    if sec < 60:
        return f"{sec:.1f}s"
    m, s = divmod(int(round(sec)), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def _vis(s: str) -> int:
    return len(_strip(s))


# Inner content width of boxes (visible chars between the side bars).
_BOX_W = 74


def _box(lines: list[str], colorfn) -> str:
    inner = min(_BOX_W, max(_vis(l) for l in lines))
    top = colorfn("╭" + "─" * (inner + 2) + "╮")
    bot = colorfn("╰" + "─" * (inner + 2) + "╯")
    rows = [top]
    for l in lines:
        if _vis(l) > inner:
            l = _strip(l)[: inner - 1] + "…"
        pad = inner - _vis(l)
        rows.append(colorfn("│ ") + l + " " * pad + colorfn(" │"))
    rows.append(bot)
    return "\n".join(rows)


# Friendly labels for tool names.
_TOOL_LABEL = {
    "read_file": "reading",
    "search_code": "searching",
    "find_callers": "tracing callers",
    "git_blame": "git blame",
    "discover_symbols": "discovering symbols",
    "cpg_slice": "CPG slice",
    "run_flawfinder": "flawfinder",
    "run_cppcheck": "cppcheck",
    "run_clang_analyzer": "clang-analyzer",
    "run_semgrep": "semgrep",
    "run_go_vet": "go vet",
    "run_staticcheck": "staticcheck",
    "run_gosec": "gosec",
}

_SEV_COLOUR = {
    "CRITICAL": _RED, "HIGH": _YELLOW, "MEDIUM": _YELLOW,
    "LOW": _CYAN, "INFO": _DIM,
}


class Telemetry:
    """Stateful pretty-printer for one assessment run."""

    def __init__(self, enabled: bool = True, sink=None):
        self.enabled = enabled
        self._sink = sink            # optional file object for an ANSI-stripped mirror
        self._t0 = time.time()
        self._tool_count = 0
        self._cur_stage: str | None = None
        self._cur_start = self._t0
        self.stage_times: list[tuple[str, float]] = []

    def _ts(self) -> str:
        return _DIM(f"[{time.time() - self._t0:5.1f}s]")

    def elapsed(self) -> float:
        return time.time() - self._t0

    def _close_stage(self) -> None:
        if self._cur_stage is not None:
            self.stage_times.append((self._cur_stage, time.time() - self._cur_start))
            self._cur_stage = None

    def _emit(self, line: str) -> None:
        if self.enabled:
            print(line, file=sys.stderr, flush=True)
        # Always mirror to the run log (even when the console is quiet), stripped
        # of ANSI so the file stays plain text.
        if self._sink is not None:
            try:
                self._sink.write(_strip(line) + "\n")
                self._sink.flush()
            except Exception:
                pass

    def _inside(self, line: str) -> None:
        # A streamed line that belongs under the current stage box.
        self._emit(f"{_DIM('│')}  {line}")

    # -- stage banners (boxed) ----------------------------------------
    def stage(self, name: str, detail: str = "") -> None:
        self._close_stage()          # book the previous section's duration
        self._cur_stage = name
        self._cur_start = time.time()
        title = _BOLD(_MAGENTA(f"▶ {name}"))
        if detail:
            title += f"   {_DIM(detail)}"
        self._emit("")
        self._emit(_box([title], _MAGENTA))

    def agent(self, name: str, detail: str = "") -> None:
        self._inside(f"{_CYAN('●')} {_BOLD(name)} {detail}")

    # -- investigator activity ----------------------------------------
    def tool(self, name: str, args: dict) -> None:
        self._tool_count += 1
        label = _TOOL_LABEL.get(name, name)
        hint = ""
        if "path" in args:
            hint = str(args["path"])
            if "start" in args:
                hint += f":{args.get('start')}-{args.get('end')}"
        elif "pattern" in args:
            hint = repr(args["pattern"])
        elif "category" in args:
            hint = args["category"] or "all"
        elif "sink" in args:
            hint = f"sink={args['sink']}"
        self._inside(f"{self._ts()} {_DIM('↳')} {label} {_DIM(hint)}")

    def thinking(self, msg: str) -> None:
        self._inside(f"{self._ts()} {_DIM('…')} {_DIM(msg)}")

    # -- findings ------------------------------------------------------
    def finding(self, title: str, severity: str, where: str = "") -> None:
        col = _SEV_COLOUR.get(severity.upper(), _DIM)
        sev = col(f"[{severity.upper()}]")
        loc = _DIM(f"({where})") if where else ""
        short = title if len(title) <= 90 else title[:87] + "..."
        self._inside(f"{self._ts()} {_GREEN('✔ found')} {sev} {short} {loc}")

    def verdict(self, title: str, verdict: str) -> None:
        v = verdict.lower()
        icon, col = {
            "confirmed": ("✓", _GREEN),
            "disputed":  ("✗", _RED),
            "needs-evidence": ("?", _YELLOW),
        }.get(v, ("·", _DIM))
        short = title if len(title) <= 70 else title[:67] + "..."
        self._inside(f"{self._ts()} {col(icon)} {col(verdict)} {_DIM('—')} {short}")

    # -- summaries -----------------------------------------------------
    def note(self, msg: str) -> None:
        self._inside(f"{self._ts()} {_DIM(msg)}")

    def done(self, msg: str) -> None:
        self._close_stage()
        total = self.elapsed()
        # Per-section timing breakdown, then the summary line (with total).
        if self.stage_times:
            width = max(len(n) for n, _ in self.stage_times)
            width = max(width, len("Total"))
            rows = [_BOLD("⏱ Timing")]
            for name, dur in self.stage_times:
                rows.append(f"{name.ljust(width)}   {_DIM(_fmt_dur(dur))}")
            rows.append(_DIM("─" * (width + 12)))
            rows.append(f"{'Total'.ljust(width)}   {_BOLD(_fmt_dur(total))}")
            self._emit(_box(rows, _CYAN))
        self._emit(_box([_BOLD(f"{msg} · {_fmt_dur(total)}")], _GREEN))


# Module-level singleton, configured by main().
_active: Telemetry | None = None


def init(enabled: bool = True, sink=None) -> Telemetry:
    global _active
    _active = Telemetry(enabled=enabled, sink=sink)
    return _active


def get() -> Telemetry | None:
    return _active
