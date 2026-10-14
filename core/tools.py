"""Tool registry for the agentic ResearcherAgent.

Each tool is a read-only / analysis instrument the model can invoke mid-
reasoning. The investigator drives; these serve. Output is pre-filtered and
length-capped before returning to the model.

Deliberately NO weaponization tools: the registry can read, search, navigate,
and statically analyze code, and propose reproducers — it cannot build or run
exploit payloads. Dynamic confirmation (ASan/Valgrind/dudect) is handled by the
existing phase agents, not exposed as free-call tools here.

Adding a tool = one Tool entry. CodeQL, Infer, Wycheproof-vector lookup, etc.
slot in the same way; stubs included at the bottom.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.prefilter import prefilter

CAP = 6000


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> str:
    try:
        # encoding/errors set explicitly: on Windows text=True defaults to cp1252,
        # which crashes a reader thread with UnicodeDecodeError when a tool (PMD/
        # SpotBugs) emits a non-cp1252 byte. UTF-8 + replace keeps the run alive.
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s: {cmd[0]}]"
    except FileNotFoundError:
        return f"[tool not installed: {cmd[0]}]"


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    execute: Callable[[dict], str]
    requires: str = ""  # external binary; "" = always available

    def available(self) -> bool:
        return not self.requires or shutil.which(self.requires) is not None

    def schema(self) -> dict:
        return {"name": self.name, "description": self.description,
                "input_schema": self.input_schema}


class ToolRegistry:
    def __init__(self, target: Path):
        self.target = Path(target)
        self._tools: dict[str, Tool] = {}

    def add(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def schemas(self) -> list[dict]:
        # Advertise all tools; unavailable ones return a graceful error message.
        # This ensures the model always sees the full tool set.
        return [t.schema() for t in self._tools.values()]

    def names(self) -> list[str]:
        return [n for n, t in self._tools.items() if t.available()]

    def dispatch(self, name: str, tool_input: dict) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return f"[unknown tool: {name}]"
        if not tool.available():
            return f"[tool '{name}' unavailable: needs '{tool.requires}']"
        out = tool.execute(tool_input)
        return prefilter(name, out, cap=CAP) if out else "[no output]"


def build_default_registry(target: Path, globs: list[str] | None = None) -> ToolRegistry:
    """Build the tool set. `globs` are the file patterns to search (e.g.
    ['*.c','*.h'] for C, ['*.java'] for Java). Defaults to C if not given."""
    globs = globs or ["*.c", "*.h"]
    # ripgrep takes one -g per pattern; build the flag list once.
    glob_flags: list[str] = []
    for g in globs:
        glob_flags += ["-g", g]
    primary_glob = globs[0]
    # Resolve to an ABSOLUTE path up front. read_file resolves each file to an
    # absolute path and then does p.relative_to(t) for the display header; if t
    # stayed relative (e.g. "..\bc-java"), that relative_to raises ValueError on
    # Windows ("not in the subpath of"), which aborted the whole evidence gather.
    t = Path(target).resolve()
    reg = ToolRegistry(t)
    tstr = str(t)

    def _safe(rel: str) -> Path | None:
        """Resolve a path and refuse anything outside the target tree."""
        p = (t / rel).resolve()
        try:
            p.relative_to(t.resolve())
        except ValueError:
            return None
        return p

    # --- navigation ----------------------------------------------------
    def read_file(i: dict) -> str:
        # Tolerate the arg-name variants local models emit instead of crashing /
        # silently no-opping: path|file|filename|filepath, start|line, and a
        # combined lines|range|line_range like "1800:1850" or "1800-1850".
        raw_path = (i.get("path") or i.get("file") or i.get("filename")
                    or i.get("filepath") or "")
        start_v = i.get("start", i.get("line"))
        end_v = i.get("end")
        rng = i.get("lines") or i.get("range") or i.get("line_range")
        if rng and (start_v is None or end_v is None):
            nums = re.findall(r"\d+", str(rng))
            if len(nums) >= 2:
                start_v, end_v = nums[0], nums[1]
            elif len(nums) == 1:
                start_v = nums[0]
        if not raw_path:
            return ('[read_file error] no file path given. Call as '
                    '{"path": "<relative file>", "start": <int>, "end": <int>}.')
        p = _safe(str(raw_path))
        if p is None:
            return f"[read_file error] path escapes target tree: {raw_path}"
        if not p.exists():
            return f"[no such file in target: {raw_path}]"
        if p.is_dir():
            return (f"[read_file error] '{raw_path}' is a directory, not a file. "
                    "Give a path to a source file (e.g. wolfcrypt/src/wc_mlkem.c).")
        try:
            start = max(0, int(start_v) - 1) if start_v is not None else 0
        except (TypeError, ValueError):
            start = 0
        try:
            end = int(end_v) if end_v is not None else start + 200
        except (TypeError, ValueError):
            end = start + 200
        lines = p.read_text(errors="ignore").splitlines()
        chunk = lines[start:end]
        # Forward slashes so the model copies a JSON-safe path (backslashes become
        # invalid \escape sequences in the findings JSON on Windows).
        rel = str(p.relative_to(t)).replace("\\", "/")
        return f"// {rel} lines {start+1}-{start+len(chunk)}\n" + \
               "\n".join(f"{start+n+1}: {ln}" for n, ln in enumerate(chunk))

    reg.add(Tool(
        "read_file",
        "Read a slice of a source file in the target tree. Use to inspect code "
        "you found via search. Args: path (relative), start (1-based line), end.",
        {"type": "object",
         "properties": {"path": {"type": "string"},
                        "start": {"type": "integer"},
                        "end": {"type": "integer"}},
         "required": ["path"]},
        read_file,
    ))

    def ripgrep(i: dict) -> str:
        pat = i.get("pattern", "")
        if not pat:
            return "[empty pattern]"
        # If caller specifies a glob use it; otherwise search all language files.
        if i.get("glob"):
            flags = ["-g", i["glob"]]
        else:
            flags = list(glob_flags)
        # Optional exclude globs (ripgrep '-g !pat'): lets a symbol-resolution
        # search skip test/example/generated files that would otherwise crowd out
        # the real implementation and be lost to the output cap.
        for ex in (i.get("exclude") or []):
            flags += ["-g", f"!{ex}"]
        # Search "." with cwd=target so ripgrep emits TARGET-RELATIVE paths
        # (wolfcrypt/src/mlkem.c) instead of absolute ones. Canonical relative
        # paths are what read_file expects and stop the model inventing bogus
        # absolute prefixes (the /mnt/p/...wolfssl-5.7.0/ mangling, open issue #2).
        return _run(["rg", "-n", "--no-heading", *flags, pat, "."],
                    cwd=tstr, timeout=60) or "[no matches]"
    reg.add(Tool(
        "search_code",
        f"Search the target with ripgrep (regex). Use to find functions, "
        f"patterns, callers. Searches {', '.join(globs)} by default. "
        f"Args: pattern (regex), glob (optional override, e.g. '{primary_glob}').",
        {"type": "object",
         "properties": {"pattern": {"type": "string"},
                        "glob": {"type": "string"}},
         "required": ["pattern"]},
        ripgrep, requires="rg",
    ))

    def find_callers(i: dict) -> str:
        fn = i.get("function", "")
        if not fn:
            return "[no function name]"
        flags = list(glob_flags)
        # Optional exclude globs so caller resolution skips test/example call
        # sites that would fill the output cap before the real caller.
        for ex in (i.get("exclude") or []):
            flags += ["-g", f"!{ex}"]
        # cwd=target + "." → target-relative paths (see ripgrep note above).
        return _run(["rg", "-n", "--no-heading", *flags,
                     rf"\b{fn}\s*\(", "."], cwd=tstr, timeout=60) \
            or "[no callers found]"
    reg.add(Tool(
        "find_callers",
        "Find call sites of a function across the target. Use to understand how "
        "a routine is invoked and whether validation happens around it. "
        "Args: function (name).",
        {"type": "object", "properties": {"function": {"type": "string"}},
         "required": ["function"]},
        find_callers, requires="rg",
    ))

    def git_blame(i: dict) -> str:
        p = _safe(i.get("path", ""))
        if p is None:
            return "[path outside target]"
        rng = i.get("line_range", "")
        cmd = ["git", "-C", tstr, "blame"]
        if rng:
            cmd += ["-L", rng]
        cmd += [str(p)]
        return _run(cmd, timeout=60)
    reg.add(Tool(
        "git_blame",
        "git blame a file/range to see when a check was added or weakened "
        "(regression hunting). Args: path (relative), line_range (e.g. '6100,6120').",
        {"type": "object",
         "properties": {"path": {"type": "string"},
                        "line_range": {"type": "string"}},
         "required": ["path"]},
        git_blame, requires="git",
    ))

    # --- static analysis (on-demand, scoped to a file) -----------------
    def flawfinder(i: dict) -> str:
        p = _safe(i.get("path", "")) if i.get("path") else t
        return _run(["flawfinder", "--quiet", "--dataonly", str(p)], timeout=120)
    reg.add(Tool(
        "run_flawfinder",
        "Run flawfinder on a file or the whole tree (omit path). Pattern-based "
        "risky-call detector. Args: path (relative, optional).",
        {"type": "object", "properties": {"path": {"type": "string"}}},
        flawfinder, requires="flawfinder",
    ))

    def cppcheck(i: dict) -> str:
        p = _safe(i.get("path", "")) if i.get("path") else t
        return _run(["cppcheck", "--enable=warning,portability", "--quiet",
                     "--template=gcc", str(p)], timeout=180)
    reg.add(Tool(
        "run_cppcheck",
        "Run cppcheck on a file or tree (omit path). Catches memory/portability "
        "issues flawfinder misses. Args: path (relative, optional).",
        {"type": "object", "properties": {"path": {"type": "string"}}},
        cppcheck, requires="cppcheck",
    ))

    def clang_analyzer(i: dict) -> str:
        p = _safe(i.get("path", ""))
        if p is None or not p.exists():
            return "[need a valid file path]"
        # Single-file analysis; full builds need scan-build wrapping the make.
        return _run(["clang", "--analyze", "-Xclang", "-analyzer-output=text",
                     f"-I{tstr}", str(p)], timeout=120)
    reg.add(Tool(
        "run_clang_analyzer",
        "Run the clang static analyzer on one file (path-sensitive dataflow; "
        "different engine than cppcheck). Args: path (relative, required).",
        {"type": "object", "properties": {"path": {"type": "string"}},
         "required": ["path"]},
        clang_analyzer, requires="clang",
    ))

    def semgrep(i: dict) -> str:
        p = _safe(i.get("path", "")) if i.get("path") else t
        cfg = i.get("config", "auto")
        return _run(["semgrep", f"--config={cfg}", "--quiet", "--no-git-ignore",
                     str(p)], timeout=180)
    reg.add(Tool(
        "run_semgrep",
        "Run semgrep (configurable rulesets). Args: path (optional), "
        "config (default 'auto').",
        {"type": "object",
         "properties": {"path": {"type": "string"}, "config": {"type": "string"}}},
        semgrep, requires="semgrep",
    ))

    return reg


# --- extension stubs: add to build_default_registry when ready ----------
#
# def _codeql(i): ...      requires a built database; wrap `codeql database
#                          analyze` and return SARIF-derived findings.
# def _wycheproof(i): ...  look up known crypto edge-case test vectors for the
#                          named primitive to feed differential testing.
# def _infer(i): ...       interprocedural memory-safety (needs compile db).


# ---------------------------------------------------------------------------
# v2: Go static analysis tools (circl and other Go targets)
# ---------------------------------------------------------------------------
import shutil as _shutil
import logging as _logging

_go_log = _logging.getLogger("pqc.go_tools")

_GO_AVAIL        = _shutil.which("go") is not None
_STATICCHECK_AVAIL = _shutil.which("staticcheck") is not None
_GOSEC_AVAIL     = _shutil.which("gosec") is not None
# NOTE: no import-time warnings here. Go/Java tools are only relevant when the
# TARGET is Go/Java; warning about them on a C/C++ run is just noise. Missing
# tools are surfaced per-language by tool_status() (see main.py preflight).


def _check_go_mod(target_path: str) -> None:
    from pathlib import Path
    if not (Path(target_path) / "go.mod").exists():
        _go_log.warning("No go.mod in %s — Go static tools may have limited output.", target_path)


def _go_run(cmd: list[str], cwd: str, timeout: int = 120) -> str:
    import subprocess
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        out = r.stdout + r.stderr
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[timeout] {' '.join(cmd)} timed out after {timeout}s"
    except Exception as e:
        return f"[error] {e}"


def register_go_tools(reg: ToolRegistry, target_path: str) -> None:
    """Register Go-specific tools into an existing registry. Call after
    build_default_registry() when targeting a Go library."""
    tstr = target_path

    def go_vet(i: dict) -> str:
        if not _GO_AVAIL:
            return "[skip] go not installed"
        _check_go_mod(tstr)
        return _go_run(["go", "vet", "./..."], cwd=tstr)

    def staticcheck(i: dict) -> str:
        if not _STATICCHECK_AVAIL:
            return "[skip] staticcheck not installed — go install honnef.co/go/tools/cmd/staticcheck@latest"
        _check_go_mod(tstr)
        return _go_run(["staticcheck", "./..."], cwd=tstr)

    def gosec(i: dict) -> str:
        if not _GOSEC_AVAIL:
            return "[skip] gosec not installed — go install github.com/securego/gosec/v2/cmd/gosec@latest"
        _check_go_mod(tstr)
        return _go_run(["gosec", "./..."], cwd=tstr)

    reg.add(Tool(
        "run_go_vet",
        "Run `go vet ./...` on the Go target. Catches unsafe.Pointer misuse, "
        "incorrect printf args, suspicious composite literals.",
        {"type": "object", "properties": {}},
        go_vet,
    ))
    reg.add(Tool(
        "run_staticcheck",
        "Run `staticcheck ./...` on the Go target. Catches nil dereferences, "
        "incorrect error handling, concurrency mistakes.",
        {"type": "object", "properties": {}},
        staticcheck,
    ))
    reg.add(Tool(
        "run_gosec",
        "Run `gosec ./...` on the Go target. Flags weak crypto, math/rand vs "
        "crypto/rand, unsafe package usage, integer overflow patterns.",
        {"type": "object", "properties": {}},
        gosec,
    ))


# ---------------------------------------------------------------------------
# Java static analysis tools (bouncycastle and other Java targets). Both run
# natively on Windows (semgrep does NOT — no native Windows build — so it is
# deliberately not used here):
#   * PMD          — SOURCE-based, NO build needed. The default Java SAST.
#   * SpotBugs (+FindSecBugs) — analyses COMPILED bytecode, so it needs a build
#     (e.g. `./gradlew assemble`); it skips gracefully when no classes exist.
#     FindSecBugs adds crypto/security detectors (predictable RNG, weak crypto,
#     non-constant-time compare) — point FINDSECBUGS_PLUGIN at its plugin jar.
# CodeQL (Java) also needs a built database and is left for separate wiring.
# ---------------------------------------------------------------------------
_PMD_AVAIL = _shutil.which("pmd") is not None
_SPOTBUGS_AVAIL = _shutil.which("spotbugs") is not None
# (Java SAST availability is reported per-language by tool_status(), not warned
# about at import — see the note by the Go probes above.)


def tool_status(lang: str) -> list[dict]:
    """Which optional analysis tools are installed and RELEVANT to `lang`.

    Returns rows of {tool, purpose, required, installed}. Universal tools (rg,
    git) plus only the SAST tools for the target's language — so a C++ run never
    reports missing Go/Java tools. Drives the main.py startup preflight/--doctor.
    """
    lang = (lang or "").lower()
    universal = [
        ("rg", "code search — REQUIRED", True),
        ("git", "blame / history", False),
    ]
    by_lang = {
        "c":         [("flawfinder", "C/C++ SAST"), ("cppcheck", "C/C++ SAST"),
                      ("clang", "clang static analyzer"), ("semgrep", "SAST (optional)")],
        "go":        [("go", "go vet"), ("staticcheck", "Go SAST"),
                      ("gosec", "Go security SAST")],
        "java":      [("pmd", "Java SAST — source"), ("spotbugs", "Java SAST — bytecode")],
    }
    by_lang["cpp"] = by_lang["boringssl"] = by_lang["c"]
    rows = [{"tool": t, "purpose": p, "required": req,
             "installed": _shutil.which(t) is not None}
            for t, p, req in universal]
    rows += [{"tool": t, "purpose": p, "required": False,
              "installed": _shutil.which(t) is not None}
             for t, p in by_lang.get(lang, by_lang["c"])]
    return rows


def register_java_tools(reg: ToolRegistry, target_path: str) -> None:
    """Register Java SAST tools into an existing registry. Call after
    build_default_registry() when targeting a Java library. PMD is source-based
    (no build); SpotBugs needs compiled classes and skips gracefully without."""
    tstr = target_path

    def pmd(i: dict) -> str:
        if not _PMD_AVAIL:
            return ("[skip] pmd not installed — https://pmd.github.io "
                    "(source-based, no build needed)")
        p = i.get("path") or "."
        # PMD 7 CLI: `pmd check`. Security + error-prone categories cover weak
        # crypto, predictable RNG, and risky patterns without compilation.
        return _run(["pmd", "check", "-d", p, "-R",
                     "category/java/security.xml,category/java/errorprone.xml",
                     "-f", "text", "--no-cache"], cwd=tstr, timeout=240)

    def spotbugs(i: dict) -> str:
        if not _SPOTBUGS_AVAIL:
            return ("[skip] spotbugs not installed — https://spotbugs.github.io "
                    "(analyses bytecode; needs a build)")
        # SpotBugs analyses BYTECODE, so it needs compiled output. Look for a
        # gradle build (per-module build/classes/java/main) or a built jar.
        from pathlib import Path as _P
        root = _P(i.get("path") or tstr)
        cls_dirs = [str(p) for p in root.rglob("build/classes/java/main")
                    if p.is_dir()][:20]
        jars = [] if cls_dirs else [str(p) for p in root.rglob("build/libs/*.jar")][:10]
        targets = cls_dirs or jars
        if not targets:
            return ("[skip] no compiled classes found — build first, e.g. "
                    "`./gradlew assemble` (SpotBugs analyses bytecode, not "
                    "source). PMD (run_pmd) covers the source-only case.")
        cmd = ["spotbugs", "-textui", "-effort:max", "-low"]
        plugin = os.environ.get("FINDSECBUGS_PLUGIN", "")
        if plugin and _P(plugin).exists():
            cmd += ["-pluginList", plugin]   # FindSecBugs crypto/security rules
        cmd += targets
        return _run(cmd, cwd=tstr, timeout=300)

    reg.add(Tool(
        "run_pmd",
        "Run PMD on the Java target (source-based; no build needed). Flags weak "
        "crypto, predictable RNG (java.util.Random), and error-prone patterns. "
        "Args: path (relative, optional).",
        {"type": "object", "properties": {"path": {"type": "string"}}},
        pmd, requires="pmd",
    ))
    reg.add(Tool(
        "run_spotbugs",
        "Run SpotBugs (with FindSecBugs when FINDSECBUGS_PLUGIN points to its "
        "jar) on the Java target's COMPILED classes. Detects predictable RNG, "
        "weak crypto, and non-constant-time compares. Needs a build (e.g. "
        "`./gradlew assemble`); skips gracefully if no classes are found. "
        "Args: path (relative, optional).",
        {"type": "object", "properties": {"path": {"type": "string"}}},
        spotbugs, requires="spotbugs",
    ))


# ---------------------------------------------------------------------------
# v3: dynamic symbol discovery — replaces reliance on hardcoded ENTRY_POINTS.
# Enumerates crypto-relevant function definitions across the whole target so
# the investigator can explore beyond the curated location map.
# ---------------------------------------------------------------------------
import subprocess as _sp

# Crypto-relevant symbol patterns (function names worth investigating in any
# PQC library, regardless of version or naming convention).
_CRYPTO_SYMBOL_PATTERNS = [
    "decap", "encap", "keygen", "key_gen", "genkey", "generate_key",
    "sign", "verify", "check", "valid", "reduce", "ntt", "intt", "sample",
    "rejection", "decode", "encode", "decompress", "compress", "poly",
    "montgomery", "barrett", "constant_time", "ct_", "memcmp", "rng", "rand",
    "seed",
    # PQClean-style naming used in liboqs vendored implementations:
    # PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec, crypto_kem_enc, crypto_sign_verify
    "crypto_kem", "crypto_sign", "pqclean", "kem_dec", "kem_enc", "kem_keypair",
]

# Per-library additions to discover_symbols' generic pqc_hint whitelist below.
# Empty (no effect) for every library except where a specific under-covered
# surface has been identified. boringssl's hybrid KEM lives inside the TLS 1.3
# state machine (HelloRetryRequest, ClientHello2 consistency, transcript/PSK
# binder recomputation), not just crypto/mlkem/*.c, so its handshake-layer
# terms need to be in the whitelist too. Scoped by library name so adding this
# cannot change discover_symbols output for any OTHER library.
_LIBRARY_PQC_HINT_EXTRA = {
    "boringssl": ("key_share", "keyshare", "client_hello", "clienthello",
                  "hello_retry", "helloretry", "handshake", "transcript",
                  "supported_group", "binder", "hybrid"),
}

# Per-library removals from discover_symbols' generic `noise` suppression list
# below. The generic list blanket-suppresses any line whose path contains
# "/ssl.c" / "tls.c" / "tls13.c" as "TLS-config noise" -- for boringssl that
# silently buries ssl/tls13_client.cc and ssl/tls13_server.cc, exactly where
# the handshake-layer entry points in libraries/boringssl.toml (e.g.
# do_read_hello_retry_request, ssl_verify_psk_binder) live. Scoped by library
# name so this cannot change discover_symbols output for any OTHER library.
_LIBRARY_NOISE_EXCLUDE = {
    "boringssl": ("/ssl.c", "tls.c", "tls13.c"),
}


def register_discovery_tool(reg: "ToolRegistry", target_path: str,
                            globs: list[str] | None = None,
                            library: str = "") -> None:
    """Register a discover_symbols tool that finds crypto-relevant functions
    across the entire target tree (not just hardcoded entry points)."""
    globs = globs or ["*.c", "*.h"]
    glob_flags: list[str] = []
    for g in globs:
        glob_flags += ["-g", g]
    library = (library or "").strip().lower()

    def discover_symbols(i: dict) -> str:
        category = i.get("category", "").strip().lower()
        if category:
            patterns = [p for p in _CRYPTO_SYMBOL_PATTERNS if category in p or p in category]
            if not patterns:
                patterns = [category]
        else:
            patterns = _CRYPTO_SYMBOL_PATTERNS

        # Build a single ripgrep alternation for function-definition-like lines.
        alt = "|".join(patterns)
        # Match C/C++/Go/Java function-ish lines containing a crypto keyword.
        rx = rf"\b\w*({alt})\w*\s*\("
        # Search "." with cwd=target so symbol locations come back
        # target-relative (canonical), matching read_file's expectations.
        cmd = ["rg", "--line-number", "--no-heading", "-i",
               "--max-count=200"] + glob_flags + [rx, "."]
        try:
            # encoding/errors explicit: ripgrep emits the matched source bytes, and
            # a .java file with a non-cp1252 byte (e.g. 0x90) crashes the reader
            # thread under Windows' default cp1252. UTF-8 + replace keeps it alive.
            r = _sp.run(cmd, capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=60,
                        cwd=target_path)
            out = r.stdout.strip()
            if not out:
                return "(no crypto-relevant symbols found)"
            # v3: keep the investigator on PQC implementation code. Prefer lines
            # in PQC-relevant files; drop benchmark/test/example/IDE/TLS-config
            # noise that causes the model to drift away from crypto internals.
            # Standardised PQC algorithm names — identical across libraries. No
            # per-library tokens (e.g. wolfSSL's "wc_mlkem") are needed: they are
            # already subsumed by the generic "mlkem"/"mldsa" substrings.
            pqc_hint = ("mlkem", "ml_kem", "kyber", "mldsa", "ml_dsa", "dilithium",
                        "falcon", "sphincs", "slhdsa", "xmss", "lms", "random",
                        "rng", "sha3", "shake", "fips", "pqc", "kem", "/sign/",
                        "/sig/") + _LIBRARY_PQC_HINT_EXTRA.get(library, ())
            noise_exclude = _LIBRARY_NOISE_EXCLUDE.get(library, ())
            noise = tuple(n for n in (
                "/test", "/tests/", "/benchmark", "/example", "/ide/",
                "/doc/", "run_benchmark", "_test.", "test_", "/mcuexpresso",
                "internal.c", "/ssl.c", "tls.c", "tls13.c")
                if n not in noise_exclude)
            lines = out.splitlines()
            prioritised = [ln for ln in lines
                           if any(h in ln.replace("\\", "/").lower() for h in pqc_hint)
                           and not any(n in ln.replace("\\", "/").lower() for n in noise)]
            # For libraries with an extra-hint surface (currently boringssl's
            # handshake terms), pull matches on those terms to the FRONT before
            # the [:150] cap below. Without this, rg's file-traversal order puts
            # the (numerous) crypto/mlkem primitive hits first, and the
            # handshake-layer lines fall past both this cap and the caller's
            # char-budget truncation despite matching pqc_hint. No-op (empty
            # extra_hint) for every library without an override, so this cannot
            # change output for anything but boringssl.
            extra_hint = _LIBRARY_PQC_HINT_EXTRA.get(library, ())
            if extra_hint and prioritised:
                boosted, rest = [], []
                for ln in prioritised:
                    norm_ln = ln.replace("\\", "/").lower()
                    (boosted if any(h in norm_ln for h in extra_hint) else rest).append(ln)
                prioritised = boosted + rest
            filtered = prioritised or [ln for ln in lines
                                       if not any(n in ln.replace("\\", "/").lower() for n in noise)]
            return "\n".join(filtered[:150]) or "(no PQC-relevant symbols found)"
        except Exception as e:
            return f"[error] {e}"

    reg.add(Tool(
        "discover_symbols",
        "Enumerate crypto-relevant function definitions across the ENTIRE target "
        "tree (decap, encap, keygen, sign, verify, ntt, reduce, sample, rng, etc). "
        "Use this FIRST to find investigation targets beyond the listed entry "
        "points. Optional 'category' arg narrows to one keyword (e.g. 'decap').",
        {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Optional keyword to narrow the search (e.g. 'decap', 'ntt', 'rng'). Omit to list all.",
                },
            },
        },
        discover_symbols,
        requires="rg",
    ))
