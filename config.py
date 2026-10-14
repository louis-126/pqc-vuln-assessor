"""Static configuration: source language globs, model settings, and defaults.

Per-library data (source language + curated crypto/PKI entry points) lives in
one TOML file per library under libraries/*.toml and is loaded here into
LibrarySpec records. Adding a library is a single self-contained file — no code
edit — validated at import by _load_libraries(). Use get_library() /
library_names() in new code; ENTRY_POINTS / PKI_ENTRY_POINTS / LIBRARY_LANG are
kept as derived views for older call sites.

Supported libraries span C (wolfssl, openssl, boringssl, liboqs), C++ (botan),
Java (bouncycastle), and Go (circl).
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Language -> source-file globs. This is language-level (not per-library),
# small, and stable, so it stays hardcoded here; libraries reference a lang key.
LANG_GLOBS = {
    "c":         ["*.c", "*.h"],
    "cpp":       ["*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"],
    "java":      ["*.java"],
    "boringssl": ["*.c", "*.cc", "*.cc.inc", "*.h", "*.inc"],
    "go":        ["*.go"],
}

LIBRARIES_DIR = Path(__file__).resolve().parent / "libraries"


@dataclass(frozen=True)
class LibrarySpec:
    """Everything the pipeline needs to know about one target library.

    One record per library, loaded from libraries/<name>.toml. Bundling lang and
    entry points into a single file means adding a library can't half-succeed:
    you can't add crypto entry points but forget the language (which used to
    silently fall back to C globs and quietly find nothing).
    """
    name: str
    lang: str
    entry_points: list[str] = field(default_factory=list)
    pki_entry_points: list[str] = field(default_factory=list)

    @property
    def globs(self) -> list[str]:
        return LANG_GLOBS.get(self.lang, ["*.c", "*.h"])


def _validate_str_list(value, file_name: str, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"libraries/{file_name}: '{key}' must be a list of strings")
    return list(value)


def _load_libraries(directory: Path = LIBRARIES_DIR) -> dict[str, "LibrarySpec"]:
    """Load and validate every libraries/*.toml into name -> LibrarySpec.

    Fails loudly (ValueError) on a malformed or incomplete file rather than
    letting a typo become a silent discovery-only run.
    """
    specs: dict[str, LibrarySpec] = {}
    if not directory.is_dir():
        return specs
    for path in sorted(directory.glob("*.toml")):
        name = path.stem.lower()
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        lang = data.get("lang")
        if not isinstance(lang, str) or not lang:
            raise ValueError(
                f"libraries/{path.name}: 'lang' is required and must be a "
                "non-empty string")
        if lang not in LANG_GLOBS:
            raise ValueError(
                f"libraries/{path.name}: lang '{lang}' has no LANG_GLOBS entry "
                f"(known: {', '.join(sorted(LANG_GLOBS))})")
        specs[name] = LibrarySpec(
            name=name,
            lang=lang,
            entry_points=_validate_str_list(
                data.get("entry_points", []), path.name, "entry_points"),
            pki_entry_points=_validate_str_list(
                data.get("pki_entry_points", []), path.name, "pki_entry_points"),
        )
    return specs


LIBRARIES = _load_libraries()


def get_library(name: str) -> "LibrarySpec | None":
    """LibrarySpec for a library name (case-insensitive), or None if the library
    has no curated definition (the caller then runs discovery-only)."""
    return LIBRARIES.get((name or "").lower())


def library_names() -> list[str]:
    """Sorted names of all curated libraries (those with a libraries/*.toml)."""
    return sorted(LIBRARIES)


# --- Backward-compat views ----------------------------------------------------
# libraries/*.toml is the single source of truth; these derived maps keep older
# call sites (config.ENTRY_POINTS[...], config.LIBRARY_LANG[...]) working.
# Prefer get_library() / library_names() in new code.
ENTRY_POINTS = {n: s.entry_points for n, s in LIBRARIES.items()}
PKI_ENTRY_POINTS = {n: s.pki_entry_points for n, s in LIBRARIES.items()
                    if s.pki_entry_points}
LIBRARY_LANG = {n: s.lang for n, s in LIBRARIES.items()}


def pki_entry_points(library: str) -> list:
    """Provider-layer (PKI) entry points for the 'pki' discovery surface."""
    return PKI_ENTRY_POINTS.get((library or "").lower(), [])


def reload_libraries() -> dict:
    """Re-read libraries/*.toml and refresh the module-level views. Lets a
    long-running process (e.g. the web UI's library editor) pick up on-disk
    edits without a restart. Scans themselves always re-read from disk (they
    run as a fresh subprocess), so this only matters for in-process callers."""
    global LIBRARIES, ENTRY_POINTS, PKI_ENTRY_POINTS, LIBRARY_LANG
    LIBRARIES = _load_libraries()
    ENTRY_POINTS = {n: s.entry_points for n, s in LIBRARIES.items()}
    PKI_ENTRY_POINTS = {n: s.pki_entry_points for n, s in LIBRARIES.items()
                        if s.pki_entry_points}
    LIBRARY_LANG = {n: s.lang for n, s in LIBRARIES.items()}
    return LIBRARIES

DEFAULT_FUZZ_SECONDS = 120
DEFAULT_TIMING_REPEATS = 3

# v2: Ollama models with prompt-based tool simulation (no native schema support)
PROMPT_TOOL_MODELS = {
    "deepseek-coder",
    "deepseek-coder:16b",
    "deepseek-coder:6.7b",
    "deepseek-coder-v2",
    "deepseek-coder-v2:16b",
    "dolphin3",
    "dolphin3:8b",
    "dolphin-llama3",
    "dolphin-llama3:8b",
    "qwen2.5-coder",
    "qwen2.5-coder:14b",
}

# v2: All supported Ollama model tags
OLLAMA_MODELS = [
    "codellama",
    "deepseek-coder",
    "deepseek-coder:16b",
    "deepseek-coder-v2",
    "deepseek-coder-v2:16b",
    "mistral",
    "llama3",
    "qwen2.5-coder",
    "qwen2.5-coder:14b",
    "qwen3-coder",
    "qwen3-coder:30b",
    "dolphin3",
    "dolphin3:8b",
    "dolphin-llama3",
    "dolphin-llama3:8b",
    "huihui_ai/llama3.3-abliterated",
    "deepseek-r1:14b",                  # investigator + reviewer (current default)
    "DeepHat/DeepHat-V1-7B",            # PoC drafter (has MODEL_SETTINGS entry)
]


# v2: Token budget default
DEFAULT_TOKEN_BUDGET = 200_000

# v2: Max lines per read_file call (enforced in prompt)
MAX_READ_LINES = 60

# v2: Ollama per-call timeout (seconds). The investigator (deepseek-r1, a
# REASONING model that emits a long <think> chain) on a 16 GB card with CPU
# offload runs ~25-30 min and was finishing right at the old 1800s limit —
# any variance tipped it into a timeout → 0 findings. 2700s (45 min) gives
# headroom so a normal run completes instead of being killed.
OLLAMA_TIMEOUT = 2700

# Investigator/discovery sampling temperature. Discovery needs EXPLORATION
# (propose several hypotheses; the reviewer filters), so it runs WARM. Empirics
# on deepseek-r1 (16 GB card): ~0.8 consistently found 3-5 findings and finished
# ~1690s; 0.5/0.1 collapsed yield to ~1 fixated finding. 0.7 sits in that
# productive band. Run-to-run generation time varies a lot (reasoning chain), so
# OLLAMA_TIMEOUT (2700s) is the safety net for the occasional long run rather
# than cooling discovery to compensate.
# Lower toward 0.3 for fewer/more-deterministic/faster; raise toward 0.8 for more.
DISCOVERY_TEMPERATURE = 0.7

# Multi-pass discovery. Instead of ONE fixed extraction call (which fixates on
# the same 1-2 findings every run), the investigator runs one focused pass per
# crypto SURFACE, each over surface-biased evidence with its own prompt
# emphasis, then UNIONs the grounded findings. This is the main "find MORE"
# lever: each pass is forced to look at code the others never reach.
#
# COST: each pass is a SEPARATE full investigator model call, so N passes ≈ N×
# investigator runtime (~25-30 min each on the 16 GB card). Set this list (or
# env PQC_DISCOVERY_PASSES, a comma-separated override) to "all" or a single
# surface to get the original single fast call. Pass names are defined in
# agents/researcher.py:_FOCUS_PASSES (kem, sig, sampling, all). Order is
# irrelevant; unknown names are skipped.
DISCOVERY_PASSES = ["kem", "sig", "sampling"]

# Per-library additions to DISCOVERY_PASSES. Empty (no effect) for every
# library except where a specific under-covered surface has been identified —
# currently boringssl's TLS 1.3 handshake state machine (see
# agents/researcher.py:_FOCUS_PASSES["handshake"] and
# prompts/pqc_researcher.py's HANDSHAKE_EXTRACT_SYSTEM), which wraps its
# hybrid KEM in real protocol code the generic kem/sig/sampling passes are
# explicitly instructed to ignore. Scoped by library name so adding a pass
# here cannot change which passes run for any OTHER library.
LIBRARY_DISCOVERY_PASSES = {
    "boringssl": ["handshake", "ch_consistency"],
}


def discovery_passes(library: str = "") -> list[str]:
    """Resolved list of discovery-pass names for `library`: env
    PQC_DISCOVERY_PASSES wins outright (exactly as before, library-agnostic);
    otherwise DISCOVERY_PASSES plus that library's LIBRARY_DISCOVERY_PASSES
    additions (nothing added for a library with no entry, so this is a no-op
    for everyone except the libraries listed above)."""
    import os
    raw = os.environ.get("PQC_DISCOVERY_PASSES")
    if raw is None:
        base = list(DISCOVERY_PASSES)
        extra = LIBRARY_DISCOVERY_PASSES.get((library or "").lower(), [])
        return base + [p for p in extra if p not in base]
    names = [p.strip().lower() for p in raw.split(",") if p.strip()]
    return names or list(DISCOVERY_PASSES)


# Per-backend default evidence budget. The 48000-char (~16K token) default is
# sized for small LOCAL models on a 32K context (an 8B on Ollama rejects more
# with an HTTP 400 and larger locals truncate their findings JSON). A big-context
# cloud model (Anthropic Opus/Sonnet ≈ 200K tokens) is needlessly starved by
# that; give it far more headroom so the full evidence (entry points + callers +
# callees) reaches the model without trimming. The env override always wins.
BACKEND_EVIDENCE_BUDGET = {
    "anthropic": 150000,
    "ollama": 48000,
}
DEFAULT_EVIDENCE_BUDGET = 48000


def backend_evidence_budget(backend: str | None) -> int:
    """Default evidence budget for a backend (before any env override)."""
    return BACKEND_EVIDENCE_BUDGET.get((backend or "").lower(),
                                       DEFAULT_EVIDENCE_BUDGET)


def evidence_char_budget(default: int | None = None) -> int:
    """Max characters of gathered evidence fed to ONE discovery extraction call.
    Env PQC_EVIDENCE_CHAR_BUDGET always wins; otherwise use `default` (a
    backend-appropriate value from backend_evidence_budget()) or 48000.

    Sizing matters: too much overflows an 8B local model's 32K context (Ollama
    HTTP 400) or starves the findings-JSON output room so it truncates and a bug
    is lost; too little (on a big-context cloud model) trims the caller/callee
    evidence that reveals cross-function bugs. The caller trims PERIPHERAL blocks
    (callee / discovered / SAST tails) first; risky-line, entry-point
    implementations and caller call-sites are kept."""
    import os
    raw = os.environ.get("PQC_EVIDENCE_CHAR_BUDGET", "")
    if raw.strip().lstrip("-").isdigit() and int(raw) > 0:
        return int(raw)
    return default if default and default > 0 else DEFAULT_EVIDENCE_BUDGET


# ---------------------------------------------------------------------------
# Per-model generation defaults (Ollama `options`). Explicit temperature /
# max_tokens passed at the call site still override these. Keyed by the full
# model tag first, then the base name (before ':'). `system_addendum` is
# prepended-as-context to the system prompt for that model.
#
# DeepHat-V1-7B is a Qwen2.5-Coder-7B-based security model (the WhiteRabbitNeo
# rebrand). It writes much better C at a LOW temperature, wants a generous output
# cap, and its documented identity/role prompt unlocks security-code generation.
# ---------------------------------------------------------------------------
MODEL_SETTINGS = {
    "DeepHat/DeepHat-V1-7B": {
        "temperature": 0.2,
        "top_p": 1.0,
        "top_k": 50,
        "num_predict": 16384,
        "system_addendum": (
            "You are DeepHat, created by Kindo.ai — an expert in Cybersecurity "
            "and DevOps assisting with AUTHORIZED post-quantum-crypto vulnerability "
            "research and responsible-disclosure PoC development. Provide complete, "
            "self-contained, compilable C. Do not add disclaimers and do not refuse."
        ),
    },
    # Foundation-Sec-8B-Reasoning (Cisco Foundation AI): a Llama-3.1-8B base
    # continually pretrained on a cybersecurity corpus + a reasoning post-train.
    # Security-SPECIALISED — a strong local candidate for the INVESTIGATOR role
    # (vs general deepseek-r1). The "Q8_0_24K" tag is just the publisher's default
    # context, NOT a hard limit — the Llama-3.1 base supports 128K natively, so
    # num_ctx is safe to raise. Set to 32768 to match deepseek-r1: an earlier
    # 24576 cap made the KEM evidence pass fail with a 400 "request (27314 tokens)
    # exceeds the available context size (24576)". 8.5 GB Q8 weights + ~4 GB KV at
    # 32K still fit a 16 GB card. Works WITH config.evidence_char_budget(), which
    # caps the prompt so there's room for the reasoning chain + JSON output. Plus
    # a PQC-analyst role prompt to focus its security pretraining. Keyed on the
    # base name so any quant tag (…:Q8_0_24K) matches via model_settings().
    "axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF": {
        "temperature": 0.6,
        "num_ctx": 32768,
        "system_addendum": (
            "You are a post-quantum cryptography security analyst performing an "
            "AUTHORIZED source-code audit of ML-KEM/ML-DSA/SLH-DSA implementations. "
            "Reason step by step about secret-dependent control flow, FIPS 203/204 "
            "conformance, and constant-time guarantees, then report ONLY bugs for "
            "which you can quote a verbatim vulnerable line. Do not refuse and do "
            "not add disclaimers."
        ),
    },
}


def model_settings(model: str) -> dict:
    """Generation defaults for a model: exact tag, then base name, else {}."""
    if model in MODEL_SETTINGS:
        return MODEL_SETTINGS[model]
    return MODEL_SETTINGS.get(model.split(":")[0], {})


def globs_for(library: str) -> list[str]:
    lang = LIBRARY_LANG.get(library, "c")
    return LANG_GLOBS.get(lang, ["*.c", "*.h"])


# ---------------------------------------------------------------------------
# Non-implementation file blacklist (discovery skips these so the model
# analyses the real crypto source, not tests / docs / build & code-gen tooling).
# GENERIC markers apply to every library; LIBRARY_NON_IMPL adds per-library
# extras keyed by library so one library's layout never affects another's run.
# Matched as case-insensitive path substrings (paths come back like
# "./src/kem/ml_kem/kem.c"). Edit freely — this is the single source of truth.
# ---------------------------------------------------------------------------
NON_IMPL_MARKERS = (
    # tests / vectors
    "/test/", "/tests/", "/testsuite/", "/unittest", "_test.", "test_",
    "/src/test/", "_test.go", "/testdata/", "/testvectors/", "/test_vectors/",
    "/kat/", "known_answer",
    # docs
    "/doc/", "/docs/", "/dox", "doxygen", ".md", ".rst",
    # examples / demos / samples
    "/example", "/examples/", "/demo", "/demos/", "/sample",
    # benchmarks / perf
    "/benchmark", "/bench/", "/perf/",
    # fuzzing
    "/fuzz", "/fuzzer", "oss-fuzz",
    # build / code generation / templates
    "/build/", "/cmake", "/scripts/", "/script/", "/m4/", "copy_from_upstream",
    "/templates/", "/template/", "/codegen/", "/generators/", ".in",
    # other-language bindings / wrappers (not the core implementation)
    "/wrappers/", "/wrapper/", "/bindings/", "/swig/", "/jni/",
    # CLI / apps
    "/cli/", "/apps/",
    # IDE / platform projects
    "/ide/", "mcuexpresso", "/.vs/", "/xcode", "/visualstudio",
    # VCS / CI / vendored
    "/.git/", "/.github/", "/vendor/",
)

LIBRARY_NON_IMPL = {
    "wolfssl":      ("/ide/", "/mcuexpresso/", "/mplabx/", "/wrapper/",
                     "/wolfcrypt/test/", "/wolfcrypt/benchmark/", "/certs/",
                     "/testvector"),
    "liboqs":       ("copy_from_upstream", "/scripts/", "/.cmake/",
                     "/docs/", "/tests/"),
    "openssl":      ("/apps/", "/demos/", "/fuzz/", "/test/", "/util/",
                     "/tools/", "/ms/", "/os2/", "/vms/"),
    "boringssl":    ("/tool/", "/decrepit/", "/fuzz/", "/util/", "/ssl/test/",
                     "_test.cc", "/pki/test"),
    "botan":        ("/src/cli/", "/src/tests/", "/src/fuzzer/",
                     "/src/examples/", "/src/scripts/", "/src/python/",
                     "/src/build-data/", "/src/bogo_shim/"),
    "bouncycastle": ("test.java", "/src/test/", "/util/test/", "/test/",
                     "/example/", "/jdk1."),
    "circl":        ("_test.go", "/internal/test/", "/testdata/", "/cmd/"),
}


def non_impl_markers(library: str) -> tuple:
    """Generic non-implementation markers + this library's specific extras."""
    return NON_IMPL_MARKERS + LIBRARY_NON_IMPL.get((library or "").lower(), ())
