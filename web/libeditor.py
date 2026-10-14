"""Backend for the web library (TOML) editor.

Lists / reads / validates / writes / deletes the per-library files under
libraries/*.toml. Validation mirrors config._load_libraries exactly, so the UI
can never write a file that would crash a later scan. After any write it calls
config.reload_libraries() so the running app (dropdowns, detection) stays fresh.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import config  # noqa: E402

LIB_DIR = config.LIBRARIES_DIR
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")

TEMPLATE = '''# {name}.toml — curated entry points for {name}
lang = "c"                    # one of: {langs}

# Crypto entry points the investigator anchors on. Keep it a lean, high-signal
# set (~7-15 uniquely-named symbols); dynamic discovery handles the rest.
entry_points = [
    # "example_kem_decapsulate",
    # "example_sig_verify",
]

# Optional provider-layer anchors, only used with PQC_DISCOVERY_PASSES=pki.
# pki_entry_points = ["checkCertificate"]
'''


def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match(name or ""))


def _path(name: str) -> Path | None:
    """Resolve libraries/<name>.toml, guarding traversal / bad names."""
    if not valid_name(name):
        return None
    p = (LIB_DIR / f"{name}.toml").resolve()
    if LIB_DIR.resolve() not in p.parents:
        return None
    return p


def validate(content: str) -> tuple[bool, str]:
    """Same rules as config._load_libraries. Returns (ok, error_message)."""
    try:
        data = tomllib.loads(content)
    except Exception as e:
        return False, f"TOML syntax error: {e}"
    lang = data.get("lang")
    if not isinstance(lang, str) or not lang:
        return False, "'lang' is required and must be a non-empty string"
    if lang not in config.LANG_GLOBS:
        return False, (f"lang '{lang}' is not supported "
                       f"(known: {', '.join(sorted(config.LANG_GLOBS))})")
    for key in ("entry_points", "pki_entry_points"):
        if key in data:
            v = data[key]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return False, f"'{key}' must be a list of strings"
    return True, ""


def list_libraries() -> list[dict]:
    """Summary of every library file, for the editor's file list."""
    out = []
    for name in config.library_names():
        spec = config.get_library(name)
        out.append({
            "name": name,
            "lang": spec.lang if spec else "?",
            "entry_points": len(spec.entry_points) if spec else 0,
            "pki_entry_points": len(spec.pki_entry_points) if spec else 0,
        })
    return out


def read_library(name: str) -> str | None:
    p = _path(name)
    if not p or not p.is_file():
        return None
    return p.read_text(encoding="utf-8")


def save_library(name: str, content: str) -> tuple[bool, str]:
    """Validate then write libraries/<name>.toml; reload config on success."""
    if not valid_name(name):
        return False, ("invalid name — use lowercase letters, digits, '-' or '_' "
                       "(this becomes the --library value)")
    p = _path(name)
    if not p:
        return False, "could not resolve a safe path for that name"
    ok, err = validate(content)
    if not ok:
        return False, err
    p.write_text(content if content.endswith("\n") else content + "\n",
                 encoding="utf-8")
    config.reload_libraries()
    return True, ""


def delete_library(name: str) -> tuple[bool, str]:
    p = _path(name)
    if not p or not p.is_file():
        return False, "not found"
    p.unlink()
    config.reload_libraries()
    return True, ""


def new_template(name: str) -> str:
    return TEMPLATE.format(name=name or "mylib",
                           langs=", ".join(sorted(config.LANG_GLOBS)))
