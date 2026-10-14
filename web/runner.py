"""Background scan-job manager for the web frontend.

Each scan runs the existing CLI (`python3 main.py ...`) as a subprocess into a
deterministic run dir, so it reuses ALL of the CLI's output plumbing: run.log,
run.json manifest, report.{html,md,json}, per-stage timings. The web layer only
orchestrates — it never re-implements the pipeline.

Jobs live in memory (this is a single-user local tool). The runs/ directory on
disk is the durable record; the history page reads from there, so job state
being lost on restart only affects live progress of in-flight scans.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = _REPO_ROOT / "runs"
WORKSPACES = _REPO_ROOT / "web" / "workspaces"
WORKSPACES.mkdir(parents=True, exist_ok=True)

# Valid choices mirrored from the CLI so the web layer rejects bad input early.
MODES = ["reason", "agent", "agent-review"]
BACKENDS = ["ollama", "anthropic"]

_JOBS: dict[str, "Job"] = {}
_LOCK = threading.Lock()

_GITHUB_RE = re.compile(
    r"^(https://github\.com/|git@github\.com:)[\w.-]+/[\w.-]+(\.git)?/?$"
)


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", text).strip("-")[:60] or "target"


class Job:
    def __init__(self, library: str, mode: str, backend: str, model: str | None,
                 explain: bool, source_kind: str, source: str,
                 discovery_passes: str | None = None,
                 reviewer_model: str | None = None,
                 git_ref: str | None = None,
                 poc: bool = False,
                 poc_drafter_model: str | None = None,
                 poc_critic_model: str | None = None,
                 poc_compile_rounds: int = 0):
        self.id = uuid.uuid4().hex[:12]
        self.library = library
        self.mode = mode
        self.backend = backend
        self.model = model
        self.reviewer_model = reviewer_model
        self.git_ref = git_ref
        self.explain = explain
        self.discovery_passes = discovery_passes   # PQC_DISCOVERY_PASSES override
        # PoC generation runs as the pipeline's last stage, in the same
        # subprocess — so packages land in <outdir>/poc/<FINDING-ID>/ and are
        # visible to the PoC pages the moment the scan finishes.
        self.poc = poc
        self.poc_drafter_model = poc_drafter_model
        self.poc_critic_model = poc_critic_model
        self.poc_compile_rounds = poc_compile_rounds
        self.source_kind = source_kind      # "github" | "path"
        self.source = source
        self.state = "queued"               # queued|preparing|running|done|failed|interrupted
        self.message = ""
        self.target: str | None = None
        self.run_id: str | None = None       # "<library>/<timestamp>" once known
        self.outdir: Path | None = None
        self.returncode: int | None = None
        self.started = time.time()
        self.finished: float | None = None
        self._proc: subprocess.Popen | None = None

    # -- serialisation for the API --------------------------------------
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "message": self.message,
            "library": self.library,
            "mode": self.mode,
            "backend": self.backend,
            "model": self.model,
            "reviewer_model": self.reviewer_model,
            "git_ref": self.git_ref,
            "source_kind": self.source_kind,
            "source": self.source,
            "target": self.target,
            "run_id": self.run_id,
            "returncode": self.returncode,
            "elapsed": round((self.finished or time.time()) - self.started, 1),
            "log_tail": self.log_tail(),
            "poc": self.poc,
            "poc_drafter_model": self.poc_drafter_model,
            "poc_critic_model": self.poc_critic_model,
            "poc_compile_rounds": self.poc_compile_rounds,
            "poc_count": self.poc_count(),
        }

    def poc_count(self) -> int:
        """How many PoC packages this run has written so far. Read from disk
        rather than tracked in memory, because the packages are produced by the
        scan subprocess, not by this thread."""
        if not self.outdir:
            return 0
        poc_root = self.outdir / "poc"
        if not poc_root.is_dir():
            return 0
        try:
            return sum(1 for d in poc_root.iterdir() if d.is_dir())
        except OSError:
            return 0

    def log_tail(self, lines: int = 40) -> list[str]:
        if not self.outdir:
            return []
        log = self.outdir / "run.log"
        if not log.exists():
            return []
        try:
            # run.log is written UTF-8 (main.py); decode it as UTF-8 explicitly.
            # Without this, Windows' cp1252 default mangles arrows/box glyphs/✓
            # in the live-progress box.
            return log.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
        except Exception:
            return []

    # -- the actual work (runs in a thread) -----------------------------
    def run(self) -> None:
        try:
            self.state = "preparing"
            target = self._prepare_target()
            self.target = str(target)

            ts = time.strftime("%Y%m%d-%H%M%S")
            self.outdir = RUNS_DIR / self.library / ts
            self.outdir.mkdir(parents=True, exist_ok=True)
            self.run_id = f"{self.library}/{ts}"

            cmd = [
                sys.executable, "main.py",
                "--target", str(target),
                "--library", self.library,
                "--mode", self.mode,
                "--backend", self.backend,
                "--outdir", str(self.outdir),
                "--no-live",                 # no ANSI boxes; run.log captures all
            ]
            if self.model:
                cmd += (["--ollama-model", self.model] if self.backend == "ollama"
                        else ["--model", self.model])
            if self.reviewer_model:
                cmd += ["--reviewer-model", self.reviewer_model]
            if self.explain:
                cmd += ["--explain"]
            if self.poc:
                cmd += ["--poc"]
                if self.poc_drafter_model:
                    cmd += ["--poc-drafter-model", self.poc_drafter_model]
                if self.poc_critic_model:
                    cmd += ["--poc-critic-model", self.poc_critic_model]
                if self.poc_compile_rounds:
                    cmd += ["--poc-compile-rounds", str(self.poc_compile_rounds)]

            self.state = "running"
            self.message = "scan in progress"
            # The scan inherits our environment; the Anthropic backend reads
            # ANTHROPIC_API_KEY from it (never taken over the wire / from a form).
            env = dict(os.environ)
            if self.discovery_passes:
                env["PQC_DISCOVERY_PASSES"] = self.discovery_passes
            self._proc = subprocess.Popen(
                cmd, cwd=str(_REPO_ROOT), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._proc.wait()
            self.returncode = self._proc.returncode
            self.finished = time.time()
            if self.returncode == 0:
                self.state = "done"
                n = self.poc_count()
                if self.poc:
                    # 0 packages is a normal outcome — the PoC stage only runs
                    # for CONFIRMED findings, so say so rather than look broken.
                    self.message = (f"scan complete · {n} PoC package(s)" if n
                                    else "scan complete · no confirmed findings to PoC")
                else:
                    self.message = "scan complete"
                self._update_latest_symlink()
            elif self.returncode in (-2, 130, -9, 137) and self.state == "interrupted":
                self.message = "scan cancelled"
            else:
                self.state = "failed"
                self.message = f"exit code {self.returncode}"
        except Exception as e:
            self.state = "failed"
            self.message = str(e)
            self.finished = time.time()

    def cancel(self) -> bool:
        if self._proc and self.state == "running":
            self.state = "interrupted"
            try:
                if sys.platform == "win32":
                    self._proc.terminate()
                else:
                    self._proc.send_signal(2)  # SIGINT -> CLI writes a partial report
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            return True
        return False

    # -- target preparation --------------------------------------------
    def _prepare_target(self) -> Path:
        if self.source_kind == "github":
            return self._clone_github(self.source, self.git_ref)
        if self.source_kind == "path":
            clean = self.source.strip("'\"")
            if clean.lower().startswith("file://"):
                import urllib.parse
                clean = clean[7:]
                if clean.lower().startswith("localhost/"):
                    clean = clean[10:]
                clean = urllib.parse.unquote(clean)
                if len(clean) >= 3 and clean[0] == "/" and clean[2] == ":":
                    clean = clean[1:]
            p = Path(clean).expanduser().resolve()
            if p.is_file():
                p = p.parent
            if not p.is_dir():
                raise ValueError(f"target directory not found: {p}")
            return p
        raise ValueError(f"unknown source kind: {self.source_kind}")

    def _clone_github(self, url: str, git_ref: str | None = None) -> Path:
        if not _GITHUB_RE.match(url):
            raise ValueError("not a valid GitHub repository URL")
        name = _slug(url.rstrip("/").split("/")[-1].replace(".git", ""))
        ref_slug = f"-{_slug(git_ref)}" if git_ref else ""
        dest = WORKSPACES / f"{name}{ref_slug}-{self.id}"
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        self.message = f"cloning repository ({git_ref or 'default branch'})…"
        cmd = ["git", "clone", "--depth", "1"]
        if git_ref:
            cmd += ["--branch", git_ref]
        cmd += [url, str(dest)]
        r = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            if git_ref:
                r2 = subprocess.run(["git", "clone", url, str(dest)], capture_output=True, text=True, timeout=600)
                if r2.returncode == 0:
                    subprocess.run(["git", "checkout", git_ref], cwd=str(dest), capture_output=True, text=True, timeout=60)
                    return dest
            raise RuntimeError(f"git clone failed: {r.stderr.strip()[:300]}")
        return dest

    def _update_latest_symlink(self) -> None:
        """Keep runs/<lib>/latest pointing at this (newest) run, matching CLI."""
        if not self.outdir:
            return
        link = self.outdir.parent / "latest"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(self.outdir.name)
        except OSError:
            pass


_PASSES = {"kem", "sig", "sampling", "pki", "all"}


MAX_POC_COMPILE_ROUNDS = 5

# Default PoC models, mirrored from main.py's argparse defaults. The web form
# sends "" for "use the default", and the CLI then applies these — so preflight
# has to check THESE, not the empty string, or a scan is accepted and the PoC
# stage still dies on an unreachable Ollama an hour later.
DEFAULT_POC_DRAFTER = "DeepHat/DeepHat-V1-7B"
DEFAULT_POC_CRITIC = "deepseek-r1:14b"

_OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


def _ollama_reachable() -> bool:
    try:
        import httpx
        httpx.get(f"{_OLLAMA_URL}/api/tags", timeout=3.0).raise_for_status()
        return True
    except Exception:
        return False


def preflight_poc_models(drafter: str | None, critic: str | None) -> None:
    """Raise ValueError if the PoC stage could not possibly run.

    A `claude-*` model needs ANTHROPIC_API_KEY; anything else is an Ollama tag
    and needs a reachable Ollama. This runs BEFORE the scan starts so a bad
    pairing costs a dialog box, not a completed scan (which is what happened
    when a Claude drafter was paired with the default local critic).
    """
    drafter = drafter or DEFAULT_POC_DRAFTER
    critic = critic or DEFAULT_POC_CRITIC
    have_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    ollama_ok = None                      # probe lazily — it costs a round trip

    problems = []
    for role, model in (("drafter", drafter), ("critic", critic)):
        if model.startswith("claude-"):
            if not have_key:
                problems.append(
                    f"PoC {role} model '{model}' is an Anthropic model but "
                    "ANTHROPIC_API_KEY is not set in the server environment.")
        else:
            if ollama_ok is None:
                ollama_ok = _ollama_reachable()
            if not ollama_ok:
                problems.append(
                    f"PoC {role} model '{model}' is a local Ollama model but "
                    f"Ollama is not reachable at {_OLLAMA_URL}. Start it "
                    "('ollama serve'), or pick a claude-* model for the "
                    f"{role} as well.")
    if problems:
        raise ValueError(" ".join(problems))


def start_job(library: str, mode: str, backend: str, model: str | None,
              explain: bool, source_kind: str, source: str,
              discovery_passes: str | None = None,
              reviewer_model: str | None = None,
              git_ref: str | None = None,
              poc: bool = False,
              poc_drafter_model: str | None = None,
              poc_critic_model: str | None = None,
              poc_compile_rounds: int = 0) -> Job:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if backend not in BACKENDS:
        raise ValueError(f"backend must be one of {BACKENDS}")
    if backend == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        raise ValueError("Anthropic backend needs ANTHROPIC_API_KEY in the "
                         "environment — export it before launching the web app.")
    if discovery_passes:
        bad = set(discovery_passes.split(",")) - _PASSES
        if bad:
            raise ValueError(f"unknown discovery pass(es): {', '.join(sorted(bad))}")
    if poc:
        # Cheap local checks before the preflight, which costs a network probe.
        if not isinstance(poc_compile_rounds, int) or poc_compile_rounds < 0:
            raise ValueError("PoC compile rounds must be a non-negative integer")
        if poc_compile_rounds > MAX_POC_COMPILE_ROUNDS:
            raise ValueError("PoC compile rounds must be at most "
                             f"{MAX_POC_COMPILE_ROUNDS}")
        preflight_poc_models(poc_drafter_model, poc_critic_model)
    job = Job(library, mode, backend, model or None, explain, source_kind, source,
              discovery_passes=discovery_passes, reviewer_model=reviewer_model or None,
              git_ref=git_ref or None, poc=poc,
              poc_drafter_model=poc_drafter_model or None,
              poc_critic_model=poc_critic_model or None,
              poc_compile_rounds=poc_compile_rounds or 0)
    with _LOCK:
        _JOBS[job.id] = job
    threading.Thread(target=job.run, daemon=True).start()
    return job


class PocJob:
    """Generate PoC packages for an ALREADY-COMPLETED run, with no re-scan.

    Shells out to `main.py --poc-only <run dir>` for the same reason Job shells
    out to `main.py`: the pipeline owns PoC generation, the web layer only
    orchestrates it. Exposes the same dict shape as Job so the existing
    /api/job/<id> polling and the progress panel work unchanged.
    """

    def __init__(self, run_id: str, drafter_model: str | None,
                 critic_model: str | None, compile_rounds: int = 0,
                 overwrite: bool = True):
        self.id = uuid.uuid4().hex[:12]
        self.run_id = run_id                     # "<library>/<timestamp>"
        self.library, _, self.timestamp = run_id.partition("/")
        self.outdir = RUNS_DIR / self.library / self.timestamp
        self.poc_drafter_model = drafter_model
        self.poc_critic_model = critic_model
        self.poc_compile_rounds = compile_rounds
        self.overwrite = overwrite
        self.kind = "poc"
        self.state = "queued"
        self.message = ""
        self.returncode: int | None = None
        self.started = time.time()
        self.finished: float | None = None
        self._proc: subprocess.Popen | None = None

    # Job-compatible surface ------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": "poc",
            "state": self.state,
            "message": self.message,
            "library": self.library,
            "mode": "poc-only",
            "run_id": self.run_id,
            "returncode": self.returncode,
            "elapsed": round((self.finished or time.time()) - self.started, 1),
            "log_tail": self.log_tail(),
            "poc": True,
            "poc_drafter_model": self.poc_drafter_model,
            "poc_critic_model": self.poc_critic_model,
            "poc_compile_rounds": self.poc_compile_rounds,
            "poc_count": self.poc_count(),
        }

    def log_tail(self, lines: int = 40) -> list[str]:
        log = self.outdir / "run.log"
        if not log.exists():
            return []
        try:
            return log.read_text(encoding="utf-8",
                                 errors="replace").splitlines()[-lines:]
        except OSError:
            return []

    def poc_count(self) -> int:
        poc_root = self.outdir / "poc"
        if not poc_root.is_dir():
            return 0
        try:
            return sum(1 for d in poc_root.iterdir() if d.is_dir())
        except OSError:
            return 0

    def cancel(self) -> bool:
        if self._proc and self.state == "running":
            self.state = "interrupted"
            try:
                self._proc.terminate()
            except Exception:
                pass
            return True
        return False

    def run(self) -> None:
        try:
            before = self.poc_count()
            cmd = [sys.executable, "main.py", "--poc-only", str(self.outdir),
                   "--no-live"]
            if self.poc_drafter_model:
                cmd += ["--poc-drafter-model", self.poc_drafter_model]
            if self.poc_critic_model:
                cmd += ["--poc-critic-model", self.poc_critic_model]
            if self.poc_compile_rounds:
                cmd += ["--poc-compile-rounds", str(self.poc_compile_rounds)]
            if not self.overwrite:
                cmd += ["--poc-keep-existing"]

            self.state = "running"
            self.message = "generating PoC packages…"
            self._proc = subprocess.Popen(
                cmd, cwd=str(_REPO_ROOT), env=dict(os.environ),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._proc.wait()
            self.returncode = self._proc.returncode
            self.finished = time.time()
            after = self.poc_count()
            if self.returncode == 0:
                self.state = "done"
                self.message = (f"{after} PoC package(s)"
                                + (f" (+{after - before} new)" if after > before else ""))
            elif self.state == "interrupted":
                self.message = "cancelled"
            else:
                self.state = "failed"
                # --poc-only exits 1 when it produced nothing; the reason is in
                # the run's own run.log, which the progress panel is showing.
                self.message = ("no packages were generated — see the log above"
                                if self.returncode == 1
                                else f"exit code {self.returncode}")
        except Exception as e:
            self.state = "failed"
            self.message = str(e)
            self.finished = time.time()


def start_poc_job(run_id: str, drafter_model: str | None = None,
                  critic_model: str | None = None,
                  compile_rounds: int = 0, overwrite: bool = True) -> PocJob:
    parts = [p for p in run_id.replace("\\", "/").split("/")
             if p and p not in ("..", ".")]
    if len(parts) != 2:
        raise ValueError("run id must be '<library>/<timestamp>'")
    run_dir = (RUNS_DIR / parts[0] / parts[1]).resolve()
    if RUNS_DIR.resolve() not in run_dir.parents or not run_dir.is_dir():
        raise ValueError("unknown run")
    if not (run_dir / "report.json").is_file():
        raise ValueError("this run has no report.json — nothing to generate from")
    preflight_poc_models(drafter_model, critic_model)
    if not isinstance(compile_rounds, int) or compile_rounds < 0:
        raise ValueError("PoC compile rounds must be a non-negative integer")
    if compile_rounds > MAX_POC_COMPILE_ROUNDS:
        raise ValueError(f"PoC compile rounds must be at most {MAX_POC_COMPILE_ROUNDS}")

    job = PocJob(f"{parts[0]}/{parts[1]}", drafter_model or None,
                 critic_model or None, compile_rounds, overwrite)
    with _LOCK:
        _JOBS[job.id] = job
    threading.Thread(target=job.run, daemon=True).start()
    return job


def get_job(job_id: str) -> Job | None:
    with _LOCK:
        return _JOBS.get(job_id)


def active_jobs() -> list[dict]:
    with _LOCK:
        return [j.to_dict() for j in _JOBS.values()
                if j.state in ("queued", "preparing", "running")]


def clear_workspaces() -> dict:
    """Delete cached clones/uploads in web/workspaces/, skipping any an active
    scan is still reading from. Returns {'dirs': n, 'freed_mb': x}."""
    if not WORKSPACES.is_dir():
        return {"dirs": 0, "freed_mb": 0.0}
    # Paths an in-flight job still needs (its cloned/uploaded target).
    with _LOCK:
        in_use = {j.target for j in _JOBS.values()
                  if j.state in ("queued", "preparing", "running") and j.target}
    removed, freed = 0, 0
    for d in WORKSPACES.iterdir():
        if not d.is_dir() or str(d.resolve()) in {str(Path(p).resolve()) for p in in_use}:
            continue
        try:
            freed += sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
        except OSError:
            pass
    return {"dirs": removed, "freed_mb": round(freed / 1_048_576, 1)}
