from __future__ import annotations

import abc
import logging
import shutil
import subprocess
from pathlib import Path

from core import AssessmentResult, Finding, LLMClient

log = logging.getLogger("pqc")


class Agent(abc.ABC):
    required_tools: tuple[str, ...] = ()

    def __init__(self, llm: LLMClient, workdir: Path):
        self.llm = llm
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)

    @property
    def name(self) -> str:
        return type(self).__name__

    def available_tools(self) -> dict[str, bool]:
        return {t: shutil.which(t) is not None for t in self.required_tools}

    def missing_tools(self) -> list[str]:
        return [t for t, ok in self.available_tools().items() if not ok]

    @abc.abstractmethod
    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        pass

    def sh(self, cmd: list[str], cwd: Path | None = None,
           timeout: int = 600, check: bool = False) -> subprocess.CompletedProcess:
        log.debug("exec: %s", " ".join(cmd))
        try:
            return subprocess.run(
                cmd, cwd=str(cwd) if cwd else None,
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout, check=check,
            )
        except subprocess.TimeoutExpired as e:
            log.warning("%s timed out after %ss", cmd[0], timeout)
            return subprocess.CompletedProcess(cmd, 124, e.stdout or "", e.stderr or "")
        except FileNotFoundError:
            log.warning("tool not found: %s", cmd[0])
            return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]} not installed")

    def save_artifact(self, name: str, content: str | bytes) -> Path:
        path = self.workdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as f:
            f.write(content)
        log.info("saved artifact: %s", path)
        return path
