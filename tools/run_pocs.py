#!/usr/bin/env python3
"""
tools/run_pocs.py — Batch PoC runner for the PQC vulnerability assessor.

Usage:
    run_pocs.py <run_dir> [--poc <FND-id>] [--unit-harness] [--cc <compiler>]

Iterates every poc/<FND-id>/ directory under <run_dir>, calls run_poc.sh for
each, aggregates result.json files, and prints a markdown summary table.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def find_run_poc_sh() -> Path:
    """Locate run_poc.sh relative to this script."""
    here = Path(__file__).resolve().parent
    candidate = here / "run_poc.sh"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"run_poc.sh not found at {candidate}")


def find_poc_dirs(run_dir: Path, only_id: str | None = None) -> list[Path]:
    poc_root = run_dir / "poc"
    if not poc_root.is_dir():
        sys.exit(f"ERROR: no poc/ directory under {run_dir}")
    dirs = sorted(p for p in poc_root.iterdir() if p.is_dir())
    if only_id:
        dirs = [d for d in dirs if d.name == only_id]
        if not dirs:
            sys.exit(f"ERROR: PoC '{only_id}' not found under {poc_root}")
    return dirs


def run_poc(run_poc_sh: Path, poc_dir: Path, unit_harness: bool, cc: str | None) -> dict:
    cmd = ["bash", str(run_poc_sh), str(poc_dir)]
    if unit_harness:
        cmd.append("--unit-harness")
    env = os.environ.copy()
    if cc:
        env["CC"] = cc

    print(f"\n{'='*70}")
    print(f"Running: {poc_dir.name}")
    print(f"{'='*70}")

    result = subprocess.run(cmd, env=env)
    if result.returncode not in (0, 1):
        print(f"WARNING: run_poc.sh exited with code {result.returncode}")

    result_json = poc_dir / "result.json"
    if result_json.exists():
        try:
            with open(result_json) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"WARNING: could not parse result.json: {e}")

    return {
        "finding_id": poc_dir.name,
        "library": "?",
        "bug_class": "?",
        "location": "?",
        "build_status": "?",
        "run_verdict": "ERROR",
        "notes": f"result.json missing or malformed after run",
    }


def print_table(results: list[dict]) -> None:
    header = f"{'FND-id':<20} {'Library':<12} {'Bug class':<15} {'Build':<8} {'Verdict':<16} Notes"
    print(f"\n{'='*len(header)}")
    print("PoC Run Summary")
    print(f"{'='*len(header)}")
    print(f"| {'FND-id':<20} | {'Library':<12} | {'Bug class':<15} | {'Build':<8} | {'Verdict':<16} | Notes |")
    print(f"| {'-'*20} | {'-'*12} | {'-'*15} | {'-'*8} | {'-'*16} | ----- |")
    for r in results:
        fid      = r.get("finding_id", "?")[:20]
        lib      = r.get("library", "?")[:12]
        bc       = r.get("bug_class", "?")[:15]
        build    = r.get("build_status", "?")[:8]
        verdict  = r.get("run_verdict", "?")[:16]
        notes    = (r.get("notes", "") or "")[:60]
        print(f"| {fid:<20} | {lib:<12} | {bc:<15} | {build:<8} | {verdict:<16} | {notes} |")
    print()

    # Counts
    demonstrated = sum(1 for r in results if r.get("run_verdict") == "DEMONSTRATED")
    not_reached  = sum(1 for r in results if r.get("run_verdict") == "NOT_REACHED")
    build_failed = sum(1 for r in results if r.get("run_verdict") == "BUILD_FAILED")
    false_pos    = sum(1 for r in results if r.get("run_verdict") == "FALSE_POSITIVE")
    print(f"Total: {len(results)}  DEMONSTRATED={demonstrated}  NOT_REACHED={not_reached}  "
          f"BUILD_FAILED={build_failed}  FALSE_POSITIVE={false_pos}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch PoC runner")
    ap.add_argument("run_dir", help="Path to run directory (e.g. runs/wolfssl_local_v4)")
    ap.add_argument("--poc", metavar="FND-id", help="Run only this PoC")
    ap.add_argument("--unit-harness", action="store_true", help="Pass --unit-harness to each run")
    ap.add_argument("--cc", metavar="compiler", help="Override CC (e.g. gcc)")
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.is_dir():
        sys.exit(f"ERROR: run directory not found: {run_dir}")

    run_poc_sh = find_run_poc_sh()
    poc_dirs = find_poc_dirs(run_dir, args.poc)

    print(f"Found {len(poc_dirs)} PoC(s) under {run_dir / 'poc'}")

    results = []
    for poc_dir in poc_dirs:
        r = run_poc(run_poc_sh, poc_dir, args.unit_harness, args.cc)
        results.append(r)

    print_table(results)

    # Write aggregated JSON
    agg_path = run_dir / "poc_results.json"
    with open(agg_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Aggregated results written to {agg_path}")


if __name__ == "__main__":
    main()
