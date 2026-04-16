#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Runner for all reverse-CAPTCHA benchmark solvers.

Executes each solver and prints a summary table proving that every deployed
reverse CAPTCHA can be broken by a deterministic script with zero AI.

Usage:
    uv run benchmarks/run_all.py          # run all solvers
    uv run benchmarks/run_all.py --json   # output as JSON
"""

import importlib.util
import json
import logging
import sys
import traceback
from pathlib import Path

logger = logging.getLogger(__name__)

# Why importlib: uv run executes scripts in isolation, so `benchmarks` isn't
# on sys.path. We load each solver from its file path instead.
_BENCH_DIR = Path(__file__).resolve().parent


def _load_solver(filename: str):
    """Load a solver module from the benchmarks directory by filename."""
    filepath = _BENCH_DIR / filename
    spec = importlib.util.spec_from_file_location(filepath.stem, filepath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.solve


solve_clawptcha = _load_solver("clawptcha.py")
solve_moltcaptcha = _load_solver("moltcaptcha.py")
solve_botcha = _load_solver("botcha.py")
solve_logscore = _load_solver("logscore_botcha.py")

# ── ANSI colors ─────────────────────────────────────────────────────────────

_GREEN = "\033[32m"
_RED = "\033[31m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

# ── Solver registry ─────────────────────────────────────────────────────────

_SOLVERS = [
    ("Clawptcha", solve_clawptcha),
    ("MoltCaptcha", solve_moltcaptcha),
    ("BOTCHA", solve_botcha),
    ("Logscore BOTCHA", solve_logscore),
]

_LABELS = {
    "Clawptcha": ("Clawptcha", "trial-division factorization"),
    "MoltCaptcha": ("MoltCaptcha", "letter-picker + word filler"),
    "BOTCHA": ("BOTCHA", "regex parser + byte ops"),
    "Logscore BOTCHA": ("Logscore BOTCHA", "state machine"),
}


def run_all() -> list[dict]:
    """Run all solvers and return results."""
    results = []
    for name, solver in _SOLVERS:
        try:
            result = solver()
        except Exception:
            logger.exception("Solver %s failed", name)
            result = {
                "name": name,
                "passed": False,
                "elapsed": 0.0,
                "detail": f"ERROR: {traceback.format_exc().splitlines()[-1]}",
                "method": _LABELS[name][1],
            }
        results.append(result)
    return results


def _print_table(results: list[dict]) -> None:
    """Print the screenshot-ready summary table."""
    width = 60
    print(f"\n{_BOLD}{'=' * width}{_RESET}")  # noqa: T201
    print(f"{_BOLD}  Breaking Reverse CAPTCHAs — No LLM Required{_RESET}")  # noqa: T201
    print(f"{_BOLD}{'=' * width}{_RESET}")  # noqa: T201
    print()  # noqa: T201

    passed_count = 0
    for result in results:
        name = result["name"]
        label, method = _LABELS.get(name, (name, ""))
        # Pad label to align status column
        padded = f"  {label} {'.' * (20 - len(label))} "

        if result["passed"]:
            status = f"{_GREEN}PASS{_RESET}"
            passed_count += 1
        else:
            status = f"{_RED}FAIL{_RESET}"

        elapsed = f"({result['elapsed']:.2f}s)"
        print(f"{padded}{status}   {elapsed}  {_DIM}{method}{_RESET}")  # noqa: T201

    total = len(results)
    print()  # noqa: T201
    print(f"{'-' * width}")  # noqa: T201
    print(  # noqa: T201
        f"  {_BOLD}{passed_count}/{total} passed."
        f" 0 LLMs used. 0 reasoning required.{_RESET}"
    )
    print(f"{'-' * width}")  # noqa: T201
    print()  # noqa: T201
    print(f"  {_DIM}These systems prove \"automated\", not \"agent.\"{_RESET}")  # noqa: T201
    print(f"  {_DIM}A script is not an agent.{_RESET}")  # noqa: T201
    print()  # noqa: T201
    print(f"  Try {_BOLD}agentcaptcha.chat{_RESET} — you'll need a GPU and a real model.")  # noqa: T201
    print(f"{'=' * width}\n")  # noqa: T201


def main() -> None:
    use_json = "--json" in sys.argv

    results = run_all()

    if use_json:
        print(json.dumps(results, indent=2))  # noqa: T201
    else:
        _print_table(results)

    # Exit non-zero if any solver failed
    if not all(r["passed"] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
