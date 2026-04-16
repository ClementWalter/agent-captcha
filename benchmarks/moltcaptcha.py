#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""MoltCaptcha SMHL solver — breaks Semantic-Mathematical Hybrid Lock without AI.

Target: MoltCaptcha (https://github.com/MoltCaptcha/MoltCaptcha)
Protocol: Local challenge — not a hosted API.
Challenge: creative format + topic + target ASCII sum of first letters + word count.
Solver:   Brute-force letter combination + filler word bank — instant.

The SMHL "haiku" (or any format) doesn't need to make semantic sense.
Verification only checks two numerical constraints:
  1. ASCII sum of each word's first letter == target
  2. Total word count == target
"""

import itertools
import json
import logging
import random
import sys
import time

logger = logging.getLogger(__name__)

# ── Word bank indexed by first letter ───────────────────────────────────────
# Why: we just need words starting with a specific letter — meaning is irrelevant
# since MoltCaptcha only checks numerical constraints.

_WORDS: dict[str, list[str]] = {
    "a": ["apple", "anchor", "atom"],
    "b": ["banana", "bridge", "byte"],
    "c": ["cherry", "cipher", "craft"],
    "d": ["delta", "drift", "dune"],
    "e": ["ember", "epoch", "edge"],
    "f": ["flame", "frost", "forge"],
    "g": ["grain", "grove", "gate"],
    "h": ["haven", "haze", "helm"],
    "i": ["ivory", "iron", "ink"],
    "j": ["jade", "jet", "jolt"],
    "k": ["knot", "keen", "kite"],
    "l": ["leaf", "loom", "lark"],
    "m": ["maple", "mist", "moth"],
    "n": ["neon", "node", "nest"],
    "o": ["orbit", "opal", "oak"],
    "p": ["prism", "pulse", "pine"],
    "q": ["quill", "quartz", "quest"],
    "r": ["reed", "rust", "rift"],
    "s": ["stone", "spark", "sage"],
    "t": ["thorn", "tide", "trace"],
    "u": ["umbra", "unit", "urn"],
    "v": ["vine", "void", "vault"],
    "w": ["wave", "wren", "wind"],
    "x": ["xenon", "xerox", "xray"],
    "y": ["yarn", "yew", "yoke"],
    "z": ["zinc", "zone", "zeal"],
}

# All printable ASCII letters for brute-force
_LETTERS = [chr(c) for c in range(ord("a"), ord("z") + 1)]


# ── Solver ──────────────────────────────────────────────────────────────────


def _find_letters(target_ascii_sum: int, count: int) -> list[str] | None:
    """Find `count` lowercase letters whose ASCII values sum to target.

    Why brute-force works: for a 3-line haiku, 26^3 = 17,576 combinations,
    which is effectively instant.
    """
    for combo in itertools.product(_LETTERS, repeat=count):
        if sum(ord(c) for c in combo) == target_ascii_sum:
            return list(combo)
    return None


def _build_line(first_letter: str, word_count: int) -> str:
    """Build a line of `word_count` words, all starting with `first_letter`."""
    words = _WORDS.get(first_letter, [f"{first_letter}word"])
    # Why: cycle through available words to fill the line
    return " ".join(words[i % len(words)] for i in range(word_count))


def solve_smhl(
    target_ascii_sum: int, target_words: int, lines: int
) -> tuple[str, bool]:
    """Solve an SMHL challenge deterministically.

    Returns (poem_text, verification_passed).
    """
    letters = _find_letters(target_ascii_sum, lines)
    if letters is None:
        return "", False

    # Distribute words across lines: floor division + remainder to first lines
    base = target_words // lines
    remainder = target_words % lines
    line_words = [base + (1 if i < remainder else 0) for i in range(lines)]

    poem_lines = [_build_line(letters[i], line_words[i]) for i in range(lines)]
    poem = "\n".join(poem_lines)

    # Verify constraints
    all_words = poem.split()
    actual_ascii_sum = sum(ord(line.split()[0][0]) for line in poem_lines)
    passed = actual_ascii_sum == target_ascii_sum and len(all_words) == target_words

    return poem, passed


# ── Challenge generation (replicates MoltCaptcha's generator) ───────────────


def _generate_challenge(
    rng: random.Random | None = None,
) -> dict:
    """Generate a representative SMHL challenge matching MoltCaptcha's format."""
    if rng is None:
        rng = random.Random(42)  # noqa: S311 — deterministic for benchmarks

    lines = 3  # haiku format
    target_words = rng.randint(8, 15)
    # Why: ASCII 'a'=97...'z'=122, so 3 letters sum to 291..366
    target_ascii_sum = rng.randint(97 * lines, 122 * lines)

    return {
        "format": "HAIKU",
        "topic": "autumn",
        "target_ascii_sum": target_ascii_sum,
        "target_words": target_words,
        "lines": lines,
        "time_limit": 20,
    }


# ── Entry point ─────────────────────────────────────────────────────────────


def solve(*, live: bool = False) -> dict:
    """Entry point used by run_all.py.

    MoltCaptcha is not a hosted API, so live and offline are the same:
    we generate a challenge locally and solve it.
    """
    t0 = time.perf_counter()

    challenge = _generate_challenge()
    poem, passed = solve_smhl(
        target_ascii_sum=challenge["target_ascii_sum"],
        target_words=challenge["target_words"],
        lines=challenge["lines"],
    )
    elapsed = time.perf_counter() - t0

    return {
        "name": "MoltCaptcha",
        "passed": passed,
        "elapsed": elapsed,
        "detail": (
            f"ascii_sum={challenge['target_ascii_sum']},"
            f" words={challenge['target_words']},"
            f" no LLM used"
        ),
        "method": "letter-picker + word filler",
    }


# ── Standalone execution ────────────────────────────────────────────────────

_GREEN = "\033[32m"
_RED = "\033[31m"
_RESET = "\033[0m"


def main() -> None:
    use_json = "--json" in sys.argv

    result = solve()

    if use_json:
        print(json.dumps(result, indent=2))  # noqa: T201
    else:
        status = f"{_GREEN}PASS{_RESET}" if result["passed"] else f"{_RED}FAIL{_RESET}"
        print(  # noqa: T201
            f"MoltCaptcha ........ {status}"
            f" ({result['detail']}, {result['elapsed']:.4f}s)"
        )


if __name__ == "__main__":
    main()
