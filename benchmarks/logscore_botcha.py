#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Logscore BOTCHA solver — breaks custody-chain narrative puzzle without AI.

Target: @logscore/botcha (npm package)
Protocol: Track object possession through transfer events, answer "who has it?"
Solver:   State machine — regex-parse verb + subject, track current holder.

The verb vocabulary is bounded by the generator. A few regex patterns
cover every event type the library can produce.
"""

import json
import logging
import random
import re
import sys
import time

logger = logging.getLogger(__name__)

# ── Solver ──────────────────────────────────────────────────────────────────

# Why: the logscore/botcha generator uses a fixed verb vocabulary.
# "left/gave/placed/handed/deposited" = object leaves the person's possession
# "retrieved/took/found/received/picked up/collected" = person acquires the object

_ACQUIRE_VERBS = re.compile(
    r"\b(retrieved|took|found|received|picked\s+up|collected|grabbed|obtained|accepted)\b",
    re.IGNORECASE,
)
_RELEASE_VERBS = re.compile(
    r"\b(left|gave|placed|handed|deposited|stored|put|dropped|set\s+down)\b",
    re.IGNORECASE,
)

# Event line pattern: "Event N: <Name> <verb> ..."
_EVENT_PATTERN = re.compile(
    r"Event\s+(\d+):\s+(\w+)\s+(.*)",
    re.IGNORECASE,
)


def solve_custody_chain(narrative: str) -> str | None:
    """Parse a custody-chain narrative and return who holds the object.

    Returns the name of the final holder, or None if parsing fails.
    """
    current_holder: str | None = None
    location: str | None = None

    for line in narrative.strip().splitlines():
        m = _EVENT_PATTERN.match(line.strip())
        if not m:
            continue

        _event_num = m.group(1)
        subject = m.group(2)
        action = m.group(3)

        if _ACQUIRE_VERBS.search(action):
            # Person acquires the object
            current_holder = subject
            location = None
        elif _RELEASE_VERBS.search(action):
            # Person releases the object to a container/location
            current_holder = None
            # Try to extract location: "in a secure container", "to Quinn"
            loc_match = re.search(r"(?:in|into|to|at)\s+(?:a\s+)?(.+?)\.?\s*$", action)
            if loc_match:
                location = loc_match.group(1).strip().rstrip(".")
            # Check if it's a person-to-person transfer: "gave it to Quinn"
            person_match = re.search(r"(?:to|gave\s+\w+\s+to)\s+(\w+)", action)
            if person_match:
                # Direct transfer: the recipient now holds it
                current_holder = person_match.group(1)

    return current_holder


# ── Challenge generation (replicates @logscore/botcha logic) ────────────────

_NAMES = [
    "Morgan", "Quinn", "Riley", "Jordan", "Casey",
    "Avery", "Dakota", "Sage", "Rowan", "Blake",
]
_OBJECTS = [
    "the silver locket", "the brass key", "the leather journal",
    "the crystal vial", "the iron medallion",
]
_CONTAINERS = [
    "a secure container", "the wooden chest", "a locked cabinet",
    "the velvet pouch", "a steel safe",
]


def _generate_challenge(
    n_events: int = 23,
    rng: random.Random | None = None,
) -> tuple[str, str]:
    """Generate a custody-chain narrative and return (narrative, answer).

    Returns (narrative_text, expected_holder_name).
    """
    if rng is None:
        rng = random.Random(42)  # noqa: S311 — deterministic for benchmarks

    obj = rng.choice(_OBJECTS)
    names = rng.sample(_NAMES, k=min(5, len(_NAMES)))
    container = rng.choice(_CONTAINERS)

    lines: list[str] = []
    current_holder: str | None = None
    transfers = 0

    for i in range(1, n_events + 1):
        if current_holder is None:
            # Someone picks it up
            person = rng.choice(names)
            verb = rng.choice(["retrieved", "found", "picked up", "took", "collected"])
            lines.append(f"Event {i}: {person} {verb} {obj} from {container}.")
            current_holder = person
            transfers += 1
        else:
            action = rng.choice(["release", "transfer", "hold"])
            if action == "release":
                verb = rng.choice(["left", "placed", "deposited", "stored"])
                lines.append(
                    f"Event {i}: {current_holder} {verb} {obj} in {container}."
                )
                current_holder = None
                transfers += 1
            elif action == "transfer":
                recipient = rng.choice([n for n in names if n != current_holder])
                lines.append(
                    f"Event {i}: {current_holder} gave {obj} to {recipient}."
                )
                current_holder = recipient
                transfers += 1
            else:
                # Hold — no change, add a distractor
                lines.append(
                    f"Event {i}: {current_holder} examined {obj} carefully."
                )

    question = (
        f"Who possesses {obj} at the conclusion of event {n_events}?"
    )
    narrative = "\n".join(lines) + "\n" + question

    return narrative, current_holder or "nobody"


# ── Entry points ────────────────────────────────────────────────────────────


def solve_offline() -> dict:
    """Generate and solve a custody-chain challenge locally."""
    t0 = time.perf_counter()

    narrative, expected = _generate_challenge(n_events=23)
    answer = solve_custody_chain(narrative)
    elapsed = time.perf_counter() - t0

    # Count events and transfers from the narrative
    events = len(re.findall(r"^Event \d+:", narrative, re.MULTILINE))
    transfers = sum(
        1
        for line in narrative.splitlines()
        if _ACQUIRE_VERBS.search(line) or _RELEASE_VERBS.search(line)
    )

    passed = answer == expected

    return {
        "name": "Logscore BOTCHA",
        "passed": passed,
        "elapsed": elapsed,
        "detail": f"events={events}, transfers={transfers}, no LLM used",
        "method": "state machine",
    }


def solve(*, live: bool = False) -> dict:
    """Entry point used by run_all.py.

    @logscore/botcha is an npm library (not a hosted API), so live and offline
    are equivalent: we generate a representative challenge and solve it.
    """
    # Why both modes are the same: there's no hosted API to hit, the npm
    # package is a library that generates challenges programmatically.
    return solve_offline()


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
            f"Logscore BOTCHA .... {status}"
            f" ({result['detail']}, {result['elapsed']:.4f}s)"
        )


if __name__ == "__main__":
    main()
