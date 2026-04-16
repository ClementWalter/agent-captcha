#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Clawptcha solver — breaks prime-factorization reverse CAPTCHA without any AI.

Target: https://verify.clawptcha.com
Protocol: GET /challenge → {id, question, product, hint}
          POST /verify   → {challengeId, answer}  (within 5 s)
Solver:   Trial division on small integers — instant.
"""

import json
import logging
import sys
import time

import requests

logger = logging.getLogger(__name__)

_BASE_URL = "https://verify.clawptcha.com"


# ── Solver ──────────────────────────────────────────────────────────────────


def factorize(n: int) -> list[int]:
    """Trial division — products are small enough that this is instant."""
    factors: list[int] = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def solve() -> dict:
    """Fetch a live challenge from verify.clawptcha.com and solve it."""
    t0 = time.perf_counter()

    resp = requests.get(f"{_BASE_URL}/challenge", timeout=5)
    resp.raise_for_status()
    challenge = resp.json()

    product = challenge["product"]
    challenge_id = challenge["id"]
    factors = factorize(product)
    answer = ",".join(str(f) for f in factors)

    # Why challengeId + answer: the API docs specify these field names,
    # not the "id"/"factors" names returned in the challenge response.
    verify_resp = requests.post(
        f"{_BASE_URL}/verify",
        json={"challengeId": challenge_id, "answer": answer},
        timeout=5,
    )
    result = verify_resp.json()
    elapsed = time.perf_counter() - t0

    passed = result.get("success", False)
    solve_time = result.get("solveTimeMs", "")
    detail = f"product={product}, factors={answer}"
    if solve_time:
        detail += f", server_ms={solve_time}"

    return {
        "name": "Clawptcha",
        "passed": passed,
        "elapsed": elapsed,
        "detail": detail,
        "method": "trial-division factorization",
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
            f"Clawptcha .......... {status}"
            f" ({result['detail']}, {result['elapsed']:.2f}s)"
        )


if __name__ == "__main__":
    main()
