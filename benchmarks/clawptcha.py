#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""Clawptcha solver — breaks prime-factorization reverse CAPTCHA without any AI.

Target: https://verify.clawptcha.com
Protocol: GET /challenge → {id, question, product, hint}
          POST /verify   → {id, factors: "p1,p2,..."}
Solver:   Trial division on small integers — instant.
"""

import json
import logging
import sys
import time

import requests

logger = logging.getLogger(__name__)

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


# ── Offline mode: self-generated challenge ──────────────────────────────────

_OFFLINE_CHALLENGE = {
    "id": "offline-demo-0001",
    "question": "Find the prime factors of 301",
    "product": 301,
    "hint": 'Return as comma-separated numbers (e.g., "3,7")',
}


def solve_offline() -> dict:
    """Generate and solve a representative challenge locally."""
    t0 = time.perf_counter()
    challenge = _OFFLINE_CHALLENGE
    product = challenge["product"]
    factors = factorize(product)
    answer = ",".join(str(f) for f in factors)
    elapsed = time.perf_counter() - t0

    # Verify locally: product of factors must equal original
    recomputed = 1
    for f in factors:
        recomputed *= f
    passed = recomputed == product

    return {
        "name": "Clawptcha",
        "passed": passed,
        "elapsed": elapsed,
        "detail": f"product={product}, factors={answer}",
        "method": "trial-division factorization",
    }


# ── Live mode: hit the real API ─────────────────────────────────────────────

_BASE_URL = "https://verify.clawptcha.com"


def solve_live() -> dict:
    """Fetch a live challenge from verify.clawptcha.com and solve it."""
    t0 = time.perf_counter()

    # Use a session to preserve cookies/connection state (Cloudflare may
    # require them for challenge-to-verify continuity).
    session = requests.Session()
    resp = session.get(f"{_BASE_URL}/challenge", timeout=5)
    resp.raise_for_status()
    challenge = resp.json()

    product = challenge["product"]
    challenge_id = challenge["id"]
    factors = factorize(product)
    answer = ",".join(str(f) for f in factors)

    # POST the answer immediately — challenges expire very quickly.
    # The API returns 404 with JSON body when a challenge has expired,
    # so we don't raise_for_status but parse the JSON instead.
    verify_resp = session.post(
        f"{_BASE_URL}/verify",
        json={"id": challenge_id, "factors": answer},
        timeout=5,
    )
    result = verify_resp.json()
    elapsed = time.perf_counter() - t0

    passed = result.get("success", False)
    error = result.get("error", "")
    detail = f"product={product}, factors={answer}"
    if error:
        detail += f", api_error={error}"

    return {
        "name": "Clawptcha",
        "passed": passed,
        "elapsed": elapsed,
        "detail": detail,
        "method": "trial-division factorization",
    }


def solve(*, live: bool = False) -> dict:
    """Entry point used by run_all.py."""
    return solve_live() if live else solve_offline()


# ── Standalone execution ────────────────────────────────────────────────────

_GREEN = "\033[32m"
_RED = "\033[31m"
_RESET = "\033[0m"


def main() -> None:
    live = "--live" in sys.argv
    use_json = "--json" in sys.argv

    result = solve(live=live)

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
