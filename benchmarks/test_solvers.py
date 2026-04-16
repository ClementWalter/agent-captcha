#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest", "requests"]
# ///
"""Unit tests for reverse-CAPTCHA benchmark solvers.

Each test covers a single assertion per the project's testing guidelines.
Tests verify solver correctness without hitting live APIs.
"""

import pytest

# ── Clawptcha factorization ─────────────────────────────────────────────────


@pytest.fixture()
def factorize():
    """Import the factorize function from clawptcha solver."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "clawptcha", Path(__file__).parent / "clawptcha.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.factorize


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (2, [2]),
        (6, [2, 3]),
        (12, [2, 2, 3]),
        (301, [7, 43]),
        (1457, [31, 47]),
        (97, [97]),  # prime
        (1, []),
        (100, [2, 2, 5, 5]),
    ],
    ids=["prime_2", "6=2x3", "12=2x2x3", "301=7x43", "1457=31x47", "prime_97", "one", "100"],
)
def test_factorize(factorize, n, expected):
    assert factorize(n) == expected


def test_clawptcha_offline_passes():
    """Clawptcha offline solver reports PASS."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "clawptcha", Path(__file__).parent / "clawptcha.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    result = mod.solve(live=False)
    assert result["passed"] is True


# ── MoltCaptcha SMHL ────────────────────────────────────────────────────────


@pytest.fixture()
def smhl_solver():
    """Import the MoltCaptcha solver module."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "moltcaptcha", Path(__file__).parent / "moltcaptcha.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_smhl_finds_letters(smhl_solver):
    """Letter finder returns letters whose ASCII sums match the target."""
    # 3 letters summing to 300: e.g. 'a'(97) + 'b'(98) + 'i'(105) = 300
    letters = smhl_solver._find_letters(300, 3)
    assert sum(ord(c) for c in letters) == 300


def test_smhl_finds_correct_count(smhl_solver):
    """Letter finder returns exactly the requested number of letters."""
    letters = smhl_solver._find_letters(300, 3)
    assert len(letters) == 3


def test_smhl_solve_passes(smhl_solver):
    """SMHL solver produces a valid poem passing both constraints."""
    poem, passed = smhl_solver.solve_smhl(300, 10, 3)
    assert passed is True


def test_smhl_word_count(smhl_solver):
    """SMHL solution has the exact target word count."""
    poem, _ = smhl_solver.solve_smhl(300, 10, 3)
    assert len(poem.split()) == 10


def test_smhl_ascii_sum(smhl_solver):
    """SMHL solution has the correct ASCII sum of first letters."""
    poem, _ = smhl_solver.solve_smhl(300, 10, 3)
    lines = poem.strip().splitlines()
    actual_sum = sum(ord(line.split()[0][0]) for line in lines)
    assert actual_sum == 300


def test_moltcaptcha_offline_passes():
    """MoltCaptcha offline solver reports PASS."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "moltcaptcha", Path(__file__).parent / "moltcaptcha.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    result = mod.solve(live=False)
    assert result["passed"] is True


# ── BOTCHA byte ops ─────────────────────────────────────────────────────────


@pytest.fixture()
def botcha():
    """Import the BOTCHA solver module."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "botcha", Path(__file__).parent / "botcha.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_parse_num_decimal(botcha):
    assert botcha._parse_num("42") == 42


def test_parse_num_hex(botcha):
    assert botcha._parse_num("0xFF") == 255


def test_parse_num_word(botcha):
    assert botcha._parse_num("eight") == 8


def test_parse_range_python_slice(botcha):
    assert botcha._parse_range("data[10:20]") == (10, 20)


def test_parse_range_rust_inclusive(botcha):
    assert botcha._parse_range("data[10..=20]") == (10, 21)


def test_parse_range_bracket_exclusive(botcha):
    assert botcha._parse_range("bytes in [10, 20)") == (10, 20)


def test_parse_range_bracket_inclusive(botcha):
    assert botcha._parse_range("bytes in [10, 20] (inclusive)") == (10, 21)


def test_parse_range_covering_inclusive(botcha):
    assert botcha._parse_range("covering bytes 174 to 217 inclusive") == (174, 218)


def test_botcha_offline_passes(botcha):
    """BOTCHA offline solver produces a valid SHA-256 hex string."""
    result = botcha.solve(live=False)
    assert result["passed"] is True


def test_botcha_solve_challenge_returns_hex(botcha):
    """solve_challenge returns a 64-char hex string."""
    import base64

    data_b64 = base64.b64encode(bytes(range(256))).decode()
    instructions = [
        "Compute SHA-256 over the slice in the range [10, 42] (inclusive). Return the leading 8 bytes of the hash output.",
        "Concatenate the raw byte results from all 1 steps in order, and return the SHA-256 hex digest of the concatenated bytes.",
    ]
    answer, _, _ = botcha.solve_challenge(data_b64, "nonce", instructions)
    assert len(answer) == 64


def test_botcha_skip_detection(botcha):
    assert botcha._is_skip("Skip this step. No computation needed.") is True


def test_botcha_noop_detection(botcha):
    assert botcha._is_skip("No-op: disregard this step completely.") is True


def test_botcha_decoy_detection(botcha):
    assert botcha._is_skip("This is a decoy operation. Pass through.") is True


def test_botcha_final_merge_detection(botcha):
    assert botcha._is_final_merge(
        "Concatenate the raw byte results and return the SHA-256 hex digest."
    ) is True


# ── Logscore BOTCHA ─────────────────────────────────────────────────────────


@pytest.fixture()
def logscore():
    """Import the logscore_botcha solver module."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "logscore_botcha", Path(__file__).parent / "logscore_botcha.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_custody_retrieve(logscore):
    """Retrieving an object transfers possession to the person."""
    narrative = "Event 1: Morgan retrieved the silver locket from the chest."
    assert logscore.solve_custody_chain(narrative) == "Morgan"


def test_custody_give(logscore):
    """Giving an object transfers possession to the recipient."""
    narrative = (
        "Event 1: Morgan retrieved the silver locket from the chest.\n"
        "Event 2: Morgan gave the silver locket to Quinn."
    )
    assert logscore.solve_custody_chain(narrative) == "Quinn"


def test_custody_place_releases(logscore):
    """Placing an object in a container releases possession."""
    narrative = (
        "Event 1: Morgan retrieved the silver locket from the chest.\n"
        "Event 2: Morgan placed the silver locket in a safe."
    )
    assert logscore.solve_custody_chain(narrative) is None


def test_logscore_offline_passes(logscore):
    """Logscore offline solver reports PASS."""
    result = logscore.solve(live=False)
    assert result["passed"] is True
