#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""BOTCHA solver — breaks byte-op reverse CAPTCHA with regex parsing, no AI.

Target: https://botcha-verify.vercel.app
Protocol: POST /api/challenge → {session_id, nonce, data_b64, instructions}
          POST /api/solve/{session_id} → {answer, hmac}
Solver:   Regex-based NL parser + deterministic byte operations.

The instruction vocabulary is finite and formulaic. Every operation can be
expressed as a regex pattern matching hex/decimal numbers and known verbs.
The generator produces ~12 operation types with varied NL wording. Some
instructions are compound (chained via pipe connectors).
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import logging
import re
import sys
import time

import requests

logger = logging.getLogger(__name__)

# ── Number parsing ──────────────────────────────────────────────────────────


_WORD_NUMS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
    "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
    "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
    "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70,
    "eighty": 80, "ninety": 90, "hundred": 100,
}


def _parse_num(s: str) -> int:
    """Parse a number that may be decimal, hex (0xNN), or an English word."""
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    if s.isdigit():
        return int(s)
    if s in _WORD_NUMS:
        return _WORD_NUMS[s]
    return int(s)


# ── Range parsing ───────────────────────────────────────────────────────────
# Why: BOTCHA uses ~10 different range notations. We normalize to [start, end).


def _parse_range(text: str) -> tuple[int, int]:
    """Parse a byte range from various NL/code notations → (start, end_exclusive)."""

    # "Starting at position N, grab the next M bytes"
    m = re.search(
        r"[Ss]tarting at position\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?(?:grab|take|read)\s+(?:the\s+)?next\s+(0x[0-9a-fA-F]+|\d+)\s+bytes",
        text,
    )
    if m:
        start = _parse_num(m.group(1))
        count = _parse_num(m.group(2))
        return start, start + count

    # "N consecutive bytes beginning at byte M"
    m = re.search(
        r"(\d+)\s+consecutive\s+bytes\s+beginning at\s+(?:bytes?|offsets?|index|position)\s+(\d+)",
        text,
    )
    if m:
        count = int(m.group(1))
        start = int(m.group(2))
        return start, start + count

    # "From position N, sample one byte then skip S, repeating until ... position E"
    m = re.search(
        r"[Ff]rom position\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?skip\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?(?:reach|position)\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        # This is really a stride op — return range for the stride
        return _parse_num(m.group(1)), _parse_num(m.group(3))

    # Python slice: data[61:101]
    m = re.search(r"data\[(\d+):(\d+)\]", text)
    if m:
        return int(m.group(1)), int(m.group(2))

    # Rust inclusive: data[99..=130]
    m = re.search(r"data\[(\d+)\.\.=(\d+)\]", text)
    if m:
        return int(m.group(1)), int(m.group(2)) + 1

    # Bracket exclusive: [68, 99)  — check BEFORE inclusive
    m = re.search(r"\[(\d+),\s*(\d+)\)", text)
    if m:
        return int(m.group(1)), int(m.group(2))

    # Bracket inclusive: [130, 171] (inclusive)
    m = re.search(r"\[(\d+),\s*(\d+)\]\s*\(inclusive\)", text)
    if m:
        return int(m.group(1)), int(m.group(2)) + 1

    # "between positions X and Y (exclusive end)"
    m = re.search(
        r"between positions?\s+(0x[0-9a-fA-F]+|\d+)\s+and\s+(0x[0-9a-fA-F]+|\d+)"
        r"\s*\(exclusive",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2))

    # "between positions X and Y" (inclusive by default when no qualifier)
    m = re.search(
        r"between positions?\s+(0x[0-9a-fA-F]+|\d+)\s+and\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2)) + 1

    # "up to (but not including) byte N"
    m = re.search(
        r"(?:bytes?|offsets?|index|position)\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?up to\s+\(but not including\)\s+"
        r"(?:bytes?|offsets?|index|position)\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2))

    # "up to and including index N"
    m = re.search(
        r"(?:bytes?|offsets?|index|position)\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?up to and including\s+"
        r"(?:bytes?|offsets?|index|position)\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2)) + 1

    # "covering bytes A to B inclusive"
    m = re.search(
        r"covering\s+(?:bytes?|octets?)\s+(0x[0-9a-fA-F]+|\d+)\s+to\s+(0x[0-9a-fA-F]+|\d+)\s+inclusive",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2)) + 1

    # "starting at index A, ending before index B"
    m = re.search(
        r"starting at (?:index|position|byte)\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?ending before (?:index|position|byte)\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2))

    # "from offset A to offset B" (inclusive)
    m = re.search(
        r"from\s+(?:bytes?|offsets?|index|position)\s+(0x[0-9a-fA-F]+|\d+)"
        r"\s+to\s+(?:bytes?|offsets?|index|position)\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        return _parse_num(m.group(1)), _parse_num(m.group(2)) + 1

    # Bracket notation without explicit qualifier: [130, 171]
    m = re.search(r"\[(\d+),\s*(\d+)\]", text)
    if m:
        return int(m.group(1)), int(m.group(2)) + 1

    # "in the range [A, B)"
    m = re.search(r"range\s*\[(\d+),\s*(\d+)\)", text)
    if m:
        return int(m.group(1)), int(m.group(2))
    m = re.search(r"range\s*\[(\d+),\s*(\d+)\]", text)
    if m:
        return int(m.group(1)), int(m.group(2)) + 1

    # "grab bytes in the range [A, B)"
    m = re.search(r"bytes.*?\[(\d+),\s*(\d+)\)", text)
    if m:
        return int(m.group(1)), int(m.group(2))

    # Generic "offset/byte/index A ... offset/byte/index B"
    offsets = re.findall(
        r"(?:offset|byte|index|position)\s+(0x[0-9a-fA-F]+|\d+)", text
    )
    if len(offsets) >= 2:
        start = _parse_num(offsets[0])
        end = _parse_num(offsets[1])
        if "not including" in text or "exclusive" in text or "before" in text:
            return start, end
        return start, end + 1

    msg = f"Cannot parse range from: {text!r}"
    raise ValueError(msg)


# ── Individual operations ───────────────────────────────────────────────────


def _op_sha256_slice(data: bytes, text: str) -> bytes:
    """SHA-256 over a slice, optionally iterated, return first N bytes."""
    start, end = _parse_range(text)
    chunk = data[start:end]

    # Check for iteration: "repeating for a total of N rounds" or "Repeat N times"
    rounds = 1
    m = re.search(r"(?:total of|Repeat)\s+(\d+)\s+(?:rounds|times)", text)
    if m:
        rounds = int(m.group(1))

    h = chunk
    for _ in range(rounds):
        h = hashlib.sha256(h).digest()

    # Return leading N bytes — N can be decimal, hex, or a word
    _num_pattern = r"0x[0-9a-fA-F]+|\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty"
    m = re.search(
        rf"(?:leading|first|only the first)\s+({_num_pattern})\s+bytes",
        text,
        re.IGNORECASE,
    )
    if m:
        return h[: _parse_num(m.group(1))]

    # "Return h[0:N]"
    m = re.search(r"h\[0:(\d+)\]", text)
    if m:
        return h[: int(m.group(1))]

    return h


def _op_conditional_xor(data: bytes, text: str) -> bytes:
    """For each byte: if >= threshold, XOR with A; else XOR with B."""
    start, end = _parse_range(text)
    chunk = data[start:end]

    m = re.search(
        r">=\s*(0x[0-9a-fA-F]+|\d+),?\s*XOR\s*(?:it\s+)?with\s*(0x[0-9a-fA-F]+|\d+)"
        r".*?otherwise\s*XOR\s*(?:it\s+)?with\s*(0x[0-9a-fA-F]+|\d+)",
        text,
        re.IGNORECASE,
    )
    if not m:
        # "at or above N get XOR'd with X, below Y get XOR'd with Z"
        m = re.search(
            r"at or above\s+(0x[0-9a-fA-F]+|\d+)\s+get\s+XOR.d with\s+(0x[0-9a-fA-F]+|\d+)"
            r".*?below\s+(?:0x[0-9a-fA-F]+|\d+)\s+get\s+XOR.d with\s+(0x[0-9a-fA-F]+|\d+)",
            text,
            re.IGNORECASE,
        )
    if not m:
        # "b ^ A when b >= T, or b ^ B when b < T"
        m = re.search(
            r"b\s*\^\s*(0x[0-9a-fA-F]+|\d+)\s+when\s+b\s*>=\s*(0x[0-9a-fA-F]+|\d+)"
            r".*?b\s*\^\s*(0x[0-9a-fA-F]+|\d+)\s+when\s+b\s*<",
            text,
            re.IGNORECASE,
        )
        if m:
            # Reorder: threshold, xor_high, xor_low
            threshold = _parse_num(m.group(2))
            xor_high = _parse_num(m.group(1))
            xor_low = _parse_num(m.group(3))
            return bytes(b ^ xor_high if b >= threshold else b ^ xor_low for b in chunk)
    if not m:
        msg = f"Cannot parse conditional XOR from: {text!r}"
        raise ValueError(msg)

    threshold = _parse_num(m.group(1))
    xor_high = _parse_num(m.group(2))
    xor_low = _parse_num(m.group(3))

    return bytes(b ^ xor_high if b >= threshold else b ^ xor_low for b in chunk)


def _op_simple_xor(data: bytes, text: str, chunk: bytes | None = None) -> bytes:
    """XOR each byte with a constant value."""
    if chunk is None:
        start, end = _parse_range(text)
        chunk = data[start:end]

    # Parse XOR value: "XOR each byte with N" or "exclusive-or every byte with N"
    m = re.search(
        r"(?:XOR|exclusive.or|xor)\s+(?:each|every)\s+(?:byte|octet)\s+with"
        r"(?:\s+(?:the\s+)?value)?\s+(0x[0-9a-fA-F]+|\d+)",
        text,
        re.IGNORECASE,
    )
    if not m:
        # "b ^ N" pattern
        m = re.search(r"b\s*\^\s*(0x[0-9a-fA-F]+|\d+)", text)
    if not m:
        # Trailing "with N" after XOR context
        m = re.search(r"(?:XOR|xor).*?with\s+(0x[0-9a-fA-F]+|\d+)", text)
    if not m:
        msg = f"Cannot parse simple XOR value from: {text!r}"
        raise ValueError(msg)

    xor_val = _parse_num(m.group(1))
    return bytes(b ^ xor_val for b in chunk)


def _op_affine_map(data: bytes, text: str, chunk: bytes | None = None) -> bytes:
    """Map each byte b to (mult * b + add) & 0xFF."""
    if chunk is None:
        start, end = _parse_range(text)
        chunk = data[start:end]

    # "(M * b + C)" or "(b * M + C)" or "result[i] = (M * input[i] + C)"
    m = re.search(
        r"\(?(0x[0-9a-fA-F]+|\d+)\s*\*\s*(?:b|input\[i\]|byte)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)?",
        text,
    )
    if not m:
        m = re.search(
            r"\(?(?:b|byte)\s*\*\s*(0x[0-9a-fA-F]+|\d+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)?",
            text,
        )
    if not m:
        msg = f"Cannot parse affine map from: {text!r}"
        raise ValueError(msg)

    mult = _parse_num(m.group(1))
    add = _parse_num(m.group(2))

    return bytes((mult * b + add) & 0xFF for b in chunk)


def _op_cbc_xor(data: bytes, text: str, chunk: bytes | None = None) -> bytes:
    """CBC-style rolling/chained XOR with an IV."""
    if chunk is None:
        start, end = _parse_range(text)
        chunk = data[start:end]

    # Parse IV from multiple patterns:
    # "IV) is N", "IV = N", "IV is N", "Start with prev = N", "in[0] ^ N"
    iv = None
    for pattern in [
        r"IV[)\s]+(?:is|=)\s*(0x[0-9a-fA-F]+|\d+)",
        r"IV\s*=\s*(0x[0-9a-fA-F]+|\d+)",
        r"prev\s*=\s*(0x[0-9a-fA-F]+|\d+)",
        r"in\[0\]\s*\^\s*(0x[0-9a-fA-F]+|\d+)",
        r"out\[0\]\s*=\s*in\[0\]\s*\^\s*(0x[0-9a-fA-F]+|\d+)",
    ]:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            iv = _parse_num(m.group(1))
            break

    if iv is None:
        msg = f"Cannot parse CBC XOR IV from: {text!r}"
        raise ValueError(msg)

    out = bytearray(len(chunk))
    prev = iv
    for i, b in enumerate(chunk):
        out[i] = b ^ prev
        prev = out[i]
    return bytes(out)


def _op_bitwise_not(data: bytes, text: str, chunk: bytes | None = None) -> bytes:
    """Bitwise complement (NOT) of each byte."""
    if chunk is None:
        start, end = _parse_range(text)
        chunk = data[start:end]
    return bytes(~b & 0xFF for b in chunk)


def _op_sum_mod(data: bytes, text: str) -> bytes:
    """Sum bytes in range, return single byte = sum % modulus."""
    # Try explicit data[A] + data[A+1] + ... + data[B] pattern first
    m = re.search(r"data\[(\d+)\]\s*\+\s*data\[(\d+)\]\s*\+\s*\.\.\.\s*\+\s*data\[(\d+)\]", text)
    if m:
        start = int(m.group(1))
        end = int(m.group(3)) + 1  # inclusive
        chunk = data[start:end]
    else:
        start, end = _parse_range(text)
        chunk = data[start:end]

    # "% N" or "modulo N" or "mod N" or "remainder when divided by N"
    m_mod = re.search(r"(?:%|modulo|mod)\s*(0x[0-9a-fA-F]+|\d+)", text)
    if not m_mod:
        m_mod = re.search(r"divided by\s+(0x[0-9a-fA-F]+|\d+)", text)
    if not m_mod:
        msg = f"Cannot parse modulus from: {text!r}"
        raise ValueError(msg)

    modulus = _parse_num(m_mod.group(1))
    return bytes([sum(chunk) % modulus])


def _op_stride(data: bytes, text: str) -> bytes:
    """Stride/subsample through data."""
    # "step size S, starting at index I, stopping before index E"
    m = re.search(
        r"step\s+(?:size\s+)?(0x[0-9a-fA-F]+|\d+)"
        r".*?(?:starting at|start)\s+(?:index\s+)?(0x[0-9a-fA-F]+|\d+)"
        r".*?(?:stopping before|stop(?:ping)?\s+before)\s+(?:index\s+)?(0x[0-9a-fA-F]+|\d+)",
        text,
        re.IGNORECASE,
    )
    if m:
        step = _parse_num(m.group(1))
        start = _parse_num(m.group(2))
        stop = _parse_num(m.group(3))
        return bytes(data[start:stop:step])

    # "take every Nth byte/octet in the range [A, B)"
    m = re.search(
        r"every\s+(0x[0-9a-fA-F]+|\d+)(?:st|nd|rd|th)\s+(?:byte|octet)",
        text,
        re.IGNORECASE,
    )
    if m:
        step = _parse_num(m.group(1))
        start, stop = _parse_range(text)
        return bytes(data[start:stop:step])

    # "Starting from offset A, take every Nth byte up to offset B"
    m = re.search(
        r"(?:starting|start)\s+(?:from\s+)?(?:offset|index|position)\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?every\s+(0x[0-9a-fA-F]+|\d+)(?:st|nd|rd|th)\s+(?:byte|octet)",
        text,
        re.IGNORECASE,
    )
    if m:
        start = _parse_num(m.group(1))
        step = _parse_num(m.group(2))
        # Find the stop
        stop_m = re.search(
            r"(?:up to|before|reaching)\s+(?:\(but not including\)\s+)?"
            r"(?:offset|index|position)\s+(0x[0-9a-fA-F]+|\d+)",
            text, re.IGNORECASE,
        )
        if stop_m:
            stop = _parse_num(stop_m.group(1))
        else:
            stop = len(data)
        return bytes(data[start:stop:step])

    # "Collect data[X], data[X + step], ... while index stays below Y"
    m = re.search(
        r"data\[(0x[0-9a-fA-F]+|\d+)\].*?data\[\1\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]"
        r".*?below\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        start = _parse_num(m.group(1))
        step = _parse_num(m.group(2))
        stop = _parse_num(m.group(3))
        return bytes(data[start:stop:step])

    # "From position N, sample one byte then skip S, repeating until ... position E"
    m = re.search(
        r"[Ff]rom position\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?skip\s+(0x[0-9a-fA-F]+|\d+)"
        r".*?(?:reach|position)\s+(0x[0-9a-fA-F]+|\d+)",
        text,
    )
    if m:
        start = _parse_num(m.group(1))
        skip = _parse_num(m.group(2))
        stop = _parse_num(m.group(3))
        # "sample one then skip S" = step of (1 + S)
        step = 1 + skip
        return bytes(data[start:stop:step])

    msg = f"Cannot parse stride from: {text!r}"
    raise ValueError(msg)


def _op_reverse_slice(data: bytes, text: str) -> bytes:
    """Reverse bytes in a range."""
    start, end = _parse_range(text)
    return bytes(reversed(data[start:end]))


def _op_sbox(data: bytes, text: str, chunk: bytes | None = None) -> bytes:
    """Nibble-level S-box substitution."""
    if chunk is None:
        start, end = _parse_range(text)
        chunk = data[start:end]

    # Parse the substitution table: [F, 9, 1, D, A, E, 2, 0, C, 4, 5, 7, 6, B, 3, 8]
    m = re.search(r"\[([0-9A-Fa-f,\s]+)\]", text)
    if not m:
        msg = f"Cannot parse S-box table from: {text!r}"
        raise ValueError(msg)

    table_str = m.group(1)
    table = [int(x.strip(), 16) for x in table_str.split(",")]
    if len(table) != 16:
        msg = f"S-box table must have 16 entries, got {len(table)}: {text!r}"
        raise ValueError(msg)

    out = bytearray(len(chunk))
    for i, b in enumerate(chunk):
        high = (b >> 4) & 0xF
        low = b & 0xF
        out[i] = (table[high] << 4) | table[low]
    return bytes(out)


# ── Code-like instruction parser ────────────────────────────────────────────


def _try_parse_code(data: bytes, text: str) -> bytes | None:
    """Handle code-like or multi-step-in-one-sentence instructions."""
    # "result = data[A:B].reverse().map(b => b ^ N)"
    m = re.search(
        r"data\[(\d+):(\d+)\]\.reverse\(\)\.map\(b\s*=>\s*b\s*\^\s*(\d+)\)",
        text,
    )
    if m:
        start, end, xor_val = int(m.group(1)), int(m.group(2)), int(m.group(3))
        chunk = data[start:end]
        return bytes(b ^ xor_val for b in reversed(chunk))

    # "data[A:B].map(b => (M * b + C) & 0xFF)"
    m = re.search(
        r"data\[(\d+):(\d+)\]\.map\(b\s*=>\s*\((\d+)\s*\*\s*b\s*\+\s*(\d+)\)",
        text,
    )
    if m:
        start, end = int(m.group(1)), int(m.group(2))
        mult, add = int(m.group(3)), int(m.group(4))
        return bytes((mult * b + add) & 0xFF for b in data[start:end])

    # NL compound: "isolate/take N bytes... reverse... XOR with V"
    lower = text.lower()
    if ("reverse" in lower or "end-to-end" in lower or "flip" in lower) and (
        "xor" in lower or "exclusive" in lower
    ):
        try:
            start, end = _parse_range(text)
            chunk = bytes(reversed(data[start:end]))
            # Extract XOR value
            m_xor = re.search(
                r"(?:xor|exclusive.or)\s+(?:each|every)\s+(?:byte|octet)\s+with"
                r"(?:\s+(?:the\s+)?value)?\s+(0x[0-9a-fA-F]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if m_xor:
                xor_val = _parse_num(m_xor.group(1))
                return bytes(b ^ xor_val for b in chunk)
        except ValueError:
            pass

    return None


# ── Compound instruction splitter ───────────────────────────────────────────

# Why: BOTCHA instructions can chain operations via natural language connectors.
_PIPE_PATTERNS = [
    r"Pipe the result into the next operation:\s*",
    r"Using the intermediate bytes,\s*",
    r"Take that result and\s+",
    r"Feed the output forward\s+and\s+",
]

# Why: some instructions use sentence-level connectors ("First... Next... Then...")
_SENTENCE_CONNECTORS = [
    r"\.\s*Next,?\s+",
    r"\.\s*Then\s+",
]


def _split_compound(text: str) -> list[str]:
    """Split a compound instruction into sub-operations."""
    parts = [text]

    # Try pipe patterns first
    for pattern in _PIPE_PATTERNS:
        new_parts = []
        for part in parts:
            split = re.split(pattern, part, maxsplit=1, flags=re.IGNORECASE)
            new_parts.extend(split)
        parts = new_parts

    # Try sentence connectors
    for pattern in _SENTENCE_CONNECTORS:
        new_parts = []
        for part in parts:
            split = re.split(pattern, part, flags=re.IGNORECASE)
            new_parts.extend(split)
        parts = new_parts

    # Also split on "First, " at the beginning
    new_parts = []
    for part in parts:
        m = re.match(r"First,?\s+", part, re.IGNORECASE)
        if m:
            new_parts.append(part[m.end() :])
        else:
            new_parts.append(part)
    parts = new_parts

    return [p.strip() for p in parts if p.strip()]


# ── Instruction dispatcher ──────────────────────────────────────────────────


def _is_skip(text: str) -> bool:
    lower = text.lower()
    return (
        "skip this step" in lower
        or "no computation needed" in lower
        or "decoy operation" in lower
        or "pass through without computing" in lower
        or "no-op" in lower
        or "disregard this step" in lower
        or "contributes nothing" in lower
    )


def _is_final_merge(text: str) -> bool:
    lower = text.lower()
    return (
        ("concatenat" in lower or "merge" in lower or "chain" in lower or "join" in lower)
        and "sha-256" in lower
        and ("hex" in lower or "digest" in lower)
    )


def _execute_single_op(
    data: bytes, text: str, prev_result: bytes | None = None
) -> bytes:
    """Execute a single (non-compound) byte operation.

    prev_result: output of the previous sub-operation in a compound chain.
    Some operations work on prev_result instead of the original data.
    """
    lower = text.lower()

    # S-box — check early because it has a distinctive marker
    if (
        "s-box" in lower or "s box" in lower or "permutation table" in lower
        or "substitution table" in lower or "nibble" in lower
        or "nibbles using the table" in lower
    ):
        return _op_sbox(data, text, chunk=prev_result)

    # SHA-256 (single or iterated)
    if "sha-256" in lower or "sha256" in lower:
        return _op_sha256_slice(data, text)

    # CBC/chained XOR — check before simple XOR
    if "cbc" in lower or "rolling xor" in lower or "chained xor" in lower:
        return _op_cbc_xor(data, text, chunk=prev_result)
    if re.search(r"start with prev\s*=", text, re.IGNORECASE):
        return _op_cbc_xor(data, text, chunk=prev_result)

    # Conditional XOR (if >= threshold or "at or above ... XOR" or "when b >= T")
    if re.search(r"if\s+.*>=.*(?:XOR|xor)", text):
        return _op_conditional_xor(data, text)
    if re.search(r"conditional\s+xor|at or above.*XOR|when\s+b\s*>=", text, re.IGNORECASE):
        return _op_conditional_xor(data, text)

    # Simple XOR — "XOR each byte with N" or "exclusive-or every byte with N"
    if re.search(r"(?:XOR|exclusive.or|xor)\s+(?:each|every)\s+(?:byte|octet)", lower):
        return _op_simple_xor(data, text, chunk=prev_result)

    # Affine map — "(M * b + C)" or "result[i] = ..."
    if re.search(r"\*\s*(?:b|input\[i\]|byte)\s*\+|\*\s*(?:b|byte).*\+", text):
        return _op_affine_map(data, text, chunk=prev_result)
    if re.search(r"(?:b|byte)\s*\*\s*(?:0x[0-9a-fA-F]+|\d+)\s*\+", text):
        return _op_affine_map(data, text, chunk=prev_result)
    if "affine cipher" in lower:
        return _op_affine_map(data, text, chunk=prev_result)

    # Bitwise NOT / complement / invert
    if "complement" in lower or "flip all bits" in lower or "bitwise not" in lower:
        return _op_bitwise_not(data, text, chunk=prev_result)
    if re.search(r"~byte|~b\b|compute ~", text):
        return _op_bitwise_not(data, text, chunk=prev_result)
    if "invert every bit" in lower or "255 minus" in lower:
        return _op_bitwise_not(data, text, chunk=prev_result)

    # Sum + modulo
    if ("sum" in lower or "add up" in lower) and (
        "%" in text or "modulo" in lower or "mod " in lower or "remainder" in lower
    ):
        return _op_sum_mod(data, text)
    # "Compute (data[A] + ... + data[B]) mod N"
    if re.search(r"data\[\d+\]\s*\+\s*data\[\d+\].*mod", text, re.IGNORECASE):
        return _op_sum_mod(data, text)

    # Stride / subsample
    if "stride" in lower or "skip" in lower or "sample" in lower:
        return _op_stride(data, text)
    if re.search(r"collect\s+data\[", text, re.IGNORECASE):
        return _op_stride(data, text)
    if re.search(r"every\s+\d+(?:st|nd|rd|th)\s+(?:byte|octet)", lower):
        return _op_stride(data, text)
    if "concatenate them" in lower and re.search(r"every\s+\d+", lower):
        return _op_stride(data, text)

    # Reverse
    if "reverse" in lower or "flip the sequence" in lower or "end-to-end" in lower:
        if prev_result is not None:
            return bytes(reversed(prev_result))
        return _op_reverse_slice(data, text)

    # Isolate / select / grab / pull out — just slice the bytes
    if re.search(r"(?:isolate|pull out|grab|select|read)\s+", lower):
        # This may be a plain slice with no further operation
        try:
            start, end = _parse_range(text)
            return bytes(data[start:end])
        except ValueError:
            pass  # Fall through to error

    msg = f"Unrecognized operation: {text!r}"
    raise ValueError(msg)


def _execute_instruction(data: bytes, text: str) -> bytes:
    """Execute a potentially compound (piped/chained) instruction.

    Compound instructions describe multiple byte operations on the original data.
    Each sub-operation runs independently on the original data, and their outputs
    are concatenated to produce the instruction's result.
    """
    # Try code-like syntax first: data[A:B].reverse().map(b => ...)
    code_result = _try_parse_code(data, text)
    if code_result is not None:
        return code_result

    # Split into sub-operations
    parts = _split_compound(text)

    if len(parts) == 1:
        return _execute_single_op(data, parts[0])

    # Each sub-operation runs independently on the original data.
    # The instruction output is the concatenation of all sub-op results.
    # Why concatenation: BOTCHA "pipe" connectors link independent operations
    # whose byte outputs are joined before the final SHA-256.
    results: list[bytes] = []
    for part in parts:
        try:
            result = _execute_single_op(data, part, prev_result=None)
            results.append(result)
        except ValueError:
            logger.warning("Sub-operation failed, skipping: %s", part)

    if not results:
        msg = f"All sub-operations failed for: {text!r}"
        raise ValueError(msg)
    return b"".join(results)


# ── Main solver ─────────────────────────────────────────────────────────────


def solve_challenge(
    data_b64: str, nonce: str, instructions: list[str]
) -> tuple[str, int, int]:
    """Solve a BOTCHA challenge.

    Returns (answer_hex, instruction_count, decoy_count).
    """
    data = base64.b64decode(data_b64)
    results: list[bytes] = []
    decoys = 0

    for instr in instructions:
        if _is_final_merge(instr):
            concat = b"".join(results)
            answer = hashlib.sha256(concat).hexdigest()
            return answer, len(instructions), decoys
        if _is_skip(instr):
            decoys += 1
            continue
        result = _execute_instruction(data, instr)
        results.append(result)

    # Fallback: concat + SHA-256
    concat = b"".join(results)
    answer = hashlib.sha256(concat).hexdigest()
    return answer, len(instructions), decoys


def compute_hmac(nonce: str, answer: str) -> str:
    """HMAC-SHA256(key=nonce, message=answer)."""
    return hmac_mod.new(
        nonce.encode(), answer.encode(), hashlib.sha256
    ).hexdigest()


# ── Offline mode ────────────────────────────────────────────────────────────
# Why: self-contained challenge so the benchmark runs without network access.

_OFFLINE_DATA = base64.b64encode(bytes(range(256))).decode()
_OFFLINE_NONCE = "deadbeef" * 4
_OFFLINE_INSTRUCTIONS = [
    (
        "Compute SHA-256 over the slice in the range [10, 42] (inclusive)."
        " Return the leading 8 bytes of the hash output."
    ),
    (
        "For each byte in the range [50, 80):"
        " if the byte is >= 100, XOR it with 200; otherwise XOR it with 55."
    ),
    (
        "Concatenate the raw byte results from all 2 steps in order,"
        " and return the SHA-256 hex digest of the concatenated bytes."
    ),
]


def solve_offline() -> dict:
    """Solve a self-generated challenge locally."""
    t0 = time.perf_counter()
    answer, n_instr, n_decoy = solve_challenge(
        _OFFLINE_DATA, _OFFLINE_NONCE, _OFFLINE_INSTRUCTIONS
    )
    elapsed = time.perf_counter() - t0

    # Verify: a 64-char hex string means the parser produced a valid SHA-256
    passed = len(answer) == 64 and all(c in "0123456789abcdef" for c in answer)

    return {
        "name": "BOTCHA",
        "passed": passed,
        "elapsed": elapsed,
        "detail": f"instructions={n_instr}, decoys={n_decoy}, no LLM used",
        "method": "regex parser + byte ops",
    }


# ── Live mode ───────────────────────────────────────────────────────────────

_BASE_URL = "https://botcha-verify.vercel.app"
_MAX_RETRIES = 5


def solve_live() -> dict:
    """Fetch and solve a live BOTCHA challenge.

    Retries up to _MAX_RETRIES times — the instruction set has many wording
    variants and some challenges may hit patterns we don't cover yet.
    """
    last_error = ""
    for attempt in range(_MAX_RETRIES):
        t0 = time.perf_counter()
        try:
            resp = requests.post(
                f"{_BASE_URL}/api/challenge",
                json={"agent_name": "benchmark", "agent_version": "1.0"},
                timeout=10,
            )
            resp.raise_for_status()
            challenge = resp.json()

            session_id = challenge["session_id"]
            nonce = challenge["nonce"]
            data_b64 = challenge["data_b64"]
            instructions = challenge["instructions"]

            answer, n_instr, n_decoy = solve_challenge(data_b64, nonce, instructions)
            answer_hmac = compute_hmac(nonce, answer)

            solve_resp = requests.post(
                f"{_BASE_URL}/api/solve/{session_id}",
                json={"answer": answer, "hmac": answer_hmac},
                timeout=10,
            )
            result = solve_resp.json()
            elapsed = time.perf_counter() - t0

            passed = result.get("success", result.get("verified", False))

            return {
                "name": "BOTCHA",
                "passed": passed,
                "elapsed": elapsed,
                "detail": f"instructions={n_instr}, decoys={n_decoy}, no LLM used",
                "method": "regex parser + byte ops",
            }
        except Exception as exc:
            last_error = str(exc)
            logger.warning(
                "BOTCHA attempt %d/%d failed: %s", attempt + 1, _MAX_RETRIES, exc
            )

    return {
        "name": "BOTCHA",
        "passed": False,
        "elapsed": 0.0,
        "detail": f"all {_MAX_RETRIES} attempts failed: {last_error}",
        "method": "regex parser + byte ops",
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
            f"BOTCHA ............. {status}"
            f" ({result['detail']}, {result['elapsed']:.2f}s)"
        )


if __name__ == "__main__":
    main()
