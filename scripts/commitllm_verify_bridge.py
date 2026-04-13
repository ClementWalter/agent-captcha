#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""CommitLLM verification bridge.

Why: keep the Node API lean while delegating canonical `verify_v4_binary`
execution to the Python bridge that can load `verilm_rs` directly.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import sys
from typing import Any

LOGGER = logging.getLogger("agent_captcha.commitllm_bridge")


def _write_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def _error(code: str, detail: str) -> int:
    _write_json({"ok": False, "error": code, "error_detail": detail})
    return 1


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing_or_invalid_{key}")
    return value


def _normalize_report(report: dict[str, Any]) -> dict[str, Any]:
    classified_raw = report.get("classified_failures")
    classified: list[dict[str, str]] = []
    if isinstance(classified_raw, list):
        for item in classified_raw:
            if isinstance(item, dict):
                code = str(item.get("code", "unknown"))
                category = str(item.get("category", "unknown"))
                message = str(item.get("message", ""))
                classified.append({"code": code, "category": category, "message": message})

    failures_raw = report.get("failures")
    failures = [str(item) for item in failures_raw] if isinstance(failures_raw, list) else []

    coverage_raw = report.get("coverage")
    coverage_level = None
    if isinstance(coverage_raw, dict):
        level_value = coverage_raw.get("level")
        if isinstance(level_value, str):
            coverage_level = level_value

    return {
        "passed": bool(report.get("passed", False)),
        "checks_run": int(report.get("checks_run", 0)),
        "checks_passed": int(report.get("checks_passed", 0)),
        "failures": failures,
        "classified_failures": classified,
        "coverage_level": coverage_level,
        "duration_us": int(report.get("duration_us", 0)),
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO)

    raw_input = sys.stdin.read()
    if not raw_input.strip():
        return _error("missing_input", "expected JSON payload via stdin")

    try:
        payload = json.loads(raw_input)
    except json.JSONDecodeError as exc:
        return _error("invalid_json", str(exc))

    if not isinstance(payload, dict):
        return _error("invalid_payload", "top-level payload must be a JSON object")

    try:
        audit_binary_base64 = _require_string(payload, "audit_binary_base64")
        verifier_key_json = _require_string(payload, "verifier_key_json")
    except ValueError as exc:
        return _error("invalid_request", str(exc))

    try:
        audit_binary = base64.b64decode(audit_binary_base64.encode("utf-8"), validate=True)
    except (ValueError, binascii.Error) as exc:
        return _error("invalid_audit_binary_base64", str(exc))

    audit_binary_sha256 = hashlib.sha256(audit_binary).hexdigest()

    try:
        import verilm_rs  # type: ignore[import-not-found]
    except ImportError as exc:
        LOGGER.exception("verilm_rs import failed")
        return _error("verilm_rs_not_installed", str(exc))

    try:
        verify_result = verilm_rs.verify_v4_binary(audit_binary, verifier_key_json)
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("verify_v4_binary execution failed")
        return _error("verify_v4_binary_failed", str(exc))

    if not isinstance(verify_result, dict):
        return _error("invalid_verify_result", "verify_v4_binary did not return a dict")

    response = {
        "ok": True,
        "audit_binary_sha256": audit_binary_sha256,
        "report": _normalize_report(verify_result),
    }
    _write_json(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
