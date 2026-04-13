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
import os
import sys
from typing import Any

LOGGER = logging.getLogger("agent_captcha.commitllm_bridge")
BRIDGE_PROTOCOL_VERSION = os.environ.get("AGENT_CAPTCHA_BRIDGE_PROTOCOL_VERSION", "agent-captcha-commitllm-bridge-v1")


def _read_int_env(name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except ValueError:
        return fallback


MAX_AUDIT_BINARY_BYTES = _read_int_env("AGENT_CAPTCHA_BRIDGE_MAX_AUDIT_BINARY_BYTES", 10_000_000)
MAX_VERIFIER_KEY_JSON_BYTES = _read_int_env("AGENT_CAPTCHA_BRIDGE_MAX_VERIFIER_KEY_JSON_BYTES", 250_000)
CPU_LIMIT_SECONDS = _read_int_env("AGENT_CAPTCHA_BRIDGE_CPU_SECONDS", 2)
MAX_MEMORY_BYTES = _read_int_env("AGENT_CAPTCHA_BRIDGE_MAX_MEMORY_BYTES", 512_000_000)

try:
    import resource
except ImportError:  # pragma: no cover - not expected on linux/macOS runtimes
    resource = None  # type: ignore[assignment]


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


def _apply_resource_limits() -> None:
    if resource is None:
        LOGGER.warning("resource module unavailable; bridge resource limits not applied")
        return

    # Why: keep verification bridge executions bounded to avoid process abuse from untrusted payloads.
    try:
        cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
        target_cpu = CPU_LIMIT_SECONDS
        if cpu_hard != resource.RLIM_INFINITY:
            target_cpu = min(target_cpu, cpu_hard)
        resource.setrlimit(resource.RLIMIT_CPU, (target_cpu, cpu_hard))
    except (ValueError, OSError):
        LOGGER.warning("failed to apply RLIMIT_CPU")

    try:
        memory_soft, memory_hard = resource.getrlimit(resource.RLIMIT_AS)
        target_memory = MAX_MEMORY_BYTES
        if memory_hard != resource.RLIM_INFINITY:
            target_memory = min(target_memory, memory_hard)
        resource.setrlimit(resource.RLIMIT_AS, (target_memory, memory_hard))
    except (ValueError, OSError):
        LOGGER.warning("failed to apply RLIMIT_AS")


def _canonicalize_json(raw: str) -> str:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid_verifier_key_json:{exc}") from exc
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    _apply_resource_limits()

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

    if len(audit_binary_base64) > MAX_AUDIT_BINARY_BYTES * 2:
        return _error("audit_binary_too_large", f"base64_length={len(audit_binary_base64)}")

    verifier_key_size = len(verifier_key_json.encode("utf-8"))
    if verifier_key_size > MAX_VERIFIER_KEY_JSON_BYTES:
        return _error("verifier_key_json_too_large", f"bytes={verifier_key_size}")

    try:
        audit_binary = base64.b64decode(audit_binary_base64.encode("utf-8"), validate=True)
    except (ValueError, binascii.Error) as exc:
        return _error("invalid_audit_binary_base64", str(exc))

    if len(audit_binary) > MAX_AUDIT_BINARY_BYTES:
        return _error("audit_binary_too_large", f"bytes={len(audit_binary)}")

    try:
        canonical_verifier_key_json = _canonicalize_json(verifier_key_json)
    except ValueError as exc:
        return _error("invalid_verifier_key_json", str(exc))

    audit_binary_sha256 = hashlib.sha256(audit_binary).hexdigest()
    verifier_key_sha256 = hashlib.sha256(canonical_verifier_key_json.encode("utf-8")).hexdigest()

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
        "bridge_protocol_version": BRIDGE_PROTOCOL_VERSION,
        "verilm_rs_version": getattr(verilm_rs, "__version__", "unknown"),
        "audit_binary_sha256": audit_binary_sha256,
        "verifier_key_sha256": verifier_key_sha256,
        "report": _normalize_report(verify_result),
    }
    _write_json(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
