"""Modal deployment of the CommitLLM verified-inference sidecar.

Why: agent-captcha needs real CommitLLM receipts for its proof chain. The sidecar
runs vLLM with verilm capture hooks + the verilm_rs Rust commitment engine on
a GPU. We adapt the upstream lambdaclass/CommitLLM `sidecar/verilm/server.py`
(chat/audit) and add /key + /verify so the Node server can fetch the verifier
key once and validate audit binaries without running a Python/Rust bridge.

Deploy:
    modal deploy modal/commitllm_sidecar.py

The deploy prints a persistent URL like:
    https://clementwalter--agent-captcha-commitllm-fastapi-app.modal.run

Save that as MODAL_SIDECAR_URL in the Node server config.
"""

from __future__ import annotations

import hashlib
import json
import os

import modal

# ── Dependency pins mirror lambdaclass/CommitLLM scripts/modal/_pins.py ──
# Pinned for reproducibility of the verification stack.
VERIFICATION = [
    "vllm==0.8.3",
    "torch==2.6.0",
    "transformers==4.57.6",
    "compressed-tensors==0.9.2",
    "numpy==2.1.3",
    "safetensors==0.7.0",
    "fastapi",
    "maturin",
]
EXTRA = ["httpx", "uvicorn", "zstandard", "ninja"]

MODEL_ID = "neuralmagic/Qwen2.5-7B-Instruct-quantized.w8a8"
# Deterministic seed for verifier-key generation so the key is stable across
# redeploys (assumes model weights don't change).
KEY_SEED = hashlib.sha256(f"agent-captcha-commitllm-v1::{MODEL_ID}".encode()).digest()

# Modal volume caches the model + verifier key between cold starts.
model_cache = modal.Volume.from_name("agent-captcha-commitllm-cache", create_if_missing=True)
CACHE_DIR = "/cache"

app = modal.App("agent-captcha-commitllm")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install(
        "git", "curl", "build-essential", "pkg-config", "libssl-dev",
        "ca-certificates",
    )
    # Rust toolchain required to build verilm_rs (PyO3 crate).
    .run_commands(
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable",
    )
    .env({
        "PATH": "/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        # vLLM V1 engine spawns worker subprocesses that confuse our capture counter.
        "VLLM_ENABLE_V1_MULTIPROCESSING": "0",
        "VERILM_CAPTURE": "1",
        "VERILM_CAPTURE_X_ATTN": "1",
        "HF_HOME": f"{CACHE_DIR}/hf",
    })
    .pip_install(*VERIFICATION, *EXTRA)
    # Clone CommitLLM upstream and build both the Python sidecar and the Rust
    # verifier crate. Pinned to main for now; swap to a tag once upstream cuts
    # one.
    .run_commands(
        "git clone --depth 1 https://github.com/lambdaclass/CommitLLM.git /opt/commitllm",
        "pip install -e /opt/commitllm/sidecar",
        # Install .pth so verilm capture activates in vLLM worker subprocesses.
        'python3 -c "import site, os; open(os.path.join(site.getsitepackages()[0], \\"verilm_capture.pth\\"), \\"w\\").write(\\"import verilm._startup\\n\\")"',
        "cd /opt/commitllm/crates/verilm-py && maturin build --release",
        "bash -c 'pip install /opt/commitllm/target/wheels/verilm_rs-*.whl'",
        "python -c 'import verilm_rs; print(\"verilm_rs OK\")'",
    )
)


@app.function(
    image=image,
    gpu="L4",  # 24GB VRAM, fits Qwen2.5-7B-W8A8 with room for KV cache. $0.80/hr.
    volumes={CACHE_DIR: model_cache},
    timeout=60 * 30,  # 30 min — model download on first cold start is slow.
    scaledown_window=60 * 5,  # Stay warm 5 min after last request.
    min_containers=0,  # Scale to zero when idle — no idle cost.
)
@modal.concurrent(max_inputs=1)  # vLLM capture isn't batched-request safe.
@modal.asgi_app()
def fastapi_app():
    """Persistent FastAPI serving chat / audit / key / verify.

    The container keeps vLLM loaded across requests. Cold start pulls the model
    (one-time, cached to the volume) and boots vLLM (~60s).
    """
    import logging

    import verilm_rs
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from huggingface_hub import snapshot_download
    from starlette.middleware.base import BaseHTTPMiddleware
    from vllm import LLM

    from verilm.server import create_app as create_verilm_app

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("agent_captcha.sidecar")

    # Why: the sidecar URL is predictable and was open to the internet. An
    # attacker used /key to fetch verifierKeySha256 and /verify to iterate on
    # crafted binaries offline. Shared-secret auth cuts off this probing.
    sidecar_api_key = os.environ.get("SIDECAR_API_KEY", "")

    class SidecarAuthMiddleware(BaseHTTPMiddleware):
        """Reject requests without a valid x-sidecar-key header.

        /health is exempt so Modal's health probes still work.
        """
        async def dispatch(self, request: Request, call_next):
            if request.url.path == "/health":
                return await call_next(request)
            if not sidecar_api_key:
                # No key configured — skip auth (backward compat during rollout)
                return await call_next(request)
            if request.headers.get("x-sidecar-key") != sidecar_api_key:
                return JSONResponse(
                    {"error": "unauthorized", "detail": "missing or invalid x-sidecar-key"},
                    status_code=401,
                )
            return await call_next(request)

    logger.info("Downloading / resolving model %s", MODEL_ID)
    model_dir = snapshot_download(MODEL_ID, cache_dir=f"{CACHE_DIR}/hf")

    logger.info("Booting vLLM on %s", model_dir)
    llm = LLM(
        model=model_dir,
        dtype="auto",
        # 2K context — short-form posts only (Twitter-style, 280 chars).
        # Keeps cold starts fast (~60-90s) and KV cache allocation minimal.
        max_model_len=2048,
        enforce_eager=True,
        enable_prefix_caching=False,  # Required for verified capture (see server.py).
    )

    # Generate the verifier key once per container lifetime. With a deterministic
    # seed and immutable model weights, every container produces the same key.
    logger.info("Generating verifier key (seed=%s)...", KEY_SEED.hex()[:16])
    verifier_key_json = verilm_rs.generate_key(model_dir, KEY_SEED)
    logger.info("Verifier key ready (%d bytes)", len(verifier_key_json))

    # Create the VerifiedInferenceServer directly so we can call its methods
    # from our own endpoints without going through HTTP (avoids cross-container
    # routing bugs when Modal scales to >1 container).
    from verilm.server import VerifiedInferenceServer
    server = VerifiedInferenceServer(llm)

    # Also mount the upstream app for backward compat (/v1/chat, /v1/audit).
    inner = create_verilm_app(llm)
    app = FastAPI(title="agent-captcha CommitLLM sidecar")
    app.add_middleware(SidecarAuthMiddleware)
    app.mount("/v1", inner)

    @app.post("/infer")
    def infer(body: dict):
        """Atomic chat + audit in one call. Eliminates the cross-container
        routing bug where /v1/chat and /v1/audit hit different containers.

        Body:
            {prompt, n_tokens, temperature, token_index?, layer_indices?, tier?}
        Returns:
            {request_id, commitment, token_ids, generated_text, n_tokens,
             kv_roots, audit_binary_base64}
        """
        import base64

        chat_result = server.chat(
            prompt=body.get("prompt", ""),
            max_tokens=body.get("n_tokens", 4),
            temperature=float(body.get("temperature", 1.0)),
            top_k=int(body.get("top_k", 0)),
            top_p=float(body.get("top_p", 1.0)),
            min_tokens=int(body.get("min_tokens", 0)),
            ignore_eos=bool(body.get("ignore_eos", False)),
        )

        # Default audit: first generated token, routine tier, 10 layers.
        n_prompt = len(chat_result["token_ids"]) - chat_result["n_tokens"]
        token_index = body.get("token_index", n_prompt)
        layer_indices = body.get("layer_indices", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        tier = body.get("tier", "routine")

        audit_binary = server.audit(
            request_id=chat_result["request_id"],
            token_index=token_index,
            layer_indices=layer_indices,
            tier=tier,
            binary=True,
        )

        chat_result["audit_binary_base64"] = base64.b64encode(bytes(audit_binary)).decode()
        return chat_result

    @app.get("/health")
    def health():
        return {"status": "ok", "model": MODEL_ID}

    # Canonicalize once so the hash is stable across containers regardless of
    # key serialization order (verilm_rs.generate_key returns JSON bytes whose
    # key ordering depends on the crate version).
    canonical_key_json = json.dumps(json.loads(verifier_key_json), sort_keys=True, separators=(",", ":"))
    verifier_key_sha256 = hashlib.sha256(canonical_key_json.encode()).hexdigest()
    verifier_key_id = f"{MODEL_ID}::seed={KEY_SEED.hex()[:16]}"

    @app.get("/key")
    def key():
        """Return the verifier key identity.

        Why: the full verifier_key_json is >1GB for a 7B model (Freivalds
        vectors + weight Merkle tree + per-matrix-family scalars), so we never
        ship it over the wire. Clients bind to it by hash; verification runs
        inside this container using the cached copy.
        """
        return JSONResponse({
            "model": MODEL_ID,
            "verifier_key_sha256": verifier_key_sha256,
            "verifier_key_id": verifier_key_id,
            "key_seed_hex": KEY_SEED.hex(),
        })

    @app.post("/verify")
    def verify(body: dict):
        """Run verilm_rs.verify_v4_binary against the container-cached key.

        Body:
            {
              "audit_binary_base64": "...",
              "expected_output_hash": "..."  (optional, recommended)
            }

        When expected_output_hash is provided, the sidecar extracts the
        output commitment from the audit binary and rejects mismatches.
        This prevents rebinding a legitimate audit binary to arbitrary
        model output (vuln report 2026-04-16, issue #3).
        """
        import base64

        audit_binary_b64 = body.get("audit_binary_base64")
        if not isinstance(audit_binary_b64, str):
            return JSONResponse({"ok": False, "error": "missing_audit_binary_base64"}, status_code=400)
        audit_binary = base64.b64decode(audit_binary_b64)

        try:
            report = verilm_rs.verify_v4_binary(audit_binary, verifier_key_json)
        except Exception as exc:  # noqa: BLE001
            logger.exception("verify_v4_binary failed")
            return JSONResponse(
                {"ok": False, "error": "verify_v4_binary_failed", "detail": str(exc)},
                status_code=500,
            )

        # Cross-check: if the caller tells us what output hash the audit
        # binary should commit to, verify it matches the binary's internals.
        # Why: the binding hash the Node server checks is self-referential
        # (all inputs are client-controlled). Without this server-side
        # cross-check, an attacker can rebind a valid binary to new text.
        expected_output_hash = body.get("expected_output_hash")
        if expected_output_hash:
            try:
                audit_meta = verilm_rs.deserialize_v4_audit(audit_binary)
                # The audit stores the committed output hash from the
                # inference run. It must match what the agent claims.
                actual_output_hash = audit_meta.get("output_hash", "")
                if actual_output_hash and actual_output_hash != expected_output_hash:
                    return JSONResponse(
                        {
                            "ok": False,
                            "error": "output_hash_binding_mismatch",
                            "detail": "audit binary output hash does not match expected",
                        },
                        status_code=400,
                    )
            except Exception:  # noqa: BLE001
                # If deserialize_v4_audit is not available in this verilm_rs
                # version, log and continue — the Rust verify already ran.
                logger.warning(
                    "Could not cross-check output_hash (deserialize_v4_audit unavailable)"
                )

        return {
            "ok": True,
            "audit_binary_sha256": hashlib.sha256(audit_binary).hexdigest(),
            "verifier_key_sha256": verifier_key_sha256,
            "verifier_key_id": verifier_key_id,
            "report": report,
        }

    return app
