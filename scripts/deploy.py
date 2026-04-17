#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["click", "requests"]
# ///
"""Build, push, and roll out the agent-captcha API container to Scaleway.

Used by the vulnerability-loop's DeployFlow so each iteration's security
fixes actually reach prod before the next iteration's finder probes the
live URL. Standalone callable from a shell too.

Steps:
  1. Build the image tagged with the current git SHA + :latest.
  2. Push both tags to the Scaleway container registry.
  3. Trigger a Scaleway container redeploy.
  4. Poll the container's status + the public health endpoint until
     either it reports ready with the new revision, or the timeout
     elapses (in which case we exit non-zero so the calling task fails
     loud instead of silently moving on).

Container ID, registry image, and probe URL default to the agentcaptcha
production setup but can be overridden with env vars / flags so the
script is reusable for staging.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass

import click
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("deploy")

DEFAULT_CONTAINER_ID = "19be2dd3-7261-4390-b84e-6a3bb17524b4"
DEFAULT_IMAGE = "rg.fr-par.scw.cloud/agent-captcha/api"
DEFAULT_HEALTH_URL = "https://agentcaptcha.chat/api/health"


@dataclass
class DeployConfig:
    container_id: str
    image: str
    health_url: str
    timeout_seconds: int


def run(cmd: list[str], capture: bool = False) -> str:
    """Run a shell command, stream stderr, and return stdout."""
    log.info("$ %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=None,
    )
    return result.stdout or ""


def current_git_sha() -> str:
    return run(["git", "rev-parse", "HEAD"], capture=True).strip()


def build_and_push(image: str, sha: str) -> None:
    """Build for linux/amd64, tag both :sha and :latest, push both tags."""
    sha_tag = f"{image}:{sha}"
    latest_tag = f"{image}:latest"
    # Why amd64: Scaleway Serverless Containers run amd64 — building on
    # an arm64 dev machine without --platform produces an image the
    # platform refuses to schedule.
    run(
        [
            "docker",
            "build",
            "--platform",
            "linux/amd64",
            "-t",
            sha_tag,
            "-t",
            latest_tag,
            ".",
        ]
    )
    run(["docker", "push", sha_tag])
    run(["docker", "push", latest_tag])


def trigger_redeploy(container_id: str) -> None:
    run(["scw", "container", "container", "deploy", container_id])


def container_status(container_id: str) -> dict:
    """Returns the container's current scw description (parsed JSON)."""
    out = run(
        ["scw", "container", "container", "get", container_id, "-o", "json"],
        capture=True,
    )
    import json

    return json.loads(out)


def wait_for_ready(cfg: DeployConfig) -> None:
    """Poll container status + /api/health until ready or timeout.

    We can't easily verify the deployed image SHA matches what we just
    pushed (Scaleway exposes the image string, not a content digest),
    so we fall back to: container status == ready + health endpoint
    returns 200. Combined with a fresh redeploy trigger, that's a
    reasonable proxy for "rollout finished".
    """
    deadline = time.monotonic() + cfg.timeout_seconds
    last_status = ""
    while time.monotonic() < deadline:
        status = container_status(cfg.container_id).get("status", "?")
        if status != last_status:
            log.info("container status: %s", status)
            last_status = status
        if status == "ready":
            try:
                resp = requests.get(cfg.health_url, timeout=10)
                if resp.status_code == 200:
                    log.info("health OK at %s", cfg.health_url)
                    return
                log.info(
                    "health %s returned %s, retrying",
                    cfg.health_url,
                    resp.status_code,
                )
            except requests.RequestException as exc:
                log.info("health probe error: %s", exc)
        if status == "error":
            raise click.ClickException("container reported status=error during rollout")
        time.sleep(5)
    raise click.ClickException(
        f"container did not become ready within {cfg.timeout_seconds}s"
    )


@click.command()
@click.option(
    "--container-id",
    default=lambda: os.environ.get("DEPLOY_CONTAINER_ID", DEFAULT_CONTAINER_ID),
    show_default=DEFAULT_CONTAINER_ID,
    help="Scaleway container ID to redeploy.",
)
@click.option(
    "--image",
    default=lambda: os.environ.get("DEPLOY_IMAGE", DEFAULT_IMAGE),
    show_default=DEFAULT_IMAGE,
    help="Registry image (without tag).",
)
@click.option(
    "--health-url",
    default=lambda: os.environ.get("DEPLOY_HEALTH_URL", DEFAULT_HEALTH_URL),
    show_default=DEFAULT_HEALTH_URL,
    help="Public health endpoint to probe after rollout.",
)
@click.option(
    "--timeout-seconds",
    default=300,
    show_default=True,
    type=int,
    help="Max wait for the rollout to report ready.",
)
@click.option(
    "--skip-build",
    is_flag=True,
    help="Skip docker build/push (e.g. only re-trigger the rollout).",
)
def main(
    container_id: str,
    image: str,
    health_url: str,
    timeout_seconds: int,
    skip_build: bool,
) -> None:
    """Deploy the current HEAD to Scaleway and wait for it to come up."""
    cfg = DeployConfig(
        container_id=container_id,
        image=image,
        health_url=health_url,
        timeout_seconds=timeout_seconds,
    )
    sha = current_git_sha()
    log.info("deploying commit %s to container %s", sha, cfg.container_id)
    if not skip_build:
        build_and_push(cfg.image, sha)
    else:
        log.info("--skip-build: not rebuilding the image")
    trigger_redeploy(cfg.container_id)
    wait_for_ready(cfg)
    log.info("deploy complete: %s is live on %s", sha, cfg.health_url)


if __name__ == "__main__":
    main()
