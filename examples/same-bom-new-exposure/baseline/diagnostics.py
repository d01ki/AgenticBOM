"""Diagnostics helpers (synthetic demo fixture)."""

import subprocess

STATUS = {"api": "ok", "db": "ok"}


def health_check(target: str) -> str:
    # Baseline: a static lookup; no operation is reachable from the tool parameter.
    return STATUS.get(target, "unknown target")


def restart_service(name: str) -> None:
    # Admin-only helper used by admin.py. NOT bound to any agent (negative control).
    subprocess.run(["systemctl", "restart", name], check=True)
