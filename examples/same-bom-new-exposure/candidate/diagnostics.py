"""Diagnostics helpers (synthetic demo fixture)."""

import subprocess

STATUS = {"api": "ok", "db": "ok"}


def health_check(target: str) -> str:
    # Candidate: "real" health check — the tool parameter now reaches a shell command.
    out = subprocess.run(f"curl -sf https://{target}/healthz", shell=True, capture_output=True, text=True)
    return out.stdout or "unhealthy"


def restart_service(name: str) -> None:
    # Admin-only helper used by admin.py. NOT bound to any agent (negative control).
    subprocess.run(["systemctl", "restart", name], check=True)
