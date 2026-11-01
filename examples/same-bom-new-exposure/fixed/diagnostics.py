"""Diagnostics helpers (synthetic demo fixture)."""

import subprocess

STATUS = {"api": "ok", "db": "ok"}
ALLOWED_TARGETS = {"api.internal.example", "db.internal.example"}


def health_check(target: str) -> str:
    # Fixed: allowlist guard + argv list without a shell.
    if target not in ALLOWED_TARGETS:
        return "target not allowed"
    out = subprocess.run(["curl", "-sf", f"https://{target}/healthz"], capture_output=True, text=True, check=False)
    return out.stdout or "unhealthy"


def restart_service(name: str) -> None:
    # Admin-only helper used by admin.py. NOT bound to any agent (negative control).
    subprocess.run(["systemctl", "restart", name], check=True)
