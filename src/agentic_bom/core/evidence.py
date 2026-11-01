"""Evidence helpers: redaction, snippets, stable hashing."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),  # OpenAI-style keys
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),  # Slack
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),  # Google API key
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*)(['\"])([^'\"]{4,})\2"
)
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Remove obvious credential material from text destined for reports."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(REDACTED, out)
    out = _ASSIGNMENT_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}", out)
    out = _LONG_HEX.sub(REDACTED, out)
    return out


def redact_target(value: str) -> str:
    """Targets (paths/URLs/commands) are kept, but URL credentials & query strings are dropped."""
    value = redact(value)
    if "://" in value:
        try:
            parts = urlsplit(value)
            host = parts.hostname or ""
            port = f":{parts.port}" if parts.port else ""
            return f"{parts.scheme}://{host}{port}{parts.path}"
        except ValueError:
            return REDACTED
    return value[:200]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(data: Any) -> str:
    return sha256_text(canonical_json(data))


def short_id(prefix: str, *parts: str) -> str:
    return f"{prefix}-{sha256_text('|'.join(parts))[:12]}"


def snippet(lines: list[str], line_no: int, max_len: int = 200) -> str:
    if 1 <= line_no <= len(lines):
        text = lines[line_no - 1].strip()
        if len(text) > max_len:
            text = text[: max_len - 1] + "…"
        return redact(text)
    return ""
