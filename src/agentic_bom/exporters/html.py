"""Self-contained HTML report. Data is embedded as escaped JSON and rendered with textContent only."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

# Characters that could terminate the <script> JSON island or confuse the HTML parser are
# replaced by their JSON unicode escapes (valid JSON, identical value after JSON.parse).
_UNSAFE = frozenset("&<>" + chr(0x2028) + chr(0x2029))
_BACKSLASH = chr(92)


def safe_json(data: Any) -> str:
    s = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return "".join(f"{_BACKSLASH}u{ord(ch):04x}" if ch in _UNSAFE else ch for ch in s)


def render_html(head: dict[str, Any], drift: dict[str, Any] | None = None, retest: str = "agentic-bom scan <path> --out out/") -> str:
    template = resources.files("agentic_bom.web").joinpath("report.html").read_text(encoding="utf-8")
    head = {k: v for k, v in head.items() if k != "metrics"}  # timings are not reproducible
    payload = {"mode": "diff" if drift else "scan", "head": head, "drift": drift, "commands": {"retest": retest}}
    return template.replace("__AEM_DATA__", safe_json(payload), 1)
