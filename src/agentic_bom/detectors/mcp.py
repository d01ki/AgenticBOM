"""Static MCP client configuration discovery (mcp.json / .mcp.json / claude_desktop_config.json ...).

Only names, transports, commands (redacted) and env *key names* are recorded;
environment values are never copied into reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from agentic_bom.core.evidence import redact_target

CONFIG_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "mcp-servers.json"}


@dataclass
class McpConfigServer:
    file: str
    name: str
    transport: str
    command: str | None
    url: str | None
    env_keys: list[str] = field(default_factory=list)
    server_file: str | None = None
    line: int = 1


def is_mcp_config(relpath: str) -> bool:
    return PurePosixPath(relpath).name in CONFIG_NAMES


def _line_of(text: str, needle: str) -> int:
    idx = text.find(f'"{needle}"')
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def parse_mcp_config(relpath: str, text: str) -> tuple[list[McpConfigServer], str | None]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        return [], type(exc).__name__
    if not isinstance(data, dict):
        return [], "not an object"
    servers = data.get("mcpServers") or data.get("servers")
    if servers is None and isinstance(data.get("mcp"), dict):
        servers = data["mcp"].get("servers")
    if not isinstance(servers, dict):
        return [], None
    out: list[McpConfigServer] = []
    for name, spec in sorted(servers.items()):
        if not isinstance(spec, dict):
            continue
        cmd = spec.get("command") if isinstance(spec.get("command"), str) else None
        args = [a for a in spec.get("args", []) if isinstance(a, str)] if isinstance(spec.get("args"), list) else []
        url = spec.get("url") if isinstance(spec.get("url"), str) else None
        transport = spec.get("type") or spec.get("transport") or ("stdio" if cmd else ("http" if url else "unknown"))
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        out.append(
            McpConfigServer(
                file=relpath,
                name=str(name)[:100],
                transport=str(transport)[:40],
                command=redact_target(" ".join([cmd] + args)) if cmd else None,
                url=redact_target(url) if url else None,
                env_keys=sorted(str(k)[:80] for k in env),
                server_file=next((a for a in args if a.endswith(".py")), None),
                line=_line_of(text, str(name)),
            )
        )
    return out, None
