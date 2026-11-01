"""Agent-centric inventory (agentic-bom.json) derived from the evidence graph.

Format: ``aem-agentic-bom`` (project-specific). It is NOT claimed to conform to
AgentBOM v1 or CycloneDX; see docs/limitations.md.
"""

from __future__ import annotations

from typing import Any

from agentic_bom.core.models import SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION

BOM_EDGE_TYPES = {"USES_MODEL", "BINDS_TOOL", "EXPOSES_TOOL", "CONNECTS_MCP", "DELEGATES_TO", "USES_SKILL"}


def to_agentic_bom(report: dict[str, Any]) -> dict[str, Any]:
    nodes = {n["id"]: n for n in report["graph"]["nodes"]}
    edges = report["graph"]["edges"]

    def targets(src: str, typ: str) -> list[str]:
        return sorted(e["target"] for e in edges if e["source"] == src and e["type"] == typ)

    def sources(dst: str, typ: str) -> list[str]:
        return sorted(e["source"] for e in edges if e["target"] == dst and e["type"] == typ)

    agents = []
    for n in sorted((n for n in nodes.values() if n["kind"] == "agent"), key=lambda n: n["id"]):
        a = n["attributes"]
        prompt = nodes.get(f"prompt:{n['id']}:instructions")
        agents.append({
            "id": n["id"],
            "name": n["name"],
            "framework": a.get("framework"),
            "model": a.get("model"),
            "instructions": {
                "provenance": a.get("instructions_provenance"),
                "sha256": prompt["attributes"].get("sha256") if prompt else None,
                "length": prompt["attributes"].get("length") if prompt else None,
                "body": "not stored",
            },
            "tools": targets(n["id"], "BINDS_TOOL"),
            "mcp_servers": targets(n["id"], "CONNECTS_MCP"),
            "delegates_to": targets(n["id"], "DELEGATES_TO"),
            "management_status": a.get("management_status", "unknown"),
            "resolution": n["resolution"],
            "evidence": n["evidence"],
        })
    tools = []
    for n in sorted((n for n in nodes.values() if n["kind"] == "tool"), key=lambda n: n["id"]):
        a = n["attributes"]
        tools.append({
            "id": n["id"],
            "name": n["name"],
            "framework": a.get("framework"),
            "contract": a.get("contract"),
            "bound_by": sources(n["id"], "BINDS_TOOL"),
            "exposed_by": sources(n["id"], "EXPOSES_TOOL"),
            "resolution": n["resolution"],
            "evidence": n["evidence"],
            **({"reason": a["reason"]} if a.get("reason") else {}),
        })

    def simple(kind: str) -> list[dict[str, Any]]:
        return [
            {"id": n["id"], "name": n["name"], "resolution": n["resolution"], "attributes": n["attributes"], "evidence": n["evidence"]}
            for n in sorted((n for n in nodes.values() if n["kind"] == kind), key=lambda n: n["id"])
        ]

    return {
        "format": "aem-agentic-bom",
        "format_note": "Project-specific agent-centric inventory; not claimed to conform to AgentBOM v1 or CycloneDX.",
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "application": report["scope"]["label"],
        "components": {
            "agents": agents,
            "tools": tools,
            "models": simple("model"),
            "mcp_servers": simple("mcp_server"),
            "packages": simple("package"),
            "data_sources": simple("data_source"),
        },
        "relationships": [e for e in edges if e["type"] in BOM_EDGE_TYPES],
    }
