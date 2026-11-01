"""Deterministic capability-path construction and classification over the evidence graph.

untrusted input (if confirmed) -> privileged prompt/agent -> explicit tool binding
-> callable operation -> affected resource (when resolvable)

The classifier never upgrades UNKNOWN; "potentially_exposed" is a static
possibility, not proof of exploitation.
"""

from __future__ import annotations

from typing import Any

from agentic_bom.analyzers.operations import CATEGORY_LABELS, DYNAMIC_DISPATCH
from agentic_bom.core.evidence import short_id
from agentic_bom.core.graph import EvidenceGraph
from agentic_bom.core.models import (
    BOUND_CAPABILITY,
    CONFIRMED,
    GUARD_ABSENT,
    GUARD_KNOWN,
    GUARD_NA,
    GUARD_UNKNOWN,
    INFERRED,
    INVENTORY_ONLY,
    OPERATION_PATH,
    PATH_UNKNOWN,
    POTENTIALLY_EXPOSED,
    UNKNOWN,
    UNSUPPORTED,
    Edge,
)

REMEDIATION = {
    "process_execution": "Pass a fixed argv list (no shell=True), validate the parameter against an explicit allowlist before the call, and keep untrusted text out of agent instructions.",
    "code_execution": "Remove eval/exec on tool-controlled data; replace with a parser or an explicit dispatch table.",
    "filesystem_write": "Constrain the path to a fixed base directory with an allowlisted name pattern; validate before writing.",
    "filesystem_delete": "Restrict deletion to an allowlisted directory and name pattern, or require human confirmation.",
    "network_state_change": "Use a fixed, configured endpoint; do not let tool parameters choose the destination URL.",
    "cloud_sdk_call": "Fix bucket/resource identifiers in code or validate against an allowlist; review the runtime identity's permissions separately (not analysed here).",
    "secret_access": "Avoid exposing secret lookups to tool parameters; fix the variable name and never return secret values to the model.",
    DYNAMIC_DISPATCH: "Replace dynamic dispatch with an explicit mapping so the reachable operations can be reviewed.",
}
MAX_DELEGATION = 2
SEVERITY = {POTENTIALLY_EXPOSED: "high", OPERATION_PATH: "medium", BOUND_CAPABILITY: "low", INVENTORY_ONLY: "info", PATH_UNKNOWN: "info"}


def classify(op_edge: Edge, binding_resolution: str, tool_resolution: str, untrusted_privileged: bool, provenance: str, bound: bool) -> tuple[str, list[str]]:
    a = op_edge.attributes
    unknowns: list[str] = []
    if tool_resolution in (UNKNOWN, UNSUPPORTED):
        return PATH_UNKNOWN, ["tool implementation not statically analysable"]
    if op_edge.resolution in (UNKNOWN, UNSUPPORTED) or a.get("operation_category") == DYNAMIC_DISPATCH:
        return PATH_UNKNOWN, [a.get("reason") or "call target resolved only at runtime (dynamic dispatch)"]
    if op_edge.resolution == INFERRED:
        unknowns.append("operation recognised with limited inference (e.g. unresolved mode/method)")
    if binding_resolution == INFERRED:
        unknowns.append("agent-to-tool binding inferred from configuration (e.g. MCP server command args)")
    if provenance == "unknown":
        unknowns.append("instruction provenance could not be resolved (dynamic or parameter without resolvable caller)")
    if not bound:
        return INVENTORY_ONLY, unknowns + ["no agent or MCP server binding found for this tool"]
    if not a.get("target_controlled"):
        if a.get("target_kind") == "unresolved":
            unknowns.append("operation target unresolved, but not derived from tool parameters in the supported model")
        return BOUND_CAPABILITY, unknowns
    guard = a.get("guard_status", GUARD_ABSENT)
    if guard == GUARD_KNOWN:
        return OPERATION_PATH, unknowns
    if untrusted_privileged:
        if guard == GUARD_UNKNOWN:
            return PATH_UNKNOWN, unknowns + ["a guard predicate exists but is not a supported pattern"]
        return POTENTIALLY_EXPOSED, unknowns
    if guard == GUARD_UNKNOWN:
        unknowns.append("a guard predicate exists but is not a supported pattern")
    return OPERATION_PATH, unknowns


def _reason(cls: str, a: dict[str, Any], untrusted: bool, entry_kind: str) -> str:
    cat = CATEGORY_LABELS.get(a.get("operation_category", ""), a.get("operation_category", "operation"))
    params = ", ".join(a.get("controlling_params", [])) or "n/a"
    if cls == POTENTIALLY_EXPOSED:
        return (f"Untrusted data reaches the agent's privileged instructions, and a bound tool parameter ({params}) "
                f"controls the target of a {cat.lower()} with no recognised guard. A model following injected instructions "
                f"could choose that argument. Static possibility only; not proof of exploitation.")
    if cls == OPERATION_PATH:
        g = a.get("guard_status")
        suffix = ""
        if g == GUARD_KNOWN:
            suffix = (" The tool requires human approval before running (needs_approval)." if a.get("guard_kind") == "human_approval"
                      else " A recognised allowlist/validation guard constrains the parameter.")
        who = "the MCP client model" if entry_kind == "mcp_server" else "the model"
        return f"Tool parameter ({params}) controls the target of a {cat.lower()} that {who} can invoke.{suffix}"
    if cls == BOUND_CAPABILITY:
        return f"Bound tool performs a {cat.lower()}, but its target is not controlled by tool parameters in the supported data-flow model."
    if cls == INVENTORY_ONLY:
        return f"Tool contains a {cat.lower()} but no agent/MCP binding was proven."
    return f"{cat}: path could not be resolved statically; review manually."


def _ev(edges: list[Edge]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in edges:
        for ev in e.evidence:
            d = ev.to_dict()
            if d not in out:
                out.append(d)
    return sorted(out, key=lambda d: (d["file"], d["line_start"], d["detector_id"]))


def _make_path(g: EvidenceGraph, entry: str | None, entry_kind: str, chain: list[Edge], tool_id: str, op_edge: Edge | None,
               untrusted_edges: list[Edge], user_edges: list[Edge], provenance: str, bound: bool) -> dict[str, Any]:
    tool = g.nodes[tool_id]
    delegates = [e.target for e in chain if e.type == "DELEGATES_TO"]
    binding_res = max((e.resolution for e in chain), key=lambda r: {CONFIRMED: 0, INFERRED: 1, UNKNOWN: 2, UNSUPPORTED: 3}[r], default=CONFIRMED)
    untrusted = bool(untrusted_edges)
    if op_edge is None:
        cls = PATH_UNKNOWN
        unknowns = [tool.attributes.get("reason") or "tool implementation not statically analysable"]
        a: dict[str, Any] = {}
        op_node = None
    else:
        cls, unknowns = classify(op_edge, binding_res, tool.resolution, untrusted, provenance, bound)
        a = op_edge.attributes
        op_node = g.nodes[op_edge.target]
    if cls == POTENTIALLY_EXPOSED and binding_res == INFERRED:
        unknowns = unknowns + ["path relies on an inferred binding"]
    if delegates:
        unknowns = unknowns + [f"reached via delegation to {', '.join(g.nodes[d].name for d in delegates)}; the sub-agent's own instructions may constrain or refuse the call"]
    edges = list(untrusted_edges) + chain + ([op_edge] if op_edge else [])
    resource_edges = g.out_edges(op_edge.target) if op_edge else []
    edges += [e for e in resource_edges if e.type in ("WRITES_TO", "READS_FROM")]
    nodes: list[str] = []
    for e in edges:
        for n in (e.source, e.target):
            if n not in nodes:
                nodes.append(n)
    key = f"{entry or '-'}{''.join('>' + d for d in delegates)}|{tool_id}|{op_edge.target if op_edge else '-'}|{op_edge.key if op_edge else ''}"
    guard = a.get("guard_status", GUARD_NA) if op_edge and a.get("target_controlled") else GUARD_NA
    severity = SEVERITY[cls]
    if cls == OPERATION_PATH and guard == GUARD_KNOWN:
        severity = "low"
    resolution = CONFIRMED
    if cls == PATH_UNKNOWN:
        resolution = UNKNOWN
    elif binding_res == INFERRED or (op_edge is not None and op_edge.resolution == INFERRED) or provenance == "unknown" or delegates:
        resolution = INFERRED
    return {
        "id": short_id("path", key),
        "key": key,
        "classification": cls,
        "severity": severity,
        "resolution": resolution,
        "entry": entry,
        "entry_kind": entry_kind,
        "entry_name": g.nodes[entry].name if entry else None,
        "agent": entry if entry_kind == "agent" else None,
        "tool": tool_id,
        "tool_name": tool.name,
        "operation": op_edge.target if op_edge else None,
        "operation_category": a.get("operation_category"),
        "operation_callee": op_node.attributes.get("callee") if op_node else None,
        "operation_target": a.get("target"),
        "operation_target_kind": a.get("target_kind"),
        "target_controlled": bool(a.get("target_controlled")),
        "content_controlled": bool(a.get("content_controlled")),
        "controlling_params": a.get("controlling_params", []),
        "content_params": a.get("content_params", []),
        "guard_status": guard,
        "guard_kind": a.get("guard_kind") if guard != GUARD_NA else None,
        "untrusted_privileged_input": untrusted,
        "untrusted_sources": sorted({e.attributes.get("source_kind", "") for e in untrusted_edges}),
        "user_role_untrusted_input": bool(user_edges),
        "instructions_provenance": provenance,
        "via": a.get("via", []),
        "delegation": [g.nodes[d].name for d in delegates],
        "nodes": nodes,
        "edges": [{"source": e.source, "target": e.target, "type": e.type, "resolution": e.resolution} for e in edges],
        "exposure_reason": _reason(cls, a, untrusted, entry_kind),
        "unknowns": unknowns,
        "evidence": _ev(edges),
        "remediation": REMEDIATION.get(a.get("operation_category", ""), "Review the tool implementation and binding manually."),
        "statements": {"static_possible": cls in (POTENTIALLY_EXPOSED, OPERATION_PATH), "runtime_observed": False, "authorization_verified": False},
    }


def compute_paths(g: EvidenceGraph) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    bound_tools: set[str] = set()
    for agent in g.nodes_of("agent"):
        untrusted_edges = g.in_edges(agent.id, "CROSSES_TRUST_BOUNDARY")
        user_edges = [e for e in g.in_edges(agent.id, "FLOWS_TO") if e.attributes.get("role") == "user_message"]
        provenance = agent.attributes.get("instructions_provenance", "unknown")
        chains: list[tuple[list[Edge], str]] = [([e], e.target) for e in g.out_edges(agent.id, "BINDS_TOOL")]
        # follow delegation (handoffs / as_tool) up to MAX_DELEGATION hops, cycle-safe
        frontier: list[tuple[list[Edge], str]] = [([], agent.id)]
        seen = {agent.id}
        for _hop in range(MAX_DELEGATION):
            nxt = []
            for prefix, src in frontier:
                for d in g.out_edges(src, "DELEGATES_TO"):
                    if d.target in seen:
                        continue
                    seen.add(d.target)
                    pre = prefix + [d]
                    chains += [(pre + [e], e.target) for e in g.out_edges(d.target, "BINDS_TOOL")]
                    for c in g.out_edges(d.target, "CONNECTS_MCP"):
                        chains += [(pre + [c, e], e.target) for e in g.out_edges(c.target, "EXPOSES_TOOL")]
                    nxt.append((pre, d.target))
            frontier = nxt
        for c in g.out_edges(agent.id, "CONNECTS_MCP"):
            exposed = g.out_edges(c.target, "EXPOSES_TOOL")
            if not exposed:
                server = g.nodes[c.target]
                paths.append(_unknown_server_path(g, agent.id, c, server.attributes.get("reason", "MCP server tools not statically resolvable")))
            for e in exposed:
                chains.append(([c, e], e.target))
        for chain, tool_id in chains:
            bound_tools.add(tool_id)
            tool = g.nodes[tool_id]
            op_edges = g.out_edges(tool_id, "REACHES_OPERATION")
            if tool.resolution in (UNKNOWN, UNSUPPORTED):
                paths.append(_make_path(g, agent.id, "agent", chain, tool_id, None, untrusted_edges, user_edges, provenance, True))
                continue
            for oe in op_edges:
                paths.append(_make_path(g, agent.id, "agent", chain, tool_id, oe, untrusted_edges, user_edges, provenance, True))
    for server in g.nodes_of("mcp_server"):
        for e in g.out_edges(server.id, "EXPOSES_TOOL"):
            bound_tools.add(e.target)
            for oe in g.out_edges(e.target, "REACHES_OPERATION"):
                paths.append(_make_path(g, server.id, "mcp_server", [e], e.target, oe, [], [], "not_applicable", True))
    for tool in g.nodes_of("tool"):
        if tool.id in bound_tools:
            continue
        for oe in g.out_edges(tool.id, "REACHES_OPERATION"):
            paths.append(_make_path(g, None, "none", [], tool.id, oe, [], [], "not_applicable", False))
    uniq = {p["key"]: p for p in paths}
    return [uniq[k] for k in sorted(uniq)]


def _unknown_server_path(g: EvidenceGraph, agent_id: str, edge: Edge, reason: str) -> dict[str, Any]:
    key = f"{agent_id}|{edge.target}|-|"
    return {
        "id": short_id("path", key),
        "key": key,
        "classification": PATH_UNKNOWN,
        "severity": "info",
        "resolution": UNKNOWN,
        "entry": agent_id,
        "entry_kind": "agent",
        "entry_name": g.nodes[agent_id].name,
        "agent": agent_id,
        "tool": None,
        "tool_name": None,
        "operation": None,
        "operation_category": None,
        "operation_callee": None,
        "operation_target": None,
        "operation_target_kind": None,
        "target_controlled": False,
        "content_controlled": False,
        "controlling_params": [],
        "content_params": [],
        "guard_status": GUARD_NA,
        "untrusted_privileged_input": bool(g.in_edges(agent_id, "CROSSES_TRUST_BOUNDARY")),
        "untrusted_sources": [],
        "user_role_untrusted_input": False,
        "instructions_provenance": g.nodes[agent_id].attributes.get("instructions_provenance", "unknown"),
        "via": [],
        "nodes": [agent_id, edge.target],
        "edges": [{"source": edge.source, "target": edge.target, "type": edge.type, "resolution": edge.resolution}],
        "exposure_reason": "Agent connects to an MCP server whose tools are not statically resolvable from this repository.",
        "unknowns": [reason],
        "evidence": _ev([edge]),
        "remediation": "Pin the MCP server source in the repository or review its tools/list output separately.",
        "statements": {"static_possible": False, "runtime_observed": False, "authorization_verified": False},
    }
