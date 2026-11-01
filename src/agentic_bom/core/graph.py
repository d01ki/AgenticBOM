"""Typed evidence graph container with deterministic serialisation."""

from __future__ import annotations

from typing import Any, Iterable

from agentic_bom.core.models import Edge, Evidence, Node


class EvidenceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str, str, str], Edge] = {}

    # -- mutation -----------------------------------------------------------
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        for ev in node.evidence:
            if ev not in existing.evidence:
                existing.evidence.append(ev)
        for k, v in node.attributes.items():
            existing.attributes.setdefault(k, v)
        return existing

    def add_edge(self, edge: Edge) -> Edge:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise KeyError(f"edge endpoints must exist: {edge.source} -> {edge.target}")
        existing = self.edges.get(edge.ident)
        if existing is None:
            self.edges[edge.ident] = edge
            return edge
        for ev in edge.evidence:
            if ev not in existing.evidence:
                existing.evidence.append(ev)
        return existing

    # -- queries ------------------------------------------------------------
    def out_edges(self, node_id: str, type_: str | None = None) -> list[Edge]:
        return sorted(
            (e for e in self.edges.values() if e.source == node_id and (type_ is None or e.type == type_)),
            key=lambda e: e.ident,
        )

    def in_edges(self, node_id: str, type_: str | None = None) -> list[Edge]:
        return sorted(
            (e for e in self.edges.values() if e.target == node_id and (type_ is None or e.type == type_)),
            key=lambda e: e.ident,
        )

    def nodes_of(self, kind: str) -> list[Node]:
        return sorted((n for n in self.nodes.values() if n.kind == kind), key=lambda n: n.id)

    # -- serialisation ------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [self.nodes[k].to_dict() for k in sorted(self.nodes)],
            "edges": [self.edges[k].to_dict() for k in sorted(self.edges)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceGraph":
        g = cls()
        for n in data.get("nodes", []):
            g.add_node(
                Node(
                    id=n["id"],
                    kind=n["kind"],
                    name=n["name"],
                    evidence=[Evidence.from_dict(e) for e in n.get("evidence", [])],
                    attributes=dict(n.get("attributes", {})),
                    resolution=n.get("resolution", "confirmed_static"),
                )
            )
        for e in data.get("edges", []):
            g.add_edge(
                Edge(
                    source=e["source"],
                    target=e["target"],
                    type=e["type"],
                    evidence=[Evidence.from_dict(x) for x in e.get("evidence", [])],
                    resolution=e.get("resolution", "confirmed_static"),
                    scope=e.get("scope", "supported_python_pattern"),
                    confidence=e.get("confidence", 1.0),
                    attributes=dict(e.get("attributes", {})),
                    key=e.get("key", ""),
                )
            )
        return g


def merge_evidence(*groups: Iterable[Evidence]) -> list[Evidence]:
    seen: list[Evidence] = []
    for grp in groups:
        for ev in grp:
            if ev not in seen:
                seen.append(ev)
    return seen
