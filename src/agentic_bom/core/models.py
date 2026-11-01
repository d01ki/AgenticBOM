"""Schema-first data model for the typed evidence graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentic_bom import __version__

SCHEMA_VERSION = "0.1.0"
TOOL_NAME = "agentic-exposure-mapper"
TOOL_VERSION = __version__

NODE_KINDS = frozenset(
    {
        "application",
        "agent",
        "model",
        "prompt",
        "mcp_client",
        "mcp_server",
        "tool",
        "skill",
        "data_source",
        "operation",
        "resource",
        "package",
        "trust_boundary",
        "identity_reference",
    }
)

EDGE_KINDS = frozenset(
    {
        "USES_MODEL",
        "BINDS_TOOL",
        "CALLS_TOOL",
        "EXPOSES_TOOL",
        "USES_SKILL",
        "READS_FROM",
        "WRITES_TO",
        "REACHES_OPERATION",
        "FLOWS_TO",
        "CROSSES_TRUST_BOUNDARY",
        "DELEGATES_TO",
        "REFERENCES_IDENTITY",
        # Extension (documented in docs/architecture.md): agent -> MCP server connection.
        "CONNECTS_MCP",
    }
)

# resolution enum. A numeric confidence never upgrades UNKNOWN to CONFIRMED.
CONFIRMED = "confirmed_static"
INFERRED = "inferred_limited"
UNKNOWN = "unknown"
UNSUPPORTED = "unsupported"
RESOLUTIONS = (CONFIRMED, INFERRED, UNKNOWN, UNSUPPORTED)

# Path classifications (design §7).
INVENTORY_ONLY = "inventory_only"
BOUND_CAPABILITY = "bound_capability"
OPERATION_PATH = "operation_path"
POTENTIALLY_EXPOSED = "potentially_exposed"
PATH_UNKNOWN = "unknown"
PATH_CLASSES = (INVENTORY_ONLY, BOUND_CAPABILITY, OPERATION_PATH, POTENTIALLY_EXPOSED, PATH_UNKNOWN)
PATH_RANK = {INVENTORY_ONLY: 0, BOUND_CAPABILITY: 1, OPERATION_PATH: 2, POTENTIALLY_EXPOSED: 3}

GUARD_KNOWN = "known"
GUARD_ABSENT = "absent"
GUARD_UNKNOWN = "unknown"
GUARD_NA = "not_applicable"

SEVERITY_ORDER = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4}


@dataclass(frozen=True)
class Evidence:
    file: str
    line_start: int
    line_end: int
    detector_id: str
    note: str = ""
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "detector_id": self.detector_id,
        }
        if self.note:
            d["note"] = self.note
        if self.snippet:
            d["snippet"] = self.snippet
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(
            file=d["file"],
            line_start=d["line_start"],
            line_end=d["line_end"],
            detector_id=d["detector_id"],
            note=d.get("note", ""),
            snippet=d.get("snippet", ""),
        )


@dataclass
class Node:
    id: str
    kind: str
    name: str
    evidence: list[Evidence] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    resolution: str = CONFIRMED

    def __post_init__(self) -> None:
        if self.kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind {self.kind!r}")
        if self.resolution not in RESOLUTIONS:
            raise ValueError(f"unknown resolution {self.resolution!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "resolution": self.resolution,
            "attributes": self.attributes,
            "evidence": [e.to_dict() for e in sorted(set(self.evidence), key=_ev_key)],
        }


@dataclass
class Edge:
    source: str
    target: str
    type: str
    evidence: list[Evidence] = field(default_factory=list)
    resolution: str = CONFIRMED
    scope: str = "supported_python_pattern"
    confidence: float = 1.0
    attributes: dict[str, Any] = field(default_factory=dict)
    key: str = ""  # disambiguates parallel edges (e.g. different helper chains)

    def __post_init__(self) -> None:
        if self.type not in EDGE_KINDS:
            raise ValueError(f"unknown edge type {self.type!r}")
        if self.resolution not in RESOLUTIONS:
            raise ValueError(f"unknown resolution {self.resolution!r}")
        if self.resolution in (UNKNOWN, UNSUPPORTED) and self.confidence > 0.5:
            # Guard rail: a numeric confidence must never make "unknown" look confirmed.
            self.confidence = 0.0

    @property
    def ident(self) -> tuple[str, str, str, str]:
        return (self.source, self.target, self.type, self.key)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "evidence": [e.to_dict() for e in sorted(set(self.evidence), key=_ev_key)],
            "resolution": self.resolution,
            "scope": self.scope,
            "confidence": self.confidence,
            "attributes": self.attributes,
        }
        if self.key:
            d["key"] = self.key
        return d


def _ev_key(e: Evidence) -> tuple:
    return (e.file, e.line_start, e.line_end, e.detector_id, e.note)
