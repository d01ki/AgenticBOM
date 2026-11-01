import pytest

from agentic_bom.core.evidence import REDACTED, redact, redact_target
from agentic_bom.core.graph import EvidenceGraph
from agentic_bom.core.models import Edge, Node


def test_unknown_edge_can_never_carry_high_confidence():
    e = Edge("a", "b", "BINDS_TOOL", resolution="unknown", confidence=1.0)
    assert e.confidence == 0.0


def test_invalid_kinds_rejected():
    with pytest.raises(ValueError):
        Node("x", "not_a_kind", "x")
    with pytest.raises(ValueError):
        Edge("a", "b", "NOT_AN_EDGE")


def test_graph_roundtrip_is_stable():
    g = EvidenceGraph()
    g.add_node(Node("agent:a", "agent", "a"))
    g.add_node(Node("tool:t", "tool", "t"))
    g.add_edge(Edge("agent:a", "tool:t", "BINDS_TOOL"))
    d = g.to_dict()
    assert EvidenceGraph.from_dict(d).to_dict() == d


def test_edges_require_existing_nodes():
    g = EvidenceGraph()
    with pytest.raises(KeyError):
        g.add_edge(Edge("a", "b", "BINDS_TOOL"))


@pytest.mark.parametrize("secret", [
    "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    "AKIAABCDEFGHIJKLMNOP",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-1234567890-abcdefghij",
])
def test_redact_known_token_shapes(secret):
    assert secret not in redact(f"token is {secret} ok")


def test_redact_assignment_and_url_parts():
    assert redact('password="hunter22"') == f'password="{REDACTED}"'
    assert redact_target("https://user:pw@example.com/path?key=abc") == "https://example.com/path"
