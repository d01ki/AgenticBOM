from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "examples"


@pytest.fixture
def make_project(tmp_path: Path):
    """Create a throwaway project from {relative_path: source} and return its root."""

    def _make(files: dict[str, str | bytes], name: str = "proj") -> Path:
        root = tmp_path / name
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(textwrap.dedent(content), encoding="utf-8")
        return root

    return _make


def paths_by(report, **kw):
    return [p for p in report["paths"] if all(p.get(k) == v for k, v in kw.items())]
