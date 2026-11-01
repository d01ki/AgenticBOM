"""Write report artefacts deterministically (sorted keys, stable ordering, no timestamps)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentic_bom.exporters.agentic_bom import to_agentic_bom
from agentic_bom.exporters.html import render_html
from agentic_bom.exporters.sarif import drift_to_sarif, scan_to_sarif
from agentic_bom.schema import validate


def _write(path: Path, text: str) -> None:
    # fixed "\n" newlines so artefacts are byte-identical across platforms
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _dump(path: Path, data: Any) -> None:
    _write(path, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def capability_graph_doc(report: dict[str, Any]) -> dict[str, Any]:
    return {k: report[k] for k in ("schema_version", "tool", "scope", "graph", "paths", "coverage", "summary")}


def write_scan(report: dict[str, Any], out: Path, html: bool = True, retest: str | None = None, do_validate: bool = True) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    bom = to_agentic_bom(report)
    graph = capability_graph_doc(report)
    if do_validate:
        validate(bom, "agentic-bom")
        validate(graph, "capability-graph")
    files = {"agentic_bom": out / "agentic-bom.json", "capability_graph": out / "capability-graph.json", "sarif": out / "findings.sarif"}
    _dump(files["agentic_bom"], bom)
    _dump(files["capability_graph"], graph)
    _dump(files["sarif"], scan_to_sarif(report))
    if html:
        files["html"] = out / "report.html"
        _write(files["html"], render_html(report, None, retest or f"agentic-bom scan {report['scope']['label']} --out out/"))
    return files


def write_diff(base: dict[str, Any], head: dict[str, Any], drift: dict[str, Any], out: Path, html: bool = True,
               retest: str | None = None, do_validate: bool = True) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for side, rep in (("base", base), ("head", head)):
        d = out / side
        d.mkdir(exist_ok=True)
        files.update({f"{side}_{k}": v for k, v in write_scan(rep, d, html=False, do_validate=do_validate).items()})
    if do_validate:
        validate(drift, "security-drift")
    files["drift"] = out / "security-drift.json"
    _dump(files["drift"], drift)
    files["sarif"] = out / "findings.sarif"
    _dump(files["sarif"], drift_to_sarif(drift))
    if html:
        files["html"] = out / "report.html"
        _write(files["html"], render_html(head, drift, retest or "agentic-bom diff <baseline> <candidate> --out out/"))
    return files
