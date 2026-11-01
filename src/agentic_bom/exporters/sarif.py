"""SARIF 2.1.0 export with stable rule IDs and source locations."""

from __future__ import annotations

from typing import Any

from agentic_bom.analyzers.drift import RULES
from agentic_bom.core.evidence import sha256_text
from agentic_bom.core.models import TOOL_NAME, TOOL_VERSION

PATH_RULES = {
    "potentially_exposed": ("AEM-P001", "Potentially exposed sensitive operation path",
                            "Untrusted data reaches privileged instructions and a bound tool parameter controls a sensitive operation without a recognised guard."),
    "operation_path": ("AEM-P002", "Agent-reachable sensitive operation path",
                       "A bound tool parameter controls the target of a sensitive operation."),
    "bound_capability": ("AEM-P003", "Bound tool performs a sensitive operation",
                         "A bound tool performs a sensitive operation whose target is not parameter-controlled in the supported model."),
    "unknown": ("AEM-P004", "Unresolved capability path",
                "Dynamic binding, dispatch, or unsupported guard: the path could not be classified statically."),
}
LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note", "none": "none"}


def _loc(ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": ev["file"], "uriBaseId": "SRCROOT"},
            "region": {"startLine": max(1, ev["line_start"]), "endLine": max(1, ev["line_end"])},
        }
    }


def _primary(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ops = [e for e in evidence if ".sensitive-op." in e["detector_id"]]
    return ops[-1:] or evidence[:1]


def _rule(rule_id: str, name: str, desc: str) -> dict[str, Any]:
    return {"id": rule_id, "name": name.replace(" ", ""), "shortDescription": {"text": name}, "fullDescription": {"text": desc}}


def _run(rules: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION, "rules": rules}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "./"}},
            "results": results,
        }],
    }


def scan_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules = [_rule(*v) for v in PATH_RULES.values()]
    results = []
    for p in report["paths"]:
        if p["classification"] not in PATH_RULES:
            continue
        rid = PATH_RULES[p["classification"]][0]
        ev = p["evidence"]
        prim = _primary(ev)
        if not prim:
            continue
        results.append({
            "ruleId": rid,
            "level": LEVEL.get(p["severity"], "note"),
            "message": {"text": f"{p.get('entry_name') or 'unbound'} -> {p.get('tool_name')} -> {p.get('operation_callee') or '?'}: {p['exposure_reason']}"},
            "locations": [_loc(e) for e in prim],
            "relatedLocations": [dict(_loc(e), id=i, message={"text": e["detector_id"]}) for i, e in enumerate(ev) if e not in prim][:20],
            "partialFingerprints": {"aemPathKey/v1": sha256_text(p["key"])[:32]},
            "properties": {"classification": p["classification"], "resolution": p["resolution"], "guard_status": p["guard_status"],
                           "unknowns": p["unknowns"], "runtime_observed": False, "authorization_verified": False},
        })
    return _run(rules, results)


def drift_to_sarif(drift: dict[str, Any]) -> dict[str, Any]:
    rules = [_rule(rid, title, title) for rid, title in RULES.values()]
    results = []
    for f in drift["findings"]:
        side = f.get("new") or f.get("old") or {}
        ev = side.get("evidence") or []
        prim = _primary(ev) if ev else []
        res = {
            "ruleId": f["rule_id"],
            "level": LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['message']} [BOM: {f['bom_delta']}; security: {f['security_delta']}]"},
            "partialFingerprints": {"aemFinding/v1": f["id"]},
            "properties": {"kind": f["kind"], "gate_eligible": f["gate_eligible"], "finding_id": f["id"]},
        }
        if prim:
            res["locations"] = [_loc(e) for e in prim]
        results.append(res)
    return _run(rules, results)
