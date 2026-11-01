"""Security-semantic drift between two scans of the same application.

Identity is line-independent: graph IDs are built from path + qualified symbol
+ component kind (+ per-function callee ordinal for operations).
"""

from __future__ import annotations

from typing import Any

from agentic_bom.core.evidence import short_id
from agentic_bom.core.models import (
    BOUND_CAPABILITY,
    CONFIRMED,
    INVENTORY_ONLY,
    OPERATION_PATH,
    PATH_RANK,
    PATH_UNKNOWN,
    POTENTIALLY_EXPOSED,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    TOOL_NAME,
    TOOL_VERSION,
)

RULES = {
    "new_bound_sensitive_operation": ("AEM-D001", "New agent-reachable sensitive operation"),
    "new_untrusted_to_privileged_path": ("AEM-D002", "Untrusted data newly reaches privileged instructions"),
    "operation_target_expanded": ("AEM-D003", "Operation target expanded to tool-parameter control"),
    "tool_contract_changed": ("AEM-D004", "Tool contract changed (same tool identity)"),
    "capability_removed": ("AEM-D005", "Exposure reduced / capability removed"),
    "review_required": ("AEM-D006", "Unresolved change requires manual review"),
}
GUIDANCE = {
    "new_bound_sensitive_operation": "Confirm the agent should be able to trigger this operation; constrain the parameter (allowlist) or unbind the tool. Re-run `agentic-bom diff` to verify.",
    "new_untrusted_to_privileged_path": "Keep untrusted data in the user-role message (Runner input), not in instructions. Re-run `agentic-bom diff` to verify the path is gone.",
    "operation_target_expanded": "Restore a fixed target or validate the parameter against an allowlist before the operation.",
    "tool_contract_changed": "Review the new description/schema as model-visible instructions; confirm new parameters do not reach sensitive operations.",
    "capability_removed": "No action needed; keep as fix-verification evidence.",
    "review_required": "Resolve the dynamic binding/guard manually; the tool does not classify unresolved constructs as safe or critical.",
}

BOM_KINDS = ("agent", "model", "tool", "mcp_server", "package", "skill")
BOM_FIELDS = {
    "agent": ("name", "framework", "model"),
    "model": ("name",),
    "tool": ("name", "framework"),
    "mcp_server": ("name", "transport", "command"),
    "package": ("version_spec",),
    "skill": ("name",),
}


def bom_inventory(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    inv: dict[str, dict[str, Any]] = {}
    for n in report["graph"]["nodes"]:
        if n["kind"] not in BOM_KINDS:
            continue
        rec: dict[str, Any] = {"kind": n["kind"]}
        for f in BOM_FIELDS[n["kind"]]:
            rec[f] = n["name"] if f == "name" else n["attributes"].get(f)
        inv[n["id"]] = rec
    return inv


def bom_delta(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    a, b = bom_inventory(base), bom_inventory(head)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    modified = []
    for k in sorted(set(a) & set(b)):
        for f in a[k]:
            if a[k].get(f) != b[k].get(f):
                modified.append({"id": k, "field": f, "old": a[k].get(f), "new": b[k].get(f)})
    status = "unchanged" if not (added or removed or modified) else "changed"
    return {
        "status": status,
        "added": added,
        "removed": removed,
        "modified": modified,
        "compared": "component inventory: agents, models, tools (identity/name/framework), MCP servers, packages. Prompt text and tool contracts are compared separately.",
    }


def _path_summary(p: dict[str, Any] | None) -> dict[str, Any] | None:
    if p is None:
        return None
    keys = ("id", "key", "classification", "severity", "resolution", "agent", "entry", "entry_kind", "entry_name", "tool", "tool_name", "operation", "operation_category",
            "operation_callee", "operation_target", "operation_target_kind", "target_controlled", "controlling_params", "content_params", "guard_status",
            "untrusted_privileged_input", "instructions_provenance", "via", "evidence", "unknowns", "exposure_reason", "remediation")
    return {k: p.get(k) for k in keys}


def _finding(kind: str, severity: str, key: str, message: str, bom: str, security_delta: str, old: Any, new: Any,
             gate_eligible: bool, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    rule_id, title = RULES[kind]
    f = {
        "id": short_id("AEM", rule_id, key),
        "rule_id": rule_id,
        "kind": kind,
        "title": title,
        "severity": severity,
        "message": message,
        "subject": key,
        "subject_name": (new or {}).get("tool_name") or (old or {}).get("tool_name"),
        "bom_delta": bom,
        "security_delta": security_delta,
        "old": old,
        "new": new,
        "guidance": GUIDANCE[kind],
        "gate_eligible": gate_eligible,
    }
    if extra:
        f.update(extra)
    return f


def _slot(p: dict[str, Any]) -> tuple | None:
    op = p.get("operation")
    if not op or not p.get("tool"):
        return None
    return (p.get("entry"), tuple(p.get("delegation") or []), p.get("tool"), p.get("operation_category"), op.rsplit(":", 1)[0])


def _sev_for_new(p: dict[str, Any]) -> str:
    c = p["classification"]
    if c == POTENTIALLY_EXPOSED:
        return "high"
    if c == OPERATION_PATH:
        return "low" if p.get("guard_status") == "known" else "medium"
    return "low"


def _label(p: dict[str, Any]) -> str:
    who = p.get("entry_name") or "unbound tool"
    if p.get("entry_kind") == "mcp_server":
        who = f"MCP server '{who}'"
    return f"{who} → {p.get('tool_name')} → {p.get('operation_callee')}"


def diff_reports(base: dict[str, Any], head: dict[str, Any], base_label: str = "baseline", head_label: str = "candidate") -> dict[str, Any]:
    bd = bom_delta(base, head)
    bstat = bd["status"]
    findings: list[dict[str, Any]] = []
    bp = {p["key"]: p for p in base["paths"]}
    hp = {p["key"]: p for p in head["paths"]}
    matched = [(k, k) for k in sorted(set(bp) & set(hp))]
    # Same capability slot (entry, delegation, tool, category, enclosing function) with a changed callee
    # (e.g. exec -> execFile) is one path that changed, not one removed + one new.
    only_old = {k: _slot(bp[k]) for k in set(bp) - set(hp)}
    only_new = {k: _slot(hp[k]) for k in set(hp) - set(bp)}
    for slot in sorted({s for s in only_old.values() if s} & {s for s in only_new.values() if s}, key=str):
        olds = [k for k, s in only_old.items() if s == slot]
        news = [k for k, s in only_new.items() if s == slot]
        if len(olds) == 1 and len(news) == 1:
            matched.append((olds[0], news[0]))
    paired_old = {o for o, _n in matched}
    paired_new = {n for _o, n in matched}

    for k in sorted(set(hp) - paired_new):
        p = hp[k]
        c = p["classification"]
        if c == INVENTORY_ONLY:
            continue
        if c == PATH_UNKNOWN:
            findings.append(_finding("review_required", "info", k, f"New unresolved path: {_label(p)} ({'; '.join(p['unknowns'])})",
                                     bstat, f"new {c} path", None, _path_summary(p), False))
            continue
        sev = _sev_for_new(p)
        findings.append(_finding(
            "new_bound_sensitive_operation", sev, k,
            f"New {c} path: {_label(p)} [{p.get('operation_category')}]",
            bstat, f"absent → {c}", None, _path_summary(p),
            gate_eligible=p["resolution"] == CONFIRMED,
        ))
    for k in sorted(set(bp) - paired_old):
        p = bp[k]
        if p["classification"] == INVENTORY_ONLY:
            continue
        findings.append(_finding("capability_removed", "info", k, f"Path removed: {_label(p)} (was {p['classification']})",
                                 bstat, f"{p['classification']} → absent", _path_summary(p), None, False))
    for ko, k in sorted(matched):
        o, n = bp[ko], hp[k]
        oc, nc = o["classification"], n["classification"]
        if nc == PATH_UNKNOWN and oc != PATH_UNKNOWN:
            findings.append(_finding("review_required", "info", k, f"Path became unresolved: {_label(n)}", bstat, f"{oc} → unknown",
                                     _path_summary(o), _path_summary(n), False))
            continue
        if oc == PATH_UNKNOWN or nc == PATH_UNKNOWN:
            continue
        if not o["target_controlled"] and n["target_controlled"]:
            findings.append(_finding("operation_target_expanded", _sev_for_new(n), k,
                                     f"Target of {n.get('operation_callee')} is now controlled by tool parameter(s) {', '.join(n['controlling_params'])}: {_label(n)}",
                                     bstat, f"{o.get('operation_target_kind')} target → parameter-controlled ({nc})", _path_summary(o), _path_summary(n),
                                     gate_eligible=n["resolution"] == CONFIRMED))
        elif PATH_RANK.get(nc, 0) > PATH_RANK.get(oc, 0):
            findings.append(_finding("new_bound_sensitive_operation", _sev_for_new(n), k, f"Path escalated {oc} → {nc}: {_label(n)}",
                                     bstat, f"{oc} → {nc}", _path_summary(o), _path_summary(n), gate_eligible=n["resolution"] == CONFIRMED))
        elif PATH_RANK.get(nc, 0) < PATH_RANK.get(oc, 0) or (o.get("guard_status") != "known" and n.get("guard_status") == "known"):
            findings.append(_finding("capability_removed", "info", k, f"Exposure reduced {oc} → {nc}: {_label(n)}",
                                     bstat, f"{oc} → {nc}" + (" (guard added)" if n.get("guard_status") == "known" else ""),
                                     _path_summary(o), _path_summary(n), False))

    findings += _trust_flow_changes(base, head, bstat)
    findings += _contract_changes(base, head, bstat)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["rule_id"], f["subject"]))

    new_paths = [f for f in findings if f["kind"] in ("new_bound_sensitive_operation", "operation_target_expanded") and f["new"]]
    n_pe = sum(1 for f in new_paths if f["new"]["classification"] == POTENTIALLY_EXPOSED)
    n_op = sum(1 for f in new_paths if f["new"]["classification"] == OPERATION_PATH)
    banner = None
    if n_pe or n_op:
        if bstat == "unchanged":
            head_txt = "Agentic BOM unchanged"
        else:
            head_txt = f"Agentic BOM changed (+{len(bd['added'])} / -{len(bd['removed'])} / ~{len(bd['modified'])})"
        if n_pe:
            banner = f"{head_txt} · {n_pe} new potential exposure path{'s' if n_pe != 1 else ''}"
        else:
            banner = f"{head_txt} · {n_op} new sensitive operation path{'s' if n_op != 1 else ''}"
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "base": {"label": base_label, "summary": base["summary"]},
        "head": {"label": head_label, "summary": head["summary"]},
        "bom_delta": bd,
        "banner": banner,
        "findings": findings,
        "counts": _counts(findings),
        "statement": "Drift is computed over static evidence graphs. 'potentially_exposed' is a static possibility, not proof of exploitation.",
    }


def _counts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"by_kind": {}, "by_severity": {}}
    for f in findings:
        out["by_kind"][f["kind"]] = out["by_kind"].get(f["kind"], 0) + 1
        out["by_severity"][f["severity"]] = out["by_severity"].get(f["severity"], 0) + 1
    return out


def _agents(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {n["id"]: n for n in report["graph"]["nodes"] if n["kind"] == "agent"}


def _trust_edges(report: dict[str, Any], agent_id: str) -> list[dict[str, Any]]:
    return [e for e in report["graph"]["edges"] if e["type"] == "CROSSES_TRUST_BOUNDARY" and e["target"] == agent_id]


def _trust_flow_changes(base: dict[str, Any], head: dict[str, Any], bstat: str) -> list[dict[str, Any]]:
    out = []
    ba, ha = _agents(base), _agents(head)
    for aid in sorted(set(ba) & set(ha)):
        op, np_ = ba[aid]["attributes"].get("instructions_provenance"), ha[aid]["attributes"].get("instructions_provenance")
        be, he = _trust_edges(base, aid), _trust_edges(head, aid)
        affected = [p["id"] for p in head["paths"] if p.get("agent") == aid and p["classification"] == POTENTIALLY_EXPOSED]
        if not be and he:
            sev = "high" if affected else "medium"
            out.append(_finding(
                "new_untrusted_to_privileged_path", sev, aid,
                f"Untrusted {', '.join(sorted({e['attributes'].get('source_kind', '?') for e in he}))} now flows into the privileged instructions of {ha[aid]['name']}",
                bstat, f"instructions provenance {op} → {np_}",
                {"instructions_provenance": op},
                {"instructions_provenance": np_, "evidence": [ev for e in he for ev in e["evidence"]], "affected_paths": affected},
                gate_eligible=all(e["resolution"] == CONFIRMED for e in he), extra={"subject_name": ha[aid]["name"]},
            ))
        elif be and not he:
            out.append(_finding("capability_removed", "info", aid + "#trust", f"Untrusted data no longer reaches the instructions of {ha[aid]['name']}",
                                bstat, f"instructions provenance {op} → {np_}", {"instructions_provenance": op}, {"instructions_provenance": np_}, False, extra={"subject_name": ha[aid]["name"]}))
        elif op != np_ and np_ == "unknown":
            out.append(_finding("review_required", "info", aid + "#trust", f"Instruction provenance of {ha[aid]['name']} became unresolved",
                                bstat, f"{op} → unknown", {"instructions_provenance": op}, {"instructions_provenance": np_}, False, extra={"subject_name": ha[aid]["name"]}))
    return out


def _contract_changes(base: dict[str, Any], head: dict[str, Any], bstat: str) -> list[dict[str, Any]]:
    out = []
    bt = {n["id"]: n for n in base["graph"]["nodes"] if n["kind"] == "tool" and "contract" in n["attributes"]}
    ht = {n["id"]: n for n in head["graph"]["nodes"] if n["kind"] == "tool" and "contract" in n["attributes"]}
    for tid in sorted(set(bt) & set(ht)):
        oc, nc = bt[tid]["attributes"]["contract"], ht[tid]["attributes"]["contract"]
        if oc["fingerprint"] == nc["fingerprint"]:
            continue
        changed = []
        if oc["description_sha256"] != nc["description_sha256"]:
            changed.append("description")
        op = {p["name"]: p for p in oc["parameters"]}
        np_ = {p["name"]: p for p in nc["parameters"]}
        added = sorted(set(np_) - set(op))
        removed = sorted(set(op) - set(np_))
        retyped = sorted(k for k in set(op) & set(np_) if op[k] != np_[k])
        if added or removed or retyped:
            changed.append("input_schema")
        if oc["annotations"] != nc["annotations"]:
            changed.append("annotations")
        if oc["name"] != nc["name"]:
            changed.append("name")
        head_paths = [p for p in head["paths"] if p.get("tool") == tid and p["classification"] in (OPERATION_PATH, POTENTIALLY_EXPOSED)]
        joined = [p for p in head_paths if set(p.get("controlling_params", [])) & set(added)]
        if joined:
            sev, gate = ("high" if any(p["classification"] == POTENTIALLY_EXPOSED for p in joined) else "medium"), True
            note = f"new parameter(s) {', '.join(added)} reach sensitive operation(s): " + "; ".join(_label(p) for p in joined)
        elif changed == ["description"]:
            sev, gate, note = "low", False, "description-only change: review_required (model-visible text changed; no source-confirmed security semantics)"
        else:
            sev, gate, note = "low", False, "contract changed; no new parameter reaches a recognised sensitive operation"
        out.append(_finding(
            "tool_contract_changed", sev, tid,
            f"Tool '{ht[tid]['name']}' contract changed ({', '.join(changed)}): {note}",
            bstat, "contract fingerprint changed",
            {"description": oc["description"], "parameters": oc["parameters"], "fingerprint": oc["fingerprint"]},
            {"description": nc["description"], "parameters": nc["parameters"], "fingerprint": nc["fingerprint"], "evidence": ht[tid]["evidence"]},
            gate_eligible=gate,
            extra={"subject_name": ht[tid]["name"], "changed_fields": changed, "parameters_added": added, "parameters_removed": removed, "parameters_changed": retyped,
                   "joined_paths": [p["id"] for p in joined], "review_status": "review_required" if not joined else "joined_to_operation_path"},
        ))
    return out


def gate(drift: dict[str, Any], threshold: str) -> list[dict[str, Any]]:
    if threshold == "none":
        return []
    t = SEVERITY_ORDER[threshold]
    return [f for f in drift["findings"] if f["gate_eligible"] and f["kind"] not in ("capability_removed", "review_required")
            and SEVERITY_ORDER.get(f["severity"], 0) >= t]
