"""Benchmark harness: compare scan / drift output against manually annotated ground truth.

Reports per-category TP/FP/FN with explicit denominators. Categories with no
expected and no predicted items are reported as N/A, never as 100%.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from pathlib import Path
from typing import Any

from agentic_bom.analyzers.drift import diff_reports
from agentic_bom.scanner import scan

CATEGORIES = ("agents", "tools", "bindings", "paths")


def predicted_sets(report: dict[str, Any]) -> dict[str, set[tuple]]:
    nodes = {n["id"]: n for n in report["graph"]["nodes"]}
    edges = report["graph"]["edges"]
    agents = {(n["name"],) for n in nodes.values() if n["kind"] == "agent"}
    tools = {(n["name"],) for n in nodes.values() if n["kind"] == "tool" and n["resolution"] in ("confirmed_static", "inferred_limited")}
    bindings = set()
    for e in edges:
        if e["type"] == "BINDS_TOOL" and nodes[e["target"]]["resolution"] in ("confirmed_static", "inferred_limited"):
            bindings.add((nodes[e["source"]]["name"], nodes[e["target"]]["name"]))
        if e["type"] == "CONNECTS_MCP":
            for e2 in edges:
                if e2["type"] == "EXPOSES_TOOL" and e2["source"] == e["target"]:
                    bindings.add((nodes[e["source"]]["name"], nodes[e2["target"]]["name"]))
    paths = set()
    unknown = set()
    for p in report["paths"]:
        entry = p.get("entry_name") or "-"
        if p["classification"] == "unknown":
            unknown.add((entry, p.get("tool_name") or "-"))
        else:
            paths.add((entry, p.get("tool_name"), p.get("operation_category"), p["classification"]))
    return {"agents": agents, "tools": tools, "bindings": bindings, "paths": paths, "unknown": unknown}


def _prf(tp: int, fp: int, fn: int) -> dict[str, Any]:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = (2 * p * r / (p + r)) if p is not None and r is not None and (p + r) else (None if p is None or r is None else 0.0)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def _fmt(x: float | None) -> str:
    return "N/A" if x is None else f"{x:.2f}"


def evaluate_scan(report: dict[str, Any], gt: dict[str, Any]) -> dict[str, Any]:
    pred = predicted_sets(report)
    exp = {
        "agents": {(a,) for a in gt.get("agents", [])},
        "tools": {(t,) for t in gt.get("tools", [])},
        "bindings": {tuple(b) for b in gt.get("bindings", [])},
        "paths": {tuple(p) for p in gt.get("paths", [])},
    }
    expected_unknowns = {tuple(u) for u in gt.get("expected_unknowns", [])}
    out: dict[str, Any] = {}
    for c in CATEGORIES:
        tp = pred[c] & exp[c]
        fp = pred[c] - exp[c]
        fn = exp[c] - pred[c]
        out[c] = {**_prf(len(tp), len(fp), len(fn)), "fp_items": sorted(map(list, fp)), "fn_items": sorted(map(list, fn))}
    # unknown handling: declared-unknown on an expected-unknown construct is the desired behaviour
    correct_unknown = pred["unknown"] & expected_unknowns
    out["unknowns"] = {
        "expected": len(expected_unknowns),
        "reported_on_expected": len(correct_unknown),
        "missing": sorted(map(list, expected_unknowns - pred["unknown"])),
        "unexpected": sorted(map(list, pred["unknown"] - expected_unknowns)),
    }
    return out


def evaluate_drift(drift: dict[str, Any], gt: dict[str, Any]) -> dict[str, Any]:
    pred = {(f["kind"], f.get("subject_name") or "") for f in drift["findings"]}
    exp = {tuple(x) for x in gt.get("findings", [])}
    tp, fp, fn = pred & exp, pred - exp, exp - pred
    res = {**_prf(len(tp), len(fp), len(fn)), "fp_items": sorted(map(list, fp)), "fn_items": sorted(map(list, fn))}
    if "bom_delta" in gt:
        res["bom_delta_expected"] = gt["bom_delta"]
        res["bom_delta_actual"] = drift["bom_delta"]["status"]
        res["bom_delta_correct"] = gt["bom_delta"] == drift["bom_delta"]["status"]
    return res


def _measure(fn, *args, **kw):
    tracemalloc.start()
    t0 = time.perf_counter()
    try:
        res = fn(*args, **kw)
    finally:
        dur = time.perf_counter() - t0
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return res, dur, peak


def run_corpus(corpus_path: Path, out_dir: Path) -> dict[str, Any]:
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    base_dir = (corpus_path.parent / corpus.get("base_dir", ".")).resolve()
    cases_out = []
    agg = {c: [0, 0, 0] for c in CATEGORIES}
    dagg = [0, 0, 0]
    durations, peaks = [], []
    unk_exp = unk_ok = 0
    all_ran = True
    for case in corpus["cases"]:
        gt = json.loads((base_dir / case["ground_truth"]).read_text(encoding="utf-8"))
        rec: dict[str, Any] = {"id": case["id"], "type": case["type"], "label": case.get("label", "")}
        try:
            if case["type"] == "scan":
                rep, dur, peak = _measure(scan, base_dir / case["path"], label=case["id"])
                ev = evaluate_scan(rep, gt)
                for c in CATEGORIES:
                    for i, k in enumerate(("tp", "fp", "fn")):
                        agg[c][i] += ev[c][k]
                unk_exp += ev["unknowns"]["expected"]
                unk_ok += ev["unknowns"]["reported_on_expected"]
                rec.update({"eval": ev, "unsupported_or_unknown_constructs": len(rep["coverage"]["unknowns"])})
            else:
                def _drift():
                    b = scan(base_dir / case["base"], label=case["id"])
                    h = scan(base_dir / case["head"], label=case["id"])
                    return diff_reports(b, h, "base", "head")
                drift, dur, peak = _measure(_drift)
                ev = evaluate_drift(drift, gt)
                for i, k in enumerate(("tp", "fp", "fn")):
                    dagg[i] += ev[k]
                rec["eval"] = ev
            rec.update({"seconds": round(dur, 4), "peak_bytes": peak, "ok": True})
            durations.append(dur)
            peaks.append(peak)
        except Exception as exc:  # benchmark must report, not hide, crashes
            all_ran = False
            rec.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        cases_out.append(rec)
    summary = {c: _prf(*agg[c]) for c in CATEGORIES}
    summary["drift_findings"] = _prf(*dagg)
    summary["expected_unknowns"] = {"expected": unk_exp, "reported_as_unknown": unk_ok}
    durations.sort()
    summary["median_case_seconds"] = round(durations[len(durations) // 2], 4) if durations else None
    summary["max_peak_bytes"] = max(peaks) if peaks else None
    result = {"corpus": corpus.get("name", corpus_path.name), "cases": cases_out, "summary": summary, "all_cases_ran": all_ran,
              "caveats": corpus.get("caveats", [])}
    result["markdown"] = to_markdown(result)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps({k: v for k, v in result.items() if k != "markdown"}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "latest.md").write_text(result["markdown"], encoding="utf-8")
    return result


def to_markdown(r: dict[str, Any]) -> str:
    s = r["summary"]
    lines = [f"# Benchmark: {r['corpus']}", ""]
    for c in r.get("caveats", []):
        lines.append(f"> {c}")
    lines += ["", "| Category | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
    for c in CATEGORIES + ("drift_findings",):
        m = s[c]
        lines.append(f"| {c} | {m['tp']} | {m['fp']} | {m['fn']} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} |")
    eu = s["expected_unknowns"]
    lines += ["", f"Expected-unknown constructs reported as `unknown`: {eu['reported_as_unknown']} / {eu['expected']}",
              f"Median case duration: {s['median_case_seconds']} s · max traced peak memory: {s['max_peak_bytes']} bytes", "",
              "## Cases", "", "| Case | Type | Label | OK | Notes |", "|---|---|---|---|---|"]
    for c in r["cases"]:
        notes = []
        ev = c.get("eval", {})
        if c["type"] == "scan" and ev:
            for cat in CATEGORIES:
                if ev[cat]["fp_items"]:
                    notes.append(f"FP {cat}: {ev[cat]['fp_items']}")
                if ev[cat]["fn_items"]:
                    notes.append(f"FN {cat}: {ev[cat]['fn_items']}")
            if ev["unknowns"]["missing"]:
                notes.append(f"missing unknowns: {ev['unknowns']['missing']}")
            if ev["unknowns"]["unexpected"]:
                notes.append(f"unexpected unknowns: {ev['unknowns']['unexpected']}")
        elif ev:
            if ev["fp_items"]:
                notes.append(f"FP: {ev['fp_items']}")
            if ev["fn_items"]:
                notes.append(f"FN: {ev['fn_items']}")
            if "bom_delta_correct" in ev:
                notes.append(f"BOM delta {ev['bom_delta_actual']} (expected {ev['bom_delta_expected']})")
        if not c.get("ok"):
            notes.append(c.get("error", "error"))
        lines.append(f"| {c['id']} | {c['type']} | {c['label']} | {'yes' if c.get('ok') else 'NO'} | {'; '.join(notes) or '—'} |")
    return "\n".join(lines) + "\n"
