"""Command-line interface: scan, diff, demo, benchmark, explain."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from agentic_bom import __version__
from agentic_bom.analyzers.drift import diff_reports, gate
from agentic_bom.core.models import SEVERITY_ORDER
from agentic_bom.core.safety import UnsafeInputError, export_git_revision, shallow_clone
from agentic_bom.exporters.writer import write_diff, write_scan
from agentic_bom.scanner import scan

SCENARIOS = ("same-bom-new-exposure", "mcp-tool-schema-drift")
LEVELS = ("none", "low", "medium", "high")
CLS_ORDER = ("potentially_exposed", "operation_path", "unknown", "bound_capability", "inventory_only")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_registry(path: str | None) -> list[str] | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("agents", [])
    return [str(x) for x in data]


def _resolve_target(target: str, ref: str | None) -> tuple[Path, str, Path | None]:
    """Return (local_path, label, temp_dir_to_cleanup)."""
    if target.startswith(("http://", "https://")):
        path = shallow_clone(target, ref)
        label = target.rstrip("/").removesuffix(".git").split("/")[-1]
        return path, label, path.parent
    p = Path(target)
    if not p.is_dir():
        raise UnsafeInputError(f"not a directory: {target}")
    return p, p.resolve().name, None


def _print_scan(report: dict[str, Any], files: dict[str, Path] | None = None) -> None:
    s = report["summary"]
    print(f"Agentic Security Exposure — {report['scope']['label']}")
    print(f"  agents: {s['agents']} (confirmed {s['agents_confirmed']}) · tools: {s['tools']} (bound {s['bound_tools']}) · "
          f"MCP servers: {s['mcp_servers']} · models: {s['models']} · packages: {s['packages']}")
    pbc = s["paths_by_classification"]
    print("  paths: " + (", ".join(f"{k}={pbc[k]}" for k in CLS_ORDER if k in pbc) or "none"))
    for p in sorted(report["paths"], key=lambda p: (CLS_ORDER.index(p["classification"]), p["key"])):
        if p["classification"] == "inventory_only":
            continue
        ev = [e for e in p["evidence"] if e["detector_id"].startswith("py.sensitive-op")] or p["evidence"]
        loc = f"{ev[-1]['file']}:{ev[-1]['line_start']}" if ev else "?"
        tool = p.get("tool_name") or "(tools not statically resolvable)"
        print(f"   [{p['classification']}/{p['severity']}] {p.get('entry_name') or 'unbound'} -> {tool} -> "
              f"{p.get('operation_callee') or '?'} ({loc}) guard={p['guard_status']}")
        for u in p["unknowns"]:
            print(f"       unknown: {u}")
    c = report["coverage"]
    if c["unsupported_languages_present"]:
        print("  not analysed (unsupported languages): " + ", ".join(f"{k}={v}" for k, v in c["unsupported_languages_present"].items()))
    if c["unknowns"]:
        print(f"  unknowns recorded: {len(c['unknowns'])} (see coverage)")
    if files:
        print("  wrote: " + ", ".join(str(v) for v in files.values()))


def _print_drift(drift: dict[str, Any], files: dict[str, Path] | None = None) -> None:
    bd = drift["bom_delta"]
    print(f"Compare {drift['base']['label']} -> {drift['head']['label']}")
    print(f"  Agentic BOM: {bd['status']}" + (f" (added {bd['added']}, removed {bd['removed']}, modified {len(bd['modified'])})" if bd["status"] != "unchanged" else ""))
    if drift["banner"]:
        print(f"  >>> {drift['banner']}")
    if not drift["findings"]:
        print("  no security-semantic changes detected within the supported scope")
    for f in drift["findings"]:
        print(f"   {f['id']} {f['rule_id']} [{f['severity']}] {f['kind']}: {f['message']}")
    if files:
        print("  wrote: " + ", ".join(str(v) for v in files.values()))


def cmd_scan(a: argparse.Namespace) -> int:
    path, label, tmp = _resolve_target(a.target, a.ref)
    try:
        report = scan(path, label=label, include_tests=a.include_tests, registry=_load_registry(a.registry), max_depth=a.max_depth)
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
    files = write_scan(report, Path(a.out), html=not a.no_html, retest=f"agentic-bom scan {a.target} --out {a.out}")
    _print_scan(report, files)
    if a.fail_on != "none":
        t = SEVERITY_ORDER[a.fail_on]
        hits = [p for p in report["paths"] if p["resolution"] == "confirmed_static" and SEVERITY_ORDER[p["severity"]] >= t
                and p["classification"] in ("potentially_exposed", "operation_path", "bound_capability")]
        if hits:
            print(f"GATE FAILED: {len(hits)} confirmed path(s) at or above '{a.fail_on}'")
            return 1
    return 0


def _side(path_or_rev: str, git_repo: str | None) -> tuple[Path, str, Path | None]:
    if git_repo:
        d = export_git_revision(Path(git_repo), path_or_rev)
        return d, path_or_rev, d
    p = Path(path_or_rev)
    if not p.is_dir():
        raise UnsafeInputError(f"not a directory: {path_or_rev}")
    return p, p.as_posix(), None


def cmd_diff(a: argparse.Namespace) -> int:
    bp, bl, bt = _side(a.base, a.git)
    hp, hl, ht = _side(a.head, a.git)
    try:
        app_label = Path(a.git).resolve().name if a.git else None
        base = scan(bp, label=app_label or Path(bp).resolve().name, include_tests=a.include_tests, max_depth=a.max_depth)
        head = scan(hp, label=app_label or Path(hp).resolve().name, include_tests=a.include_tests, max_depth=a.max_depth)
    finally:
        for t in (bt, ht):
            if t is not None:
                shutil.rmtree(t, ignore_errors=True)
    drift = diff_reports(base, head, bl, hl)
    retest = f"agentic-bom diff {a.base} {a.head}" + (f" --git {a.git}" if a.git else "") + f" --out {a.out}"
    files = write_diff(base, head, drift, Path(a.out), html=not a.no_html, retest=retest)
    _print_drift(drift, files)
    hits = gate(drift, a.fail_on)
    if hits:
        print(f"GATE FAILED: {len(hits)} gate-eligible finding(s) at or above '{a.fail_on}'")
        return 1
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    ex = Path(a.examples_dir) if a.examples_dir else _repo_root() / "examples"
    scenarios = SCENARIOS if a.scenario == "all" else (a.scenario,)
    for sc in scenarios:
        root = ex / sc
        if not root.is_dir():
            print(f"scenario directory not found: {root} (pass --examples-dir)", file=sys.stderr)
            return 2
        out = Path(a.out) / sc
        reps = {}
        print(f"=== Demo: {sc} (offline; scanned code is never executed)")
        for rev in ("baseline", "candidate", "fixed"):
            reps[rev] = scan(root / rev, label=sc)
            write_scan(reps[rev], out / "scans" / rev, html=not a.no_html, retest=f"agentic-bom scan {root / rev} --out {out / 'scans' / rev}")
            s = reps[rev]["summary"]
            print(f"--- scan {rev}: paths {s['paths_by_classification'] or '{}'}")
        for i, (b, h) in enumerate((("baseline", "candidate"), ("candidate", "fixed")), 1):
            drift = diff_reports(reps[b], reps[h], b, h)
            files = write_diff(reps[b], reps[h], drift, out / f"{i}-{b}-vs-{h}", html=not a.no_html,
                               retest=f"agentic-bom diff {root / b} {root / h} --out {out / f'{i}-{b}-vs-{h}'}")
            _print_drift(drift)
            if "html" in files:
                print(f"  report: {files['html']}")
        print()
    return 0


def cmd_benchmark(a: argparse.Namespace) -> int:
    from agentic_bom.benchmark import run_corpus

    corpus = Path(a.corpus)
    if not corpus.is_file():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2
    result = run_corpus(corpus, Path(a.out))
    print(result["markdown"])
    return 0 if result["all_cases_ran"] else 1


def cmd_explain(a: argparse.Namespace) -> int:
    data = json.loads(Path(a.report).read_text(encoding="utf-8"))
    items: list[dict[str, Any]] = data.get("findings") or []
    items += data.get("paths") or []
    match = [x for x in items if x.get("id") == a.finding_id or x.get("key") == a.finding_id]
    if not match:
        print(f"no finding/path with id {a.finding_id} in {a.report}", file=sys.stderr)
        return 2
    x = match[0]
    if "rule_id" in x:
        print(f"{x['id']}  {x['rule_id']}  {x['title']}  [{x['severity']}]")
        print(f"  {x['message']}")
        print(f"  BOM delta: {x['bom_delta']} · security delta: {x['security_delta']} · CI-gate eligible: {x['gate_eligible']}")
        for side in ("old", "new"):
            v = x.get(side)
            print(f"  {side}: " + ("absent" if not v else ""))
            if v:
                for k in ("classification", "instructions_provenance", "guard_status", "controlling_params", "operation_target"):
                    if v.get(k) not in (None, [], ""):
                        print(f"     {k}: {v[k]}")
                for u in v.get("unknowns") or []:
                    print(f"     unknown: {u}")
                for e in v.get("evidence") or []:
                    print(f"     evidence {e['file']}:{e['line_start']} [{e['detector_id']}] {e.get('snippet', '')}")
        print(f"  guidance: {x['guidance']}")
    else:
        print(f"{x['id']}  {x['classification']} [{x['severity']}] {x.get('entry_name')} -> {x.get('tool_name')} -> {x.get('operation_callee')}")
        print(f"  {x['exposure_reason']}")
        for u in x["unknowns"]:
            print(f"  unknown: {u}")
        for e in x["evidence"]:
            print(f"  evidence {e['file']}:{e['line_start']} [{e['detector_id']}] {e.get('snippet', '')}")
        print(f"  remediation: {x['remediation']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentic-bom", description="Agentic Exposure Mapper: static agent capability exposure & security drift (never executes scanned code).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a local directory or https://github.com/<owner>/<repo> URL")
    s.add_argument("target")
    s.add_argument("--out", default="out")
    s.add_argument("--ref", help="git branch/tag or full commit SHA (URL targets only)")
    s.add_argument("--include-tests", action="store_true", help="also analyse tests/ and test_*.py (excluded by default)")
    s.add_argument("--registry", help="JSON list of approved agent names/IDs for registration comparison")
    s.add_argument("--max-depth", type=int, default=3, help="max helper-call hops followed from a tool (default 3)")
    s.add_argument("--fail-on", choices=LEVELS, default="none")
    s.add_argument("--no-html", action="store_true")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("diff", help="compare two directories (or two git revisions with --git REPO)")
    d.add_argument("base")
    d.add_argument("head")
    d.add_argument("--git", metavar="REPO", help="treat BASE/HEAD as revisions of this local git repository")
    d.add_argument("--out", default="out")
    d.add_argument("--fail-on", choices=LEVELS, default="none")
    d.add_argument("--include-tests", action="store_true")
    d.add_argument("--max-depth", type=int, default=3)
    d.add_argument("--no-html", action="store_true")
    d.set_defaults(func=cmd_diff)

    m = sub.add_parser("demo", help="run the bundled offline three-revision demo")
    m.add_argument("--scenario", choices=SCENARIOS + ("all",), default="same-bom-new-exposure")
    m.add_argument("--out", default="out/demo")
    m.add_argument("--examples-dir")
    m.add_argument("--no-html", action="store_true")
    m.set_defaults(func=cmd_demo)

    b = sub.add_parser("benchmark", help="benchmark against annotated ground truth")
    bs = b.add_subparsers(dest="bcmd", required=True)
    br = bs.add_parser("run")
    br.add_argument("--corpus", default="benchmark/corpus.json")
    br.add_argument("--out", default="benchmark/reports")
    br.set_defaults(func=cmd_benchmark)

    e = sub.add_parser("explain", help="explain a finding or path from a JSON report")
    e.add_argument("finding_id")
    e.add_argument("--report", required=True)
    e.set_defaults(func=cmd_explain)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except UnsafeInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
