"""Scan orchestration: files -> index -> detectors -> analyzers -> typed evidence graph -> paths."""

from __future__ import annotations

import ast
import posixpath
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from agentic_bom.analyzers import operations as ops
from agentic_bom.analyzers.capability_paths import compute_paths
from agentic_bom.analyzers.trust_flow import AgentSite, AnalysisContext, Taint
from agentic_bom.core.evidence import snippet
from agentic_bom.core.graph import EvidenceGraph
from agentic_bom.core.models import (
    CONFIRMED,
    INFERRED,
    SCHEMA_VERSION,
    TOOL_NAME,
    TOOL_VERSION,
    UNKNOWN,
    UNSUPPORTED,
    Edge,
    Evidence,
    Node,
)
from agentic_bom.core.safety import read_text, safe_walk
from agentic_bom.detectors.mcp import is_mcp_config, parse_mcp_config
from agentic_bom.detectors.packages import AI_PACKAGES, parse_pyproject, parse_requirements
from agentic_bom.detectors.python import ProjectIndex, ToolInfo, _tool_contract, detect_tools, is_route_handler, tool_params

SUPPORTED_MATRIX = {
    "languages": {"python": "supported (AST, explicit patterns)", "typescript": "not implemented in this revision", "javascript": "not implemented in this revision"},
    "frameworks": {
        "openai-agents (Python)": "Agent(), @function_tool, function_tool(fn), Runner.run*, MCPServerStdio/Sse/StreamableHttp",
        "mcp FastMCP (Python)": "FastMCP(), @server.tool()",
        "langchain / langgraph (Python)": "@tool, StructuredTool.from_function, create_react_agent",
        "flask / fastapi-style routes": "route handler parameters and flask.request treated as untrusted sources",
    },
    "operations": sorted(ops.CATEGORY_LABELS),
}
SOURCE_LABELS = {
    "stdin": "stdin / input()",
    "argv": "command-line arguments",
    "http_request": "HTTP request data",
    "http_request_param": "HTTP route parameter",
    "network_content": "fetched network content",
}


def _origin_kind(origin: str) -> tuple[str, int]:
    body = origin.split(":", 1)[1]
    kind, _, line = body.partition("@")
    return kind, int(line) if line.isdigit() else 0


class Scanner:
    def __init__(self, root: Path, label: str | None = None, include_tests: bool = False, registry: list[str] | None = None, max_depth: int = 3) -> None:
        self.root = Path(root).resolve()
        self.label = label or self.root.name
        self.include_tests = include_tests
        self.registry = registry
        self.max_depth = max_depth
        self.graph = EvidenceGraph()
        self.unknowns: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    def run(self) -> dict[str, Any]:
        t0 = time.perf_counter()
        walk = safe_walk(self.root, include_tests=self.include_tests)
        index = ProjectIndex(self.root)
        packages = []
        mcp_configs = []
        config_errors = []
        unreadable = []
        n_py = 0
        for f in walk.files:
            rel = f.relative_to(self.root).as_posix()
            try:
                text = read_text(f)
            except (OSError, ValueError):
                unreadable.append(rel)
                continue
            name = f.name
            if f.suffix == ".py":
                n_py += 1
                index.add_source(rel, text)
            elif name.startswith("requirements") and name.endswith(".txt"):
                packages += parse_requirements(rel, text)
            elif name == "pyproject.toml":
                packages += parse_pyproject(rel, text)
            elif is_mcp_config(rel):
                servers, err = parse_mcp_config(rel, text)
                mcp_configs += servers
                if err:
                    config_errors.append({"file": rel, "error": err})
        self.index = index
        self.ctx = AnalysisContext(index, max_depth=self.max_depth)
        tools = detect_tools(index)

        # -- source-mode pass: agents, runner calls, call sites, all direct ops
        sites: list[AgentSite] = []
        runners = []
        call_sites: dict[str, list] = defaultdict(list)
        direct_ops = []
        for mod in self._modules():
            funcs: list[tuple[Any, str]] = [(None, "<module>")] + [(f, q) for q, f in sorted(mod.functions.items())]
            for func, q in funcs:
                env: dict[str, Taint] = {}
                if func is not None:
                    route = is_route_handler(mod, func)
                    for a in list(func.args.posonlyargs) + list(func.args.args) + list(func.args.kwonlyargs):
                        if a.arg in ("self", "cls"):
                            continue
                        env[a.arg] = Taint(frozenset({f"source:http_request_param@{func.lineno}" if route else f"param:{a.arg}"}))
                res = self.ctx.analyze(mod, func, q, env, 0, (), "source")
                sites += res.agent_sites
                runners += res.runner_sites
                direct_ops += res.ops
                for cs in res.call_sites:
                    call_sites[cs.callee_fid].append(cs)

        # bound but undecorated functions are still analysed (resolution inferred_limited)
        for site in sites:
            for ref in site.tools:
                if ref.kind == "function" and f"tool:{ref.fid}" not in tools:
                    relpath, fq = ref.fid.split(":", 1)
                    mod = index.module_for_file(relpath)
                    if mod is None or fq not in mod.functions:
                        continue
                    fn = mod.functions[fq]
                    tools[f"tool:{ref.fid}"] = ToolInfo(
                        id=f"tool:{ref.fid}", name=fn.name, framework="undecorated-function", module=mod, func=fn, func_qual=fq,
                        params=[a.arg for a in tool_params(fn)], contract=_tool_contract(fn.name, ast.get_docstring(fn) or "", fn, {}),
                        line=fn.lineno, decorator_line=fn.lineno,
                    )

        g = self.graph
        app_id = f"application:{self.label}"
        g.add_node(Node(app_id, "application", self.label, attributes={"root": "."}))
        self._add_packages(packages, index)
        self._add_tools(tools)
        self._add_fastmcp_servers(tools)
        self._add_agents(sites, runners, call_sites, tools)
        self._add_mcp_configs(mcp_configs)
        reached = {n.id for n in g.nodes_of("operation")}
        unreached = sorted(
            ({"operation": o.op_id, "category": o.category, "callee": o.callee, "file": o.file, "line": o.line, "function": o.func_qual}
             for o in direct_ops if o.op_id not in reached and o.category != ops.DYNAMIC_DISPATCH),
            key=lambda d: (d["file"], d["line"], d["operation"]),
        )
        paths = compute_paths(g)
        duration = time.perf_counter() - t0
        coverage = {
            "supported_matrix": SUPPORTED_MATRIX,
            "python_files_analyzed": len({m.relpath for m in self._modules()}),
            "python_files_seen": n_py,
            "parse_errors": sorted(index.parse_errors, key=lambda d: d["file"]),
            "unreadable_files": sorted(unreadable),
            "config_errors": config_errors,
            "skipped_large_files": walk.skipped_large,
            "skipped_symlinks": walk.skipped_symlinks,
            "excluded_test_files": walk.excluded_tests,
            "file_limit_truncated": walk.truncated,
            "unsupported_languages_present": walk.other_language_files,
            "unknowns": sorted(self.unknowns, key=lambda d: (d.get("file", ""), d.get("line", 0), d.get("reason", ""))),
            "unreached_sensitive_operations": unreached,
            "analysis_limits": {"max_helper_depth": self.max_depth, "interprocedural": "bounded helper following + one-level call-site provenance"},
            "statement": "All results are static possibilities within the supported scope. runtime_observed=false, authorization_verified=false.",
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "scope": {"label": self.label, "include_tests": self.include_tests},
            "graph": g.to_dict(),
            "paths": paths,
            "coverage": coverage,
            "summary": summarize(g, paths),
            "metrics": {"scan_seconds": round(duration, 3)},
        }

    def _modules(self):
        return sorted({id(m): m for m in self.index.modules.values()}.values(), key=lambda m: m.relpath)

    def _ev(self, file: str, line: int, detector: str, end: int | None = None, note: str = "", with_snippet: bool = True) -> Evidence:
        mod = self.index.module_for_file(file) if hasattr(self, "index") else None
        snip = snippet(mod.lines, line) if (mod is not None and with_snippet) else ""
        return Evidence(file, line, end or line, detector, note, snip)

    # ------------------------------------------------------------------
    def _add_packages(self, packages, index: ProjectIndex) -> None:
        imported = set()
        for m in self._modules():
            imported |= m.imported_top_modules
        for p in packages:
            self.graph.add_node(Node(
                f"package:{p.name}", "package", p.name,
                [Evidence(p.file, p.line, p.line, "manifest.dependency")],
                {"version_spec": p.version_spec, "imported_in_code": p.import_name in imported, "ai_related": p.name in AI_PACKAGES},
            ))

    def _add_tools(self, tools: dict[str, ToolInfo]) -> None:
        g = self.graph
        for tid in sorted(tools):
            t = tools[tid]
            res = CONFIRMED if t.framework != "undecorated-function" else INFERRED
            g.add_node(Node(
                t.id, "tool", t.name,
                [self._ev(t.module.relpath, t.decorator_line, f"py.tool-definition.{t.framework}", t.line)],
                {"framework": t.framework, "file": t.module.relpath, "function": t.func_qual, "parameters": t.params, "contract": t.contract},
                resolution=res,
            ))
            init_env = {p: Taint(frozenset({f"param:{p}"})) for p in t.params}
            r = self.ctx.analyze(t.module, t.func, t.func_qual, init_env, 0, (t.fid,), "tool")
            for o in r.ops:
                attrs = dict(o.attributes)
                g.add_node(Node(
                    o.op_id, "operation", o.callee,
                    [self._ev(o.file, o.line, f"py.sensitive-op.{o.category}", o.end_line)],
                    {"category": o.category, "callee": o.callee, "file": o.file, "function": o.func_qual, **attrs},
                    resolution=o.resolution if o.resolution in (UNKNOWN, UNSUPPORTED) else CONFIRMED,
                ))
                via = [{"file": f, "line": ln, "caller": c, "callee": ce} for f, ln, c, ce in o.via]
                ev = [self._ev(f, ln, "py.helper-call") for f, ln, _c, _ce in o.via] + [self._ev(o.file, o.line, f"py.sensitive-op.{o.category}", o.end_line)]
                params = sorted({x.split(":", 1)[1] for x in o.origins if x.startswith("param:")})
                content_params = sorted({x.split(":", 1)[1] for x in o.content_origins if x.startswith("param:")})
                g.add_edge(Edge(
                    t.id, o.op_id, "REACHES_OPERATION", ev, resolution=o.resolution,
                    scope="supported_python_pattern" if not o.via else f"bounded_helper_chain:{len(o.via)}",
                    confidence=1.0 if o.resolution == CONFIRMED else (0.6 if o.resolution == INFERRED else 0.0),
                    attributes={
                        "operation_category": o.category,
                        "target_controlled": o.target_controlled and bool(params),
                        "content_controlled": bool(content_params),
                        "controlling_params": params,
                        "content_params": content_params,
                        "guard_status": o.guard if (o.target_controlled and params) else "not_applicable",
                        "target": o.target,
                        "target_kind": o.target_kind,
                        "via": via,
                        **{k: v for k, v in attrs.items() if k in ("shell", "method", "mode", "reason")},
                    },
                    key="->".join(v["callee"] for v in via),
                ))
                if o.resolution == UNKNOWN:
                    self.unknowns.append({"kind": "operation", "file": o.file, "line": o.line, "reason": dict(o.attributes).get("reason", f"dynamic call {o.callee}"), "tool": t.id})
                if o.target_kind == "literal" and o.target:
                    rid = f"resource:{o.category}:{o.target}"
                    g.add_node(Node(rid, "resource", o.target, attributes={"category": o.category}))
                    et = "READS_FROM" if o.category == ops.SECRET_ACCESS else "WRITES_TO"
                    g.add_edge(Edge(o.op_id, rid, et, [self._ev(o.file, o.line, f"py.sensitive-op.{o.category}")]))

    def _add_fastmcp_servers(self, tools: dict[str, ToolInfo]) -> None:
        g = self.graph
        from agentic_bom.detectors.python import const_str
        for mod in self._modules():
            for var, call in sorted(mod.fastmcp_vars.items()):
                sid = f"mcp_server:{mod.relpath}:{var}"
                name = const_str(mod, call.args[0] if call.args else None) or var
                g.add_node(Node(sid, "mcp_server", name, [self._ev(mod.relpath, call.lineno, "py.mcp-fastmcp-server")],
                                {"source": "fastmcp", "file": mod.relpath, "variable": var}))
                for t in sorted(tools.values(), key=lambda t: t.id):
                    if t.module is mod and t.mcp_server_var == var:
                        g.add_edge(Edge(sid, t.id, "EXPOSES_TOOL", [self._ev(mod.relpath, t.decorator_line, "py.mcp-tool-registration")]))

    def _resolve_server_file(self, site_file: str, server_file: str) -> list[str]:
        cands = [posixpath.normpath(server_file.replace("\\", "/")), posixpath.normpath(posixpath.join(posixpath.dirname(site_file), server_file.replace("\\", "/")))]
        out = []
        for c in cands:
            mod = self.index.module_for_file(c)
            if mod is not None:
                out += [f"mcp_server:{mod.relpath}:{v}" for v in sorted(mod.fastmcp_vars)]
        return sorted(set(out))

    def _agent_id(self, site: AgentSite, used: set[str]) -> str:
        key = site.name or site.var or f"line{site.line}"
        aid = f"agent:{site.file}:{key}"
        if aid in used:
            aid = f"agent:{site.file}:{key}@{site.func_qual}"
        used.add(aid)
        return aid

    def _add_agents(self, sites: list[AgentSite], runners, call_sites, tools) -> None:
        g = self.graph
        used: set[str] = set()
        site_ids: dict[int, str] = {}
        for site in sorted(sites, key=lambda s: (s.file, s.line)):
            aid = self._agent_id(site, used)
            site_ids[id(site)] = aid
            provenance, sources, prov_ev = self._provenance(site, call_sites)
            mgmt = "unknown"
            if self.registry is not None:
                mgmt = "registered" if (site.name in self.registry or aid in self.registry) else "unregistered"
            g.add_node(Node(aid, "agent", site.name or site.var or aid,
                            [self._ev(site.file, site.line, f"py.agent-definition.{site.framework}", site.end_line)],
                            {"framework": site.framework, "file": site.file, "function": site.func_qual, "variable": site.var,
                             "model": site.model or ("unresolved" if site.model is None else site.model),
                             "instructions_provenance": provenance, "management_status": mgmt},
                            resolution=CONFIRMED if site.name else INFERRED))
            if site.model:
                mid = f"model:{site.model}"
                g.add_node(Node(mid, "model", site.model))
                g.add_edge(Edge(aid, mid, "USES_MODEL", [self._ev(site.file, site.model_line, "py.agent-model")]))
            if site.instructions_kind != "absent":
                pid = f"prompt:{aid}:instructions"
                g.add_node(Node(pid, "prompt", f"{site.name or aid} instructions",
                                [self._ev(site.file, site.instructions_line, "py.agent-instructions", with_snippet=False)],
                                {"role": "instructions", "kind": site.instructions_kind, "sha256": site.instructions_sha256,
                                 "length": site.instructions_length, "provenance": provenance, "body": "not stored"},
                                resolution=UNKNOWN if provenance == "unknown" else CONFIRMED))
                g.add_edge(Edge(pid, aid, "FLOWS_TO", [self._ev(site.file, site.instructions_line, "py.agent-instructions", with_snippet=False)],
                                attributes={"role": "instructions"}))
                if provenance == "unknown":
                    self.unknowns.append({"kind": "instructions", "file": site.file, "line": site.instructions_line, "reason": "instruction provenance unresolved", "agent": aid})
                if provenance == "untrusted":
                    tb = "trust_boundary:privileged-instructions"
                    g.add_node(Node(tb, "trust_boundary", "Privileged instructions (system/developer role)"))
                    for (kind, file, line), extra_ev in sources:
                        did = f"data_source:{file}:{kind}@{line}"
                        g.add_node(Node(did, "data_source", SOURCE_LABELS.get(kind, kind), [self._ev(file, line, f"py.untrusted-source.{kind}")],
                                        {"source_kind": kind, "trust": "untrusted"}))
                        evs = [self._ev(file, line, f"py.untrusted-source.{kind}"), self._ev(site.file, site.instructions_line, "py.agent-instructions", with_snippet=False)] + extra_ev
                        g.add_edge(Edge(did, pid, "FLOWS_TO", evs, attributes={"role": "instructions"}))
                        g.add_edge(Edge(did, aid, "CROSSES_TRUST_BOUNDARY", evs, attributes={"boundary": tb, "source_kind": kind},
                                        resolution=CONFIRMED, scope="supported_python_pattern" if not extra_ev else "one_level_call_site"))
            n_unknown = 0
            for ref in site.tools:
                if ref.kind == "function":
                    tid = f"tool:{ref.fid}"
                    if tid not in g.nodes:
                        continue
                    g.add_edge(Edge(aid, tid, "BINDS_TOOL", [self._ev(site.file, ref.line, "py.agent-tool-binding")],
                                    resolution=CONFIRMED if tools[tid].framework != "undecorated-function" else INFERRED))
                else:
                    n_unknown += 1
                    tid = f"tool:{ref.kind}:{site.file}:{ref.qual or aid}#{n_unknown}"
                    res = UNSUPPORTED if ref.kind == "external" else UNKNOWN
                    g.add_node(Node(tid, "tool", ref.qual or "unresolved tool", [self._ev(site.file, ref.line, "py.agent-tool-binding")],
                                    {"framework": ref.kind, "reason": ref.reason}, resolution=res))
                    g.add_edge(Edge(aid, tid, "BINDS_TOOL", [self._ev(site.file, ref.line, "py.agent-tool-binding", note=ref.reason)],
                                    resolution=CONFIRMED if ref.kind == "external" else UNKNOWN, confidence=0.0))
                    self.unknowns.append({"kind": "tool_binding", "file": site.file, "line": ref.line, "reason": ref.reason, "agent": aid})
            for i, ref in enumerate(site.mcp_refs, 1):
                targets = self._resolve_server_file(site.file, ref.server_file) if ref.server_file else []
                ev = [self._ev(site.file, ref.line, "py.agent-mcp-connection", note=ref.command or ref.url or "")]
                if targets:
                    for sid in targets:
                        g.add_edge(Edge(aid, sid, "CONNECTS_MCP", ev, resolution=INFERRED, confidence=0.8, scope="mcp_stdio_command_args",
                                        attributes={"transport": ref.transport, "command": ref.command}))
                else:
                    sid = f"mcp_server:external:{site.file}:{aid}#{i}"
                    reason = "MCP server source not in scanned repository; tools/list not statically resolvable"
                    g.add_node(Node(sid, "mcp_server", ref.command or ref.url or "external MCP server", ev,
                                    {"source": "external", "transport": ref.transport, "reason": reason}, resolution=UNKNOWN))
                    g.add_edge(Edge(aid, sid, "CONNECTS_MCP", ev, resolution=UNKNOWN, attributes={"transport": ref.transport}))
                    self.unknowns.append({"kind": "mcp_server", "file": site.file, "line": ref.line, "reason": reason, "agent": aid})
        # handoffs
        for site in sites:
            for var in site.handoff_vars:
                for other in sites:
                    if other.var == var and other.file == site.file and other is not site:
                        g.add_edge(Edge(site_ids[id(site)], site_ids[id(other)], "DELEGATES_TO", [self._ev(site.file, site.line, "py.agent-handoff")]))
        # user-role inputs via Runner.run*
        for r in runners:
            targets = []
            if r.agent_site is not None:
                targets = [r.agent_site]
            elif r.agent_factory_qual:
                targets = [s for s in sites if f"{s.file}:{s.func_qual}" == r.agent_factory_qual and s.returned]
            for s in targets:
                aid = site_ids[id(s)]
                if r.input_taint is None:
                    continue
                for o in r.input_taint.untrusted_sources:
                    kind, line = _origin_kind(o)
                    did = f"data_source:{r.file}:{kind}@{line}"
                    g.add_node(Node(did, "data_source", SOURCE_LABELS.get(kind, kind), [self._ev(r.file, line, f"py.untrusted-source.{kind}")],
                                    {"source_kind": kind, "trust": "untrusted"}))
                    g.add_edge(Edge(did, aid, "FLOWS_TO", [self._ev(r.file, line, f"py.untrusted-source.{kind}"), self._ev(r.file, r.line, "py.runner-input")],
                                    attributes={"role": "user_message"}))
                    g.nodes[aid].attributes["user_input_untrusted"] = True

    def _provenance(self, site: AgentSite, call_sites) -> tuple[str, list, list]:
        """Return (provenance, [((kind, file, line), extra_evidence)], evidence)."""
        k = site.instructions_kind
        if k == "absent":
            return "absent", [], []
        if k == "static":
            return "static", [], []
        if k == "callable":
            return "unknown", [], []
        t = site.instructions_taint
        if t is None:
            return "static", [], []
        sources = []
        for o in t.untrusted_sources:
            kind, line = _origin_kind(o)
            sources.append(((kind, site.file, line), []))
        unresolved = False
        if t.params:
            callers = call_sites.get(f"{site.file}:{site.func_qual}", [])
            if not callers:
                unresolved = True
            for cs in callers:
                for p in t.params:
                    at = cs.arg_taints.get(p)
                    if at is None:
                        continue
                    if at.untrusted_sources:
                        for o in at.untrusted_sources:
                            kind, line = _origin_kind(o)
                            sources.append(((kind, cs.file, line), [self._ev(cs.file, cs.line, "py.call-site-argument")]))
                    else:
                        unresolved = True
        if sources:
            return "untrusted", sources, []
        return ("unknown" if unresolved else "static"), [], []

    def _add_mcp_configs(self, configs) -> None:
        g = self.graph
        for c in configs:
            sid = f"mcp_server:config:{c.file}:{c.name}"
            attrs = {"source": "config", "transport": c.transport, "command": c.command, "url": c.url, "env_keys": c.env_keys, "env_values": "not stored"}
            if c.server_file:
                attrs["source_server_candidates"] = self._resolve_server_file(c.file, c.server_file)
            g.add_node(Node(sid, "mcp_server", c.name, [Evidence(c.file, c.line, c.line, "config.mcp-server")], attrs,
                            resolution=INFERRED if attrs.get("source_server_candidates") else UNKNOWN))


def summarize(g: EvidenceGraph, paths: list[dict[str, Any]]) -> dict[str, Any]:
    by_cls: dict[str, int] = defaultdict(int)
    for p in paths:
        by_cls[p["classification"]] += 1
    agents = g.nodes_of("agent")
    bound = {e.target for e in g.edges.values() if e.type in ("BINDS_TOOL", "EXPOSES_TOOL")}
    return {
        "agents": len(agents),
        "agents_confirmed": sum(1 for a in agents if a.resolution == CONFIRMED),
        "tools": len(g.nodes_of("tool")),
        "bound_tools": len([t for t in g.nodes_of("tool") if t.id in bound]),
        "mcp_servers": len(g.nodes_of("mcp_server")),
        "models": len(g.nodes_of("model")),
        "packages": len(g.nodes_of("package")),
        "sensitive_operations": len(g.nodes_of("operation")),
        "paths_by_classification": dict(sorted(by_cls.items())),
        "sensitive_operation_paths": by_cls.get("operation_path", 0) + by_cls.get("potentially_exposed", 0),
        "potentially_exposed_paths": by_cls.get("potentially_exposed", 0),
        "unknown_paths": by_cls.get("unknown", 0),
    }


def scan(root: Path | str, **kw: Any) -> dict[str, Any]:
    return Scanner(Path(root), **kw).run()
