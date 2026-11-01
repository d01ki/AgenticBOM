"""TypeScript / JavaScript detector (explicit patterns, pure Python).

Supported (see docs/methodology.md):
  * OpenAI Agents JS (`@openai/agents`): ``new Agent({...})``, ``tool({...})``, ``run(agent, input)``,
    ``agent.asTool()``, ``handoffs``, ``MCPServerStdio`` / ``MCPServerStreamableHttp``, hosted tools.
  * Vercel AI SDK (`ai`): ``tool({...})``, ``generateText/streamText/generateObject/streamObject({...})``,
    ``Experimental_Agent`` / ``Agent``.
  * MCP TypeScript SDK: ``new McpServer(...)`` + ``server.tool(...)`` / ``server.registerTool(...)``.
  * Sources: Express-style ``app.METHOD(path, handler)``, Next.js route handlers, ``process.argv``,
    ``process.stdin``, ``fetch()`` responses.
Everything the parser or resolver cannot follow is reported as UNKNOWN.
"""

from __future__ import annotations

import posixpath
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from agentic_bom.analyzers import operations as ops
from agentic_bom.analyzers.trust_flow import (
    GUARD_STRENGTH,
    AgentSite,
    CallSite,
    FunctionResult,
    McpRef,
    OpHit,
    RunnerSite,
    Taint,
    ToolRef,
    merge,
    merge_env,
)
from agentic_bom.core.evidence import fingerprint, redact, redact_target, sha256_text, snippet
from agentic_bom.core.models import CONFIRMED, GUARD_ABSENT, GUARD_KNOWN, GUARD_UNKNOWN, INFERRED, UNKNOWN
from agentic_bom.detectors.ts_parser import ParseError, parse

TS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
RESOLVE_EXTS = (".ts", ".tsx", ".mts", ".js", ".jsx", ".mjs", ".cjs")

AGENT_NEW = {"@openai/agents.Agent", "@openai/agents-core.Agent", "ai.Experimental_Agent", "ai.Agent"}
AGENT_CALLS = {"ai.generateText", "ai.streamText", "ai.generateObject", "ai.streamObject"}
TOOL_FUNCS = {"@openai/agents.tool", "@openai/agents-core.tool", "ai.tool"}
RUN_FUNCS = {"@openai/agents.run", "@openai/agents-core.run"}
HANDOFF_FUNCS = {"@openai/agents.handoff", "@openai/agents-core.handoff"}
MCP_SERVER_NEW = {
    "@modelcontextprotocol/sdk/server/mcp.McpServer",
    "@modelcontextprotocol/sdk/server/index.Server",
    # the TS SDK split into @modelcontextprotocol/server on its main branch (observed at 1e608ca)
    "@modelcontextprotocol/server.McpServer",
    "@modelcontextprotocol/server/mcp.McpServer",
    "fastmcp.FastMCP",
}
PROVIDER_TOOL_RE = re.compile(r"^@ai-sdk/[^.]+\.[A-Za-z_$][\w$]*\.tools\.[\w$]+$")
MCP_CLIENT_NEW = {
    "@openai/agents.MCPServerStdio": "stdio",
    "@openai/agents.MCPServerStreamableHttp": "streamable_http",
    "@openai/agents.MCPServerSSE": "sse",
}
HOSTED_TOOL_FUNCS = {f"@openai/agents.{n}" for n in ("webSearchTool", "fileSearchTool", "codeInterpreterTool", "imageGenerationTool")}
UNKNOWN_TOOL_FUNCS = {"@openai/agents.hostedMcpTool": "hosted MCP tool: remote tools not statically resolvable",
                      "@openai/agents.computerTool": "computer-use tool: actions depend on the Computer implementation (not modelled)"}
LIBRARY_TOOL_FUNCS = {"@openai/agents.shellTool": ops.PROCESS_EXECUTION, "@openai/agents.localShellTool": ops.PROCESS_EXECUTION}

TS_SINKS: dict[str, str] = {}
for _n in ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"):
    TS_SINKS[f"child_process.{_n}"] = ops.PROCESS_EXECUTION
for _n in ("execa", "execaCommand", "execaSync", "$"):
    TS_SINKS[f"execa.{_n}"] = ops.PROCESS_EXECUTION
TS_SINKS["global.eval"] = ops.CODE_EXECUTION
for _n in ("runInNewContext", "runInThisContext", "runInContext", "compileFunction"):
    TS_SINKS[f"vm.{_n}"] = ops.CODE_EXECUTION
for _n in ("writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "copyFile", "copyFileSync",
           "cp", "cpSync", "rename", "renameSync", "chmod", "chmodSync", "symlink", "symlinkSync", "outputFile", "outputFileSync"):
    TS_SINKS[f"fs.{_n}"] = ops.FILESYSTEM_WRITE
for _n in ("unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "remove", "removeSync"):
    TS_SINKS[f"fs.{_n}"] = ops.FILESYSTEM_DELETE
for _lib in ("axios", "got", "ky", "superagent"):
    for _m in ("post", "put", "patch", "delete", "del"):
        TS_SINKS[f"{_lib}.{_m}"] = ops.NETWORK_STATE_CHANGE
TS_TARGET_ARGS = {ops.FILESYSTEM_WRITE: (0,), ops.FILESYSTEM_DELETE: (0,), ops.NETWORK_STATE_CHANGE: (0,)}
TWO_PATH_FS = {"copyFile", "copyFileSync", "cp", "cpSync", "rename", "renameSync", "symlink", "symlinkSync"}
CLEANSERS = {"global.Number", "global.parseInt", "global.parseFloat", "global.Boolean", "global.isNaN", "Math.round", "Math.floor"}
ARRAY_CALLBACK_METHODS = {"map", "forEach", "filter", "reduce", "flatMap", "find", "some", "every", "then", "sort", "findIndex"}
ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "all", "use", "route"}
NEXT_ROUTE_EXPORTS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
GLOBALS = {"eval", "fetch", "Function", "process", "require", "JSON", "console", "Number", "parseInt", "parseFloat", "Boolean",
           "isNaN", "Math", "Object", "Array", "String", "Promise", "Buffer", "setTimeout", "Date", "Error", "URL"}
AWS_READ_PREFIXES = ("Get", "List", "Head", "Describe", "Query", "Scan", "Batch Get")


def normalize_spec(spec: str) -> str:
    s = spec
    if s.startswith("node:"):
        s = s[5:]
    if s in ("fs/promises", "fs-extra"):
        s = "fs"
    if s == "child_process" or s == "node:child_process":
        return "child_process"
    s = re.sub(r"\.(js|mjs|cjs)$", "", s)
    return s


def canonical(q: str | None) -> str | None:
    if q is None:
        return None
    q = q.replace("fs.promises.", "fs.")
    q = re.sub(r"^util\.promisify\((.+)\)$", r"\1", q)
    return q


@dataclass
class Unit:
    qual: str
    fn: dict[str, Any]
    kind: str  # decl | const | method | prop | route | mcp_handler | tool_execute
    cls: str | None = None


@dataclass
class TsTool:
    id: str
    name: str
    framework: str
    file: str
    line: int
    unit: Unit | None
    params: list[str]
    contract: dict[str, Any]
    mcp_server_id: str | None = None
    obj_param: str | None = None
    execute_ref: dict[str, Any] | None = None
    unit_file: str | None = None
    client_executed: bool = False
    ops: list[OpHit] = field(default_factory=list)
    unknowns: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class TsModule:
    relpath: str
    body: list[dict[str, Any]]
    lines: list[str]
    imports: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    consts: dict[str, dict[str, Any]] = field(default_factory=dict)
    classes: dict[str, dict[str, Any]] = field(default_factory=dict)
    exports: dict[str, str] = field(default_factory=dict)  # exported name -> local name
    units: dict[str, Unit] = field(default_factory=dict)
    unit_by_fn: dict[int, Unit] = field(default_factory=dict)
    tool_by_call: dict[int, str] = field(default_factory=dict)
    mcp_servers: dict[str, tuple[str, int]] = field(default_factory=dict)  # var -> (name, line)
    top_modules: set[str] = field(default_factory=set)


@dataclass
class TsResult:
    tools: dict[str, TsTool] = field(default_factory=dict)
    agent_sites: list[AgentSite] = field(default_factory=list)
    runner_sites: list[RunnerSite] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    direct_ops: list[OpHit] = field(default_factory=list)
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    skipped_regions: int = 0
    files: int = 0
    lines: dict[str, list[str]] = field(default_factory=dict)
    imported_packages: set[str] = field(default_factory=set)


def _lit(n: dict[str, Any] | None) -> Any:
    if n is None:
        return None
    if n["k"] == "Lit":
        return n["value"]
    if n["k"] == "Tpl" and not n["exprs"]:
        return n["quasis"][0]
    return None


def _prop(obj: dict[str, Any] | None, key: str) -> dict[str, Any] | None:
    if not obj or obj["k"] != "Object":
        return None
    for p in obj["props"]:
        if p["k"] == "Prop" and p.get("key") == key:
            return p["value"]
    return None


def _children(n: Any) -> Iterable[Any]:
    if isinstance(n, dict):
        for k, v in n.items():
            if k in ("k", "line"):
                continue
            yield v
    elif isinstance(n, (list, tuple)):
        yield from n


def _pattern_names(p: dict[str, Any] | None) -> list[tuple[str, str | None]]:
    """(local name, property key) pairs bound by a pattern."""
    if p is None:
        return []
    if p["k"] == "Ident":
        return [(p["name"], None)]
    if p["k"] == "ObjPat":
        out = []
        for key, val, _d in p["props"]:
            if val["k"] == "Ident":
                out.append((val["name"], key))
            else:
                out += _pattern_names(val)
        if p.get("rest"):
            out += _pattern_names(p["rest"])
        return out
    if p["k"] == "ArrPat":
        out = []
        for e in p["elts"]:
            out += _pattern_names(e)
        return out
    return []


# --------------------------------------------------------------------------- project index
class TsProject:
    def __init__(self) -> None:
        self.modules: dict[str, TsModule] = {}
        self.result = TsResult()

    def add(self, relpath: str, src: str) -> None:
        self.result.files += 1
        try:
            pr = parse(src)
        except (ParseError, RecursionError, MemoryError) as exc:
            self.result.parse_errors.append({"file": relpath, "error": type(exc).__name__})
            return
        mod = TsModule(relpath, pr.body, src.splitlines())
        self.result.skipped_regions += pr.skipped_regions
        self.result.lines[relpath] = mod.lines
        try:
            self._index(mod)
        except RecursionError:
            self.result.parse_errors.append({"file": relpath, "error": "RecursionError"})
            return
        self.modules[relpath] = mod

    def resolve_relative(self, from_file: str, spec: str) -> TsModule | None:
        if not spec.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_file), spec))
        stem = re.sub(r"\.(js|mjs|cjs|ts|tsx|jsx)$", "", base)
        for cand in [base] + [stem + e for e in RESOLVE_EXTS] + [posixpath.join(base, "index" + e) for e in RESOLVE_EXTS]:
            if cand in self.modules:
                return self.modules[cand]
        return None

    # -- indexing
    def _index(self, mod: TsModule) -> None:
        for st in mod.body:
            k = st["k"]
            if k == "Import":
                if st["source"]:
                    spec = normalize_spec(st["source"])
                    mod.top_modules.add(_top_pkg(st["source"]))
                    for local, imported in st["specs"]:
                        mod.imports[local] = (spec, None if imported in ("*", "default") and not st["source"].startswith(".") else imported)
                        if st["source"].startswith("."):
                            mod.imports[local] = (st["source"], imported)
            elif k == "Var":
                for target, init in st["decls"]:
                    self._index_require(mod, target, init)
                    if target["k"] == "Ident" and init is not None:
                        mod.consts[target["name"]] = init
                        if st.get("exported"):
                            mod.exports[target["name"]] = target["name"]
            elif k == "Func" and st.get("name"):
                if st.get("exported"):
                    mod.exports[st["name"]] = st["name"]
            elif k == "Class" and st.get("name"):
                mod.classes[st["name"]] = st
                if st.get("exported"):
                    mod.exports[st["name"]] = st["name"]
            elif k == "ExportNames" and not st.get("source"):
                for local, exported in st["names"]:
                    mod.exports[exported] = local
            elif k == "ExportDefault" and st["expr"]["k"] == "Ident":
                mod.exports["default"] = st["expr"]["name"]
        self._collect_units(mod)

    def _index_require(self, mod: TsModule, target: dict[str, Any], init: dict[str, Any] | None) -> None:
        if not init or init["k"] != "Call" or init["callee"]["k"] != "Ident" or init["callee"]["name"] != "require":
            return
        spec = _lit(init["args"][0]) if init["args"] else None
        if not isinstance(spec, str):
            return
        mod.top_modules.add(_top_pkg(spec))
        norm = spec if spec.startswith(".") else normalize_spec(spec)
        if target["k"] == "Ident":
            mod.imports[target["name"]] = (norm, None if not spec.startswith(".") else "*")
        elif target["k"] == "ObjPat":
            for key, val, _d in target["props"]:
                if val["k"] == "Ident" and key:
                    mod.imports[val["name"]] = (norm, key)

    def _add_unit(self, mod: TsModule, qual: str, fn: dict[str, Any], kind: str, cls: str | None = None) -> Unit:
        if id(fn) in mod.unit_by_fn:
            return mod.unit_by_fn[id(fn)]
        base, n = qual, 2
        while qual in mod.units:
            qual = f"{base}@{fn['line']}" if n == 2 else f"{base}@{fn['line']}#{n}"
            n += 1
        u = Unit(qual, fn, kind, cls)
        mod.units[qual] = u
        mod.unit_by_fn[id(fn)] = u
        return u

    def _collect_units(self, mod: TsModule) -> None:
        is_next_route = bool(re.search(r"(^|/)app/(.+/)?route\.(t|j)sx?$", mod.relpath)) or bool(re.search(r"(^|/)pages/api/", mod.relpath))

        def visit(node: Any, prefix: str, assign: str | None = None, prop: str | None = None, callee_info: dict | None = None) -> None:
            if isinstance(node, list):
                for x in node:
                    visit(x, prefix)
                return
            if not isinstance(node, dict):
                return
            k = node.get("k")
            if k == "Func":
                unit = mod.unit_by_fn.get(id(node))
                if unit is None:
                    name = node.get("name") if node.get("decl") else None
                    label = name or assign or prop
                    if label:
                        kind = "decl" if name else ("const" if assign else "prop")
                        if is_next_route and not prefix and (label in NEXT_ROUTE_EXPORTS or label == "default"):
                            kind = "route"
                        unit = self._add_unit(mod, f"{prefix}.{label}" if prefix else label, node, kind)
                if unit is not None:
                    visit(node["params"], unit.qual)
                    visit(node["body"], unit.qual)
                else:  # inline callback: stays part of the enclosing unit
                    visit(node["params"], prefix)
                    visit(node["body"], prefix)
                return
            if k == "Class":
                cname = node.get("name") or f"class@{node['line']}"
                for mname, m in node["methods"].items():
                    u = self._add_unit(mod, f"{cname}.{mname}", m, "method", cls=cname)
                    visit(m["body"], u.qual)
                for fname, fv in node["fields"].items():
                    visit(fv, cname, assign=fname)
                return
            if k == "Var":
                for target, init in node["decls"]:
                    if init is not None:
                        visit(init, prefix, assign=target["name"] if target["k"] == "Ident" else None)
                return
            if k == "ExportDefault":
                visit(node["expr"], prefix, assign="default")
                return
            if k == "Call":
                self._call_hooks(mod, node, prefix, assign, prop)
                visit(node["callee"], prefix)
                for a in node["args"]:
                    visit(a, prefix)
                return
            if k == "New":
                if node["callee"]["k"] == "Ident" and assign and self.qual(mod, node["callee"]) in MCP_SERVER_NEW:
                    name = _lit(_prop(node["args"][0], "name")) if node["args"] else None
                    mod.mcp_servers[assign] = (name or assign, node["line"])
                visit(node["callee"], prefix)
                for a in node["args"]:
                    visit(a, prefix)
                return
            if k == "Object":
                for p in node["props"]:
                    if p["k"] == "Prop":
                        visit(p["value"], prefix, prop=p.get("key"))
                    else:
                        visit(p.get("arg"), prefix)
                return
            if k == "Assign":
                tgt = node["target"]
                name = tgt["name"] if tgt["k"] == "Ident" else (tgt["prop"] if tgt["k"] == "Member" and isinstance(tgt["prop"], str) else None)
                visit(node["value"], prefix, assign=name)
                return
            for ch in _children(node):
                visit(ch, prefix)

        visit(mod.body, "")

    def _call_hooks(self, mod: TsModule, call: dict[str, Any], prefix: str, assign: str | None, prop: str | None) -> None:
        q = self.qual(mod, call["callee"])
        cal = call["callee"]
        provider_tool = bool(q and PROVIDER_TOOL_RE.match(q)) and bool(call["args"]) and call["args"][0]["k"] == "Object" \
            and _prop(call["args"][0], "execute") is not None
        if (q in TOOL_FUNCS or provider_tool) and call["args"] and call["args"][0]["k"] == "Object":
            obj = call["args"][0]
            name = _lit(_prop(obj, "name")) or (q.rsplit(".", 1)[-1] if provider_tool else None)
            label = assign or prop or name or f"tool@{call['line']}"
            tqual = f"{prefix}.{label}" if prefix else label
            execute = _prop(obj, "execute")
            unit = self._add_unit(mod, f"{tqual}.execute", execute, "tool_execute") if execute and execute["k"] == "Func" else None
            tid = f"tool:{mod.relpath}:{tqual}"
            if tid in self.result.tools:
                tid = f"{tid}@{call['line']}"
            schema = _prop(obj, "parameters") or _prop(obj, "inputSchema")
            appr = _prop(obj, "needsApproval")
            annotations = {}
            if appr is not None:
                lv = _lit(appr)
                annotations["needs_approval"] = "True" if lv is True else ("False" if lv is False else "dynamic")
            fw = "vercel-ai-provider-tool" if provider_tool else ("openai-agents-js" if q.startswith("@openai") else "vercel-ai")
            tool = self._make_tool(mod, tid, name or prop or assign or label, fw, call["line"], unit, schema,
                                   _lit(_prop(obj, "description")) or "", annotations)
            if execute is None:
                tool.client_executed = True
            elif unit is None:
                tool.execute_ref = execute
            mod.tool_by_call[id(call)] = tid
            self.result.tools[tid] = tool
            return
        if cal["k"] == "Member" and isinstance(cal["prop"], str) and cal["prop"] in ("tool", "registerTool") and cal["obj"]["k"] == "Ident" \
                and cal["obj"]["name"] in mod.mcp_servers and call["args"]:
            server_var = cal["obj"]["name"]
            name = _lit(call["args"][0]) or f"tool@{call['line']}"
            handler = call["args"][-1] if call["args"][-1]["k"] == "Func" else None
            desc, schema = "", None
            rest = call["args"][1:-1] if handler else call["args"][1:]
            annotations: dict[str, str] = {}
            if cal["prop"] == "registerTool" and rest and rest[0]["k"] == "Object":
                cfg = rest[0]
                desc = _lit(_prop(cfg, "description")) or ""
                schema = _prop(cfg, "inputSchema")
                ann = _prop(cfg, "annotations")
                if ann is not None and ann["k"] == "Object":
                    for p in ann["props"]:
                        if p["k"] == "Prop" and p.get("key"):
                            annotations[p["key"]] = str(_lit(p["value"]))[:60]
            else:
                for a in rest:
                    if isinstance(_lit(a), str):
                        desc = _lit(a)
                    elif a["k"] in ("Object", "Call"):
                        schema = schema or a
            tqual = f"{server_var}.{name}"
            unit = self._add_unit(mod, tqual, handler, "mcp_handler") if handler else None
            tid = f"tool:{mod.relpath}:{tqual}"
            tool = self._make_tool(mod, tid, str(name), "mcp-ts", call["line"], unit, schema, desc, annotations)
            tool.mcp_server_id = f"mcp_server:{mod.relpath}:{server_var}"
            self.result.tools[tid] = tool
            return
        # Express-style routes: app.post('/x', [...middleware], handler)
        if cal["k"] == "Member" and isinstance(cal["prop"], str) and cal["prop"] in ROUTE_METHODS and call["args"] and isinstance(_lit(call["args"][0]), str) \
                and call["args"][-1]["k"] == "Func" and str(_lit(call["args"][0])).startswith("/"):
            self._add_unit(mod, f"route:{cal['prop'].upper()} {_lit(call['args'][0])}", call["args"][-1], "route")

    def _make_tool(self, mod: TsModule, tid: str, name: str, framework: str, line: int, unit: Unit | None,
                   schema: dict[str, Any] | None, description: str, annotations: dict[str, str]) -> TsTool:
        params = schema_params(schema)
        obj_param = None
        if unit is not None and unit.fn["params"]:
            first = unit.fn["params"][0]["pat"]
            if first["k"] == "ObjPat":
                names = [key or local for local, key in _pattern_names(first)]
                if not params:
                    params = [{"name": n, "annotation": None, "required": True} for n in names]
            elif first["k"] == "Ident":
                obj_param = first["name"]
        desc = redact(description or "")
        contract = {
            "name": name,
            "description": desc[:500],
            "description_sha256": sha256_text(description or ""),
            "parameters": params,
            "annotations": dict(sorted(annotations.items())),
        }
        contract["schema_fingerprint"] = fingerprint(params)
        contract["fingerprint"] = fingerprint({k: contract[k] for k in ("name", "description_sha256", "parameters", "annotations")})
        return TsTool(tid, name, framework, mod.relpath, line, unit, [p["name"] for p in params], contract, obj_param=obj_param)

    # -- names
    def qual(self, mod: TsModule, n: dict[str, Any] | None, shadow: set[str] | None = None) -> str | None:
        if n is None:
            return None
        if n["k"] == "Ident":
            name = n["name"]
            if shadow and name in shadow:
                return None
            if name in mod.imports:
                spec, imported = mod.imports[name]
                if spec.startswith("."):
                    return f"rel:{mod.relpath}:{spec}:{imported}"
                return f"{spec}.{imported}" if imported else spec
            if name in mod.units:
                return f"local:{mod.relpath}:{name}"
            if name in mod.classes:
                return f"class:{mod.relpath}:{name}"
            if name in mod.consts:
                init = mod.consts[name]
                if init["k"] == "Call" and init["args"] and self.qual(mod, init["callee"]) in ("util.promisify", "util.promisify"):
                    inner = self.qual(mod, init["args"][0])
                    return inner
                return f"const:{mod.relpath}:{name}"
            if name in GLOBALS:
                return f"global.{name}"
            return None
        if n["k"] == "Member" and isinstance(n["prop"], str):
            base = self.qual(mod, n["obj"], shadow)
            if base is None:
                return None
            return f"{base}.{n['prop']}"
        return None

    def resolve_function(self, mod: TsModule, q: str | None, depth: int = 0) -> tuple[TsModule, Unit] | None:
        if not q or depth > 4:
            return None
        if q.startswith("local:"):
            _, rel, name = q.split(":", 2)
            m = self.modules.get(rel)
            if m and name in m.units:
                return m, m.units[name]
            return None
        if q.startswith("rel:"):
            _, rel, spec, imported = q.split(":", 3)
            rest = ""
            if "." in imported:
                imported, rest = imported.split(".", 1)
            target = self.resolve_relative(rel, spec)
            if target is None:
                return None
            local = target.exports.get(imported or "default", imported if imported in target.units else None)
            if local is None and imported in (None, "*", "None"):
                return None
            if rest:
                local = f"{local}.{rest}" if local else rest
            if local and local in target.units:
                return target, target.units[local]
            if local and local in target.imports:
                return self.resolve_function(target, self.qual(target, {"k": "Ident", "name": local, "line": 0}), depth + 1)
        return None


def _top_pkg(spec: str) -> str:
    if spec.startswith("."):
        return ""
    s = spec[5:] if spec.startswith("node:") else spec
    parts = s.split("/")
    return "/".join(parts[:2]) if s.startswith("@") else parts[0]


def schema_params(schema: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Parameter names from z.object({...}), a raw zod shape {...} or a JSON-schema object."""
    if schema is None:
        return []
    obj = schema
    if schema["k"] == "Call":
        if schema["args"] and schema["args"][0]["k"] == "Object":
            obj = schema["args"][0]
        elif schema["callee"]["k"] == "Member" and schema["callee"]["obj"]["k"] == "Call":
            return schema_params(schema["callee"]["obj"])  # z.object({...}).strict()
        else:
            return []
    if obj["k"] != "Object":
        return []
    props = _prop(obj, "properties")
    if props is not None and props["k"] == "Object" and _lit(_prop(obj, "type")) == "object":
        req = _prop(obj, "required")
        required = {_lit(e) for e in req["elts"]} if req is not None and req["k"] == "Array" else set()
        return [{"name": p["key"], "annotation": str(_lit(_prop(p["value"], "type"))), "required": p["key"] in required}
                for p in props["props"] if p["k"] == "Prop" and p.get("key")]
    out = []
    for p in obj["props"]:
        if p["k"] != "Prop" or not p.get("key"):
            continue
        chain, base, cur = [], None, p["value"]
        while cur is not None and cur["k"] == "Call" and cur["callee"]["k"] == "Member":
            chain.append(cur["callee"]["prop"])
            cur = cur["callee"]["obj"]
            if cur["k"] == "Ident":
                break
        base = chain[-1] if chain else None
        out.append({"name": p["key"], "annotation": f"z.{base}()" if base else None,
                    "required": not any(c in ("optional", "nullish", "default") for c in chain)})
    return out


# --------------------------------------------------------------------------- function analysis
class TsAnalyzer:
    def __init__(self, project: TsProject, mod: TsModule, unit: Unit | None, init_env: dict[str, Taint], depth: int,
                 stack: tuple[str, ...], mode: str, obj_param: str | None = None) -> None:
        self.p = project
        self.mod = mod
        self.unit = unit
        self.qual_name = unit.qual if unit else "<module>"
        self.init_env = dict(init_env)
        self.depth = depth
        self.stack = stack
        self.mode = mode
        self.obj_param = obj_param
        self.local_assigns: dict[str, dict[str, Any]] = {}
        self.local_types: dict[str, str] = {}
        self.agent_vars: dict[str, AgentSite] = {}
        self.counts: Counter[str] = Counter()
        self.res = FunctionResult()
        self.shadow: set[str] = set(init_env)
        if unit:
            for prm in unit.fn["params"]:
                self.shadow |= {n for n, _k in _pattern_names(prm["pat"])}

    def scoped_unit(self, name: str) -> Unit | None:
        """Resolve a function name through enclosing function scopes (innermost first)."""
        parts = self.qual_name.split(".")
        for i in range(len(parts), 0, -1):
            u = self.mod.units.get(".".join(parts[:i] + [name]))
            if u is not None:
                return u
        return None

    def run(self) -> FunctionResult:
        body = self.unit.fn["body"] if self.unit else [s for s in self.mod.body if s["k"] not in ("Func", "Class")]
        self.run_block(body, dict(self.init_env))
        return self.res

    # -- statements
    def run_block(self, stmts: list[dict[str, Any]], env: dict[str, Taint]) -> dict[str, Taint]:
        for st in stmts:
            env = self.run_stmt(st, env)
        return env

    def _terminates(self, stmts: list[dict[str, Any]]) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if last["k"] in ("Return", "Throw", "Jump"):
            return True
        if last["k"] == "If":
            return self._terminates(last["cons"]) and self._terminates(last["alt"])
        if last["k"] == "Block":
            return self._terminates(last["body"])
        return False

    def run_stmt(self, st: dict[str, Any], env: dict[str, Taint]) -> dict[str, Taint]:
        k = st["k"]
        if k in ("Func", "Class", "Import", "ExportNames"):
            return env
        if k == "Var":
            env = dict(env)
            for target, init in st["decls"]:
                if init is None:
                    continue
                name = target["name"] if target["k"] == "Ident" else None
                self.visit(init, env, assign_name=name)
                self.bind(target, self.taint(init, env), init, env)
            return env
        if k == "Expr":
            e = st["expr"]
            self.visit(e, env)
            if e["k"] == "Assign":
                env = dict(env)
                t = self.taint(e["value"], env)
                if e["op"] != "=":
                    t = merge(t, self.taint(e["target"], env))
                self.bind(e["target"], t, e["value"], env)
            return env
        if k == "Return":
            if st["arg"] is not None:
                self.visit(st["arg"], env, is_return=True)
                if st["arg"]["k"] == "Ident" and st["arg"]["name"] in self.agent_vars:
                    self.agent_vars[st["arg"]["name"]].returned = True
            return env
        if k == "Throw":
            self.visit(st["arg"], env)
            return env
        if k == "If":
            self.visit(st["test"], env)
            body_env, else_env = dict(env), dict(env)
            g = self.guard(st["test"], env)
            if g:
                var, kind, positive = g
                cur = env[var]
                ng = kind if GUARD_STRENGTH[kind] >= GUARD_STRENGTH[cur.guard] else cur.guard
                (body_env if positive else else_env)[var] = Taint(cur.origins, ng)
            b = self.run_block(st["cons"], body_env)
            e = self.run_block(st["alt"], else_env)
            bt, et = self._terminates(st["cons"]), self._terminates(st["alt"])
            if bt and not et:
                return e
            if et and not bt:
                return b
            return merge_env(b, e)
        if k == "Loop":
            body_env = dict(env)
            if st.get("head") is not None:
                self.visit(st["head"], env)
                if st.get("head_var") is not None:
                    self.bind(st["head_var"], self.taint(st["head"], env), None, body_env)
            out = self.run_block(st["body"], body_env)
            return merge_env(env, out)
        if k == "Block":
            return self.run_block(st["body"], env)
        if k == "Try":
            out = self.run_block(st["block"], dict(env))
            out = merge_env(out, self.run_block(st["handler"], dict(env)))
            return self.run_block(st["final"], out)
        if k == "Switch":
            self.visit(st["disc"], env)
            merged = dict(env)
            for case in st["cases"]:
                merged = merge_env(merged, self.run_block(case, dict(env)))
            return merged
        if k == "ExportDefault":
            self.visit(st["expr"], env)
            return env
        return env

    def bind(self, target: dict[str, Any], t: Taint | None, value: dict[str, Any] | None, env: dict[str, Taint]) -> None:
        if target["k"] == "Ident":
            n = target["name"]
            self.shadow.add(n)
            if t is not None:
                env[n] = t
            else:
                env.pop(n, None)
            if value is not None:
                self.local_assigns[n] = value
                ty = self.type_of(value)
                if ty:
                    self.local_types[n] = ty
                else:
                    self.local_types.pop(n, None)
        elif target["k"] == "ObjPat":
            for local, key in _pattern_names(target):
                self.shadow.add(local)
                sub = t
                if t is not None and key and any(o.startswith("objparam:") for o in t.origins):
                    sub = Taint(frozenset({f"param:{key}"}), t.guard)
                if sub is not None:
                    env[local] = sub
                else:
                    env.pop(local, None)
        elif target["k"] == "ArrPat":
            for local, _k in _pattern_names(target):
                self.shadow.add(local)
                if t is not None:
                    env[local] = t
        elif target["k"] == "Member" and target["obj"]["k"] == "Ident" and t is not None:
            n = target["obj"]["name"]
            env[n] = merge(env.get(n), t)  # obj.x = tainted -> obj tainted

    # -- types (receivers)
    def type_of(self, e: dict[str, Any] | None) -> str | None:
        if e is None:
            return None
        if e["k"] == "Unary" and e["op"] == "await":
            return self.type_of(e["arg"])
        if e["k"] == "New":
            q = self.p.qual(self.mod, e["callee"], self.shadow - set(self.local_assigns))
            if q and q.startswith("class:"):
                return q
            if q and q.startswith("rel:"):
                return q
            return None
        if e["k"] == "Ident":
            if e["name"] in self.local_types:
                return self.local_types[e["name"]]
            init = self.mod.consts.get(e["name"])
            if init is not None and e["name"] not in self.local_assigns:
                return self.type_of(init) if init["k"] == "New" else None
        if e["k"] == "Ident" and e["name"] == "this" and self.unit and self.unit.cls:
            return f"class:{self.mod.relpath}:{self.unit.cls}"
        if e["k"] == "Member" and isinstance(e["prop"], str) and e["obj"]["k"] == "Ident" and e["obj"]["name"] == "this" and self.unit and self.unit.cls:
            cls = self.mod.classes.get(self.unit.cls)
            if cls:
                fv = cls["fields"].get(e["prop"])
                if fv is not None:
                    return self.type_of(fv)
                ctor = cls["methods"].get("constructor")
                if ctor:
                    for node in _walk(ctor["body"]):
                        if node.get("k") == "Assign" and node["target"]["k"] == "Member" and node["target"]["obj"]["k"] == "Ident" \
                                and node["target"]["obj"]["name"] == "this" and node["target"]["prop"] == e["prop"]:
                            return self.type_of(node["value"])
        return None

    def method_target(self, callee: dict[str, Any]) -> tuple[TsModule, Unit] | None:
        if callee["k"] != "Member" or not isinstance(callee["prop"], str):
            return None
        if callee["obj"]["k"] == "Ident" and callee["obj"]["name"] == "this" and self.unit and self.unit.cls:
            u = self.mod.units.get(f"{self.unit.cls}.{callee['prop']}")
            return (self.mod, u) if u else None
        ty = self.type_of(callee["obj"])
        if ty and ty.startswith("class:"):
            _, rel, cname = ty.split(":", 2)
            m = self.p.modules.get(rel)
            u = m.units.get(f"{cname}.{callee['prop']}") if m else None
            return (m, u) if u else None
        if ty and ty.startswith("rel:"):
            found = self.p.resolve_function(self.mod, f"{ty}.{callee['prop']}")
            return found
        return None

    # -- guards
    def guard(self, test: dict[str, Any], env: dict[str, Taint]) -> tuple[str, str, bool] | None:
        positive = True
        while test["k"] == "Unary" and test["op"] == "!":
            positive = not positive
            test = test["arg"]
        if test["k"] == "Bin" and test["op"] in ("&&", "||"):
            for side in (test["left"], test["right"]):
                g = self.guard(side, env)
                if g:
                    return g[0], g[1], g[2] if positive else not g[2]
            return None
        if test["k"] == "Bin" and test["op"] in ("===", "==", "!==", "!="):
            a, b = test["left"], test["right"]
            for x, y in ((a, b), (b, a)):
                if x["k"] == "Ident" and x["name"] in env and self.taint(y, env) is None:
                    if y["k"] == "Lit" and y["value"] is None:
                        return None  # null/undefined check is not a guard
                    pos = test["op"] in ("===", "==")
                    return x["name"], GUARD_KNOWN, pos if positive else not pos
            # ALLOWED.indexOf(x) === -1
            return None
        if test["k"] == "Call":
            cal = test["callee"]
            if cal["k"] == "Member" and cal["prop"] in ("includes", "has", "test") and test["args"]:
                arg = test["args"][0]
                if arg["k"] == "Ident" and arg["name"] in env and self.taint(cal["obj"], env) is None:
                    return arg["name"], GUARD_KNOWN, positive
            for n in _walk(test):
                if n.get("k") == "Ident" and n["name"] in env:
                    return n["name"], GUARD_UNKNOWN, positive
        return None

    # -- taint
    def source_kind(self, e: dict[str, Any]) -> str | None:
        q = self.p.qual(self.mod, e if e["k"] != "Call" else e["callee"], self.shadow)
        if q is None:
            return None
        if e["k"] == "Call":
            if q == "global.fetch":
                opts = e["args"][1] if len(e["args"]) > 1 else None
                method = str(_lit(_prop(opts, "method")) or "GET").upper()
                return "network_content" if method in ("GET", "HEAD") else None
            if q in ("readline.question", "fs.readFileSync") and e["args"] and _lit(e["args"][0]) in (0, "0", "/dev/stdin"):
                return "stdin"
            return None
        if q == "global.process.argv" or q.startswith("global.process.argv."):
            return "argv"
        if q == "global.process.stdin" or q.startswith("global.process.stdin."):
            return "stdin"
        return None

    def taint(self, e: dict[str, Any] | None, env: dict[str, Taint]) -> Taint | None:
        if e is None:
            return None
        k = e["k"]
        if k == "Ident":
            if e["name"] in env:
                t = env[e["name"]]
                if any(o.startswith("objparam:") for o in t.origins) and self.p_schema_params:
                    return Taint(frozenset(f"param:{p}" for p in self.p_schema_params), t.guard)
                return t
            src = self.source_kind(e)
            return Taint(frozenset({f"source:{src}@{e['line']}"})) if src else None
        if k in ("Lit", "Regex", "Func", "Class"):
            return None
        if k == "Tpl":
            return merge(*(self.taint(x, env) for x in e["exprs"]))
        if k == "TaggedTpl":
            return self.taint(e["tpl"], env)
        if k == "Bin":
            if e["op"] in ("===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in"):
                return None
            return merge(self.taint(e["left"], env), self.taint(e["right"], env))
        if k == "Cond":
            return merge(self.taint(e["cons"], env), self.taint(e["alt"], env))
        if k == "Unary":
            if e["op"] in ("!", "typeof", "void", "delete"):
                return None
            return self.taint(e["arg"], env)
        if k == "Call":
            src = self.source_kind(e)
            if src:
                return Taint(frozenset({f"source:{src}@{e['line']}"}))
            q = self.p.qual(self.mod, e["callee"], self.shadow)
            if q in CLEANSERS:
                return None
            parts = [self.taint(a.get("arg") if a["k"] == "Spread" else a, env) for a in e["args"]]
            if e["callee"]["k"] == "Member":
                parts.append(self.taint(e["callee"]["obj"], env))
            t = merge(*parts)
            if t is not None and t.guard == GUARD_ABSENT:
                target = self.p.resolve_function(self.mod, q) if q else None
                if target is None and e["callee"]["k"] == "Ident":
                    nested = self.scoped_unit(e["callee"]["name"])
                    target = (self.mod, nested) if nested else None
                if target is not None and _is_validator(target[1].fn):
                    t = Taint(t.origins, GUARD_UNKNOWN)
            return t
        if k == "New":
            return merge(*(self.taint(a, env) for a in e["args"]))
        if k == "Member":
            src = self.source_kind(e)
            if src:
                return Taint(frozenset({f"source:{src}@{e['line']}"}))
            obj = e["obj"]
            if obj["k"] == "Ident" and obj["name"] in env and isinstance(e["prop"], str):
                t = env[obj["name"]]
                if any(o.startswith("objparam:") for o in t.origins):
                    return Taint(frozenset({f"param:{e['prop']}"}), t.guard)
            return self.taint(obj, env)
        if k in ("Array",):
            return merge(*(self.taint(x.get("arg") if x["k"] == "Spread" else x, env) for x in e["elts"]))
        if k == "Object":
            return merge(*(self.taint(p.get("value") if p["k"] == "Prop" else p.get("arg"), env) for p in e["props"]))
        if k in ("Spread", "SpreadProp"):
            return self.taint(e["arg"], env)
        if k == "Assign":
            return self.taint(e["value"], env)
        if k == "Seq":
            return self.taint(e["items"][-1], env) if e["items"] else None
        return None

    p_schema_params: list[str] = []

    # -- visiting
    def visit(self, e: Any, env: dict[str, Taint], assign_name: str | None = None, is_return: bool = False) -> None:
        if isinstance(e, list):
            for x in e:
                self.visit(x, env)
            return
        if not isinstance(e, dict):
            return
        k = e.get("k")
        direct = e["arg"] if k == "Unary" and e["op"] == "await" else e
        if k == "Func":
            if id(e) in self.mod.unit_by_fn:
                return  # separate unit
            # inline callback: analysed in place with the current (closure) environment
            sub = dict(env)
            for prm in e["params"]:
                for n, _key in _pattern_names(prm["pat"]):
                    sub.pop(n, None)
            self.run_block(e["body"], sub)
            return
        if k == "Unary" and e["op"] == "await":
            self.visit(e["arg"], env, assign_name, is_return)
            return
        if k == "Call":
            self.visit(e["callee"], env)
            for a in e["args"]:
                if a["k"] == "Func" and id(a) not in self.mod.unit_by_fn and e["callee"]["k"] == "Member" \
                        and isinstance(e["callee"]["prop"], str) and e["callee"]["prop"] in ARRAY_CALLBACK_METHODS:
                    sub = dict(env)
                    recv = self.taint(e["callee"]["obj"], env)
                    for prm in a["params"][:1]:
                        for n, _key in _pattern_names(prm["pat"]):
                            if recv is not None:
                                sub[n] = recv
                            else:
                                sub.pop(n, None)
                    self.run_block(a["body"], sub)
                else:
                    self.visit(a, env)
            self.handle_call(e, env, assign_name if direct is e else None, is_return and direct is e)
            return
        if k == "New":
            for a in e["args"]:
                self.visit(a, env)
            self.handle_new(e, env, assign_name if direct is e else None, is_return and direct is e)
            return
        if k == "Member":
            self.visit(e["obj"], env)
            if not isinstance(e["prop"], str):
                self.visit(e["prop"], env)
            q = self.p.qual(self.mod, e["obj"], self.shadow)
            if q == "global.process.env":
                key = e["prop"] if isinstance(e["prop"], str) else _lit(e["prop"])
                self.record_op(e, ops.SECRET_ACCESS, "process.env", env, [e["prop"]] if not isinstance(e["prop"], str) else [],
                               [], target_override=str(key) if key else None)
            return
        if k == "Tpl":
            self.visit(e["exprs"], env)
            return
        for ch in _children(e):
            self.visit(ch, env)

    def handle_new(self, e: dict[str, Any], env: dict[str, Taint], assign_name: str | None, is_return: bool) -> None:
        q = self.p.qual(self.mod, e["callee"], self.shadow)
        if q in AGENT_NEW:
            self.record_agent(e, env, assign_name, is_return, "openai-agents-js" if q.startswith("@openai") else "vercel-ai")
        elif q == "global.Function":
            self.record_op(e, ops.CODE_EXECUTION, "new Function", env, list(e["args"]), [])
        elif q in ("vm.Script",):
            self.record_op(e, ops.CODE_EXECUTION, "vm.Script", env, list(e["args"]), [])

    def handle_call(self, e: dict[str, Any], env: dict[str, Taint], assign_name: str | None, is_return: bool) -> None:
        cal = e["callee"]
        if cal["k"] == "Member" and isinstance(cal["prop"], dict) and _lit(cal["prop"]) is None:
            self.record_op(e, ops.DYNAMIC_DISPATCH, "<computed>()", env, list(e["args"]) + [cal["prop"]], [], resolution=UNKNOWN)
            return
        q = canonical(self.p.qual(self.mod, cal, self.shadow))
        if q in ("global.require", "global.import") or (cal["k"] == "Ident" and cal["name"] == "import"):
            if e["args"] and not isinstance(_lit(e["args"][0]), str):
                self.record_op(e, ops.DYNAMIC_DISPATCH, "dynamic import", env, list(e["args"]), [], resolution=UNKNOWN)
            return
        if q in TS_SINKS:
            cat = TS_SINKS[q]
            tgt, cont = self._split(e["args"], cat, q)
            attrs = {}
            if cat == ops.PROCESS_EXECUTION:
                opts = next((a for a in e["args"] if a["k"] == "Object"), None)
                sh = _lit(_prop(opts, "shell"))
                if q.split(".")[-1] in ("exec", "execSync"):
                    attrs["shell"] = True
                elif sh is not None:
                    attrs["shell"] = bool(sh)
            self.record_op(e, cat, q, env, tgt, cont, attrs=attrs)
            return
        if q in ("global.eval",):
            self.record_op(e, ops.CODE_EXECUTION, "eval", env, list(e["args"]), [])
            return
        if q == "global.fetch":
            opts = e["args"][1] if len(e["args"]) > 1 else None
            method = _prop(opts, "method")
            mv = _lit(method)
            if method is not None and mv is None:
                self.record_op(e, ops.NETWORK_STATE_CHANGE, "fetch", env, e["args"][:1], [], resolution=INFERRED, attrs={"method": "unresolved"})
            elif isinstance(mv, str) and mv.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                self.record_op(e, ops.NETWORK_STATE_CHANGE, "fetch", env, e["args"][:1], [_prop(opts, "body")], attrs={"method": mv.upper()})
            return
        if cal["k"] == "Member" and cal["prop"] == "send" and e["args"] and e["args"][0]["k"] == "New":
            cq = self.p.qual(self.mod, e["args"][0]["callee"], self.shadow) or ""
            if cq.startswith("@aws-sdk/"):
                cmd = cq.rsplit(".", 1)[-1]
                verb = re.sub(r"Command$", "", cmd)
                if verb.startswith(("GetSecretValue", "GetParameter")):
                    self.record_op(e, ops.SECRET_ACCESS, f"aws-sdk.{cmd}", env, list(e["args"][0]["args"]), [])
                elif not verb.startswith(AWS_READ_PREFIXES):
                    self.record_op(e, ops.CLOUD_SDK_CALL, f"aws-sdk.{cmd}", env, list(e["args"][0]["args"]), [], attrs={"api": cmd})
                return
        if q in AGENT_CALLS:
            self.record_agent(e, env, assign_name, is_return, "vercel-ai", call_style=True)
            return
        if q in RUN_FUNCS or (cal["k"] == "Member" and isinstance(cal["prop"], str) and cal["prop"] == "run" and e["args"] and e["args"][0]["k"] == "Ident"
                              and e["args"][0]["name"] in self.agent_vars):
            self.record_runner(e, env)
            return
        target = self.p.resolve_function(self.mod, q) if q else None
        if target is None:
            target = self.method_target(cal)
        if target is None and cal["k"] == "Ident":
            nested = self.scoped_unit(cal["name"])
            if nested:
                target = (self.mod, nested)
        if target is not None:
            self.follow(e, env, target)

    def _split(self, args: list[dict[str, Any]], cat: str, callee: str = "") -> tuple[list, list]:
        pos = TS_TARGET_ARGS.get(cat)
        if cat == ops.FILESYSTEM_WRITE and callee.rsplit(".", 1)[-1] in TWO_PATH_FS:
            pos = (0, 1)
        if pos is None:
            return list(args), []
        tgt, cont = [], []
        for i, a in enumerate(args):
            (tgt if i in pos else cont).append(a)
        return tgt, cont

    def record_op(self, node: dict[str, Any], cat: str, callee: str, env: dict[str, Taint], target_exprs: list, content_exprs: list,
                  resolution: str = CONFIRMED, attrs: dict | None = None, target_override: str | None = None) -> None:
        target_exprs = [x.get("arg") if x and x["k"] == "Spread" else x for x in target_exprs if x is not None]
        content_exprs = [x for x in content_exprs if x is not None]
        tt = merge(*(self.taint(x, env) for x in target_exprs))
        ct = merge(*(self.taint(x, env) for x in content_exprs))
        if target_override is not None and tt is None:
            target, tkind = redact_target(target_override), "literal"
        else:
            target, tkind = self._describe(target_exprs, tt)
        self.counts[callee] += 1
        op_id = f"operation:{self.mod.relpath}:{self.qual_name}:{callee}#{self.counts[callee]}"
        self.res.ops.append(OpHit(
            op_id=op_id, category=cat, callee=callee, file=self.mod.relpath, line=node["line"], end_line=node["line"],
            func_qual=self.qual_name, target_controlled=tt is not None, content_controlled=ct is not None,
            origins=tuple(sorted(tt.origins)) if tt else (), content_origins=tuple(sorted(ct.origins)) if ct else (),
            guard=tt.guard if tt else GUARD_ABSENT, target=target, target_kind=tkind, resolution=resolution,
            attributes=tuple(sorted((attrs or {}).items())), snippet=snippet(self.mod.lines, node["line"]),
        ))

    def _describe(self, exprs: list, t: Taint | None) -> tuple[str, str]:
        if not exprs:
            return "", "unresolved"
        if t is not None:
            names = t.params + [o.split(":", 1)[1].split("@")[0] for o in t.untrusted_sources]
            return "symbolic:" + ",".join(sorted(set(names))), "symbolic"
        first = exprs[0]
        v = self.const_str(first)
        if v is not None:
            return redact_target(v), "literal"
        if first["k"] == "Array":
            parts = [self.const_str(x) for x in first["elts"]]
            if all(p is not None for p in parts):
                return redact_target(" ".join(parts)), "literal"  # type: ignore[arg-type]
        return "unresolved", "unresolved"

    def const_str(self, e: dict[str, Any] | None, depth: int = 0) -> str | None:
        if e is None or depth > 4:
            return None
        v = _lit(e)
        if isinstance(v, str):
            return v
        if e["k"] == "Ident" and e["name"] not in self.local_assigns and e["name"] in self.mod.consts:
            return self.const_str(self.mod.consts[e["name"]], depth + 1)
        if e["k"] == "Ident" and e["name"] in self.local_assigns:
            return self.const_str(self.local_assigns[e["name"]], depth + 1)
        if e["k"] == "Tpl":
            out = [e["quasis"][0]]
            for x, q in zip(e["exprs"], e["quasis"][1:]):
                s = self.const_str(x, depth + 1)
                if s is None:
                    return None
                out += [s, q]
            return "".join(out)
        if e["k"] == "Bin" and e["op"] == "+":
            a, b = self.const_str(e["left"], depth + 1), self.const_str(e["right"], depth + 1)
            return a + b if a is not None and b is not None else None
        return None

    def follow(self, call: dict[str, Any], env: dict[str, Taint], target: tuple[TsModule, Unit]) -> None:
        tmod, unit = target
        fid = f"{tmod.relpath}:{unit.qual}"
        arg_taints: dict[str, Taint | None] = {}
        for i, prm in enumerate(unit.fn["params"]):
            arg = call["args"][i] if i < len(call["args"]) else None
            if arg is not None and arg["k"] == "Spread":
                arg = arg["arg"]
            names = _pattern_names(prm["pat"])
            if prm["pat"]["k"] == "Ident":
                arg_taints[names[0][0]] = self.taint(arg, env)
            else:
                for local, key in names:
                    sub = _prop(arg, key) if (arg is not None and arg["k"] == "Object" and key) else arg
                    arg_taints[local] = self.taint(sub, env)
        if self.mode == "source":
            self.res.call_sites.append(CallSite(fid, self.mod.relpath, call["line"], self.qual_name, arg_taints))
            return
        if fid in self.stack:
            return
        if self.depth + 1 > 3:
            if _may_reach_sink(self.p, tmod, unit):
                self.record_op(call, ops.DYNAMIC_DISPATCH, f"depth-limit:{unit.qual}", env, list(call["args"]), [], resolution=UNKNOWN,
                               attrs={"reason": "helper chain exceeds 3 hops and a recognised sink is syntactically reachable beyond it"})
            return
        init = {p: t for p, t in arg_taints.items() if t is not None}
        sub = self.p.analyze(tmod, unit, init, self.depth + 1, self.stack + (fid,), "tool")
        step = (self.mod.relpath, call["line"], self.qual_name, fid)
        for o in sub.ops:
            self.res.ops.append(o.with_via(step))

    # -- agents
    def record_agent(self, e: dict[str, Any], env: dict[str, Taint], assign_name: str | None, is_return: bool,
                     framework: str, call_style: bool = False) -> None:
        cfg = e["args"][0] if e["args"] and e["args"][0]["k"] == "Object" else None
        if cfg is None:
            return
        if call_style and _prop(cfg, "tools") is None:
            return  # a model call without tools has no agent capability
        name = self.const_str(_prop(cfg, "name"))
        if call_style and not name:
            fn = self.p.qual(self.mod, e["callee"]).split(".")[-1]
            where = self.qual_name.replace("route:", "")
            name = f"{fn} in {where}" if where != "<module>" else f"{fn}@{self.mod.relpath}:{e['line']}"
        instr = _prop(cfg, "instructions") or _prop(cfg, "system")
        kind, taint, digest, length = "absent", None, None, None
        if instr is not None:
            s = self.const_str(instr)
            if s is not None:
                kind, digest, length = "static", sha256_text(s), len(s)
            elif instr["k"] == "Func":
                kind = "callable"
            else:
                kind, taint, digest = "dynamic", self.taint(instr, env), sha256_text(repr(instr.get("k")) + str(instr["line"]))
        model_e = _prop(cfg, "model")
        model = self.const_str(model_e)
        if model is None and model_e is not None and model_e["k"] == "Call" and model_e["args"]:
            model = self.const_str(model_e["args"][0])
        tools_e = _prop(cfg, "tools")
        site = AgentSite(
            file=self.mod.relpath, line=e["line"], end_line=e["line"], func_qual=self.qual_name, framework=framework,
            var=assign_name, name=name, model=model, model_line=model_e["line"] if model_e else e["line"],
            instructions_kind=kind, instructions_taint=taint, instructions_sha256=digest, instructions_length=length,
            instructions_line=instr["line"] if instr else e["line"],
            tools=self.resolve_tools(tools_e) if tools_e is not None else [],
            handoff_refs=self.resolve_handoffs(_prop(cfg, "handoffs")),
            mcp_refs=self.resolve_mcp(_prop(cfg, "mcpServers")),
            returned=is_return, col=0,
        )
        if assign_name:
            self.agent_vars[assign_name] = site
        self.res.agent_sites.append(site)
        if call_style:
            user = merge(self.taint(_prop(cfg, "prompt"), env), self.taint(_prop(cfg, "messages"), env))
            self.res.runner_sites.append(RunnerSite(self.mod.relpath, e["line"], self.qual_name, None, None, user, site))

    def _tool_ref(self, el: dict[str, Any], depth: int = 0) -> list[ToolRef]:
        line = el["line"]
        if depth > 4:
            return [ToolRef("unknown", None, line, reason="tool indirection too deep")]
        if el["k"] == "Call" and id(el) in self.mod.tool_by_call:
            return [ToolRef("function", self.mod.tool_by_call[id(el)][len("tool:"):], line)]
        if el["k"] == "Ident":
            n = el["name"]
            init = self.local_assigns.get(n) if n in self.local_assigns else self.mod.consts.get(n)
            if init is not None:
                return self._tool_ref(init, depth + 1)
            if n in self.mod.imports and self.mod.imports[n][0].startswith("."):
                spec, imported = self.mod.imports[n]
                tmod = self.p.resolve_relative(self.mod.relpath, spec)
                if tmod is not None:
                    local = tmod.exports.get(imported or "default", imported)
                    init = tmod.consts.get(local) if local else None
                    if init is not None and init["k"] == "Call" and id(init) in tmod.tool_by_call:
                        return [ToolRef("function", tmod.tool_by_call[id(init)][len("tool:"):], line)]
                    if init is not None and init["k"] in ("Array", "Object"):
                        sub = TsAnalyzer(self.p, tmod, None, {}, 0, (), "source")
                        return sub.resolve_tools(init)
            q = self.p.qual(self.mod, el)
            if q and not q.startswith(("local:", "const:", "rel:")):
                return [ToolRef("external", None, line, q, reason="tool object defined outside the scanned project")]
            return [ToolRef("unknown", None, line, reason=f"unresolved tool reference {n}")]
        if el["k"] == "Member" and isinstance(el["prop"], str) and el["obj"]["k"] == "Ident":
            base = self.local_assigns.get(el["obj"]["name"]) or self.mod.consts.get(el["obj"]["name"])
            if base is not None and base["k"] == "Object" and _prop(base, el["prop"]) is not None:
                return self._tool_ref(_prop(base, el["prop"]), depth + 1)
        if el["k"] == "Unary" and el["op"] == "await":
            return self._tool_ref(el["arg"], depth + 1)
        if el["k"] == "Call":
            q = self.p.qual(self.mod, el["callee"], self.shadow) or ""
            factory = self.p.resolve_function(self.mod, q) if q else None
            if factory is not None:
                fmod, funit = factory
                for st in _walk(funit.fn["body"]):
                    if st.get("k") == "Return" and st.get("arg") is not None and st["arg"]["k"] == "Call" and id(st["arg"]) in fmod.tool_by_call:
                        return [ToolRef("function", fmod.tool_by_call[id(st["arg"])][len("tool:"):], line)]
            if q in HOSTED_TOOL_FUNCS or PROVIDER_TOOL_RE.match(q):
                return [ToolRef("hosted", None, line, q, reason="provider-hosted tool; no operation on the application host")]
            if q in UNKNOWN_TOOL_FUNCS:
                return [ToolRef("unknown", None, line, q, reason=UNKNOWN_TOOL_FUNCS[q])]
            if q in LIBRARY_TOOL_FUNCS:
                cfg = el["args"][0] if el["args"] and el["args"][0]["k"] == "Object" else None
                env_cfg = _prop(cfg, "environment")
                if env_cfg is not None:
                    etype = self.const_str(_prop(env_cfg, "type")) if env_cfg["k"] == "Object" else None
                    if etype in ops.HOSTED_SHELL_ENVIRONMENTS:
                        return [ToolRef("hosted", None, line, q, reason=f"shellTool runs in a provider-hosted container ({etype})")]
                    if etype != "local":
                        return [ToolRef("unknown", None, line, q, reason="shellTool environment not statically resolvable (local vs hosted container)")]
                appr = _prop(cfg, "needsApproval")
                approval = None if appr is None else ("True" if _lit(appr) is True else ("False" if _lit(appr) is False else "dynamic"))
                return [ToolRef("library", None, line, q, reason="documented library tool behaviour (source not analysed)", approval=approval)]
            if el["callee"]["k"] == "Member" and el["callee"]["prop"] == "asTool":
                ref = self.agent_ref(el["callee"]["obj"])
                if ref is not None:
                    return [ToolRef("agent", None, line, _lit(_prop(el["args"][0] if el["args"] else None, "toolName")),
                                    reason="agent.asTool() delegation", agent_ref=ref)]
                return [ToolRef("unknown", None, line, reason="agent.asTool() on an unresolvable agent expression")]
            return [ToolRef("unknown", None, line, reason=f"unsupported tool expression {q or el['callee'].get('name', '?')}(…)")]
        return [ToolRef("unknown", None, line, reason="unsupported tool expression")]

    def resolve_tools(self, e: dict[str, Any], depth: int = 0) -> list[ToolRef]:
        if depth > 4:
            return [ToolRef("unknown", None, e["line"], reason="tool list indirection too deep")]
        if e["k"] == "Array":
            out: list[ToolRef] = []
            for x in e["elts"]:
                out += self.resolve_tools(x["arg"], depth + 1) if x["k"] == "Spread" else self._tool_ref(x)
            return out
        if e["k"] == "Object":  # Vercel AI: { name: tool }
            out = []
            for p in e["props"]:
                if p["k"] == "Prop":
                    out += self._tool_ref(p["value"])
                else:
                    out += self.resolve_tools(p["arg"], depth + 1)
            return out
        if e["k"] == "Ident":
            n = e["name"]
            init = self.local_assigns.get(n) if n in self.local_assigns else self.mod.consts.get(n)
            if init is not None and init["k"] in ("Array", "Object"):
                return self.resolve_tools(init, depth + 1)
            if init is not None:
                return self._tool_ref(e)
            if n in self.mod.imports and self.mod.imports[n][0].startswith("."):
                return self._tool_ref(e)
        return [ToolRef("unknown", None, e["line"], reason="dynamic tool list")]

    def agent_ref(self, e: dict[str, Any] | None, depth: int = 0) -> dict[str, Any] | None:
        if e is None or depth > 4:
            return None
        if e["k"] == "Call":
            q = self.p.qual(self.mod, e["callee"], self.shadow)
            if q in HANDOFF_FUNCS and e["args"]:
                return self.agent_ref(e["args"][0], depth + 1)
            target = self.p.resolve_function(self.mod, q) if q else None
            if target is not None:
                return {"factory": f"{target[0].relpath}:{target[1].qual}", "ref_line": e["line"]}
            return None
        if e["k"] == "New" and self.p.qual(self.mod, e["callee"]) in AGENT_NEW:
            return {"inline": True, "file": self.mod.relpath, "line": e["line"], "col": 0, "ref_line": e["line"]}
        if e["k"] == "Ident":
            n = e["name"]
            if n in self.agent_vars:
                return {"file": self.mod.relpath, "func": self.qual_name, "var": n, "ref_line": e["line"]}
            if n in self.local_assigns:
                return self.agent_ref(self.local_assigns[n], depth + 1)
            if n in self.mod.consts:
                return {"file": self.mod.relpath, "func": "<module>", "var": n, "ref_line": e["line"]}
            if n in self.mod.imports and self.mod.imports[n][0].startswith("."):
                spec, imported = self.mod.imports[n]
                tmod = self.p.resolve_relative(self.mod.relpath, spec)
                if tmod is not None:
                    local = tmod.exports.get(imported or "default", imported)
                    if local in tmod.consts:
                        return {"file": tmod.relpath, "func": "<module>", "var": local, "ref_line": e["line"]}
        return None

    def resolve_handoffs(self, e: dict[str, Any] | None) -> list[dict[str, Any]]:
        if e is None:
            return []
        if e["k"] != "Array":
            return [{"unresolved": True, "ref_line": e["line"], "reason": "dynamic handoffs list"}]
        out = []
        for x in e["elts"]:
            r = self.agent_ref(x)
            out.append(r if r is not None else {"unresolved": True, "ref_line": x["line"], "reason": "unresolved handoff"})
        return out

    def resolve_mcp(self, e: dict[str, Any] | None) -> list[McpRef]:
        if e is None:
            return []
        elts = e["elts"] if e["k"] == "Array" else [e]
        out = []
        for x in elts:
            node = x
            if node["k"] == "Ident":
                node = self.local_assigns.get(node["name"]) or self.mod.consts.get(node["name"]) or node
            if node["k"] != "New":
                out.append(McpRef("unknown", x["line"], resolution=UNKNOWN))
                continue
            transport = MCP_CLIENT_NEW.get(self.p.qual(self.mod, node["callee"]) or "")
            if transport is None:
                out.append(McpRef("unknown", x["line"], resolution=UNKNOWN))
                continue
            cfg = node["args"][0] if node["args"] else None
            ref = McpRef(transport, node["line"])
            strings: list[str] = []
            full = self.const_str(_prop(cfg, "fullCommand"))
            if full:
                strings = full.split()
                ref.command = full
            else:
                ref.command = self.const_str(_prop(cfg, "command"))
                args = _prop(cfg, "args")
                if args is not None and args["k"] == "Array":
                    strings = [s for s in (self.const_str(a) for a in args["elts"]) if s]
                if ref.command:
                    ref.command = " ".join([ref.command] + strings)
            url = self.const_str(_prop(cfg, "url"))
            ref.url = redact_target(url) if url else None
            ref.server_file = next((s for s in strings if s.endswith(TS_SUFFIXES + (".py",))), None)
            if ref.command:
                ref.command = redact_target(ref.command)
            if ref.server_file is None and transport == "stdio":
                ref.resolution = UNKNOWN
            out.append(ref)
        return out

    def record_runner(self, e: dict[str, Any], env: dict[str, Taint]) -> None:
        agent_e = e["args"][0] if e["args"] else None
        input_e = e["args"][1] if len(e["args"]) > 1 else None
        var = agent_e["name"] if agent_e is not None and agent_e["k"] == "Ident" else None
        site = self.agent_vars.get(var) if var else None
        factory = None
        if site is None and var and var in self.local_assigns:
            v = self.local_assigns[var]
            v = v["arg"] if v["k"] == "Unary" and v["op"] == "await" else v
            if v["k"] == "Call":
                t = self.p.resolve_function(self.mod, self.p.qual(self.mod, v["callee"], self.shadow - {var}))
                if t:
                    factory = f"{t[0].relpath}:{t[1].qual}"
        self.res.runner_sites.append(RunnerSite(self.mod.relpath, e["line"], self.qual_name, var, factory, self.taint(input_e, env), site))


_VALIDATOR_CACHE: dict[int, bool] = {}


def _is_validator(fn: dict[str, Any]) -> bool:
    """A helper that throws (or returns early) under a condition on its own parameter: a guard we cannot model."""
    key = id(fn)
    if key in _VALIDATOR_CACHE:
        return _VALIDATOR_CACHE[key]
    params = {n for prm in fn["params"] for n, _k in _pattern_names(prm["pat"])}
    found = False
    for st in _walk(fn["body"]):
        if st.get("k") == "If" and st["cons"] and st["cons"][-1]["k"] in ("Throw", "Return"):
            names = {x["name"] for x in _walk(st["test"]) if x.get("k") == "Ident"}
            if names & params or any(x.get("k") == "Ident" for x in _walk(st["test"])):
                found = st["cons"][-1]["k"] == "Throw" or bool(names & params)
                if found:
                    break
    _VALIDATOR_CACHE[key] = found
    return found


def _walk(n: Any) -> Iterable[dict[str, Any]]:
    stack = [n]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if "k" in cur:
                yield cur
            stack.extend(v for k, v in cur.items() if k not in ("k", "line"))
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)


def _may_reach_sink(p: TsProject, mod: TsModule, unit: Unit, budget: int = 40) -> bool:
    seen: set[tuple[str, str]] = set()
    stack = [(mod, unit)]
    while stack and len(seen) < budget:
        m, u = stack.pop()
        if (m.relpath, u.qual) in seen:
            continue
        seen.add((m.relpath, u.qual))
        for n in _walk(u.fn["body"]):
            if n["k"] in ("Call", "New"):
                q = canonical(p.qual(m, n["callee"]))
                if q in TS_SINKS or q in ("global.eval", "global.fetch", "global.Function"):
                    return True
                if n["callee"]["k"] == "Member" and isinstance(n["callee"]["prop"], dict):
                    return True
                t = p.resolve_function(m, q) if q else None
                if t:
                    stack.append(t)
            if n["k"] == "Member" and p.qual(m, n["obj"]) == "global.process.env":
                return True
    return bool(stack)


def _analyze(self: TsProject, mod: TsModule, unit: Unit | None, init_env: dict[str, Taint], depth: int, stack: tuple[str, ...],
             mode: str, obj_param: str | None = None, schema_params: list[str] | None = None) -> FunctionResult:
    key = (mod.relpath, unit.qual if unit else "<module>", mode, depth, frozenset(init_env.items()))
    cache = self.__dict__.setdefault("_cache", {})
    if key in cache:
        return cache[key]
    a = TsAnalyzer(self, mod, unit, init_env, depth, stack, mode, obj_param)
    a.p_schema_params = schema_params or []
    try:
        res = a.run()
    except RecursionError:
        res = FunctionResult(unknowns=[{"file": mod.relpath, "line": unit.fn["line"] if unit else 1, "reason": "analysis recursion budget exceeded"}])
    cache[key] = res
    return res


TsProject.analyze = _analyze  # type: ignore[attr-defined]


def analyze_project(files: dict[str, str]) -> TsResult:
    """Analyse TS/JS sources ``{relpath: text}`` and return detector results."""
    proj = TsProject()
    for rel in sorted(files):
        proj.add(rel, files[rel])
    res = proj.result
    for mod in proj.modules.values():
        res.imported_packages |= {m for m in mod.top_modules if m}
        for var, (name, line) in sorted(mod.mcp_servers.items()):
            res.mcp_servers.append({"id": f"mcp_server:{mod.relpath}:{var}", "name": str(name), "file": mod.relpath, "line": line, "var": var})
    # resolve `execute: handlerRef` to a function unit (same file or relative import)
    for tool in res.tools.values():
        if tool.execute_ref is not None and tool.unit is None:
            tmod = proj.modules[tool.file]
            found = proj.resolve_function(tmod, proj.qual(tmod, tool.execute_ref))
            if found is not None:
                tool.unit_file, tool.unit = found[0].relpath, found[1]
                if not tool.params and tool.unit.fn["params"] and tool.unit.fn["params"][0]["pat"]["k"] == "ObjPat":
                    tool.params = [k or n for n, k in _pattern_names(tool.unit.fn["params"][0]["pat"])]
    # tool-mode analysis
    for tid in sorted(res.tools):
        tool = res.tools[tid]
        if tool.unit is None:
            continue
        mod = proj.modules[tool.unit_file or tool.file]
        init: dict[str, Taint] = {}
        first = tool.unit.fn["params"][0]["pat"] if tool.unit.fn["params"] else None
        if first is not None and first["k"] == "ObjPat":
            for local, key in _pattern_names(first):
                init[local] = Taint(frozenset({f"param:{key or local}"}))
        elif first is not None and first["k"] == "Ident":
            init[first["name"]] = Taint(frozenset({f"objparam:{first['name']}"}))
        r = proj.analyze(mod, tool.unit, init, 0, (f"{mod.relpath}:{tool.unit.qual}",), "tool", tool.obj_param, tool.params)  # type: ignore[attr-defined]
        tool.ops = r.ops
    # source-mode analysis for every unit and module body
    for rel in sorted(proj.modules):
        mod = proj.modules[rel]
        for unit in [None] + [mod.units[q] for q in sorted(mod.units)]:
            env: dict[str, Taint] = {}
            if unit is not None:
                for prm in unit.fn["params"]:
                    for local, _key in _pattern_names(prm["pat"]):
                        env[local] = Taint(frozenset({f"source:http_request_param@{unit.fn['line']}" if unit.kind == "route" else f"param:{local}"}))
            r = proj.analyze(mod, unit, env, 0, (), "source")  # type: ignore[attr-defined]
            res.agent_sites += r.agent_sites
            res.runner_sites += r.runner_sites
            res.call_sites += r.call_sites
            res.direct_ops += r.ops
    return res
