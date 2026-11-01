"""Python AST project index, import/symbol resolver and framework recognisers.

Supported explicit patterns (see docs/methodology.md for the full matrix):
  * OpenAI Agents SDK: ``Agent(...)``, ``@function_tool``, ``function_tool(fn)``,
    ``Runner.run/run_sync/run_streamed``, ``MCPServerStdio/Sse/StreamableHttp``.
  * MCP Python SDK / FastMCP: ``FastMCP(...)`` + ``@server.tool()``.
  * LangChain/LangGraph: ``@tool``, ``StructuredTool.from_function``, ``create_react_agent``.
Anything else is reported as an explicit coverage gap, never as "safe".
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from agentic_bom.core.evidence import fingerprint, redact, sha256_text

BUILTIN_NAMES = frozenset(dir(builtins))

AGENT_CTORS = {"agents.Agent", "agents.agent.Agent"}
LANGGRAPH_AGENT_CTORS = {"langgraph.prebuilt.create_react_agent", "langgraph.prebuilt.chat_agent_executor.create_react_agent"}
HANDOFF_FUNCS = {"agents.handoff", "agents.handoffs.handoff"}
RUNNER_FUNCS = {
    f"agents.{cls}.{m}" for cls in ("Runner", "run.Runner") for m in ("run", "run_sync", "run_streamed")
}
FUNCTION_TOOL_DECORATORS = {"agents.function_tool", "agents.tool.function_tool"}
LANGCHAIN_TOOL_DECORATORS = {"langchain_core.tools.tool", "langchain.tools.tool", "langchain.agents.tool", "langchain_core.tools.convert.tool"}
FUNCTION_TOOL_WRAPPERS = (
    FUNCTION_TOOL_DECORATORS
    | LANGCHAIN_TOOL_DECORATORS
    | {"langchain_core.tools.StructuredTool.from_function", "langchain.tools.StructuredTool.from_function"}
)
FASTMCP_CTORS = {
    "mcp.server.fastmcp.FastMCP",
    "mcp.server.fastmcp.server.FastMCP",
    "fastmcp.FastMCP",
    # MCP Python SDK renamed FastMCP -> MCPServer on its main branch (observed at d7845c0)
    "mcp.server.mcpserver.MCPServer",
    "mcp.server.mcpserver.server.MCPServer",
}
MCP_CLIENT_CTORS = {
    "agents.mcp.MCPServerStdio": "stdio",
    "agents.mcp.server.MCPServerStdio": "stdio",
    "agents.mcp.MCPServerSse": "sse",
    "agents.mcp.server.MCPServerSse": "sse",
    "agents.mcp.MCPServerStreamableHttp": "streamable_http",
    "agents.mcp.server.MCPServerStreamableHttp": "streamable_http",
}
ROUTE_DECORATOR_ATTRS = {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket"}

# Modules that must never be resolved to a same-named local file via suffix matching.
_NO_SUFFIX_MATCH = {
    "os", "sys", "subprocess", "shutil", "pathlib", "builtins", "requests", "httpx", "boto3",
    "flask", "agents", "mcp", "fastmcp", "langchain", "langchain_core", "langgraph", "json", "re",
    "asyncio", "io", "urllib",
}


@dataclass
class ModuleInfo:
    relpath: str
    modname: str
    is_package: bool
    tree: ast.Module
    lines: list[str]
    imports: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    classes: set[str] = field(default_factory=set)
    module_assigns: dict[str, ast.expr] = field(default_factory=dict)
    fastmcp_vars: dict[str, ast.Call] = field(default_factory=dict)
    imported_top_modules: set[str] = field(default_factory=set)


@dataclass
class ToolInfo:
    id: str
    name: str
    framework: str
    module: ModuleInfo
    func: ast.FunctionDef | ast.AsyncFunctionDef
    func_qual: str
    params: list[str]
    contract: dict[str, Any]
    mcp_server_var: str | None = None
    line: int = 0
    decorator_line: int = 0

    @property
    def fid(self) -> str:
        return f"{self.module.relpath}:{self.func_qual}"


def module_name_for(rel: PurePosixPath) -> tuple[str, bool]:
    parts = list(rel.with_suffix("").parts)
    is_pkg = False
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
        is_pkg = True
    return ".".join(parts) if parts else "__root__", is_pkg


class ProjectIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules: dict[str, ModuleInfo] = {}
        self.by_path: dict[str, ModuleInfo] = {}
        self.parse_errors: list[dict[str, str]] = []
        self._suffix_cache: dict[str, ModuleInfo | None] = {}

    # -- building -----------------------------------------------------------
    def add_source(self, relpath: str, source: str) -> None:
        rel = PurePosixPath(relpath)
        modname, is_pkg = module_name_for(rel)
        try:
            tree = ast.parse(source, filename=relpath)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            self.parse_errors.append({"file": relpath, "error": type(exc).__name__})
            return
        mod = ModuleInfo(relpath=relpath, modname=modname, is_package=is_pkg, tree=tree, lines=source.splitlines())
        try:
            self._index_module(mod)
        except RecursionError:
            self.parse_errors.append({"file": relpath, "error": "RecursionError"})
            return
        self.modules[modname] = mod
        self.by_path[relpath] = mod
        # also register without a leading "src." so imports resolve for src-layout projects
        if modname.startswith("src."):
            self.modules.setdefault(modname[4:], mod)

    def _index_module(self, mod: ModuleInfo) -> None:
        pkg_parts = mod.modname.split(".") if mod.is_package else mod.modname.split(".")[:-1]
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    mod.imported_top_modules.add(a.name.split(".")[0])
                    if a.asname:
                        mod.imports[a.asname] = (a.name, None)
                    else:
                        top = a.name.split(".")[0]
                        mod.imports[top] = (top, None)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base_parts = pkg_parts[: len(pkg_parts) - (node.level - 1)] if node.level > 1 else list(pkg_parts)
                    if node.level - 1 > len(pkg_parts):
                        base_parts = []
                    base = ".".join(base_parts + ([node.module] if node.module else []))
                else:
                    base = node.module or ""
                    mod.imported_top_modules.add(base.split(".")[0])
                for a in node.names:
                    if a.name == "*":
                        continue
                    mod.imports[a.asname or a.name] = (base, a.name) if base else (a.name, None)
        for stmt in mod.tree.body:
            self._index_stmt(mod, stmt, prefix="")
        # FastMCP instances anywhere in the module (module level or inside factory functions)
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and len(node.targets) == 1:
                tgt = node.targets[0]
                if isinstance(tgt, ast.Name) and self.qualname(mod, node.value.func) in FASTMCP_CTORS:
                    mod.fastmcp_vars[tgt.id] = node.value

    def _index_stmt(self, mod: ModuleInfo, stmt: ast.stmt, prefix: str) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            q = f"{prefix}{stmt.name}"
            mod.functions[q] = stmt
            # one level of nested functions (common for tool factories)
            if not prefix:
                for sub in stmt.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        mod.functions[f"{q}.{sub.name}"] = sub
        elif isinstance(stmt, ast.ClassDef) and not prefix:
            mod.classes.add(stmt.name)
            for sub in stmt.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mod.functions[f"{stmt.name}.{sub.name}"] = sub
        elif isinstance(stmt, ast.Assign) and not prefix:
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    mod.module_assigns[tgt.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and not prefix and stmt.value is not None:
            if isinstance(stmt.target, ast.Name):
                mod.module_assigns[stmt.target.id] = stmt.value
        elif isinstance(stmt, (ast.If, ast.Try)) and not prefix:
            for sub in getattr(stmt, "body", []):
                self._index_stmt(mod, sub, prefix)

    # -- resolution ---------------------------------------------------------
    def resolve_module(self, modname: str) -> ModuleInfo | None:
        if modname in self.modules:
            return self.modules[modname]
        if modname.split(".")[0] in _NO_SUFFIX_MATCH:
            return None
        if modname in self._suffix_cache:
            return self._suffix_cache[modname]
        cands = {id(m): m for name, m in self.modules.items() if name.endswith("." + modname)}
        found = next(iter(cands.values())) if len(cands) == 1 else None
        self._suffix_cache[modname] = found
        return found

    def qualname(self, mod: ModuleInfo, expr: ast.AST) -> str | None:
        """Best-effort fully qualified name of a Name/Attribute expression."""
        if isinstance(expr, ast.Name):
            n = expr.id
            if n in mod.imports:
                m, a = mod.imports[n]
                return f"{m}.{a}" if a else m
            if n in mod.functions or n in mod.classes or n in mod.module_assigns:
                return f"{mod.modname}.{n}"
            if n in BUILTIN_NAMES:
                return f"builtins.{n}"
            return None
        if isinstance(expr, ast.Attribute):
            base = self.qualname(mod, expr.value)
            return f"{base}.{expr.attr}" if base else None
        return None

    def lookup_function(self, qual: str | None, _depth: int = 0) -> tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef, str] | None:
        if not qual or _depth > 4:
            return None
        parts = qual.split(".")
        for i in range(len(parts) - 1, 0, -1):
            modpart, rest = ".".join(parts[:i]), ".".join(parts[i:])
            m = self.resolve_module(modpart)
            if m is None:
                continue
            if rest in m.functions:
                return m, m.functions[rest], rest
            head = rest.split(".")[0]
            if head in m.imports:  # re-export through __init__ or alias
                im, ia = m.imports[head]
                target = f"{im}.{ia}" if ia else im
                tail = rest[len(head):]
                return self.lookup_function(target + tail, _depth + 1)
            return None
        return None

    def lookup_class(self, qual: str | None) -> tuple[ModuleInfo, str] | None:
        if not qual or "." not in qual:
            return None
        modpart, name = qual.rsplit(".", 1)
        m = self.resolve_module(modpart)
        if m is None:
            return None
        if name in m.classes:
            return m, name
        if name in m.imports:
            im, ia = m.imports[name]
            if ia and f"{im}.{ia}" != qual:
                return self.lookup_class(f"{im}.{ia}")
        return None

    def lookup_module_var(self, qual: str | None) -> tuple[ModuleInfo, ast.expr] | None:
        if not qual or "." not in qual:
            return None
        modpart, name = qual.rsplit(".", 1)
        m = self.resolve_module(modpart)
        if m is None:
            return None
        if name in m.module_assigns:
            return m, m.module_assigns[name]
        if name in m.imports:
            im, ia = m.imports[name]
            if ia:
                return self.lookup_module_var(f"{im}.{ia}")
        return None

    def module_for_file(self, rel: str) -> ModuleInfo | None:
        return self.by_path.get(rel)


def const_str(mod: ModuleInfo, expr: ast.AST | None, index: ProjectIndex | None = None, _depth: int = 0) -> str | None:
    """Statically evaluate a string constant (literals, module-level constants, constant f-strings, + concat)."""
    if expr is None or _depth > 5:
        return None
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, ast.Name):
        if expr.id in mod.module_assigns:
            return const_str(mod, mod.module_assigns[expr.id], index, _depth + 1)
        if index is not None and expr.id in mod.imports:
            found = index.lookup_module_var(index.qualname(mod, expr))
            if found:
                return const_str(found[0], found[1], index, _depth + 1)
        return None
    if isinstance(expr, ast.JoinedStr):
        out = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                out.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                s = const_str(mod, v.value, index, _depth + 1)
                if s is None:
                    return None
                out.append(s)
        return "".join(out)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        a = const_str(mod, expr.left, index, _depth + 1)
        b = const_str(mod, expr.right, index, _depth + 1)
        return a + b if a is not None and b is not None else None
    return None


def _decorator_parts(dec: ast.expr) -> tuple[ast.expr, ast.Call | None]:
    if isinstance(dec, ast.Call):
        return dec.func, dec
    return dec, None


def is_route_handler(mod: ModuleInfo, func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        f, call = _decorator_parts(dec)
        if call is not None and isinstance(f, ast.Attribute) and f.attr in ROUTE_DECORATOR_ATTRS:
            return True
    return False


def tool_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    args = list(func.args.posonlyargs) + list(func.args.args) + list(func.args.kwonlyargs)
    out = []
    for i, a in enumerate(args):
        if i == 0 and a.arg in ("self", "cls"):
            continue
        ann = ast.unparse(a.annotation) if a.annotation is not None else ""
        if "RunContextWrapper" in ann or ann.endswith("Context") or a.arg in ("ctx", "context") and ann:
            continue
        out.append(a)
    return out


def _tool_contract(name: str, description: str, func: ast.FunctionDef | ast.AsyncFunctionDef, annotations: dict[str, str]) -> dict[str, Any]:
    params = []
    defaults = list(func.args.defaults)
    positional = list(func.args.posonlyargs) + list(func.args.args)
    default_map: dict[str, ast.expr] = {}
    for a, d in zip(positional[len(positional) - len(defaults):], defaults):
        default_map[a.arg] = d
    for a, d in zip(func.args.kwonlyargs, func.args.kw_defaults):
        if d is not None:
            default_map[a.arg] = d
    for a in tool_params(func):
        p: dict[str, Any] = {
            "name": a.arg,
            "annotation": ast.unparse(a.annotation) if a.annotation is not None else None,
            "required": a.arg not in default_map,
        }
        params.append(p)
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
    return contract


def detect_tools(index: ProjectIndex) -> dict[str, ToolInfo]:
    """Find tool definitions via supported decorators and wrapper calls."""
    tools: dict[str, ToolInfo] = {}
    for mod in sorted({id(m): m for m in index.modules.values()}.values(), key=lambda m: m.relpath):
        for fqual, func in sorted(mod.functions.items()):
            for dec in func.decorator_list:
                f, call = _decorator_parts(dec)
                q = index.qualname(mod, f)
                framework = None
                server_var = None
                override_name = None
                description = ast.get_docstring(func) or ""
                annotations: dict[str, str] = {}
                if q in FUNCTION_TOOL_DECORATORS:
                    framework = "openai-agents"
                    if call:
                        for kw in call.keywords:
                            if kw.arg == "name_override":
                                override_name = const_str(mod, kw.value)
                            elif kw.arg == "description_override":
                                description = const_str(mod, kw.value) or description
                            elif kw.arg:
                                annotations[kw.arg] = redact(ast.unparse(kw.value))[:120]
                elif q in LANGCHAIN_TOOL_DECORATORS:
                    framework = "langchain"
                    if call and call.args:
                        override_name = const_str(mod, call.args[0])
                    if call:
                        for kw in call.keywords:
                            if kw.arg == "description":
                                description = const_str(mod, kw.value) or description
                            elif kw.arg:
                                annotations[kw.arg] = redact(ast.unparse(kw.value))[:120]
                elif isinstance(f, ast.Attribute) and f.attr == "tool" and isinstance(f.value, ast.Name) and f.value.id in mod.fastmcp_vars:
                    framework = "mcp-fastmcp"
                    server_var = f.value.id
                    if call:
                        for kw in call.keywords:
                            if kw.arg == "name":
                                override_name = const_str(mod, kw.value)
                            elif kw.arg == "description":
                                description = const_str(mod, kw.value) or description
                            elif kw.arg:
                                annotations[kw.arg] = redact(ast.unparse(kw.value))[:120]
                        if call.args:
                            override_name = const_str(mod, call.args[0]) or override_name
                if framework is None:
                    continue
                name = override_name or func.name
                ti = ToolInfo(
                    id=f"tool:{mod.relpath}:{fqual}",
                    name=name,
                    framework=framework,
                    module=mod,
                    func=func,
                    func_qual=fqual,
                    params=[a.arg for a in tool_params(func)],
                    contract=_tool_contract(name, description, func, annotations),
                    mcp_server_var=server_var,
                    line=func.lineno,
                    decorator_line=dec.lineno,
                )
                tools[ti.id] = ti
                break
        # wrapper style: my_tool = function_tool(fn) / StructuredTool.from_function(fn)
        for var, value in mod.module_assigns.items():
            if isinstance(value, ast.Call) and index.qualname(mod, value.func) in FUNCTION_TOOL_WRAPPERS and value.args:
                target = index.lookup_function(index.qualname(mod, value.args[0]))
                if target is None:
                    continue
                tmod, tfunc, tq = target
                tid = f"tool:{tmod.relpath}:{tq}"
                if tid in tools:
                    continue
                name = func_name = tfunc.name
                for kw in value.keywords:
                    if kw.arg in ("name_override", "name"):
                        name = const_str(mod, kw.value) or func_name
                tools[tid] = ToolInfo(
                    id=tid,
                    name=name,
                    framework="openai-agents" if "agents" in (index.qualname(mod, value.func) or "") else "langchain",
                    module=tmod,
                    func=tfunc,
                    func_qual=tq,
                    params=[a.arg for a in tool_params(tfunc)],
                    contract=_tool_contract(name, ast.get_docstring(tfunc) or "", tfunc, {}),
                    line=tfunc.lineno,
                    decorator_line=value.lineno,
                )
    return tools
