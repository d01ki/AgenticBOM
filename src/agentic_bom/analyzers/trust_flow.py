"""Bounded, deterministic intra-/inter-procedural taint walker.

The walker never executes code. It tracks which values originate from tool
parameters (``param:<name>``) or recognised untrusted sources
(``source:<kind>@<line>``), whether a recognised guard constrains them, and
which recognised sensitive operations they reach. Helper calls into project
functions are followed up to ``max_depth`` hops with cycle detection; anything
beyond that becomes an explicit UNKNOWN.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from agentic_bom.analyzers import operations as ops
from agentic_bom.core.evidence import redact, redact_target, sha256_text, snippet
from agentic_bom.core.models import CONFIRMED, GUARD_ABSENT, GUARD_KNOWN, GUARD_UNKNOWN, INFERRED, UNKNOWN
from agentic_bom.detectors.python import (
    AGENT_CTORS,
    HANDOFF_FUNCS,
    FUNCTION_TOOL_WRAPPERS,
    LANGGRAPH_AGENT_CTORS,
    MCP_CLIENT_CTORS,
    RUNNER_FUNCS,
    ModuleInfo,
    ProjectIndex,
    const_str,
)

GUARD_STRENGTH = {GUARD_ABSENT: 0, GUARD_UNKNOWN: 1, GUARD_KNOWN: 2}
CLEANSERS = {"builtins.int", "builtins.float", "builtins.bool", "builtins.len", "builtins.isinstance", "builtins.hash", "builtins.id", "builtins.type"}
STR_VALIDATORS = {"isalnum", "isdigit", "isdecimal", "isnumeric", "isidentifier", "isalpha"}
NETWORK_FETCH = {"requests.get", "httpx.get", "urllib.request.urlopen", "requests.Session.get"}


@dataclass(frozen=True)
class Taint:
    origins: frozenset[str]
    guard: str = GUARD_ABSENT

    @property
    def untrusted_sources(self) -> list[str]:
        return sorted(o for o in self.origins if o.startswith("source:"))

    @property
    def params(self) -> list[str]:
        return sorted(o.split(":", 1)[1] for o in self.origins if o.startswith("param:"))


def merge(*taints: Taint | None) -> Taint | None:
    ts = [t for t in taints if t is not None]
    if not ts:
        return None
    origins: frozenset[str] = frozenset().union(*(t.origins for t in ts))
    guard = min((t.guard for t in ts), key=lambda g: GUARD_STRENGTH[g])
    return Taint(origins, guard)


def merge_env(a: dict[str, Taint], b: dict[str, Taint]) -> dict[str, Taint]:
    out: dict[str, Taint] = {}
    for k in set(a) | set(b):
        m = merge(a.get(k), b.get(k))
        if m is not None:
            out[k] = m
    return out


@dataclass(frozen=True)
class OpHit:
    op_id: str
    category: str
    callee: str
    file: str
    line: int
    end_line: int
    func_qual: str
    target_controlled: bool
    content_controlled: bool
    origins: tuple[str, ...]  # origins controlling the operation target
    content_origins: tuple[str, ...]  # origins reaching content/payload arguments only
    guard: str
    target: str
    target_kind: str  # literal | symbolic | unresolved
    resolution: str
    via: tuple[tuple[str, int, str, str], ...] = ()  # (file, line, caller_qual, callee_qual)
    attributes: tuple[tuple[str, Any], ...] = ()
    snippet: str = ""

    def with_via(self, step: tuple[str, int, str, str]) -> "OpHit":
        return replace(self, via=(step,) + self.via)


@dataclass
class ToolRef:
    kind: str  # function | library | agent | external | unknown
    fid: str | None
    line: int
    qual: str | None = None
    reason: str = ""
    agent_ref: dict[str, Any] | None = None
    approval: str | None = None  # needs_approval: "True" | other expression text | None


@dataclass
class McpRef:
    transport: str
    line: int
    server_file: str | None = None
    command: str | None = None
    url: str | None = None
    resolution: str = INFERRED


@dataclass
class AgentSite:
    file: str
    line: int
    end_line: int
    func_qual: str
    framework: str
    var: str | None
    name: str | None
    model: str | None
    model_line: int
    instructions_kind: str  # absent | static | dynamic | callable
    instructions_taint: Taint | None
    instructions_sha256: str | None
    instructions_length: int | None
    instructions_line: int
    tools: list[ToolRef]
    handoff_refs: list[dict[str, Any]]
    mcp_refs: list[McpRef]
    returned: bool = False
    col: int = 0


@dataclass
class RunnerSite:
    file: str
    line: int
    func_qual: str
    agent_var: str | None
    agent_factory_qual: str | None
    input_taint: Taint | None
    agent_site: AgentSite | None = None


@dataclass
class CallSite:
    callee_fid: str
    file: str
    line: int
    func_qual: str
    arg_taints: dict[str, Taint | None]


@dataclass
class FunctionResult:
    ops: list[OpHit] = field(default_factory=list)
    agent_sites: list[AgentSite] = field(default_factory=list)
    runner_sites: list[RunnerSite] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    unknowns: list[dict[str, Any]] = field(default_factory=list)


class AnalysisContext:
    def __init__(self, index: ProjectIndex, max_depth: int = 3) -> None:
        self.index = index
        self.max_depth = max_depth
        self._cache: dict[tuple, FunctionResult] = {}
        self._class_attrs: dict[tuple[str, str], dict[str, str]] = {}
        self._sink_reach: dict[tuple[str, str], bool] = {}

    def may_reach_sink(self, mod: ModuleInfo, func, fqual: str, budget: int = 40) -> bool:
        """Over-approximate: could any recognised sink be reached from ``func`` (ignoring data flow)?"""
        key = (mod.relpath, fqual)
        if key in self._sink_reach:
            return self._sink_reach[key]
        seen: set[tuple[str, str]] = set()
        stack = [(mod, func, fqual)]
        found = False
        while stack and len(seen) < budget and not found:
            m, fn, q = stack.pop()
            if (m.relpath, q) in seen:
                continue
            seen.add((m.relpath, q))
            cls = q.split(".")[0] if q.split(".")[0] in m.classes else None
            for node in ast.walk(fn):
                if isinstance(node, ast.Subscript) and self.index.qualname(m, node.value) == "os.environ":
                    found = True
                    break
                if not isinstance(node, ast.Call):
                    continue
                f = node.func
                if isinstance(f, (ast.Call, ast.Subscript)):
                    found = True  # dynamic dispatch
                    break
                cq = self.index.qualname(m, f)
                if cq and (cq in ops.SINKS or cq in ops.OPEN_FUNCS or cq in ops.GENERIC_REQUEST or cq in ops.CLOUD_FACTORIES
                           or cq in ("importlib.import_module", "builtins.__import__")):
                    found = True
                    break
                if isinstance(f, ast.Attribute) and f.attr in ops.PATH_METHODS:
                    found = True
                    break
                target = self.index.lookup_function(cq) if cq else None
                if target is None and isinstance(f, ast.Attribute) and cls and isinstance(f.value, ast.Name) and f.value.id == "self":
                    mq = f"{cls}.{f.attr}"
                    target = (m, m.functions[mq], mq) if mq in m.functions else None
                if target is None and isinstance(f, ast.Attribute):
                    # unknown receiver: any project method with this name could be the target (over-approximation)
                    for om in self.index.modules.values():
                        for oq, ofn in om.functions.items():
                            if oq.endswith("." + f.attr) and oq.count(".") == 1:
                                stack.append((om, ofn, oq))
                if target is not None:
                    stack.append(target)
        if stack and not found:
            found = True  # budget exhausted: stay conservative
        self._sink_reach[key] = found
        return found

    def class_attr_type(self, mod: ModuleInfo, cname: str, attr: str) -> str | None:
        key = (mod.relpath, cname)
        if key not in self._class_attrs:
            self._class_attrs[key] = {}
            types: dict[str, str] = {}
            for q, fn in sorted(mod.functions.items()):
                if not q.startswith(cname + ".") or q.count(".") != 1:
                    continue
                fa = FunctionAnalyzer(self, mod, fn, q, {}, 0, (), "source")
                for node in ast.walk(fn):
                    if isinstance(node, ast.Assign) and len(node.targets) == 1:
                        t = node.targets[0]
                        if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                            ty = fa.expr_type(node.value)
                            if ty:
                                types.setdefault(t.attr, ty)
            self._class_attrs[key] = types
        return self._class_attrs[key].get(attr)

    def analyze(
        self,
        mod: ModuleInfo,
        func: ast.FunctionDef | ast.AsyncFunctionDef | None,
        func_qual: str,
        init_env: dict[str, Taint],
        depth: int,
        stack: tuple[str, ...],
        mode: str,
    ) -> FunctionResult:
        key = (mod.relpath, func_qual, mode, depth, frozenset(init_env.items()))
        if key in self._cache:
            return self._cache[key]
        fa = FunctionAnalyzer(self, mod, func, func_qual, init_env, depth, stack, mode)
        try:
            res = fa.run()
        except RecursionError:
            res = FunctionResult(unknowns=[{"file": mod.relpath, "line": getattr(func, "lineno", 1), "reason": "parser recursion budget exceeded"}])
        self._cache[key] = res
        return res


def _terminates(stmts: list[ast.stmt]) -> bool:
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.If):
        return _terminates(last.body) and _terminates(last.orelse)
    return False


def _kw(call: ast.Call, name: str, pos: int | None = None) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    if pos is not None and len(call.args) > pos and not isinstance(call.args[pos], ast.Starred):
        return call.args[pos]
    return None


class FunctionAnalyzer:
    def __init__(self, ctx: AnalysisContext, mod: ModuleInfo, func, func_qual: str, init_env: dict[str, Taint], depth: int, stack: tuple[str, ...], mode: str) -> None:
        self.ctx = ctx
        self.index = ctx.index
        self.mod = mod
        self.func = func
        self.func_qual = func_qual
        self.init_env = dict(init_env)
        self.depth = depth
        self.stack = stack
        self.mode = mode  # "tool" (follow helpers, collect ops) | "source" (collect agents/call sites)
        self.local_assigns: dict[str, ast.expr] = {}
        self.local_types: dict[str, str] = {}
        self.agent_vars: dict[str, AgentSite] = {}
        self.counts: Counter[str] = Counter()
        self.res = FunctionResult()
        self._type_depth = 0
        head = func_qual.split(".")[0]
        params = [a.arg for a in func.args.args] if func is not None else []
        self.self_class = head if (head in mod.classes and params[:1] == ["self"]) else None

    # -- driver -------------------------------------------------------------
    def run(self) -> FunctionResult:
        if self.func is None:
            body = [s for s in self.mod.tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        else:
            body = self.func.body
        self.run_block(body, dict(self.init_env))
        return self.res

    def run_block(self, stmts: Iterable[ast.stmt], env: dict[str, Taint]) -> dict[str, Taint]:
        for st in stmts:
            env = self.run_stmt(st, env)
        return env

    def run_stmt(self, st: ast.stmt, env: dict[str, Taint]) -> dict[str, Taint]:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            return env
        if isinstance(st, ast.Assign):
            name = st.targets[0].id if len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) else None
            self.visit_expr(st.value, env, assign_name=name)
            t = self.expr_taint(st.value, env)
            env = dict(env)
            for tgt in st.targets:
                self.bind_target(tgt, t, st.value, env)
            return env
        if isinstance(st, ast.AnnAssign):
            if st.value is None:
                return env
            name = st.target.id if isinstance(st.target, ast.Name) else None
            self.visit_expr(st.value, env, assign_name=name)
            env = dict(env)
            self.bind_target(st.target, self.expr_taint(st.value, env), st.value, env)
            return env
        if isinstance(st, ast.AugAssign):
            self.visit_expr(st.value, env)
            env = dict(env)
            if isinstance(st.target, ast.Name):
                m = merge(env.get(st.target.id), self.expr_taint(st.value, env))
                if m is not None:
                    env[st.target.id] = m
            return env
        if isinstance(st, ast.Return):
            if st.value is not None:
                self.visit_expr(st.value, env, is_return=True)
                if isinstance(st.value, ast.Name) and st.value.id in self.agent_vars:
                    self.agent_vars[st.value.id].returned = True
            return env
        if isinstance(st, ast.If):
            return self.run_if(st, env)
        if isinstance(st, (ast.For, ast.AsyncFor)):
            self.visit_expr(st.iter, env)
            body_env = dict(env)
            self.bind_target(st.target, self.expr_taint(st.iter, env), None, body_env)
            out = self.run_block(st.body, body_env)
            out = self.run_block(st.orelse, out)
            return merge_env(env, out)
        if isinstance(st, ast.While):
            self.visit_expr(st.test, env)
            out = self.run_block(st.body, dict(env))
            out = self.run_block(st.orelse, out)
            return merge_env(env, out)
        if isinstance(st, (ast.With, ast.AsyncWith)):
            env = dict(env)
            for item in st.items:
                self.visit_expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self.bind_target(item.optional_vars, self.expr_taint(item.context_expr, env), item.context_expr, env)
            return self.run_block(st.body, env)
        if isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            out = self.run_block(st.body, dict(env))
            merged = out
            for h in st.handlers:
                merged = merge_env(merged, self.run_block(h.body, dict(env)))
            merged = self.run_block(st.orelse, merged)
            return self.run_block(st.finalbody, merged)
        if isinstance(st, ast.Match):
            self.visit_expr(st.subject, env)
            merged = dict(env)
            for case in st.cases:
                merged = merge_env(merged, self.run_block(case.body, dict(env)))
            return merged
        # Expr, Assert, Raise, Delete, etc.
        for child in ast.iter_child_nodes(st):
            if isinstance(child, ast.expr):
                self.visit_expr(child, env)
        return env

    def run_if(self, st: ast.If, env: dict[str, Taint]) -> dict[str, Taint]:
        self.visit_expr(st.test, env)
        body_env, else_env = dict(env), dict(env)
        g = self.guard_info(st.test, env)
        if g is not None:
            var, kind, positive = g
            cur = env[var]
            new_guard = kind if GUARD_STRENGTH[kind] >= GUARD_STRENGTH[cur.guard] else cur.guard
            guarded = Taint(cur.origins, new_guard)
            if positive:
                body_env[var] = guarded
            else:
                else_env[var] = guarded
        body_out = self.run_block(st.body, body_env)
        else_out = self.run_block(st.orelse, else_env)
        bt, et = _terminates(st.body), _terminates(st.orelse)
        if bt and not et:
            return else_out
        if et and not bt:
            return body_out
        return merge_env(body_out, else_out)

    # -- guards -------------------------------------------------------------
    def _tainted_name(self, e: ast.AST, env: dict[str, Taint]) -> str | None:
        return e.id if isinstance(e, ast.Name) and e.id in env else None

    def guard_info(self, test: ast.expr, env: dict[str, Taint]) -> tuple[str, str, bool] | None:
        """Return (var, guard_kind, positive) when ``test`` constrains a tainted variable."""
        positive = True
        while isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            positive = not positive
            test = test.operand
        if isinstance(test, ast.BoolOp):
            for v in test.values:
                g = self.guard_info(v, env)
                if g is not None:
                    var, kind, pos = g
                    return var, kind, pos if positive else not pos
            return None
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            left, right, op = test.left, test.comparators[0], test.ops[0]
            var = self._tainted_name(left, env)
            if var is None or self.expr_taint(right, env) is not None:
                return None
            if isinstance(op, (ast.In, ast.Eq)):
                return var, GUARD_KNOWN, positive
            if isinstance(op, (ast.NotIn, ast.NotEq)):
                return var, GUARD_KNOWN, not positive
            return None
        if isinstance(test, ast.Call):
            q = self.qual(test.func)
            if q in ("re.fullmatch", "re.match") and len(test.args) >= 2:
                var = self._tainted_name(test.args[1], env)
                if var:
                    return var, GUARD_KNOWN, positive
            if isinstance(test.func, ast.Attribute):
                recv_var = self._tainted_name(test.func.value, env)
                if recv_var and test.func.attr in STR_VALIDATORS:
                    return recv_var, GUARD_KNOWN, positive
                if test.func.attr in ("fullmatch", "match") and test.args:
                    var = self._tainted_name(test.args[0], env)
                    if var and self.expr_taint(test.func.value, env) is None:
                        return var, GUARD_KNOWN, positive
            if isinstance(test.func, ast.Name) and test.func.id == "len":
                return None
            # Any other predicate over a tainted variable: a guard may exist but is unsupported.
            for n in ast.walk(test):
                var = self._tainted_name(n, env)
                if var:
                    return var, GUARD_UNKNOWN, positive
        return None

    # -- names & types -----------------------------------------------------
    def qual(self, expr: ast.AST) -> str | None:
        if isinstance(expr, ast.Name) and (expr.id in self.local_assigns or expr.id in self.init_env):
            return None  # shadowed by a local
        return self.index.qualname(self.mod, expr)

    def expr_type(self, e: ast.AST | None) -> str | None:
        if e is None or self._type_depth > 6:
            return None
        self._type_depth += 1
        try:
            if isinstance(e, ast.Call):
                q = self.qual(e.func)
                if q in ops.PATH_FACTORIES or (q and q.startswith("pathlib.Path.")):
                    return "path"
                cls = self.index.lookup_class(q)
                if cls is not None:
                    return f"class:{cls[0].modname}:{cls[1]}"
                if q in ops.CLOUD_FACTORIES:
                    svc = const_str(self.mod, _kw(e, "service_name", 0), self.index) or "unknown"
                    return f"boto3:{svc}"
                if isinstance(e.func, ast.Attribute) and e.func.attr in ("joinpath", "with_suffix", "with_name", "resolve", "absolute", "expanduser"):
                    return self.expr_type(e.func.value)
                return None
            if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
                return "path" if self.expr_type(e.left) == "path" else None
            if isinstance(e, ast.Attribute) and e.attr == "parent":
                return self.expr_type(e.value)
            if isinstance(e, ast.Attribute):
                owner = self.expr_type(e.value)
                if owner and owner.startswith("class:"):
                    _, modname, cname = owner.split(":", 2)
                    m = self.index.modules.get(modname)
                    if m is not None:
                        return self.ctx.class_attr_type(m, cname, e.attr)
                return None
            if isinstance(e, ast.Name):
                if e.id in self.local_types:
                    return self.local_types[e.id]
                if e.id == "self" and self.self_class is not None:
                    return f"class:{self.mod.modname}:{self.self_class}"
                if e.id not in self.local_assigns and e.id in self.mod.module_assigns:
                    return self.expr_type(self.mod.module_assigns[e.id])
            return None
        finally:
            self._type_depth -= 1

    def bind_target(self, tgt: ast.AST, taint: Taint | None, value: ast.expr | None, env: dict[str, Taint]) -> None:
        if isinstance(tgt, ast.Name):
            if taint is not None:
                env[tgt.id] = taint
            else:
                env.pop(tgt.id, None)
            if value is not None:
                self.local_assigns[tgt.id] = value
                t = self.expr_type(value)
                if t:
                    self.local_types[tgt.id] = t
                else:
                    self.local_types.pop(tgt.id, None)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for el in tgt.elts:
                self.bind_target(el.value if isinstance(el, ast.Starred) else el, taint, None, env)
        elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name) and taint is not None:
            m = merge(env.get(tgt.value.id), taint)
            if m is not None:
                env[tgt.value.id] = m

    # -- taint --------------------------------------------------------------
    def source_kind(self, e: ast.AST) -> str | None:
        if isinstance(e, ast.Call):
            q = self.qual(e.func)
            if q == "builtins.input":
                return "stdin"
            if q and q.startswith("sys.stdin."):
                return "stdin"
            if q and q.startswith("flask.request."):
                return "http_request"
            if q in NETWORK_FETCH:
                return "network_content"
            return None
        if isinstance(e, (ast.Attribute, ast.Name)):
            q = self.qual(e)
            if q is None:
                return None
            if q == "sys.argv" or q.startswith("sys.argv."):
                return "argv"
            if q == "flask.request" or q.startswith("flask.request."):
                return "http_request"
            if q == "sys.stdin" or q.startswith("sys.stdin."):
                return "stdin"
        return None

    def expr_taint(self, e: ast.AST | None, env: dict[str, Taint]) -> Taint | None:
        if e is None:
            return None
        if isinstance(e, ast.Name):
            if e.id in env:
                return env[e.id]
            src = self.source_kind(e)
            return Taint(frozenset({f"source:{src}@{e.lineno}"})) if src else None
        if isinstance(e, ast.Constant):
            return None
        if isinstance(e, ast.JoinedStr):
            return merge(*(self.expr_taint(v, env) for v in e.values))
        if isinstance(e, ast.FormattedValue):
            return self.expr_taint(e.value, env)
        if isinstance(e, ast.BinOp):
            return merge(self.expr_taint(e.left, env), self.expr_taint(e.right, env))
        if isinstance(e, ast.BoolOp):
            return merge(*(self.expr_taint(v, env) for v in e.values))
        if isinstance(e, ast.IfExp):
            return merge(self.expr_taint(e.body, env), self.expr_taint(e.orelse, env))
        if isinstance(e, ast.Compare):
            return None
        if isinstance(e, ast.UnaryOp):
            return None if isinstance(e.op, ast.Not) else self.expr_taint(e.operand, env)
        if isinstance(e, ast.Call):
            src = self.source_kind(e)
            if src:
                return Taint(frozenset({f"source:{src}@{e.lineno}"}))
            q = self.qual(e.func)
            if q in CLEANSERS:
                return None
            parts = [self.expr_taint(a.value if isinstance(a, ast.Starred) else a, env) for a in e.args]
            parts += [self.expr_taint(k.value, env) for k in e.keywords]
            if isinstance(e.func, ast.Attribute):
                parts.append(self.expr_taint(e.func.value, env))
            return merge(*parts)
        if isinstance(e, ast.Attribute):
            src = self.source_kind(e)
            if src:
                return Taint(frozenset({f"source:{src}@{e.lineno}"}))
            return self.expr_taint(e.value, env)
        if isinstance(e, ast.Subscript):
            src = self.source_kind(e.value)
            if src:
                return Taint(frozenset({f"source:{src}@{e.lineno}"}))
            # selecting from an untainted container with a tainted key yields a constant value
            return self.expr_taint(e.value, env)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return merge(*(self.expr_taint(x, env) for x in e.elts))
        if isinstance(e, ast.Dict):
            return merge(*(self.expr_taint(x, env) for x in list(e.keys) + list(e.values) if x is not None))
        if isinstance(e, ast.Starred):
            return self.expr_taint(e.value, env)
        if isinstance(e, ast.Await):
            return self.expr_taint(e.value, env)
        if isinstance(e, ast.NamedExpr):
            return self.expr_taint(e.value, env)
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return merge(*(self.expr_taint(g.iter, env) for g in e.generators))
        if isinstance(e, ast.DictComp):
            return merge(*(self.expr_taint(g.iter, env) for g in e.generators))
        return None

    # -- call handling ------------------------------------------------------
    def visit_expr(self, expr: ast.expr, env: dict[str, Taint], assign_name: str | None = None, is_return: bool = False) -> None:
        direct = expr.value if isinstance(expr, ast.Await) else expr
        nodes = [n for n in ast.walk(expr) if isinstance(n, (ast.Call, ast.Subscript))]
        nodes.sort(key=lambda n: (n.lineno, n.col_offset))
        for n in nodes:
            if isinstance(n, ast.Subscript):
                if isinstance(n.ctx, ast.Load) and self.qual(n.value) == "os.environ":
                    self.record_op(n, ops.SECRET_ACCESS, "os.environ[]", env, target_exprs=[n.slice], content_exprs=[])
                continue
            self.handle_call(n, env, assign_name if n is direct else None, is_return and n is direct)

    def handle_call(self, call: ast.Call, env: dict[str, Taint], assign_name: str | None, is_return: bool) -> None:
        f = call.func
        # dynamic dispatch -> UNKNOWN
        if isinstance(f, ast.Call) and self.qual(f.func) == "builtins.getattr":
            self.record_op(call, ops.DYNAMIC_DISPATCH, "getattr(...)()", env, resolution=UNKNOWN)
            return
        if isinstance(f, ast.Subscript):
            self.record_op(call, ops.DYNAMIC_DISPATCH, "<subscript>()", env, resolution=UNKNOWN)
            return
        q = self.qual(f)
        if q in ("importlib.import_module", "builtins.__import__"):
            self.record_op(call, ops.DYNAMIC_DISPATCH, q, env, resolution=UNKNOWN)
            return
        cat = ops.match_function(q)
        if cat:
            self.record_op(call, cat, q, env, attrs=self._sink_attrs(call, cat))
            return
        if q in ops.OPEN_FUNCS:
            mode_expr = _kw(call, "mode", 1)
            if mode_expr is None:
                return
            mode = const_str(self.mod, mode_expr, self.index)
            if mode is None:
                self.record_op(call, ops.FILESYSTEM_WRITE, q, env, target_exprs=[_kw(call, "file", 0)], content_exprs=[], resolution=INFERRED,
                               attrs={"mode": "unresolved"})
            elif any(c in mode for c in "wax+"):
                self.record_op(call, ops.FILESYSTEM_WRITE, q, env, target_exprs=[_kw(call, "file", 0)], content_exprs=[], attrs={"mode": mode})
            return
        if q in ops.GENERIC_REQUEST:
            method = (const_str(self.mod, _kw(call, "method", 0), self.index) or "").upper()
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                self.record_op(call, ops.NETWORK_STATE_CHANGE, q, env, target_exprs=[_kw(call, "url", 1)],
                               content_exprs=[k.value for k in call.keywords if k.arg in ops.NETWORK_CONTENT_KWARGS], attrs={"method": method})
            elif not method:
                self.record_op(call, ops.NETWORK_STATE_CHANGE, q, env, target_exprs=[_kw(call, "url", 1)], content_exprs=[],
                               resolution=INFERRED, attrs={"method": "unresolved"})
            return
        if isinstance(f, ast.Attribute):
            rtype = self.expr_type(f.value)
            if rtype == "path" and f.attr in ops.PATH_METHODS:
                cat = ops.PATH_METHODS[f.attr]
                self.record_op(call, cat, f"pathlib.Path.{f.attr}", env, target_exprs=[f.value], content_exprs=list(call.args))
                return
            if rtype and rtype.startswith("class:"):
                _, modname, cname = rtype.split(":", 2)
                m = self.index.modules.get(modname)
                meth = f"{cname}.{f.attr}"
                if m is not None and meth in m.functions:
                    self.follow_helper(call, env, (m, m.functions[meth], meth))
                return
            if rtype and rtype.startswith("boto3:"):
                svc = rtype.split(":", 1)[1]
                if (svc, f.attr) in (("secretsmanager", "get_secret_value"), ("ssm", "get_parameter"), ("ssm", "get_parameters")):
                    self.record_op(call, ops.SECRET_ACCESS, f"boto3.{svc}.{f.attr}", env, attrs={"service": svc})
                elif not f.attr.startswith(ops.CLOUD_READ_PREFIXES):
                    self.record_op(call, ops.CLOUD_SDK_CALL, f"boto3.{svc}.{f.attr}", env, attrs={"service": svc, "api": f.attr})
                return
        if q in AGENT_CTORS or q in LANGGRAPH_AGENT_CTORS:
            self.record_agent(call, env, assign_name, is_return, framework="openai-agents" if q in AGENT_CTORS else "langgraph")
            return
        if q in RUNNER_FUNCS:
            self.record_runner(call, env)
            return
        target = self.index.lookup_function(q) if q else None
        if target is None and isinstance(f, ast.Name) and self.func is not None:
            nested = f"{self.func_qual}.{f.id}"
            if nested in self.mod.functions:
                target = (self.mod, self.mod.functions[nested], nested)
        if target is not None:
            self.follow_helper(call, env, target)

    def _sink_attrs(self, call: ast.Call, cat: str) -> dict[str, Any]:
        attrs: dict[str, Any] = {}
        if cat == ops.PROCESS_EXECUTION:
            sh = _kw(call, "shell")
            if isinstance(sh, ast.Constant):
                attrs["shell"] = bool(sh.value)
            elif sh is not None:
                attrs["shell"] = "unresolved"
        return attrs

    def _split_args(self, call: ast.Call, cat: str) -> tuple[list[ast.expr], list[ast.expr]]:
        positions, kws = ops.TARGET_ARGS.get(cat, (None, None))
        target: list[ast.expr] = []
        content: list[ast.expr] = []
        for i, a in enumerate(call.args):
            a = a.value if isinstance(a, ast.Starred) else a
            (target if positions is None or i in positions else content).append(a)
        for k in call.keywords:
            if k.arg in ops.IGNORED_KWARGS:
                continue
            if positions is None or (k.arg in kws) or k.arg is None:
                target.append(k.value)
            else:
                content.append(k.value)
        return target, content

    def _describe_target(self, exprs: list[ast.expr | None], taint: Taint | None) -> tuple[str, str]:
        exprs = [e for e in exprs if e is not None]
        if not exprs:
            return "", "unresolved"
        first = exprs[0]
        s = const_str(self.mod, first, self.index)
        if s is not None and taint is None:
            return redact_target(s), "literal"
        if isinstance(first, (ast.List, ast.Tuple)) and taint is None:
            parts = [const_str(self.mod, el, self.index) for el in first.elts]
            if all(p is not None for p in parts):
                return redact_target(" ".join(parts)), "literal"  # type: ignore[arg-type]
        if taint is not None:
            names = taint.params + [o.split(":", 1)[1].split("@")[0] for o in taint.untrusted_sources]
            return "symbolic:" + ",".join(sorted(set(names))), "symbolic"
        return redact(ast.unparse(first))[:120], "unresolved"

    def record_op(self, node: ast.AST, cat: str, callee: str, env: dict[str, Taint], target_exprs: list | None = None,
                  content_exprs: list | None = None, resolution: str = CONFIRMED, attrs: dict | None = None) -> None:
        if target_exprs is None and isinstance(node, ast.Call):
            target_exprs, auto_content = self._split_args(node, cat)
            if content_exprs is None:
                content_exprs = auto_content
        target_exprs = [e for e in (target_exprs or []) if e is not None]
        content_exprs = [e for e in (content_exprs or []) if e is not None]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Call) and cat == ops.DYNAMIC_DISPATCH:
            target_exprs = target_exprs + list(node.func.args)
        tt = merge(*(self.expr_taint(e, env) for e in target_exprs))
        ct = merge(*(self.expr_taint(e, env) for e in content_exprs))
        target, tkind = self._describe_target(target_exprs, tt)
        if cat == ops.DYNAMIC_DISPATCH:
            target, tkind = (target if tkind == "symbolic" else "unresolved-callee"), ("symbolic" if tt else "unresolved")
        self.counts[callee] += 1
        op_id = f"operation:{self.mod.relpath}:{self.func_qual}:{callee}#{self.counts[callee]}"
        origins = tuple(sorted(tt.origins)) if tt else ()
        content_origins = tuple(sorted(ct.origins)) if ct else ()
        guard = tt.guard if tt else GUARD_ABSENT
        self.res.ops.append(
            OpHit(
                op_id=op_id,
                category=cat,
                callee=callee,
                file=self.mod.relpath,
                line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                func_qual=self.func_qual,
                target_controlled=tt is not None,
                content_controlled=ct is not None,
                origins=origins,
                content_origins=content_origins,
                guard=guard,
                target=target,
                target_kind=tkind,
                resolution=resolution,
                attributes=tuple(sorted((attrs or {}).items())),
                snippet=snippet(self.mod.lines, node.lineno),
            )
        )

    def follow_helper(self, call: ast.Call, env: dict[str, Taint], target: tuple) -> None:
        tmod, tfunc, tq = target
        fid = f"{tmod.relpath}:{tq}"
        params = [a.arg for a in list(tfunc.args.posonlyargs) + list(tfunc.args.args)]
        if params and params[0] in ("self", "cls"):
            params = params[1:]
        kwonly = [a.arg for a in tfunc.args.kwonlyargs]
        arg_taints: dict[str, Taint | None] = {p: None for p in params + kwonly}
        star_taint = None
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Starred):
                star_taint = merge(star_taint, self.expr_taint(a.value, env))
                continue
            if i < len(params):
                arg_taints[params[i]] = self.expr_taint(a, env)
            elif tfunc.args.vararg is not None:
                arg_taints[tfunc.args.vararg.arg] = merge(arg_taints.get(tfunc.args.vararg.arg), self.expr_taint(a, env))
        for k in call.keywords:
            t = self.expr_taint(k.value, env)
            if k.arg in arg_taints:
                arg_taints[k.arg] = t
            elif k.arg is None or tfunc.args.kwarg is not None:
                star_taint = merge(star_taint, t)
        if star_taint is not None:
            for p in arg_taints:
                arg_taints[p] = merge(arg_taints[p], star_taint)
        if self.mode == "source":
            self.res.call_sites.append(CallSite(fid, self.mod.relpath, call.lineno, self.func_qual, arg_taints))
            return
        if fid in self.stack:
            return  # recursion: already being analysed on this chain
        if self.depth + 1 > self.ctx.max_depth:
            if self.ctx.may_reach_sink(tmod, tfunc, tq):
                self.record_op(call, ops.DYNAMIC_DISPATCH, f"depth-limit:{tq}", env, resolution=UNKNOWN,
                               attrs={"reason": f"helper chain exceeds {self.ctx.max_depth} hops and a recognised sink is syntactically reachable beyond it"})
            return
        init_env = {p: t for p, t in arg_taints.items() if t is not None}
        sub = self.ctx.analyze(tmod, tfunc, tq, init_env, self.depth + 1, self.stack + (fid,), "tool")
        step = (self.mod.relpath, call.lineno, self.func_qual, f"{tmod.relpath}:{tq}")
        for op in sub.ops:
            self.res.ops.append(op.with_via(step))
        self.res.unknowns.extend(sub.unknowns)

    # -- agents -------------------------------------------------------------
    def record_agent(self, call: ast.Call, env: dict[str, Taint], assign_name: str | None, is_return: bool, framework: str) -> None:
        if framework == "openai-agents":
            name_e, instr_e, model_e, tools_e = _kw(call, "name", 0), _kw(call, "instructions"), _kw(call, "model"), _kw(call, "tools")
            handoffs_e, mcp_e = _kw(call, "handoffs"), _kw(call, "mcp_servers")
        else:  # langgraph.create_react_agent(model, tools, *, prompt=..., name=...)
            name_e, instr_e, model_e, tools_e = _kw(call, "name"), _kw(call, "prompt") or _kw(call, "state_modifier"), _kw(call, "model", 0), _kw(call, "tools", 1)
            handoffs_e, mcp_e = None, None
        name = const_str(self.mod, name_e, self.index)
        model = const_str(self.mod, model_e, self.index)
        if model is None and model_e is not None:
            model = None
        # instructions
        kind, taint, digest, length = "absent", None, None, None
        if instr_e is not None:
            s = const_str(self.mod, instr_e, self.index)
            if s is not None:
                kind, digest, length = "static", sha256_text(s), len(s)
            elif isinstance(instr_e, ast.Lambda) or self.index.lookup_function(self.qual(instr_e)) is not None:
                kind = "callable"
            else:
                kind = "dynamic"
                taint = self.expr_taint(instr_e, env)
                digest = sha256_text(ast.unparse(instr_e))
                if isinstance(instr_e, ast.Name) and instr_e.id in self.local_assigns:
                    digest = sha256_text(ast.unparse(self.local_assigns[instr_e.id]))
        site = AgentSite(
            file=self.mod.relpath,
            line=call.lineno,
            end_line=getattr(call, "end_lineno", call.lineno) or call.lineno,
            func_qual=self.func_qual,
            framework=framework,
            var=assign_name,
            name=name,
            model=model,
            model_line=model_e.lineno if model_e is not None else call.lineno,
            instructions_kind=kind,
            instructions_taint=taint,
            instructions_sha256=digest,
            instructions_length=length,
            instructions_line=instr_e.lineno if instr_e is not None else call.lineno,
            tools=self.resolve_tools(tools_e, self.mod, 0) if tools_e is not None else [],
            handoff_refs=self.resolve_handoffs(handoffs_e),
            mcp_refs=self.resolve_mcp(mcp_e) if mcp_e is not None else [],
            returned=is_return,
            col=call.col_offset,
        )
        if assign_name:
            self.agent_vars[assign_name] = site
        self.res.agent_sites.append(site)

    def resolve_tools(self, expr: ast.expr, mod: ModuleInfo, depth: int) -> list[ToolRef]:
        line = getattr(expr, "lineno", 0)
        if depth > 4:
            return [ToolRef("unknown", None, line, reason="tool list indirection too deep")]
        if isinstance(expr, (ast.List, ast.Tuple)):
            out: list[ToolRef] = []
            for el in expr.elts:
                if isinstance(el, ast.Starred):
                    out += self.resolve_tools(el.value, mod, depth + 1)
                else:
                    out += self.resolve_one_tool(el, mod, depth)
            return out
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self.resolve_tools(expr.left, mod, depth + 1) + self.resolve_tools(expr.right, mod, depth + 1)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "get_tools":
            kit = expr.func.value
            if isinstance(kit, ast.Name) and mod is self.mod and kit.id in self.local_assigns:
                kit = self.local_assigns[kit.id]
            elif isinstance(kit, ast.Name) and kit.id in mod.module_assigns:
                kit = mod.module_assigns[kit.id]
            if isinstance(kit, ast.Call):
                kq = self.index.qualname(mod, kit.func)
                table = ops.LIBRARY_TOOLKITS.get(kq or "")
                if table is not None:
                    selected = None
                    sel = _kw(kit, "selected_tools")
                    if isinstance(sel, (ast.List, ast.Tuple)):
                        selected = {const_str(mod, x, self.index) for x in sel.elts}
                    out = []
                    for tname, lib in sorted(table.items()):
                        if not lib or (selected is not None and tname not in selected):
                            continue
                        out.append(ToolRef("library", None, line, lib, reason=f"{kq.rsplit('.', 1)[-1]}.get_tools() -> {tname}"))
                    if selected is None and _kw(kit, "selected_tools") is not None:
                        out.append(ToolRef("unknown", None, line, reason="toolkit selected_tools not statically resolvable"))
                    return out
        if isinstance(expr, ast.Name):
            if mod is self.mod and expr.id in self.local_assigns:
                return self.resolve_tools(self.local_assigns[expr.id], mod, depth + 1)
            if expr.id in mod.module_assigns:
                return self.resolve_tools(mod.module_assigns[expr.id], mod, depth + 1)
            found = self.index.lookup_module_var(self.index.qualname(mod, expr))
            if found:
                return self.resolve_tools(found[1], found[0], depth + 1)
        return [ToolRef("unknown", None, line, reason=f"dynamic tool list: {redact(ast.unparse(expr))[:80]}")]

    def resolve_one_tool(self, el: ast.expr, mod: ModuleInfo, depth: int) -> list[ToolRef]:
        line = el.lineno
        if isinstance(el, ast.Name):
            if mod is self.mod and el.id in self.local_assigns:
                return self.resolve_one_tool(self.local_assigns[el.id], mod, depth + 1) if depth < 4 else [ToolRef("unknown", None, line, reason="indirection")]
            if mod is self.mod and self.func is not None and f"{self.func_qual}.{el.id}" in mod.functions:
                return [ToolRef("function", f"{mod.relpath}:{self.func_qual}.{el.id}", line)]
            if el.id in mod.module_assigns and isinstance(mod.module_assigns[el.id], ast.Call):
                return self.resolve_one_tool(mod.module_assigns[el.id], mod, depth + 1)
        if isinstance(el, (ast.Name, ast.Attribute)):
            q = self.index.qualname(mod, el)
            target = self.index.lookup_function(q)
            if target is not None:
                tmod, _f, tq = target
                return [ToolRef("function", f"{tmod.relpath}:{tq}", line, q)]
            found = self.index.lookup_module_var(q)
            if found and isinstance(found[1], ast.Call) and depth < 4:
                return self.resolve_one_tool(found[1], found[0], depth + 1)
            if q in ops.HOSTED_TOOLS:
                return [ToolRef("hosted", None, line, q, reason="provider-hosted tool; no operation on the application host")]
            if q in ops.LIBRARY_TOOLS:
                return [ToolRef("library", None, line, q, reason="documented library tool behaviour (source not analysed)")]
            if q and not q.startswith("builtins."):
                return [ToolRef("external", None, line, q, reason="tool object defined outside the scanned project")]
            return [ToolRef("unknown", None, line, reason=f"unresolved tool reference {redact(ast.unparse(el))[:60]}")]
        if isinstance(el, ast.Call):
            q = self.index.qualname(mod, el.func)
            if q in FUNCTION_TOOL_WRAPPERS and el.args:
                return self.resolve_one_tool(el.args[0], mod, depth + 1)
            if isinstance(el.func, ast.Attribute) and el.func.attr == "as_tool":
                ref = self.agent_ref(el.func.value, mod) if mod is self.mod else None
                if ref is not None:
                    tname = const_str(mod, _kw(el, "tool_name", 0), self.index)
                    return [ToolRef("agent", None, line, tname, reason="agent.as_tool() delegation", agent_ref=ref)]
                return [ToolRef("unknown", None, line, reason="agent.as_tool() on an unresolvable agent expression")]
            if q in ops.HOSTED_TOOLS:
                return [ToolRef("hosted", None, line, q, reason="provider-hosted tool; no operation on the application host")]
            if q in ops.LIBRARY_TOOLS:
                if q.startswith("agents.") and q.endswith(".ShellTool"):
                    env_type = self._shell_environment(el, mod)
                    if env_type in ops.HOSTED_SHELL_ENVIRONMENTS:
                        return [ToolRef("hosted", None, line, q, reason=f"ShellTool runs in a provider-hosted container ({env_type})")]
                    if env_type == "?":
                        return [ToolRef("unknown", None, line, q, reason="ShellTool environment not statically resolvable (local vs hosted container)")]
                appr = _kw(el, "needs_approval")
                approval = None if appr is None else (str(appr.value) if isinstance(appr, ast.Constant) else "dynamic")
                return [ToolRef("library", None, line, q, reason="documented library tool behaviour (source not analysed)", approval=approval)]
            if q and not q.startswith(mod.modname + "."):
                return [ToolRef("external", None, line, q, reason="library tool instance; operations not analysed")]
        return [ToolRef("unknown", None, line, reason=f"unsupported tool expression {redact(ast.unparse(el))[:60]}")]

    def _shell_environment(self, call: ast.Call, mod: ModuleInfo) -> str | None:
        """None = local (default), a type string when literal, "?" when unresolvable."""
        env = _kw(call, "environment")
        if env is None or (isinstance(env, ast.Constant) and env.value is None):
            return None
        if isinstance(env, ast.Name):
            env = (self.local_assigns.get(env.id) if mod is self.mod else None) or mod.module_assigns.get(env.id)
        if isinstance(env, ast.Dict):
            for k, v in zip(env.keys, env.values):
                if k is not None and const_str(mod, k, self.index) == "type":
                    t = const_str(mod, v, self.index)
                    return t if t else "?"
        return "?"

    def agent_ref(self, e: ast.expr, mod: ModuleInfo, depth: int = 0) -> dict[str, Any] | None:
        """Describe where the agent referenced by ``e`` is defined; resolved to a site by the scanner."""
        if depth > 4:
            return None
        line = getattr(e, "lineno", 0)
        if isinstance(e, ast.Call):
            q = self.index.qualname(mod, e.func)
            if q in HANDOFF_FUNCS:
                inner = _kw(e, "agent", 0)
                return self.agent_ref(inner, mod, depth + 1) if inner is not None else None
            if q in AGENT_CTORS or q in LANGGRAPH_AGENT_CTORS:
                return {"inline": True, "file": mod.relpath, "line": e.lineno, "col": e.col_offset, "ref_line": line}
            target = self.index.lookup_function(q)
            if target is not None:
                return {"factory": f"{target[0].relpath}:{target[2]}", "ref_line": line}
            return None
        if isinstance(e, ast.Name):
            if mod is self.mod and e.id in self.agent_vars:
                return {"file": mod.relpath, "func": self.func_qual, "var": e.id, "ref_line": line}
            if mod is self.mod and e.id in self.local_assigns:
                v = self.local_assigns[e.id]
                return self.agent_ref(v.value if isinstance(v, ast.Await) else v, mod, depth + 1)
            if e.id in mod.module_assigns:
                return {"file": mod.relpath, "func": "<module>", "var": e.id, "ref_line": line}
        if isinstance(e, (ast.Name, ast.Attribute)):
            q = self.index.qualname(mod, e)
            if q and "." in q:
                modpart, var = q.rsplit(".", 1)
                m = self.index.resolve_module(modpart)
                if m is not None and var in m.module_assigns:
                    return {"file": m.relpath, "func": "<module>", "var": var, "ref_line": line}
        return None

    def resolve_handoffs(self, expr: ast.expr | None) -> list[dict[str, Any]]:
        if expr is None:
            return []
        if isinstance(expr, ast.Name) and expr.id in self.local_assigns:
            expr = self.local_assigns[expr.id]
        elts = expr.elts if isinstance(expr, (ast.List, ast.Tuple)) else None
        if elts is None:
            return [{"unresolved": True, "ref_line": expr.lineno, "reason": "dynamic handoffs list"}]
        out = []
        for el in elts:
            ref = self.agent_ref(el, self.mod)
            out.append(ref if ref is not None else {"unresolved": True, "ref_line": el.lineno, "reason": f"unresolved handoff {redact(ast.unparse(el))[:60]}"})
        return out

    def resolve_mcp(self, expr: ast.expr) -> list[McpRef]:
        elts = expr.elts if isinstance(expr, (ast.List, ast.Tuple)) else [expr]
        out: list[McpRef] = []
        for el in elts:
            call = el
            if isinstance(el, ast.Name):
                call = self.local_assigns.get(el.id) or self.mod.module_assigns.get(el.id)
            if not isinstance(call, ast.Call):
                out.append(McpRef("unknown", el.lineno, resolution=UNKNOWN))
                continue
            transport = MCP_CLIENT_CTORS.get(self.index.qualname(self.mod, call.func) or "")
            if transport is None:
                out.append(McpRef("unknown", el.lineno, resolution=UNKNOWN))
                continue
            params = _kw(call, "params", 0)
            if isinstance(params, ast.Name):
                params = self.local_assigns.get(params.id) or self.mod.module_assigns.get(params.id)
            ref = McpRef(transport, call.lineno)
            strings: list[str] = []
            if isinstance(params, ast.Dict):
                for k, v in zip(params.keys, params.values):
                    key = const_str(self.mod, k, self.index) if k is not None else None
                    if key == "command":
                        ref.command = const_str(self.mod, v, self.index)
                    elif key == "args" and isinstance(v, (ast.List, ast.Tuple)):
                        strings += [s for s in (const_str(self.mod, x, self.index) for x in v.elts) if s]
                    elif key == "url":
                        u = const_str(self.mod, v, self.index)
                        ref.url = redact_target(u) if u else None
            ref.server_file = next((s for s in strings if s.endswith(".py")), None)
            if ref.command:
                ref.command = redact_target(" ".join([ref.command] + strings))
            if ref.server_file is None and transport == "stdio":
                ref.resolution = UNKNOWN
            out.append(ref)
        return out

    def record_runner(self, call: ast.Call, env: dict[str, Taint]) -> None:
        agent_e = _kw(call, "starting_agent", 0)
        input_e = _kw(call, "input", 1)
        var = agent_e.id if isinstance(agent_e, ast.Name) else None
        site = self.agent_vars.get(var) if var else None
        factory = None
        if site is None and var and var in self.local_assigns:
            v = self.local_assigns[var]
            v = v.value if isinstance(v, ast.Await) else v
            if isinstance(v, ast.Call):
                target = self.index.lookup_function(self.qual(v.func))
                if target:
                    factory = f"{target[0].relpath}:{target[2]}"
        self.res.runner_sites.append(
            RunnerSite(self.mod.relpath, call.lineno, self.func_qual, var, factory, self.expr_taint(input_e, env), site)
        )
