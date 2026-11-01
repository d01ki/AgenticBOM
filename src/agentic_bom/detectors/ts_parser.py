"""Tolerant TypeScript/JavaScript tokenizer and parser (pure Python, no Node.js).

It is *not* a complete ECMAScript/TypeScript parser. It recognises the
statement and expression forms needed to find agents, tools, handlers, data
flow and sink calls, skips type syntax (annotations, `as`, generics,
interfaces, type aliases, enums, declare) and recovers from anything it does
not understand by skipping to the next statement. Unparsed regions are
counted so coverage can report them.

AST nodes are plain dicts: ``{"k": <kind>, "line": <int>, ...}``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PUNCT = sorted(
    [
        ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
        "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=",
        "&=", "|=", "^=", "**", "<<", ">>",
        "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^", "!", "~",
        "?", ":", "=", ".", "@", "#",
    ],
    key=len,
    reverse=True,
)
REGEX_PREV_KW = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await", "instanceof"}
MAX_TOKENS = 400_000
BACKSLASH = chr(92)
MAX_DEPTH = 200


@dataclass
class Tok:
    k: str  # id | num | str | tpl | re | p | eof
    v: Any
    line: int
    nl: bool = False  # preceded by a newline


class ParseError(Exception):
    pass


_HI = chr(0x80) + "-" + chr(0xFFFF)
_WS_RE = re.compile("[ \t\r\f\v" + chr(0xFEFF) + chr(0xA0) + "]+")
_ID_RE = re.compile("[A-Za-z_$" + _HI + "][A-Za-z0-9_$" + _HI + "]*")
_NUM_RE = re.compile(r"(?:0[xXbBoO][0-9A-Fa-f_]+n?|[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9]+)?n?|\.[0-9][0-9_]*(?:[eE][+-]?[0-9]+)?)")
_STR_RE = {q: re.compile(q + r"((?:[^" + q + r"\\\n]|\\.)*)" + q + "?", re.S) for q in ("'", '"')}
_ESC_RE = re.compile(r"\\(.)", re.S)
_PUNCT_RE = re.compile("|".join(re.escape(x) for x in PUNCT))
_BLOCK_END = "*/"


def _unescape_str(raw: str) -> str:
    return _ESC_RE.sub(lambda m: _unescape(m.group(1)), raw) if "\\" in raw else raw


def tokenize(src: str) -> list[Tok]:
    return _tokenize(src, 0)


def _tokenize(src: str, tdepth: int) -> list[Tok]:
    out: list[Tok] = []
    append = out.append
    i, n, line = 0, len(src), 1
    nl = True
    if src.startswith("#!"):
        i = src.find("\n")
        i = n if i < 0 else i
    ws_match, id_match, num_match, punct_match = _WS_RE.match, _ID_RE.match, _NUM_RE.match, _PUNCT_RE.match
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            nl = True
            continue
        m = ws_match(src, i)
        if m:
            i = m.end()
            continue
        if c == "/" and i + 1 < n:
            c2 = src[i + 1]
            if c2 == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if c2 == "*":
                j = src.find(_BLOCK_END, i + 2)
                j = n if j < 0 else j + 2
                k = src.count("\n", i, j)
                if k:
                    line += k
                    nl = True
                i = j
                continue
        if len(out) > MAX_TOKENS:
            raise ParseError("token budget exceeded")
        m = id_match(src, i)
        if m:
            append(Tok("id", m.group(), line, nl))
            i = m.end()
            nl = False
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = num_match(src, i)
            j = m.end() if m and m.end() > i else i + 1
            append(Tok("num", src[i:j], line, nl))
            i = j
            nl = False
            continue
        if c == "'" or c == '"':
            m = _STR_RE[c].match(src, i)
            raw = m.group(1)
            append(Tok("str", _unescape_str(raw), line, nl))
            k = raw.count("\n")
            line += k
            i = m.end()
            nl = False
            continue
        if c == "`":
            start_line = line
            quasis, exprs, j = _template(src, i + 1, tdepth)
            line += src.count("\n", i, j)
            append(Tok("tpl", (quasis, exprs, start_line), start_line, nl))
            i = j
            nl = False
            continue
        if c == "/" and _regex_allowed(out):
            j, in_cls = i + 1, False
            while j < n and src[j] != "\n":
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_cls = True
                elif ch == "]":
                    in_cls = False
                elif ch == "/" and not in_cls:
                    break
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            append(Tok("re", src[i:j], line, nl))
            i = j
            nl = False
            continue
        m = punct_match(src, i)
        if m:
            append(Tok("p", m.group(), line, nl))
            i = m.end()
            nl = False
            continue
        i += 1  # unknown char: skip
    out.append(Tok("eof", None, line, True))
    return out


def _unescape(ch: str) -> str:
    return {"n": "\n", "t": "\t", "r": "\r"}.get(ch, ch)


MAX_TEMPLATE_DEPTH = 32


def _skip_template(src: str, i: int, depth: int = 0) -> int:
    """Return the index just past the template literal whose body starts at ``i`` (no tokenization)."""
    if depth > MAX_TEMPLATE_DEPTH:
        raise ParseError("template literal nesting too deep")
    n = len(src)
    while i < n:
        c = src[i]
        if c == BACKSLASH:
            i += 2
            continue
        if c == "`":
            return i + 1
        if src.startswith("${", i):
            i = _skip_braces(src, i + 2, depth)
            continue
        i += 1
    return n


def _skip_braces(src: str, j: int, depth: int) -> int:
    """From just after ``${``, return the index just past the matching ``}``."""
    n, level = len(src), 1
    while j < n and level:
        c = src[j]
        if c == "{":
            level += 1
        elif c == "}":
            level -= 1
        elif c in "'\"":
            j += 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == BACKSLASH else 1
        elif c == "`":
            j = _skip_template(src, j + 1, depth + 1)
            continue
        j += 1
    return j


def _template(src: str, i: int, depth: int = 0) -> tuple[list[str], list[list[Tok]], int]:
    if depth > MAX_TEMPLATE_DEPTH:
        raise ParseError("template literal nesting too deep")
    quasis, exprs, buf, n = [], [], [], len(src)
    while i < n:
        c = src[i]
        if c == BACKSLASH and i + 1 < n:
            buf.append(_unescape(src[i + 1]))
            i += 2
            continue
        if c == "`":
            quasis.append("".join(buf))
            return quasis, exprs, i + 1
        if src.startswith("${", i):
            quasis.append("".join(buf))
            buf = []
            j = _skip_braces(src, i + 2, depth)
            exprs.append(_tokenize(src[i + 2 : j - 1], depth + 1))
            i = j
            continue
        buf.append(c)
        i += 1
    quasis.append("".join(buf))
    return quasis, exprs, n


def _regex_allowed(out: list[Tok]) -> bool:
    if not out:
        return True
    t = out[-1]
    if t.k == "p":
        return t.v not in (")", "]", "}")
    if t.k == "id":
        return t.v in REGEX_PREV_KW
    return False


def N(k: str, line: int, **kw: Any) -> dict[str, Any]:
    kw["k"] = k
    kw["line"] = line
    return kw


BINARY_PREC = {
    "??": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6,
    "==": 7, "!=": 7, "===": 7, "!==": 7,
    "<": 8, ">": 8, "<=": 8, ">=": 8, "instanceof": 8, "in": 8,
    "<<": 9, ">>": 9, ">>>": 9, "+": 10, "-": 10, "*": 11, "/": 11, "%": 11, "**": 12,
}
ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??="}
TYPE_DECL_KW = {"interface", "type", "declare", "enum", "namespace", "module", "abstract"}


@dataclass
class ParseResult:
    body: list[dict[str, Any]]
    skipped_regions: int = 0
    errors: list[str] = field(default_factory=list)


class Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.t = toks
        self.i = 0
        self.skipped = 0
        self.depth = 0

    # -- token helpers
    def peek(self, k: int = 0) -> Tok:
        j = self.i + k
        return self.t[j] if j < len(self.t) else self.t[-1]

    def next(self) -> Tok:
        tok = self.peek()
        if tok.k != "eof":
            self.i += 1
        return tok

    def at(self, v: str, k: int = 0) -> bool:
        tok = self.peek(k)
        return tok.k in ("p", "id") and tok.v == v

    def eat(self, v: str) -> bool:
        if self.at(v):
            self.i += 1
            return True
        return False

    def expect(self, v: str) -> Tok:
        if not self.at(v):
            raise ParseError(f"expected {v!r} at line {self.peek().line}, got {self.peek().v!r}")
        return self.next()

    def skip_balanced(self) -> None:
        """Skip one bracketed group starting at the current opening token."""
        pairs = {"(": ")", "[": "]", "{": "}"}
        open_ = self.peek().v
        close = pairs.get(open_)
        if close is None:
            self.next()
            return
        depth = 0
        while self.peek().k != "eof":
            tok = self.next()
            if tok.k == "p" and tok.v == open_:
                depth += 1
            elif tok.k == "p" and tok.v == close:
                depth -= 1
                if depth == 0:
                    return

    def skip_statement(self) -> None:
        """Error recovery: skip to the end of the current statement."""
        self.skipped += 1
        depth = 0
        start = self.i
        while self.peek().k != "eof":
            tok = self.peek()
            if tok.k == "p" and tok.v in "([{":
                depth += 1
            elif tok.k == "p" and tok.v in ")]}":
                if depth == 0:
                    if self.i == start:
                        self.next()
                    return
                depth -= 1
                if depth == 0 and tok.v == "}":
                    self.next()
                    if not self.at(";") and not self.at(")") and not self.at(","):
                        return
                    continue
            elif tok.k == "p" and tok.v == ";" and depth == 0:
                self.next()
                return
            elif depth == 0 and tok.nl and self.i > start and tok.k == "id" and tok.v in ("const", "let", "var", "function", "export", "import", "class", "async", "return", "if", "for", "while"):
                return
            self.next()

    def skip_type(self, stops: set[str]) -> None:
        """Skip a type expression until one of ``stops`` at depth 0."""
        depth = 0
        first = True
        while self.peek().k != "eof":
            tok = self.peek()
            if tok.k == "p":
                if depth == 0 and tok.v in stops and not (first and tok.v == "{"):
                    return
                if tok.v in ("(", "[", "{", "<"):
                    depth += 1
                elif tok.v in (")", "]", "}", ">"):
                    if depth == 0:
                        return
                    depth -= 1
                elif tok.v == ">>":
                    depth = max(0, depth - 2)
                elif tok.v == ">>>":
                    depth = max(0, depth - 3)
                elif tok.v == "=>" and depth == 0 and "=>" in stops:
                    return
            elif tok.k == "eof":
                return
            elif depth == 0 and tok.nl and not first and tok.k == "id" and tok.v in ("const", "let", "var", "function", "export", "import", "return"):
                return
            first = False
            self.next()

    # -- program / statements
    def parse_program(self) -> ParseResult:
        body = self.parse_statements(top=True)
        return ParseResult(body, self.skipped)

    def parse_statements(self, top: bool = False) -> list[dict[str, Any]]:
        out = []
        while self.peek().k != "eof" and not (not top and self.at("}")):
            start = self.i
            try:
                st = self.parse_statement()
                if st is not None:
                    out.append(st)
            except (ParseError, RecursionError, IndexError):
                self.i = start
                self.skip_statement()
            if self.i == start:
                self.next()
        return out

    def parse_block(self) -> list[dict[str, Any]]:
        self.expect("{")
        body = self.parse_statements()
        self.eat("}")
        return body

    def parse_statement(self) -> dict[str, Any] | None:
        tok = self.peek()
        line = tok.line
        if tok.k == "p":
            if tok.v == ";":
                self.next()
                return None
            if tok.v == "{":
                return N("Block", line, body=self.parse_block())
            if tok.v == "@":
                self.next()
                self.parse_lhs()
                return None
        if tok.k == "id":
            v = tok.v
            if v == "import" and not self.at("(", 1) and not self.at(".", 1):
                return self.parse_import()
            if v == "export":
                return self.parse_export()
            if v in ("const", "let", "var") or (v == "using" and self.peek(1).k == "id"):
                if v == "const" and self.at("enum", 1):
                    self.skip_statement()
                    return None
                return self.parse_var()
            if v == "function" or (v == "async" and self.at("function", 1) and not self.peek(1).nl):
                return self.parse_function_decl()
            if v == "class" or (v == "abstract" and self.at("class", 1)):
                if v == "abstract":
                    self.next()
                return self.parse_class()
            if v in TYPE_DECL_KW and self.peek(1).k == "id" and not self.peek(1).nl:
                if v != "type" or self.at("=", 2) or self.at("<", 2):
                    self.skip_type_declaration()
                    return None
            if v == "if":
                self.next()
                self.expect("(")
                test = self.parse_expression()
                self.expect(")")
                cons = self.parse_statement()
                alt = None
                if self.eat("else"):
                    alt = self.parse_statement()
                return N("If", line, test=test, cons=_as_list(cons), alt=_as_list(alt))
            if v in ("for", "while"):
                self.next()
                self.eat("await")
                head, head_var = None, None
                if self.at("("):
                    start = self.i
                    self.skip_balanced()
                    head, head_var = self._head_expr(start)
                body = self.parse_statement()
                return N("Loop", line, head=head, head_var=head_var, body=_as_list(body))
            if v == "do":
                self.next()
                body = self.parse_statement()
                if self.eat("while") and self.at("("):
                    self.skip_balanced()
                return N("Loop", line, head=None, body=_as_list(body))
            if v == "switch":
                self.next()
                self.expect("(")
                disc = self.parse_expression()
                self.expect(")")
                self.expect("{")
                cases: list[list[dict[str, Any]]] = []
                cur: list[dict[str, Any]] = []
                while not self.at("}") and self.peek().k != "eof":
                    if self.at("case") or self.at("default"):
                        self.next()
                        if not self.at(":"):
                            self.parse_expression()
                        self.expect(":")
                        if cur:
                            cases.append(cur)
                        cur = []
                        continue
                    st = self.parse_statement()
                    if st is not None:
                        cur.append(st)
                if cur:
                    cases.append(cur)
                self.eat("}")
                return N("Switch", line, disc=disc, cases=cases)
            if v == "try":
                self.next()
                block = self.parse_block()
                handler: list[dict[str, Any]] = []
                final: list[dict[str, Any]] = []
                if self.eat("catch"):
                    if self.at("("):
                        self.skip_balanced()
                    handler = self.parse_block()
                if self.eat("finally"):
                    final = self.parse_block()
                return N("Try", line, block=block, handler=handler, final=final)
            if v == "return":
                self.next()
                arg = None
                if not self.at(";") and not self.at("}") and not self.peek().nl and self.peek().k != "eof":
                    arg = self.parse_expression()
                self.eat(";")
                return N("Return", line, arg=arg)
            if v == "throw":
                self.next()
                arg = self.parse_expression()
                self.eat(";")
                return N("Throw", line, arg=arg)
            if v in ("break", "continue"):
                self.next()
                if self.peek().k == "id" and not self.peek().nl:
                    self.next()
                self.eat(";")
                return N("Jump", line)
            if self.peek(1).k == "p" and self.peek(1).v == ":" and v not in ("default", "case"):
                self.next()
                self.next()
                return self.parse_statement()  # label
        expr = self.parse_expression()
        self.eat(";")
        return N("Expr", line, expr=expr)

    def _head_expr(self, start: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Parse `for (const x of EXPR)` heads loosely: (iterated expression, loop binding pattern)."""
        toks = self.t[start + 1 : self.i - 1] + [Tok("eof", None, self.t[self.i - 1].line, True)]
        for j, tk in enumerate(toks):
            if tk.k == "id" and tk.v in ("of", "in") and j > 0:
                binding = None
                if toks[0].k == "id" and toks[0].v in ("const", "let", "var"):
                    try:
                        binding = Parser(toks[1:j] + [Tok("eof", None, tk.line, True)]).parse_binding()
                    except (ParseError, IndexError):
                        binding = None
                try:
                    return Parser(toks[j + 1 :]).parse_expression(), binding
                except (ParseError, RecursionError):
                    return None, binding
        return None, None

    def skip_type_declaration(self) -> None:
        self.skipped += 0  # type declarations are expected, not a coverage gap
        depth = 0
        while self.peek().k != "eof":
            tok = self.next()
            if tok.k == "p" and tok.v in "([{<":
                depth += 1
            elif tok.k == "p" and tok.v in ")]}>":
                depth -= 1
                if depth <= 0 and tok.v == "}":
                    if not self.at("|") and not self.at("&") and not self.at("["):
                        self.eat(";")
                        return
            elif tok.k == "p" and tok.v == ";" and depth <= 0:
                return
            if depth <= 0 and self.peek().nl and self.peek().k == "id" and self.peek().v in ("const", "let", "var", "function", "export", "import", "class", "interface", "type"):
                return

    def parse_import(self) -> dict[str, Any]:
        line = self.next().line
        specs: list[tuple[str, str | None]] = []
        if self.peek().k == "str":
            src = self.next().v
            self.eat(";")
            return N("Import", line, specs=specs, source=src)
        if self.at("type") and (self.peek(1).k == "id" and self.peek(1).v != "from" or self.at("{", 1)):
            self.next()
            self._skip_to_from()
            return N("Import", line, specs=[], source=None)
        if self.peek().k == "id" and not self.at("{") and not self.at("*"):
            specs.append((self.next().v, "default"))
            self.eat(",")
        if self.eat("*"):
            self.expect("as")
            specs.append((self.next().v, "*"))
        if self.at("{"):
            self.next()
            while not self.at("}") and self.peek().k != "eof":
                if self.at("type") and self.peek(1).k == "id" and not self.at(",", 1) and not self.at("}", 1):
                    self.next()
                tk = self.next()
                imported = tk.v
                local = imported
                if self.eat("as"):
                    local = self.next().v
                specs.append((local, imported))
                self.eat(",")
            self.eat("}")
        src = None
        if self.eat("from") and self.peek().k == "str":
            src = self.next().v
        if self.at("with") or self.at("assert"):
            self.next()
            if self.at("{"):
                self.skip_balanced()
        self.eat(";")
        return N("Import", line, specs=specs, source=src)

    def _skip_to_from(self) -> None:
        while self.peek().k != "eof" and not self.at("from"):
            self.next()
        self.eat("from")
        if self.peek().k == "str":
            self.next()
        self.eat(";")

    def parse_export(self) -> dict[str, Any] | None:
        line = self.next().line
        if self.eat("default"):
            if self.at("function") or (self.at("async") and self.at("function", 1)):
                d = self.parse_function_decl()
                d["exported"] = True
                return d
            if self.at("class"):
                return self.parse_class()
            expr = self.parse_expression()
            self.eat(";")
            return N("ExportDefault", line, expr=expr)
        if self.at("{") or self.at("*") or (self.at("type") and self.at("{", 1)):
            if self.at("type"):
                self.next()
            if self.eat("*"):
                if self.eat("as"):
                    self.next()
                self._skip_to_from()
                return None
            self.next()
            names = []
            while not self.at("}") and self.peek().k != "eof":
                local = self.next().v
                exported = local
                if self.eat("as"):
                    exported = self.next().v
                names.append((local, exported))
                self.eat(",")
            self.eat("}")
            src = None
            if self.eat("from") and self.peek().k == "str":
                src = self.next().v
            self.eat(";")
            return N("ExportNames", line, names=names, source=src)
        st = self.parse_statement()
        if st is not None:
            st["exported"] = True
        return st

    def parse_var(self) -> dict[str, Any]:
        tok = self.next()
        decls = []
        while True:
            target = self.parse_binding()
            if self.eat("!"):
                pass
            if self.eat(":"):
                self.skip_type({"=", ",", ";"})
            init = None
            if self.eat("="):
                init = self.parse_assign()
            decls.append((target, init))
            if not self.eat(","):
                break
        self.eat(";")
        return N("Var", tok.line, kind=tok.v, decls=decls)

    def parse_binding(self) -> dict[str, Any]:
        tok = self.peek()
        if self.at("{"):
            self.next()
            props = []
            rest = None
            while not self.at("}") and self.peek().k != "eof":
                if self.eat("..."):
                    rest = self.parse_binding()
                    self.eat(",")
                    continue
                key_tok = self.next()
                key = key_tok.v if key_tok.k in ("id", "str", "num") else None
                if key_tok.k == "p" and key_tok.v == "[":
                    self.i -= 1
                    self.skip_balanced()
                if self.eat(":"):
                    value = self.parse_binding()
                else:
                    value = N("Ident", key_tok.line, name=key)
                default = None
                if self.eat("="):
                    default = self.parse_assign()
                props.append((key, value, default))
                self.eat(",")
            self.eat("}")
            return N("ObjPat", tok.line, props=props, rest=rest)
        if self.at("["):
            self.next()
            elts = []
            while not self.at("]") and self.peek().k != "eof":
                if self.at(","):
                    self.next()
                    elts.append(None)
                    continue
                self.eat("...")
                b = self.parse_binding()
                if self.eat("="):
                    self.parse_assign()
                elts.append(b)
                self.eat(",")
            self.eat("]")
            return N("ArrPat", tok.line, elts=elts)
        name = self.next()
        if name.k != "id":
            raise ParseError("binding expected")
        return N("Ident", name.line, name=name.v)

    def parse_params(self) -> list[dict[str, Any]]:
        self.expect("(")
        params = []
        while not self.at(")") and self.peek().k != "eof":
            while self.peek().k == "id" and self.peek().v in ("public", "private", "protected", "readonly", "override") and self.peek(1).k == "id":
                self.next()
            if self.at("@"):
                self.next()
                self.parse_lhs()
            rest = self.eat("...")
            if self.at("this") and (self.at(":", 1) or self.at(",", 1)):
                self.next()
                if self.eat(":"):
                    self.skip_type({",", ")"})
                self.eat(",")
                continue
            b = self.parse_binding()
            self.eat("?")
            if self.eat(":"):
                self.skip_type({",", ")", "="})
            default = None
            if self.eat("="):
                default = self.parse_assign()
            params.append(N("Param", b["line"], pat=b, default=default, rest=rest))
            self.eat(",")
        self.expect(")")
        return params

    def parse_function_decl(self) -> dict[str, Any]:
        is_async = self.eat("async")
        line = self.expect("function").line
        self.eat("*")
        name = self.next().v if self.peek().k == "id" else None
        if self.at("<"):
            self.skip_generic()
        params = self.parse_params()
        if self.eat(":"):
            self.skip_type({"{"})
        body = self.parse_block() if self.at("{") else []
        self.eat(";")
        return N("Func", line, name=name, params=params, body=body, is_async=is_async, decl=True)

    def skip_generic(self) -> None:
        depth = 0
        while self.peek().k != "eof":
            tok = self.next()
            if tok.k == "p" and tok.v == "<":
                depth += 1
            elif tok.k == "p" and tok.v == ">":
                depth -= 1
            elif tok.k == "p" and tok.v == ">>":
                depth -= 2
            elif tok.k == "p" and tok.v == ">>>":
                depth -= 3
            if depth <= 0:
                return

    def parse_class(self) -> dict[str, Any]:
        line = self.expect("class").line
        name = self.next().v if self.peek().k == "id" and not self.at("extends") and not self.at("implements") and not self.at("{") else None
        if self.at("<"):
            self.skip_generic()
        superclass = None
        if self.eat("extends"):
            superclass = self.parse_lhs()
        if self.eat("implements"):
            self.skip_type({"{"})
        self.expect("{")
        methods: dict[str, dict[str, Any]] = {}
        fields: dict[str, dict[str, Any]] = {}
        while not self.at("}") and self.peek().k != "eof":
            start = self.i
            try:
                if self.eat(";"):
                    continue
                if self.at("@"):
                    self.next()
                    self.parse_lhs()
                    continue
                while self.peek().k == "id" and self.peek().v in ("public", "private", "protected", "static", "readonly", "abstract", "override", "declare", "accessor") \
                        and not self.at("(", 1) and not self.at("=", 1) and not self.at(":", 1):
                    self.next()
                is_async = False
                if self.at("async") and not self.at("(", 1) and not self.peek(1).nl:
                    self.next()
                    is_async = True
                self.eat("*")
                if (self.at("get") or self.at("set")) and self.peek(1).k == "id":
                    self.next()
                key_tok = self.next()
                if key_tok.k == "p" and key_tok.v == "[":
                    self.i -= 1
                    self.skip_balanced()
                    key = None
                elif key_tok.k == "p" and key_tok.v == "#":
                    key = "#" + self.next().v
                else:
                    key = str(key_tok.v)
                self.eat("?")
                self.eat("!")
                if self.at("<"):
                    self.skip_generic()
                if self.at("("):
                    params = self.parse_params()
                    if self.eat(":"):
                        self.skip_type({"{", ";"})
                    body = self.parse_block() if self.at("{") else []
                    if key:
                        methods[key] = N("Func", key_tok.line, name=key, params=params, body=body, is_async=is_async, method=True)
                    continue
                if self.eat(":"):
                    self.skip_type({"=", ";", "}"})
                if self.eat("="):
                    value = self.parse_assign()
                    if key:
                        fields[key] = value
                self.eat(";")
            except (ParseError, RecursionError):
                self.i = start
                self.skip_statement()
            if self.i == start:
                self.next()
        self.eat("}")
        return N("Class", line, name=name, methods=methods, fields=fields, superclass=superclass)

    # -- expressions
    def parse_expression(self) -> dict[str, Any]:
        e = self.parse_assign()
        if self.at(","):
            items = [e]
            while self.eat(","):
                if self.at(")") or self.at(";"):
                    break
                items.append(self.parse_assign())
            return N("Seq", e["line"], items=items)
        return e

    def _arrow_ahead(self) -> bool:
        """Is the token stream at an arrow function (``x =>``, ``(…) =>``, ``async (…) =>``, ``<T>(…) =>``)?"""
        j = self.i
        if self.t[j].k == "id" and self.t[j].v == "async" and not self.t[j + 1].nl:
            j += 1
        if self.t[j].k == "id" and self.t[j + 1].k == "p" and self.t[j + 1].v == "=>":
            return True
        if self.t[j].k == "p" and self.t[j].v == "<":
            depth = 0
            while j < len(self.t) - 1:
                if self.t[j].v == "<":
                    depth += 1
                elif self.t[j].v == ">":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
        if not (self.t[j].k == "p" and self.t[j].v == "("):
            return False
        depth = 0
        while j < len(self.t) - 1:
            tk = self.t[j]
            if tk.k == "p" and tk.v in "([{":
                depth += 1
            elif tk.k == "p" and tk.v in ")]}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        nxt = self.t[j + 1] if j + 1 < len(self.t) else self.t[-1]
        if nxt.k == "p" and nxt.v == "=>":
            return True
        if nxt.k == "p" and nxt.v == ":":
            # return type annotation: scan to "=>" at depth 0 within a bounded window
            depth = 0
            for k in range(j + 2, min(j + 200, len(self.t))):
                tk = self.t[k]
                if tk.k == "p" and tk.v in "([{<":
                    depth += 1
                elif tk.k == "p" and tk.v in ")]}>":
                    depth -= 1
                    if depth < 0:
                        return False
                elif tk.k == "p" and tk.v == "=>" and depth == 0:
                    return True
                elif tk.k == "p" and tk.v in (";", ",") and depth == 0:
                    return False
        return False

    def parse_arrow(self) -> dict[str, Any]:
        line = self.peek().line
        is_async = False
        if self.at("async") and not self.at("=>", 1):
            self.next()
            is_async = True
        if self.at("<"):
            self.skip_generic()
        if self.peek().k == "id" and self.at("=>", 1):
            tok = self.next()
            params = [N("Param", tok.line, pat=N("Ident", tok.line, name=tok.v), default=None, rest=False)]
        else:
            params = self.parse_params()
            if self.eat(":"):
                self.skip_type({"=>"})
        self.expect("=>")
        if self.at("{"):
            body = self.parse_block()
            return N("Func", line, name=None, params=params, body=body, is_async=is_async, arrow=True)
        expr = self.parse_assign()
        return N("Func", line, name=None, params=params, body=[N("Return", expr["line"], arg=expr)], is_async=is_async, arrow=True, expr_body=True)

    def parse_assign(self) -> dict[str, Any]:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            self.depth -= 1
            raise ParseError("expression too deep")
        try:
            if self._arrow_ahead():
                return self.parse_arrow()
            if self.at("yield"):
                line = self.next().line
                self.eat("*")
                arg = None if self.at(")") or self.at(";") or self.at(",") or self.at("}") else self.parse_assign()
                return N("Unary", line, op="yield", arg=arg)
            left = self.parse_conditional()
            if self.peek().k == "p" and self.peek().v in ASSIGN_OPS:
                op = self.next().v
                right = self.parse_assign()
                return N("Assign", left["line"], op=op, target=left, value=right)
            return left
        finally:
            self.depth -= 1

    def parse_conditional(self) -> dict[str, Any]:
        test = self.parse_binary(0)
        if self.at("?"):
            self.next()
            cons = self.parse_assign()
            self.expect(":")
            alt = self.parse_assign()
            return N("Cond", test["line"], test=test, cons=cons, alt=alt)
        return test

    def parse_binary(self, min_prec: int) -> dict[str, Any]:
        left = self.parse_unary()
        while True:
            tok = self.peek()
            op = tok.v if tok.k in ("p", "id") else None
            if op in ("as", "satisfies") and tok.k == "id" and not tok.nl:
                self.next()
                if self.at("const"):
                    self.next()
                else:
                    self.skip_type({")", "]", "}", ",", ";", "=", "?", ":", "&&", "||", "??", "==", "===", "!=", "!==", "+", "-", "*", "/", ".", "=>"})
                continue
            prec = BINARY_PREC.get(op or "")
            if prec is None or prec <= min_prec:
                return left
            if tok.k == "id" and tok.nl:
                return left
            self.next()
            right = self.parse_binary(prec if op != "**" else prec - 1)
            left = N("Bin", left["line"], op=op, left=left, right=right)

    def parse_unary(self) -> dict[str, Any]:
        tok = self.peek()
        if tok.k == "p" and tok.v in ("!", "-", "+", "~", "++", "--"):
            self.next()
            return N("Unary", tok.line, op=tok.v, arg=self.parse_unary())
        if tok.k == "id" and tok.v in ("typeof", "void", "delete", "await"):
            if not (tok.v == "await" and (self.at(")", 1) or self.at(";", 1))):
                self.next()
                return N("Unary", tok.line, op=tok.v, arg=self.parse_unary())
        if tok.k == "p" and tok.v == "<" and not self._arrow_ahead():
            self.skip_generic()  # legacy <T>expr assertion
            return self.parse_unary()
        expr = self.parse_postfix()
        if self.peek().k == "p" and self.peek().v in ("++", "--") and not self.peek().nl:
            self.next()
        return expr

    def parse_args(self) -> list[dict[str, Any]]:
        self.expect("(")
        args = []
        while not self.at(")") and self.peek().k != "eof":
            if self.eat("..."):
                args.append(N("Spread", self.peek().line, arg=self.parse_assign()))
            else:
                args.append(self.parse_assign())
            if not self.eat(","):
                break
        self.expect(")")
        return args

    def _generic_call_ahead(self) -> bool:
        if not self.at("<"):
            return False
        depth = 0
        for k in range(self.i, min(self.i + 120, len(self.t))):
            tk = self.t[k]
            if tk.k == "p" and tk.v == "<":
                depth += 1
            elif tk.k == "p" and tk.v in (">", ">>", ">>>"):
                depth -= len(tk.v)
                if depth <= 0:
                    nxt = self.t[k + 1] if k + 1 < len(self.t) else self.t[-1]
                    return nxt.k == "p" and nxt.v in ("(", "`")
            elif tk.k == "p" and tk.v in (";", "{", "}", "&&", "||", "=", "=>") and not (tk.v == "{" and depth > 0):
                return False
        return False

    def parse_postfix(self) -> dict[str, Any]:
        expr = self.parse_lhs()
        while True:
            tok = self.peek()
            if tok.k == "p" and tok.v == "(" :
                expr = N("Call", tok.line, callee=expr, args=self.parse_args(), optional=False)
            elif tok.k == "p" and tok.v == "?." and self.at("(", 1):
                self.next()
                expr = N("Call", tok.line, callee=expr, args=self.parse_args(), optional=True)
            elif tok.k == "tpl":
                self.next()
                expr = N("TaggedTpl", tok.line, tag=expr, tpl=self._tpl_node(tok))
            elif tok.k == "p" and tok.v == "<" and self._generic_call_ahead():
                self.skip_generic()
            elif tok.k == "p" and tok.v == "!" and not tok.nl and not self.at("=", 1):
                self.next()  # non-null assertion
            else:
                return expr

    def parse_lhs(self) -> dict[str, Any]:
        tok = self.peek()
        if tok.k == "id" and tok.v == "new" and not self.at(".", 1):
            self.next()
            callee = self.parse_lhs_no_call()
            if self.at("<"):
                self.skip_generic()
            args = self.parse_args() if self.at("(") else []
            expr = N("New", tok.line, callee=callee, args=args)
        else:
            expr = self.parse_primary()
        return self._members(expr, allow_call=True)

    def parse_lhs_no_call(self) -> dict[str, Any]:
        expr = self.parse_primary()
        return self._members(expr, allow_call=False)

    def _members(self, expr: dict[str, Any], allow_call: bool) -> dict[str, Any]:
        while True:
            tok = self.peek()
            if tok.k == "p" and tok.v == ".":
                self.next()
                nm = self.next()
                if nm.k == "p" and nm.v == "#":
                    nm = self.next()
                expr = N("Member", tok.line, obj=expr, prop=str(nm.v), computed=False)
            elif tok.k == "p" and tok.v == "?." and not self.at("(", 1):
                self.next()
                if self.at("["):
                    self.next()
                    idx = self.parse_expression()
                    self.expect("]")
                    expr = N("Member", tok.line, obj=expr, prop=idx, computed=True)
                else:
                    expr = N("Member", tok.line, obj=expr, prop=str(self.next().v), computed=False)
            elif tok.k == "p" and tok.v == "[" and not tok.nl:
                self.next()
                idx = self.parse_expression()
                self.expect("]")
                expr = N("Member", tok.line, obj=expr, prop=idx, computed=True)
            elif allow_call and tok.k == "p" and tok.v == "(" and not (tok.nl and expr["k"] in ("Func",)):
                expr = N("Call", tok.line, callee=expr, args=self.parse_args(), optional=False)
            elif tok.k == "p" and tok.v == "!" and not tok.nl and not self.at("=", 1) and (self.at(".", 1) or self.at("[", 1) or self.at("(", 1)):
                self.next()
            else:
                return expr

    def _tpl_node(self, tok: Tok) -> dict[str, Any]:
        quasis, expr_toks, line = tok.v
        exprs = []
        for toks in expr_toks:
            try:
                exprs.append(Parser(toks).parse_expression())
            except (ParseError, RecursionError, IndexError):
                exprs.append(N("Unknown", line))
        return N("Tpl", line, quasis=quasis, exprs=exprs)

    def parse_primary(self) -> dict[str, Any]:
        tok = self.peek()
        if tok.k == "id":
            if tok.v == "function" or (tok.v == "async" and self.at("function", 1)):
                is_async = self.eat("async")
                self.next()
                self.eat("*")
                name = self.next().v if self.peek().k == "id" else None
                if self.at("<"):
                    self.skip_generic()
                params = self.parse_params()
                if self.eat(":"):
                    self.skip_type({"{"})
                body = self.parse_block()
                return N("Func", tok.line, name=name, params=params, body=body, is_async=is_async)
            if tok.v == "class":
                return self.parse_class()
            if tok.v == "import" and self.at("(", 1):
                self.next()
                return N("Ident", tok.line, name="import")
            self.next()
            if tok.v in ("true", "false"):
                return N("Lit", tok.line, value=tok.v == "true")
            if tok.v in ("null", "undefined"):
                return N("Lit", tok.line, value=None)
            return N("Ident", tok.line, name=tok.v)
        if tok.k == "num":
            self.next()
            return N("Lit", tok.line, value=tok.v, num=True)
        if tok.k == "str":
            self.next()
            return N("Lit", tok.line, value=tok.v)
        if tok.k == "tpl":
            self.next()
            return self._tpl_node(tok)
        if tok.k == "re":
            self.next()
            return N("Regex", tok.line, value=tok.v)
        if tok.k == "p":
            if tok.v == "(":
                self.next()
                e = self.parse_expression()
                self.expect(")")
                return e
            if tok.v == "[":
                self.next()
                elts = []
                while not self.at("]") and self.peek().k != "eof":
                    if self.at(","):
                        self.next()
                        continue
                    if self.eat("..."):
                        elts.append(N("Spread", self.peek().line, arg=self.parse_assign()))
                    else:
                        elts.append(self.parse_assign())
                    if not self.eat(","):
                        break
                self.expect("]")
                return N("Array", tok.line, elts=elts)
            if tok.v == "{":
                return self.parse_object()
            if tok.v == "#":
                self.next()
                return N("Ident", tok.line, name="#" + str(self.next().v))
        raise ParseError(f"unexpected token {tok.v!r} at line {tok.line}")

    def parse_object(self) -> dict[str, Any]:
        line = self.expect("{").line
        props: list[dict[str, Any]] = []
        while not self.at("}") and self.peek().k != "eof":
            tok = self.peek()
            if self.eat("..."):
                props.append(N("SpreadProp", tok.line, arg=self.parse_assign()))
                self.eat(",")
                continue
            is_async = False
            if self.at("async") and not self.at(":", 1) and not self.at("(", 1) and not self.at(",", 1) and not self.at("}", 1):
                self.next()
                is_async = True
            self.eat("*")
            if (self.at("get") or self.at("set")) and not self.at(":", 1) and not self.at("(", 1) and not self.at(",", 1) and not self.at("}", 1):
                self.next()
            ktok = self.next()
            computed = None
            if ktok.k == "p" and ktok.v == "[":
                computed = self.parse_assign()
                self.expect("]")
                key = None
            else:
                key = str(ktok.v)
            if self.at("(") or self.at("<"):
                if self.at("<"):
                    self.skip_generic()
                params = self.parse_params()
                if self.eat(":"):
                    self.skip_type({"{"})
                body = self.parse_block()
                props.append(N("Prop", ktok.line, key=key, computed=computed,
                               value=N("Func", ktok.line, name=key, params=params, body=body, is_async=is_async, method=True)))
            elif self.eat(":"):
                props.append(N("Prop", ktok.line, key=key, computed=computed, value=self.parse_assign()))
            else:
                default = None
                if self.eat("="):
                    default = self.parse_assign()
                props.append(N("Prop", ktok.line, key=key, computed=None, value=N("Ident", ktok.line, name=key), shorthand=True, default=default))
            if not self.eat(","):
                break
        self.expect("}")
        return N("Object", line, props=props)


def _as_list(st: dict[str, Any] | None) -> list[dict[str, Any]]:
    if st is None:
        return []
    if st["k"] == "Block":
        return st["body"]
    return [st]


def parse(src: str) -> ParseResult:
    toks = tokenize(src)
    p = Parser(toks)
    return p.parse_program()
