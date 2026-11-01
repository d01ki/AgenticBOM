"""Local web GUI: run scans, comparisons and demos from the browser.

Security model (the GUI can start scans of local paths, so it is locked down):
  * binds to loopback only; the Host header must be the loopback address + port (DNS-rebinding guard)
  * a random per-process token is required: ``/?token=...`` once, then an HttpOnly SameSite=Strict cookie
  * every POST also needs the token in ``X-AEM-Token`` (CSRF) and a JSON body; a foreign Origin is rejected
  * scanned code is never executed (same scanner as the CLI); GitHub URLs go through the same allowlist
Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import threading
import time
from collections import OrderedDict
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agentic_bom import __version__
from agentic_bom.analyzers.drift import diff_reports
from agentic_bom.core.safety import UnsafeInputError, export_git_revision, shallow_clone
from agentic_bom.exporters.agentic_bom import to_agentic_bom
from agentic_bom.exporters.html import render_html
from agentic_bom.exporters.sarif import drift_to_sarif, scan_to_sarif
from agentic_bom.exporters.writer import capability_graph_doc
from agentic_bom.scanner import scan

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_BODY = 64 * 1024
MAX_RUNS = 50
COOKIE = "aem_token"
SCENARIOS = ("same-bom-new-exposure", "mcp-tool-schema-drift", "ts-same-bom-new-exposure")
_RUN_ID = re.compile(r"^[0-9a-f]{12}$")


class GuiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class AppState:
    def __init__(self, examples_dir: Path | None, start_dir: Path) -> None:
        self.token = secrets.token_hex(24)
        self.runs: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()  # one analysis at a time keeps memory bounded
        self.examples_dir = examples_dir
        self.start_dir = start_dir

    def add_run(self, run: dict[str, Any]) -> dict[str, Any]:
        run["id"] = secrets.token_hex(6)
        run["created"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.runs[run["id"]] = run
            while len(self.runs) > MAX_RUNS:
                self.runs.popitem(last=False)
        return run

    def get_run(self, run_id: str) -> dict[str, Any]:
        if not _RUN_ID.match(run_id):
            raise GuiError(404, "unknown run")
        with self.lock:
            run = self.runs.get(run_id)
        if run is None:
            raise GuiError(404, "unknown run")
        return run


def run_listing(run: dict[str, Any]) -> dict[str, Any]:
    head = run["head"]
    out = {
        "id": run["id"],
        "kind": run["kind"],
        "label": run["label"],
        "created": run["created"],
        "summary": head["summary"],
        "banner": run["drift"]["banner"] if run.get("drift") else None,
        "bom_status": run["drift"]["bom_delta"]["status"] if run.get("drift") else None,
        "findings": len(run["drift"]["findings"]) if run.get("drift") else None,
        "risk_findings": (sum(1 for f in run["drift"]["findings"] if f["kind"] != "capability_removed") if run.get("drift") else None),
        "artifacts": artifact_names(run),
    }
    return out


def artifact_names(run: dict[str, Any]) -> list[str]:
    names = ["agentic-bom.json", "capability-graph.json", "findings.sarif"]
    if run.get("drift"):
        names.append("security-drift.json")
    return names


def artifact(run: dict[str, Any], name: str) -> tuple[str, str]:
    head, drift = run["head"], run.get("drift")
    if name == "agentic-bom.json":
        data: Any = to_agentic_bom(head)
    elif name == "capability-graph.json":
        data = capability_graph_doc(head)
    elif name == "findings.sarif":
        data = drift_to_sarif(drift) if drift else scan_to_sarif(head)
    elif name == "security-drift.json" and drift:
        data = drift
    else:
        raise GuiError(404, "unknown artifact")
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", "application/json"


# ---------------------------------------------------------------------------- actions
def _local_dir(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise GuiError(400, f"{field}: a directory path is required")
    p = Path(value.strip()).expanduser()
    if not p.is_dir():
        raise GuiError(400, f"{field}: not a directory")
    return p.resolve()


def _bool(v: Any) -> bool:
    return v is True


def action_scan(state: AppState, body: dict[str, Any]) -> dict[str, Any]:
    target = body.get("target")
    if not isinstance(target, str) or not target.strip():
        raise GuiError(400, "target: a directory path or https://github.com/<owner>/<repo> URL is required")
    target = target.strip()
    ref = body.get("ref") or None
    if ref is not None and not isinstance(ref, str):
        raise GuiError(400, "ref must be a string")
    tmp = None
    if target.startswith(("http://", "https://")):
        path = shallow_clone(target, ref)  # validates host allowlist
        tmp = path.parent
        label = target.rstrip("/").removesuffix(".git").split("/")[-1]
    else:
        path = _local_dir(target, "target")
        label = path.name
    try:
        with state.scan_lock:
            report = scan(path, label=label, include_tests=_bool(body.get("include_tests")))
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
    run = state.add_run({"kind": "scan", "label": label, "head": report, "drift": None,
                         "retest": f"agentic-bom scan {target}" + (f" --ref {ref}" if ref else "") + " --out out/"})
    return run_listing(run)


def action_diff(state: AppState, body: dict[str, Any]) -> dict[str, Any]:
    git_repo = body.get("git_repo")
    temps: list[Path] = []
    try:
        if git_repo:
            repo = _local_dir(git_repo, "git_repo")
            b_rev, h_rev = body.get("base"), body.get("head")
            if not isinstance(b_rev, str) or not isinstance(h_rev, str):
                raise GuiError(400, "base/head revisions are required")
            bp = export_git_revision(repo, b_rev.strip())
            temps.append(bp)
            hp = export_git_revision(repo, h_rev.strip())
            temps.append(hp)
            label, bl, hl = repo.name, b_rev.strip(), h_rev.strip()
            retest = f"agentic-bom diff {bl} {hl} --git {repo} --out out/"
        else:
            bp, hp = _local_dir(body.get("base"), "base"), _local_dir(body.get("head"), "head")
            bl, hl = bp.name, hp.name
            label = hp.parent.name if (bp.parent == hp.parent or bp.name == hp.name) else hp.name
            retest = f"agentic-bom diff {bp} {hp} --out out/"
        inc = _bool(body.get("include_tests"))
        with state.scan_lock:
            base = scan(bp, label=label, include_tests=inc)
            head = scan(hp, label=label, include_tests=inc)
    finally:
        for t in temps:
            shutil.rmtree(t, ignore_errors=True)
    drift = diff_reports(base, head, bl, hl)
    run = state.add_run({"kind": "diff", "label": f"{label}: {bl} → {hl}", "head": head, "base": base, "drift": drift, "retest": retest})
    return run_listing(run)


def action_demo(state: AppState, body: dict[str, Any]) -> dict[str, Any]:
    scenario = body.get("scenario")
    if scenario not in SCENARIOS:
        raise GuiError(400, "unknown scenario")
    if state.examples_dir is None or not (state.examples_dir / scenario).is_dir():
        raise GuiError(404, "bundled examples not found (start with --examples-dir)")
    root = state.examples_dir / scenario
    with state.scan_lock:
        reps = {rev: scan(root / rev, label=scenario) for rev in ("baseline", "candidate", "fixed")}
    out = []
    for b, h in (("baseline", "candidate"), ("candidate", "fixed")):
        drift = diff_reports(reps[b], reps[h], b, h)
        run = state.add_run({"kind": "diff", "label": f"{scenario}: {b} → {h}", "head": reps[h], "base": reps[b], "drift": drift,
                             "retest": f"agentic-bom diff {root / b} {root / h} --out out/"})
        out.append(run_listing(run))
    return {"runs": out}


def list_dirs(state: AppState, raw: str | None) -> dict[str, Any]:
    p = Path(raw).expanduser() if raw else state.start_dir
    try:
        p = p.resolve()
    except OSError:
        raise GuiError(400, "invalid path")
    if not p.is_dir():
        raise GuiError(400, "not a directory")
    dirs = []
    try:
        for entry in sorted(os.scandir(p), key=lambda e: e.name.lower()):
            try:
                if entry.is_dir(follow_symlinks=False) and not entry.name.startswith("."):
                    dirs.append(entry.name)
            except OSError:
                continue
            if len(dirs) >= 500:
                break
    except OSError:
        raise GuiError(403, "directory not readable")
    hints = [n for n in ("pyproject.toml", "requirements.txt", "setup.py", ".git") if (p / n).exists()]
    roots = []
    if os.name == "nt":
        roots = [f"{d}:\\" for d in "CDEFGHIJ" if Path(f"{d}:\\").exists()]
    return {"path": str(p), "parent": str(p.parent) if p.parent != p else None, "dirs": dirs, "project_hints": hints, "roots": roots}


# ---------------------------------------------------------------------------- HTTP layer
class Handler(BaseHTTPRequestHandler):
    server_version = f"AEM-GUI/{__version__}"
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> AppState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet; never log tokens
        if os.environ.get("AEM_GUI_LOG"):
            msg = fmt % args
            super().log_message("%s", re.sub(r"token=[0-9a-f]+", "token=***", msg))

    # -- helpers
    def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        if self.path.startswith("/api/"):
            self._json(status, {"error": message})
        else:
            page = f"<!DOCTYPE html><meta charset=utf-8><title>{status}</title><p>{status}: {_esc(message)}</p>"
            self._send(status, page.encode("utf-8"), "text/html; charset=utf-8")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.server.server_address[1]  # type: ignore[attr-defined]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        return host in allowed

    def _cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return None
        return c[COOKIE].value if COOKIE in c else None

    def _authed(self) -> bool:
        tok = self._cookie_token()
        return tok is not None and secrets.compare_digest(tok, self.state.token)

    def _guard(self) -> bool:
        if not self._host_ok():
            self._error(403, "forbidden host")
            return False
        return True

    # -- GET
    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        try:
            if not self._guard():
                return
            url = urlsplit(self.path)
            q = parse_qs(url.query)
            if url.path == "/" and "token" in q:
                if secrets.compare_digest(q["token"][0], self.state.token):
                    cookie = f"{COOKIE}={self.state.token}; HttpOnly; SameSite=Strict; Path=/"
                    self._send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
                else:
                    self._error(403, "invalid token")
                return
            if not self._authed():
                self._error(403, "open the URL printed in the terminal (it contains the access token)")
                return
            self.route_get(url.path, q)
        except GuiError as exc:
            self._error(exc.status, exc.message)
        except Exception:  # pragma: no cover - defensive
            self._error(500, "internal error")

    def route_get(self, path: str, q: dict[str, list[str]]) -> None:
        if path == "/":
            html = resources.files("agentic_bom.web").joinpath("app.html").read_text(encoding="utf-8")
            html = html.replace("__AEM_TOKEN__", self.state.token).replace("__AEM_VERSION__", __version__)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/runs":
            with self.state.lock:
                runs = [run_listing(r) for r in reversed(self.state.runs.values())]
            self._json(200, {"runs": runs})
        elif path == "/api/scenarios":
            available = [s for s in SCENARIOS if self.state.examples_dir and (self.state.examples_dir / s).is_dir()]
            self._json(200, {"scenarios": available})
        elif path == "/api/fs":
            self._json(200, list_dirs(self.state, (q.get("path") or [None])[0]))
        elif path.startswith("/report/"):
            run = self.state.get_run(path[len("/report/"):])
            html = render_html(run["head"], run.get("drift"), run["retest"])
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path.startswith("/download/"):
            parts = path.split("/")
            if len(parts) != 4:
                raise GuiError(404, "not found")
            run = self.state.get_run(parts[2])
            body, ctype = artifact(run, parts[3])
            fname = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{run['id']}-{parts[3]}")
            self._send(200, body.encode("utf-8"), ctype, {"Content-Disposition": f'attachment; filename="{fname}"'})
        else:
            raise GuiError(404, "not found")

    # -- POST
    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self._guard():
                return
            if not self._authed():
                raise GuiError(403, "not authenticated")
            hdr = self.headers.get("X-AEM-Token") or ""
            if not secrets.compare_digest(hdr, self.state.token):
                raise GuiError(403, "missing CSRF token")
            origin = self.headers.get("Origin")
            if origin and origin.lower() != f"http://{(self.headers.get('Host') or '').lower()}":
                raise GuiError(403, "cross-origin request rejected")
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                raise GuiError(415, "JSON body required")
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > MAX_BODY:
                raise GuiError(413, "body too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                raise GuiError(400, "invalid JSON")
            if not isinstance(body, dict):
                raise GuiError(400, "JSON object expected")
            path = urlsplit(self.path).path
            if path == "/api/scan":
                self._json(200, action_scan(self.state, body))
            elif path == "/api/diff":
                self._json(200, action_diff(self.state, body))
            elif path == "/api/demo":
                self._json(200, action_demo(self.state, body))
            else:
                raise GuiError(404, "not found")
        except GuiError as exc:
            self._json(exc.status, {"error": exc.message})
        except UnsafeInputError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # report the class, never a traceback
            self._json(500, {"error": f"analysis failed: {type(exc).__name__}"})


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def make_server(host: str = "127.0.0.1", port: int = 8765, examples_dir: Path | None = None, start_dir: Path | None = None) -> ThreadingHTTPServer:
    if host not in LOOPBACK_HOSTS:
        raise UnsafeInputError("the GUI only binds to a loopback address (127.0.0.1, localhost or ::1)")
    cls = ThreadingHTTPServer
    if host == "::1":
        import socket

        class _V6(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        cls = _V6
    srv = cls((host, port), Handler)
    srv.daemon_threads = True
    srv.state = AppState(examples_dir, (start_dir or Path.cwd()).resolve())  # type: ignore[attr-defined]
    return srv


def gui_url(srv: ThreadingHTTPServer) -> str:
    host, port = srv.server_address[0], srv.server_address[1]
    shown = "127.0.0.1" if host in ("127.0.0.1", "0.0.0.0") else ("[::1]" if host == "::1" else "localhost")
    return f"http://{shown}:{port}/?token={srv.state.token}"  # type: ignore[attr-defined]
