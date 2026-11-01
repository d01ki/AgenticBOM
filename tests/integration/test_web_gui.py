"""Local web GUI: access control and end-to-end flows over real HTTP."""

import http.client
import json
import threading

import pytest

from agentic_bom.core.safety import UnsafeInputError
from agentic_bom.web.server import make_server

from ..conftest import EXAMPLES

SAME = EXAMPLES / "same-bom-new-exposure"


@pytest.fixture(scope="module")
def gui():
    srv = make_server("127.0.0.1", 0, EXAMPLES)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    yield srv, port, srv.state.token
    srv.shutdown()
    srv.server_close()


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    h = {"Host": f"127.0.0.1:{port}"}
    h.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    payload = r.read()
    c.close()
    return r, payload


def auth(token, extra=None):
    h = {"Cookie": f"aem_token={token}"}
    h.update(extra or {})
    return h


def post(port, token, path, body, **extra):
    return req(port, "POST", path, body, auth(token, {"X-AEM-Token": token, **extra}))


def test_refuses_non_loopback_bind():
    with pytest.raises(UnsafeInputError):
        make_server("0.0.0.0", 0)


def test_token_required_and_exchanged_for_cookie(gui):
    _, port, token = gui
    assert req(port, "GET", "/")[0].status == 403
    assert req(port, "GET", "/?token=" + "0" * 48)[0].status == 403
    r, _ = req(port, "GET", f"/?token={token}")
    assert r.status == 303 and r.getheader("Location") == "/"
    cookie = r.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    r, body = req(port, "GET", "/", headers=auth(token))
    assert r.status == 200 and b"Agentic Exposure Mapper" in body
    assert "default-src 'none'" in body.decode()
    assert r.getheader("X-Frame-Options") == "SAMEORIGIN"


def test_dns_rebinding_host_rejected(gui):
    _, port, token = gui
    r, _ = req(port, "GET", "/api/runs", headers=auth(token, {"Host": f"evil.example:{port}"}))
    assert r.status == 403


def test_post_requires_csrf_header_json_and_same_origin(gui):
    _, port, token = gui
    body = {"target": str(SAME / "candidate")}
    assert req(port, "POST", "/api/scan", body, auth(token))[0].status == 403  # no X-AEM-Token
    assert req(port, "POST", "/api/scan", body, {"X-AEM-Token": token})[0].status == 403  # no cookie
    assert post(port, token, "/api/scan", body, Origin="http://evil.example")[0].status == 403
    r, _ = post(port, token, "/api/scan", body, **{"Content-Type": "text/plain"})
    assert r.status == 415


def test_scan_report_and_downloads(gui):
    _, port, token = gui
    r, payload = post(port, token, "/api/scan", {"target": str(SAME / "candidate")}, Origin=f"http://127.0.0.1:{port}")
    assert r.status == 200, payload
    run = json.loads(payload)
    assert run["kind"] == "scan" and run["summary"]["potentially_exposed_paths"] == 1
    r, html = req(port, "GET", f"/report/{run['id']}", headers=auth(token))
    assert r.status == 200 and b'id="aem-data"' in html
    for name in run["artifacts"]:
        r, data = req(port, "GET", f"/download/{run['id']}/{name}", headers=auth(token))
        assert r.status == 200 and "attachment" in r.getheader("Content-Disposition")
        json.loads(data)
    assert req(port, "GET", f"/download/{run['id']}/..%2f..%2fsecret", headers=auth(token))[0].status == 404
    assert req(port, "GET", "/report/not-a-run", headers=auth(token))[0].status == 404


def test_diff_and_demo(gui):
    _, port, token = gui
    r, payload = post(port, token, "/api/diff", {"base": str(SAME / "baseline"), "head": str(SAME / "candidate")})
    run = json.loads(payload)
    assert r.status == 200 and run["banner"] == "Agentic BOM unchanged · 1 new potential exposure path"
    r, payload = post(port, token, "/api/demo", {"scenario": "mcp-tool-schema-drift"})
    assert r.status == 200 and len(json.loads(payload)["runs"]) == 2
    r, payload = req(port, "GET", "/api/runs", headers=auth(token))
    assert len(json.loads(payload)["runs"]) >= 3


def test_input_errors_are_clean(gui):
    _, port, token = gui
    r, payload = post(port, token, "/api/scan", {"target": "https://evil.example/a/b"})
    assert r.status == 400 and "github.com" in json.loads(payload)["error"]
    r, payload = post(port, token, "/api/scan", {"target": str(SAME / "does-not-exist")})
    assert r.status == 400 and json.loads(payload)["error"] == "target: not a directory"
    r, payload = post(port, token, "/api/demo", {"scenario": "../../etc"})
    assert r.status == 400


def test_folder_browser_lists_directories_only(gui):
    _, port, token = gui
    r, payload = req(port, "GET", "/api/fs?path=" + str(SAME).replace("\\", "/"), headers=auth(token))
    d = json.loads(payload)
    assert r.status == 200 and d["dirs"] == ["baseline", "candidate", "fixed"]
