"""Hostile-repository and malformed-input tests. The scanner must never execute scanned code."""

import io
import json
import os
import tarfile

import pytest

from agentic_bom.core import safety
from agentic_bom.core.safety import UnsafeInputError, safe_extract_tar, validate_github_url
from agentic_bom.exporters.writer import write_scan
from agentic_bom.scanner import scan


def test_never_executes_scanned_code(make_project, tmp_path):
    marker = tmp_path / "PWNED"
    payload = f"open({str(marker)!r}, 'w').write('x')\n"
    root = make_project({
        "setup.py": payload,
        "conftest.py": payload,
        "app.py": payload + "from agents import Agent\nA = Agent(name='a', instructions='s')\n",
        "pkg/__init__.py": payload,
        "nb.ipynb": "{}",
    })
    r = scan(root)
    assert not marker.exists()
    assert r["summary"]["agents"] == 1


def test_malformed_and_binary_files_are_reported_not_fatal(make_project):
    root = make_project({
        "bad.py": "def broken(:\n",
        "bin.py": b"\x00\x01\x02binary",
        "deep.py": "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n",
        "ok.py": "from agents import Agent\nA = Agent(name='ok', instructions='s')\n",
        "mcp.json": "{not json",
    })
    r = scan(root)
    errs = {e["file"] for e in r["coverage"]["parse_errors"]}
    assert "bad.py" in errs and "deep.py" in errs
    assert r["coverage"]["unreadable_files"] == ["bin.py"]
    assert r["coverage"]["config_errors"][0]["file"] == "mcp.json"
    assert r["summary"]["agents"] == 1


def test_large_files_skipped(make_project, monkeypatch):
    monkeypatch.setattr(safety, "MAX_FILE_BYTES", 100)
    root = make_project({"big.py": "x = 1\n" * 100, "small.py": "y = 2\n"})
    r = scan(root)
    assert r["coverage"]["skipped_large_files"] == ["big.py"]


def test_symlinks_are_not_followed(make_project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("from agents import Agent\nA = Agent(name='outside', instructions='s')\n", encoding="utf-8")
    root = make_project({"app.py": "VERSION = 1\n"})
    try:
        os.symlink(outside, root / "linkdir", target_is_directory=True)
        os.symlink(outside / "secret.py", root / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    r = scan(root)
    assert r["summary"]["agents"] == 0
    assert set(r["coverage"]["skipped_symlinks"]) == {"linkdir", "link.py"}


def test_prompt_bodies_and_secrets_are_not_written(make_project, tmp_path):
    secret = "sk-proj-THISISASECRETKEYVALUE1234567890"
    root = make_project({
        "app.py": (
            "import os\nfrom agents import Agent, function_tool\n"
            f"SYSTEM = 'Top secret system prompt body. key={secret}'\n"
            "@function_tool\ndef t(p: str) -> str:\n"
            f"    '''Tool doc with {secret}'''\n"
            f"    return os.getenv('OPENAI_API_KEY', '{secret}')\n"
            "A = Agent(name='a', instructions=SYSTEM, tools=[t])\n"
        ),
        ".mcp.json": json.dumps({"mcpServers": {"s": {"command": "node", "args": ["x.js", f"--token={secret}"], "env": {"K": "env-secret-value"}}}}),
    })
    files = write_scan(scan(root), tmp_path / "out")
    blob = "".join(p.read_text(encoding="utf-8") for p in files.values())
    assert secret not in blob
    assert "Top secret system prompt body" not in blob
    assert "env-secret-value" not in blob


def test_html_report_escapes_hostile_names(make_project, tmp_path):
    evil = "</script><img src=x onerror=alert(1)>"
    root = make_project({"app.py": f"from agents import Agent, function_tool\n@function_tool(name_override={evil!r})\ndef t(p: str) -> str:\n    return p\nA = Agent(name={evil!r}, instructions='s', tools=[t])\n"})
    files = write_scan(scan(root), tmp_path / "out")
    html = files["html"].read_text(encoding="utf-8")
    assert evil not in html and "<img src=x" not in html
    assert html.count("</script>") == 2  # only our own two script blocks


@pytest.mark.parametrize("url", [
    "http://github.com/a/b",
    "https://gitlab.com/a/b",
    "https://github.com.evil.com/a/b",
    "https://github.com/a/b/../../c",
    "https://github.com/a",
    "file:///etc/passwd",
    "--upload-pack=touch /tmp/x",
    "https://user:pw@github.com/a/b",
    "https://github.com/../b",
])
def test_github_url_allowlist(url):
    with pytest.raises(UnsafeInputError):
        validate_github_url(url)


def test_github_url_normalised():
    assert validate_github_url("https://github.com/openai/openai-agents-python") == "https://github.com/openai/openai-agents-python.git"


@pytest.mark.parametrize("ref", ["--output=/tmp/x", "a..b", "x;rm -rf", "$(id)"])
def test_git_ref_validation(ref, tmp_path):
    with pytest.raises(UnsafeInputError):
        safety.export_git_revision(tmp_path, ref)


def test_tar_extraction_blocks_traversal_and_links(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in (("ok.py", b"x=1\n"), ("../evil.py", b"bad"), ("/abs.py", b"bad")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    buf.seek(0)
    dest = tmp_path / "dest"
    dest.mkdir()
    safe_extract_tar(buf, dest)
    assert sorted(p.name for p in dest.rglob("*")) == ["ok.py"]
    assert not (tmp_path / "evil.py").exists()
