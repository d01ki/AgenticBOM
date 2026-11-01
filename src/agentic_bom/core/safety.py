"""Read-only, bounded repository access. Nothing here executes scanned code."""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MAX_DEPTH = 30
CLONE_TIMEOUT_S = 180

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "site-packages",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".eggs",
}
TEST_DIRS = {"tests", "test", "testing", "__tests__"}

ALLOWED_GIT_HOSTS = {"github.com"}
_GITHUB_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.\-]{1,100})/([A-Za-z0-9_.\-]{1,100}?)(?:\.git)?/?$")
# branch/tag/sha plus ~N / ^N suffixes; leading "-" and ".." are rejected separately
_GIT_REV = re.compile(r"^[A-Za-z0-9_.\-/~^]{1,100}$")


class UnsafeInputError(ValueError):
    pass


@dataclass
class WalkResult:
    files: list[Path] = field(default_factory=list)
    skipped_large: list[str] = field(default_factory=list)
    skipped_symlinks: list[str] = field(default_factory=list)
    excluded_tests: list[str] = field(default_factory=list)
    truncated: bool = False
    other_language_files: dict[str, int] = field(default_factory=dict)


def is_test_path(rel: Path) -> bool:
    parts = rel.parts
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    name = parts[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def safe_walk(root: Path, include_tests: bool = False, suffixes: tuple[str, ...] = (".py", ".json")) -> WalkResult:
    """Walk ``root`` without following symlinks or leaving the root."""
    root = root.resolve()
    res = WalkResult()
    other_lang = {".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".mjs": "javascript", ".go": "go", ".java": "java"}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        rel_dir = dp.relative_to(root)
        if len(rel_dir.parts) > MAX_DEPTH:
            dirnames[:] = []
            continue
        keep = []
        for d in sorted(dirnames):
            full = dp / d
            if d in SKIP_DIRS or d.endswith(".egg-info"):
                continue
            if full.is_symlink():
                res.skipped_symlinks.append((rel_dir / d).as_posix())
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            full = dp / fn
            rel = rel_dir / fn
            if full.is_symlink():
                res.skipped_symlinks.append(rel.as_posix())
                continue
            suffix = full.suffix.lower()
            if suffix in other_lang:
                lang = other_lang[suffix]
                res.other_language_files[lang] = res.other_language_files.get(lang, 0) + 1
            if suffix not in suffixes and fn not in ("requirements.txt", "pyproject.toml"):
                if not (fn.startswith("requirements") and fn.endswith(".txt")):
                    continue
            try:
                resolved = full.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError):
                res.skipped_symlinks.append(rel.as_posix())
                continue
            if not include_tests and suffix == ".py" and is_test_path(rel):
                res.excluded_tests.append(rel.as_posix())
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                res.skipped_large.append(rel.as_posix())
                continue
            if len(res.files) >= MAX_FILES:
                res.truncated = True
                return res
            res.files.append(full)
    return res


def read_text(path: Path) -> str:
    with open(path, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    if b"\x00" in data[:8192]:
        raise ValueError("binary file")
    return data.decode("utf-8", errors="replace")


def validate_github_url(url: str) -> str:
    m = _GITHUB_URL.match(url.strip())
    if not m:
        raise UnsafeInputError(
            "only https://github.com/<owner>/<repo> URLs are accepted (host allowlist: "
            + ", ".join(sorted(ALLOWED_GIT_HOSTS))
            + ")"
        )
    owner, repo = m.group(1), m.group(2)
    if owner.startswith(".") or repo.startswith(".") or ".." in owner or ".." in repo:
        raise UnsafeInputError("invalid owner/repo")
    return f"https://github.com/{owner}/{repo}.git"


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ASKPASS": "",
        }
    )
    return env


_GIT_SAFE_CONFIG = [
    "-c", "core.symlinks=false",
    "-c", "core.hooksPath=" + os.devnull,
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "http.followRedirects=false",
    "-c", "submodule.recurse=false",
    "-c", "core.fsmonitor=false",
]


def shallow_clone(url: str, ref: str | None = None) -> Path:
    """Shallow-clone a validated GitHub URL into a fresh temp dir (no checkout hooks, no submodules)."""
    safe_url = validate_github_url(url)
    if ref is not None and not _GIT_REV.match(ref):
        raise UnsafeInputError("invalid git ref")
    if ref is not None and (ref.startswith("-") or ".." in ref):
        raise UnsafeInputError("invalid git ref")
    dest = Path(tempfile.mkdtemp(prefix="aem-clone-"))
    target = dest / "repo"
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git executable not found")
    if ref and re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        subprocess.run([git, *_GIT_SAFE_CONFIG, "init", "-q", str(target)], check=True, env=_git_env(), timeout=CLONE_TIMEOUT_S)
        subprocess.run([git, *_GIT_SAFE_CONFIG, "-C", str(target), "fetch", "-q", "--depth", "1", "--no-recurse-submodules", safe_url, ref],
                       check=True, env=_git_env(), timeout=CLONE_TIMEOUT_S)
        subprocess.run([git, *_GIT_SAFE_CONFIG, "-C", str(target), "checkout", "-q", "FETCH_HEAD"], check=True, env=_git_env(), timeout=CLONE_TIMEOUT_S)
    else:
        cmd = [git, *_GIT_SAFE_CONFIG, "clone", "-q", "--depth", "1", "--no-recurse-submodules", "--single-branch"]
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", safe_url, str(target)]
        subprocess.run(cmd, check=True, env=_git_env(), timeout=CLONE_TIMEOUT_S)
    return target


def export_git_revision(repo: Path, rev: str) -> Path:
    """Export ``rev`` of a local git repo into a temp dir via ``git archive`` with safe extraction."""
    if not _GIT_REV.match(rev) or rev.startswith("-") or ".." in rev:
        raise UnsafeInputError("invalid git revision")
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git executable not found")
    proc = subprocess.run(
        [git, *_GIT_SAFE_CONFIG, "-C", str(repo), "archive", "--format=tar", rev],
        check=True,
        capture_output=True,
        env=_git_env(),
        timeout=CLONE_TIMEOUT_S,
    )
    dest = Path(tempfile.mkdtemp(prefix=f"aem-rev-"))
    safe_extract_tar(io.BytesIO(proc.stdout), dest)
    return dest


def safe_extract_tar(fileobj: io.BytesIO, dest: Path) -> None:
    dest = dest.resolve()
    with tarfile.open(fileobj=fileobj, mode="r:") as tf:
        for m in tf.getmembers():
            name = m.name
            if name.startswith(("/", "\\")) or ".." in Path(name).parts or ":" in name:
                continue
            if not (m.isfile() or m.isdir()):
                continue  # skip symlinks, hardlinks, devices
            if m.isfile() and m.size > MAX_FILE_BYTES * 5:
                continue
            target = (dest / name).resolve()
            try:
                target.relative_to(dest)
            except ValueError:
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out)
