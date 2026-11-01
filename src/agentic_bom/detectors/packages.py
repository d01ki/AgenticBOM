"""Dependency manifest parsing (requirements*.txt, pyproject.toml) without executing anything."""

from __future__ import annotations

import re
from dataclasses import dataclass

# distribution name -> import name, where they differ
IMPORT_NAMES = {
    "openai-agents": "agents",
    "langchain-core": "langchain_core",
    "langchain-community": "langchain_community",
    "langchain-openai": "langchain_openai",
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "python-dotenv": "dotenv",
    "scikit-learn": "sklearn",
    "pillow": "PIL",
    "mcp": "mcp",
}
AI_PACKAGES_NPM = {"@openai/agents", "@openai/agents-core", "ai", "@ai-sdk/openai", "@ai-sdk/anthropic", "@modelcontextprotocol/sdk",
                   "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "@langchain/langgraph", "fastmcp"}
AI_PACKAGES = AI_PACKAGES_NPM | {"openai-agents", "openai", "anthropic", "mcp", "fastmcp", "langchain", "langchain-core", "langgraph", "langchain-openai", "crewai", "autogen", "llama-index"}

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*([<>=!~]=?[^;#\s]*(?:\s*,\s*[<>=!~]=?[^;#\s]*)*)?")


@dataclass(frozen=True)
class PackageRef:
    name: str
    version_spec: str
    file: str
    line: int
    ecosystem: str = "pypi"

    @property
    def import_name(self) -> str:
        return IMPORT_NAMES.get(self.name, self.name.replace("-", "_"))


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(relpath: str, text: str) -> list[PackageRef]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:")):
            continue
        m = _REQ.match(line)
        if m:
            out.append(PackageRef(normalize(m.group(1)), (m.group(3) or "").replace(" ", ""), relpath, i))
    return out


def parse_pyproject(relpath: str, text: str) -> list[PackageRef]:
    out: list[PackageRef] = []
    lines = text.splitlines()
    in_deps = False
    in_poetry = False
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s.startswith("["):
            in_poetry = s == "[tool.poetry.dependencies]"
            in_deps = False
        if re.match(r"^dependencies\s*=\s*\[", s):
            in_deps = True
            s = s.split("[", 1)[1]
        if in_deps:
            for q in re.findall(r"['\"]([^'\"]+)['\"]", s):
                m = _REQ.match(q)
                if m:
                    out.append(PackageRef(normalize(m.group(1)), (m.group(3) or "").replace(" ", ""), relpath, i))
            if "]" in s:
                in_deps = False
            continue
        if in_poetry and "=" in s and not s.startswith("#"):
            k, v = s.split("=", 1)
            k = k.strip().strip('"')
            if k and k != "python":
                ver = re.findall(r"['\"]([^'\"]*)['\"]", v)
                out.append(PackageRef(normalize(k), ver[0] if ver else "", relpath, i))
    return out


def parse_package_json(relpath: str, text: str) -> list[PackageRef]:
    """npm dependencies (runtime + dev). Names are kept verbatim (scoped packages included)."""
    import json

    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    out = []
    lines = text.splitlines()
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, ver in sorted(deps.items()):
            if not isinstance(name, str):
                continue
            line = next((i for i, ln in enumerate(lines, 1) if f'"{name}"' in ln), 1)
            out.append(PackageRef(name[:120], str(ver)[:60] if isinstance(ver, str) else "", relpath, line, "npm"))
    return out
