from agentic_bom.detectors.mcp import parse_mcp_config
from agentic_bom.detectors.packages import parse_pyproject, parse_requirements
from agentic_bom.detectors.python import ProjectIndex, const_str, detect_tools


def _index(files):
    idx = ProjectIndex(root=None)
    for rel, src in files.items():
        idx.add_source(rel, src)
    return idx


def test_detects_supported_tool_decorators_and_wrappers():
    idx = _index({
        "t.py": (
            "from agents import function_tool\n"
            "from langchain_core.tools import tool\n"
            "from mcp.server.fastmcp import FastMCP\n"
            "srv = FastMCP('s')\n"
            "@function_tool\ndef a(x: str) -> str:\n    '''doc a'''\n    return x\n"
            "@function_tool(name_override='bee')\ndef b(x: str) -> str:\n    return x\n"
            "@tool\ndef c(x: str) -> str:\n    return x\n"
            "@srv.tool()\ndef d(x: str) -> str:\n    return x\n"
            "def e(x: str) -> str:\n    return x\n"
            "wrapped = function_tool(e)\n"
            "def not_a_tool(x):\n    return x\n"
        )
    })
    tools = detect_tools(idx)
    names = {t.name: t.framework for t in tools.values()}
    assert names == {"a": "openai-agents", "bee": "openai-agents", "c": "langchain", "d": "mcp-fastmcp", "e": "openai-agents"}
    a = tools["tool:t.py:a"]
    assert a.contract["description"] == "doc a"
    assert a.contract["parameters"] == [{"name": "x", "annotation": "str", "required": True}]


def test_relative_import_and_reexport_resolution():
    idx = _index({
        "pkg/__init__.py": "from .impl import helper\n",
        "pkg/impl.py": "def helper(x):\n    return x\n",
        "pkg/user.py": "from . import impl\nfrom pkg import helper as h\n",
    })
    user = idx.modules["pkg.user"]
    assert user.imports["impl"] == ("pkg", "impl")
    found = idx.lookup_function("pkg.helper")
    assert found is not None and found[2] == "helper" and found[0].relpath == "pkg/impl.py"
    assert idx.lookup_function(idx.qualname(user, __import__("ast").parse("h").body[0].value))[2] == "helper"


def test_const_str_follows_module_constants_and_fstrings():
    idx = _index({"m.py": "A = 'x'\nB = A + 'y'\nC = f'{B}-z'\nD = f'{unknown}'\n"})
    m = idx.modules["m"]
    assert const_str(m, m.module_assigns["C"]) == "xy-z"
    assert const_str(m, m.module_assigns["D"]) is None


def test_parse_errors_are_recorded_not_raised():
    idx = _index({"bad.py": "def (:\n"})
    assert idx.parse_errors == [{"file": "bad.py", "error": "SyntaxError"}]


def test_manifests():
    reqs = parse_requirements("requirements.txt", "openai-agents==0.3.3\n# c\n-e .\nrequests>=2,<3 ; python_version>'3'\n")
    assert [(p.name, p.version_spec) for p in reqs] == [("openai-agents", "==0.3.3"), ("requests", ">=2,<3")]
    pp = parse_pyproject("pyproject.toml", '[project]\ndependencies = [\n  "mcp>=1.0",\n  "httpx",\n]\n')
    assert [p.name for p in pp] == ["mcp", "httpx"]


def test_mcp_config_never_stores_env_values():
    servers, err = parse_mcp_config(".mcp.json", '{"mcpServers": {"x": {"command": "python", "args": ["s.py"], "env": {"TOKEN": "secret-value"}}}}')
    assert err is None and servers[0].env_keys == ["TOKEN"] and servers[0].server_file == "s.py"
    assert "secret-value" not in repr(servers)
