import pytest

from agentic_bom.scanner import scan

TOOL_HDR = "import os, re, subprocess\nfrom agents import Agent, function_tool\n"


def _single_path(make_project, body: str, instructions: str = "'static'", prelude: str = ""):
    src = TOOL_HDR + prelude + "@function_tool\ndef t(p: str) -> str:\n" + body + f"\nA = Agent(name='a', instructions={instructions}, tools=[t])\n"
    r = scan(make_project({"app.py": src}))
    assert len(r["paths"]) == 1, r["paths"]
    return r["paths"][0]


@pytest.mark.parametrize("body,guard", [
    ("    if p not in {'a', 'b'}:\n        return 'no'\n    os.remove(p)\n    return 'ok'\n", "known"),
    ("    if p in ALLOWED:\n        os.remove(p)\n    return 'ok'\n", "known"),
    ("    if not p.isalnum():\n        raise ValueError\n    os.remove(p)\n    return 'ok'\n", "known"),
    ("    if not re.fullmatch(r'[a-z]+', p):\n        raise ValueError\n    os.remove(p)\n    return 'ok'\n", "known"),
    ("    if not validate(p):\n        raise ValueError\n    os.remove(p)\n    return 'ok'\n", "unknown"),
    ("    os.remove(p)\n    return 'ok'\n", "absent"),
    ("    if p in ALLOWED:\n        pass\n    os.remove(p)\n    return 'ok'\n", "absent"),
])
def test_guard_recognition(make_project, body, guard):
    p = _single_path(make_project, body, prelude="ALLOWED = {'x'}\ndef validate(v):\n    return True\n")
    assert p["guard_status"] == guard


def test_constant_command_is_bound_capability_not_operation_path(make_project):
    p = _single_path(make_project, "    subprocess.run(['git', 'status'])\n    return p\n")
    assert p["classification"] == "bound_capability" and p["operation_target"] == "git status"


def test_constant_lookup_with_tainted_key_is_not_param_controlled(make_project):
    p = _single_path(make_project, "    subprocess.run(CMDS[p])\n    return 'x'\n", prelude="CMDS = {'up': ['uptime']}\n")
    assert p["classification"] == "bound_capability"


def test_int_cleanser_drops_taint(make_project):
    p = _single_path(make_project, "    n = int(p)\n    subprocess.run(['sleep', str(n)])\n    return 'x'\n")
    assert p["classification"] == "bound_capability"


def test_fstring_propagates_taint_and_shell_flag(make_project):
    p = _single_path(make_project, "    subprocess.run(f'ping {p}', shell=True)\n    return 'x'\n")
    assert p["classification"] == "operation_path" and p["controlling_params"] == ["p"]


def test_untrusted_instructions_make_path_potentially_exposed(make_project):
    src = TOOL_HDR + "import sys\n@function_tool\ndef t(p: str) -> str:\n    os.remove(p)\n    return 'x'\n" \
        "def main():\n    note = sys.stdin.read()\n    Agent(name='a', instructions='hi ' + note, tools=[t])\n"
    r = scan(make_project({"app.py": src}))
    assert [p["classification"] for p in r["paths"]] == ["potentially_exposed"]
    assert r["paths"][0]["untrusted_sources"] == ["stdin"]


def test_user_role_input_alone_is_not_potentially_exposed(make_project):
    src = TOOL_HDR + "import sys\nfrom agents import Runner\n@function_tool\ndef t(p: str) -> str:\n    os.remove(p)\n    return 'x'\n" \
        "def main():\n    a = Agent(name='a', instructions='static', tools=[t])\n    Runner.run_sync(a, sys.stdin.read())\n"
    r = scan(make_project({"app.py": src}))
    p = r["paths"][0]
    assert p["classification"] == "operation_path" and p["user_role_untrusted_input"] is True


def test_parameter_provenance_without_callers_is_unknown(make_project):
    src = TOOL_HDR + "@function_tool\ndef t(p: str) -> str:\n    os.remove(p)\n    return 'x'\n" \
        "def build(text):\n    return Agent(name='a', instructions=text, tools=[t])\n"
    r = scan(make_project({"app.py": src}))
    agent = next(n for n in r["graph"]["nodes"] if n["kind"] == "agent")
    assert agent["attributes"]["instructions_provenance"] == "unknown"
    assert r["paths"][0]["resolution"] == "inferred_limited"


def test_content_only_param_does_not_control_target(make_project):
    p = _single_path(make_project, "    open('/var/log/app.log', 'a').write(p)\n    return 'x'\n")
    assert p["classification"] == "bound_capability" and p["operation_target"] == "/var/log/app.log"


def test_secret_env_names_recorded_without_values(make_project):
    p = _single_path(make_project, "    return os.environ['API_TOKEN'] + p\n")
    assert p["operation_category"] == "secret_access" and p["operation_target"] == "API_TOKEN"
