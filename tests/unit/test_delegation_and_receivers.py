from agentic_bom.scanner import scan

from ..conftest import REPO, paths_by

CASES = REPO / "benchmark" / "cases"


def test_handoff_and_as_tool_propagate_paths_conservatively():
    r = scan(CASES / "delegation")
    delegated = [p for p in r["paths"] if p["delegation"]]
    assert {(p["delegation"][0], p["tool_name"]) for p in delegated} == {("ops", "restart"), ("writer", "save")}
    for p in delegated:
        assert p["entry_name"] == "triage" and p["classification"] == "potentially_exposed"
        assert p["resolution"] == "inferred_limited"  # never CI-gate eligible on its own
        assert any("delegation" in u for u in p["unknowns"])
    modes = {e["attributes"]["mode"] for e in r["graph"]["edges"] if e["type"] == "DELEGATES_TO"}
    assert modes == {"handoff", "as_tool"}


def test_delegation_diamond_is_deduplicated_and_bounded(make_project):
    # c -> {b, a}, b -> a, d -> c: each agent reaches rm once, via its shortest delegation chain, max 2 hops
    src = (
        "import os\nfrom agents import Agent, function_tool\n"
        "@function_tool\ndef rm(p: str) -> str:\n    os.remove(p)\n    return 'x'\n"
        "a = Agent(name='a', instructions='s', tools=[rm])\n"
        "b = Agent(name='b', instructions='s', handoffs=[a])\n"
        "c = Agent(name='c', instructions='s', handoffs=[b, a])\n"
        "d = Agent(name='d', instructions='s', handoffs=[c])\n"
        "e = Agent(name='e', instructions='s', handoffs=[d])\n"
    )
    r = scan(make_project({"app.py": src}))
    got = sorted((p["entry_name"], tuple(p["delegation"])) for p in r["paths"])
    assert got == [("a", ()), ("b", ("a",)), ("c", ("a",)), ("d", ("c", "a"))]  # e is 3 hops away -> not followed


def test_unresolved_as_tool_is_unknown(make_project):
    src = "from agents import Agent\ndef pick():\n    return None\nA = Agent(name='a', instructions='s', tools=[pick().as_tool(tool_name='x', tool_description='y')])\n"
    r = scan(make_project({"app.py": src}))
    assert [p["classification"] for p in r["paths"]] == ["unknown"]


def test_library_tools_are_modelled_as_inferred():
    r = scan(CASES / "library-tools")
    assert {(p["tool_name"], p["operation_category"]) for p in r["paths"]} == {("ShellTool", "process_execution"), ("WriteFileTool", "filesystem_write")}
    assert all(p["resolution"] == "inferred_limited" for p in r["paths"])


def test_class_method_receivers_are_followed():
    r = scan(CASES / "class-receiver")
    got = {(p["tool_name"], p["operation_callee"], p["classification"]) for p in r["paths"]}
    assert got == {("remove_export", "boto3.s3.delete_object", "operation_path"), ("purge_dir", "shutil.rmtree", "operation_path")}
    purge = paths_by(r, tool_name="purge_dir")[0]
    assert [v["callee"].split(":")[1] for v in purge["via"]] == ["Storage.purge", "Storage._wipe"]
