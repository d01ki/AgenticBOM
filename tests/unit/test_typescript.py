"""TypeScript/JavaScript parser and analyzer behaviour."""

import pytest

from agentic_bom.analyzers.drift import diff_reports
from agentic_bom.detectors.ts_parser import parse, tokenize
from agentic_bom.scanner import scan

from ..conftest import EXAMPLES, REPO, paths_by

TSDEMO = EXAMPLES / "ts-same-bom-new-exposure"
CASES = REPO / "benchmark" / "cases"


def kinds(src):
    return [s["k"] for s in parse(src).body]


def test_parser_skips_type_syntax_and_keeps_structure():
    src = """
    import type { A } from './a';
    interface I { x: string }
    type T<U> = { u: U } | null;
    export enum E { A, B }
    declare const g: any;
    abstract class C<T> extends B implements I { private x = 1; m(a: string): void {} }
    export const f = async <T,>(a: T): Promise<T> => a as unknown as T;
    let y = cond ? a < b : foo<number>(1)!;
    """
    assert kinds(src) == ["Import", "Class", "Var", "Var"]
    assert parse(src).skipped_regions == 0


def test_tokenizer_strings_templates_regex_comments():
    toks = tokenize("const s = 'a\\'b'; const r = /x\\/y/g; // c\n/* d */ const t = `x${1 + `y${2}`}z`;")
    vals = [(t.k, t.v) for t in toks if t.k in ("str", "re")]
    assert vals == [("str", "a'b"), ("re", "/x\\/y/g")]
    assert sum(1 for t in toks if t.k == "tpl") == 1


@pytest.mark.parametrize("src", [
    "x = " + "(" * 3000 + "1" + ")" * 3000,
    "const a = `" + "${`" * 400 + "x" + "`}" * 400 + "`",
    "const s = 'unterminated\nconst t = 1",
    "function f( { [",
    "}}}}} ))) ]]] const ok = 1;",
    "\x00\x01 const a = 1",
])
def test_parser_never_crashes_on_hostile_input(src):
    try:
        parse(src)
    except Exception as exc:  # only our declared failure modes may escape
        assert type(exc).__name__ in ("ParseError", "RecursionError")


def test_ts_demo_three_revisions():
    r = {v: scan(TSDEMO / v, label="ts") for v in ("baseline", "candidate", "fixed")}
    assert r["baseline"]["paths"] == []
    cand = r["candidate"]["paths"]
    assert [(p["classification"], p["operation_callee"], p["untrusted_sources"]) for p in cand] == [("potentially_exposed", "child_process.exec", ["stdin"])]
    assert [v["callee"] for v in cand[0]["via"]] == ["src/diagnostics.ts:healthCheck"]
    fixed = r["fixed"]["paths"]
    assert [(p["classification"], p["guard_status"]) for p in fixed] == [("operation_path", "known")]
    d1 = diff_reports(r["baseline"], r["candidate"])
    assert d1["banner"] == "Agentic BOM unchanged · 1 new potential exposure path"
    d2 = diff_reports(r["candidate"], r["fixed"])
    assert {f["kind"] for f in d2["findings"]} == {"capability_removed"}  # exec -> execFile matched as the same capability slot
    assert any(u["function"] == "restartService" for u in r["baseline"]["coverage"]["unreached_sensitive_operations"])


def test_vercel_next_route_and_hosted_tool():
    r = scan(CASES / "ts-vercel-next")
    p = r["paths"]
    assert [(x["entry_name"], x["tool_name"], x["classification"], x["controlling_params"], x["content_params"]) for x in p] == \
        [("generateText in POST", "saveDraft", "potentially_exposed", ["path"], ["content"])]
    hosted = [n for n in r["graph"]["nodes"] if n["kind"] == "tool" and n["attributes"].get("framework") == "provider-hosted"]
    assert len(hosted) == 1


def test_mcp_ts_server_guard_and_binding():
    r = scan(CASES / "ts-mcp-server")
    got = {(p["entry_kind"], p["operation_callee"], p["guard_status"], p["resolution"]) for p in r["paths"]}
    assert ("mcp_server", "fs.writeFile", "known", "confirmed_static") in got
    assert ("mcp_server", "fetch", "absent", "confirmed_static") in got
    assert ("agent", "fetch", "absent", "inferred_limited") in got  # MCPServerStdio args -> server.ts


def test_express_class_receiver_and_handoff():
    r = scan(CASES / "ts-express-handoff")
    pe = paths_by(r, classification="potentially_exposed")
    assert [(p["tool_name"], p["operation_callee"], p["controlling_params"]) for p in pe] == [("cleanup_export", "aws-sdk.DeleteObjectCommand", ["key"])]
    deleg = [p for p in r["paths"] if p["delegation"]]
    assert [(p["delegation"], p["guard_kind"], p["resolution"]) for p in deleg] == [(["ops"], "human_approval", "inferred_limited")]


def test_ts_negative_controls():
    r = scan(CASES / "ts-negative")
    assert sorted((p["tool_name"], p["classification"]) for p in r["paths"]) == [
        ("git_status", "bound_capability"), ("run_action", "unknown"), ("wipe", "inventory_only")]
    assert r["coverage"]["excluded_test_files"] == ["src/__tests__/agent.test.ts"]


def test_validator_helper_makes_guard_unknown_not_absent(make_project):
    src = """
    import { tool, Agent } from '@openai/agents';
    import { writeFileSync } from 'fs';
    import { z } from 'zod';
    function safePath(p: string): string {
      if (!p.startsWith('/data/')) { throw new Error('outside'); }
      return p;
    }
    const save = tool({ name: 'save', description: 'd', parameters: z.object({ p: z.string() }),
      execute: async ({ p }) => { writeFileSync(safePath(p), 'x'); return 'ok'; } });
    export const a = new Agent({ name: 'a', instructions: 's', tools: [save] });
    """
    p = scan(make_project({"a.ts": src}))["paths"][0]
    assert (p["classification"], p["guard_status"]) == ("operation_path", "unknown")


def test_generate_text_without_tools_is_not_an_agent(make_project):
    src = "import { generateText } from 'ai';\nexport async function f(q: string) { return generateText({ model: 'm', prompt: q }); }\n"
    assert scan(make_project({"a.ts": src}))["summary"]["agents"] == 0


def test_js_container_shell_tool_is_hosted(make_project):
    src = """
    import { Agent, shellTool } from '@openai/agents';
    export const a = new Agent({ name: 'a', instructions: 's', tools: [shellTool({ environment: { type: 'container_auto' } })] });
    export const b = new Agent({ name: 'b', instructions: 's', tools: [shellTool({ shell, needsApproval: true })] });
    """
    r = scan(make_project({"a.ts": src}))
    assert [(p["entry_name"], p["guard_kind"]) for p in r["paths"]] == [("b", "human_approval")]
