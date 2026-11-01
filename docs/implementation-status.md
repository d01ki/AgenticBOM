# Implementation status (v0.1.0, 2026-11-01)

Environment: Windows 11, Python 3.10.11, pytest 9.1.1, jsonschema available (the built-in validator also runs). The runtime has no third-party dependencies.

## P0 checklist (design §14)

| # | Item | Status |
|---|---|---|
| 1 | New repo, CLI, packaging, licence and attribution | ✅ `pyproject.toml`, the `agentic-bom` entry point (verified with `pip install -e .` in a clean venv), Apache-2.0, `NOTICE.md`. **No AIBOM Inspector code reused** because it was not available in the workspace. A discovery adapter was therefore not built. |
| 2 | Graph and evidence schema, JSON output, schema validation | ✅ `core/models.py`, 3 JSON Schemas; every write is validated |
| 3 | Explicit bindings and sensitive-operation recognition | ✅ Python: OpenAI Agents SDK, FastMCP/MCPServer, LangChain/LangGraph |
| 4 | Deterministic capability paths and unknown handling | ✅ |
| 5 | Baseline/candidate semantic diff and SARIF gate | ✅ directories or `--git` revisions, `--fail-on` |
| 6 | Three-phase bundled demo and negative controls | ✅ 2 scenarios × 3 revisions, 6 negative/unknown controls |
| 7 | Basic graph UI and evidence drawer | ✅ self-contained HTML. Rendered in headless Chrome with 0 JS errors. |
| 8 | Tests and recorded outputs; limitations documented | ✅ see below |

## Acceptance gates (design §15)

| Gate | Result | Evidence |
|---|---|---|
| `scan` emits a validated BOM, graph and evidence | ✅ | `test_scan_emits_validated_bom_graph_and_evidence` |
| An unbound sensitive function is not treated as a capability | ✅ | `restart_service` and `purge` appear only under `unreached_sensitive_operations`; `wipe_cache` → `inventory_only` |
| A same-component pair yields a new, well-supported path | ✅ | `bom_delta=unchanged`, AEM-D001 and AEM-D002 at `high`, evidence `app.py:19/26/27`, `diagnostics.py:10` |
| The fixed revision removes the path with no invented claim | ✅ | only `capability_removed`; gate passes |
| Unsupported or dynamic code gives `unknown` | ✅ | `dynamic-dispatch`, `unsupported-guard` |
| Tests pass and output is reproducible | ✅ | 65 passed, 1 skipped; byte-identical outputs across runs |
| A small external pinned corpus is evaluated, with honest limits | ⚠️ partial | 2 repos scanned at pinned SHAs and spot-checked; **no full ground truth** (see below) |
| README explains novelty, prior art, supported matrix and the one-command demo | ✅ | `README.md`, `docs/novelty-positioning.md` |

## Test run (actual output)

```
$ python -m pytest -q
65 passed, 1 skipped in ~5s
```

The skipped test is `test_symlinks_are_not_followed`: creating symlinks needs elevated rights on this Windows account. The test still needs to run on Linux CI.

## Bundled benchmark (actual output, `agentic-bom benchmark run`)

| Category | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| agents | 13 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| tools | 21 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| bindings | 20 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| paths | 13 | 0 | 1 | 1.00 | 0.93 | 0.96 |
| drift_findings | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |

Expected-unknown constructs reported as `unknown`: 4 / 4. Median case time is about 0.02 s.

**Read with care.** These are 13 scan and 5 drift cases. The tool author wrote the fixtures and annotated them, so the numbers show designed behaviour, not ecosystem accuracy. The one FN is deliberate: `helper-chain-depth/write_deep` reaches `open(..., 'a')` after 4 hops, which is beyond the 3-hop budget. AEM reports it as `unknown`, and strict scoring counts it as a miss.

## External pinned repositories (spot check, no ground truth)

| Repo | SHA | Py files | Excluded tests | Agents | Tools | MCP servers | Paths | Time |
|---|---|---|---|---|---|---|---|---|
| openai/openai-agents-python | `e355d69152d4f4730dfb03b63dbce53e8d9f5d8c` | 562 | 468 | 155 (151 named) | 100 | 16 | 1 bound_capability, 53 unknown | 11.6 s |
| modelcontextprotocol/python-sdk | `d7845c073a2b9ba5ab2817ecf93d3e45ef24cd14` | 585 | 285 | 0 | 126 | 84 | 6 unknown | 3.9 s |

Observations from the spot check:

- **False negative found and fixed.** The first scan of `python-sdk` found 0 MCP servers. At this SHA the SDK has renamed `FastMCP` to `mcp.server.mcpserver.MCPServer`. That constructor is now recognised and the re-scan finds 126 tools and 84 servers. This shows how much detection depends on framework API versions; matching on API names needs regression fixtures per SDK version.
- In `openai-agents-python`, unknown paths break down as: 26 library or hosted tool instances (`WebSearchTool`, `HostedMCPTool`, …), 11 `agent.as_tool()`, 10 MCP servers outside the repo, 4 dynamic tool lists, and 2 unsupported or unresolved references. These are mostly inherent to example code that uses hosted tools.
- A grep of example files that contain both `function_tool` and common sink APIs found one candidate (`examples/mcp/get_all_mcp_tools_example/main.py`). That file uses MCP and has no local sink, so no obvious false negative was seen. **This is not a recall measurement.**
- The `python-sdk` unknowns are all `helper chain exceeds 3 hops`. The cause is tool helpers that call into the SDK's own vendored internals. This is a noise source on repos that contain a framework.
- No `potentially_exposed` path was reported on either repo. The spot check found no reason to doubt this, but without annotation it says nothing about precision or recall.

Reproduce:

```bash
agentic-bom scan https://github.com/openai/openai-agents-python --ref e355d69152d4f4730dfb03b63dbce53e8d9f5d8c --out out/ext/oa
agentic-bom scan https://github.com/modelcontextprotocol/python-sdk --ref d7845c073a2b9ba5ab2817ecf93d3e45ef24cd14 --out out/ext/sdk
```

## Defects found during implementation (kept for transparency)

1. **The HTML JSON escaping was a no-op.** The `<`/`>`/`&` escape table was mangled into identity mappings, so a repo-controlled agent name containing `</script>` could break out of the JSON island. `test_html_report_escapes_hostile_names` caught it before release, and the escapes are now computed at runtime.
2. The HTML embedded scan timings, which made it non-reproducible. Timings are now stripped, and artefacts are written with LF newlines.
3. Git revision validation rejected `HEAD~1`. `~` and `^` are now allowed; a leading `-` and `..` are still rejected.

## P1 increment 1 (branch `feat/p1-delegation-ci`)

| Item | Status |
|---|---|
| GitHub Actions CI (Ubuntu and Windows × Python 3.10/3.12): tests, demo, benchmark, documented gate exit codes | ✅ added. Linux runs the symlink test that is skipped locally. |
| Delegation paths: `handoffs`, `handoff()`, `agent.as_tool()` (≤2 hops, `inferred_limited`) | ✅ |
| Library tool behaviour model (LangChain shell/REPL/file/requests tools, `FileManagementToolkit.get_tools()`, OpenAI `ShellTool`/`LocalShellTool`) | ✅ |
| Provider-hosted tools and hosted-container `ShellTool` recorded with no host operation | ✅ |
| `needs_approval` modelled as a human-approval guard | ✅ |
| Receiver typing for project classes and `self.attr` | ✅ |
| Depth-limit `unknown` only when a sink is syntactically reachable | ✅ |

Tests: **74 passed, 1 skipped**. Bundled benchmark (16 scan and 5 drift cases): agents 18/0/0, tools 27/0/0, bindings 26/0/0, **paths 21 TP / 0 FP / 1 FN**, drift 8/0/0 (TP/FP/FN). The same caveats as above apply.

### External re-scan after increment 1 (same pinned SHAs)

| Repo | Before | After |
|---|---|---|
| openai-agents-python | 1 bound_capability, **53 unknown** | 1 bound_capability, 4 operation_path (local `ShellTool`, all with `needs_approval` → guard `known`, severity low), **29 unknown** |
| python-sdk | 6 unknown (depth limit) | 4 unknown (depth limit with a syntactically reachable sink) |

The remaining oa unknowns are 11 library tool instances that are not modelled, 10 MCP servers outside the repo, 5 dynamic tool lists or namespaces, 2 `as_tool()` calls on unresolvable agents, and 1 unresolved reference.

### Defects found and fixed in increment 1 (from the external spot check)

4. **False positives on hosted-container shells.** The first version of the library model mapped every `agents.ShellTool` to host `process_execution`. 4 of 8 new oa paths were `ShellTool(environment={"type": "container_auto"|"container_reference"})`, which runs in a provider-hosted container. AEM now reads `environment`, and a non-literal value gives `unknown`.
5. **Evidence aliasing.** Nodes and edges shared one evidence list object, so merging evidence into a shared operation node leaked other agents' file:line evidence into the first agent's path. `Node` and `Edge` now copy their evidence on construction (regression test `test_evidence_lists_are_not_aliased_between_graph_elements`).
6. **Missing `needs_approval` guard.** The SDK's human-in-the-loop flag was ignored, which overstated severity for all 4 local shell agents. It is now modelled as a guard.
7. **Depth-limit noise.** After receiver typing, depth-limit unknowns on python-sdk rose from 6 to 22. Reachability pre-filtering brought them down to 4.

## Local web GUI (branch `feat/web-gui`)

`agentic-bom serve` (alias `gui`) runs a stdlib-only local server with Scan, Compare (folders or git revisions) and Demo forms, a server-side folder picker, session run history, report viewing and artefact downloads.

- Security: loopback-only bind (anything else is refused); Host-header allowlist against DNS rebinding; per-process token exchanged for an HttpOnly SameSite=Strict cookie; a CSRF header plus same-origin check on every POST; JSON-only bodies of at most 64 KB; strict CSP (`default-src 'none'`, no eval); reports in an `allow-scripts`-only sandboxed iframe; errors return the exception class only, never a traceback.
- Verified with `tests/integration/test_web_gui.py` (8 tests over real HTTP) and a headless Chrome walkthrough: demo, report drawer, folder picker, compare, input-validation error, local scan, download. The only browser console error was the intentional 400 from the invalid-URL test.
- Limits: run history is in memory only (last 50 runs, lost on restart). Analyses run one at a time with no cancel button. There is no progress bar for long GitHub clones.

## TypeScript / JavaScript detector (branch `feat/typescript-detector`)

Added a pure-Python TS/JS parser and analyzer (no Node.js dependency). It covers OpenAI Agents JS, the Vercel AI SDK and the MCP TS SDK, with Express/Next.js sources, the TS demo `ts-same-bom-new-exposure`, 4 TS benchmark cases and 2 TS drift cases.

- Tests: **99 passed, 1 skipped**. Bundled benchmark (23 scan and 7 drift cases): agents 26/0/0, tools 42/0/0, bindings 40/0/0, **paths 33 TP / 0 FP / 1 FN**, drift 12/0/0 (TP/FP/FN). Same caveats as above: author-annotated synthetic fixtures.

### External TS spot check (pinned SHAs, no ground truth)

| Repo | SHA | TS/JS files | Unparsed regions | Agents | Tools | MCP servers | Paths | Time |
|---|---|---|---|---|---|---|---|---|
| openai/openai-agents-js | `9b33d73a3ad696f0c43689d1428e901bfdc37fa0` | 782 | 261 | 284 | 133 | 13 | 2 operation_path (local `shellTool`, `needsApproval` → low), 42 unknown | 12 s |
| modelcontextprotocol/typescript-sdk | `1e608caeb5130b2ad0fa067c84b26a038c1c6e36` | 439 | 156 | 0 | 115 | 82 | none | 6 s |
| vercel/ai | `dffe4053c15709577329518044b1ec1d4c6bb0fe` | 6,228 | 2,354 | 567 | 919 | 21 | 25 operation_path, 2 bound_capability, ~113 unknown | 41 s |

Spot-check results (source read by hand):

- **True positives in vercel/ai examples:** calculator tools calling `eval(expression)`, and the Anthropic bash/shell examples calling `exec(command)` through `lib/shell-executor.ts` (one with `needsApproval` → low).
- **Memory tool:** every path goes through `validatePath()` (`startsWith` + throw). AEM reports guard `unknown`, not `absent`.
- Checkout note: on Windows the vercel/ai and typescript-sdk clones need `core.longpaths=true`.

Defects found and fixed during this spot check:

8. **Crash.** A computed member callee (`obj[x](...)`) was compared against a set of method names, raising `TypeError`.
9. **Wrong write target.** `fs.writeFile(path, data)` counted `data` as part of the target, which hid a regex guard on `path`. Only copy/rename-style calls now have two target arguments.
10. **Missed framework rename.** MCP TS SDK servers were missed because the SDK moved to `@modelcontextprotocol/server`. This is the same failure class as the Python `FastMCP`→`MCPServer` rename.
11. **Hosted-container false positives.** `shellTool({ environment: { type: 'container_auto' } })` in the JS SDK runs in a provider container, which is the same false-positive class as in Python. AEM now reads `environment` and `needsApproval`.
12. **Inflated agent count.** `generateText` calls without `tools` were counted as agents (1,488 on vercel/ai). Only calls with `tools` count now (567).
13. **Performance.** The character-by-character tokenizer took 174 s on vercel/ai. Regex tokenization brought it to 41 s.
14. **Exponential nested templates.** Nested template literals re-tokenized inner templates. A 400-level nesting case hung, found by the hostile-input test. There is now a skip-only scanner and a depth limit of 32.
15. **Fix reported as a new path.** The TS demo's fix (`exec` → `execFile`) showed up as a new path. Capability slot matching now pairs the two.

## Not done / next steps

- TS/JS: `tsconfig` path aliases, `export * from` barrels, LangChain.js / Mastra.
- CycloneDX export and AgentBOM v1 interoperability. Not started, and conformance is not claimed.
- Receiver typing for parameters, factories and containers (still a silent false-negative class).
- Extending the library tool model (ComputerTool, LangChain toolkits beyond file management) and per-version SDK regression fixtures.
- An external corpus of 20 or more independently annotated repos (P1). Pairs of revisions taken from real commit history, to test drift on non-synthetic changes.
- A fair comparison against Cisco AI BOM and other scanners on scoped tasks (P1).
- Agent identity enrichment from IaC (P2, optional).
- Before use for Black Hat Asia 2027 (CFT closes 2026-11-02): per design §16, describe this only as what has been verified above. The external evaluation is a spot check, not a benchmark.
