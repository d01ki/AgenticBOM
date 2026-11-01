# Agentic Exposure Mapper (AEM)

> Working name. Check GitHub, PyPI and trademarks before you pick a final name.

An Agentic BOM tells you what an agent contains. AEM shows which sensitive operations are connected to that agent, what evidence supports each connection, and which new exposure paths appear after a change, even when the BOM itself is identical.

AEM is a static, offline analyzer for Python and TypeScript/JavaScript agent repositories. It parses Python with `ast` and TS/JS with a built-in tolerant parser (no Node.js needed), and it never runs the code. It needs no cloud credentials and no LLM calls, and it never executes `setup.py`, MCP servers, notebooks or anything else in the scanned repository.

```text
untrusted input ──CROSSES_TRUST_BOUNDARY──▶ agent (privileged instructions)
                                              │ BINDS_TOOL / CONNECTS_MCP→EXPOSES_TOOL
                                              ▼
                                            tool ──REACHES_OPERATION (≤3 helper hops)──▶ subprocess.run / os.remove / requests.post / boto3 …
```

## One-command demo (offline)

```bash
pip install -e .            # Python ≥ 3.10, no runtime dependencies
agentic-bom demo --scenario all --out out/demo
# open out/demo/same-bom-new-exposure/1-baseline-vs-candidate/report.html
```

Bundled scenario `same-bom-new-exposure` (baseline → candidate → fixed):

| Step | Change | Agentic BOM | AEM result |
|---|---|---|---|
| baseline → candidate | the ticket from stdin moves into the agent's `instructions`, and the tool helper now runs `subprocess.run(f"curl … {target}", shell=True)` | **unchanged** | `Agentic BOM unchanged · 1 new potential exposure path`, with AEM-D001 and AEM-D002 at `high` and file:line evidence for every hop |
| candidate → fixed | allowlist guard added, argv list used, ticket moved back to the user-role message | unchanged | only `capability_removed` findings; the CI gate passes |

`ts-same-bom-new-exposure` is the same story in TypeScript (OpenAI Agents JS, `promisify(exec)` → `execFile` fix).

There is also `mcp-tool-schema-drift`. In that scenario a FastMCP tool gains a `sync_url` parameter and a manipulative description. AEM reports `tool_contract_changed` and joins it to the new agent→MCP→tool→`requests.post` path.

## Local web GUI

```bash
agentic-bom serve            # alias: agentic-bom gui ; opens the browser automatically
```

From the browser you can run **Scan** (a local folder via the built-in folder picker, or a GitHub URL), **Compare** (two folders, or two revisions of a git repository) and **Demo**. Each result opens as the interactive report, and you can download `agentic-bom.json`, `capability-graph.json`, `findings.sarif` and `security-drift.json`. All runs from the session are listed in the sidebar.

The GUI binds to loopback only. Access needs the one-time token URL printed in the terminal, which is exchanged for an HttpOnly SameSite=Strict cookie. POST requests need a CSRF header and a same-origin request. The Host header is checked to block DNS rebinding. Reports render in a sandboxed iframe. Scanned code is never executed.

## CLI

```bash
agentic-bom scan ./project --out out/                       # local directory
agentic-bom scan https://github.com/owner/repo --ref <sha>  # read-only shallow clone (github.com only)
agentic-bom diff ./baseline ./candidate --fail-on high      # exits 1 if the gate fails
agentic-bom diff HEAD~1 HEAD --git ./repo --fail-on high    # two git revisions (via `git archive`)
agentic-bom demo --scenario same-bom-new-exposure
agentic-bom benchmark run --corpus benchmark/corpus.json
agentic-bom explain <finding-id> --report out/security-drift.json
```

Outputs: `agentic-bom.json`, `capability-graph.json`, `security-drift.json`, `findings.sarif` (SARIF 2.1.0) and a self-contained `report.html`. The report has an interactive graph and an evidence drawer.

## What is classified, and how strongly

| Class | Meaning |
|---|---|
| `inventory_only` | A tool contains a sensitive operation, but no agent or MCP binding was proven. |
| `bound_capability` | A bound tool performs the operation, but its target is not controlled by tool parameters. |
| `operation_path` | A tool parameter controls the operation target. The guard status is shown as known, absent or unknown. |
| `potentially_exposed` | Untrusted data reaches the privileged instructions **and** a parameter-controlled, unguarded operation is bound. This is a static possibility, not proof of exploitation. |
| `unknown` | The binding, dispatch or guard is dynamic or unsupported. Such paths are never reported as safe or critical. |

Every relationship carries `resolution` (`confirmed_static` / `inferred_limited` / `unknown` / `unsupported`), `scope`, `confidence` and `evidence[]` (file, lines, detector id). Every path records `runtime_observed=false` and `authorization_verified=false`.

## Supported matrix (honest)

| Area | Status |
|---|---|
| Python | ✅ AST, explicit patterns, bounded inter-procedural helper following (3 hops) |
| OpenAI Agents SDK (Py) | ✅ `Agent`, `@function_tool`, `function_tool(fn)`, `Runner.run*`, `MCPServerStdio/Sse/StreamableHttp` |
| MCP Python SDK | ✅ `FastMCP` / `MCPServer` + `@server.tool()`; MCP JSON configs (`mcp.json`, `.mcp.json`, `claude_desktop_config.json`) |
| LangChain / LangGraph (Py) | ✅ `@tool`, `StructuredTool.from_function`, `create_react_agent` |
| TypeScript / JavaScript | ✅ built-in tolerant parser (no Node.js), explicit patterns; unparsed regions are counted in coverage |
| OpenAI Agents JS, Vercel AI SDK, MCP TS SDK | ✅ `new Agent`, `tool()`, `run()`, `asTool`/handoffs, `generateText/streamText` (with tools), provider tools with `execute`, `McpServer.tool/registerTool` |
| Express / Next.js routes (TS/JS) | ✅ handler parameters treated as untrusted sources |
| Delegation (`handoffs`, `as_tool`) | ✅ ≤2 hops, always `inferred_limited` |
| Library tools (LangChain shell/REPL/file/requests, OpenAI `ShellTool`) | ✅ modelled from documented behaviour (`inferred_limited`); others `unknown` |
| Provider-hosted tools, `needs_approval` | ✅ hosted = no host operation; `needs_approval=True` = human-approval guard |
| Remote MCP servers, dynamic tool lists | ⚠️ reported as `unknown` |
| IAM / OAuth effective permissions, runtime behaviour | ❌ out of scope by design |

## Prior art and novelty

AEM does **not** claim to have invented Agentic BOMs, MCP schema fingerprinting or agent-tool discovery. See [`docs/novelty-positioning.md`](docs/novelty-positioning.md) for how it relates to AgentBOM, Cisco AI BOM, OWASP AgBOM and AIBOM Inspector. The hypothesis under test is narrower: an evidence graph combined with a before/after capability-path diff, plus controlled negative cases, finds exposure changes that BOM-only diffs miss.

## Evaluation

- Bundled synthetic corpus: 13 scan cases and 5 drift cases, all with ground truth, including negative and unknown controls. Run `agentic-bom benchmark run` to reproduce. The fixtures and the ground truth were written by the tool author, so these numbers show the tool behaves as designed. They are **not** a measure of accuracy across the wider ecosystem. Results are in [`benchmark/reports/latest.md`](benchmark/reports/latest.md).
- External pinned repositories: two public repos were scanned at fixed SHAs. Only a spot check was done, with no full ground truth. See [`docs/implementation-status.md`](docs/implementation-status.md).

## Documentation

[architecture](docs/architecture.md) · [methodology](docs/methodology.md) · [limitations](docs/limitations.md) · [novelty positioning](docs/novelty-positioning.md) · [demo guide](docs/demo-guide.md) · [implementation status](docs/implementation-status.md)

## License

Apache-2.0. See `LICENSE` and `NOTICE.md`.
