# Limitations

AEM reports **static possibilities inside a stated scope**. It does not prove exploitability, and it does not prove that a path is absent.

## What results do *not* mean

- `potentially_exposed` does **not** mean that a model will choose the tool, that an injection will succeed, or that an attacker can reach the input in production.
- No finding says anything about IAM, OAuth, network policy or sandboxing. Every path has `authorization_verified=false`.
- Nothing is observed at runtime. Every path has `runtime_observed=false`.
- When no paths are found, that means no paths were found *in supported patterns*. Check the coverage tab and `coverage.unknowns`.

## Known analysis gaps (v0.1)

| Gap | Effect |
|---|---|
| TypeScript/JavaScript parsing | A built-in tolerant parser, not the TypeScript compiler. Constructs it cannot parse are skipped one statement at a time and counted in `ts_js_unparsed_regions` (on the `ai` repository about 2,354 regions across 6,228 files). Type information is not used. Template literals nested more than 32 levels deep become a per-file parse error. |
| TS/JS resolution | Relative imports (`./x`, `index.*`, `.js`→`.ts`) and in-file functions, nested scopes, class methods (`this.m()`, `new Cls().m()`, `this.field = new X()`) are followed. Path aliases from `tsconfig` (`@/lib/x`), barrel re-exports via `export * from`, dynamic `require`/`import()` and dependency-injected objects are not. `promisify(fn)` is only resolved for module-level constants. |
| TS/JS frameworks | Only the patterns in the supported matrix are recognised. LangChain.js, Mastra, CrewAI-TS and similar libraries are not modelled. `generateText`/`streamText` calls without `tools` are treated as model calls rather than agents. |
| Delegation (`handoffs`, `handoff()`, `agent.as_tool()`) | Followed for up to 2 hops, cycle-safe. Delegated paths are always `inferred_limited` and therefore never gate-eligible, because the sub-agent's own instructions may refuse or transform the call. Agents passed in through dynamic expressions become `unknown`. |
| Library tools | Only the tools in `LIBRARY_TOOLS` (LangChain `ShellTool`, `PythonREPLTool`, file-management and requests tools, `FileManagementToolkit.get_tools()`, OpenAI `ShellTool`/`LocalShellTool`) are modelled, from their *documented* behaviour (`inferred_limited`; the library source is not analysed). Other library tools give `unknown`. |
| Provider-hosted tools (`WebSearchTool`, `FileSearchTool`, `CodeInterpreterTool`, `ImageGenerationTool`, `ShellTool` in a hosted container) | Recorded as bound tools with **no host-side operation**. Risk inside the provider's sandbox is out of scope. `HostedMCPTool` stays `unknown`. |
| `needs_approval` | A literal `True` is treated as a `known` guard of kind `human_approval`. Any non-literal value gives `unknown`. AEM does not check that the approval UI or callback really blocks execution. |
| Remote MCP servers, or servers outside the repo | `unknown` server, tools not enumerated. |
| Helper chains longer than 3 hops | `unknown` only when a recognised sink is still syntactically reachable beyond the limit (an over-approximation). Large vendored frameworks can still produce some of these. |
| Method calls on objects without inferred types | Types are inferred for `pathlib.Path`, `boto3` clients, project classes (`x = Cls()`, `Cls().m()`) and `self.attr` assigned in that class's methods. Receivers from parameters, factories or containers are still untyped, so sinks behind them are silently missed. |
| Class-based tools, `FunctionTool(...)` built by hand, dynamic `instructions` callables | `unknown` or not detected. |
| Untrusted sources | Only the listed APIs and route parameters. Message queues, files, DB reads and email are not modelled. |
| Guards | Only the listed patterns are `known`. Path normalisation checks (`realpath(...).startswith(base)`) are `unknown`, even when correct. |
| Instruction provenance | Only one level of call sites. Deeper chains give `unknown`. |
| Sanitisation semantics | `shlex.quote` and similar do **not** clear taint. A quoted shell argument is still parameter-controlled. |
| Database writes, email or messaging, LLM-to-LLM delegation | Not recognised as sensitive operations. |
| CycloneDX / AgentBOM v1 export | Not implemented. `agentic-bom.json` is a project-specific format and is labelled as such. |
| Registry comparison | `--registry` gives registered or unregistered. Without a registry, every agent is `management_status=unknown`, never "shadow". |

## Evaluation caveats

- The bundled corpus is synthetic. The author wrote both the fixtures and the annotations, so it shows designed behaviour and cannot tell you ecosystem precision or recall.
- External pinned scans were spot-checked by hand, not fully annotated.

## Safety boundaries of the scanner itself

- It reads files only. It does not follow symlinks, it skips files over 1 MB, it caps the walk at 20,000 files and a directory depth of 30, and it catches parser recursion and syntax errors per file.
- It clones only `https://github.com/<owner>/<repo>`. Git runs with `protocol.allow=never` except https, redirects off, no hooks, no submodules, `core.symlinks=false`, and no terminal prompts.
- Prompt bodies are never stored, only a hash and a length. Environment values from MCP configs are never stored. Token-shaped strings in snippets, descriptions and targets are redacted.
- The HTML report embeds data as JSON with `< > &` escaped, renders it with `textContent` only, and ships a restrictive CSP.
