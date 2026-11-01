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
| TypeScript/JavaScript (Vercel AI SDK, OpenAI Agents TS) | Not analysed. The file count is reported under `unsupported_languages_present`. |
| `agent.as_tool()`, handoff-reachable tools | `as_tool` gives `unknown`. `handoffs` are recorded as `DELEGATES_TO` but paths are not propagated through delegation. |
| Library or hosted tools (`WebSearchTool`, `HostedMCPTool`, `ShellTool`, …) | `unsupported` tool node, `unknown` path. |
| Remote MCP servers, or servers outside the repo | `unknown` server, tools not enumerated. |
| Helper chains longer than 3 hops | `unknown` (`helper chain exceeds 3 hops`). These can be noisy on repositories that vendor large libraries; see the MCP SDK external scan. |
| Method calls on objects without inferred types | Not followed (only `pathlib.Path` and `boto3` clients are typed). A sink behind `self.client.run(x)` is missed. Unlike dynamic dispatch, this is a silent false-negative class. |
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
