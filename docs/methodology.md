# Methodology

## 1. Discovery

- **Tools**: functions decorated with `agents.function_tool`, `langchain_core.tools.tool` (and its aliases), or `<FastMCP|MCPServer instance>.tool()`, plus module-level wrappers (`x = function_tool(fn)`, `StructuredTool.from_function(fn)`). Each tool records a **contract**: name, description (redacted, truncated to 500 chars, with a SHA-256 of the full text), parameters (name, annotation, required) and decorator annotations. It also records fingerprints over all of these.
- **Agents**: `agents.Agent(...)` and `langgraph.prebuilt.create_react_agent(...)` calls, found anywhere (module level or inside functions). The detector reads `name`, `model`, `instructions`/`prompt`, `tools`, `handoffs` and `mcp_servers`.
- **Bindings**: `tools=` elements are resolved through local variables, module constants, imports, re-exports, `+` concatenation, `*` unpacking and wrapper calls. A function that is bound but has no decorator is still analysed, with `inferred_limited`. Library tool objects (such as `WebSearchTool()`) become `unsupported`. Anything else becomes `unknown`.
- **MCP**: `MCPServerStdio(params={"command": ..., "args": [... "server.py"]})` is resolved to a FastMCP/MCPServer instance in that file. The result is `CONNECTS_MCP` with resolution `inferred_limited`. Remote or unresolvable servers become `unknown`.

- **Delegation**: `handoffs=[a, handoff(b)]` and `tools=[c.as_tool(...)]` become `DELEGATES_TO` edges (`mode=handoff|as_tool`). Agent references are resolved through local variables, module variables, imports, inline `Agent(...)` and factory functions that return an agent. Paths are propagated through at most 2 delegation hops, deduplicated, keep the *delegating* agent's trust status, and are marked `inferred_limited`.
- **Library tools** (`analyzers/operations.py: LIBRARY_TOOLS`, `LIBRARY_TOOLKITS`): modelled from documented behaviour as a parameter-controlled operation on `<model-supplied>` arguments, with `inferred_limited` and scope `library_behaviour_model`. `FileManagementToolkit(selected_tools=[...]).get_tools()` is expanded and filtered by `selected_tools` when that is a literal.
- **Hosted tools**: provider-hosted tools, and `ShellTool(environment={"type": "container_auto"|"container_reference"})`, are bound with no host operation. A non-literal `environment` gives `unknown`.

### TypeScript / JavaScript

- **Parser** (`detectors/ts_parser.py`): a regex tokenizer plus a recursive-descent parser for statements and expressions. Type syntax is skipped: annotations, `as`/`satisfies`, generics, `interface`, `type`, `enum`, `declare`. Error recovery skips one statement at a time and counts the region.
- **Function units**: function declarations, `const f = () => {}`, class methods, object-literal methods, `tool({execute})` handlers, MCP handlers and route handlers are each analysed as a unit. Callbacks passed inline (`.map(x => …)`, `setTimeout(() => …)`) are analysed in place, with the enclosing environment. Array-method callbacks inherit the receiver's taint.
- **Tools**: `tool({...})` from `@openai/agents` or `ai`. Vercel provider tools (`anthropic.tools.bash_…({ execute })`) are treated as local tools when they have an `execute`, and as provider-hosted otherwise. The MCP TS SDK forms `server.tool(name, [desc], shape, handler)` and `server.registerTool(name, {description, inputSchema, annotations}, handler)` are recognised. Contract parameters come from `z.object({...})`, raw zod shapes or JSON-schema `properties`. A tool without `execute` is client-executed: it is bound but has no server-side operation.
- **Agents**: `new Agent({...})` (OpenAI Agents JS, AI SDK `Experimental_Agent`) and `generateText/streamText/generateObject/streamObject({ tools, system, prompt|messages })`. `system`/`instructions` count as privileged instructions; `prompt`/`messages` count as user-role input.
- **Sources**: parameters of `app.get/post/...('/path', handler)` and of Next.js `app/**/route.ts` exports (`GET`, `POST`, …); `process.argv`, `process.stdin`, `readFileSync(0)`, `fetch()` GET responses. One-level call-site provenance works the same way as for Python.
- **Sinks**: `child_process.exec/execSync/spawn/execFile/fork` (also through `promisify`), `execa`, `eval`, `new Function`, `vm.*`, `fs.*` writes and deletes (`fs/promises`, `fs-extra`), `fetch` with a state-changing `method`, `axios/got/ky.post/put/patch/delete`, `process.env.*`, AWS SDK v3 `client.send(new XxxCommand(...))` (non-read commands), and computed calls `obj[x](...)` (→ `unknown`).
- **Guards**: `ALLOWED.includes(x)` / `.has(x)` / `/re/.test(x)` and `x === 'lit'` count as `known`. Other predicates count as `unknown`. A value that passes through a project helper that throws under a condition (validator-style) gets guard `unknown`, never `absent`.

## 2. Taint and trust flow (bounded, deterministic)

Each tool function is walked statement by statement. Tool parameters start as tainted (`param:<name>`). Taint propagates through assignments, f-strings, `+`, `%`/`.format` on tainted receivers, containers, comprehensions and method calls on tainted objects.

- **Cleansers**: `int`, `float`, `bool` and `len` drop taint. Indexing an *untainted* container with a tainted key yields an untainted value, because the result is a selection among constants.
- **Branches**: for `if/else`, taint is merged across branches. A branch that always terminates (`return`, `raise`, `continue`, `break`) is pruned.
- **Guards**, applied to the guarded variable:
  - `known`: `x in/not in <untainted>`, `x == / != <untainted>`, `re.fullmatch/re.match(p, x)`, compiled `P.fullmatch(x)`, and `x.isalnum()/isdigit()/isidentifier()/…`.
  - `unknown`: any other predicate over a tainted variable, such as a project validator or `startswith`.
  - A guard only applies where the control flow ensures it, for example `if x not in A: return` followed by the sink.
- **Helpers**: calls into project functions are followed with argument→parameter taint mapping, up to `--max-depth` hops (default 3). Cycles are cut. Hitting the depth limit yields a `dynamic_dispatch` operation with `resolution=unknown`, but only if a syntactic over-approximation (any recognised sink call reachable through project functions, or methods of the same name, within a 40-function budget) says a sink could lie beyond the limit.
- **Receivers**: method calls are followed when the receiver type is inferred: `x = Cls()`, `Cls().m()`, `self.m()` inside `Cls`, and `self.attr.m()` where `self.attr = ...` is assigned in one of `Cls`'s methods (for example a `boto3` client or another project class).
- **Human approval**: `@function_tool(needs_approval=True)` or `ShellTool(needs_approval=True)` makes the guard `known` (`guard_kind=human_approval`). A non-literal `needs_approval` gives `unknown`.
- **Dynamic dispatch**: `getattr(...)()`, `table[x]()`, `importlib.import_module` and `__import__` yield `unknown`.

Agent instructions are evaluated in the enclosing function. Untrusted sources are:

- `input()` and `sys.stdin.*`
- `sys.argv`
- `flask.request.*`
- `requests.get`/`httpx.get`/`urlopen` results
- parameters of route handlers (`@app.get/post/...`)

If the instructions depend only on a function parameter, AEM checks the **call sites** of that function one level up. A source-tainted argument means `untrusted`, constants mean `static`, and anything else means `unknown`.

`Runner.run*(agent, input)` with untrusted input is recorded as a **user-role** flow (`FLOWS_TO role=user_message`). It does *not* create `potentially_exposed` on its own. That case is the user-role negative control.

## 3. Sensitive operations

| Category | Recognised (fully qualified after import resolution) |
|---|---|
| process_execution | `subprocess.run/call/check_call/check_output/Popen/getoutput`, `os.system/popen/exec*/spawn*`, `asyncio.create_subprocess_*` |
| code_execution | `eval`, `exec` |
| filesystem_write | `open(..., 'w'/'a'/'x'/'+')`, `shutil.copy*/move`, `os.rename/replace/chmod/chown`, `Path(...).write_text/write_bytes/touch/rename/replace/chmod` |
| filesystem_delete | `os.remove/unlink/rmdir/removedirs`, `shutil.rmtree`, `Path.unlink/rmdir` |
| network_state_change | `requests/httpx.post/put/patch/delete`, `requests/httpx.request` with a state-changing method |
| cloud_sdk_call | any non-read method on a `boto3.client/resource(...)` value. This identifies the operation only and says nothing about IAM. |
| secret_access | `os.getenv`, `os.environ[...]`, `os.environ.get`, `secretsmanager.get_secret_value`, `ssm.get_parameter(s)` |

**Target vs content**: for filesystem and network operations, only the path or URL argument decides `target_controlled`. Payload parameters are listed separately as `content_params`. For process and code execution, every argument counts as target.

## 4. Classification

```
tool/op unresolved or dynamic           -> unknown
no agent/MCP binding                     -> inventory_only
target not parameter-controlled          -> bound_capability
guard known                              -> operation_path (severity low)
untrusted→privileged + guard absent      -> potentially_exposed (high)
untrusted→privileged + guard unknown     -> unknown
otherwise                                -> operation_path (medium)
```

`resolution` on a path is `inferred_limited` whenever any link is inferred: MCP binding from command args, unresolved instruction provenance, or an unresolved `open` mode or HTTP method.

## 5. Drift rules

| Rule | Kind | Trigger |
|---|---|---|
| AEM-D001 | `new_bound_sensitive_operation` | a new path key exists, or an existing path rises in rank (bound → operation → potentially_exposed) |
| AEM-D002 | `new_untrusted_to_privileged_path` | an agent gains a `CROSSES_TRUST_BOUNDARY` edge |
| AEM-D003 | `operation_target_expanded` | same path key, target goes from constant to parameter-controlled |
| AEM-D004 | `tool_contract_changed` | same tool ID, different contract fingerprint. Severity is medium or high only when a *newly added parameter* reaches a sensitive operation. Description-only changes get `review_status=review_required` and are never gate-eligible. |
| AEM-D005 | `capability_removed` | a path disappears, drops in rank or gains a known guard, or a trust flow is removed |
| AEM-D006 | `review_required` | a new or changed path is `unknown`, or provenance becomes unknown. Severity is always `info`. |

**Capability slot matching**: when a path key disappears and a new one appears with the same entry, delegation, tool, operation category and enclosing function (for example `exec` replaced by `execFile` in the same helper), the two are compared as one changed path. This avoids reporting a fix as removed + new.

**BOM delta** compares the component inventory: agents (name, framework, model), models, tools (identity, name, framework), MCP servers and packages (version spec). It deliberately leaves out prompt text and tool contracts, which are diffed separately above.

**CI gate** (`--fail-on`): it counts only findings with `gate_eligible=true`, meaning `confirmed_static` evidence and a kind other than removed or review. `inferred_limited` paths, such as MCP bindings inferred from args, are not gate-eligible.
