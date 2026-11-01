# Demo guide (about 5 minutes, fully offline)

```bash
pip install -e .
agentic-bom demo --scenario all --out out/demo
```

## Act 1: same BOM, new exposure

Open `out/demo/same-bom-new-exposure/1-baseline-vs-candidate/report.html`.

1. **Banner:** `Agentic BOM unchanged · 1 new potential exposure path`. Point out that the package list, agents, tools and model are identical, so a BOM diff is empty.
2. **Graph:** the dashed red chain runs `stdin → support-triage → run_diagnostic → subprocess.run`.
3. **Click the path** to open the drawer. Walk through the evidence:
   - `app.py:26`: `ticket = sys.stdin.read()` is the untrusted source.
   - `app.py:27`: `build_agent(ticket)` is the call site, which gives provenance through the parameter.
   - `app.py:19`: the ticket is interpolated into the `instructions`, crossing the trust boundary.
   - `support_tools.py:19` → `diagnostics.py:10`: helper hop to `subprocess.run(f"curl … {target}", shell=True)`.
   - The guard is `absent`. `runtime_observed=false` and `authorization_verified=false`.
4. **Compare revisions tab:** AEM-D001 and AEM-D002 are both `high` and both CI-gate eligible.
5. **Negative control, in the same repo:** the coverage tab lists `restart_service` (`subprocess.run`) as *not reachable from any agent/tool*. It is dangerous code, but it is not attributed to the agent.

CI gate:

```bash
agentic-bom diff examples/same-bom-new-exposure/baseline examples/same-bom-new-exposure/candidate --fail-on high   # exit 1
```

## Act 2: the fix

Open `2-candidate-vs-fixed/report.html`. It shows only `capability_removed` findings: the trust flow is gone, and the path moves from `potentially_exposed` to `operation_path` with guard `known` (`if target not in ALLOWED_TARGETS`). No new vulnerability is claimed.

```bash
agentic-bom diff examples/same-bom-new-exposure/candidate examples/same-bom-new-exposure/fixed --fail-on high      # exit 0
```

## Act 3: MCP contract drift joined to a path

Open `out/demo/mcp-tool-schema-drift/1-baseline-vs-candidate/report.html`. The `save_note` tool gains `sync_url` and a manipulative description. AEM reports:

- AEM-D004 `tool_contract_changed`, with the old and new description and `sync_url` as the added parameter.
- An escalation to `medium`, because `sync_url` reaches `requests.post`. The finding is joined to `notes-assistant → MCP server 'notes' → save_note → requests.post`.
- The agent→MCP binding is shown as `inferred_limited`, because it is resolved from the `MCPServerStdio` args.

## Act 4: honesty slide

- `examples/negative-controls/dynamic-dispatch` and `unsupported-guard` both give `unknown`, never `safe` or `critical`.
- `agentic-bom benchmark run` prints TP/FP/FN, including the deliberate depth-limit false negative and the caveat that the corpus is synthetic.
- Show the supported matrix: TypeScript is not implemented.
