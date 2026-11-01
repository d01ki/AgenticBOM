# Benchmark: AEM bundled synthetic corpus v0.1

> Synthetic fixtures written by the tool author; ground truth annotated by the same author (not independent). These numbers show the tool behaves as designed on its own fixtures; they are NOT evidence of ecosystem accuracy.
> External pinned public-repository evaluation is tracked separately (see docs/implementation-status.md).

| Category | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| agents | 13 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| tools | 21 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| bindings | 20 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| paths | 13 | 0 | 1 | 1.00 | 0.93 | 0.96 |
| drift_findings | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |

Expected-unknown constructs reported as `unknown`: 4 / 4
Median case duration: 0.0204 s · max traced peak memory: 1087748 bytes

## Cases

| Case | Type | Label | OK | Notes |
|---|---|---|---|---|
| same-bom-baseline | scan | negative | yes | — |
| same-bom-candidate | scan | positive | yes | — |
| same-bom-fixed | scan | positive (guarded) | yes | — |
| mcp-candidate | scan | positive | yes | — |
| langgraph-flask-delete | scan | positive | yes | — |
| fastapi-eval-cloud | scan | positive | yes | — |
| helper-chain-depth | scan | positive + depth limit | yes | FN paths: [['recorder', 'write_deep', 'filesystem_write', 'operation_path']] |
| neg-unbound-helper | scan | negative | yes | — |
| neg-fixed-command | scan | negative | yes | — |
| neg-user-role-only | scan | negative (for potentially_exposed) | yes | — |
| neg-test-fixture-excluded | scan | negative | yes | — |
| neg-dynamic-dispatch | scan | unknown control | yes | — |
| neg-unsupported-guard | scan | unknown control | yes | — |
| drift-same-bom-1 | drift | drift | yes | BOM delta unchanged (expected unchanged) |
| drift-same-bom-2 | drift | drift | yes | BOM delta unchanged (expected unchanged) |
| drift-mcp-1 | drift | drift | yes | BOM delta changed (expected changed) |
| drift-mcp-2 | drift | drift | yes | BOM delta unchanged (expected unchanged) |
| drift-identical | drift | drift | yes | BOM delta unchanged (expected unchanged) |
