# Novelty positioning

This document states what AEM does and does not claim. It makes no claim to be "industry first". Any comparative claim needs the reproducible re-testing described in the last section.

## Prior art (re-check before any submission)

| Project | What it claims to do | Relation to AEM |
|---|---|---|
| AgentBOM (https://agentbom.org/spec/v1) | A declarative format for models, tools, skills, permissions, data access, autonomy and signatures | A format, not a source analyzer. AEM does not emit AgentBOM v1 and does not claim conformance. |
| Cisco AI BOM (https://github.com/cisco-ai-defense/aibom) | Broad discovery of AI components and relationships across frameworks, MCP, agents, repos and containers | Its component and relationship discovery is broader than AEM's. AEM should not be scored against it on inventory breadth. |
| OWASP ACS AgBOM (https://owaspacs.org/docs/spec/inspect/) | Dynamic inventory of models, tools, MCP servers, peers and capabilities | Dynamic and runtime oriented. AEM is static only. |
| AIBOM Inspector (https://github.com/d01ki/AIBOM-Inspector) | Local-first detection, role-aware prompt data flow, agent-tool binding, drift | The predecessor. Agent-tool binding, prompt-role flow and drift are **not new in AEM** and must not be presented as newly invented. |
| MCP scanners and schema-pinning tools | Tool description poisoning checks and tools/list fingerprinting | Generic schema drift is not new. AEM's contribution here is limited to *joining* a contract change to a source-confirmed binding and operation path. |

## Hypothesis under test (not an established result)

> An evidence graph (agent → tool → operation, with file:line evidence, resolution and unknowns), combined with a before/after capability-path diff, finds security-relevant exposure changes that BOM-only diffs do not report, including cases where the component inventory is identical.

The parts of AEM intended to be distinctive are:

1. **Capability-path diff.** Drift is keyed on line-independent `entry|tool|operation|helper-chain` paths, not on component lists. Same-BOM regressions show up as `bom_delta=unchanged` alongside a new `potentially_exposed` path.
2. **Explicit epistemic status.** Every edge and path carries `resolution`. Unknown and dynamic constructs stay `unknown`, and a confidence number can never upgrade them.
3. **Target vs content control, and guard status.** An operation counts as parameter-controlled only when the parameter decides the *target*. The guard status is known, absent or unknown.
4. **Contract changes joined to paths.** `tool_contract_changed` escalates only when a new parameter reaches a recognised sensitive operation. Description-only changes stay `review_required`.

## What would be needed to claim superiority

- Run equivalent, versioned configurations of the other tools on the same pinned revisions.
- Compare only what each tool claims to detect. Do not fail a BOM generator for not doing path analysis.
- Show a BOM-only diff baseline next to AEM's path diff on the same revision pairs, and include AEM's false positives and false negatives.
- Use independent annotators for ground truth.

None of this has been done yet. See `docs/implementation-status.md`.
