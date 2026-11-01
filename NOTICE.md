# NOTICE

Agentic Exposure Mapper (provisional name)
Copyright 2026 the Agentic Exposure Mapper authors.

Licensed under the Apache License, Version 2.0 (see `LICENSE`).

## Provenance and heritage

This project was designed as a separate tool next to **AIBOM Inspector**
(https://github.com/d01ki/AIBOM-Inspector, Apache-2.0), which covers local-first AI component
detection, role-aware prompt data flow, agent-tool binding and drift.

- **No source code from AIBOM Inspector was copied into this revision.** The AIBOM Inspector
  source was not available in this workspace while v0.1 was implemented. All detectors,
  analyzers, exporters and the UI here were written from scratch.
- The *concepts* of agent-tool binding detection, prompt-role data flow and drift are shared
  with AIBOM Inspector and other prior art. This project does not claim to have invented them.
  See `docs/novelty-positioning.md`.
- If AIBOM Inspector discovery code is reused later, it must keep its original copyright and
  Apache-2.0 notices, and it must be listed in the dependency/provenance table below.

## Third-party components

| Component | Use | License |
|---|---|---|
| Python standard library (`ast`, `json`, `tarfile`, …) | runtime | PSF |
| `pytest` (dev only) | tests | MIT |
| `jsonschema` (optional) | extra schema validation if installed | MIT |

The runtime has no third-party dependencies.

Framework names (OpenAI Agents SDK, MCP, LangChain, LangGraph, FastAPI, Flask, boto3) are
used only to recognise their APIs statically. None of them is bundled or executed.
