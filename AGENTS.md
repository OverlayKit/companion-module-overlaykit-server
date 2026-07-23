# Agent Operating Contract

This repository is governed by the compiled contract in `.overlaykit/governance/`.

Before changing product code, an agent must:

1. Run `npm run governance:verify`.
2. Read `.overlaykit/governance/plan.json`.
3. Identify the active change contract and its ADRs.
4. Identify the active product specification and acceptance criteria.
5. State its agent identity and human principal.
6. Classify relevant claims as facts, inferences, assumptions, or unknowns.

Facts and inferences require evidence. Blocking unknowns stop an approved or implemented change.
Accepted decisions and specifications are immutable; create explicit successors instead of editing
their history.

The OverlayKit server is the sole authority for protocol, admission, catalogs, revisions, command
outcomes, and production state. This module may validate and project server evidence, but it may
not create a second operational authority.

An agent may produce evidence, but it cannot approve its own hypothesis, reinterpret stale evidence
as current, create an ADR before human acceptance, or merge merely because a hypothesis was
accepted.

Memory Cloud is the persistent store for lessons and operational context. The compiled governance
plan remains the normative project law.

Before handing off a change, run:

```bash
npm run governance:check
npm run check
npm run build
```
