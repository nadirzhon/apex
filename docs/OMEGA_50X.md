# OMEGA 50X — evidence-first target

`50/10` is not a marketing score. It is an intentionally excessive engineering target designed so a normal `10/10` becomes the minimum acceptable level.

## The rule

APEX gets **zero credit** for a vulnerability class merely because a module exists, a tool is installed, or a unit test passes. Credit is earned only when the system receives a **blind, previously unseen, loopback-only challenge**, produces a finding without ground-truth leakage, supplies replayable evidence, and passes scoring after labels are revealed.

## 10/10 gate

Across a sufficiently diverse blind suite:

- precision >= 98%
- recall >= 90%
- F1 >= 94%
- >= 98% of reported findings contain replayable evidence
- confidence calibration error <= 8%
- no scope escape
- no benchmark label leakage

## 50/10 target

- precision >= 99.5%
- recall >= 97%
- F1 >= 98%
- 100% evidence coverage
- confidence calibration error <= 3%
- deterministic replay of every published finding
- zero target-policy violations
- performance reported by vulnerability family, not only aggregate score
- holdout challenges never used during development

## Architecture required to reach it

1. **Blind Challenge Arena** — labels remain hidden until scoring.
2. **Explorer** — discovers application states from browser/API observations rather than a predeclared endpoint list.
3. **Persistent World Model** — actors, resources, ownership, tenants, workflows and observed state transitions with provenance.
4. **Competing Reasoners** — multiple independent hypothesis strategies; agreement is evidence, not truth.
5. **Experiment Planner** — chooses the cheapest safe experiment that can falsify a hypothesis.
6. **Evidence Graph** — every claim points to observations, controls, replay steps and model state.
7. **Adversarial Court + Quality Gate** — publication is harder than discovery.
8. **Holdout League** — unknown applications and negative controls determine the real score.
9. **Resource Accounting** — latency and eventually model/tool cost per confirmed finding.
10. **Regression Memory** — every false positive and false negative becomes a permanent challenge.

## Development order

The next milestones are deliberately ordered by scientific value, not feature count:

- M1: blind arena + strict loopback boundary + multidimensional scoring
- M2: observation/event schema and provenance-backed world model
- M3: local browser/API exploration adapter for controlled lab apps
- M4: hypothesis portfolio + falsification planner
- M5: replayable evidence bundles and automatic negative controls
- M6: diverse local holdout applications with hidden labels
- M7: benchmark dashboard and per-family scorecards

Until M6 produces strong holdout results, APEX must not claim parity or superiority to any external autonomous security product.
