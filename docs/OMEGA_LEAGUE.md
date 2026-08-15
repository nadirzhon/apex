# OMEGA League

APEX capability claims must be earned on matched, blind, reproducible evaluation.
Architecture complexity and unit-test count are not capability metrics.

## Why this exists

Recent autonomous-security evaluations expose three recurring failure modes:

1. benchmark scores are inflated when architecture and backbone model change together;
2. CTF-style tasks can overstate real-world performance and can be contaminated by training data;
3. aggregate success hides weak vulnerability families, false positives, cost, and seed variance.

OMEGA League therefore evaluates APEX against a plain-agent baseline with the same
model, task, environment digest, seed, step/time/cost budget, and scoring rule.

## Required protocol

- Keep hidden labels outside the solver context.
- Use train/dev tasks for engineering and a separate holdout split for claims.
- Run every claimed task with multiple seeds.
- Report micro solve rate and macro solve rate across vulnerability families.
- Report invalid findings, valid-submission rate, evidence coverage, scope violations,
  median steps, latency, total cost, and cost per solve.
- Compare against a plain frontier coding-agent baseline under matched budgets.
- Never move benchmark answers, flags, reference exploits, hidden labels, or oracle
  verdicts into persistent memory.
- Preserve append-only traces and environment digests for reproducibility.

## Default claim gate

A capability claim is blocked unless all of the following hold:

- at least 50 unique tasks;
- at least 20 unique holdout tasks;
- at least 5 vulnerability families;
- at least 2 seeds per task;
- holdout solve rate >= 70%;
- valid-submission rate >= 98%;
- evidence coverage >= 98%;
- solve-rate improvement over matched plain baseline >= 5 percentage points;
- holdout improvement over matched baseline >= 5 percentage points;
- zero scope violations.

These are minimum proof requirements, not a claim that APEX is state of the art.
A stronger claim needs a larger external benchmark and published reproducible traces.

## Research-backed next benchmark targets

Use only controlled/local instances and follow each benchmark's license and safety
requirements. Priority evaluation families:

- XBOW-style validation challenges for matched public comparison;
- CVE-Bench for realistic reproducible web-vulnerability tasks;
- AgentCyberRange/TermiBench-style ranges for harder multi-stage evaluation;
- purpose-built negative cases containing catch-all 200s, decoy endpoints, misleading
  headers, inaccessible objects, role boundaries, and workflow traps.

APEX should not be called superior to another system until matched external results
support that statement.
