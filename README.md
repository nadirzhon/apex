# APEX

**Authorized security automation for modern web and AI systems.**

APEX is a scope-first security automation platform that combines reconnaissance, web checks, secrets analysis, mobile analysis, LLM red-team testing, evidence collection and reporting behind explicit authorization gates.

> **Authorized use only.** APEX is designed for bug-bounty programs, VDPs and engagements where the operator has explicit permission to test the target.

## Why it matters

Security automation becomes dangerous when scope and authorization are treated as an afterthought. APEX makes them part of the execution model:

- explicit scope definition
- fail-closed target validation
- authorization confirmation before active testing
- per-host rate limiting
- reproducible findings and evidence
- Markdown/HTML reporting
- MCP interface for AI-assisted workflows

The result is not just a collection of scanners, but an orchestration layer around specialized security agents and tools.

## Architecture

```
                    ┌─────────────────────┐
                    │   Scope / Policy    │
                    │     fail-closed     │
                    └──────────┬──────────┘
                               │
                     ┌─────────▼─────────┐
                     │    Orchestrator   │
                     └─────────┬─────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
       Recon                Web / API          AI Security
          │                    │                    │
       Assets             Findings             agentstrike
          └────────────────────┼────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Evidence / Quality  │
                    │       / CVSS        │
                    └──────────┬──────────┘
                               ▼
                    Markdown / HTML / MCP
```

## Core capabilities

| Area | Capability |
|---|---|
| Scope | JSON programs, in/out-of-scope rules, authorization gates |
| Recon | DNS/HTTP discovery and asset inventory |
| Web | Security headers, TLS, exposed-file checks |
| Secrets | Detection of exposed credentials with masked reporting |
| Mobile | Offline APK analysis |
| AI security | Prompt-injection testing through agentstrike |
| Web vulnerabilities | Authorized SQLi/XSS checks through the web-vuln scanner |
| Orchestration | Agent registry, dependencies, execution history |
| Evidence | Quality gates, reproducible findings, CVSS 3.1 |
| Reporting | Markdown and HTML reports |
| AI integration | MCP server for controlled agent workflows |
| Performance | Optional concurrent Go core with JSONL boundary |

## Quick start

```bash
git clone https://github.com/nadirzhon/apex
cd apex

python3 -m apex.cli --help

# Optional package install
pip install -e .

# Optional MCP support
pip install -e '.[mcp]'
```

Create an explicit scope:

```json
{
  "program": "Example Corp",
  "authorized": true,
  "rate_limit_rps": 2,
  "in_scope": ["*.example.com", "api.example.com"],
  "out_of_scope": ["staging.example.com"]
}
```

Run a baseline workflow:

```bash
apex --scope program.json scope
apex --scope program.json --i-am-authorized orchestrate --profile baseline --json
apex --scope program.json report
```

Without authorization or when a target is outside scope, execution fails closed.

## MCP interface

APEX exposes controlled operations through MCP so an AI assistant can work with the same authorization boundary:

```bash
APEX_SCOPE=program.json APEX_AUTHORIZED=1 python -m apex.mcp_server
```

The MCP layer can inspect scope, run authorized modules, review findings and generate reports without bypassing the policy gate.

## Engineering highlights

- Python standard-library core with optional integrations
- Go concurrent network core for performance-sensitive workloads
- deterministic scope enforcement
- isolated modules and agent specifications
- JSON state and JSONL event contracts
- CVSS 3.1 scoring
- evidence-quality validation
- CLI + MCP interfaces
- designed for reproducible security research rather than blind scanning

## Related projects

- [agentstrike](https://github.com/nadirzhon/agentstrike) — LLM-agent red-team fuzzer
- [mcpscan](https://github.com/nadirzhon/mcpscan) — MCP security scanner
- [offsec-mcp](https://github.com/nadirzhon/offsec-mcp) — authorized security tools exposed to AI agents

## License

MIT. The license does not remove the operator's responsibility to test only systems they are authorized to test.
