# Changelog

All notable changes to APEX are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-10-16

First packaged release published to PyPI as `apex-bounty`.

### Added
- **Distribution**: `apex-bounty` is now installable via `pip` / `pipx`; ships the
  `apex` and `apex-auto` console entry points.
- PyPI metadata: trove classifiers, project URLs (repository, issues, changelog).
- Automated release workflow (`.github/workflows/release.yml`) that builds and
  publishes to PyPI via OIDC Trusted Publishing on every `v*` tag.
- Hybrid Go core (`core/`, `cmd/apex-core/`) and agent orchestration bridge.
- Loopback-only autonomous lab solver with XBEN proof-of-concept.
- Offline, network-free demo walkthrough (`docs/DEMO.md`).

### Core platform (as of 1.2.0)
- Scope-first, fail-closed authorization model with per-host rate limiting.
- Modules: recon, non-destructive web checks, secrets, mobile (APK static),
  LLM red-team (agentstrike), active `webvuln` (SQLi/XSS/exposed-files).
- ASCEND logic-vulnerability engine (AWM graph + evidence/falsification).
- Orchestrator, quality/CVSS scoring, Markdown/HTML reporting.
- MCP interface for AI-assisted workflows.
- 140 passing tests; green CI; pure-stdlib core (zero runtime dependencies).

[1.2.0]: https://github.com/nadirzhon/apex/releases/tag/v1.2.0
