# Changelog

All notable changes to APEX are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **CORS misconfiguration detector** (`web` module, passive): flags reflection of an
  arbitrary `Origin` and `Origin: null` together with `Allow-Credentials: true`
  (cross-origin read of authenticated data — marked ELIGIBLE). Pure GET, runs in the
  default baseline.
- **Open-redirect detector** (`webprobe` module, active, gated behind
  `policy.active_web_validation`): mutates only pre-existing redirect-style parameters
  to a benign canary host and inspects the `Location` header without following the
  redirect. CLI: `apex webprobe --target <url>`.
- **Subdomain-takeover fingerprinting** (`recon` module, passive): detects
  dangling-service "claim this / not found" signatures (GitHub Pages, S3, Heroku,
  Fastly, Shopify, …) on in-scope hosts.
- Advisor playbooks and HackerOne-eligibility routing for CORS, open redirect and
  subdomain takeover.

### Changed
- `SafeHTTP.get` gains `allow_redirects` (default `True`); `False` returns the raw
  3xx response without following `Location` (fixes the "no cross-host redirect
  following" promise in the client docstring).

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
