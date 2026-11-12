# Changelog

All notable changes to APEX are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Program-mandated identification headers on every request.** Many programs require
  test traffic to carry a header such as `X-HackerOne-Research: <username>`.
  - `SafeHTTP(default_headers=...)`: headers are merged as `User-Agent` → client
    defaults → per-call headers (later wins, names compared case-insensitively) and are
    sent on every request, including every followed redirect hop. Without
    `default_headers` behaviour is unchanged.
  - Engagement manifest: optional `http_headers` object, passed by Autopilot to the one
    client shared by `recon`, `web`, `secrets`, `webprobe` and HAR replay.
  - `http_headers` is validated fail-closed at load: string name/value, valid header
    token, non-empty single-line value (no CR/LF), no duplicates; `Cookie`,
    `Authorization`, `Host` and framing headers are refused — credentials still go only
    through `accounts.*.headers_env`.
  - A manifest that sets `http_headers` together with the `webvuln` module is refused:
    the external scanner has its own HTTP stack and would not send them.

### Fixed
- **One broken host no longer aborts the whole engagement.** `SafeHTTP.get` let
  connection-level failures escape (`http.client.RemoteDisconnected` from a host that
  closes the connection without answering crashed an Autopilot run inside `recon`
  before any artifact was written). Every `OSError` (connection reset/refused/aborted,
  timeouts, TLS errors, DNS failures) and `http.client.HTTPException` (remote
  disconnect, bad status line, incomplete read, …) — on the first request or on a
  redirect hop — now yields `Response(status=0, error=...)`, the same as an unreachable
  host. Successful requests, throttling, scope checks and redirects are unchanged.

## [1.3.0] — 2026-11-12

### Added
- **CORS misconfiguration detector** (`web` module, passive): flags reflection of an
  arbitrary `Origin` and `Origin: null` together with `Allow-Credentials: true`
  (cross-origin read of authenticated data — marked ELIGIBLE). Pure GET, runs in the
  default baseline.
- **Open-redirect detector** (`webprobe` module, active, gated behind
  `policy.active_web_validation`): mutates only pre-existing redirect-style parameters
  to a benign canary host and inspects the `Location` header without following the
  redirect. CLI: `apex webprobe --target <url>`.
- **Subdomain-takeover detection** (`recon` module, passive): a finding is confirmed by
  two independent signals — a dangling-service "claim this / not found" signature in the
  response (GitHub Pages, S3, Heroku, Fastly, Shopify, …) **and** the host's CNAME chain
  pointing at that service's domain (`github.io`, `s3*.amazonaws.com`, `herokuapp.com`, …).
  A marker without a matching CNAME is never reported as a takeover: generic markers
  yield nothing, service-unique phrases yield a low-severity "CNAME not confirmed" note
  (not ELIGIBLE). The resolver is injectable (`recon.run(..., cname_resolver=...)`);
  the default uses the stdlib, runs only after a marker matched, and a missing or
  failing resolver degrades to the low-confidence path instead of crashing.
- Advisor playbooks and HackerOne-eligibility routing for CORS, open redirect and
  subdomain takeover.

### Changed
- `SafeHTTP.get` gains `allow_redirects` (default `True`); `False` returns the raw
  3xx response without following `Location` (fixes the "no cross-host redirect
  following" promise in the client docstring).

### Fixed
- **Subdomain-takeover false negative**: `SafeHTTP.get` discarded the body of 4xx/5xx
  responses, so the fingerprints never matched in real runs — dangling services answer
  with 404/5xx. Error bodies are now kept (GET only, still capped by `max_bytes`, no
  extra requests).
- **Subdomain-takeover false positive**: generic markers (`NoSuchBucket`,
  `Repository not found`, `project not found`, `Please renew your subscription`) fired
  on any live page that merely mentioned them and produced a critical finding. They now
  require an error status (>= 400) in addition to the CNAME match, so a host's own 404
  page saying "Repository not found" is no longer reported. Evidence includes the HTTP
  status and the matched CNAME.
- **Exposed-file false positives on soft-404 / SPA catch-all sites**: the `web` module
  takes a baseline from a non-existent path and requires the response to differ from the
  generic shell; markers for `server-status`, Actuator and Swagger were tightened.
- **Open-redirect probe crash**: a malformed `Location` (e.g. an unterminated IPv6
  literal) raised `ValueError` and aborted the whole `webprobe` run; it is now treated
  as "not a redirect to the canary".

### Security
- Redirects are scope-checked on every hop: `SafeHTTP(in_scope=...)` refuses to follow a
  `Location` that leaves scope and returns the 3xx response instead (fail-closed). Wired
  into the CLI, autopilot and MCP server clients.
- **Rate limit applies to every redirect hop**: followed redirects previously went out
  back-to-back, so a chain of N redirects sent N extra requests past
  `rate_limit_rps`. Each hop (same host or a different one) now waits for the client's
  throttle like any other request; the scope check still runs first, so a refused
  out-of-scope hop costs no slot. The limiter stays a single per-client one shared by
  all hosts, which is stricter than a per-host limit.

### Tests
- 188 new offline tests for the detectors' edge cases (error-body handling on a
  loopback server, every takeover fingerprint, CNAME confirmation with a stub resolver
  (no real DNS), status gating, end-to-end `recon.run`,
  `Location` parsing, multi-parameter and non-3xx open-redirect cases, redirect-hop
  throttling with a fake clock and server-side timestamps).

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
