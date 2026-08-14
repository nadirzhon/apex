# APEX Autopilot

APEX Autopilot connects the existing scope gate, discovery modules, controlled
account replay, report generator and advisor into one declarative engagement.

It is intended only for bug-bounty / VDP / pentest targets you are explicitly
authorized to test. The existing `authorized:true` scope field and
`--i-am-authorized` runtime confirmation are still mandatory.

## 1. Prepare the program scope

Use the same scope format as the rest of APEX. Example:

```json
{
  "program": "Example Corp — Public Bug Bounty",
  "platform": "hackerone",
  "authorized": true,
  "researcher": "you",
  "rate_limit_rps": 2,
  "in_scope": ["*.example.com"],
  "out_of_scope": ["status.example.com"],
  "rules": "No DoS, no social engineering, no credential brute force."
}
```

## 2. Create one engagement manifest

See `examples/engagement.example.json`.

Safe default:

```json
{
  "name": "Example Corp authorized bounty",
  "scope_file": "program.example.json",
  "targets": ["https://example.com"],
  "modules": ["recon", "web", "secrets"],
  "har_files": [],
  "accounts": {},
  "policy": {
    "active_web_validation": false,
    "crawl_active_targets": false,
    "minimum_report_severity": "medium"
  }
}
```

## 3. Optional controlled test account

Autopilot never stores account cookies or tokens in the manifest. Reference an
environment variable instead:

```json
{
  "accounts": {
    "attacker": {"headers_env": "APEX_ATTACKER_HEADERS"}
  }
}
```

Then provide the header locally:

```sh
export APEX_ATTACKER_HEADERS='{"Cookie":"session=YOUR_TEST_ACCOUNT_COOKIE"}'
```

For `ascend_har`, the baseline request/session comes from your HAR capture and
`accounts.attacker` supplies the second controlled test account. Only your own
accounts should be used.

## 4. Run

Installed entrypoint:

```sh
apex-auto --manifest examples/engagement.example.json --i-am-authorized
```

Without installation:

```sh
python -m apex.auto_cli --manifest examples/engagement.example.json --i-am-authorized
```

Outputs are written to the manifest's `out_dir` and `state_file`:

- `state.json` — discovered assets and findings
- `report.md` — Markdown report
- `report.html` — HTML report
- `advisor.txt` — prioritized next-action / evidence guidance

## Module behavior

- `recon` — scope-derived asset discovery
- `web` — non-destructive web checks
- `secrets` — exposed-secret discovery with existing masking behavior
- `ascend_har` — controlled authorization replay from a HAR using a second test account
- `webvuln` — active validation; rejected unless `policy.active_web_validation=true`

Active validation remains an explicit local policy decision because bug-bounty
program rules differ. Scope authorization alone does not imply that every active
technique is permitted.

## Fail-closed properties

Before network work Autopilot:

1. loads the referenced scope,
2. requires `authorized:true`,
3. requires `--i-am-authorized`,
4. guards every configured target,
5. refuses unknown modules,
6. refuses active validation unless it was explicitly enabled in the engagement policy,
7. resolves account secrets only from environment variables at runtime.

The goal is a one-command engagement after you have supplied the program rules,
scope and your controlled test-account material — not a bypass around those rules.
