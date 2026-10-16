# APEX — demo walkthrough

A reproducible, **offline** walkthrough using the bundled example scope in
[`examples/`](../examples/). No network access and no credentials are required —
every command below runs against the shipped `program.example.json`.

> APEX is for **authorized** testing only. The example program is fictional
> (`*.example.com`) and exists purely to demonstrate the workflow.

## 1. Inspect the scope (fail-closed policy object)

```console
$ python3 -m apex.cli --scope examples/program.example.json scope
программа: Example Corp — Public Bug Bounty (hackerone)
authorized: True  researcher: nadirzhon
in_scope: *.example.com, api.example.com, com.example.mobile
out_of_scope: blog.example.com, *.staging.example.com, status.example.com
rate_limit: 2.0 rps
rules: Только неразрушающее тестирование. Запрещены DoS, соц.инженерия, спам ...
```

## 2. List run profiles and plan a run (no network)

```console
$ python3 -m apex.cli orchestrate --list-profiles
baseline         web → secrets → quality
passive          recon → secrets → quality
fast-baseline    go-recon → web → secrets → quality
offline-review   quality

$ python3 -m apex.cli --scope examples/program.example.json --i-am-authorized \
      orchestrate --profile baseline --dry-run
[orchestrator] план: web → secrets → quality
    planned  web
    planned  secrets
    planned  quality
```

`--dry-run` shows the plan without touching the network — useful for reviewing
exactly what would run before authorizing active work.

## 3. Generate a report (offline-review profile)

The `offline-review` profile runs only the non-network `quality` stage, so it
works anywhere and produces a real Markdown + HTML report:

```console
$ python3 -m apex.cli --scope examples/program.example.json \
      orchestrate --profile offline-review
[orchestrator] план: quality
  completed  quality — 2 мс
[orchestrator] отчёт: .apex/report.md · .apex/report.html
```

Resulting `.apex/report.md`:

```markdown
# Отчёт APEX — Example Corp — Public Bug Bounty

- **Платформа:** hackerone
- **Исследователь:** nadirzhon
- **Активов:** 0  ·  **Находок:** 0

## Находки
_Находок нет._

> Отчёт сгенерирован APEX в рамках авторизованного тестирования ...
```

## 4. The authorization gate

Active and network-touching modules call `scope.assert_ready(authorized)` before
doing any work. Running them without `--i-am-authorized`, or against a target
that is out of scope, **fails closed** — the request never leaves the machine.
Offline review (no network, no active checks) is allowed without the flag, which
is why step 3 works without `--i-am-authorized`.

## Next steps

- Point `--scope` at your own program file (see
  [`examples/program.example.json`](../examples/program.example.json)).
- For a full authorized run against in-scope targets:
  `apex --scope program.json --i-am-authorized orchestrate --profile baseline --json`
- Drive the same policy boundary from an AI assistant via the MCP server
  (`python -m apex.mcp_server`) — see the README.
