"""Генерация отчёта под программу bug bounty: Markdown + HTML.
Каждая находка — с доказательством, CVSS и ремедиацией."""
from __future__ import annotations

import datetime as dt
import html
from pathlib import Path

from .models import Finding
from .scope import Scope
from .store import Store

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RU = {"critical": "критическая", "high": "высокая", "medium": "средняя",
       "low": "низкая", "info": "инфо"}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDER.get(f.severity, 9), -f.cvss_score))


def markdown(scope: Scope, store: Store) -> str:
    fs = _sorted(store.findings)
    counts = store.by_severity()
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Отчёт APEX — {scope.program or 'программа'}",
        "",
        f"- **Платформа:** {scope.platform or '—'}",
        f"- **Исследователь:** {scope.researcher or '—'}",
        f"- **Дата:** {now}",
        f"- **Активов:** {len(store.assets)}  ·  **Находок:** {len(fs)}",
        "",
        "## Сводка по серьёзности",
        "",
        "| Серьёзность | Кол-во |",
        "|---|---|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"| {_RU[sev]} | {counts[sev]} |")
    lines += ["", "## Находки", ""]
    if not fs:
        lines.append("_Находок нет._")
    for i, f in enumerate(fs, 1):
        cvss = f" · CVSS {f.cvss_score}" if f.cvss_score else ""
        lines += [
            f"### {i}. {f.title}  ",
            f"**Серьёзность:** {_RU.get(f.severity, f.severity)}{cvss}  ",
            f"**Цель:** `{f.target}`  ·  **Модуль:** {f.module}  ",
            "",
        ]
        if f.cvss_vector:
            lines.append(f"**CVSS-вектор:** `{f.cvss_vector}`  ")
        if f.review_status != "unreviewed":
            lines.append(
                f"**Качество доказательств:** {f.quality_score}/100 · "
                f"`{f.review_status}`  "
            )
            if f.review_notes:
                lines.append("**Что дополнить:** " + "; ".join(f.review_notes) + "  ")
        if f.description:
            lines += ["", f.description, ""]
        if f.evidence:
            lines += ["**Доказательство:**", "```", f.evidence, "```", ""]
        if f.remediation:
            lines += [f"**Ремедиация:** {f.remediation}", ""]
        lines.append("---")
    lines += [
        "",
        "> Отчёт сгенерирован APEX в рамках авторизованного тестирования "
        f"по scope программы «{scope.program}». Все проверки неразрушающие.",
    ]
    return "\n".join(lines)


def html_report(scope: Scope, store: Store) -> str:
    fs = _sorted(store.findings)
    color = {"critical": "#B3123B", "high": "#C0392B", "medium": "#C77B12",
             "low": "#2C7A4B", "info": "#556"}
    rows = []
    for i, f in enumerate(fs, 1):
        c = color.get(f.severity, "#556")
        rows.append(f"""
        <article class="f">
          <div class="badge" style="background:{c}">{html.escape(_RU.get(f.severity, f.severity))}
            {(' · CVSS ' + str(f.cvss_score)) if f.cvss_score else ''}</div>
          <h3>{i}. {html.escape(f.title)}</h3>
          <p class="meta"><code>{html.escape(f.target)}</code> · {html.escape(f.module)}</p>
          {f'<p>{html.escape(f.description)}</p>' if f.description else ''}
          {f'<pre>{html.escape(f.evidence)}</pre>' if f.evidence else ''}
          {f'<p class="rem"><b>Ремедиация:</b> {html.escape(f.remediation)}</p>' if f.remediation else ''}
          {f'<p class="vec"><b>CVSS:</b> <code>{html.escape(f.cvss_vector)}</code></p>' if f.cvss_vector else ''}
          {f'<p class="vec"><b>Качество доказательств:</b> {f.quality_score}/100 · <code>{html.escape(f.review_status)}</code></p>' if f.review_status != 'unreviewed' else ''}
        </article>""")
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APEX — {html.escape(scope.program or 'отчёт')}</title>
<style>
:root{{--ink:#12161c;--mut:#5a6472;--line:#e3e6ea;--bg:#f6f7f9}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.6 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:56rem;margin:0 auto;padding:2.5rem 1.2rem 5rem}}
h1{{font-size:1.9rem;margin:0 0 .3rem}} .sub{{color:var(--mut);margin:0 0 2rem}}
.f{{background:#fff;border:1px solid var(--line);border-radius:8px;padding:1.2rem 1.4rem;margin:1rem 0}}
.badge{{display:inline-block;color:#fff;font-size:.72rem;font-weight:700;letter-spacing:.03em;
text-transform:uppercase;padding:.2rem .6rem;border-radius:4px}}
.f h3{{margin:.6rem 0 .2rem;font-size:1.15rem}} .meta{{color:var(--mut);margin:.1rem 0 .6rem;font-size:.9rem}}
pre{{background:#0e1319;color:#cfe;padding:.8rem 1rem;border-radius:6px;overflow:auto;font-size:.82rem}}
code{{font-family:ui-monospace,Menlo,monospace;font-size:.85em}}
.rem{{color:#2c7a4b}} .vec{{color:var(--mut);font-size:.85rem}}
</style></head><body><div class="wrap">
<h1>APEX — {html.escape(scope.program or 'программа')}</h1>
<p class="sub">{html.escape(scope.platform or '')} · исследователь {html.escape(scope.researcher or '—')}
· {now} · находок: {len(fs)}</p>
{''.join(rows) if rows else '<p>Находок нет.</p>'}
<p class="sub" style="margin-top:2rem">Сгенерировано APEX. Авторизованное тестирование, неразрушающие проверки.</p>
</div></body></html>"""


def write(scope: Scope, store: Store, out_dir: str = ".apex") -> tuple[str, str]:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    md = d / "report.md"
    ht = d / "report.html"
    md.write_text(markdown(scope, store), encoding="utf-8")
    ht.write_text(html_report(scope, store), encoding="utf-8")
    return str(md), str(ht)
