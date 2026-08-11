"""Дирижёр боевых инструментов (Kali-класс): nuclei, sqlmap, ffuf, nmap.

Вместо самописных проверок APEX оркеструет индустриальные инструменты —
их держит в форме мировое сообщество, у них тысячи шаблонов и реальная
эксплуатация. APEX добавляет то, чего у них поодиночке нет: единый
scope-гейт (fail-closed на каждую цель), нормализацию вывода в Finding+CVSS,
приоритизацию по деньгам (advise) и один отчёт под программу.

ВСЕ инструменты здесь активны (шлют пробы/эксплуатируют), поэтому работают
только внутри scope и с --i-am-authorized. Каждый вызов — через scope.guard.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..models import Finding
from ..scope import Scope
from ..store import Store

_SEV_CVSS = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "info": "",
}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


# ── nuclei: 5000+ шаблонов уязвимостей ───────────────────────────────────
def run_nuclei(scope: Scope, store: Store, authorized: bool,
               targets: list[str], *, timeout: int = 300) -> list[Finding]:
    scope.assert_ready(authorized)
    if not have("nuclei"):
        raise RuntimeError("nuclei не установлен (brew install nuclei).")
    findings: list[Finding] = []
    for url in targets:
        scope.guard(url)
        proc = subprocess.run(
            ["nuclei", "-u", url, "-jsonl", "-silent", "-nc",
             "-rate-limit", str(int(scope.rate_limit_rps) or 2)],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = r.get("info", {})
            sev = str(info.get("severity", "info")).lower()
            findings.append(Finding(
                title=f"[nuclei] {info.get('name', r.get('template-id', 'finding'))}",
                severity=sev,
                target=r.get("matched-at") or r.get("host") or url,
                module="arsenal/nuclei",
                description=f"template: {r.get('template-id', '')}. "
                            + (info.get("description", "") or "")[:300],
                evidence=f"matched-at: {r.get('matched-at', '')}\n"
                         f"type: {r.get('type', '')}\ntemplate: {r.get('template-id', '')}",
                remediation=(info.get("remediation", "") or "")[:400],
                cvss_vector=_SEV_CVSS.get(sev, ""),
                references=(info.get("reference") or [])[:5]
                           if isinstance(info.get("reference"), list) else [],
            ))
    for f in findings:
        store.add_finding(f)
    return findings


# ── sqlmap: реальная эксплуатация SQLi до доказательства ──────────────────
def run_sqlmap(scope: Scope, store: Store, authorized: bool,
               targets: list[str], *, timeout: int = 600) -> list[Finding]:
    scope.assert_ready(authorized)
    if not have("sqlmap"):
        raise RuntimeError("sqlmap не установлен (brew install sqlmap).")
    findings: list[Finding] = []
    for url in targets:
        scope.guard(url)
        # --batch: без вопросов; безопасный уровень, без дампа чужих данных
        proc = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--smart", "--level", "1",
             "--risk", "1", "--flush-session", "--answers=crack=N,dict=N"],
            capture_output=True, text=True, timeout=timeout,
        )
        out = proc.stdout
        if "is vulnerable" in out or "sqlmap identified the following injection" in out.lower():
            # вытащим тип инъекции и СУБД, если sqlmap их назвал
            dbms = ""
            for marker in ("back-end DBMS:", "the back-end DBMS is"):
                if marker in out:
                    dbms = out.split(marker, 1)[1].splitlines()[0].strip()
                    break
            findings.append(Finding(
                title=f"[sqlmap] SQL injection подтверждена ({dbms or 'DBMS не назван'})",
                severity="critical",
                target=url,
                module="arsenal/sqlmap",
                description="sqlmap подтвердил инъекцию активной эксплуатацией. "
                            "Доказательство — управляемость запроса, без выгрузки чужих данных.",
                evidence=_excerpt_sqlmap(out),
                remediation="Параметризованные запросы/ORM; никакой конкатенации ввода в SQL.",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ))
    for f in findings:
        store.add_finding(f)
    return findings


def _excerpt_sqlmap(out: str) -> str:
    """Собрать компактное доказательство из вывода sqlmap (тип инъекции, payload)."""
    keep = []
    for ln in out.splitlines():
        s = ln.strip()
        if any(k in s for k in ("Parameter:", "Type:", "Title:", "Payload:", "back-end DBMS")):
            keep.append(s)
    return "\n".join(keep[:20]) or "sqlmap подтвердил инъекцию (детали в полном логе)."
