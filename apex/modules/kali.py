"""Мост APEX → контейнер apex-kali (полный bug-bounty арсенал в Docker).

APEX (на хосте) дирижирует боевыми инструментами внутри Kali-контейнера через
`docker run`, нормализует их вывод в Finding и держит всё под scope-гейтом.
Заточка под заработок: не «весь Kali», а рабочий цикл —
  subfinder → ffuf (скрытая поверхность) → nuclei (уязвимости) → sqlmap (эксплуатация).

Все функции активны (шлют пробы по цели) → работают только in-scope и с
--i-am-authorized; каждая цель проходит scope.guard (fail-closed).
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..models import Finding
from ..scope import Scope
from ..store import Store

KALI_IMAGE = "apex-kali:latest"
FFUF_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

_SEV_CVSS = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "info": "",
}


def kali_available() -> bool:
    """Есть ли docker и собранный образ apex-kali."""
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "images", "-q", KALI_IMAGE],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def _docker_run(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Запустить инструмент внутри apex-kali. args — команда с аргументами."""
    return subprocess.run(
        ["docker", "run", "--rm", KALI_IMAGE] + args,
        capture_output=True, text=True, timeout=timeout,
    )


# ── subfinder: карта поддоменов (пассивно) ───────────────────────────────
def run_subfinder(scope: Scope, store: Store, authorized: bool,
                  domain: str, *, timeout: int = 180) -> list[str]:
    scope.assert_ready(authorized)
    scope.guard(domain)
    from ..models import Asset
    r = _docker_run(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    subs = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    for s in subs:
        try:
            store.add_asset(Asset(kind="url", value=f"https://{s}"))
        except Exception:
            pass
    return subs


# ── ffuf: content discovery (скрытая поверхность → серьёзные баги) ────────
def run_ffuf(scope: Scope, store: Store, authorized: bool,
             base_url: str, *, wordlist: str = FFUF_WORDLIST,
             timeout: int = 300) -> list[Finding]:
    scope.assert_ready(authorized)
    scope.guard(base_url)
    url = base_url.rstrip("/") + "/FUZZ"
    rate = str(int(scope.rate_limit_rps * 10) or 20)
    # ffuf пишет JSON в файл внутри контейнера, забираем cat'ом в той же команде
    cmd = (f"ffuf -u {url} -w {wordlist} -mc 200,204,301,302,307,401,403 "
           f"-of json -o /tmp/ffuf.json -s -rate {rate} >/dev/null 2>&1; cat /tmp/ffuf.json")
    r = _docker_run(["bash", "-c", cmd], timeout=timeout)
    findings: list[Finding] = []
    try:
        data = json.loads(r.stdout or "{}")
        results = data.get("results", [])
    except json.JSONDecodeError:
        results = []
    for item in results:
        path = item.get("input", {}).get("FUZZ", "")
        code = item.get("status", 0)
        full = item.get("url", f"{base_url}/{path}")
        # интересные коды: 401/403 (закрытая зона), 200 на sensitive-путях
        sev = "medium" if code in (401, 403) or any(
            k in path.lower() for k in ("admin", "config", "backup", "api", "debug", ".git", "internal")
        ) else "info"
        findings.append(Finding(
            title=f"[ffuf] Обнаружен путь /{path} (HTTP {code})",
            severity=sev,
            target=full,
            module="kali/ffuf",
            description="Content discovery: скрытый/недокументированный endpoint. "
                        "Проверь вручную — забытые API и админки часто ведут к серьёзным багам.",
            evidence=f"URL: {full}\nHTTP {code}\nдлина: {item.get('length', '?')}",
            remediation="Убери/закрой служебные пути; не полагайся на secrecy-by-obscurity.",
            cvss_vector=_SEV_CVSS.get(sev, ""),
        ))
    for f in findings:
        store.add_finding(f)
    return findings


# ── nuclei: 5000+ шаблонов через контейнер ───────────────────────────────
def run_nuclei(scope: Scope, store: Store, authorized: bool,
               target: str, *, timeout: int = 600) -> list[Finding]:
    scope.assert_ready(authorized)
    scope.guard(target)
    r = _docker_run(
        ["nuclei", "-u", target, "-jsonl", "-silent", "-nc",
         "-rl", str(int(scope.rate_limit_rps) or 2)],
        timeout=timeout,
    )
    findings: list[Finding] = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {})
        sev = str(info.get("severity", "info")).lower()
        findings.append(Finding(
            title=f"[nuclei] {info.get('name', j.get('template-id', 'finding'))}",
            severity=sev,
            target=j.get("matched-at") or target,
            module="kali/nuclei",
            description=f"template: {j.get('template-id', '')}. "
                        + (info.get("description", "") or "")[:300],
            evidence=f"matched-at: {j.get('matched-at', '')}\ntemplate: {j.get('template-id', '')}",
            remediation=(info.get("remediation", "") or "")[:400],
            cvss_vector=_SEV_CVSS.get(sev, ""),
        ))
    for f in findings:
        store.add_finding(f)
    return findings


# ── sqlmap: эксплуатация через контейнер ─────────────────────────────────
def run_sqlmap(scope: Scope, store: Store, authorized: bool,
               target: str, *, timeout: int = 600) -> list[Finding]:
    scope.assert_ready(authorized)
    scope.guard(target)
    r = _docker_run(
        ["sqlmap", "-u", target, "--batch", "--smart", "--level", "1", "--risk", "1"],
        timeout=timeout,
    )
    out = r.stdout
    findings: list[Finding] = []
    if "is vulnerable" in out or "sqlmap identified" in out.lower():
        dbms = ""
        if "back-end DBMS:" in out:
            dbms = out.split("back-end DBMS:", 1)[1].splitlines()[0].strip()
        keep = [s.strip() for s in out.splitlines()
                if any(k in s for k in ("Parameter:", "Type:", "Title:", "Payload:"))]
        findings.append(Finding(
            title=f"[sqlmap] SQL injection подтверждена ({dbms or 'DBMS не назван'})",
            severity="critical",
            target=target,
            module="kali/sqlmap",
            description="sqlmap подтвердил инъекцию активной эксплуатацией (без выгрузки чужих данных).",
            evidence="\n".join(keep[:20]) or "инъекция подтверждена",
            remediation="Параметризованные запросы/ORM; без конкатенации ввода в SQL.",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ))
    for f in findings:
        store.add_finding(f)
    return findings
