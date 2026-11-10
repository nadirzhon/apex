"""Неразрушающие веб-проверки: заголовки безопасности, флаги cookie, TLS,
экспонированные чувствительные файлы. Только безопасные GET/HEAD, rate-limited,
строго внутри scope. Никакой эксплуатации, фаззинга или изменения состояния."""
from __future__ import annotations

import datetime as dt
import socket
import ssl
from urllib.parse import urlparse

from ..http import SafeHTTP
from ..models import Finding
from ..scope import Scope
from ..store import Store

# Заголовок → (описание, ремедиация, CVSS-вектор при отсутствии)
SEC_HEADERS = {
    "strict-transport-security": (
        "Отсутствует HSTS — возможна деградация до HTTP (MITM/downgrade).",
        "Добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "content-security-policy": (
        "Отсутствует Content-Security-Policy — ослаблена защита от XSS.",
        "Внедрите строгую CSP (default-src 'self', без unsafe-inline).",
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "x-frame-options": (
        "Нет X-Frame-Options/frame-ancestors — риск clickjacking.",
        "Установите X-Frame-Options: DENY или CSP frame-ancestors 'none'.",
        "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
    "x-content-type-options": (
        "Нет X-Content-Type-Options: nosniff — MIME-sniffing.",
        "Добавьте X-Content-Type-Options: nosniff.",
        "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
}

# Курируемый список широко известных экспонируемых файлов. НЕ брутфорс —
# небольшой набор индикаторов утечки, каждый проверяется одним GET.
SENSITIVE_PATHS = {
    "/.git/HEAD": ("Экспонирован каталог .git — утечка исходного кода/истории.",
                   "Закройте доступ к .git на веб-сервере.",
                   "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", b"ref:"),
    "/.env": ("Экспонирован .env — вероятна утечка секретов/кред.",
              "Уберите .env из веб-корня, ротацию секретов.",
              "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", b"="),
    "/.well-known/security.txt": ("security.txt присутствует (информативно, не уязвимость).",
                                  "—", "", b"Contact"),
    "/server-status": ("Открыт Apache server-status — утечка внутренней инфы.",
                       "Ограничьте mod_status по IP.",
                       "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", b"Apache Server Status"),
    "/actuator/health": ("Открыт Spring Actuator — возможна утечка метрик/энвов.",
                         "Ограничьте /actuator, отключите чувствительные эндпоинты.",
                         "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", b'"status"'),
    "/swagger.json": ("Открыта спецификация API (Swagger/OpenAPI).",
                      "Ограничьте доступ к спецификации в проде.", "", b'"swagger"'),
}

# Путь, которого почти наверняка нет — базовая линия для детекта soft-404 / SPA
# catch-all (сайт отдаёт 200+index.html на любой путь). Один запрос на хост.
SOFT404_PROBE = "/apex-nonexistent-7f3qz9a1"

# Произвольный «чужой» Origin для проверки CORS. Не принадлежит цели — если сервер
# отражает его в Access-Control-Allow-Origin, доверие к Origin сломано.
CORS_PROBE_ORIGIN = "https://apex-cors-probe.attacker.example"


def _cors_findings(url: str, http: SafeHTTP) -> list[Finding]:
    """Пассивный детект небезопасной CORS-конфигурации.

    Отправляем один GET с произвольным чужим Origin и один с Origin: null,
    смотрим Access-Control-Allow-Origin (ACAO) и -Allow-Credentials (ACAC).
    Опасно, когда сервер отражает ПРОИЗВОЛЬНЫЙ Origin (или null) ВМЕСТЕ с
    credentials: любой сайт атакующего читает ответы с данными жертвы.
    Чистый GET, состояние не меняется — безопасно в baseline."""
    out: list[Finding] = []
    r = http.get(url, headers={"Origin": CORS_PROBE_ORIGIN})
    if not r.status:
        return out
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

    if acao == CORS_PROBE_ORIGIN:
        if acac:
            out.append(Finding(
                title="CORS: отражение произвольного Origin с credentials",
                severity="high", target=url, module="web",
                description="Сервер отражает любой переданный Origin в ACAO и ставит "
                            "Allow-Credentials: true — чужой сайт читает ответы с данными "
                            "аутентифицированной жертвы (межсайтовое чтение).",
                evidence=f"Origin: {CORS_PROBE_ORIGIN} → ACAO: {acao}; ACAC: true",
                remediation="Сверяй Origin со строгим allowlist; никогда не отражай "
                            "произвольный Origin вместе с Allow-Credentials.",
                cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            ))
        else:
            out.append(Finding(
                title="CORS: отражение произвольного Origin (без credentials)",
                severity="medium", target=url, module="web",
                description="Сервер отражает любой Origin в ACAO. Без credentials читаются "
                            "только неаутентифицированные данные — impact нужно доказать.",
                evidence=f"Origin: {CORS_PROBE_ORIGIN} → ACAO: {acao}; ACAC: отсутствует",
                remediation="Отражай только Origin из строгого allowlist.",
                cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
            ))
    elif acao == "*" and acac:
        out.append(Finding(
            title="CORS: wildcard ACAO вместе с Allow-Credentials",
            severity="low", target=url, module="web",
            description="ACAO: * одновременно с Allow-Credentials: true — невалидная "
                        "комбинация (браузер её игнорирует), но признак неверной CORS-настройки.",
            evidence="ACAO: *; ACAC: true",
            remediation="Убери Allow-Credentials при wildcard либо задай строгий allowlist.",
            cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        ))

    # Origin: null (эксплуатируется из sandboxed iframe / data: документа)
    rn = http.get(url, headers={"Origin": "null"})
    if rn.status and rn.headers.get("access-control-allow-origin", "") == "null" \
            and rn.headers.get("access-control-allow-credentials", "").strip().lower() == "true":
        out.append(Finding(
            title="CORS: разрешён Origin null с credentials",
            severity="high", target=url, module="web",
            description="ACAO: null + Allow-Credentials: true. Origin null достижим из "
                        "sandboxed iframe — атакующий читает аутентифицированные ответы.",
            evidence="Origin: null → ACAO: null; ACAC: true",
            remediation="Никогда не доверяй Origin: null; используй строгий allowlist.",
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        ))
    return out


def _is_real_exposure(r, baseline, marker: bytes) -> bool:
    """Отличить реально экспонированный файл от soft-404 / SPA catch-all.

    На сайтах, где любой путь возвращает 200 (SPA/кастомный 404), сам по себе
    статус 200 — не доказательство. Тогда требуем, чтобы ответ был специфичен
    для файла, а не повторял общую оболочку приложения."""
    if r.status != 200:
        return False
    catch_all = baseline is not None and baseline.status == 200
    if marker:
        if marker not in r.body:
            return False
        # на catch-all маркер должен отличать файл от общей оболочки
        if catch_all and baseline.body and marker in baseline.body:
            return False
        return True
    # без маркера: на catch-all нужен content-type, отличный от оболочки
    if catch_all:
        ct = r.headers.get("content-type", "").lower()
        base_ct = baseline.headers.get("content-type", "").lower()
        if "html" in ct and "html" in base_ct:
            return False
    return True


def _tls_finding(host: str, port: int = 443) -> Finding | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
    except (OSError, ssl.SSLError):
        return None
    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        return None
    try:
        exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    days = (exp - dt.datetime.utcnow()).days
    if days < 0:
        return Finding(
            title="TLS-сертификат просрочен", severity="high", target=host,
            module="web", description=f"Сертификат истёк {abs(days)} дн. назад.",
            evidence=f"notAfter={not_after}, protocol={proto}",
            remediation="Обновите сертификат; включите авто-ротацию (ACME).",
            cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        )
    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        return Finding(
            title=f"Устаревший протокол TLS ({proto})", severity="medium",
            target=host, module="web", evidence=f"negotiated={proto}",
            description="Сервер согласовал устаревшую версию TLS.",
            remediation="Отключите TLS<1.2, включите только TLS1.2/1.3.",
            cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )
    return None


def run(scope: Scope, store: Store, http: SafeHTTP, authorized: bool,
        targets: list[str] | None = None) -> list[Finding]:
    scope.assert_ready(authorized)
    findings: list[Finding] = []

    urls = targets or [a.value for a in store.assets.values() if a.kind == "url"]
    for url in urls:
        scope.guard(url)                      # fail-closed на каждую цель
        host = urlparse(url).hostname or ""

        base = http.get(url)
        if base.status:
            # заголовки безопасности
            for hdr, (desc, rem, vec) in SEC_HEADERS.items():
                if hdr not in base.headers:
                    findings.append(Finding(
                        title=f"Отсутствует заголовок: {hdr}", severity="low",
                        target=url, module="web", description=desc,
                        evidence=f"GET {url} → заголовок '{hdr}' не найден",
                        remediation=rem, cvss_vector=vec,
                    ))
            # флаги cookie
            sc = base.headers.get("set-cookie", "")
            if sc and ("secure" not in sc.lower() or "httponly" not in sc.lower()):
                findings.append(Finding(
                    title="Cookie без флагов Secure/HttpOnly", severity="low",
                    target=url, module="web",
                    evidence=f"Set-Cookie: {sc[:120]}",
                    description="Кука без Secure/HttpOnly — риск перехвата/XSS-кражи.",
                    remediation="Добавьте Secure; HttpOnly; SameSite=Lax/Strict.",
                    cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                ))

            # CORS: небезопасное доверие к Origin (пассивно, чистый GET)
            findings.extend(_cors_findings(url, http))

        # базовая линия soft-404 / SPA catch-all: один запрос по несуществующему пути
        baseline = http.get(url.rstrip("/") + SOFT404_PROBE)

        # экспонированные файлы
        for path, (desc, rem, vec, marker) in SENSITIVE_PATHS.items():
            probe = url.rstrip("/") + path
            scope.guard(probe)
            r = http.get(probe)
            if _is_real_exposure(r, baseline, marker):
                sev = "info" if not vec else "high"
                note = " (отличается от soft-404 базовой линии)" if baseline.status == 200 else ""
                findings.append(Finding(
                    title=f"Экспонирован {path}", severity=sev,
                    target=probe, module="web", description=desc,
                    evidence=f"GET {probe} → 200 ({len(r.body)} байт){note}",
                    remediation=rem, cvss_vector=vec,
                ))

        # TLS
        if host and url.startswith("https"):
            tf = _tls_finding(host)
            if tf:
                findings.append(tf)

    for f in findings:
        store.add_finding(f)
    return findings
