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
    "/.well-known/security.txt": ("security.txt отсутствует (не уязвимость).",
                                  "Добавьте .well-known/security.txt.", "", b""),
    "/server-status": ("Открыт Apache server-status — утечка внутренней инфы.",
                       "Ограничьте mod_status по IP.",
                       "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", b"Apache"),
    "/actuator/health": ("Открыт Spring Actuator — возможна утечка метрик/энвов.",
                         "Ограничьте /actuator, отключите чувствительные эндпоинты.",
                         "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", b"status"),
    "/swagger.json": ("Открыта спецификация API (Swagger/OpenAPI).",
                      "Ограничьте доступ к спецификации в проде.", "", b"swagger"),
}


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

        # экспонированные файлы
        for path, (desc, rem, vec, marker) in SENSITIVE_PATHS.items():
            probe = url.rstrip("/") + path
            scope.guard(probe)
            r = http.get(probe)
            if r.status == 200 and (not marker or marker in r.body):
                sev = "info" if not vec else "high"
                findings.append(Finding(
                    title=f"Экспонирован {path}", severity=sev,
                    target=probe, module="web", description=desc,
                    evidence=f"GET {probe} → 200 ({len(r.body)} байт)",
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
