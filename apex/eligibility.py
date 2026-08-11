"""Фильтр приемлемости по списку HackerOne «Core Ineligible Findings».

Практическая польза: не давать оператору подавать то, что платформа закроет
как invalid (это бьёт по репутации и тратит время). Каждая находка получает
вердикт: ELIGIBLE (нести в отчёт), NEEDS_IMPACT (только с доказанным impact),
INELIGIBLE (не подавать — закроют).

Источник: HackerOne Core Ineligible Findings (2025-05-19).
"""
from __future__ import annotations

ELIGIBLE = "ELIGIBLE"
NEEDS_IMPACT = "NEEDS_IMPACT"
INELIGIBLE = "INELIGIBLE"

# (подстрока в title.lower() или module) → (вердикт, причина по списку HackerOne)
_INELIGIBLE = [
    ("заголов", "Missing security headers = optional hardening (HSTS/CSP/nosniff)."),
    ("cookie", "Cookie handling (HttpOnly/Secure) = optional hardening."),
    ("tls", "SSL/TLS configuration = optional hardening."),
    ("сертификат", "SSL/TLS certificate config = optional hardening."),
    ("протокол", "TLS protocol version = optional hardening."),
    ("version", "Software version / banner disclosure."),
    ("banner", "Banner identification."),
    ("rate limit", "Most rate-limiting issues are ineligible."),
    ("ssl pinning", "Lack of SSL pinning (mobile) — ineligible."),
    ("jailbreak", "Lack of jailbreak detection — ineligible."),
    ("spf", "Optional email security (SPF/DKIM/DMARC)."),
    ("dkim", "Optional email security (SPF/DKIM/DMARC)."),
    ("dmarc", "Optional email security (SPF/DKIM/DMARC)."),
    ("security.txt", "Info-only, not a vulnerability."),
    ("cleartext", "Cleartext traffic — обычно hardening без прямого impact."),
    ("опасные разрешения", "Разрешения манифеста без impact — hardening."),
]

# требуют ДОКАЗАННОГО impact, иначе закроют
_NEEDS_IMPACT = [
    ("open redirect", "Open redirect — только с дополнительным security-impact."),
    ("редирект", "Open redirect — только с дополнительным security-impact."),
    ("csrf", "CSRF — только на sensitive-действии."),
    ("cors", "CORS — только с продемонстрированным impact."),
    ("clickjack", "Clickjacking — только на sensitive-действии."),
    ("x-frame", "Clickjacking-защита — нужен рабочий PoC на sensitive-действии."),
    ("self-xss", "Self-XSS — только если атакует другой аккаунт."),
    ("swagger", "Раскрытие схемы API — ценно только если ведёт к доступу."),
    ("actuator", "Info-эндпоинт — нужен реальный утёкший секрет/доступ."),
    ("server-status", "Info-эндпоинт — нужен реальный чувствительный контент."),
    ("nuclei", "Многие nuclei-срабатывания = info/version — нужен impact."),
]

# всегда ценные классы (реальный impact) — приоритет над эвристиками выше
_ELIGIBLE_STRONG = [
    ("idor", "BOLA/IDOR — межпользовательский доступ, топ-класс."),
    ("bola", "BOLA/IDOR — межпользовательский доступ, топ-класс."),
    (".env", "Утечка конфигурации/секретов."),
    (".git", "Раскрытие исходного кода."),
    ("секрет", "Утёкший секрет/ключ."),
    ("sql", "SQL-инъекция — прямой доступ к данным."),
    ("prompt injection", "OWASP LLM01 — оплачивается при impact."),
    ("privilege", "Privilege escalation / BFLA."),
    ("privesc", "Privilege escalation / BFLA."),
    ("ssrf", "SSRF — доступ к внутренним ресурсам."),
]


def classify(finding) -> tuple[str, str]:
    t = (finding.title or "").lower()
    m = (finding.module or "").lower()
    hay = t + " " + m

    for key, why in _ELIGIBLE_STRONG:
        if key in hay:
            # stored/reflected XSS — eligible, но self-XSS уводим в needs_impact ниже
            return ELIGIBLE, why
    if "xss" in hay and "self" not in hay:
        return ELIGIBLE, "XSS с исполнением — eligible (stored дороже reflected)."
    for key, why in _INELIGIBLE:
        if key in hay:
            return INELIGIBLE, why
    for key, why in _NEEDS_IMPACT:
        if key in hay:
            return NEEDS_IMPACT, why
    # по умолчанию — требует ручной оценки impact, а не автоподача
    return NEEDS_IMPACT, "Класс не в списке — оцени реальный impact перед подачей."


def partition(findings) -> dict[str, list]:
    out = {ELIGIBLE: [], NEEDS_IMPACT: [], INELIGIBLE: []}
    for f in findings:
        verdict, why = classify(f)
        out[verdict].append((f, why))
    return out
