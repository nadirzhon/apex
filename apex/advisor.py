"""Советник APEX — превращает находки в план действий «что делать дальше».

Главная идея: инструмент не только находит, но и ВЕДЁТ оператора. По каждой
зацепке — как подтвердить, как безопасно довести до impact (за это и платят),
какие доказательства собрать, ожидаемый чек, шаблон отчёта. Плюс гид «что
искать руками» для классов, дающих большие выплаты у крупных программ.

Всё — руководство для АВТОРИЗОВАННОГО тестирования. Эскалация до impact
описана в неразрушающем ключе (свой коллаборатор, свои тестовые аккаунты).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .store import Store

_SEV_WEIGHT = {"critical": 100, "high": 60, "medium": 30, "low": 8, "info": 2}


@dataclass
class Playbook:
    klass: str
    why_pays: str
    reward: str
    verify: list[str] = field(default_factory=list)
    escalate: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    report_tip: str = ""
    safety: str = ""


# ── Плейбуки по классам находок, которые APEX детектит ───────────────────────
PLAYBOOKS: dict[str, Playbook] = {
    "ssrf": Playbook(
        klass="SSRF — сервер/агент ходит по твоему URL (в т.ч. MCP fetch-инструмент)",
        why_pays="Критичен в облаке (доступ к metadata 169.254.169.254). Большие выплаты.",
        reward="$2 000 – $30 000+.",
        verify=[
            "Найди параметр, где сервер/агент загружает URL (fetch/preview/webhook/MCP url-параметр).",
            "Подставь СВОЙ collaborator-домен и поймай входящий запрос от IP цели.",
        ],
        escalate=[
            "Доказательство — попадание на ТВОЙ коллаборатор. Внутреннюю сеть и cloud-metadata "
            "трогать осторожно и строго по правилам программы.",
            "Для MCP: покажи, что агент по prompt-injection дёргает fetch на внутренний адрес.",
        ],
        evidence=["уязвимый параметр", "лог входящего запроса на твой домен от IP цели"],
        report_tip="Собственный OOB-сервер (interactsh/свой) обязателен. Для MCP — приложи canary.",
        safety="Не сканируй внутреннюю сеть цели без явного разрешения.",
    ),
    "sqli": Playbook(
        klass="SQL-инъекция — прямой доступ к БД",
        why_pays="Один из самых дорогих классов: доступ к данным всех пользователей.",
        reward="$3 000 – $30 000+ (critical).",
        verify=[
            "Подтверди инъекцию безопасно: булева/тайминг-проверка (AND 1=1 vs 1=2), НЕ дамп данных.",
            "Зафиксируй уязвимый параметр и тип БД по сообщению об ошибке.",
        ],
        escalate=[
            "НЕ выгружай чужие данные. Impact доказывается контролируемым признаком "
            "(разница ответов, задержка sleep), а не кражей строк.",
            "Максимум — вытащи version()/current_user на своём тестовом аккаунте.",
        ],
        evidence=["уязвимый параметр+payload", "разница ответов true/false или тайминг", "тип БД"],
        report_tip="Заголовок: «SQL Injection in <param> at <endpoint>». Приложи безопасный PoC.",
        safety="Никакого дампа/UPDATE/DROP. Только доказательство управляемости запроса.",
    ),
    "xss": Playbook(
        klass="Reflected/Stored XSS — исполнение кода в браузере жертвы",
        why_pays="Ведёт к краже сессии/действиям от лица пользователя (часто ATO).",
        reward="$500 – $10 000+ (stored и на чувствительном домене — дороже).",
        verify=[
            "Подтверди, что payload реально исполняется (alert(document.domain)), а не просто отражается.",
            "Проверь контекст (HTML/attr/JS) и обходит ли он экранирование/CSP.",
        ],
        escalate=[
            "Для impact покажи кражу непубличного (напр. document.cookie на своём тест-аккаунте).",
            "Stored XSS на странице, которую видят другие — существенно дороже reflected.",
        ],
        evidence=["URL+payload", "скриншот срабатывания alert(document.domain)", "контекст внедрения"],
        report_tip="Заголовок: «Reflected XSS in <param>». PoC-ссылка, срабатывающая в один клик.",
        safety="Тестируй только на своём аккаунте; не таргетируй других пользователей.",
    ),
    "exposed_env": Playbook(
        klass="Экспонированный .env / конфиг с секретами",
        why_pays="Прямая утечка кредов → часто критическая уязвимость.",
        reward="$1 000 – $10 000+ у крупных программ (зависит от того, что в файле).",
        verify=[
            "Скачай файл GET-запросом и проверь, что это реальный конфиг, а не заглушка.",
            "Определи, какие секреты внутри (ключи БД, API-токены, SMTP).",
        ],
        escalate=[
            "НЕ используй найденные креды для входа в чужие системы — это уже взлом.",
            "Impact доказывается САМИМ фактом доступности секрета, не его применением.",
            "Если ключ — облачный (AWS), можно показать его тип/права ТОЛЬКО на своём "
            "тестовом окружении, не трогая инфраструктуру цели.",
        ],
        evidence=["URL + код ответа 200", "фрагмент файла с ЗАМАСКИРОВАННЫМИ секретами",
                  "тип найденных секретов"],
        report_tip="Заголовок: «Sensitive file exposure: .env leaks production credentials».",
        safety="Не логинься чужими кредами. Доказывай доступность, не эксплуатацию.",
    ),
    "exposed_git": Playbook(
        klass="Экспонированный каталог .git",
        why_pays="Полная выгрузка исходников/истории → утечка секретов и логики.",
        reward="$500 – $5 000+.",
        verify=["Проверь /.git/HEAD и /.git/config на 200.",
                "Убедись, что доступны объекты (не только HEAD)."],
        escalate=["Достаточно доказать доступность .git; выкачивать весь репозиторий цели "
                  "не нужно и рискованно."],
        evidence=["URL /.git/HEAD → 200", "содержимое config (без секретов в отчёте)"],
        report_tip="Заголовок: «Source code disclosure via exposed .git directory».",
        safety="Не публикуй выкачанный код. Минимальное доказательство.",
    ),
    "leaked_secret": Playbook(
        klass="Утёкший API-ключ/токен в коде фронтенда",
        why_pays="Живой ключ в JS = мисконфигурация с реальным impact.",
        reward="$250 – $5 000+ (критично для Stripe/AWS/платёжных).",
        verify=["Подтверди, что ключ активен НЕразрушающим способом: для платёжных — "
                "проверка на своём аккаунте/в песочнице, не транзакции цели.",
                "Отличи публичный ключ (ок) от секретного (баг)."],
        escalate=["Покажи, что ключ секретный и что он даёт (scope прав) — на своём "
                  "окружении. Никаких действий от имени цели."],
        evidence=["URL файла", "замаскированный ключ", "доказательство активности (безопасное)"],
        report_tip="Уточни разницу public vs secret key — триажеры это ценят.",
        safety="Платёжные ключи — только песочница/свой аккаунт.",
    ),
    "prompt_injection": Playbook(
        klass="Prompt injection в AI-продукте (OWASP LLM01)",
        why_pays="Молодой класс, крупные вендоры (OpenAI/Google/MS) платят, защиты незрелые.",
        reward="$500 – $20 000+ при доказанном доступе к данным/инструментам агента.",
        verify=["Canary уже доказал управляемость. Теперь определи ПРИВИЛЕГИИ агента: "
                "к каким данным/инструментам/действиям он имеет доступ."],
        escalate=["Доведи до impact НА СВОИХ данных: заставь агента раскрыть свой "
                  "system-prompt, или выполнить инструмент на твоём тестовом объекте, "
                  "или утечь ДАННЫЕ ТВОЕГО аккаунта. Не трогай чужих пользователей."],
        evidence=["payload", "ответ с canary", "что именно агент сделал/раскрыл"],
        report_tip="Свяжи с бизнес-impact: «инъекция → доступ к X через инструмент Y».",
        safety="Только свои аккаунты/данные. Никаких чужих пользователей.",
    ),
    "missing_header": Playbook(
        klass="Отсутствующий security-заголовок",
        why_pays="Обычно low/informational; в одиночку у крупных редко платят.",
        reward="$0 – $150 (часто N/A). Полезно как усилитель к другому багу.",
        verify=["Подтверди отсутствие; проверь, эксплуатируется ли (например, нет CSP → "
                "ищи XSS, который теперь опаснее)."],
        escalate=["Не подавай в одиночку на зрелой программе — отклонят. Ищи связку: "
                  "нет X-Frame-Options → рабочий clickjacking-PoC на чувствительном действии."],
        evidence=["заголовки ответа", "PoC связки, если есть"],
        report_tip="Подавай только с доказанным impact, иначе — informational.",
        safety="",
    ),
    "tls_issue": Playbook(
        klass="Проблема TLS (просрочен/устаревший протокол)",
        why_pays="Low/medium; ценится в связке или на строгих программах.",
        reward="$0 – $500.",
        verify=["Подтверди версию/срок; проверь, основной ли это домен."],
        escalate=["Покажи практический риск (downgrade/MITM-сценарий) для чувствительного потока."],
        evidence=["вывод рукопожатия", "notAfter/версия протокола"],
        report_tip="Привяжи к конкретному чувствительному трафику.",
        safety="",
    ),
    "mobile_issue": Playbook(
        klass="Проблема мобильного приложения (cleartext/секреты/разрешения)",
        why_pays="Зашитые секреты и cleartext у крупных мобильных программ платят.",
        reward="$250 – $3 000+.",
        verify=["Подтверди находку в APK; для секретов — что ключ секретный и активный."],
        escalate=["Свяжи с сетевым/данными impact на СВОЁМ устройстве/аккаунте."],
        evidence=["путь в APK", "фрагмент манифеста/кода", "замаскированный секрет"],
        report_tip="Укажи версию приложения и точный путь к артефакту.",
        safety="Тесты только на своём устройстве и аккаунте.",
    ),
}

# ── Гид «что искать РУКАМИ» — классы под большой чек, которые APEX не ловит ────
HUNT_GUIDE: list[Playbook] = [
    Playbook(
        klass="IDOR / BOLA — доступ к чужим объектам по ID",
        why_pays="Самый частый крупный баг у больших SaaS/финтех. Триажеры любят.",
        reward="$1 000 – $30 000+.",
        verify=["Заведи ДВА своих тестовых аккаунта (A и B).",
                "Действием из A обратись к объекту B по его ID (заказ, файл, профиль).",
                "Если A видит/меняет данные B — это IDOR."],
        escalate=["Доказывай ТОЛЬКО на своих двух аккаунтах. Не трогай реальных пользователей.",
                  "Покажи чтение И запись, если возможно — выше severity."],
        evidence=["два аккаунта", "запрос со сменённым ID", "ответ с чужими (твоими B) данными"],
        report_tip="Чётко: «A получил доступ к ресурсу B через смену object_id».",
        safety="Только собственные тестовые аккаунты.",
    ),
    Playbook(
        klass="SSRF — сервер ходит по твоему URL",
        why_pays="Критичен в облаке (доступ к metadata). Большие выплаты.",
        reward="$2 000 – $30 000+.",
        verify=["Найди параметр, где сервер загружает URL (webhook, импорт, превью).",
                "Подставь СВОЙ collaborator-домен, лови входящий запрос от сервера цели."],
        escalate=["Доказательство — попадание на ТВОЙ коллаборатор. Внутреннюю сеть цели "
                  "и metadata трогать осторожно и по правилам программы."],
        evidence=["уязвимый параметр", "лог входящего запроса на твой домен от IP цели"],
        report_tip="Собственный OOB-сервер (interactsh/свой) — обязателен.",
        safety="Не сканируй внутреннюю сеть цели без явного разрешения.",
    ),
    Playbook(
        klass="Subdomain takeover",
        why_pays="Простой для доказательства, платят у всех крупных.",
        reward="$500 – $5 000.",
        verify=["Найди CNAME на неактивный сервис (S3/GitHub Pages/Heroku и т.п.).",
                "Проверь, что сервис отдаёт «not found / claim this»."],
        escalate=["Заклейми поддомен на СВОЁМ аккаунте сервиса, повесь безобидную страницу-маркер."],
        evidence=["dig CNAME", "скриншот захваченного поддомена с твоим маркером"],
        report_tip="Не размещай ничего вредоносного — только доказательный маркер.",
        safety="Только безобидная страница-подтверждение.",
    ),
    Playbook(
        klass="Broken access control / privilege escalation",
        why_pays="Логика доступа — топ по выплатам у больших компаний.",
        reward="$1 000 – $30 000+.",
        verify=["Сравни, что может обычный пользователь vs админ (свои аккаунты).",
                "Попробуй вызвать админ-действие из аккаунта обычного пользователя."],
        escalate=["Доказывай на своих ролях; покажи конкретное запрещённое действие, которое прошло."],
        evidence=["запрос обычного юзера к привилегированному эндпоинту", "успешный ответ"],
        report_tip="Опиши матрицу ролей и где она сломалась.",
        safety="Только свои аккаунты/роли.",
    ),
]


def _match(finding) -> str | None:
    t = finding.title.lower()
    m = finding.module
    if m == "llm":
        return "prompt_injection"
    if "sql injection" in t or "sqli" in t:
        return "sqli"
    if "xss" in t:
        return "xss"
    if ".env" in t or "конфиг" in t:
        return "exposed_env"
    if ".git" in t:
        return "exposed_git"
    if "секрет" in t or "ключ" in t or "secret" in t:
        return "leaked_secret"
    # MCP: свободный url-параметр — реальный SSRF-вектор у агентного инструмента
    if "ssrf" in t or ("unconstrained" in t and "url" in t):
        return "ssrf"
    if "actuator" in t or "swagger" in t:
        return "exposed_env"
    if "заголов" in t or "cookie" in t:
        return "missing_header"
    if "tls" in t or "сертификат" in t or "протокол" in t:
        return "tls_issue"
    if m == "mobile":
        return "mobile_issue"
    return None


def _lead_score(finding) -> int:
    base = _SEV_WEIGHT.get(finding.severity, 5)
    # усилители: секреты/exposed-файлы/llm — ближе к деньгам
    if finding.module in ("secrets", "llm"):
        base += 25
    if ".env" in finding.title.lower() or ".git" in finding.title.lower():
        base += 20
    return base


def advise(store: Store) -> str:
    """Текстовый план действий: приоритет по деньгам + шаги по каждой зацепке."""
    ranked = sorted(store.findings, key=_lead_score, reverse=True)
    out: list[str] = []
    out.append("═" * 70)
    out.append("APEX — ПЛАН ДЕЙСТВИЙ (что делать дальше, по приоритету дохода)")
    out.append("═" * 70)

    if not ranked:
        out.append("\nНаходок пока нет. Сначала: apex run / apex web / apex secrets.\n")
    else:
        top = ranked[0]
        out.append(f"\n▶ НАЧНИ ОТСЮДА: «{top.title}» → {top.target}")
        pk = PLAYBOOKS.get(_match(top) or "")
        if pk:
            out.append(f"  Почему: {pk.why_pays}  Ожидаемый чек: {pk.reward}")
        out.append("")

    for i, f in enumerate(ranked, 1):
        pk = PLAYBOOKS.get(_match(f) or "")
        out.append(f"[{i}] ({f.severity}) {f.title}")
        out.append(f"    цель: {f.target}")
        if not pk:
            out.append("    → проверь вручную; собери доказательство и оцени impact.\n")
            continue
        out.append(f"    класс: {pk.klass}  ·  чек: {pk.reward}")
        out.append("    ПОДТВЕРДИТЬ:")
        for s in pk.verify:
            out.append(f"      • {s}")
        out.append("    ДОВЕСТИ ДО IMPACT (безопасно, в рамках scope):")
        for s in pk.escalate:
            out.append(f"      • {s}")
        out.append("    ДОКАЗАТЕЛЬСТВА: " + "; ".join(pk.evidence))
        if pk.report_tip:
            out.append(f"    ОТЧЁТ: {pk.report_tip}")
        if pk.safety:
            out.append(f"    ⚠ {pk.safety}")
        out.append("")

    out.append("─" * 70)
    out.append("ОХОТА РУКАМИ — классы под БОЛЬШОЙ чек (APEX их не ловит авто):")
    out.append("─" * 70)
    for pk in HUNT_GUIDE:
        out.append(f"\n◆ {pk.klass}  ·  {pk.reward}")
        out.append(f"  почему: {pk.why_pays}")
        out.append("  как искать:")
        for s in pk.verify:
            out.append(f"    • {s}")
        out.append("  довести до impact:")
        for s in pk.escalate:
            out.append(f"    • {s}")
        if pk.safety:
            out.append(f"  ⚠ {pk.safety}")
    out.append("")
    out.append("Всё — для программ, где у тебя есть разрешение (scope). "
               "Impact доказывай на СВОИХ аккаунтах/коллабораторе, не на чужих данных.")
    return "\n".join(out)
