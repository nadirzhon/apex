# APEX

**Платформа автоматизации авторизованного bug bounty корпоративного масштаба.** Scope-first, неразрушающая, с мостом MCP для управления из Claude/агента. Ядро — чистый Python stdlib, ноль зависимостей.

> ⚠️ **Только для авторизованного тестирования.** APEX работает **исключительно внутри объявленного scope** программы bug bounty, которую вы имеете право тестировать (публичная программа на HackerOne/Bugcrowd, VDP, договор на пентест). Тестирование чужой инфраструктуры без разрешения — **незаконно**. Ответственность на операторе.

## Почему «работает только на большие корпорации» — и почему это легально

Крупные компании, которых можно легально тестировать, — это те, у кого есть **публичная программа bug bounty с объявленным scope**. APEX превращает этот scope в закон движка: каждый модуль сверяет цель со scope и **отказывает (fail-closed)**, если цель вне программы. Управление scope — реальная боль баунти-хантера; здесь оно в центре архитектуры и одновременно служит предохранителем.

Чего APEX **не делает** принципиально: эксплуатация/RCE, DoS/нагрузочные атаки, массовое сканирование произвольных целей, брутфорс учёток, кража/эксфильтрация данных, обход защит цели. Только **discovery → доказательства → отчёт**.

## Возможности

- **Scope-движок (fail-closed)** — JSON-описание программы: домены, wildcard, API, мобильные пакеты, out-of-scope, rate-limit, правила. Тройной гейт: `authorized:true` в scope + флаг `--i-am-authorized` + проверка каждой цели.
- **Web** — неразрушающие проверки: заголовки безопасности, флаги cookie, TLS/сертификаты, курируемый список экспонированных файлов (`.git`, `.env`, actuator, swagger…).
- **Secrets** — поиск утёкших ключей в HTML/JS (AWS/GCP/Slack/Stripe/JWT/приватные ключи), значения в отчёте маскируются.
- **Mobile** — статический анализ APK (офлайн): разрешения, cleartext-трафик, зашитые секреты.
- **LLM / AI red-team** — авторизованный prompt-injection по LLM/агентным эндпоинтам через мост к [agentstrike](https://github.com/nadirzhon/agentstrike) (генетический фаззер). Доказательство — canary-маркер (OWASP LLM01), неразрушающе. **Это единственный класс, где даже гиганты сейчас реально уязвимы** — их AI-продукты молоды.
- **Web-vuln (серьёзные классы)** — активная проверка **SQL-инъекций и reflected XSS** реальными payload'ами (детекция по ошибке БД / отражению). Это не гигиена, а critical/high за $3 000–$30 000+. Мост к [web-vuln-scanner](https://github.com/nadirzhon/web-vuln-scanner); активно, поэтому только in-scope + `--i-am-authorized`.
- **Kali-арсенал (Docker)** — полный bug-bounty стек в контейнере `apex-kali` (nmap/sqlmap/nuclei/ffuf/gobuster/subfinder/nikto + seclists). APEX дирижирует ими через `docker run` под scope-гейтом: `kali --tool subfinder|ffuf|nuclei|sqlmap`. **ffuf+seclists = content discovery** (скрытые endpoints, где живут серьёзные баги); **sqlmap = реальная эксплуатация** SQLi до proof.
- **Giants — прицел на крупнейшие цели** — встроенный каталог bug-bounty программ гигантов (Anthropic, OpenAI, Microsoft, xAI, Google) с их scope, политикой по prompt injection и выплатами. `giants --hunt <ключ>` одной командой наводит **весь арсенал** (web + secrets + MCP-скан + AI red-team) на выбранного гиганта — только по доменам, которые есть в твоём scope-файле (fail-closed).
- **Советник (`advise`)** — не только находит, но и **ведёт**: приоритизирует находки по потенциальному чеку и по каждой даёт пошаговый план — как подтвердить, как безопасно довести до impact (за это платят), какие доказательства собрать, ожидаемая выплата, шаблон отчёта. Плюс гид «что искать руками» (IDOR/SSRF/subdomain takeover/broken access control) для большого чека.
- **ASCEND — логические уязвимости** — движок автономного поиска BOLA/IDOR, privesc, state-machine bypass. **Application World Model** (граф состояний приложения с анти-отравлением хешей) + **3-way differential validation** (Baseline/Attacker/Control → гарантия против ложных: подтверждает, только если атакующий получил данные жертвы И это не кастомная 200-ошибка). `apex ascend --selftest` показывает движок в деле.
- **CVSS 3.1** — собственный калькулятор base score (без зависимостей).
- **Отчёты** — профессиональный репорт под программу: Markdown + HTML, доказательства, ремедиация, серьёзность по CVSS.
- **Мост MCP** — движок как MCP-инструменты; Claude ведёт энгейджмент разговором в границах scope.

## Установка

```sh
git clone https://github.com/nadirzhon/apex && cd apex
python3 -m apex.cli --help          # ядро работает сразу, без установки
# или как пакет:
pip install -e .                    # команда `apex`
pip install -e '.[mcp]'             # + мост MCP (fastmcp)
```

Требуется Python ≥ 3.10.

Модуль `llm` дополнительно требует [agentstrike](https://github.com/nadirzhon/agentstrike): установите пакетом или клонируйте рядом (`~/Desktop/agentstrike`) — модуль подхватит его сам (или задайте `APEX_AGENTSTRIKE_PATH`).

### Уровень: с кем это реально конкурирует

Честно: ни один инструмент не «выигрывает» баги уровня протокола/крипты/RE (Telegram, ядро мессенджеров) — это ручная работа мирового топа. APEX силён в другом: широкий охват веб/мобильных программ **и** фронт **AI-безопасности** (`llm`-модуль), где поле молодое и автоматизация с генетическим фаззингом даёт настоящий edge против крупных вендоров, запускающих AI-bounty.

## Scope-файл

```json
{
  "program": "Example Corp — Public Bug Bounty",
  "platform": "hackerone",
  "authorized": true,
  "researcher": "you",
  "rate_limit_rps": 2,
  "in_scope": ["*.example.com", "api.example.com", "com.example.mobile"],
  "out_of_scope": ["blog.example.com", "*.staging.example.com"],
  "rules": "Только неразрушающее тестирование. Без DoS и соц.инженерии."
}
```

## Использование

```sh
apex --scope program.json scope                      # показать границы
apex --scope program.json --i-am-authorized run      # recon → web → secrets → отчёт
apex --scope program.json --i-am-authorized web --target https://api.example.com
apex --scope program.json --i-am-authorized secrets --target https://example.com
apex --scope program.json --i-am-authorized mobile --apk app.apk --package com.example.mobile
apex giants                                          # каталог гигантов + их scope/выплаты
apex --scope program.json --i-am-authorized giants --hunt anthropic   # навести весь арсенал
apex --scope program.json --i-am-authorized llm --target https://api.example.com/chat \
     --field message --response-path choices.0.message.content \
     --header "Authorization: Bearer TOKEN" --generations 4
apex ascend --selftest                               # демо движка «ноль ложных»
apex --scope program.json --i-am-authorized ascend \
     --idor 'https://api.example.com/orders/{id}' --victim-id 1001 --control-id 999999 \
     --victim-header 'Cookie: s=VICTIM' --attacker-header 'Cookie: s=ATTACKER'  # живой BOLA/IDOR
apex --state .apex/state.json advise                 # ПЛАН ДЕЙСТВИЙ: что делать дальше
apex --scope program.json report                     # собрать отчёт из находок
```

Без `--i-am-authorized` или при цели вне scope — **отказ** (exit 3), ничего не отправляется.

## Мост MCP

```sh
pip install -e '.[mcp]'
APEX_SCOPE=program.json APEX_AUTHORIZED=1 python -m apex.mcp_server
# подключить в Claude Code:
claude mcp add apex -- python -m apex.mcp_server
```

Инструменты: `scope_show`, `scope_check`, `run_recon`, `scan_web`, `scan_secrets`, `scan_mobile`, `findings_list`, `generate_report`. Все — под тем же scope-гейтом.

## Архитектура

```
apex/
├── scope.py         гейт авторизации (fail-closed)
├── http.py          безопасный rate-limited клиент (только GET/HEAD)
├── models.py        Finding/Asset + калькулятор CVSS 3.1
├── store.py         хранилище активов и находок (JSON)
├── modules/
│   ├── recon.py     DNS + HTTP fingerprint in-scope хостов
│   ├── web.py       заголовки, TLS, экспонированные файлы
│   ├── secrets.py   утёкшие ключи в web-контенте
│   ├── mobile.py    статический анализ APK
│   ├── llm.py       red-team prompt-injection (мост к agentstrike)
│   └── webvuln.py   активные SQLi/XSS/exposed-files (мост к web-vuln-scanner)
├── advisor.py       советник: приоритет по деньгам + «что делать дальше»
├── giants.py        каталог AI-программ гигантов + наводка арсенала
├── ascend/          движок логических уязвимостей (PROJECT_ASCEND)
│   ├── awm.py       Application World Model — граф состояний + анти-отравление
│   ├── differential.py  3-way validation (Baseline/Attacker/Control) — 0% ложных
│   ├── executor.py  живой BOLA/IDOR-тест реальными HTTP-запросами (2 актёра)
│   └── pipeline.py  слоистый оркестратор под scope-гейтом
├── report.py        отчёты Markdown + HTML
├── cli.py           CLI-оркестратор
└── mcp_server.py    мост MCP
```

## Лицензия

MIT — см. [LICENSE](LICENSE). Лицензия не снимает с оператора ответственности за законность тестирования.
