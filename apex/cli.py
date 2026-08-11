"""APEX CLI — оркестратор авторизованного bug bounty.

Пример:
  apex scope --scope program.json
  apex run   --scope program.json --i-am-authorized
  apex report --scope program.json
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .http import SafeHTTP
from .report import write as write_report
from .scope import Scope
from .store import Store
from .modules import recon, web, secrets, mobile, llm, webvuln, arsenal, kali
from . import giants as giants_mod

BANNER = (
    "APEX — только для АВТОРИЗОВАННОГО тестирования в рамках объявленной "
    "программы bug bounty. Работа вне scope незаконна."
)


def _load(args) -> tuple[Scope, Store, SafeHTTP]:
    scope = Scope.load(args.scope)
    store = Store(args.state)
    store.program = scope.program
    http = SafeHTTP(rate_limit_rps=scope.rate_limit_rps)
    return scope, store, http


def _print_findings(new):
    if not new:
        print("  находок нет")
        return
    for f in new:
        print(f"  [{f.severity:>8}] {f.title}  → {f.target}")


def cmd_scope(args):
    scope = Scope.load(args.scope)
    print(scope.summary())


def cmd_recon(args):
    scope, store, http = _load(args)
    print(f"[recon] программа «{scope.program}» …")
    recon.run(scope, store, http, args.i_am_authorized)
    store.save()
    urls = [a.value for a in store.assets.values() if a.kind == "url"]
    print(f"  активов: {len(store.assets)} (URL: {len(urls)})")
    for u in urls:
        print(f"    {u}")


def cmd_web(args):
    scope, store, http = _load(args)
    print(f"[web] проверки в scope «{scope.program}» …")
    new = web.run(scope, store, http, args.i_am_authorized, args.target or None)
    store.save()
    _print_findings(new)


def cmd_secrets(args):
    scope, store, http = _load(args)
    print("[secrets] поиск утёкших ключей …")
    new = secrets.run(scope, store, http, args.i_am_authorized, args.target or None)
    store.save()
    _print_findings(new)


def cmd_mobile(args):
    scope, store, http = _load(args)
    print(f"[mobile] статический анализ {args.apk} …")
    new = mobile.run(scope, store, args.apk, args.i_am_authorized, args.package)
    store.save()
    _print_findings(new)


def cmd_giants(args):
    if args.hunt:
        scope, store, http = _load(args)
        print(f"[giants] наводжу арсенал на «{args.hunt}» в рамках scope «{scope.program}» …")
        new = giants_mod.hunt(args.hunt, scope, store, http, args.i_am_authorized)
        store.save()
        _print_findings(new)
        print(f"\n  итог: {len(new)} кандидатов. Отчёт: apex --scope ... report")
        return
    # каталог целей
    print("APEX Giants — прицел на крупнейшие цели\n")
    for g in giants_mod.list_programs():
        print(f"  ▸ {g['key']:11} {g['name']}")
        print(f"      платформа: {g['platform']}  ·  {g['reward']}")
        print(f"      prompt injection: {g['prompt_injection']}")
        print(f"      scope: {', '.join(g['web_scope'])}")
        if g.get('note'):
            print(f"      ↳ {g['note']}")
        print()
    print("Охота:  apex --scope <program.json> --i-am-authorized giants --hunt <key>")
    print("Scope-файл должен включать домены цели и authorized:true (твоя регистрация в программе).")


def cmd_llm(args):
    scope, store, http = _load(args)
    print(f"[llm] red-team prompt-injection по {args.target} …")
    headers = {}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    new = llm.run(
        scope, store, http, args.i_am_authorized, [args.target],
        field=args.field, response_path=args.response_path,
        headers=headers or None, generations=args.generations,
    )
    store.save()
    _print_findings(new)


def cmd_webvuln(args):
    scope, store, http = _load(args)
    print(f"[webvuln] активная проверка SQLi/XSS/exposed-files: {args.target} …")
    new = webvuln.run(scope, store, http, args.i_am_authorized, [args.target], crawl=not args.no_crawl)
    store.save()
    _print_findings(new)


def cmd_arsenal(args):
    scope, store, http = _load(args)
    tool = args.tool
    print(f"[arsenal] {tool} по {args.target} (боевой инструмент, в рамках scope) …")
    if tool == "nuclei":
        new = arsenal.run_nuclei(scope, store, args.i_am_authorized, [args.target])
    elif tool == "sqlmap":
        new = arsenal.run_sqlmap(scope, store, args.i_am_authorized, [args.target])
    else:
        print(f"неизвестный инструмент: {tool}"); return
    store.save()
    _print_findings(new)


def cmd_kali(args):
    scope, store, http = _load(args)
    if not kali.kali_available():
        print("[kali] образ apex-kali не найден. Собери: docker build -t apex-kali ~/Desktop/apex-kali")
        return
    t = args.tool
    print(f"[kali] {t} по {args.target} (через apex-kali контейнер, в рамках scope) …")
    if t == "subfinder":
        subs = kali.run_subfinder(scope, store, args.i_am_authorized, args.target)
        store.save()
        print(f"  поддоменов: {len(subs)}")
        for s in subs[:40]:
            print(f"    {s}")
        return
    fn = {"ffuf": kali.run_ffuf, "nuclei": kali.run_nuclei, "sqlmap": kali.run_sqlmap}.get(t)
    if not fn:
        print(f"неизвестный инструмент: {t}"); return
    new = fn(scope, store, args.i_am_authorized, args.target)
    store.save()
    _print_findings(new)


def cmd_advise(args):
    from .advisor import advise
    store = Store(args.state)
    print(advise(store))


def cmd_ascend(args):
    """ASCEND — движок логических уязвимостей (AWM-граф + 3-way differential)."""
    from .ascend.differential import three_way, Resp
    print("ASCEND — автономный поиск логических уязвимостей (BOLA/IDOR, privesc)")
    print("Архитектура (под scope-гейтом, Layer 0):")
    print("  L1  Recon → AWM   : граф состояний приложения (узлы+рёбра+привилегии)")
    print("  L2  SLM Gatekeeper: дешёвый фильтр (отсекает 80-90% дорогих вызовов)")
    print("  L3  Hypothesis    : гипотезы из AWM + опц. Frontier-LLM")
    print("  L4  Differential  : 3-way validation → 0% ложных → Finding+CVSS")
    # живой IDOR/BOLA-тест с 3-way differential
    if getattr(args, "idor", None):
        scope, store, http = _load(args)
        from .ascend.executor import run_idor, IdorTest
        t = IdorTest(url_template=args.idor, victim_id=args.victim_id,
                     control_id=args.control_id, id_param=args.id_param)
        print(f"[ascend] живой IDOR-тест: {args.idor} "
              f"(victim={args.victim_id}, control={args.control_id})")
        findings, verdict = run_idor(scope, store, http, args.i_am_authorized, t,
                                     args.victim_header or "", args.attacker_header or "")
        store.save()
        print("  " + verdict.as_evidence())
        _print_findings(findings)
        return
    if not args.selftest:
        print("\nЗапусти самотест движка «0% ложных»:  apex ascend --selftest")
        print("Живой IDOR-тест:  apex ... ascend --idor 'https://t/api/orders/{id}' "
              "--victim-id 1001 --control-id 999999 "
              "--victim-header 'Cookie: s=V' --attacker-header 'Cookie: s=A'")
        return
    print("\n[selftest] 3-way differential на синтетике:")
    victim = Resp(200, '{"order":42,"user":"victim","card":"1111","total":500}')
    cases = {
        "реальный IDOR (attacker=данные жертвы, control=ошибка)":
            (Resp(200, '{"order":42,"user":"victim","card":"1111","total":500}'),
             Resp(200, '{"error":"not found"}')),
        "FP-ловушка: кастомный 200 error":
            (Resp(200, '<html>Oops, not found</html>'),
             Resp(200, '<html>Oops, not found</html>')),
        "FP-ловушка: generic дашборд на любой id":
            (Resp(200, '<html>Your dashboard</html>'),
             Resp(200, '<html>Your dashboard</html>')),
    }
    for name, (attacker, control) in cases.items():
        v = three_way(victim, attacker, control)
        mark = "✓ ПОДТВЕРЖДЕНО" if v.confirmed else "✗ отклонено"
        print(f"  {mark}  {name}")
        print(f"       {v.as_evidence()}")


def cmd_report(args):
    scope = Scope.load(args.scope)
    store = Store(args.state)
    md, ht = write_report(scope, store, args.out)
    counts = store.by_severity()
    print(f"[report] находок: {len(store.findings)}  {dict(counts)}")
    print(f"  Markdown → {md}")
    print(f"  HTML     → {ht}")


def cmd_run(args):
    """Полный конвейер: recon → web → secrets → отчёт."""
    scope, store, http = _load(args)
    print(BANNER)
    print(f"\n[run] полный энгейджмент по «{scope.program}»\n")
    scope.assert_ready(args.i_am_authorized)

    print("→ recon")
    recon.run(scope, store, http, args.i_am_authorized)
    store.save()
    print(f"  активов: {len(store.assets)}")

    tgt = args.target or None
    print("→ web")
    web.run(scope, store, http, args.i_am_authorized, tgt)
    store.save()

    print("→ secrets")
    secrets.run(scope, store, http, args.i_am_authorized, tgt)
    store.save()

    md, ht = write_report(scope, store, args.out)
    print(f"\n[итог] находок: {len(store.findings)}  {dict(store.by_severity())}")
    print(f"  отчёт: {md} · {ht}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apex", description=BANNER)
    p.add_argument("--version", action="version", version=f"APEX {__version__}")
    p.add_argument("--scope", default="program.json", help="JSON-файл scope программы")
    p.add_argument("--state", default=".apex/state.json", help="файл состояния движка")
    p.add_argument("--out", default=".apex", help="каталог отчётов")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="явное подтверждение права на тестирование этой программы")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scope", help="показать загруженный scope").set_defaults(fn=cmd_scope)
    sub.add_parser("recon", help="разведка in-scope хостов").set_defaults(fn=cmd_recon)
    w = sub.add_parser("web", help="неразрушающие веб-проверки")
    w.add_argument("--target", action="append", help="явный URL (можно повторять)")
    w.set_defaults(fn=cmd_web)
    s = sub.add_parser("secrets", help="поиск утёкших секретов")
    s.add_argument("--target", action="append", help="явный URL (можно повторять)")
    s.set_defaults(fn=cmd_secrets)
    m = sub.add_parser("mobile", help="статический анализ APK")
    m.add_argument("--apk", required=True, help="путь к .apk")
    m.add_argument("--package", default="", help="идентификатор пакета (com.example.app)")
    m.set_defaults(fn=cmd_mobile)
    l = sub.add_parser("llm", help="red-team prompt-injection по LLM-эндпоинту (agentstrike)")
    l.add_argument("--target", required=True, help="URL LLM/агентного API (в scope)")
    l.add_argument("--field", default="message", help="имя поля запроса с промптом (по умолч. message)")
    l.add_argument("--response-path", default="response", help="путь к ответу в JSON, напр. choices.0.text")
    l.add_argument("--header", action="append", help='HTTP-заголовок, напр. "Authorization: Bearer TOKEN"')
    l.add_argument("--generations", type=int, default=3, help="поколений генетического поиска")
    l.set_defaults(fn=cmd_llm)
    v = sub.add_parser("webvuln", help="активная проверка серьёзных классов: SQLi/XSS/exposed-files")
    v.add_argument("--target", required=True, help="URL в scope для активного теста")
    v.add_argument("--no-crawl", action="store_true", help="не обходить сайт, тестировать только заданный URL")
    v.set_defaults(fn=cmd_webvuln)
    a = sub.add_parser("arsenal", help="боевые инструменты Kali-класса (nuclei/sqlmap) под scope-гейтом")
    a.add_argument("--tool", required=True, choices=["nuclei", "sqlmap"], help="какой инструмент запустить")
    a.add_argument("--target", required=True, help="URL в scope")
    a.set_defaults(fn=cmd_arsenal)
    k = sub.add_parser("kali", help="полный арсенал через apex-kali контейнер (subfinder/ffuf/nuclei/sqlmap)")
    k.add_argument("--tool", required=True, choices=["subfinder", "ffuf", "nuclei", "sqlmap"])
    k.add_argument("--target", required=True, help="домен (subfinder) или URL в scope")
    k.set_defaults(fn=cmd_kali)
    g = sub.add_parser("giants", help="каталог гигантов + охота всем арсеналом")
    g.add_argument("--hunt", help="ключ гиганта (anthropic/openai/microsoft/xai/google) — навести арсенал")
    g.set_defaults(fn=cmd_giants)
    sub.add_parser("advise", help="план действий: что делать дальше по находкам").set_defaults(fn=cmd_advise)
    asc = sub.add_parser("ascend", help="движок логических уязвимостей: AWM-граф + 3-way differential (ноль ложных)")
    asc.add_argument("--selftest", action="store_true", help="демо движка нулевых ложных срабатываний")
    asc.add_argument("--idor", metavar="URL_TEMPLATE", help="живой IDOR/BOLA-тест; URL с {id}")
    asc.add_argument("--victim-id", default="", help="id объекта, принадлежащего victim")
    asc.add_argument("--control-id", default="", help="заведомо несуществующий id (контроль)")
    asc.add_argument("--id-param", default="id", help="имя id-параметра (для отчёта)")
    asc.add_argument("--victim-header", help="сессия victim, напр. 'Cookie: s=V'")
    asc.add_argument("--attacker-header", help="сессия attacker, напр. 'Cookie: s=A'")
    asc.set_defaults(fn=cmd_ascend)
    sub.add_parser("report", help="сгенерировать отчёт").set_defaults(fn=cmd_report)
    r = sub.add_parser("run", help="полный конвейер + отчёт")
    r.add_argument("--target", action="append", help="явные URL для web/secrets")
    r.set_defaults(fn=cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
        return 0
    except PermissionError as e:
        print(f"[ОТКАЗ ГЕЙТА] {e}", file=sys.stderr)
        return 3
    except (FileNotFoundError, ValueError) as e:
        print(f"[ошибка] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
