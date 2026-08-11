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
from .modules import recon, web, secrets, mobile, llm

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
