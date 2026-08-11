"""Autorize-режим: автоматический поиск IDOR/BOLA по HAR-экспорту.

Идея (как расширение Autorize для Burp): ты ходишь по приложению под своим
аккаунтом A и экспортируешь трафик в HAR. Инструмент берёт КАЖДЫЙ запрос,
повторяет его с сессией аккаунта B (attacker) и сравнивает ответ с тем, что
получил A (baseline из HAR). Если B получил те же данные, что A → кандидат
в IDOR/BOLA.

Только GET (не меняем состояние), только in-scope, статика пропускается,
rate-limit соблюдается. Результат — КАНДИДАТЫ; подтверждай их через
`ascend --idor` (полный 3-way differential) перед подачей.
"""
from __future__ import annotations

import json
from difflib import SequenceMatcher

from ..http import SafeHTTP
from ..models import Finding
from ..scope import Scope
from ..store import Store

_STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
           ".woff2", ".ttf", ".ico", ".map", ".mp4", ".webp", ".avif")


def _parse_header(h: str) -> dict[str, str]:
    if not h or ":" not in h:
        return {}
    k, v = h.split(":", 1)
    return {k.strip(): v.strip()}


def _load_har(path: str) -> list[dict]:
    data = json.loads(open(path, encoding="utf-8").read())
    out = []
    for e in data.get("log", {}).get("entries", []):
        req = e.get("request", {})
        resp = e.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "GET")
        body = (resp.get("content", {}) or {}).get("text", "") or ""
        out.append({"url": url, "method": method,
                    "status": resp.get("status", 0), "body": body})
    return out


def _sim(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def run(scope: Scope, store: Store, http: SafeHTTP, authorized: bool,
        har_path: str, attacker_header: str, *, min_sim: float = 0.85,
        min_len: int = 40) -> tuple[list[Finding], dict]:
    """Прогнать HAR: повторить каждый GET с cookie attacker, найти IDOR-кандидатов."""
    scope.assert_ready(authorized)
    attacker_h = _parse_header(attacker_header)
    if not attacker_h:
        raise ValueError("нужен --attacker-header 'Cookie: ...' пустого аккаунта")

    entries = _load_har(har_path)
    findings: list[Finding] = []
    stats = {"total": len(entries), "tested": 0, "skipped": 0,
             "no_body": 0, "out_of_scope": 0, "candidates": 0}
    seen = set()

    for e in entries:
        url, method = e["url"], e["method"]
        # только GET, только уникальные, не статика
        if method != "GET" or url in seen:
            stats["skipped"] += 1
            continue
        if any(url.split("?")[0].lower().endswith(ext) for ext in _STATIC):
            stats["skipped"] += 1
            continue
        seen.add(url)
        # baseline из HAR обязателен (что видел A)
        if not e["body"] or len(e["body"]) < min_len or e["status"] != 200:
            stats["no_body"] += 1
            continue
        # scope-гейт на каждую цель
        if not scope.in_scope_target(url):
            stats["out_of_scope"] += 1
            continue

        stats["tested"] += 1
        replay = http.get(url, headers=attacker_h)      # повтор с cookie attacker
        if replay.status != 200 or len(replay.text) < min_len:
            continue
        s = _sim(replay.text, e["body"])
        if s >= min_sim:                                # B получил данные A
            stats["candidates"] += 1
            findings.append(Finding(
                title=f"IDOR-кандидат (Autorize): {url.split('?')[0]}",
                severity="high", target=url, module="ascend/autorize",
                description="Аккаунт-attacker получил ответ, совпадающий с ответом "
                            "владельца → возможный доступ к чужим данным. КАНДИДАТ: "
                            "подтверди через `ascend --idor` (3-way differential).",
                evidence=f"GET {url}\nstatus(attacker)=200  "
                         f"sim(attacker, owner)={s:.2f} (порог >{min_sim})\n"
                         f"размеры: attacker={len(replay.text)}б, owner={len(e['body'])}б",
                remediation="Проверяй владение объектом на сервере при каждом запросе.",
                cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            ))

    for f in findings:
        store.add_finding(f)
    return findings, stats
