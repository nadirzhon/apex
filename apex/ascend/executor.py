"""Живой исполнитель ASCEND: гоняет 3-way differential validation реальными
HTTP-запросами через APEX SafeHTTP, с сессиями двух актёров.

IDOR/BOLA-тест (на СВОИХ двух тестовых аккаунтах, в рамках scope):
  • baseline — victim-сессия читает СВОЙ объект (эталон реальных данных);
  • attacker — attacker-сессия читает объект victim (пытается BOLA);
  • control  — attacker-сессия читает заведомо несуществующий объект
               (эталон отказа/«кастомной 200-ошибки»).
Инвариант three_way режет ложные срабатывания.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..http import SafeHTTP
from ..models import Finding
from ..scope import Scope
from ..store import Store
from .differential import Resp, three_way


def _parse_header(h: str) -> dict[str, str]:
    if not h or ":" not in h:
        return {}
    k, v = h.split(":", 1)
    return {k.strip(): v.strip()}


@dataclass
class IdorTest:
    url_template: str      # содержит {id}
    victim_id: str         # объект, принадлежащий victim
    control_id: str        # заведомо несуществующий/вне диапазона id
    id_param: str = "id"


def run_idor(scope: Scope, store: Store, http: SafeHTTP, authorized: bool,
             test: IdorTest, victim_header: str, attacker_header: str) -> list[Finding]:
    """Живой BOLA/IDOR-тест с 3-way differential. Возвращает Finding при
    подтверждении. Все три URL проходят scope.guard (fail-closed)."""
    scope.assert_ready(authorized)

    victim_h = _parse_header(victim_header)
    attacker_h = _parse_header(attacker_header)

    url_victim = test.url_template.replace("{id}", str(test.victim_id))
    url_control = test.url_template.replace("{id}", str(test.control_id))
    for u in (url_victim, url_control):
        scope.guard(u)

    # baseline: victim читает свой объект
    b = http.get(url_victim, headers=victim_h)
    # attacker: attacker читает объект victim
    a = http.get(url_victim, headers=attacker_h)
    # control: attacker читает несуществующий объект
    c = http.get(url_control, headers=attacker_h)

    verdict = three_way(Resp(b.status, b.text),
                        Resp(a.status, a.text),
                        Resp(c.status, c.text))

    findings: list[Finding] = []
    if verdict.confirmed:
        findings.append(Finding(
            title=f"BOLA/IDOR: {test.url_template} (параметр {test.id_param})",
            severity="high", target=url_victim, module="ascend/idor",
            description="Атакующий получил объект другого пользователя. "
                        "Подтверждено 3-way differential validation (не ложное срабатывание: "
                        "ответ атакующего совпал с данными жертвы и отличается от страницы-ошибки).",
            evidence=(
                f"baseline (victim→свой объект): HTTP {b.status}, {len(b.text)} байт\n"
                f"attacker (attacker→объект victim): HTTP {a.status}, {len(a.text)} байт\n"
                f"control  (attacker→несущ. объект): HTTP {c.status}, {len(c.text)} байт\n"
                + verdict.as_evidence()
            ),
            remediation="Проверяй владение объектом на сервере при КАЖДОМ запросе "
                        "(object-level authorization); не доверяй ID из клиента.",
            cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        ))
        for f in findings:
            store.add_finding(f)
    return findings, verdict
