"""Мульти-идентичность + self-provisioned объекты (breakthrough #2 роя, M1+M2).

Фатальная критика роя (A2): выведенная политика π отравляется галлюцинацией —
нельзя ДОГАДЫВАТЬСЯ, что «объект приватный». Решение: не догадываться, а
СКОНСТРУИРОВАТЬ ground-truth. Мы создаём приватный объект под идентичностью A
секунду назад → `should_deny(B → объект A)` = факт, а не оценка.

Поток self-provisioned IDOR (всё под scope.guard, authorized-only):
  1. provision: A создаёт СВОЙ приватный объект (POST) → ловим object_id
  2. baseline: A читает свой объект (эталон реальных данных)
  3. attacker: B читает объект A (должно быть отказано — ground-truth)
  4. control:  B читает заведомо несуществующий объект (эталон отказа)
  5. three_way: атакующий похож на baseline и НЕ похож на control → IDOR

Это снимает единственный конфаундер, который убивал authz-детект: «а вдруг
объект вообще публичный». По конструкции — не публичный.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from ..models import Finding
from ..scope import Scope
from ..store import Store
from .differential import Resp, three_way


@dataclass
class Identity:
    """Тестовая идентичность: имя + заголовки авторизации (свой аккаунт)."""
    name: str
    headers: dict = field(default_factory=dict)


@dataclass
class IdentityPool:
    """Пул контролируемых идентичностей. Минимум A и B (одноранговые),
    опц. anon/low для BFLA. Все — СВОИ тестовые аккаунты в рамках scope."""
    victim: Identity      # A — создаёт объект
    attacker: Identity    # B — пытается получить объект A
    anon: Identity | None = None


_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _req(url: str, method: str, headers: dict, body: bytes | None = None,
         timeout: int = 15) -> Resp:
    req = urllib.request.Request(url, method=method, data=body,
                                 headers={"User-Agent": "ASCEND/1.0 (authorized)", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            return Resp(r.status, r.read(200_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            b = e.read(50_000).decode("utf-8", "replace")
        except Exception:
            b = ""
        return Resp(e.code, b)
    except Exception:
        return Resp(0, "")


def _dig(obj, path: str):
    """Достать значение по пути 'a.b.0.id' из JSON."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


@dataclass
class ProvisionSpec:
    create_url: str                 # POST сюда, чтобы создать объект как A
    read_template: str              # шаблон чтения, содержит {id}
    id_path: str = "id"             # путь к object_id в JSON-ответе create
    create_method: str = "POST"
    create_payload: dict | None = None
    control_id: str = "0"           # заведомо несуществующий id для эталона отказа
    content_type: str = "application/json"


def self_provisioned_idor(scope: Scope, store: Store, authorized: bool,
                          pool: IdentityPool, spec: ProvisionSpec) -> list[Finding]:
    """Полный self-provisioned IDOR-тест с ground-truth. Возвращает Finding
    при подтверждении. Каждый URL — через scope.guard (fail-closed)."""
    scope.assert_ready(authorized)
    scope.guard(spec.create_url)

    # 1) PROVISION — A создаёт свой приватный объект
    payload = None
    hdr_v = dict(pool.victim.headers)
    if spec.create_payload is not None:
        payload = json.dumps(spec.create_payload).encode()
        hdr_v.setdefault("Content-Type", spec.content_type)
    created = _req(spec.create_url, spec.create_method, hdr_v, payload)
    if created.status not in (200, 201):
        return []  # не смогли создать объект — тест невозможен, молча выходим
    try:
        obj_id = _dig(json.loads(created.body), spec.id_path)
    except json.JSONDecodeError:
        obj_id = None
    if obj_id is None:
        return []
    obj_id = str(obj_id)

    read_url = spec.read_template.format(id=obj_id)
    control_url = spec.read_template.format(id=spec.control_id)
    scope.guard(read_url)
    scope.guard(control_url)

    # 2) baseline — A читает СВОЙ объект (эталон реальных данных)
    baseline = _req(read_url, "GET", pool.victim.headers)
    # 3) attacker — B читает объект A (ground-truth: должно быть отказано)
    attacker = _req(read_url, "GET", pool.attacker.headers)
    # 4) control — B читает несуществующий объект (эталон отказа/кастомной 200)
    control = _req(control_url, "GET", pool.attacker.headers)

    v = three_way(baseline, attacker, control)
    if not v.confirmed:
        return []

    f = Finding(
        title=f"BOLA/IDOR (ground-truth): {pool.attacker.name} читает приватный объект {pool.victim.name}",
        severity="high",
        target=read_url,
        module="ascend/identity",
        description=(
            "Self-provisioned доказательство: объект создан приватно под "
            f"«{pool.victim.name}» непосредственно перед тестом, поэтому "
            "should_deny — ground-truth, не догадка. Атакующая идентичность "
            "получила данные владельца."
        ),
        evidence=f"object_id={obj_id} (создан как {pool.victim.name})\n" + v.as_evidence(),
        remediation="Проверяй владельца объекта на стороне сервера для каждого запроса (object-level authz).",
        cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    )
    store.add_finding(f)
    return [f]
