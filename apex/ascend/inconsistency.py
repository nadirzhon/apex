"""Self-inconsistency оракул (breakthrough #3 роя, M3).

Самый робастный механизм: единственный оракул, полностью свободный от узкого
горла «точность вывода политики π». Идея: не знать, какая политика ПРАВИЛЬНАЯ,
а поймать приложение на противоречии самому себе.

Если над объектами ОДНОГО типа T:
  • endpoint E1 проверяет владельца (чужой доступ → отказ),
  • endpoint E2 над тем же типом T — НЕ проверяет (чужой доступ → 200 с данными),
то E2 почти наверняка баг — и это видно БЕЗ знания «правильной» политики,
просто из несогласованности enforcement внутри одного типа.

Пример: GET /api/orders/{id} проверяет владельца, а
GET /api/orders/{id}/invoice — нет. Второй — дыра.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding
from ..scope import Scope
from ..store import Store


@dataclass
class EnforcementObservation:
    """Наблюдение поведения endpoint'а над объектом чужого владельца."""
    endpoint_key: str          # "GET /api/orders/{id}"
    object_type: str           # "order" — семантический тип объекта
    cross_owner_denied: bool   # при доступе чужой идентичности объект скрыт/отказан?
    sample_url: str = ""       # пример URL для доказательства


@dataclass
class Inconsistency:
    object_type: str
    enforcing: list[str]       # endpoints, которые проверяют владельца
    leaking: list[str]         # endpoints над тем же типом, которые НЕ проверяют
    leak_samples: list[str] = field(default_factory=list)


def detect(observations: list[EnforcementObservation]) -> list[Inconsistency]:
    """Найти типы объектов, где enforcement НЕсогласован между endpoint'ами."""
    by_type: dict[str, list[EnforcementObservation]] = {}
    for o in observations:
        by_type.setdefault(o.object_type, []).append(o)

    out: list[Inconsistency] = []
    for otype, obs in by_type.items():
        enforcing = [o.endpoint_key for o in obs if o.cross_owner_denied]
        leaking = [o.endpoint_key for o in obs if not o.cross_owner_denied]
        # противоречие: над одним типом ЕСТЬ и проверяющие, и не-проверяющие
        if enforcing and leaking:
            samples = [o.sample_url for o in obs if not o.cross_owner_denied and o.sample_url]
            out.append(Inconsistency(otype, enforcing, leaking, samples))
    return out


def to_findings(scope: Scope, store: Store, authorized: bool,
                observations: list[EnforcementObservation]) -> list[Finding]:
    """Превратить обнаруженные несогласованности в Finding'и."""
    scope.assert_ready(authorized)
    findings: list[Finding] = []
    for inc in detect(observations):
        f = Finding(
            title=f"Несогласованный authz над типом «{inc.object_type}»: "
                  f"{len(inc.leaking)} endpoint(ов) не проверяют владельца",
            severity="high",
            target=inc.leak_samples[0] if inc.leak_samples else inc.leaking[0],
            module="ascend/inconsistency",
            description=(
                f"Над объектами типа «{inc.object_type}» enforcement противоречив: "
                f"проверяют владельца — {', '.join(inc.enforcing)}; "
                f"НЕ проверяют — {', '.join(inc.leaking)}. "
                "Само противоречие — сильный сигнал бага, БЕЗ знания правильной политики."
            ),
            evidence=f"enforcing: {inc.enforcing}\nleaking: {inc.leaking}\nsamples: {inc.leak_samples}",
            remediation="Приведи object-level authz к единому виду для всех endpoint'ов над типом.",
            cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        )
        store.add_finding(f)
        findings.append(f)
    return findings
