"""Слоистый конвейер ASCEND под scope-гейтом.

Layer 0  Authorization   — scope.assert_ready + guard на каждой цели (fail-closed)
Layer 1  Recon → AWM     — построение графа состояний приложения
Layer 2  SLM Gatekeeper  — дешёвый фильтр кандидатов (отсекает 80-90% до Layer 3)
Layer 3  Hypothesis      — генерация гипотез (детерминированный дефолт из AWM;
                            подключаемо к LLM/NEMESIS)
Layer 4  Differential    — 3-way validation → Finding (0% ложных)

LLM-слой не хардкодится: hypothesize принимает необязательный reasoner-колбэк.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..models import Finding
from ..scope import Scope
from ..store import Store
from .awm import AWM, Node, Priv
from .differential import Resp, three_way


@dataclass
class Hypothesis:
    klass: str                     # "IDOR/BOLA" | "BFLA/privesc" | ...
    node_key: str
    param: str
    description: str
    cvss_vector: str = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # BOLA-типичный ~8.1


# fetch(role, url) -> Resp ; role: "victim"|"attacker"|"control"
Fetcher = Callable[[str, str], Resp]
# gatekeeper(hypothesis) -> bool ; reasoner(node) -> list[Hypothesis]
Gatekeeper = Callable[[Hypothesis], bool]
Reasoner = Callable[[Node], list[Hypothesis]]


class AscendPipeline:
    def __init__(self, scope: Scope, store: Store, authorized: bool):
        scope.assert_ready(authorized)          # Layer 0 — сразу, до всего
        self.scope = scope
        self.store = store
        self.awm = AWM()

    # ── Layer 1: построить AWM из обнаруженных эндпоинтов ────────────────
    def build_awm(self, endpoints: list[dict]) -> AWM:
        for ep in endpoints:
            url = ep.get("url", "")
            self.scope.guard(url)               # ничего вне scope в граф не попадёт
            self.awm.add_node(Node(
                key=ep.get("key") or f"{ep.get('method','GET')} {url}",
                method=ep.get("method", "GET"), url=url,
                status=ep.get("status", 0),
                privilege=ep.get("privilege", Priv.USER),
                params=ep.get("params", []),
            ))
        return self.awm

    # ── Layer 3: гипотезы (детерминированный дефолт + опц. LLM) ──────────
    def hypothesize(self, reasoner: Reasoner | None = None) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for node in self.awm.idor_candidates():
            for p in node.params:
                hyps.append(Hypothesis(
                    klass="IDOR/BOLA", node_key=node.key, param=p,
                    description=f"Атакующий обращается к {node.key} со значением "
                                f"параметра '{p}', принадлежащим другому пользователю.",
                ))
            if reasoner:                        # усиление Frontier-моделью, если дана
                hyps.extend(reasoner(node))
        for e in self.awm.privilege_jumps():
            hyps.append(Hypothesis(
                klass="BFLA/privesc", node_key=e.dst, param="(роль)",
                description=f"Переход {e.src} → {e.dst} доступен без нужной привилегии.",
                cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            ))
        return hyps

    # ── Layer 2 + Layer 4: гейткипер → 3-way validation → Finding ───────
    def validate(self, hyps: list[Hypothesis], fetch: Fetcher,
                 gatekeeper: Gatekeeper | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for h in hyps:
            if gatekeeper and not gatekeeper(h):
                continue                        # Layer 2 отсёк
            node = self.awm.nodes.get(h.node_key)
            url = node.url if node else h.node_key
            self.scope.guard(url)               # ещё раз, перед реальными запросами
            baseline = fetch("victim", url)
            attacker = fetch("attacker", url)
            control = fetch("control", url)
            v = three_way(baseline, attacker, control)
            if not v.confirmed:
                continue
            findings.append(Finding(
                title=f"{h.klass}: {h.node_key} (параметр {h.param})",
                severity="high", target=url, module="ascend",
                description=h.description
                    + " Подтверждено 3-way differential validation.",
                evidence=v.as_evidence(),
                remediation="Проверяй владение объектом на сервере (object-level "
                            "authorization) для каждого запроса, не доверяй ID из клиента.",
                cvss_vector=h.cvss_vector,
            ))
        for f in findings:
            self.store.add_finding(f)
        return findings
