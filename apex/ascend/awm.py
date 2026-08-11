"""Application World Model (AWM) — направленный граф состояний приложения.

Узлы = состояния/эндпоинты, рёбра = переходы с уровнем привилегий
(ANON → USER → ADMIN). Хеш состояния снимается ПОСЛЕ вычистки динамического
шума (таймстемпы, CSRF, nonce, отражённый ввод) — иначе граф «отравляется»
(agents 851-900 в спеке ASCEND). Ноль внешних зависимостей: граф на dict,
Neo4j/NetworkX не нужны для ядра.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import IntEnum

# порядок привилегий важен: переход вверх без проверки = потенциальный BFLA/privesc
class Priv(IntEnum):
    ANON = 0
    USER = 1
    STAFF = 2
    ADMIN = 3


# Шум, который нельзя пускать в хеш состояния (иначе одинаковые состояния
# получат разные хеши → ложные «переходы» и отравление графа).
_NOISE = [
    re.compile(r'\b\d{10,13}\b'),                              # unix timestamps
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*'),  # ISO datetime
    re.compile(r'(?i)(csrf|xsrf|nonce|request[_-]?id|trace[_-]?id)["\s:=]+[\w\-]+'),
    re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),  # UUIDs
    re.compile(r'(?i)(sessionid|token|jwt)["\s:=]+[\w\.\-]+'),
]


def normalize(body: str, reflected: list[str] | None = None) -> str:
    """Убрать динамический шум и отражённый ввод перед хешированием."""
    s = body
    for rx in _NOISE:
        s = rx.sub("∅", s)
    for r in reflected or []:
        if r:
            s = s.replace(r, "∅")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def state_hash(status: int, body: str, reflected: list[str] | None = None) -> str:
    """SHA256 стабильного представления состояния (status + очищенное тело)."""
    norm = normalize(body, reflected)
    return hashlib.sha256(f"{status}\x00{norm}".encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Node:
    key: str                       # endpoint-ключ: "GET /api/orders/{id}"
    method: str = "GET"
    url: str = ""
    status: int = 0
    privilege: int = Priv.ANON
    state: str = ""                # state_hash последнего ответа
    params: list[str] = field(default_factory=list)   # id/uuid-параметры (кандидаты в IDOR)
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    action: str                    # что вызвало переход (request-подпись)
    priv_required: int = Priv.ANON


class AWM:
    """Directed knowledge graph модели приложения."""

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, node: Node) -> Node:
        ex = self.nodes.get(node.key)
        if ex:
            # обновляем состояние/привилегию, не дублируем узел (Graph_Delta_Engine)
            if node.state:
                ex.state = node.state
            ex.privilege = max(ex.privilege, node.privilege)
            for p in node.params:
                if p not in ex.params:
                    ex.params.append(p)
            return ex
        self.nodes[node.key] = node
        return node

    def add_edge(self, src: str, dst: str, action: str, priv: int = Priv.ANON) -> None:
        for e in self.edges:
            if e.src == src and e.dst == dst and e.action == action:
                return  # дедуп
        self.edges.append(Edge(src, dst, action, priv))

    # ── аналитика графа: где искать логические баги ──────────────────────
    def idor_candidates(self) -> list[Node]:
        """Узлы с object-id параметром — кандидаты на BOLA/IDOR."""
        return [n for n in self.nodes.values() if n.params]

    def privilege_jumps(self) -> list[Edge]:
        """Рёбра, ведущие вверх по привилегиям — кандидаты на BFLA/privesc."""
        out = []
        for e in self.edges:
            s = self.nodes.get(e.src)
            d = self.nodes.get(e.dst)
            if s and d and d.privilege > s.privilege and e.priv_required < d.privilege:
                out.append(e)
        return out

    def summary(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "idor_candidates": len(self.idor_candidates()),
            "privilege_jumps": len(self.privilege_jumps()),
        }
