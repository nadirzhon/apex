"""ASCEND — движок автономного поиска логических уязвимостей.

Реализация архитектуры PROJECT_ASCEND: Application World Model (граф состояний)
+ 3-way differential validation (0% ложных) + слоистый конвейер под scope-гейтом.

«1000 агентов» из спеки — это архитектура ролей, а не 1000 процессов. Здесь
она собрана как детерминированный конвейер с подключаемым LLM-слоем гипотез.
Всё работает ТОЛЬКО внутри авторизованного scope (Layer 0).
"""
from .awm import AWM, Node, Edge, Priv, state_hash, normalize
from .differential import three_way, Resp, DiffVerdict

__all__ = ["AWM", "Node", "Edge", "Priv", "state_hash", "normalize",
           "three_way", "Resp", "DiffVerdict"]
