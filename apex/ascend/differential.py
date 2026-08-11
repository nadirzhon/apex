"""3-Way Differential Control Validation — движок нулевых ложных срабатываний.

Проблема автосканеров: «200 OK» ≠ уязвимость. Кастомные страницы-ошибки
отдают 200, и наивный сканер репортит IDOR там, где его нет.

Решение (спека ASCEND, Layer 4): каждую гипотезу проверяем ТРЕМЯ запросами:
  • Baseline — легитимный доступ жертвы к СВОему объекту (эталон «как выглядит
    настоящий ресурс»).
  • Attacker — атакующий пытается получить объект жертвы.
  • Control — запрос к заведомо НЕсуществующему/чужому-вне-диапазона объекту
    (эталон «как выглядит отказ/ошибка», даже если это кастомный 200).

Инвариант подтверждения (строгий, И):
  status(attacker) == 200
  AND sim(attacker, baseline) > SIM_BASELINE_MIN   # атакующий получил реальные данные
  AND sim(attacker, control)  < SIM_CONTROL_MAX    # и это НЕ страница-ошибка

Так кастомная 200-ошибка режется: attacker будет похож на control, а не на
baseline → инвариант не выполнен → НЕ репортим.
"""
from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

SIM_BASELINE_MIN = 0.85
SIM_CONTROL_MAX = 0.60


@dataclass
class Resp:
    status: int
    body: str


def _sim(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


@dataclass
class DiffVerdict:
    confirmed: bool
    reason: str
    status_attacker: int
    sim_baseline: float
    sim_control: float

    def as_evidence(self) -> str:
        return (
            f"status(attacker)={self.status_attacker}  "
            f"sim(attacker,baseline)={self.sim_baseline:.2f} (порог >{SIM_BASELINE_MIN})  "
            f"sim(attacker,control)={self.sim_control:.2f} (порог <{SIM_CONTROL_MAX})  "
            f"→ {'ПОДТВЕРЖДЕНО' if self.confirmed else 'отклонено'}: {self.reason}"
        )


def three_way(baseline: Resp, attacker: Resp, control: Resp,
              *, sim_baseline_min: float = SIM_BASELINE_MIN,
              sim_control_max: float = SIM_CONTROL_MAX) -> DiffVerdict:
    """Применить строгий дифференциальный инвариант. Возвращает вердикт с числами."""
    s_base = _sim(attacker.body, baseline.body)
    s_ctrl = _sim(attacker.body, control.body)

    if attacker.status != 200:
        return DiffVerdict(False, f"attacker status={attacker.status}≠200",
                           attacker.status, s_base, s_ctrl)
    if s_base <= sim_baseline_min:
        return DiffVerdict(False, "ответ не похож на реальные данные жертвы",
                           attacker.status, s_base, s_ctrl)
    if s_ctrl >= sim_control_max:
        return DiffVerdict(False, "ответ похож на страницу-ошибку (кастомный 200)",
                           attacker.status, s_base, s_ctrl)
    return DiffVerdict(True, "атакующий получил данные жертвы, это не ошибка",
                       attacker.status, s_base, s_ctrl)
