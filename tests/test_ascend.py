"""Тесты ядра ASCEND: хеш состояния (анти-отравление), 3-way differential
(ловит реальный IDOR, режет кастомный 200), сборка AWM + гипотезы."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apex.ascend.awm import state_hash, AWM, Node, Priv
from apex.ascend.differential import three_way, Resp
from apex.ascend.pipeline import AscendPipeline
from apex.scope import Scope


def test_state_hash_ignores_noise():
    # два одинаковых состояния с разными таймстемпами/CSRF → ОДИН хеш
    a = '{"user":"bob","ts":1712345678,"csrf":"abc123","balance":100}'
    b = '{"user":"bob","ts":1799999999,"csrf":"zzz999","balance":100}'
    assert state_hash(200, a) == state_hash(200, b)


def test_state_hash_distinguishes_real_change():
    a = '{"user":"bob","balance":100}'
    b = '{"user":"bob","balance":9999}'
    assert state_hash(200, a) != state_hash(200, b)


def test_differential_confirms_real_idor():
    # baseline = данные жертвы; attacker получил ТО ЖЕ; control = ошибка
    victim = Resp(200, '{"order":42,"user":"victim","card":"**** 1111","total":500}')
    attacker = Resp(200, '{"order":42,"user":"victim","card":"**** 1111","total":500}')
    control = Resp(200, '{"error":"not found"}')
    v = three_way(victim, attacker, control)
    assert v.confirmed, v.as_evidence()


def test_differential_rejects_custom_200_error():
    # кастомная страница-ошибка отдаёт 200 → attacker похож на control, НЕ на baseline
    victim = Resp(200, '{"order":42,"user":"victim","card":"**** 1111","total":500}')
    attacker = Resp(200, '<html>Oops! Page not found. Return home.</html>')
    control = Resp(200, '<html>Oops! Page not found. Return home.</html>')
    v = three_way(victim, attacker, control)
    assert not v.confirmed, "кастомный 200 должен быть отклонён"


def test_differential_rejects_generic_200_page():
    # FP-ловушка: приложение на ЛЮБОЙ id отдаёт один и тот же дашборд (200).
    # attacker ≈ control (оба — дашборд), НЕ ≈ baseline (реальный заказ) → отказ.
    victim = Resp(200, '{"order":42,"user":"victim","card":"1111","total":500,"items":[1,2,3]}')
    generic = '<html><body>Welcome to your dashboard</body></html>'
    attacker = Resp(200, generic)
    control = Resp(200, generic)
    v = three_way(victim, attacker, control)
    assert not v.confirmed, "generic 200 должен быть отклонён"


def test_differential_rejects_non_200():
    victim = Resp(200, '{"data":"x"}')
    attacker = Resp(403, '{"data":"x"}')
    control = Resp(404, '{"error":"nope"}')
    assert not three_way(victim, attacker, control).confirmed


def test_awm_idor_and_privjump():
    g = AWM()
    g.add_node(Node(key="GET /api/orders/{id}", url="https://t.example/api/orders/{id}",
                    privilege=Priv.USER, params=["id"]))
    g.add_node(Node(key="GET /admin", url="https://t.example/admin", privilege=Priv.ADMIN))
    g.add_node(Node(key="GET /home", url="https://t.example/home", privilege=Priv.USER))
    g.add_edge("GET /home", "GET /admin", "nav", priv=Priv.USER)
    assert len(g.idor_candidates()) == 1
    assert len(g.privilege_jumps()) == 1


def test_pipeline_end_to_end_synthetic():
    scope = Scope(program="T", authorized=True, in_scope=["t.example"])
    from apex.store import Store
    store = Store("/tmp/ascend-test-state.json")
    store.findings.clear()
    pl = AscendPipeline(scope, store, authorized=True)
    pl.build_awm([{"key": "GET /api/orders/{id}", "method": "GET",
                   "url": "https://t.example/api/orders/1", "privilege": Priv.USER,
                   "params": ["id"]}])
    hyps = pl.hypothesize()
    assert any(h.klass == "IDOR/BOLA" for h in hyps)

    def fetch(role, url):
        if role == "control":
            return Resp(200, '{"error":"not found"}')
        return Resp(200, '{"order":1,"user":"victim","secret":"abc","total":500}')

    found = pl.validate(hyps, fetch)
    assert len(found) == 1 and found[0].module == "ascend"


if __name__ == "__main__":
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            n += 1
            print(f"  ok  {name}")
    print(f"\n{n} тестов ASCEND пройдено")
