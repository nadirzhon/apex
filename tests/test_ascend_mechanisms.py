"""Тесты новых механизмов ASCEND: self-inconsistency + self-provisioned identity."""
import pytest
from apex.scope import Scope
from apex.store import Store
from apex.ascend.inconsistency import detect, to_findings, EnforcementObservation
from apex.ascend import identity
from apex.ascend.differential import Resp


def _scope():
    return Scope(program="t", authorized=True, in_scope=["t.example", "https://t.example"])


# ── self-inconsistency оракул (breakthrough #3) ──────────────────────────
def test_inconsistency_flags_mixed_enforcement():
    obs = [
        EnforcementObservation("GET /orders/{id}", "order", cross_owner_denied=True),
        EnforcementObservation("GET /orders/{id}/invoice", "order", cross_owner_denied=False),
    ]
    incs = detect(obs)
    assert len(incs) == 1
    assert incs[0].object_type == "order"
    assert "GET /orders/{id}/invoice" in incs[0].leaking


def test_inconsistency_ignores_consistent_type():
    obs = [
        EnforcementObservation("GET /profile/{id}", "profile", cross_owner_denied=True),
        EnforcementObservation("GET /profile/{id}/avatar", "profile", cross_owner_denied=True),
    ]
    assert detect(obs) == []


def test_inconsistency_all_leaking_is_not_contradiction():
    # если ВСЕ не проверяют — это не self-contradiction (нужен и проверяющий, и нет)
    obs = [
        EnforcementObservation("GET /a/{id}", "x", cross_owner_denied=False),
        EnforcementObservation("GET /b/{id}", "x", cross_owner_denied=False),
    ]
    assert detect(obs) == []


def test_inconsistency_to_findings():
    obs = [
        EnforcementObservation("GET /orders/{id}", "order", cross_owner_denied=True),
        EnforcementObservation("GET /orders/{id}/invoice", "order", cross_owner_denied=False,
                               sample_url="https://t.example/orders/1/invoice"),
    ]
    fs = to_findings(_scope(), Store("/tmp/x.json"), True, obs)
    assert len(fs) == 1 and fs[0].module == "ascend/inconsistency" and fs[0].severity in ("high","medium")


# ── self-provisioned identity (breakthrough #2) ──────────────────────────
def test_identity_gate_refuses_unauthorized():
    pool = identity.IdentityPool(
        victim=identity.Identity("A"), attacker=identity.Identity("B"))
    spec = identity.ProvisionSpec(create_url="https://t.example/orders",
                                  read_template="https://t.example/orders/{id}")
    with pytest.raises(PermissionError):
        identity.self_provisioned_idor(_scope() and Scope(program="t", authorized=False, in_scope=["t.example"]),
                                       Store("/tmp/x.json"), False, pool, spec)


def test_identity_dig_json_path():
    assert identity._dig({"data": {"order": {"id": 42}}}, "data.order.id") == 42
    assert identity._dig({"items": [{"id": 7}]}, "items.0.id") == 7
    assert identity._dig({"a": 1}, "b.c") is None


def test_self_provisioned_confirms_real_idor(monkeypatch):
    # мокаем сеть: create→id=42; A читает свой (данные); B читает объект A (те же данные=IDOR);
    # B читает control (ошибка)
    victim_data = '{"order":42,"owner":"A","card":"1111"}'
    def fake_req(url, method, headers, body=None, timeout=15):
        if method == "POST":
            return Resp(201, '{"id":42}')
        if "/orders/0" in url:            # control — несуществующий
            return Resp(200, '{"error":"not found"}')
        return Resp(200, victim_data)      # baseline (A) и attacker (B) — те же данные
    monkeypatch.setattr(identity, "_req", fake_req)
    pool = identity.IdentityPool(identity.Identity("A", {"Cookie": "s=A"}),
                                 identity.Identity("B", {"Cookie": "s=B"}))
    spec = identity.ProvisionSpec(create_url="https://t.example/orders",
                                  read_template="https://t.example/orders/{id}",
                                  id_path="id", create_payload={"x": 1}, control_id="0")
    fs = identity.self_provisioned_idor(_scope(), Store("/tmp/x.json"), True, pool, spec)
    assert len(fs) == 1 and fs[0].module == "ascend/identity"


def test_self_provisioned_rejects_when_attacker_denied(monkeypatch):
    # правильный authz: B получает отказ (похоже на control) → НЕ репортим
    def fake_req(url, method, headers, body=None, timeout=15):
        if method == "POST":
            return Resp(201, '{"id":42}')
        if headers.get("Cookie") == "s=B":   # attacker — отказ
            return Resp(200, '{"error":"forbidden"}')
        if "/orders/0" in url:
            return Resp(200, '{"error":"forbidden"}')
        return Resp(200, '{"order":42,"owner":"A"}')  # baseline A
    monkeypatch.setattr(identity, "_req", fake_req)
    pool = identity.IdentityPool(identity.Identity("A", {"Cookie": "s=A"}),
                                 identity.Identity("B", {"Cookie": "s=B"}))
    spec = identity.ProvisionSpec(create_url="https://t.example/orders",
                                  read_template="https://t.example/orders/{id}", control_id="0")
    fs = identity.self_provisioned_idor(_scope(), Store("/tmp/x.json"), True, pool, spec)
    assert fs == []  # authz работает корректно → находки нет
