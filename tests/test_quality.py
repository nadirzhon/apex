from apex.models import Finding
from apex.quality import review


def test_complete_evidence_is_prioritized():
    finding = Finding(
        title="Broken object authorization",
        severity="high",
        target="https://example.com/api/orders/42",
        module="ascend",
        description="Другой тестовый пользователь получает приватный объект владельца.",
        evidence="GET https://example.com/api/orders/42 → HTTP 200 with owner marker",
        remediation="Проверять владельца объекта на сервере.",
        cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        references=["OWASP API1:2023"],
    )

    result = review(finding)

    assert result.score >= 80
    assert result.status == "ready_for_human_review"
    assert len(result.fingerprint) == 16


def test_weak_candidate_is_not_presented_as_ready():
    finding = Finding(
        title="Maybe vulnerable", severity="high", target="x", module="scanner"
    )

    result = review(finding)

    assert result.score < 55
    assert result.status == "insufficient_evidence"
