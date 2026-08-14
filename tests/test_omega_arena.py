import pytest

from apex.ascend.arena import (
    BlindArena,
    BlindChallenge,
    GroundTruth,
    ReportedFinding,
    assert_loopback_target,
)
from apex.ascend.evaluation import score_results


def test_arena_rejects_non_loopback_targets():
    with pytest.raises(PermissionError):
        assert_loopback_target("https://example.com")
    assert_loopback_target("http://127.0.0.1:8080")
    assert_loopback_target("http://localhost:3000")


def test_ground_truth_is_not_given_to_solver():
    seen = {}

    def solver(target, metadata):
        seen["target"] = target
        seen["metadata"] = metadata
        return [ReportedFinding("r1", "idor", "/orders/1", 0.99, "replayable proof")]

    challenge = BlindChallenge(
        "unknown-app",
        "http://127.0.0.1:9000",
        ground_truth=(GroundTruth("g1", "idor", "/orders/1"),),
        metadata={"hint": "api"},
    )
    result = BlindArena().run(challenge, solver)
    assert seen == {"target": challenge.target, "metadata": {"hint": "api"}}
    assert len(result.ground_truth) == 1


def test_fifty_of_ten_requires_near_perfect_blind_results():
    challenges = []
    for i in range(40):
        truth = (GroundTruth(f"g{i}", "authz", f"/object/{i}"),)
        challenge = BlindChallenge(f"c{i}", "http://127.0.0.1:8000", truth)

        def solver(target, metadata, i=i):
            return [ReportedFinding(f"r{i}", "authz", f"/object/{i}", 0.99, "proof")]

        challenges.append(BlindArena().run(challenge, solver))

    score = score_results(challenges)
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.evidence_rate == 1.0
    assert score.fifty_of_ten


def test_false_positive_breaks_50x_gate():
    challenge = BlindChallenge(
        "negative",
        "http://127.0.0.1:8000",
        ground_truth=(),
    )
    result = BlindArena().run(
        challenge,
        lambda *_: [ReportedFinding("x", "sqli", "/safe", 0.95, "weak proof")],
    )
    score = score_results([result])
    assert score.false_positives == 1
    assert not score.ten_of_ten
    assert not score.fifty_of_ten
