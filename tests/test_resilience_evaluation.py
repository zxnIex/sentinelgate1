from sentinelgate.evaluation import run as run_evaluation
from sentinelgate.resilience import run as run_resilience


def test_evaluation_corpus_is_exact_and_reports_scope():
    report = run_evaluation()
    assert report["exact_match_rate"] == 1.0
    assert report["attack_detection_rate"] == 1.0
    assert report["benign_false_positive_rate"] == 0.0
    assert "not an efficacy claim" in report["scope"]


def test_resilience_scenarios_fail_closed_and_are_race_safe():
    report = run_resilience()
    assert report["passed"] == report["total"]
    assert report["total"] >= 4
