from sentinelgate.watch_simulator import run


def test_watch_simulator_regression_scenarios_pass():
    result = run()
    assert result["all_passed"] is True
    assert result["attack_scenarios_detected"] == result["attack_scenario_count"]
    assert result["benign_scenarios_clear"] == result["benign_scenario_count"]
    assert "not an efficacy claim" in result["claim_boundary"]
