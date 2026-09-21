from sentinelgate.policy import PolicyEngine
from sentinelgate.redteam import run_suite


def test_redteam_suite(policy_file):
    results = run_suite(PolicyEngine(policy_file))
    assert all(item["passed"] for item in results), results
