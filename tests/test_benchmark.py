from sentinelgate.benchmark import run


def test_benchmark_reports_explicit_scope():
    report = run(100)
    assert report["benchmark"] == "local_policy_evaluation"
    assert report["iterations"] == 100
    assert report["latency_ms"]["p99"] >= 0
    assert report["throughput_rps"] > 0
    assert "excludes HTTP and connectors" in report["scope"]
