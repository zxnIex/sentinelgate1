import hashlib
import json
from types import SimpleNamespace

from sentinelgate import benchmark_suite
from sentinelgate.postgres_backup import create_backup, restore_drill
from sentinelgate.production_benchmark import _call, _direct_baseline, _latency_summary
from sentinelgate.telemetry import RuntimeTelemetry


def test_runtime_telemetry_exports_low_cardinality_histograms():
    telemetry = RuntimeTelemetry()
    telemetry.observe("GET", "/health", 200, 0.004)
    telemetry.observe("GET", "/health", 503, 0.3)
    snapshot = telemetry.snapshot()
    assert snapshot["http_requests"] == 2
    assert snapshot["http_5xx"] == 1
    output = telemetry.prometheus()
    assert 'route="/health",status="200"' in output
    assert "sentinelgate_http_request_duration_seconds_bucket" in output


def test_production_benchmark_generates_every_scenario(tmp_path):
    scenarios = [
        _call(index, "trusted", "trace-t", "untrusted", "trace-u")[0]
        for index in range(5)
    ]
    assert scenarios == ["safe", "denied", "approval", "field_tainted", "payload"]
    assert _latency_summary([1.0, 2.0, 3.0])["p50"] == 2.0
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    (knowledge / "policy.md").write_text("Security policy", encoding="utf-8")
    baseline = _direct_baseline(2, knowledge)
    assert baseline["iterations"] == 2
    assert baseline["throughput_rps"] > 0


def test_benchmark_suite_stamps_release_and_limitations(monkeypatch):
    monkeypatch.setattr(benchmark_suite, "run_performance", lambda _: {"ok": True})
    monkeypatch.setattr(benchmark_suite, "run_evaluation", lambda _: {"cases": 10})
    monkeypatch.setattr(benchmark_suite, "run_adversarial", lambda _: {"cases": 100})
    monkeypatch.setattr(benchmark_suite, "run_resilience", lambda: {"passed": 4})
    result = benchmark_suite.run(5)
    assert result["sentinelgate_version"] == "0.10.0"
    assert result["adversarial_probes"]["cases"] == 100
    assert result["limitations"]


def test_backup_creation_and_restore_drill_use_fixed_client_commands(monkeypatch, tmp_path):
    calls = []

    def fake_run(arguments, **kwargs):
        calls.append(arguments)
        if "pg_dump" in arguments[0]:
            output = arguments[arguments.index("--file") + 1]
            with open(output, "wb") as destination:
                destination.write(b"custom-format-backup")
        return SimpleNamespace(stdout="; catalog\n1; TABLE public agents\n")

    monkeypatch.setattr(
        "sentinelgate.postgres_backup._executable", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("sentinelgate.postgres_backup.subprocess.run", fake_run)
    backup = tmp_path / "sentinelgate.dump"
    manifest = create_backup(
        "postgresql://user:password@localhost:5432/sentinelgate", backup
    )
    assert manifest["sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert json.loads(backup.with_suffix(".dump.manifest.json").read_text())["sha256"]
    result = restore_drill(
        "postgresql://user:password@localhost:5432/sentinelgate",
        backup,
        "sentinelgate_restore_drill",
    )
    assert result["restored"] is True
    assert any("createdb" in command[0] for command in calls)
