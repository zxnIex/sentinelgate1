# Benchmarking SentinelGate v0.9

SentinelGate publishes three different measurements. They must not be collapsed into one
"security score."

## 1. Regression conformance

`python -m sentinelgate.evaluation`

Confirms that known configured rules return their expected decisions. A 100% result means the
implementation matches the test policy; it is not an attack-detection claim.

## 2. Project-authored adversarial probes

`python -m sentinelgate.adversarial_evaluation --output evidence/adversarial-v0.9.json`

Expands 100 attack and benign variations across prompt injection, secret-like data,
field-classification boundaries and permission checks. Misses and false positives are retained in
the output. The source references OWASP and MITRE ATT&CK/ATLAS categories, but the cases have not
been independently validated.

## 3. Live HTTP load benchmark

Run this only against an isolated deployment because it creates agent identities and audit data:

```bash
python -m sentinelgate.production_benchmark \
  --base-url http://127.0.0.1:8000 \
  --concurrency 1,10,50,100 \
  --requests-per-level 50 \
  --output evidence/http-benchmark.json
```

`SENTINEL_ADMIN_TOKEN` is read from the environment. Use `--admin-token` only where command-line
history exposure is acceptable. `--server-pid` makes CPU and peak RSS refer to the server process;
otherwise they refer to the benchmark client.

The harness covers safe, denied, approval-required, field-tainted and 1 KiB–1 MiB payload paths.
It reports p50/p95/p99, throughput, HTTP errors, decisions and resources at each concurrency level.
It also measures direct local knowledge-tool execution as a baseline.

For one million requests, use `--requests-per-level 250000` with four concurrency levels. First
create a benchmark-only policy with a rate limit above the intended volume. Never weaken the
production policy or run this against customer data. Publish the policy hash, commit, machine,
database, server command, worker count and whether TLS was enabled with every result.

The live harness uses `/v1/evaluate`, so it includes HTTP, authentication, policy and database work
but deliberately excludes connector execution. Connector latency and upstream availability must be
reported separately because they are properties of both systems, not just SentinelGate.

## External-validation gate

Do not market these project-authored probes as an independent benchmark. A credible efficacy claim
requires a frozen corpus selected or reviewed by an external party, a preregistered scoring method,
unmodified results including misses, and enough benign production-shaped workflows to measure
operational false positives.
