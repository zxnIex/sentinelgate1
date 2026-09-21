# Benchmarking SentinelGate v0.10

SentinelGate publishes distinct measurements. Never collapse them into a single "security score."

## Regression and project-authored security evidence

```powershell
python -m sentinelgate.benchmark_suite --iterations 2000 --output evidence/benchmark-v0.10.json
```

The ten-case regression suite confirms known rules return their expected decisions. The 100-case
adversarial set varies injection, secret-like data, field classification and authorization paths.
It retains misses and false positives. Both are project-authored and neither is independent
validation.

## Live HTTP and connector benchmark

Run only against an isolated deployment. The harness creates agent identities, approvals, audit
events and database rows.

```powershell
python -m sentinelgate.production_benchmark `
  --base-url http://127.0.0.1:8000 `
  --concurrency 1,10,50,100 `
  --requests-per-level 250 `
  --endpoint /v1/execute `
  --output evidence/http-benchmark-v0.10.json
```

`SENTINEL_ADMIN_TOKEN` is read from the environment. `--server-pid` makes CPU time and peak RSS
refer to the server; without it they describe the benchmark client.

The default `/v1/execute` path compares direct local knowledge-tool execution with the same allowed
call through HTTP, authentication, policy, database work and the bounded connector. Denied,
field-tainted and approval-required cases stop before connector execution. Use `/v1/evaluate` only
when intentionally measuring decision overhead without connectors.

The harness covers:

- concurrency 1, 10, 50 and 100;
- safe, denied, approval-required and field-tainted requests;
- payloads from 1 KiB through 1 MiB;
- client-observed p50/p95/p99 and throughput;
- HTTP status, decision distribution and error rate;
- process CPU and peak RSS when a server PID is supplied;
- server version, enforcement mode, readiness and database backend;
- the exact reproduction command and whether transport used TLS.

## One-million-request PostgreSQL run

Four levels with 250,000 requests each produce one million requests:

```powershell
python -m sentinelgate.production_benchmark `
  --base-url https://benchmark.sentinelgate.example `
  --concurrency 1,10,50,100 `
  --requests-per-level 250000 `
  --endpoint /v1/execute `
  --server-pid 12345 `
  --output evidence/http-postgres-million.json
```

Before running:

1. Use a disposable PostgreSQL deployment with no customer data.
2. Use a benchmark-only policy whose rate and egress limits exceed the planned volume.
3. Record machine/database sizes, worker count, TLS termination and server command.
4. Capture PostgreSQL CPU, memory, connections, locks and storage latency from the provider.
5. Do not silently remove warm-up failures or rerun only unfavourable levels.

The repository does not ship a fabricated million-request result. Running the harness is a load
test with real infrastructure cost and must happen on the target PostgreSQL environment.

## PostgreSQL concurrency verification

The CI job runs multi-connection approval, outbox and audit-chain races against PostgreSQL 17. To
repeat locally, point only at an explicitly disposable database whose name ends in `_test`:

```powershell
$env:SENTINEL_POSTGRES_TEST_URL = "postgresql://sentinelgate:password@127.0.0.1:5432/sentinelgate_test"
pytest tests/integration
```

The integration test drops and recreates the `public` schema. The suffix guard is deliberate.

## Claim boundary

For every published result include the commit/tag, policy and corpus digests, exact command,
Python version, host, database, worker count, TLS state and unedited output. Independent efficacy
claims require a frozen corpus selected or reviewed by an external party, a preregistered scoring
method, production-shaped benign workflows and all misses.
