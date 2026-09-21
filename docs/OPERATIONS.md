# SentinelGate v0.10 operations

## Durable notifications

When `SENTINEL_APPROVAL_WEBHOOK_URL` is set, the gateway commits an `approval.required` job to the
database instead of performing network delivery inside the agent request. Run at least one worker:

```powershell
python -m sentinelgate.worker
```

Jobs are deduplicated by approval ID, claimed with a lease, retried with bounded exponential
backoff and moved to `dead` after the configured attempt limit. PostgreSQL uses row locks with
`SKIP LOCKED`; SQLite serializes claims and remains a local-development option only. Worker
heartbeats and the queue are visible under **System health** and `/v1/system/status`.

Worker settings:

| Variable | Default | Purpose |
|---|---:|---|
| `SENTINEL_WORKER_POLL_INTERVAL_SECONDS` | `1` | Idle poll interval |
| `SENTINEL_WORKER_LEASE_SECONDS` | `30` | Time before an abandoned claim can be reclaimed |
| `SENTINEL_WORKER_MAX_ATTEMPTS` | `8` | Delivery attempts before dead-letter state |
| `SENTINEL_WORKER_ID` | generated | Stable instance name when explicitly set |

## Prometheus

Authenticated `/metrics` output includes request counters, latency histograms, business-state
gauges and notification queue metrics. `config/prometheus.example.yml` demonstrates bearer-token
scraping. Use a read-only viewer token at the reverse proxy or identity provider; do not embed an
administrator secret in a checked-in configuration.

## PostgreSQL backup and recovery drill

The commands require PostgreSQL client tools (`pg_dump`, `pg_restore`, `createdb`). Passwords are
passed through the child-process environment, not command-line arguments.

```powershell
python -m sentinelgate.postgres_backup backup .\backups\sentinelgate.dump
python -m sentinelgate.postgres_backup verify .\backups\sentinelgate.dump
python -m sentinelgate.postgres_backup restore-drill .\backups\sentinelgate.dump `
  --target-database sentinelgate_restore_drill
```

Backup publication is atomic and creates a SHA-256 manifest. Verification checks both the digest
and the `pg_restore` catalog. Restore drills refuse a target without the `_restore_drill` suffix,
refuse the source database and never delete an existing database. Clean up the disposable target
manually after application-level validation.

This tooling does not replace managed-database point-in-time recovery, encrypted object retention,
scheduled recovery exercises or provider failover testing.

## Operational alerts

At minimum alert on:

- readiness failure or invalid audit chain;
- HTTP 5xx rate and p95/p99 latency;
- dead notification jobs or an increasing retry backlog;
- stale worker heartbeat when webhooks are enabled;
- PostgreSQL pool exhaustion, connection failures and lock waits;
- abrupt changes in deny, approval or containment volume.
