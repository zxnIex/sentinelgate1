# PostgreSQL deployment

v0.9 accepts `SENTINEL_DATABASE_URL=postgresql://...` and uses a bounded psycopg connection pool.
SQLite remains available for local development, but `SENTINEL_ENVIRONMENT=production` refuses to
start without PostgreSQL.

```env
SENTINEL_DATABASE_URL=postgresql://sentinelgate:strong-password@postgres:5432/sentinelgate
SENTINEL_DATABASE_POOL_MIN_SIZE=1
SENTINEL_DATABASE_POOL_MAX_SIZE=10
```

The store applies idempotent schema creation and records schema versions in
`schema_migrations`. PostgreSQL advisory transaction locks protect approval consumption, rate and
egress reservations, incident upserts and the audit hash chain across multiple workers.

For local evaluation:

```bash
export POSTGRES_PASSWORD='generate-a-long-random-value'
docker compose up --build
```

Before any production claim, the operator must still test migrations against a copy of production
data, point-in-time backup restoration, connection exhaustion, primary failover, transaction races,
and application rollback in its chosen managed PostgreSQL service. The repository cannot certify
those operational properties.
