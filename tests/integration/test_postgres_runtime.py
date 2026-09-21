"""Multi-connection PostgreSQL checks; requires an explicitly disposable test DB."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import urlparse

import psycopg
import pytest

from sentinelgate.models import AgentPrincipal, ToolCallRequest, utc_now
from sentinelgate.security import request_hash
from sentinelgate.storage import Store

URL = os.getenv("SENTINEL_POSTGRES_TEST_URL")
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def postgres_url():
    if not URL:
        pytest.skip("SENTINEL_POSTGRES_TEST_URL is not configured")
    database = urlparse(URL).path.strip("/")
    if not database.endswith("_test"):
        pytest.fail("PostgreSQL integration URL must target a database ending in _test")
    with psycopg.connect(URL) as connection:
        connection.execute("DROP SCHEMA public CASCADE")
        connection.execute("CREATE SCHEMA public")
    return URL


@pytest.fixture(scope="module")
def stores(postgres_url):
    first = Store(postgres_url, "audit-key", "encryption-key-that-is-long-enough", 1, 4)
    second = Store(postgres_url, "audit-key", "encryption-key-that-is-long-enough", 1, 4)
    try:
        yield first, second
    finally:
        first.close()
        second.close()


def test_multi_instance_approval_and_outbox_claim_are_single_winner(stores):
    first, second = stores
    principal = AgentPrincipal(
        agent_id="postgres-agent",
        tenant_id="postgres-test",
        scopes=frozenset({"tools:email:send"}),
        token_id="token-postgres",
        expires_at=utc_now() + timedelta(hours=1),
    )
    request = ToolCallRequest(
        user_id="u",
        tool_name="send_email",
        arguments={"to": "test@example.com", "subject": "test", "body": "test"},
    )
    approval = first.create_approval(request, request_hash(request, principal), principal, 900)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda store: store.resolve_approval(approval.id, "approved", "reviewer", "ok"),
                (first, second),
            )
        )
    assert sum(result is not None for result in results) == 1

    first.enqueue_outbox("approval.required", "postgres-job", {"approval_id": approval.id})
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = list(pool.map(lambda store: store.claim_outbox("worker", 30), (first, second)))
    assert sum(job is not None for job in jobs) == 1


def test_concurrent_audit_chain_remains_valid_across_instances(stores):
    first, second = stores
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda index: (first if index % 2 else second).append_audit(
                    "postgres_concurrency_test", {"index": index}
                ),
                range(100),
            )
        )
    assert first.verify_audit_chain() is True
