"""Durable background worker for approval notifications and future connectors."""

import argparse
import os
import signal
import socket
import time
from dataclasses import dataclass
from uuid import uuid4

from sentinelgate.notifications import ApprovalNotifier
from sentinelgate.settings import Settings, get_settings
from sentinelgate.storage import Store


@dataclass(frozen=True)
class WorkResult:
    claimed: bool
    completed: bool
    job_id: str | None = None


class DurableWorker:
    def __init__(
        self,
        store: Store,
        notifier: ApprovalNotifier,
        worker_id: str,
        lease_seconds: int = 30,
    ):
        self.store = store
        self.notifier = notifier
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds

    def process_one(self) -> WorkResult:
        self.store.heartbeat_worker(self.worker_id)
        job = self.store.claim_outbox(self.worker_id, self.lease_seconds)
        if not job:
            return WorkResult(False, False)
        try:
            if job["kind"] != "approval.required":
                raise RuntimeError(f"Unsupported outbox job kind: {job['kind']}")
            approval_id = str(job["payload"]["approval_id"])
            approval = self.store.get_approval(approval_id)
            if approval is None:
                raise RuntimeError("Approval record is unavailable")
            if approval.status != "pending":
                self.store.complete_outbox(job["id"], self.worker_id)
                self.store.heartbeat_worker(self.worker_id, processed_delta=1)
                self.store.append_audit(
                    "approval_notification_skipped",
                    {"approval_id": approval_id, "reason": "approval_not_pending"},
                )
                return WorkResult(True, True, job["id"])
            delivered = self.notifier.notify(
                approval, list(job["payload"].get("reason_codes", []))
            )
            if not delivered:
                raise RuntimeError("Webhook delivery did not return a success response")
            self.store.complete_outbox(job["id"], self.worker_id)
            self.store.heartbeat_worker(self.worker_id, processed_delta=1)
            self.store.append_audit(
                "approval_notification_delivered",
                {
                    "approval_id": approval_id,
                    "job_id": job["id"],
                    "attempt": job["attempts"],
                },
            )
            return WorkResult(True, True, job["id"])
        except Exception as exc:  # noqa: BLE001 - durable job boundary records and retries
            delay = min(300, 2 ** min(int(job["attempts"]), 8))
            self.store.retry_outbox(
                job["id"], self.worker_id, f"{type(exc).__name__}: {exc}", delay
            )
            self.store.heartbeat_worker(self.worker_id, failed_delta=1)
            self.store.append_audit(
                "approval_notification_retry",
                {
                    "job_id": job["id"],
                    "attempt": job["attempts"],
                    "retry_seconds": delay,
                    "error_type": type(exc).__name__,
                },
            )
            return WorkResult(True, False, job["id"])


def _store(settings: Settings) -> Store:
    return Store(
        settings.database_url or settings.database_path,
        settings.audit_signing_key,
        settings.data_encryption_key,
        pool_min_size=settings.database_pool_min_size,
        pool_max_size=settings.database_pool_max_size,
    )


def run(*, once: bool = False) -> int:
    settings = get_settings()
    if not settings.approval_webhook_url:
        raise RuntimeError("SENTINEL_APPROVAL_WEBHOOK_URL is required for the worker")
    worker_id = settings.worker_id or (
        f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:8]}"
    )
    store = _store(settings)
    notifier = ApprovalNotifier(
        settings.approval_webhook_url,
        settings.approval_webhook_secret,
        settings.console_public_url,
    )
    worker = DurableWorker(store, notifier, worker_id, settings.worker_lease_seconds)
    stopping = False

    def stop(*_: object) -> None:
        nonlocal stopping
        stopping = True

    if not once:
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
    try:
        while not stopping:
            result = worker.process_one()
            if once:
                return 0 if not result.claimed or result.completed else 1
            if not result.claimed:
                time.sleep(settings.worker_poll_interval_seconds)
        return 0
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SentinelGate durable worker")
    parser.add_argument("--once", action="store_true", help="Process at most one job")
    args = parser.parse_args()
    raise SystemExit(run(once=args.once))


if __name__ == "__main__":
    main()
