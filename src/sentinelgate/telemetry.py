"""Low-cardinality runtime telemetry with Prometheus exposition."""

import time
from collections import Counter
from threading import Lock
from typing import Any

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


class RuntimeTelemetry:
    def __init__(self) -> None:
        self.started = time.time()
        self._lock = Lock()
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._latency_buckets: Counter[tuple[str, str, float]] = Counter()
        self._latency_count: Counter[tuple[str, str]] = Counter()
        self._latency_sum: Counter[tuple[str, str]] = Counter()

    def observe(self, method: str, route: str, status: int, elapsed: float) -> None:
        key = (method, route)
        with self._lock:
            self._requests[(method, route, status)] += 1
            self._latency_count[key] += 1
            self._latency_sum[key] += elapsed
            for bucket in LATENCY_BUCKETS:
                if elapsed <= bucket:
                    self._latency_buckets[(method, route, bucket)] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            request_count = sum(self._requests.values())
            error_count = sum(
                count for (*_, status), count in self._requests.items() if status >= 500
            )
        return {
            "uptime_seconds": round(time.time() - self.started, 3),
            "http_requests": request_count,
            "http_5xx": error_count,
        }

    def prometheus(self) -> str:
        lines = [
            "# HELP sentinelgate_process_uptime_seconds Process uptime.",
            "# TYPE sentinelgate_process_uptime_seconds gauge",
            f"sentinelgate_process_uptime_seconds {time.time() - self.started:.3f}",
            "# HELP sentinelgate_http_requests_total HTTP requests by route and status.",
            "# TYPE sentinelgate_http_requests_total counter",
        ]
        with self._lock:
            requests = dict(self._requests)
            buckets = dict(self._latency_buckets)
            counts = dict(self._latency_count)
            sums = dict(self._latency_sum)
        for (method, route, status), count in sorted(requests.items()):
            labels = f'method="{method}",route="{route}",status="{status}"'
            lines.append(f"sentinelgate_http_requests_total{{{labels}}} {count}")
        lines.extend(
            [
                "# HELP sentinelgate_http_request_duration_seconds Request latency.",
                "# TYPE sentinelgate_http_request_duration_seconds histogram",
            ]
        )
        for method, route in sorted(counts):
            labels = f'method="{method}",route="{route}"'
            for bucket in LATENCY_BUCKETS:
                count = buckets.get((method, route, bucket), 0)
                lines.append(
                    "sentinelgate_http_request_duration_seconds_bucket"
                    f'{{{labels},le="{bucket}"}} {count}'
                )
            lines.append(
                "sentinelgate_http_request_duration_seconds_bucket"
                f'{{{labels},le="+Inf"}} {counts[(method, route)]}'
            )
            lines.append(
                f"sentinelgate_http_request_duration_seconds_sum{{{labels}}} "
                f"{sums[(method, route)]:.9f}"
            )
            lines.append(
                f"sentinelgate_http_request_duration_seconds_count{{{labels}}} "
                f"{counts[(method, route)]}"
            )
        return "\n".join(lines) + "\n"


runtime_telemetry = RuntimeTelemetry()
