"""Optional framework adapters. Core SentinelGate has no framework dependency."""

from sentinelgate.adapters.core import GuardedCallable, GuardedToolError

__all__ = ["GuardedCallable", "GuardedToolError"]
