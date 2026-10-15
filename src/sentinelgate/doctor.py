"""Local installation diagnostics with actionable, secret-safe output."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str
    fix: str = ""


def run_doctor(root: Path, base_url: str | None = None) -> dict[str, Any]:
    checks: list[DoctorCheck] = []
    python_ok = sys.version_info >= (3, 11)
    checks.append(
        DoctorCheck(
            "python_version",
            "pass" if python_ok else "fail",
            ".".join(map(str, sys.version_info[:3])),
            "Install Python 3.11 or newer" if not python_ok else "",
        )
    )
    env_path = root / ".env"
    values = dotenv_values(env_path) if env_path.is_file() else {}
    checks.append(
        DoctorCheck(
            "environment_file",
            "pass" if env_path.is_file() else "fail",
            str(env_path),
            "Run: sentinelgate init" if not env_path.is_file() else "",
        )
    )
    policy_value = values.get("SENTINEL_POLICY_PATH") or "./config/policies.json"
    policy = (root / str(policy_value)).resolve()
    policy_valid = False
    policy_detail = str(policy)
    try:
        document = json.loads(policy.read_text(encoding="utf-8"))
        policy_valid = bool(document.get("version") and document.get("tools"))
        if not policy_valid:
            policy_detail += " (missing version or tools)"
    except (OSError, ValueError) as exc:
        policy_detail += f" ({exc})"
    checks.append(
        DoctorCheck(
            "policy",
            "pass" if policy_valid else "fail",
            policy_detail,
            "Run: sentinelgate init --force-policy" if not policy_valid else "",
        )
    )
    secret_names = (
        "SENTINEL_ADMIN_TOKEN",
        "SENTINEL_AUDIT_SIGNING_KEY",
        "SENTINEL_TOKEN_SIGNING_KEY",
        "SENTINEL_DATA_ENCRYPTION_KEY",
    )
    secret_values = [str(values.get(name, "")) for name in secret_names]
    secret_ok = all(
        len(str(values.get(name, ""))) >= 32
        and not str(values.get(name, "")).startswith("replace-with-")
        for name in secret_names
    ) and len(set(secret_values)) == len(secret_values)
    checks.append(
        DoctorCheck(
            "application_secrets",
            "pass" if secret_ok else "fail",
            "four distinct strong values" if secret_ok else "missing, weak or example values",
            "Run: sentinelgate init --rotate-secrets" if not secret_ok else "",
        )
    )
    ignored = False
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "check-ignore", ".env"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        ignored = result.returncode == 0
        checks.append(
            DoctorCheck(
                "env_gitignored",
                "pass" if ignored else "fail",
                ".env is ignored" if ignored else ".env could be committed",
                "Add .env to .gitignore" if not ignored else "",
            )
        )
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", ".env"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        ).returncode == 0
        checks.append(
            DoctorCheck(
                "env_not_tracked",
                "fail" if tracked else "pass",
                ".env is tracked by Git" if tracked else ".env is not tracked",
                "Remove it from Git history and rotate exposed secrets" if tracked else "",
            )
        )
    url = base_url or os.getenv("SENTINEL_BASE_URL")
    if url:
        try:
            response = httpx.get(
                f"{url.rstrip('/')}/health", timeout=3.0, trust_env=False
            )
            response.raise_for_status()
            payload = response.json()
            version = payload.get("version", "unknown")
            checks.append(
                DoctorCheck(
                    "gateway_health",
                    "pass",
                    f"{url} responded successfully (v{version})",
                )
            )
        except httpx.HTTPError as exc:
            checks.append(
                DoctorCheck(
                    "gateway_health",
                    "fail",
                    str(exc),
                    "Start with: sentinelgate serve",
                )
            )
    failed = sum(item.status == "fail" for item in checks)
    return {
        "ok": failed == 0,
        "failed": failed,
        "checks": [asdict(item) for item in checks],
    }
