"""Developer CLI for installation, diagnostics, policy generation and examples."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from sentinelgate.doctor import run_doctor
from sentinelgate.funnel import FunnelRecorder
from sentinelgate.onboarding import (
    FRAMEWORKS,
    generate_starter_policy,
    integration_snippet,
    load_tool_file,
)


def _dotenv(values: dict[str, str]) -> str:
    return "".join(f"{key}={value}\n" for key, value in values.items())


def _upsert_dotenv(existing: str, values: dict[str, str]) -> str:
    """Update selected dotenv keys without discarding unrelated configuration."""
    remaining = dict(values)
    output: list[str] = []
    for line in existing.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            output.append(line)
            continue
        key = stripped.split("=", 1)[0].removeprefix("export ").strip()
        if key in remaining:
            newline = "\r\n" if line.endswith("\r\n") else "\n"
            output.append(f"{key}={remaining.pop(key)}{newline}")
        else:
            output.append(line)
    if output and not output[-1].endswith(("\n", "\r")):
        output[-1] += "\n"
    output.extend(f"{key}={value}\n" for key, value in remaining.items())
    return "".join(output)


def _recorder(root: Path, enabled: bool) -> FunnelRecorder:
    return FunnelRecorder(
        root,
        enabled=enabled,
        endpoint=os.getenv("SENTINEL_ONBOARDING_TELEMETRY_ENDPOINT"),
    )


def initialize(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    recorder = _recorder(root, args.telemetry)
    recorder.record("init_started")
    env_path = root / ".env"
    if env_path.exists() and not args.rotate_secrets:
        print(f"Kept existing {env_path}")
    else:
        values = {
            "SENTINEL_DATABASE_PATH": "./data/sentinelgate.db",
            "SENTINEL_POLICY_PATH": "./config/policies.json",
            "SENTINEL_KNOWLEDGE_PATH": "./knowledge",
            "SENTINEL_MCP_UPSTREAMS_PATH": "./config/mcp_upstreams.json",
            "SENTINEL_DEPLOYMENT_MODE": "dedicated",
            "SENTINEL_ADMIN_AUTH_MODE": "shared",
            "SENTINEL_ADMIN_TOKEN": secrets.token_urlsafe(48),
            "SENTINEL_AUDIT_SIGNING_KEY": secrets.token_urlsafe(48),
            "SENTINEL_TOKEN_SIGNING_KEY": secrets.token_urlsafe(48),
            "SENTINEL_DATA_ENCRYPTION_KEY": secrets.token_urlsafe(48),
            "SENTINEL_APPROVAL_WEBHOOK_SECRET": secrets.token_urlsafe(48),
            "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
            "SENTINEL_PRODUCT_NAME": args.product_name,
            "SENTINEL_ENVIRONMENT": "development",
            "SENTINEL_ENFORCEMENT_MODE": "enforce",
            "SENTINEL_WATCH_ENABLED": "true",
            "SENTINEL_WATCH_MONITOR_ONLY": "true",
        }
        if env_path.exists():
            secret_keys = {
                key: value
                for key, value in values.items()
                if key
                in {
                    "SENTINEL_ADMIN_TOKEN",
                    "SENTINEL_AUDIT_SIGNING_KEY",
                    "SENTINEL_TOKEN_SIGNING_KEY",
                    "SENTINEL_DATA_ENCRYPTION_KEY",
                    "SENTINEL_APPROVAL_WEBHOOK_SECRET",
                    "POSTGRES_PASSWORD",
                }
            }
            current = env_path.read_text(encoding="utf-8")
            env_path.write_text(_upsert_dotenv(current, secret_keys), encoding="utf-8")
            print(f"Rotated local secrets in {env_path}; preserved other settings")
        else:
            env_path.write_text(_dotenv(values), encoding="utf-8")
            print(f"Created {env_path} with unique local secrets")
    config = root / "config"
    config.mkdir(exist_ok=True)
    policy_path = config / "policies.json"
    if not policy_path.exists() or args.force_policy:
        starter = generate_starter_policy(
            load_tool_file(
                json.dumps(
                    [
                        {
                            "name": "search_knowledge",
                            "description": "Search governed documentation",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}},
                                "required": ["query"],
                                "additionalProperties": False,
                            },
                        }
                    ]
                )
            ),
            "research-agent",
        )["policy"]
        policy_path.write_text(json.dumps(starter, indent=2) + "\n", encoding="utf-8")
        print(f"Created conservative starter policy: {policy_path}")
    mcp_path = config / "mcp_upstreams.json"
    if not mcp_path.exists():
        mcp_path.write_text('{"servers": {}}\n', encoding="utf-8")
    (root / "knowledge").mkdir(exist_ok=True)
    gitignore = root / ".gitignore"
    ignored = {".env", ".venv/", "data/", ".sentinelgate/", "*.pem", "*.key"}
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    missing = [item for item in sorted(ignored) if item not in existing.splitlines()]
    if missing:
        with gitignore.open("a", encoding="utf-8") as stream:
            if existing and not existing.endswith("\n"):
                stream.write("\n")
            stream.write("\n".join(missing) + "\n")
    recorder.record("init_completed")
    print("Next: sentinelgate doctor")
    print("Then: sentinelgate serve")
    return 0


def doctor_command(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    recorder = _recorder(root, args.telemetry)
    recorder.record("doctor_started")
    report = run_doctor(root, args.url)
    for item in report["checks"]:
        symbol = "PASS" if item["status"] == "pass" else "FAIL"
        print(f"[{symbol}] {item['name']}: {item['detail']}")
        if item["fix"]:
            print(f"       Fix: {item['fix']}")
    recorder.record("doctor_passed" if report["ok"] else "doctor_failed", success=report["ok"])
    if args.json:
        print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def policy_command(args: argparse.Namespace) -> int:
    source = Path(args.tools)
    tools = load_tool_file(source.read_text(encoding="utf-8"))
    draft = generate_starter_policy(tools, args.agent_id)
    destination = Path(args.output)
    destination.write_text(json.dumps(draft, indent=2) + "\n", encoding="utf-8")
    _recorder(Path.cwd(), args.telemetry).record("policy_generated")
    print(f"Generated review-required policy draft: {destination}")
    return 0


def snippet_command(args: argparse.Namespace) -> int:
    snippet = integration_snippet(args.framework, tool_name=args.tool)
    if args.output:
        Path(args.output).write_text(snippet, encoding="utf-8")
        print(f"Wrote {args.framework} integration snippet to {args.output}")
    else:
        print(snippet)
    _recorder(Path.cwd(), args.telemetry).record("snippet_generated")
    return 0


def serve_command(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed", file=sys.stderr)
        return 1
    uvicorn.run(
        "sentinelgate.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinelgate")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a safe local configuration")
    init.add_argument("--directory", default=".")
    init.add_argument("--product-name", default="Agent Control Plane")
    init.add_argument("--rotate-secrets", action="store_true")
    init.add_argument("--force-policy", action="store_true")
    init.add_argument("--telemetry", action="store_true", help="Opt in to minimal funnel telemetry")
    init.set_defaults(handler=initialize)

    doctor = sub.add_parser("doctor", help="Diagnose configuration and a running gateway")
    doctor.add_argument("--directory", default=".")
    doctor.add_argument("--url")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--telemetry", action="store_true")
    doctor.set_defaults(handler=doctor_command)

    policy = sub.add_parser("generate-policy", help="Generate a conservative policy draft")
    policy.add_argument("--tools", required=True, help="OpenAI or MCP tools JSON")
    policy.add_argument("--agent-id", required=True)
    policy.add_argument("--output", default="generated-policy.json")
    policy.add_argument("--telemetry", action="store_true")
    policy.set_defaults(handler=policy_command)

    snippet = sub.add_parser("snippet", help="Generate framework integration code")
    snippet.add_argument("framework", choices=FRAMEWORKS)
    snippet.add_argument("--tool", default="search_knowledge")
    snippet.add_argument("--output")
    snippet.add_argument("--telemetry", action="store_true")
    snippet.set_defaults(handler=snippet_command)

    serve = sub.add_parser("serve", help="Run the local gateway")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(handler=serve_command)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
