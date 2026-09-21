"""PostgreSQL backup, verification and bounded restore-drill commands."""

import argparse
import hashlib
import json
import os
import re
import shutil

# Required for fixed PostgreSQL client commands; no shell is used.
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlparse


class BackupError(RuntimeError):
    pass


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise BackupError(f"Required PostgreSQL client executable is unavailable: {name}")
    return str(Path(resolved).resolve())


def _connection_environment(database_url: str) -> tuple[dict[str, str], str]:
    parsed = urlparse(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
    if parsed.scheme != "postgresql" or not parsed.hostname or not parsed.path.strip("/"):
        raise BackupError("A PostgreSQL SENTINEL_DATABASE_URL is required")
    environment = os.environ.copy()
    environment.update(
        {
            "PGHOST": parsed.hostname,
            "PGPORT": str(parsed.port or 5432),
            "PGDATABASE": unquote(parsed.path.strip("/")),
            "PGUSER": unquote(parsed.username or ""),
        }
    )
    if parsed.password:
        environment["PGPASSWORD"] = unquote(parsed.password)
    return environment, environment["PGDATABASE"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_backup(database_url: str, destination: Path) -> dict[str, object]:
    environment, database = _connection_environment(database_url)
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".partial")
    try:
        # Executable is resolved to an absolute path and every flag is fixed.
        subprocess.run(  # nosec B603
            [_executable("pg_dump"), "--format=custom", "--no-owner", "--file", str(temporary)],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        temporary.replace(destination)
    except (OSError, subprocess.CalledProcessError) as exc:
        if temporary.exists():
            temporary.unlink()
        raise BackupError("pg_dump failed; backup was not published") from exc
    manifest = {
        "format": "postgresql-custom",
        "database": database,
        "created_at": datetime.now(UTC).isoformat(),
        "size_bytes": destination.stat().st_size,
        "sha256": _sha256(destination),
        "file": destination.name,
    }
    destination.with_suffix(destination.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def verify_backup(backup: Path) -> dict[str, object]:
    backup = backup.resolve()
    manifest_path = backup.with_suffix(backup.suffix + ".manifest.json")
    if not backup.is_file() or not manifest_path.is_file():
        raise BackupError("Backup and manifest must both exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual = _sha256(backup)
    if actual != manifest.get("sha256"):
        raise BackupError("Backup digest does not match its manifest")
    try:
        # Executable is resolved to an absolute path and every flag is fixed.
        result = subprocess.run(  # nosec B603
            [_executable("pg_restore"), "--list", str(backup)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BackupError("pg_restore could not read the backup catalog") from exc
    return {
        "verified": True,
        "sha256": actual,
        "catalog_entries": len([line for line in result.stdout.splitlines() if line and not line.startswith(";")]),
        "manifest": manifest,
    }


def restore_drill(database_url: str, backup: Path, target_database: str) -> dict[str, object]:
    if (
        not target_database.endswith("_restore_drill")
        or not re.fullmatch(r"[A-Za-z0-9_]{1,63}", target_database)
    ):
        raise BackupError("Restore-drill database name must end with _restore_drill")
    environment, source_database = _connection_environment(database_url)
    if target_database == source_database:
        raise BackupError("Restore drill may not target the source database")
    verification = verify_backup(backup)
    target_environment = environment | {"PGDATABASE": target_database}
    try:
        # Database name is allowlisted and the subprocess never invokes a shell.
        subprocess.run(  # nosec B603
            [_executable("createdb"), target_database],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        # Database name is allowlisted and the subprocess never invokes a shell.
        subprocess.run(  # nosec B603
            [
                _executable("pg_restore"),
                "--exit-on-error",
                "--no-owner",
                "--dbname",
                target_database,
                str(backup.resolve()),
            ],
            env=target_environment,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BackupError(
            "Restore drill failed. SentinelGate does not delete or overwrite the target; inspect it manually."
        ) from exc
    return {
        "restored": True,
        "source_database": source_database,
        "target_database": target_database,
        "backup_sha256": verification["sha256"],
        "cleanup": f"Drop {target_database} manually after validation.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelGate PostgreSQL recovery tools")
    parser.add_argument(
        "--database-url", default=os.getenv("SENTINEL_DATABASE_URL"), help=argparse.SUPPRESS
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("output", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("backup", type=Path)
    restore_parser = subparsers.add_parser("restore-drill")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("--target-database", required=True)
    args = parser.parse_args()
    if args.command in {"backup", "restore-drill"} and not args.database_url:
        parser.error("SENTINEL_DATABASE_URL is required")
    if args.command == "backup":
        result = create_backup(args.database_url, args.output)
    elif args.command == "verify":
        result = verify_backup(args.backup)
    else:
        result = restore_drill(args.database_url, args.backup, args.target_database)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
