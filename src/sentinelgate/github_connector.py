import base64
import json
from datetime import timedelta
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import Field, field_validator

from sentinelgate.executor import (
    StrictArguments,
    ToolExecutionError,
    ToolRegistry,
    ToolResult,
)
from sentinelgate.models import DataClassification, TrustLevel, utc_now

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
NAME = r"^[a-zA-Z0-9_.-]{1,100}$"
BRANCH = r"^[a-zA-Z0-9._/-]{1,200}$"


def _validated_branch(value: str) -> str:
    if value.startswith("/") or ".." in value or "//" in value:
        raise ValueError("GitHub ref must be normalized")
    return value


def _validated_path(value: str) -> str:
    parts = value.replace("\\", "/").split("/")
    if value.startswith(("/", "\\")) or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("GitHub path must be a normalized repository-relative path")
    basename = parts[-1].casefold()
    if basename == ".env" or basename.startswith(".env.") or basename.endswith((".pem", ".key")):
        raise ValueError("Secret-bearing file paths are not accessible by this connector")
    return value


class RepositoryArguments(StrictArguments):
    owner: str = Field(pattern=NAME)
    repo: str = Field(pattern=NAME)


class GitHubIssueArguments(RepositoryArguments):
    issue_number: int = Field(ge=1)


class GitHubReadFileArguments(RepositoryArguments):
    path: str = Field(min_length=1, max_length=500)
    ref: str = Field(default="main", pattern=BRANCH)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        return _validated_path(value)

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value: str) -> str:
        return _validated_branch(value)


class GitHubCommentArguments(GitHubIssueArguments):
    body: str = Field(min_length=1, max_length=10_000)


class GitHubCreateBranchArguments(RepositoryArguments):
    branch: str = Field(pattern=BRANCH)
    from_ref: str = Field(default="main", pattern=BRANCH)

    @field_validator("branch", "from_ref")
    @classmethod
    def safe_refs(cls, value: str) -> str:
        return _validated_branch(value)

    @field_validator("branch")
    @classmethod
    def non_protected_branch(cls, value: str) -> str:
        if value.casefold() in {"main", "master"}:
            raise ValueError("Protected branch names cannot be created or overwritten")
        return value


class GitHubCreatePullRequestArguments(RepositoryArguments):
    title: str = Field(min_length=1, max_length=256)
    body: str = Field(default="", max_length=20_000)
    head: str = Field(pattern=BRANCH)
    base: str = Field(default="main", pattern=BRANCH)
    draft: bool = True

    @field_validator("head", "base")
    @classmethod
    def safe_refs(cls, value: str) -> str:
        return _validated_branch(value)

    @field_validator("head")
    @classmethod
    def non_protected_head(cls, value: str) -> str:
        if value.casefold() in {"main", "master"}:
            raise ValueError("Pull-request head cannot be a protected branch")
        return value


class GitHubUpdateFileArguments(RepositoryArguments):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=256_000)
    message: str = Field(min_length=1, max_length=200)
    branch: str = Field(pattern=BRANCH)
    sha: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{40}$")

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        normalized = _validated_path(value)
        if normalized.casefold().startswith(".github/workflows/"):
            raise ValueError("GitHub Actions workflows cannot be modified")
        return normalized

    @field_validator("branch")
    @classmethod
    def non_protected_branch(cls, value: str) -> str:
        value = _validated_branch(value)
        if value.casefold() in {"main", "master"}:
            raise ValueError("Direct writes to protected branches are forbidden")
        return value


class GitHubAppClient:
    """GitHub App client that mints repository- and permission-scoped tokens."""

    def __init__(
        self,
        app_id: str | None,
        installation_id: int | None,
        private_key_path: Path | None,
        allowed_repositories: set[str] | None = None,
        client: httpx.Client | None = None,
    ):
        self.app_id = app_id
        self.installation_id = installation_id
        self.private_key_path = private_key_path
        self.allowed_repositories = {
            item.casefold() for item in (allowed_repositories or set()) if item
        }
        self.client = client or httpx.Client(
            base_url=GITHUB_API,
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._tokens: dict[tuple[str, tuple[tuple[str, str], ...]], tuple[str, Any]] = {}
        self._lock = Lock()

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.installation_id and self.private_key_path)

    def verify(self) -> dict[str, Any]:
        if not self.allowed_repositories:
            raise ToolExecutionError("GitHub repository allowlist is empty")
        full_name = min(self.allowed_repositories)
        owner, repo = full_name.split("/", 1)
        payload = self.request(
            "GET", f"/repos/{owner}/{repo}", owner=owner, repo=repo,
            permissions={"contents": "read"},
        )
        if not isinstance(payload, dict) or not payload.get("full_name"):
            raise ToolExecutionError(
                "GitHub verification returned malformed repository data"
            )
        return {
            "status": "verified",
            "repository": str(payload["full_name"]),
            "private": bool(payload.get("private", False)),
        }

    def request(
        self,
        method: str,
        path: str,
        *,
        owner: str,
        repo: str,
        permissions: dict[str, str],
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        self._assert_repository(owner, repo)
        token = self._installation_token(repo, permissions)
        try:
            response = self.client.request(
                method,
                path,
                headers=self._headers(token),
                json=json_body,
                params=params,
            )
        except httpx.HTTPError as exc:
            raise ToolExecutionError("GitHub API request failed") from exc
        if response.status_code >= 400:
            request_id = response.headers.get("x-github-request-id", "unknown")
            raise ToolExecutionError(
                f"GitHub API returned {response.status_code} (request {request_id})"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ToolExecutionError("GitHub API returned invalid JSON") from exc

    def _assert_repository(self, owner: str, repo: str) -> None:
        full_name = f"{owner}/{repo}".casefold()
        if not self.allowed_repositories:
            raise ToolExecutionError("GitHub repository allowlist is empty")
        if full_name not in self.allowed_repositories:
            raise ToolExecutionError("Repository is outside the SentinelGate allowlist")
        if not self.configured:
            raise ToolExecutionError("GitHub App connector is not configured")

    def _installation_token(
        self, repo: str, permissions: dict[str, str]
    ) -> str:
        key = (repo.casefold(), tuple(sorted(permissions.items())))
        with self._lock:
            cached = self._tokens.get(key)
            if cached and cached[1] > utc_now() + timedelta(minutes=2):
                return cached[0]
            jwt = self._app_jwt()
            try:
                response = self.client.post(
                    f"/app/installations/{self.installation_id}/access_tokens",
                    headers=self._headers(jwt),
                    json={"repositories": [repo], "permissions": permissions},
                )
            except httpx.HTTPError as exc:
                raise ToolExecutionError("Could not mint GitHub installation token") from exc
            if response.status_code >= 400:
                raise ToolExecutionError(
                    f"GitHub installation token request returned {response.status_code}"
                )
            payload = response.json()
            try:
                token = str(payload["token"])
                expires_at = payload["expires_at"]
                from datetime import datetime

                expiry = datetime.fromisoformat(expires_at)
            except (KeyError, TypeError, ValueError) as exc:
                raise ToolExecutionError("GitHub returned a malformed installation token") from exc
            self._tokens[key] = (token, expiry)
            return token

    def _app_jwt(self) -> str:
        if self.private_key_path is None:
            raise ToolExecutionError("GitHub App private key is not configured")
        try:
            pem = self.private_key_path.read_bytes()
            private_key = serialization.load_pem_private_key(pem, password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise ToolExecutionError("Cannot load GitHub App private key") from exc
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ToolExecutionError("GitHub App private key must be RSA")
        now = int(utc_now().timestamp())
        header = self._b64({"alg": "RS256", "typ": "JWT"})
        payload = self._b64({"iat": now - 60, "exp": now + 540, "iss": self.app_id})
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{self._b64_bytes(signature)}"

    @staticmethod
    def _headers(token: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "SentinelGate/0.7",
        }

    @classmethod
    def _b64(cls, value: dict[str, Any]) -> str:
        return cls._b64_bytes(
            json.dumps(value, separators=(",", ":")).encode("utf-8")
        )

    @staticmethod
    def _b64_bytes(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class GitHubConnector:
    def __init__(self, client: GitHubAppClient):
        self.client = client

    def get_issue(self, args: dict[str, Any]) -> ToolResult:
        item = self.client.request(
            "GET",
            f"/repos/{args['owner']}/{args['repo']}/issues/{args['issue_number']}",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"issues": "read"},
        )
        output = {
            "number": item.get("number"),
            "title": item.get("title", ""),
            "body": str(item.get("body") or "")[:50_000],
            "state": item.get("state"),
            "author": (item.get("user") or {}).get("login"),
            "url": item.get("html_url"),
        }
        source = f"github:{args['owner']}/{args['repo']}:issue:{args['issue_number']}"
        return ToolResult(
            output=output,
            classification=DataClassification.INTERNAL,
            labels=frozenset({"github", "external_content", "issue"}),
            trust=TrustLevel.UNTRUSTED,
            sources=(source,),
        )

    def read_file(self, args: dict[str, Any]) -> ToolResult:
        item = self.client.request(
            "GET",
            f"/repos/{args['owner']}/{args['repo']}/contents/{quote(args['path'], safe='/')}",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"contents": "read"},
            params={"ref": args["ref"]},
        )
        if item.get("type") != "file" or item.get("encoding") != "base64":
            raise ToolExecutionError("GitHub path is not a base64-encoded file")
        try:
            encoded = "".join(str(item.get("content", "")).split())
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > 256_000:
                raise ToolExecutionError("GitHub file exceeds the 256 KB connector limit")
            content = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ToolExecutionError("GitHub file is not supported UTF-8 text") from exc
        output = {
            "path": item.get("path"),
            "sha": item.get("sha"),
            "ref": args["ref"],
            "content": content,
        }
        source = f"github:{args['owner']}/{args['repo']}:{args['ref']}:{args['path']}"
        return ToolResult(
            output=output,
            classification=DataClassification.INTERNAL,
            labels=frozenset({"github", "source-code"}),
            trust=TrustLevel.TRUSTED,
            sources=(source,),
        )

    def comment(self, args: dict[str, Any]) -> ToolResult:
        item = self.client.request(
            "POST",
            f"/repos/{args['owner']}/{args['repo']}/issues/{args['issue_number']}/comments",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"issues": "write"},
            json_body={"body": args["body"]},
        )
        return ToolResult(
            output={"id": item.get("id"), "url": item.get("html_url")},
            labels=frozenset({"github", "write"}),
            sources=(f"github:{args['owner']}/{args['repo']}:comment",),
        )

    def create_branch(self, args: dict[str, Any]) -> ToolResult:
        ref = self.client.request(
            "GET",
            f"/repos/{args['owner']}/{args['repo']}/git/ref/heads/{quote(args['from_ref'], safe='')}",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"contents": "read"},
        )
        sha = ((ref.get("object") or {}).get("sha"))
        if not sha:
            raise ToolExecutionError("GitHub source branch did not return a commit SHA")
        created = self.client.request(
            "POST",
            f"/repos/{args['owner']}/{args['repo']}/git/refs",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"contents": "write"},
            json_body={"ref": f"refs/heads/{args['branch']}", "sha": sha},
        )
        return ToolResult(
            output={"ref": created.get("ref"), "sha": sha},
            labels=frozenset({"github", "write"}),
            sources=(f"github:{args['owner']}/{args['repo']}:branch:{args['branch']}",),
        )

    def create_pull_request(self, args: dict[str, Any]) -> ToolResult:
        item = self.client.request(
            "POST",
            f"/repos/{args['owner']}/{args['repo']}/pulls",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"pull_requests": "write"},
            json_body={
                "title": args["title"],
                "body": args["body"],
                "head": args["head"],
                "base": args["base"],
                "draft": args["draft"],
            },
        )
        return ToolResult(
            output={
                "number": item.get("number"),
                "url": item.get("html_url"),
                "state": item.get("state"),
            },
            labels=frozenset({"github", "write", "pull-request"}),
            sources=(f"github:{args['owner']}/{args['repo']}:pull-request",),
        )

    def update_file(self, args: dict[str, Any]) -> ToolResult:
        raw = args["content"].encode("utf-8")
        if len(raw) > 256_000:
            raise ToolExecutionError("GitHub file exceeds the 256 KB connector limit")
        body = {
            "message": args["message"],
            "content": base64.b64encode(raw).decode("ascii"),
            "branch": args["branch"],
        }
        if args.get("sha"):
            body["sha"] = args["sha"]
        item = self.client.request(
            "PUT",
            f"/repos/{args['owner']}/{args['repo']}/contents/{quote(args['path'], safe='/')}",
            owner=args["owner"],
            repo=args["repo"],
            permissions={"contents": "write"},
            json_body=body,
        )
        commit = item.get("commit") or {}
        content = item.get("content") or {}
        return ToolResult(
            output={
                "path": content.get("path", args["path"]),
                "sha": content.get("sha"),
                "commit_sha": commit.get("sha"),
                "url": content.get("html_url"),
            },
            classification=DataClassification.INTERNAL,
            labels=frozenset({"github", "write", "source-code"}),
            sources=(f"github:{args['owner']}/{args['repo']}:{args['branch']}:{args['path']}",),
        )


def register_github_tools(registry: ToolRegistry, connector: GitHubConnector) -> None:
    registry.register(
        "github_get_issue",
        connector.get_issue,
        GitHubIssueArguments,
        "Read a GitHub issue. Issue text is treated as untrusted external content.",
    )
    registry.register(
        "github_read_file",
        connector.read_file,
        GitHubReadFileArguments,
        "Read one bounded UTF-8 file from an allowlisted GitHub repository.",
    )
    registry.register(
        "github_comment_issue",
        connector.comment,
        GitHubCommentArguments,
        "Create a GitHub issue or pull-request comment after policy approval.",
    )
    registry.register(
        "github_create_branch",
        connector.create_branch,
        GitHubCreateBranchArguments,
        "Create a branch from an existing ref after policy approval.",
    )
    registry.register(
        "github_create_pull_request",
        connector.create_pull_request,
        GitHubCreatePullRequestArguments,
        "Create a draft pull request after policy approval.",
    )
    registry.register(
        "github_update_file",
        connector.update_file,
        GitHubUpdateFileArguments,
        "Create or update one file on a non-protected branch after exact approval.",
    )
