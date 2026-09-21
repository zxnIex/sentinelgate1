# GitHub App connector

The GitHub connector is the first real network connector in SentinelGate. It is intentionally
narrow: GitHub.com, explicitly allowlisted repositories and six bounded operations.

## 1. Create the GitHub App

In GitHub, create an App for the organization or account that owns the test repository. The
connector does not need a callback URL or webhook for this release. Grant only the repository
permissions required by the enabled tools:

| SentinelGate tool | GitHub repository permission |
|---|---|
| `github_get_issue` | Issues: read |
| `github_read_file` | Contents: read |
| `github_comment_issue` | Issues: write |
| `github_create_branch` | Contents: write |
| `github_update_file` | Contents: write |
| `github_create_pull_request` | Pull requests: write |

Install the App on selected repositories rather than every repository. Generate an RSA private
key, store it outside the project and restrict its filesystem permissions. GitHub documents the
[App JWT](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app)
and [installation-token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
flows used by the connector.

## 2. Configure SentinelGate

```env
SENTINEL_GITHUB_APP_ID=123456
SENTINEL_GITHUB_INSTALLATION_ID=789012
SENTINEL_GITHUB_PRIVATE_KEY_PATH=C:/secure/sentinelgate-app.private-key.pem
SENTINEL_GITHUB_ALLOWED_REPOSITORIES=acme/example-agent-repo
```

Repository names use `owner/repository` and are comma-separated. An empty list denies all
GitHub operations. SentinelGate asks GitHub for a short-lived token restricted to the requested
repository and permission; it never returns that token to the model or dashboard.

## 3. Start in observe mode

Set `SENTINEL_ENFORCEMENT_MODE=observe`, restart the API and mirror calls through
`POST /v1/evaluate` or `POST /mcp`. Observe mode never invokes GitHub, so it is suitable for
checking identities, scopes and proposed policies without repository side effects.

Use dashboard policy replay to inspect the verdicts, then move to `warn` or `enforce`.

## 4. Test an enforced workflow

Issue a `coding-agent` token with only the necessary scopes. Attest the user's request with one
stable trace ID, then perform:

1. `github_get_issue` or `github_read_file`;
2. `github_create_branch`;
3. `github_update_file` on that non-protected branch;
4. `github_create_pull_request`.

Every write becomes an exact, expiring approval. The operator sees the complete arguments,
including file path, content, target branch and provenance, before executing it once.

## Security boundaries

- Issue bodies are `untrusted` and receive `external_content` taint.
- Source files are `internal`; detected credentials cause output blocking.
- Untrusted or prompt-injected traces cannot reach GitHub write tools.
- `.env`, `.env.*`, PEM and key files cannot be read or written.
- `.github/workflows/*` cannot be modified.
- File updates cannot target `main` or `master`.
- Pull requests may target a protected base, but their head must be a non-protected branch.
- Files are limited to 256 KB, and egress budgets may impose a lower policy limit.

SentinelGate cannot stop a developer from giving the agent a second, direct GitHub credential.
Production deployment must remove bypass paths and protect App configuration and private keys.
