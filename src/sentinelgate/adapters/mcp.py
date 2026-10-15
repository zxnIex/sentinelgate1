from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MCPGatewayConfig:
    base_url: str
    agent_token: str
    upstream_server_id: str | None = None

    @property
    def url(self) -> str:
        root = self.base_url.rstrip("/")
        if self.upstream_server_id:
            return f"{root}/mcp/upstream/{self.upstream_server_id}"
        return f"{root}/mcp"

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.agent_token}"}

    def as_client_config(self) -> dict[str, object]:
        return {"url": self.url, "headers": self.headers}
