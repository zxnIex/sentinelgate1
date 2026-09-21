from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, SchemaError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinelgate.knowledge import KnowledgeBase
from sentinelgate.models import DataClassification, TrustLevel


class ToolExecutionError(RuntimeError):
    pass


class ToolValidationError(ValueError):
    pass


class StrictArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SearchKnowledgeArguments(StrictArguments):
    query: str = Field(min_length=1, max_length=500)


class SendEmailArguments(StrictArguments):
    to: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=320)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(max_length=10_000)


class ReadCustomerArguments(StrictArguments):
    customer_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")


@dataclass(frozen=True)
class RegisteredTool:
    handler: Callable[[dict[str, Any]], Any]
    arguments_model: type[BaseModel] | None
    description: str
    input_schema: dict[str, Any] | None = None


@dataclass(frozen=True)
class ToolResult:
    output: Any
    classification: DataClassification = DataClassification.PUBLIC
    labels: frozenset[str] = frozenset()
    trust: TrustLevel = TrustLevel.TRUSTED
    sources: tuple[str, ...] = ()


class ToolRegistry:
    """Code-owned tool registry; arbitrary network destinations are not accepted."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        name: str,
        handler: Callable[[dict[str, Any]], Any],
        arguments_model: type[BaseModel] | None = None,
        description: str = "",
    ) -> None:
        if name in self._tools:
            raise ValueError(f"Tool already registered: {name}")
        self._tools[name] = RegisteredTool(handler, arguments_model, description)

    def register_schema(
        self,
        name: str,
        handler: Callable[[dict[str, Any]], Any],
        input_schema: dict[str, Any],
        description: str = "",
    ) -> None:
        if name in self._tools:
            return
        try:
            Draft202012Validator.check_schema(input_schema)
        except SchemaError as exc:
            raise ToolValidationError(f"Invalid JSON schema for {name}") from exc
        self._tools[name] = RegisteredTool(
            handler, None, description, input_schema
        )

    def definitions(self) -> list[dict[str, Any]]:
        """Return MCP/OpenAI-compatible definitions from code-owned schemas."""
        definitions = []
        for name, tool in sorted(self._tools.items()):
            schema = tool.input_schema or (
                tool.arguments_model.model_json_schema()
                if tool.arguments_model is not None
                else {"type": "object", "additionalProperties": False}
            )
            definitions.append(
                {
                    "name": name,
                    "description": tool.description or f"SentinelGate tool: {name}",
                    "inputSchema": schema,
                }
            )
        return definitions

    def validate(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools.get(name)
        if tool is None or tool.arguments_model is None:
            if tool and tool.input_schema and list(
                Draft202012Validator(tool.input_schema).iter_errors(arguments)
            ):
                raise ToolValidationError(
                    f"Arguments failed schema for {name}"
                )
            return arguments
        try:
            return tool.arguments_model.model_validate(arguments).model_dump()
        except ValidationError as exc:
            raise ToolValidationError(f"Arguments failed schema for {name}") from exc

    def execute(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolExecutionError(f"No executor registered for tool: {name}")
        validated = self.validate(name, arguments)
        try:
            result = tool.handler(validated)
            return result if isinstance(result, ToolResult) else ToolResult(output=result)
        except ToolExecutionError:
            raise
        except Exception as exc:
            raise ToolExecutionError(f"Tool execution failed: {name}") from exc


def demo_registry(knowledge_path: Path | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    knowledge = KnowledgeBase(knowledge_path or Path("./knowledge"))
    registry.register(
        "search_knowledge",
        knowledge.search,
        SearchKnowledgeArguments,
        "Search the governed local knowledge base. Returned data carries signed provenance.",
    )
    registry.register(
        "send_email",
        lambda args: {
            "simulated": True,
            "message": "Email accepted by the demo connector; no real email was sent.",
            "to": args["to"],
        },
        SendEmailArguments,
        "Submit an email through the guarded demo connector. This build does not send real email.",
    )
    registry.register(
        "read_customer_record",
        lambda args: {"customer_id": args["customer_id"], "status": "demo-record"},
        ReadCustomerArguments,
        "Read a simulated customer record through a sensitive-data boundary.",
    )
    return registry
