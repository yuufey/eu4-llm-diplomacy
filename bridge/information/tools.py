"""LLM-facing tools for the read-only information service.

The service itself owns persistence, scheduling and source semantics.  This
module provides the narrow boundary that a model can discover through MCP or
the optional JSONL runner.  The boundary validates the complete request shape
before calling :class:`InformationService`; unknown keys are rejected so a
caller cannot accidentally turn a configuration request into an unrelated
operation.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Callable, Mapping, TYPE_CHECKING

from .model import InformationError, canonical
from .presentation import present_concise, present_discovery

if TYPE_CHECKING:  # pragma: no cover - imported only by type checkers
    from .service import InformationService


_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_TAG = r"^[A-Z0-9]{3}$"


def _schema(kind: str, **values: Any) -> dict[str, Any]:
    result = {"type": kind}
    result.update(values)
    return result


IDENTIFIER_SCHEMA = _schema("string", pattern=_IDENTIFIER)
TAG_SCHEMA = _schema("string", pattern=_TAG)

QUERY_SCHEMA = _schema(
    "object",
    properties={
        "topic": _schema("string", minLength=1, maxLength=128),
        # The information source defines the object identity.  The outer
        # schema keeps it an object while allowing topic-specific keys.
        "object": _schema("object", additionalProperties=True),
        "fields": _schema(
            "array",
            items=_schema("string", minLength=1, maxLength=128),
            minItems=1,
        ),
        "parameters": _schema("object", additionalProperties=True),
    },
    # ``fields`` and ``parameters`` are optional in the public query
    # contract.  InformationService expands them to the topic's declared
    # fields and an empty parameter object after validating the request.
    required=["topic", "object"],
    additionalProperties=False,
)

REPORT_CONFIG_SCHEMA = _schema(
    "object",
    properties={
        "name": _schema("string", minLength=1, maxLength=256),
        "queries": _schema("array", items=QUERY_SCHEMA, minItems=1),
        "detail": _schema("string", enum=["raw", "brief", "full"]),
    },
    # Report create and update both replace the complete configuration.  The
    # service performs a second semantic validation after this shape check.
    required=["name", "queries", "detail"],
    additionalProperties=False,
)

BINDING_SCHEMA = _schema(
    "object",
    properties={
        "session_id": IDENTIFIER_SCHEMA,
        "observer": _schema("string", minLength=1, maxLength=256),
        "game_version": _schema("string", minLength=1, maxLength=128),
        "game_sha256": _schema("string", pattern=r"^[0-9a-fA-F]{64}$"),
        "world_id": IDENTIFIER_SCHEMA,
    },
    # If supplied, a binding is a complete identity.  Omitting it requests
    # the source's current context, which is handled by the service.
    required=["session_id", "observer", "game_version"],
    additionalProperties=False,
)

SCHEDULE_SCHEMA = _schema(
    "object",
    properties={
        "basis": _schema("string", enum=["real", "game"]),
        "every": _schema("integer", minimum=1, maximum=315576000),
        "unit": _schema("string", enum=["seconds", "days"]),
        "missed": _schema("string", enum=["coalesce", "skip"]),
    },
    required=["basis", "every", "unit", "missed"],
    additionalProperties=False,
)

EVENT_SCHEMA = _schema(
    "object",
    properties={
        "types": _schema(
            "array",
            items=_schema("string", minLength=1, maxLength=128),
            minItems=1,
        ),
        "actors": _schema("array", items=TAG_SCHEMA, minItems=1),
        "recipients": _schema("array", items=TAG_SCHEMA, minItems=1),
        "proposal_statuses": _schema("array", items=IDENTIFIER_SCHEMA, minItems=1),
    },
    required=["types"],
    additionalProperties=False,
)

SUBSCRIPTION_CONFIG_SCHEMA = _schema(
    "object",
    properties={
        "name": _schema("string", minLength=1, maxLength=256),
        "kind": _schema("string", enum=["periodic", "event", "change"]),
        "report_id": IDENTIFIER_SCHEMA,
        "enabled": _schema("boolean"),
        "binding": BINDING_SCHEMA,
        "schedule": SCHEDULE_SCHEMA,
        "event": EVENT_SCHEMA,
    },
    # ``binding`` is optional because it defaults to the current source
    # context.  The schedule/event section is required according to ``kind``
    # and checked by _validate_operation_shape.
    required=["name", "kind", "report_id", "enabled"],
    additionalProperties=False,
)


def _object_schema(properties: Mapping[str, dict[str, Any]], required: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
    return _schema(
        "object",
        properties=dict(properties),
        required=list(required),
        additionalProperties=False,
    )


TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "information_discover",
        "description": "查看信息主题与字段名，可用topics筛选；view=full包含对象参数定义、来源和触发能力。",
        "inputSchema": _object_schema({}),
    },
    {
        "name": "information_query",
        "description": "读取游戏信息，默认返回已换算的业务值。金币均为ducats，previous_month_recurring表示上一月经常收支，null表示无可用值。支持批量查询或report_id；view=full读取完整记录。",
        "inputSchema": _object_schema(
            {
                "request_id": IDENTIFIER_SCHEMA,
                "queries": _schema("array", items=QUERY_SCHEMA, minItems=1),
                "report_id": IDENTIFIER_SCHEMA,
            },
            ["request_id"],
        ),
    },
    {
        "name": "information_get_result",
        "description": "按result_id回读结果，默认简洁业务值，view=full返回完整存储记录和交付状态。",
        "inputSchema": _object_schema({"result_id": IDENTIFIER_SCHEMA}, ["result_id"]),
    },
    {
        "name": "information_manage_report",
        "description": "创建、读取、列出、修改或删除可复用的信息集合和详细程度配置。修改使用 expected_version 防止覆盖并发更新。",
        "inputSchema": _object_schema(
            {
                "request_id": IDENTIFIER_SCHEMA,
                "operation": _schema("string", enum=["create", "get", "list", "update", "delete"]),
                "report_id": IDENTIFIER_SCHEMA,
                "config": REPORT_CONFIG_SCHEMA,
                "expected_version": _schema("integer", minimum=1),
            },
            ["request_id", "operation"],
        ),
    },
    {
        "name": "information_manage_subscription",
        "description": "创建、读取、列出、修改、暂停、恢复或取消订阅。定期、事件和变化订阅共用同一报告与结果路径。已配置实时战报采集管理时，事件订阅共用采集来源；capture与runtime分别说明来源状态和订阅实际运行状态。",
        "inputSchema": _object_schema(
            {
                "request_id": IDENTIFIER_SCHEMA,
                "operation": _schema("string", enum=["create", "get", "list", "update", "pause", "resume", "cancel"]),
                "subscription_id": IDENTIFIER_SCHEMA,
                "config": SUBSCRIPTION_CONFIG_SCHEMA,
                "expected_version": _schema("integer", minimum=1),
            },
            ["request_id", "operation"],
        ),
    },
    {
        "name": "information_configure",
        "description": "读取、更新或清除全局信息服务覆盖配置。更新在校验完整后整体生效。",
        "inputSchema": _object_schema(
            {
                "request_id": IDENTIFIER_SCHEMA,
                "operation": _schema("string", enum=["get", "update", "clear"]),
                "values": _schema("object", additionalProperties=True),
                "expected_version": _schema("integer", minimum=0),
            },
            ["request_id", "operation"],
        ),
    },
    {
        "name": "information_status",
        "description": "查看信息服务、来源、调度、订阅和最近导出的实际运行状态；可限制为一个订阅。",
        "inputSchema": _object_schema({"subscription_id": IDENTIFIER_SCHEMA}),
    },
    {
        "name": "information_list_results",
        "description": "按报告详细程度列出最近结果、来源完整性、尝试状态和 SQLite outbox 交付状态。brief结果附完整结果读取入口。",
        "inputSchema": _object_schema({"limit": _schema("integer", minimum=1, maximum=1000)}),
    },
    {
        "name": "information_tick",
        "description": "运行一次到期调度与事件匹配循环；不会推进游戏日期，也不会执行外交动作。",
        "inputSchema": _object_schema({}),
    },
)

for _tool in TOOL_DEFINITIONS:
    if _tool["name"] in {"information_discover", "information_query", "information_get_result",
                          "information_list_results", "information_tick"}:
        _tool["inputSchema"]["properties"]["view"] = _schema(
            "string", enum=["concise", "full"], default="concise",
            description="默认返回业务值；full返回内部来源、诊断及完整原始记录。")
    if _tool["name"] == "information_discover":
        _tool["inputSchema"]["properties"]["topics"] = _schema(
            "array", items=_schema("string"), minItems=1)

TOOL_NAMES = tuple(item["name"] for item in TOOL_DEFINITIONS)
INFORMATION_TOOL_DEFINITIONS = TOOL_DEFINITIONS
TOOLS = TOOL_DEFINITIONS


def _canonical(value: Any) -> str:
    # ``canonical`` also rejects NaN and non-JSON values.  Keep this adapter
    # local so a malformed model value receives the same project error shape.
    return canonical(value)


def _type_matches(value: Any, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return type(value) is int
    if kind == "boolean":
        return type(value) is bool
    if kind == "number":
        return type(value) in (int, float)
    if kind == "null":
        return value is None
    return False


def validate_schema(value: Any, schema: Mapping[str, Any], path: str = "arguments") -> None:
    """Validate the small JSON Schema subset used by the tool definitions.

    The server intentionally does not depend on ``jsonschema``.  This keeps
    the stdio entry point usable in the project's minimal Python environment
    and makes the accepted subset explicit and deterministic.
    """

    kind = schema.get("type")
    if not isinstance(kind, str) or not _type_matches(value, kind):
        raise InformationError("invalid_parameters", f"{path} must be {kind}")
    if "enum" in schema and not any(_canonical(value) == _canonical(item) for item in schema["enum"]):
        raise InformationError("invalid_parameters", f"{path} is outside the allowed values")
    if "const" in schema and _canonical(value) != _canonical(schema["const"]):
        raise InformationError("invalid_parameters", f"{path} must equal {schema['const']!r}")

    if kind == "object":
        if any(not isinstance(key, str) for key in value):
            raise InformationError("invalid_parameters", f"{path} object keys must be strings")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise InformationError("invalid_schema", f"{path} has invalid properties")
        missing = set(schema.get("required", ())) - set(value)
        if missing:
            raise InformationError("invalid_parameters", f"{path}: missing={sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise InformationError("invalid_parameters", f"{path}: unknown={sorted(extra)}")
        for key, item in value.items():
            if key in properties:
                validate_schema(item, properties[key], f"{path}.{key}")
    elif kind == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise InformationError("invalid_parameters", f"{path} has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise InformationError("invalid_parameters", f"{path} has too many items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                validate_schema(item, item_schema, f"{path}[{index}]")
    elif kind == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise InformationError("invalid_parameters", f"{path} is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise InformationError("invalid_parameters", f"{path} is too long")
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            raise InformationError("invalid_parameters", f"{path} does not match the required pattern")
    elif kind in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            raise InformationError("invalid_parameters", f"{path} is below the minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise InformationError("invalid_parameters", f"{path} is above the maximum")


def _validate_operation_shape(name: str, arguments: dict[str, Any]) -> None:
    operation = arguments.get("operation")
    if name == "information_query":
        has_queries = "queries" in arguments
        has_report = "report_id" in arguments
        if has_queries == has_report:
            raise InformationError("invalid_parameters", "query requires exactly one of queries or report_id")
    elif name == "information_manage_report":
        if operation in {"get", "update", "delete"} and "report_id" not in arguments:
            raise InformationError("invalid_parameters", f"{operation} requires report_id")
        if operation == "create" and "config" not in arguments:
            raise InformationError("invalid_parameters", "create requires config")
        if operation == "create" and any(key in arguments for key in ("report_id", "expected_version")):
            raise InformationError("invalid_parameters", "create accepts only request_id, operation and config")
        if operation == "update" and "config" not in arguments:
            raise InformationError("invalid_parameters", "update requires config")
        if operation in {"update", "delete"} and "expected_version" not in arguments:
            raise InformationError("invalid_parameters", f"{operation} requires expected_version")
        if operation == "delete" and "config" in arguments:
            raise InformationError("invalid_parameters", "delete does not accept config")
        if operation == "list" and any(key in arguments for key in ("report_id", "config", "expected_version")):
            raise InformationError("invalid_parameters", "list accepts only request_id and operation")
        if operation == "get" and any(key in arguments for key in ("config", "expected_version")):
            raise InformationError("invalid_parameters", f"{operation} does not accept config or expected_version")
    elif name == "information_manage_subscription":
        if operation in {"get", "update", "pause", "resume", "cancel"} and "subscription_id" not in arguments:
            raise InformationError("invalid_parameters", f"{operation} requires subscription_id")
        if operation == "create" and "config" not in arguments:
            raise InformationError("invalid_parameters", "create requires config")
        if operation == "create" and any(key in arguments for key in ("subscription_id", "expected_version")):
            raise InformationError("invalid_parameters", "create accepts only request_id, operation and config")
        if operation == "update" and "config" not in arguments:
            raise InformationError("invalid_parameters", "update requires config")
        if operation in {"update", "pause", "resume", "cancel"} and "expected_version" not in arguments:
            raise InformationError("invalid_parameters", f"{operation} requires expected_version")
        if operation in {"pause", "resume", "cancel"} and "config" in arguments:
            raise InformationError("invalid_parameters", f"{operation} does not accept config")
        if operation in {"create", "update"}:
            config = arguments.get("config")
            # The nested schema already checks the complete common shape.
            # Trigger-specific sections are deliberately checked here so a
            # periodic/change update cannot retain stale event filters (or
            # vice versa) through an accidental partial replacement.
            kind = config.get("kind") if isinstance(config, dict) else None
            if kind == "event":
                if "event" not in config:
                    raise InformationError("invalid_parameters", "event subscription requires event")
                if "schedule" in config:
                    raise InformationError("invalid_parameters", "event subscription does not accept schedule")
            elif kind in {"periodic", "change"}:
                if "schedule" not in config:
                    raise InformationError("invalid_parameters", f"{kind} subscription requires schedule")
                if "event" in config:
                    raise InformationError("invalid_parameters", f"{kind} subscription does not accept event")
        if operation == "list" and any(key in arguments for key in ("subscription_id", "config", "expected_version")):
            raise InformationError("invalid_parameters", "list accepts only request_id and operation")
        if operation == "get" and any(key in arguments for key in ("config", "expected_version")):
            raise InformationError("invalid_parameters", f"{operation} does not accept config or expected_version")
    elif name == "information_configure":
        if operation == "update" and "values" not in arguments:
            raise InformationError("invalid_parameters", "update requires values")
        if operation in {"update", "clear"} and "expected_version" not in arguments:
            raise InformationError("invalid_parameters", f"{operation} requires expected_version")
        if operation == "get" and any(key in arguments for key in ("values", "expected_version")):
            raise InformationError("invalid_parameters", "get does not accept values or expected_version")
        if operation == "clear" and "values" in arguments:
            raise InformationError("invalid_parameters", "clear does not accept values")


class InformationTools:
    """Strict model-tool facade over one :class:`InformationService`.

    ``call`` intentionally raises :class:`InformationError` for malformed
    requests.  The MCP transport converts that exception into either a JSON-
    RPC parameter error or an MCP tool error while keeping the server alive.
    """

    def __init__(self, service: "InformationService") -> None:
        self.service = service
        self._definitions = deepcopy(list(TOOL_DEFINITIONS))
        self._schemas = {item["name"]: item["inputSchema"] for item in self._definitions}

    def definitions(self) -> list[dict[str, Any]]:
        """Return independent definitions suitable for ``tools/list``."""

        return deepcopy(self._definitions)

    # Common aliases make this facade convenient for small hosts without
    # turning the service methods themselves into a public protocol.
    list_tools = definitions

    def validate(self, name: str, arguments: Any) -> dict[str, Any]:
        if not isinstance(name, str) or name not in self._schemas:
            raise InformationError("unknown_tool", f"Unknown information tool: {name!r}")
        if not isinstance(arguments, dict):
            raise InformationError("invalid_parameters", "arguments must be an object")
        try:
            canonical(arguments)
        except InformationError as error:
            raise InformationError("invalid_parameters", f"arguments must be valid JSON: {error}") from error
        validate_schema(arguments, self._schemas[name])
        _validate_operation_shape(name, arguments)
        return arguments

    def call(self, name: str, arguments: Any | None = None) -> Any:
        arguments = {} if arguments is None else arguments
        arguments = self.validate(name, arguments)
        method_name = name.removeprefix("information_")
        method: Callable[..., Any] = getattr(self.service, method_name, None)
        if not callable(method):
            raise InformationError("service_unavailable", f"Information service has no method {method_name!r}")
        # Passing only supplied optional values preserves the service's own
        # defaults (notably list_results(limit=50) and query filters).
        values = dict(arguments)
        view = values.pop("view", "concise")
        topics = values.pop("topics", None) if name == "information_discover" else None
        result = method(**values)
        if name == "information_discover":
            if topics is not None:
                result = dict(result, topics=[topic for topic in result.get("topics", [])
                                              if topic["topic_id"] in topics])
            return result if view == "full" else present_discovery(result)
        if view == "full":
            return result
        if name in {"information_query", "information_get_result"}:
            return present_concise(result)
        if (name in {"information_list_results", "information_tick"}
                and isinstance(result, dict) and isinstance(result.get("results"), list)):
            return {"results": [present_concise(item) for item in result["results"]]}
        return result

    dispatch = call


InformationToolRegistry = InformationTools


def tool_definitions() -> list[dict[str, Any]]:
    """Return the process-independent MCP tool definitions."""

    return deepcopy(list(TOOL_DEFINITIONS))


def call_tool(service: "InformationService", name: str, arguments: Any | None = None) -> Any:
    """Call one information tool without constructing an MCP transport."""

    return InformationTools(service).call(name, arguments)


__all__ = [
    "InformationTools",
    "InformationToolRegistry",
    "TOOL_DEFINITIONS",
    "INFORMATION_TOOL_DEFINITIONS",
    "TOOL_NAMES",
    "TOOLS",
    "tool_definitions",
    "call_tool",
    "validate_schema",
]
