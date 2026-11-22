"""One tool registry for information and the existing diplomacy session."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .diplomacy_control import DiplomacyPermissionError
from .diplomat_recall import MAX_DIPLOMAT_ID, TOOL_NAME as RECALL_TOOL
from .game_time_control import TOOL_DEFINITION as GAME_TIME_DEFINITION, TOOL_NAME as GAME_TIME_TOOL
from .information.model import InformationError, canonical
from .information.tools import InformationTools, TAG_SCHEMA, validate_schema


_ACTION_PROPERTIES = {
    "action_id": {"type": "string", "minLength": 1},
    "actor": TAG_SCHEMA,
    "recipient": TAG_SCHEMA,
    "phase": {"type": "string", "enum": ["initiate", "accept", "reject", "withdraw"]},
    "parameters": {"type": "object", "additionalProperties": True},
}
_ACTION_REQUIRED = ["action_id", "actor", "recipient"]
_REQUEST_ID = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}

_RECALL_DEFINITION = {
    "name": RECALL_TOOL,
    "description": "按 N05 查询返回的外交官 ID，召回本轮控制国的一名外交官。用原 request_id 查询结果。",
    "inputSchema": {
        "type": "object",
        "properties": {
            "request_id": _REQUEST_ID,
            "diplomat_id": {"type": "integer", "minimum": 0, "maximum": MAX_DIPLOMAT_ID},
        },
        "required": ["request_id", "diplomat_id"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": False, "destructiveHint": True,
                    "idempotentHint": True, "openWorldHint": True},
}


DIPLOMACY_TOOL_DEFINITIONS = (
    {
        "name": "list_diplomatic_actions",
        "description": "列出外交行动、参数及当前会话支持的查询和执行能力。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "actor": TAG_SCHEMA,
                "recipient": TAG_SCHEMA,
                "category": {"type": "string", "enum": ["diplomatic_action", "peace_term", "peace"]},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
    {
        "name": "inspect_diplomatic_action",
        "description": "查询具体外交方案的当前条件、接受因素及可执行状态。",
        "inputSchema": {
            "type": "object", "properties": _ACTION_PROPERTIES,
            "required": _ACTION_REQUIRED, "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
    {
        "name": "execute_diplomatic_action",
        "description": (
            "执行一次外交行动，可能改变真实游戏状态。使用唯一 request_id，"
            "随后用 get_diplomatic_result 或信息查询复查。结果未知时保留原编号查询。"
        ),
        "inputSchema": {
            "type": "object", "properties": {"request_id": _REQUEST_ID, **_ACTION_PROPERTIES},
            "required": ["request_id", *_ACTION_REQUIRED], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True,
                        "idempotentHint": False, "openWorldHint": True},
    },
    {
        "name": "get_diplomatic_result",
        "description": "按原请求编号读取外交执行状态、游戏结果及已有证据。",
        "inputSchema": {
            "type": "object", "properties": {"request_id": {"type": "string", "minLength": 1}},
            "required": ["request_id"], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
)


class GameTools:
    """Reuse one service's readers, diplomacy executor and collection lock.

    Registration does not read game state or submit an action. Offline hosts
    expose the same definitions and report source_unavailable for diplomacy.
    The host owns service/journal shutdown, just as it does for information.
    """

    instructions = (
        "Information tools query game state and manage reports/subscriptions. "
        "Diplomacy tools inspect and execute actions through the same configured game session. "
        "execute_diplomatic_action can change the game. Inspect current conditions, use a unique "
        "request_id, then read get_diplomatic_result and query affected state. "
        "For an unknown outcome keep the original request_id and read its result. "
        "A live operator session is required for diplomacy tools."
    )

    def __init__(self, service: Any, diplomacy_tools: Any = None):
        self.service = service
        self.information = InformationTools(service)
        self.diplomacy = (diplomacy_tools if diplomacy_tools is not None
                          else getattr(service, "diplomacy_tools", None))
        self.control = getattr(service, "diplomacy_control", getattr(self.diplomacy, "control", None))
        if self.control is not None:
            self.instructions = (
                self.instructions + f" Assigned principal: {self.control.principal}. "
                f"Controlled country: {self.control.controlled_country or 'none (read only)'}. "
                "For inbound accept/reject the recipient is the decision country."
            )
        self.diplomacy_execution_error = getattr(service, "diplomacy_execution_error", None)
        self._definitions = deepcopy(list(DIPLOMACY_TOOL_DEFINITIONS))
        if self.diplomacy_execution_error is not None:
            self._definitions = [item for item in self._definitions if item["name"] != "execute_diplomatic_action"]
            self.instructions += " Diplomacy execution is unavailable because the native country set could not be confirmed."
        elif getattr(self.diplomacy, "can_recall_diplomat", False) is True:
            self._definitions.append(deepcopy(_RECALL_DEFINITION))
        self.clock = getattr(service, "game_time_control", None)
        self.game_time_control_error = getattr(service, "game_time_control_error", None)
        if self.clock is not None:
            self._definitions.append(deepcopy(GAME_TIME_DEFINITION))
            self.instructions += " set_game_speed controls the game clock in this observer test."
        self._schemas = {item["name"]: item["inputSchema"] for item in self._definitions}

    def definitions(self) -> list[dict[str, Any]]:
        return self.information.definitions() + deepcopy(self._definitions)

    list_tools = definitions

    def call(self, name: str, arguments: Any = None) -> Any:
        if name == GAME_TIME_TOOL and self.clock is None:
            raise InformationError(*(self.game_time_control_error or ("permission_denied", "Clock control is disabled")))
        if name in ("execute_diplomatic_action", RECALL_TOOL) and self.diplomacy_execution_error is not None:
            raise InformationError(*self.diplomacy_execution_error)
        if not isinstance(name, str) or name not in self._schemas:
            return self.information.call(name, arguments)
        arguments = {} if arguments is None else arguments
        try:
            canonical(arguments)
        except InformationError as error:
            raise InformationError("invalid_parameters", str(error)) from error
        validate_schema(arguments, self._schemas[name])
        arguments = deepcopy(arguments)
        if name != GAME_TIME_TOOL and self.diplomacy is None:
            raise InformationError("source_unavailable", "Diplomacy requires a live --operator-session with diplomacy enabled")
        # The background scheduler and all live information collection already
        # acquire this reentrant lock. An action completes before either reads.
        with self.service.collection_lock.acquire():
            if self.service._closed:
                raise InformationError("service_closed", "Game service is closed")
            if name == GAME_TIME_TOOL:
                return self.clock(arguments["speed"])
            try:
                if self.control is not None:
                    if name in ("inspect_diplomatic_action", "execute_diplomatic_action"):
                        self.control.authorize(arguments["action_id"], arguments["actor"],
                                               arguments["recipient"], arguments.get("phase", "initiate"))
                    elif name == "list_diplomatic_actions":
                        actor = self.control.authorize_listing(arguments.get("actor"), arguments.get("recipient"))
                        if actor is not None:
                            arguments["actor"] = actor
                result = getattr(self.diplomacy, name)(**arguments)
                if self.diplomacy_execution_error is not None:
                    self._mark_diplomacy_execution_unavailable(name, result)
                return result
            except DiplomacyPermissionError as error:
                raise InformationError("permission_denied", str(error)) from error
            except InformationError:
                raise
            except ValueError as error:
                raise InformationError("invalid_parameters", str(error)) from error

    def _mark_diplomacy_execution_unavailable(self, name: str, result: dict) -> None:
        code, message = self.diplomacy_execution_error
        if name == "inspect_diplomatic_action":
            result.setdefault("interface_support", {}).update(execute="unavailable", execute_reason_code=code)
            result["authorization"] = {"status": "unavailable", "complete": True,
                                       "reasons": [{"code": code, "text": message}]}
        elif name == "list_diplomatic_actions":
            result["execution_unavailable"] = {"code": code, "message": message}
            for group in ("actions", "incoming_action_definitions"):
                for action in result.get(group, ()):
                    for phase in action.get("phases", {}).values():
                        phase.update(execute="unavailable", execute_reason_code=code)
                        phase.pop("execute_protocol", None)
                        phase.pop("execute_protocol_reason_code", None)
            for proposal in result.get("incoming_proposals", ()):
                proposal.pop("execute", None)

    dispatch = call
