"""Read operator-declared decision context without inferring game facts.

The file is deliberately a small input channel.  It supplies only the two
C03 declarations owned here; native legality, strategy, and current game
state remain outside this source's claim.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError
from .sources import _result, _source_info


TOPIC = "C03"
FIELDS = ("strategic_goals", "diplomatic_constraints")
_ALL_FIELDS = frozenset(get_topic(TOPIC)["fields"])
_MAX_FILE_BYTES = 64 * 1024
_MAX_DECLARATIONS = 64
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_TAG = re.compile(r"[A-Z0-9]{3}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTITY_KEYS = ("mode", "observer", "session_id", "game_sha256", "game_version", "game_date")
_GAPS = [
    "NO_NATIVE_LEGALITY_OR_STRATEGY_INFERRED",
    "OPERATOR_INPUT_IS_NOT_GAME_FACT",
    "DECLARATIONS_DO_NOT_PROVE_EFFECT_OR_EXHAUSTIVENESS",
]


class _InputFileError(ValueError):
    """A bounded input file was unreadable or failed its strict schema."""

    def __init__(self, message: str, *, reason: str = "C03_INPUT_FILE_INVALID",
                 unavailable: bool = False):
        super().__init__(message)
        self.reason = reason
        self.unavailable = unavailable


def _identity(context: Any) -> tuple[Any, ...]:
    if not isinstance(context, dict):
        return ()
    return tuple(context.get(key) for key in _IDENTITY_KEYS)


def _ready_identity(context: Any) -> bool:
    if not isinstance(context, dict) or context.get("status") != "ready":
        return False
    return all(context.get(key) is not None for key in _IDENTITY_KEYS)


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(raw: bytes) -> dict[str, Any]:
    def reject_constant(value):
        raise ValueError(f"non-standard JSON constant: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _InputFileError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise _InputFileError("top-level JSON must be an object")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise _InputFileError(message)


def _validate_binding(binding: Any) -> dict[str, str]:
    _require(isinstance(binding, dict), "binding must be an object")
    _require(set(binding) == {"session_id", "observer", "game_sha256"},
             "binding keys are invalid")
    session_id = binding["session_id"]
    observer = binding["observer"]
    game_sha256 = binding["game_sha256"]
    _require(isinstance(session_id, str) and _ID.fullmatch(session_id) is not None,
             "binding.session_id is invalid")
    _require(isinstance(observer, str) and _TAG.fullmatch(observer) is not None,
             "binding.observer is invalid")
    _require(isinstance(game_sha256, str) and _SHA.fullmatch(game_sha256) is not None,
             "binding.game_sha256 is invalid")
    return {"session_id": session_id, "observer": observer, "game_sha256": game_sha256}


def _validate_declarations(value: Any, field: str) -> list[dict[str, str]]:
    _require(isinstance(value, list), f"{field} must be a list")
    _require(len(value) <= _MAX_DECLARATIONS, f"{field} has too many declarations")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        _require(isinstance(item, dict) and set(item) == {"id", "text"},
                 f"{field} declaration shape is invalid")
        identifier = item["id"]
        text = item["text"]
        _require(isinstance(identifier, str) and _ID.fullmatch(identifier) is not None,
                 f"{field} declaration id is invalid")
        _require(identifier not in seen, f"{field} declaration id is duplicated")
        _require(isinstance(text, str) and bool(text) and len(text) <= 2048,
                 f"{field} declaration text is invalid")
        seen.add(identifier)
        result.append({"id": identifier, "text": text})
    return result


def _validate_document(document: Any) -> dict[str, Any]:
    _require(isinstance(document, dict), "document must be an object")
    _require({"schema", "binding"} <= set(document)
             and set(document) <= {"schema", "binding", *FIELDS},
             "document keys are invalid")
    _require(document["schema"] == "EU4-DECISION-CONTEXT/1", "schema is invalid")
    binding = _validate_binding(document["binding"])
    declarations = {}
    for field in FIELDS:
        if field in document:
            declarations[field] = _validate_declarations(document[field], field)
    return {"binding": binding, "declarations": declarations}


def _stat_signature(stat_result) -> tuple[int, int, int, int]:
    return (
        int(stat_result.st_size),
        int(getattr(stat_result, "st_mtime_ns", 0)),
        int(getattr(stat_result, "st_ctime_ns", 0)),
        int(getattr(stat_result, "st_ino", 0)),
    )


class DecisionContextInputsSource:
    """Expose explicitly declared C03 goals/constraints as partial inputs."""

    event_types: tuple[str, ...] = ()
    field_names = FIELDS
    projection_version = 1

    def __init__(self, base_source: Any, config_path: str | Path, *, shared_parameters: dict | None = None):
        self.base_source = base_source
        # A factory may supply the common topic schema when another owner
        # provides paging. This source still accepts no parameters itself.
        self.shared_parameters = deepcopy(shared_parameters)
        try:
            self.config_path = Path(config_path).resolve()
        except (TypeError, ValueError, OSError) as exc:
            raise InformationError("invalid_config_path", "Decision context config path is invalid") from exc

    def context(self) -> dict:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict]:
        topic = get_topic(TOPIC)
        topic.update(
            status="available",
            source=type(self).__name__,
            visibility="input_or_unknown",
            context_scope="session",
            supported_versions=["1.37.4"],
            triggers=["query", "periodic", "change"],
            observer_roles=[],
            source_kind="operator_input",
            basis="explicitly_declared_operator_input",
            parameters=(deepcopy(self.shared_parameters) if self.shared_parameters is not None else
                        {"type": "object", "properties": {}, "additionalProperties": False}),
        )
        topic["object_types"] = ["session"]
        topic["fields"] = {
            "strategic_goals": {
                "coverage": "partial", "source": type(self).__name__, "complete": False,
                "unit": "declared_objectives", "scale": 1, "period": "declared",
                "source_kind": "operator_input", "basis": "explicitly_declared_operator_input",
                "game_fact": False, "supported_object_types": ["session"],
                "supported_parameters": [],
                "gaps": deepcopy(_GAPS),
            },
            "diplomatic_constraints": {
                "coverage": "partial", "source": type(self).__name__, "complete": False,
                "unit": "declared_constraints", "scale": 1, "period": "declared",
                "source_kind": "operator_input", "basis": "explicitly_declared_operator_input",
                "game_fact": False, "supported_object_types": ["session"],
                "supported_parameters": [],
                "gaps": deepcopy(_GAPS),
            },
        }
        if self.shared_parameters is not None:
            # In a shared topic these labels describe only this owner's fields.
            topic.pop("source_kind", None)
            topic.pop("basis", None)
        return [topic]

    def validate_query(self, query: Any, context: dict | None = None) -> dict:
        if (not isinstance(query, dict)
                or not {"topic", "object", "fields"} <= set(query)
                or set(query) - {"topic", "object", "fields", "parameters"}):
            raise InformationError("invalid_parameters", "C03 query has missing or unknown keys")
        if query["topic"] != TOPIC:
            raise InformationError("unsupported_topic", "Decision context inputs support C03 only")
        obj = query["object"]
        if not isinstance(obj, dict) or obj.get("type") != "session" or set(obj) - {"type", "session_id"}:
            raise InformationError("invalid_object", "C03 requires a session selector")
        if "session_id" in obj and (
                not isinstance(obj["session_id"], str) or _ID.fullmatch(obj["session_id"]) is None):
            raise InformationError("invalid_object", "C03 session_id is invalid")
        fields = query["fields"]
        if (not isinstance(fields, list) or not fields or
                any(not isinstance(name, str) or name not in _ALL_FIELDS for name in fields)
                or len(fields) != len(set(fields))):
            raise InformationError("invalid_fields", "C03 requires unique known fields")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "C03 parameters must be empty")
        return {"topic": TOPIC, "object": deepcopy(obj), "fields": list(fields), "parameters": {}}

    def query_capabilities(self, query: Any) -> list[tuple[dict, dict]]:
        normalized = self.validate_query(query)
        fields = [field for field in normalized["fields"] if field in self.field_names]
        if not fields:
            return []
        return [(dict(normalized, fields=fields), self.catalog()[0])]

    def _unknown_fields(self, fields: list[str], reason: str) -> dict[str, dict]:
        return {
            field: {"status": "unknown", "reason": reason, "period": "declared", "complete": False}
            for field in fields if field in self.field_names
        }

    def _unavailable_fields(self, fields: list[str], reason: str) -> dict[str, dict]:
        return {
            field: {"status": "unavailable", "reason": reason, "period": "declared", "complete": False}
            for field in fields if field in self.field_names
        }

    def _source(self, context: dict, *, provenance: dict | None = None) -> dict:
        source = _source_info(type(self).__name__, context, mode="operator_input", complete=False,
                              provenance=provenance)
        source.update(source_kind="operator_input", basis="explicitly_declared_operator_input",
                      game_fact=False, projection_version=self.projection_version)
        return source

    def _result(self, query: dict, context: dict, fields: dict, provenance: dict | None = None) -> dict:
        return _result(query, context, fields, False, self._source(context, provenance=provenance))

    def _file(self) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            before = self.config_path.stat()
        except OSError as exc:
            raise _InputFileError("input file is unavailable") from exc
        before_signature = _stat_signature(before)
        try:
            with self.config_path.open("rb") as stream:
                raw = stream.read(_MAX_FILE_BYTES + 1)
        except (OSError, ValueError) as exc:
            raise _InputFileError("input file is unreadable") from exc
        if len(raw) > _MAX_FILE_BYTES:
            raise _InputFileError("input file exceeds byte limit")
        try:
            after_signature = _stat_signature(self.config_path.stat())
        except OSError as exc:
            raise _InputFileError("input file disappeared") from exc
        if before_signature != after_signature:
            raise _InputFileError("input file changed during read",
                                  reason="C03_INPUT_FILE_CHANGED_DURING_READ",
                                  unavailable=True)
        document = _validate_document(_strict_json(raw))
        return document, {
            "file_sha256": hashlib.sha256(raw).hexdigest(),
            "file_bytes": len(raw),
            "source_path": str(self.config_path),
        }

    def read(self, query: Any, context: dict | None = None) -> dict:
        normalized = self.validate_query(query, context)
        selected = [field for field in normalized["fields"] if field in self.field_names]
        current = deepcopy(context) if isinstance(context, dict) else {}
        fields = {
            field: {"status": "unsupported", "reason": "C03_DECISION_CONTEXT_FIELD_NOT_IMPLEMENTED"}
            for field in normalized["fields"] if field not in self.field_names
        }
        if not selected:
            try:
                current = self.context()
            except Exception:
                current = {}
            return self._result(normalized, current, fields)

        try:
            before = self.context()
        except Exception:
            before = current
            return self._result(normalized, before,
                                {**fields, **self._unavailable_fields(selected, "C03_CONTEXT_UNAVAILABLE")})
        fields.update(self._unknown_fields(selected, "C03_INPUT_NOT_DECLARED"))

        def failure(reason: str, *, unavailable: bool = False, provenance: dict | None = None) -> dict:
            replacement = (self._unavailable_fields(selected, reason) if unavailable
                           else self._unknown_fields(selected, reason))
            merged = dict(fields)
            merged.update(replacement)
            return self._result(normalized, before, merged, provenance)

        if not _ready_identity(before):
            return failure("C03_CONTEXT_UNAVAILABLE", unavailable=True)
        if isinstance(context, dict) and _identity(context) != _identity(before):
            return failure("C03_CONTEXT_MISMATCH", unavailable=True)
        obj_session = normalized["object"].get("session_id")
        if obj_session is not None and obj_session != before.get("session_id"):
            return failure("C03_SESSION_SCOPE_MISMATCH", unavailable=True)

        document = None
        provenance = None
        file_error = None
        try:
            document, provenance = self._file()
        except Exception as exc:
            file_error = exc

        try:
            after = self.context()
        except Exception:
            after = {}
        if not _ready_identity(after) or _identity(before) != _identity(after):
            return self._result(
                normalized, before,
                {**fields, **self._unavailable_fields(selected, "C03_CONTEXT_CHANGED_DURING_READ")},
                provenance,
            )
        if file_error is not None:
            return failure(
                getattr(file_error, "reason", "C03_INPUT_FILE_INVALID"),
                unavailable=bool(getattr(file_error, "unavailable", False)),
                provenance=provenance,
            )
        if not isinstance(document, dict) or not isinstance(provenance, dict):
            return failure("C03_INPUT_FILE_INVALID")
        expected_binding = {
            "session_id": before.get("session_id"),
            "observer": before.get("observer"),
            "game_sha256": before.get("game_sha256"),
        }
        if document["binding"] != expected_binding:
            return failure("C03_INPUT_BINDING_MISMATCH")

        for field in selected:
            if field not in document["declarations"]:
                continue
            declarations = deepcopy(document["declarations"][field])
            fields[field] = {
                "status": "known",
                "value": {
                    "source_kind": "operator_input",
                    "binding": deepcopy(document["binding"]),
                    "declarations": declarations,
                    "game_fact": False,
                },
                "unit": "declared_objectives" if field == "strategic_goals" else "declared_constraints",
                "scale": 1,
                "period": "declared",
                "source_kind": "operator_input",
                "basis": "explicitly_declared_operator_input",
                "game_fact": False,
                "partial": True,
                "complete": False,
                "gaps": deepcopy(_GAPS),
            }
        return self._result(normalized, before, fields, provenance)


__all__ = ["DecisionContextInputsSource"]
