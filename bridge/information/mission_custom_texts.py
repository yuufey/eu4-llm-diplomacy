"""Normalize and conservatively derive the two selectable mission texts.

The native probe reports a country-bound custom-localisation registry.  This
module only turns that observation into a small, stable record and combines a
whole dynamic template with a separately captured literal cache entry.  It
does not evaluate a game script, call a native function, or claim the UI's
``Root`` object.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any, NoReturn

from .model import InformationError


SUPPORTED_METHODS = (
    "GetSelectableMissionTitle",
    "GetSelectableMissionDescription",
)
WHOLE_TEMPLATES = {
    method: f"[Root.{method}]" for method in SUPPORTED_METHODS
}

_ASCII_TEXT = re.compile(r"[!-~]{1,256}\Z")
_HEX = re.compile(r"[0-9a-fA-F]*\Z")
_MAX_LITERAL_BYTES = 8192
_MAX_RAW_HEX = _MAX_LITERAL_BYTES * 2
_MAX_TEMPLATE_CHARS = 8192
_MAX_DERIVED_BYTES = 32768


def _fail(code: str, message: str) -> NoReturn:
    raise InformationError(f"custom_localization_{code}", message)


def _mapping(value: Any, label: str, code: str = "snapshot_invalid") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code, f"{label} must be an object")
    return value


def _exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        _fail("method_invalid", f"{label} must be a boolean")
    return value


def _exact_int(value: Any, label: str) -> int:
    if type(value) is not int:
        _fail("method_invalid", f"{label} must be an integer")
    return value


def _ascii(value: Any, label: str, *, max_bytes: int = 256) -> str:
    if (not isinstance(value, str) or not value or len(value) > max_bytes
            or _ASCII_TEXT.fullmatch(value) is None):
        _fail("method_invalid", f"{label} must be printable ASCII")
    return value


def _safe_reason(value: Any, default: str) -> str:
    if isinstance(value, str) and value and len(value) <= 256 and "\r" not in value and "\n" not in value:
        return value
    return default


def _unknown_method(name: str, reason: Any) -> dict[str, Any]:
    # Do not carry text_key or selection from an unknown observation: neither
    # is a consumable derivation proof in that state.
    return {
        "status": "unknown",
        "reason": _safe_reason(reason, "CUSTOM_METHOD_UNRESOLVED"),
    }


def _validate_requested(requested_methods: Any) -> list[str]:
    if not isinstance(requested_methods, list) or not requested_methods:
        _fail("request_invalid", "requested_methods must be a distinct supported method list")
    if len(requested_methods) > len(SUPPORTED_METHODS):
        _fail("request_invalid", "requested_methods contains too many methods")
    if any(not isinstance(method, str) or method not in SUPPORTED_METHODS
           for method in requested_methods):
        _fail("request_invalid", "requested_methods contains an unsupported method")
    if len(set(requested_methods)) != len(requested_methods):
        _fail("request_invalid", "requested_methods must not contain duplicates")
    return list(requested_methods)


def _validate_context(context: Any) -> tuple[Mapping[str, Any], str, Any, str]:
    context = _mapping(context, "context", "context_invalid")
    observer = context.get("observer")
    if not isinstance(observer, str) or re.fullmatch(r"[A-Z0-9]{3}", observer) is None:
        _fail("observer_scope_mismatch", "Custom text derivation requires a country observer")
    if context.get("status") != "ready" or context.get("mode") != "live":
        _fail("context_invalid", "custom text derivation requires a ready live context")
    session_id = context.get("session_id")
    game_sha256 = context.get("game_sha256")
    game_date = context.get("game_date")
    if (not isinstance(session_id, str) or not session_id
            or not isinstance(game_sha256, str) or not game_sha256
            or game_date is None or type(game_date) is bool
            or not isinstance(game_date, (str, int))):
        _fail("context_invalid", "context must contain a live session, executable hash and date")
    return context, session_id, game_date, game_sha256


def _validate_shell(report: Any, context: Any, requested: list[str]) -> Mapping[str, Any]:
    report = _mapping(report, "report")
    context, session_id, game_date, game_sha256 = _validate_context(context)
    required = (
        "identity", "request", "query_scope", "static_contract_guard",
        "file_code_guard", "runtime_code_guard", "doublepass", "before",
        "after", "cleanup", "methods",
    )
    for key in required:
        if not isinstance(report.get(key), Mapping):
            _fail("snapshot_invalid", f"report.{key} must be an object")

    if report.get("status") != "observed" or report.get("read_only") is not True:
        _fail("snapshot_incomplete", "custom-localisation capture is not observed read-only data")

    identity = report["identity"]
    if (identity.get("binding_verified") is not True
            or identity.get("installation_session_id") != session_id
            or identity.get("process_path_sha256") != game_sha256):
        _fail("snapshot_incomplete", "capture identity does not match the session context")

    request = report["request"]
    if (request.get("country") != context.get("observer")
            or request.get("methods") != requested):
        _fail("request_invalid", "capture request does not match the observer or method list")

    query_scope = report["query_scope"]
    if (query_scope.get("country") != context.get("observer")
            or query_scope.get("root_kind") != "country"
            or query_scope.get("binding") != "explicit_query_observer"
            or query_scope.get("ui_root_scope_verified") is not False):
        _fail("root_scope_unverified", "capture is not explicitly bound to the observer country Root")

    for key in ("static_contract_guard", "file_code_guard", "runtime_code_guard"):
        if report[key].get("status") != "observed":
            _fail("snapshot_incomplete", f"{key} did not pass its observed guard")

    doublepass = report["doublepass"]
    if (doublepass.get("performed") is not True
            or doublepass.get("consistent") is not True):
        _fail("snapshot_incomplete", "custom-localisation capture was not a consistent double pass")

    for name in ("before", "after"):
        snapshot = report[name]
        date = snapshot.get("game_date")
        if not isinstance(date, Mapping) or snapshot.get("status") != "observed":
            _fail("snapshot_incomplete", f"{name} snapshot is not observed")
        if date.get("raw") != game_date:
            _fail("context_changed", "custom-localisation capture belongs to another game date")

    handle_close = report["cleanup"].get("handle_close")
    if not isinstance(handle_close, Mapping) or handle_close.get("closed") is not True:
        _fail("snapshot_incomplete", "capture handle was not closed")

    methods = report["methods"]
    if set(methods.keys()) != set(requested):
        _fail("snapshot_incomplete", "capture method set does not match the request")
    return report


def _selection(method: Mapping[str, Any], name: str, *, require_status: bool = True) -> dict[str, Any]:
    selection = method.get("selection")
    if not isinstance(selection, Mapping):
        _fail("method_invalid", f"{name} has no selection record")
    status = selection.get("status")
    if status == "unknown":
        reason = selection.get("unknown_reason") or method.get("unknown_reason")
        _fail("method_unknown", _safe_reason(reason, "CUSTOM_SELECTION_UNRESOLVED"))
    if (require_status and status != "observed") or (not require_status and status not in (None, "observed")):
        _fail("method_invalid", f"{name} selection is not observed")

    if selection.get("kind") != "single_unconditional_positive_weight":
        _fail("method_invalid", f"{name} does not satisfy the singleton selection rule")
    option_count = _exact_int(selection.get("option_count"), f"{name}.option_count")
    predicate_count = _exact_int(selection.get("predicate_count"), f"{name}.predicate_count")
    weight = _exact_int(selection.get("weight"), f"{name}.weight")
    random_flag = _exact_int(selection.get("random_flag"), f"{name}.random_flag")
    root_enum = _exact_int(selection.get("root_promotion_enum"), f"{name}.root_promotion_enum")
    modifiers_empty = _exact_bool(selection.get("modifiers_empty"), f"{name}.modifiers_empty")
    builtin_absent = _exact_bool(selection.get("builtin_name_absent"), f"{name}.builtin_name_absent")
    derived = _exact_bool(selection.get("derived_for_query_country_root"), f"{name}.derived_for_query_country_root")
    ui_verified = _exact_bool(selection.get("ui_root_scope_verified"), f"{name}.ui_root_scope_verified")
    if option_count != 1 or predicate_count != 0:
        _fail("method_invalid", f"{name} is not a single predicate-free option")
    if not 0 < weight < 0x80000000:
        _fail("method_invalid", f"{name} has an unbounded or non-positive weight")
    if random_flag not in (0, 1):
        _fail("method_invalid", f"{name}.random_flag is outside the observed domain")
    if (not modifiers_empty or not builtin_absent or not derived
            or root_enum != 3 or ui_verified):
        _fail("root_scope_unverified", f"{name} is not proven for the observer country Root")
    return {
        "kind": "single_unconditional_positive_weight",
        "option_count": option_count,
        "predicate_count": predicate_count,
        "weight": weight,
        "modifiers_empty": True,
        "random_flag": random_flag,
        "builtin_name_absent": True,
        "root_promotion_enum": 3,
        "derived_for_query_country_root": True,
        "ui_root_scope_verified": False,
    }


def _normalize_method(name: str, raw: Any) -> dict[str, Any]:
    raw = _mapping(raw, f"methods.{name}", "method_invalid")
    if raw.get("name") != name:
        _fail("method_invalid", f"methods.{name}.name does not match the request")
    if raw.get("status") == "unknown":
        selection = raw.get("selection")
        nested_reason = selection.get("unknown_reason") if isinstance(selection, Mapping) else None
        return _unknown_method(name, raw.get("unknown_reason") or raw.get("reason") or nested_reason)
    if raw.get("status") != "observed":
        _fail("method_invalid", f"methods.{name}.status is neither observed nor unknown")

    text_key = raw.get("text_key")
    if not isinstance(text_key, Mapping):
        _fail("method_invalid", f"methods.{name}.text_key is not an object")
    if text_key.get("status") == "unknown":
        return _unknown_method(name, text_key.get("unknown_reason") or raw.get("unknown_reason"))
    if text_key.get("status") != "observed":
        _fail("method_invalid", f"methods.{name}.text_key is not observed")
    text = _ascii(text_key.get("text"), f"methods.{name}.text_key.text", max_bytes=160)
    raw_selection = raw.get("selection")
    if isinstance(raw_selection, Mapping) and raw_selection.get("status") == "unknown":
        return _unknown_method(name, raw_selection.get("unknown_reason") or raw.get("unknown_reason"))
    selection = _selection(raw, name)
    return {"status": "known", "text_key": text, "selection": selection}


def normalize_methods(report: Any, context: Any, requested_methods: Any) -> dict[str, Any]:
    """Validate a bounded custom-localisation capture and expose safe methods.

    ``status=known`` describes the capture structure.  An individual method
    may still be ``unknown``; that result contains only its reason and cannot
    supply a localization key to a later cache lookup.
    """
    requested = _validate_requested(requested_methods)
    report = _validate_shell(report, context, requested)
    methods: dict[str, Any] = {}
    for name in requested:
        methods[name] = _normalize_method(name, report["methods"][name])

    context_map, session_id, game_date, game_sha256 = _validate_context(context)
    provenance: dict[str, Any] = {
        "source": "custom_localization_capture",
        "read_only": True,
        "session_id": session_id,
        "game_sha256": game_sha256,
        "game_date": game_date,
        "country": context_map["observer"],
        "root_binding": "explicit_query_observer_country",
        "ui_root_scope_verified": False,
        "selection_rule": "single_unconditional_positive_weight",
        "doublepass_consistent": True,
        "handle_closed": True,
        "native_function_invoked": False,
        "dynamic_substitution_evaluated": False,
        "methods": list(requested),
    }
    profile = report.get("profile")
    if isinstance(profile, Mapping) and isinstance(profile.get("sha256"), str):
        provenance["profile_sha256"] = profile["sha256"]
    if isinstance(report.get("probe_script_sha256"), str):
        provenance["probe_sha256"] = report["probe_script_sha256"]
    # Keep this local variable explicit: the context is validated for the
    # identity/date check above, and the result never carries a live object.
    del context_map
    return {"status": "known", "methods": methods, "provenance": provenance}


def _valid_hex(value: Any) -> bool:
    return (isinstance(value, str) and len(value) <= _MAX_RAW_HEX
            and len(value) % 2 == 0 and _HEX.fullmatch(value) is not None)


def _utf8_length(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def match_single_template(entry: Any) -> dict[str, str] | None:
    """Return the one proven selectable token and its untouched literals.

    A selectable token may be embedded in ordinary text.  The surrounding
    text is retained byte-for-byte at the Python string level; any additional
    bracket or dollar marker makes the entry unresolved because it would
    require another engine substitution stage.
    """
    if not isinstance(entry, Mapping):
        return None
    if (entry.get("status") != "unknown"
            or entry.get("reason") != "DYNAMIC_LOCALIZATION_UNRESOLVED"):
        return None
    template = entry.get("template")
    if (not isinstance(template, str) or not template
            or len(template) > _MAX_TEMPLATE_CHARS):
        return None
    template_bytes = _utf8_length(template)
    if template_bytes is None or template_bytes > _MAX_DERIVED_BYTES:
        return None

    matches: list[tuple[str, int, int]] = []
    for method, token in WHOLE_TEMPLATES.items():
        count = template.count(token)
        if count:
            matches.append((method, count, template.find(token)))
    if len(matches) != 1 or matches[0][1] != 1:
        return None

    method, _, start = matches[0]
    token = WHOLE_TEMPLATES[method]
    prefix = template[:start]
    suffix = template[start + len(token):]
    surrounding = prefix + suffix
    if any(marker in surrounding for marker in "[]$"):
        return None
    if "\x00" in surrounding or any(0xD800 <= ord(char) <= 0xDFFF for char in surrounding):
        return None
    if _utf8_length(prefix) is None or _utf8_length(suffix) is None:
        return None
    return {"method": method, "prefix": prefix, "suffix": suffix}


def _normalized_method_is_usable(method_name: str, normalized: Any) -> bool:
    if not isinstance(normalized, Mapping) or normalized.get("status") != "known":
        return False
    if normalized.get("name", method_name) != method_name:
        return False
    if not isinstance(normalized.get("text_key"), str):
        return False
    text_key = normalized["text_key"]
    if _ASCII_TEXT.fullmatch(text_key) is None:
        return False
    try:
        _selection(normalized, method_name, require_status=False)
    except InformationError:
        return False
    return True


def _cache_entry_is_literal(entry: Any) -> tuple[bool, str | None]:
    if not isinstance(entry, Mapping) or entry.get("status") != "known":
        return False, None
    text = entry.get("text")
    if not isinstance(text, str) or "\x00" in text or any(0xD800 <= ord(char) <= 0xDFFF for char in text):
        return False, None
    try:
        encoded_text = text.encode("utf-8")
    except UnicodeEncodeError:
        return False, None
    if (len(encoded_text) > _MAX_LITERAL_BYTES
            or any(marker in text for marker in "[]$")):
        return False, None
    for key in ("template", "unresolved_tokens", "unresolved_markers"):
        if key not in entry:
            continue
        value = entry[key]
        if key == "template" or value not in ([], ()):
            return False, None
    if entry.get("dynamic_substitution_evaluated") is True:
        return False, None
    raw_hex = entry.get("raw_template_hex")
    if raw_hex is None:
        raw_hex = entry.get("value_hex")
    if not _valid_hex(raw_hex):
        return False, None
    return True, raw_hex


def apply_single_template(
    original_entry: Any,
    method_name: Any,
    normalized_method: Any,
    selected_cache_entry: Any,
) -> dict[str, Any]:
    """Apply one proven singleton method to one matched template entry.

    A failed proof returns a deep copy of ``original_entry``.  This keeps the
    prior dynamic value unknown and prevents a malformed cache record from
    becoming a known text.  The returned entry retains the source template
    and raw bytes for audit, while removing markers that would falsely claim
    they remain unresolved after derivation.
    """
    if not isinstance(original_entry, Mapping):
        _fail("entry_invalid", "original_entry must be an object")
    if not isinstance(method_name, str) or method_name not in SUPPORTED_METHODS:
        _fail("method_invalid", "method_name is not supported")
    try:
        original = deepcopy(dict(original_entry))
    except Exception as exc:
        _fail("entry_invalid", f"original_entry cannot be copied: {exc}")

    template_match = match_single_template(original)
    if template_match is None or template_match["method"] != method_name:
        return original
    if not _normalized_method_is_usable(method_name, normalized_method):
        return original
    if not isinstance(selected_cache_entry, Mapping):
        return original
    original_codec = original.get("codec")
    selected_codec = selected_cache_entry.get("codec")
    if (not isinstance(original_codec, str) or not original_codec
            or not isinstance(selected_codec, str) or not selected_codec
            or original_codec != selected_codec):
        return original
    usable, selected_raw_hex = _cache_entry_is_literal(selected_cache_entry)
    if not usable:
        return original

    selected_text = selected_cache_entry["text"]
    derived_text = (template_match["prefix"] + selected_text
                    + template_match["suffix"])
    derived_bytes = _utf8_length(derived_text)
    if (derived_bytes is None or derived_bytes > _MAX_DERIVED_BYTES
            or "\x00" in derived_text
            or any(0xD800 <= ord(char) <= 0xDFFF for char in derived_text)):
        return original
    result = original
    result.pop("unresolved_tokens", None)
    result.pop("unresolved_markers", None)
    result.pop("reason", None)
    result.update({
        "status": "known",
        "text": derived_text,
        "dynamic_substitution_evaluated": False,
        "custom_text_derivation": {
            "method": method_name,
            "text_key": normalized_method["text_key"],
            "rule": "single_unconditional_positive_weight",
            "root_binding": "explicit_query_observer_country",
            "ui_root_scope_verified": False,
            "selected_text_raw_hex": selected_raw_hex,
            "literal_prefix": template_match["prefix"],
            "literal_suffix": template_match["suffix"],
            "selection": deepcopy(normalized_method["selection"]),
            "native_function_invoked": False,
        },
    })
    return result


__all__ = [
    "SUPPORTED_METHODS",
    "WHOLE_TEMPLATES",
    "match_single_template",
    "normalize_methods",
    "apply_single_template",
]
