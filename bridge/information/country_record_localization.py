"""Localize validated current-country modifier records.

This module is deliberately an adapter seam for :mod:`country_records`.  It
does not capture the modifier list itself.  A caller gives it the child record
returned by ``country_modifiers_memory.read_fields``; the child is validated
again before any localization key is requested.  The native literal reader is
shared with trade and mission information sources, and is only called for a
ready live FRA context.

The static convention is narrow and explicit: a modifier definition key is
the name key and its description key is ``desc_`` followed by that key.  Disk
localisation files establish that convention, but their text is never used as
a fallback for a missing native cache entry.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from . import country_modifiers_memory
from .model import InformationError


_COUNTRY = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_LANGUAGE = "l_english"
_DESCRIPTION_PREFIX = "desc_"
_LOCALISATION_NOT_READ = "LOCALISATION_NOT_READ"
_IDENTITY_KEYS = (
    "status", "mode", "session_id", "game_sha256", "observer", "game_date",
)
_KEY_LIMIT = 160

_BASE_BASIS = "native_direct_country_modifier_records"
_BASE_ORIGIN = "copied_native_country_records"
_LOCALIZATION_BASIS = "native_country_modifier_localization_cache"
_LOCALIZATION_ORIGIN = "copied_native_localization_cache"


def _copy(value: Any) -> Any:
    return deepcopy(value)


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _valid_ascii_key(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= _KEY_LIMIT
        and all(0x21 <= ord(char) <= 0x7E for char in value)
    )


def _raw_key_hex(key: str) -> str:
    try:
        return (key.encode("ascii") + b"\0").hex()
    except (UnicodeEncodeError, AttributeError):
        return ""


def _context_identity(context: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(context.get(key) for key in _IDENTITY_KEYS)


def _read_base_context(base_source: Any) -> dict[str, Any] | None:
    method = getattr(base_source, "context", None)
    if not callable(method):
        return None
    try:
        value = method()
    except Exception:
        return None
    return deepcopy(dict(value)) if isinstance(value, Mapping) else None


def _live_context_reason(
    context: Any,
    country: str,
    base_context: Mapping[str, Any] | None = None,
) -> str | None:
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
        return "OBSERVER_SCOPE_MISMATCH"
    if not isinstance(context, Mapping):
        return _LOCALISATION_NOT_READ
    if context.get("status") != "ready" or context.get("mode") != "live":
        return _LOCALISATION_NOT_READ
    if context.get("observer") != country:
        return "OBSERVER_SCOPE_MISMATCH"
    if context.get("game_version") not in (None, _VERSION):
        return "GAME_VERSION_MISMATCH"
    if context.get("game_sha256") not in (None, _GAME_SHA256):
        return "GAME_BUILD_MISMATCH"
    if base_context is not None and _context_identity(base_context) != _context_identity(context):
        return "LOCALIZATION_CONTEXT_BINDING_INVALID"
    return None


def _unknown_value(
    key: str,
    reason: str,
    *,
    status: str = "unknown",
    localized: Mapping[str, Any] | None = None,
    entry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    localized = localized if isinstance(localized, Mapping) else {}
    entry = entry if isinstance(entry, Mapping) else {}
    provenance = localized.get("provenance", {})
    if not isinstance(provenance, Mapping):
        provenance = {}
    codec = entry.get("codec", localized.get("codec", provenance.get("codec")))
    raw_template_hex = entry.get("raw_template_hex", entry.get("value_hex"))
    result: dict[str, Any] = {
        "status": status,
        "reason": reason,
        "key": key,
        "raw_key_hex": _raw_key_hex(key),
        "language": localized.get("language", entry.get("language")),
        "codec": codec,
        "encoding": codec,
        "source": "native_localization_cache",
        "reader_provenance": _copy(dict(provenance)),
    }
    if isinstance(raw_template_hex, str):
        result["raw_template_hex"] = raw_template_hex
    for field in ("template", "unresolved_tokens", "unresolved_markers"):
        if field in entry:
            result[field] = _copy(entry[field])
    return result


def _known_or_unknown(
    key: str,
    localized: Mapping[str, Any],
    entry: Any,
) -> dict[str, Any]:
    """Normalize one neutral-reader entry without synthesizing display text."""

    if not isinstance(entry, Mapping):
        return _unknown_value(key, "LOCALIZATION_KEY_UNRESOLVED", localized=localized)
    entry_status = entry.get("status")
    if entry_status != "known":
        reason = entry.get("reason") or entry.get("unknown_reason")
        if not isinstance(reason, str) or not reason:
            reason = (
                "DYNAMIC_LOCALIZATION_UNRESOLVED"
                if entry_status in {"template", "dynamic"}
                else "LOCALIZATION_KEY_UNRESOLVED"
            )
        return _unknown_value(key, reason, localized=localized, entry=entry)

    text = entry.get("text")
    raw_template_hex = entry.get("raw_template_hex", entry.get("value_hex"))
    if raw_template_hex is not None:
        if (
            not isinstance(raw_template_hex, str)
            or len(raw_template_hex) % 2
            or any(char not in "0123456789abcdefABCDEF" for char in raw_template_hex)
        ):
            return _unknown_value(key, "LOCALIZATION_BYTES_INVALID", localized=localized, entry=entry)
    dynamic = (
        not isinstance(text, str)
        or any(marker in text for marker in "[]$")
        or bool(entry.get("dynamic_tokens"))
        or bool(entry.get("unresolved_tokens"))
        or bool(entry.get("unresolved_markers"))
        or entry.get("decoded_status") not in (None, "decoded")
        or (
            isinstance(entry.get("template"), str)
            and (
                entry.get("template") != text
                or any(marker in entry["template"] for marker in "[]$")
            )
        )
    )
    if dynamic:
        return _unknown_value(
            key,
            entry.get("reason") if isinstance(entry.get("reason"), str) else "DYNAMIC_LOCALIZATION_UNRESOLVED",
            localized=localized,
            entry=entry,
        )
    result = _unknown_value(key, "LOCALIZATION_KEY_UNRESOLVED", status="known", localized=localized, entry=entry)
    result.pop("reason", None)
    result["value"] = text
    return result


def _record_values(record: Any) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Validate and extract the child record's compact modifier values."""

    try:
        valid = country_modifiers_memory.validate_record(record)
    except Exception:
        valid = False
    if valid is not True:
        return None, "MODIFIER_RECORD_INVALID"
    if not isinstance(record, Mapping):
        return None, "MODIFIER_RECORD_INVALID"
    fields = record.get("fields")
    values = record.get("values")
    field = fields.get("modifiers") if isinstance(fields, Mapping) else None
    entries = field.get("value") if isinstance(field, Mapping) else None
    if entries is None and isinstance(values, Mapping):
        entries = values.get("modifiers")
    if not isinstance(entries, list) or any(not isinstance(item, Mapping) for item in entries):
        return None, "MODIFIER_RECORD_INVALID"
    if field.get("status") != "known" if isinstance(field, Mapping) else True:
        return None, "MODIFIER_RECORD_INVALID"
    return [_copy(dict(item)) for item in entries], None


class NativeCountryModifierLocalizationSource:
    """Resolve names and descriptions for one validated modifier child record.

    The reader is called once for the de-duplicated name and description key
    list.  ``localization_reader`` is shared by callers that combine this
    source with trade or mission text reads.  When omitted, a normal
    ``NativeLocalizationReader`` is constructed lazily only after the supplied
    context has passed the live FRA preflight; recorded, saved, unbound, and
    otherwise unavailable contexts never construct or invoke it.
    """

    def __init__(self, base_source: Any = None, *, localization_reader: Any = None):
        self.base_source = base_source
        self.localization_reader = localization_reader

    def _reader(self) -> Any:
        if self.localization_reader is None:
            from .native_localization import NativeLocalizationReader

            self.localization_reader = NativeLocalizationReader(self.base_source)
        return self.localization_reader

    @staticmethod
    def _field_value(item: Mapping[str, Any], field: str) -> dict[str, Any]:
        key = item.get("key")
        localized = item.get("_localized", {})
        if not isinstance(key, str):
            return {
                "modifier_id": key,
                "status": "unknown",
                "reason": "MODIFIER_KEY_INVALID",
            }
        result = _copy(localized.get(field, {})) if isinstance(localized, Mapping) else {}
        result["modifier_id"] = key
        # Keep the stable native key available beside the field's exact lookup
        # key; this is useful when both name and description are unresolved.
        return result

    def localize_records(
        self,
        record: Any,
        context: Mapping[str, Any] | None,
        *,
        country: str = _COUNTRY,
    ) -> dict[str, Any]:
        entries, record_reason = _record_values(record)
        if record_reason is not None or entries is None:
            return self._failed_result(record_reason or "MODIFIER_RECORD_INVALID", country=country)

        result_entries: list[dict[str, Any]] = []
        keys: list[str] = []
        key_fields: dict[str, tuple[str, str]] = {}
        for native in entries:
            item = _copy(native)
            key = item.get("key")
            if not _valid_ascii_key(key):
                item["_localized"] = {
                    "name": _unknown_value(str(key), "MODIFIER_KEY_INVALID"),
                    "description": _unknown_value(str(key), "MODIFIER_KEY_INVALID"),
                }
                result_entries.append(item)
                continue
            name_key = key
            description_key = _DESCRIPTION_PREFIX + key
            if not _valid_ascii_key(description_key):
                item["_localized"] = {
                    "name": _unknown_value(name_key, "MODIFIER_KEY_INVALID"),
                    "description": _unknown_value(description_key, "MODIFIER_KEY_INVALID"),
                }
                result_entries.append(item)
                continue
            key_fields[key] = (name_key, description_key)
            for lookup_key in (name_key, description_key):
                if lookup_key not in keys:
                    keys.append(lookup_key)
            result_entries.append(item)

        base_context = _read_base_context(self.base_source)
        preflight = _live_context_reason(context, country, base_context)
        localized: Mapping[str, Any] = {}
        localization_status = "unknown"
        localization_reason: str | None = preflight
        attempted = False

        if preflight is None and keys:
            attempted = True
            try:
                reader = self._reader()
                method = getattr(reader, "localized_text", None)
                if not callable(method):
                    raise InformationError(_LOCALISATION_NOT_READ, "Localization reader is unavailable")
                localized_value = method(country, deepcopy(dict(context)), keys)
                localized = localized_value if isinstance(localized_value, Mapping) else {}
                if localized.get("status") != "known" or not isinstance(localized.get("entries"), Mapping):
                    localization_reason = localized.get("reason") if isinstance(localized.get("reason"), str) else "LOCALIZATION_READER_INCOMPLETE"
                else:
                    localization_status = "known"
                    localization_reason = None
            except InformationError as exc:
                localization_reason = str(getattr(exc, "code", None) or "LOCALIZATION_READ_FAILED")
            except Exception as exc:
                localization_reason = getattr(exc, "code", None)
                if not isinstance(localization_reason, str) or not localization_reason:
                    localization_reason = "LOCALIZATION_READ_FAILED"

            after_context = _read_base_context(self.base_source)
            if after_context is not None and base_context is not None and _context_identity(after_context) != _context_identity(base_context):
                localization_status = "unavailable"
                localization_reason = "LOCALIZATION_CONTEXT_CHANGED"

        reader_entries = localized.get("entries", {}) if isinstance(localized, Mapping) else {}
        for item in result_entries:
            key = item.get("key")
            if key not in key_fields:
                continue
            name_key, description_key = key_fields[key]
            if not attempted:
                reason = localization_reason or _LOCALISATION_NOT_READ
                item["_localized"] = {
                    "name": _unknown_value(name_key, reason, status="unknown"),
                    "description": _unknown_value(description_key, reason, status="unknown"),
                }
            elif localization_status != "known":
                reason = localization_reason or "LOCALIZATION_READER_INCOMPLETE"
                status = "unavailable" if localization_status == "unavailable" else "unknown"
                item["_localized"] = {
                    "name": _unknown_value(name_key, reason, status=status, localized=localized),
                    "description": _unknown_value(description_key, reason, status=status, localized=localized),
                }
            else:
                item["_localized"] = {
                    "name": _known_or_unknown(name_key, localized, reader_entries.get(name_key)),
                    "description": _known_or_unknown(description_key, localized, reader_entries.get(description_key)),
                }

        output_records: list[dict[str, Any]] = []
        for item in result_entries:
            output = _copy(item)
            localized_item = output.pop("_localized", {})
            key = output.get("key")
            output["modifier_id"] = key
            output["name"] = _copy(localized_item.get("name", _unknown_value(str(key), "MODIFIER_KEY_INVALID")))
            output["description"] = _copy(localized_item.get("description", _unknown_value(str(key), "MODIFIER_KEY_INVALID")))
            output_records.append(output)

        name_values = [
            {"modifier_id": item.get("modifier_id"), **{k: _copy(v) for k, v in item["name"].items() if k != "modifier_id"}}
            for item in output_records
        ]
        description_values = [
            {"modifier_id": item.get("modifier_id"), **{k: _copy(v) for k, v in item["description"].items() if k != "modifier_id"}}
            for item in output_records
        ]
        name_complete = bool(name_values) and all(item.get("status") == "known" for item in name_values)
        description_complete = bool(description_values) and all(item.get("status") == "known" for item in description_values)
        # An empty validated modifier list is known as an empty list; it has no
        # localization keys and is complete for both fields.
        if not output_records:
            name_complete = description_complete = True
        fields = {
            "name": self._field(name_values, name_complete, localization_reason),
            "description": self._field(description_values, description_complete, localization_reason),
        }
        provenance = {
            "reader": "NativeLocalizationReader",
            "source": "native_localization_cache",
            "key_convention": {
                "name": "modifier_key",
                "description": "desc_<modifier_key>",
                "language": _LANGUAGE,
            },
            "requested_keys": keys,
            "attempted": attempted,
            "status": localization_status if attempted else "not_read",
            "reason": localization_reason,
            "language": localized.get("language") if isinstance(localized, Mapping) else None,
            "codec": (localized.get("provenance", {}).get("codec")
                      if isinstance(localized.get("provenance"), Mapping) else localized.get("codec"))
                      if isinstance(localized, Mapping) else None,
            "reader_provenance": _copy(localized.get("provenance", {})) if isinstance(localized, Mapping) and isinstance(localized.get("provenance", {}), Mapping) else {},
            "resource_text_used_as_fallback": False,
            "native_cache_and_names_atomic": False,
        }
        return {
            "status": "known",
            "country": country,
            "records": output_records,
            "fields": fields,
            "complete": name_complete and description_complete,
            "basis": _LOCALIZATION_BASIS,
            "value_origin": _LOCALIZATION_ORIGIN,
            "period": "current",
            "source": provenance,
        }

    def localize_record(
        self,
        record: Any,
        context: Mapping[str, Any] | None,
        *,
        country: str = _COUNTRY,
    ) -> dict[str, Any]:
        """Singular alias retained for callers that pass one child record."""

        return self.localize_records(record, context, country=country)

    @staticmethod
    def _field(values: list[dict[str, Any]], complete: bool, reason: str | None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "known" if complete else "unknown",
            "value": values,
            "raw": _copy(values),
            "complete": complete,
            "unit": "localized_text",
            "scale": 1,
            "period": "current",
            "basis": _LOCALIZATION_BASIS,
            "value_origin": _LOCALIZATION_ORIGIN,
            "source": "NativeCountryModifierLocalizationSource",
        }
        if not complete:
            result["reason"] = reason or "LOCALIZATION_FIELDS_INCOMPLETE"
        return result

    @staticmethod
    def _failed_result(reason: str, *, country: str) -> dict[str, Any]:
        return {
            "status": "unknown",
            "country": country,
            "records": [],
            "fields": {
                "name": {"status": "unknown", "reason": reason, "complete": False, "value": []},
                "description": {"status": "unknown", "reason": reason, "complete": False, "value": []},
            },
            "complete": False,
            "basis": _LOCALIZATION_BASIS,
            "value_origin": _LOCALIZATION_ORIGIN,
            "period": "current",
            "source": {
                "reader": "NativeLocalizationReader",
                "source": "native_localization_cache",
                "attempted": False,
                "status": "not_read",
                "reason": reason,
                "key_convention": {"name": "modifier_key", "description": "desc_<modifier_key>", "language": _LANGUAGE},
                "resource_text_used_as_fallback": False,
            },
        }


def localize_modifier_records(
    record: Any,
    context: Mapping[str, Any] | None,
    *,
    base_source: Any = None,
    localization_reader: Any = None,
    country: str = _COUNTRY,
) -> dict[str, Any]:
    """Functional convenience wrapper around the shared adapter."""

    return NativeCountryModifierLocalizationSource(
        base_source, localization_reader=localization_reader,
    ).localize_records(record, context, country=country)


# The longer name is useful to callers that treat loans/modifiers as one
# country-record family.  Keep both spellings as the same implementation so a
# parent source can choose its terminology without introducing a second seam.
NativeCountryRecordLocalizationSource = NativeCountryModifierLocalizationSource


def localize_modifier_record(
    record: Any,
    context: Mapping[str, Any] | None,
    *,
    base_source: Any = None,
    localization_reader: Any = None,
    country: str = _COUNTRY,
) -> dict[str, Any]:
    return localize_modifier_records(
        record, context, base_source=base_source,
        localization_reader=localization_reader, country=country,
    )


__all__ = [
    "NativeCountryModifierLocalizationSource",
    "NativeCountryRecordLocalizationSource",
    "localize_modifier_records",
    "localize_modifier_record",
]
