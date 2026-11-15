"""Project the bounded v6 native battle-text extension.

The extension contains copied native values, not a rendered battle window.
This module keeps each source field separate and applies the explicit
``eu4_escape`` codec only to observed bytes.  A malformed text value is kept
as an unknown field with its raw bytes; a date mismatch makes only the local
text projection unknown so the embedded v5 battle record remains usable.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bridge.native_text import decode_native_text_hex


CODEC = "eu4_escape"
FIELD_ORDER = (
    "definition_key",
    "auxiliary_text",
    "title_helper_candidate",
    "line1_text",
)
FIELD_SOURCES = {
    "definition_key": "message_metadata",
    "auxiliary_text": "message_metadata",
    "title_helper_candidate": "title_helper_candidate",
    "line1_text": "native_line1",
}
KNOWN_STATES = frozenset(("known", "unknown", "absent"))


class BattleNativeTextError(ValueError):
    """The v6 native-text extension cannot be safely projected."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BattleNativeTextError(f"{label}_must_be_object")
    return value


def _field(field_name: str, value: Any) -> dict[str, Any]:
    item = _mapping(value, field_name)
    status = item.get("status")
    source = item.get("source")
    expected_source = FIELD_SOURCES[field_name]
    if status not in KNOWN_STATES:
        raise BattleNativeTextError(f"invalid_field_status:{field_name}")
    if source != expected_source:
        raise BattleNativeTextError(f"field_source_mismatch:{field_name}")

    raw_hex = item.get("raw_hex")
    if status == "known":
        if not isinstance(raw_hex, str):
            raise BattleNativeTextError(f"observed_raw_missing:{field_name}")
        try:
            decoded = decode_native_text_hex(
                raw_hex, codec=CODEC, max_bytes=8192, max_bytes_limit=8192,
            )
        except (ValueError, UnicodeError) as error:
            # The wire decoder has already validated framing, field state,
            # source and hex syntax.  Codec validity is a narrower text
            # knowledge issue: retain the exact bytes instead of retracting
            # the whole v5 battle record.
            return {
                "status": "unknown",
                "raw_hex": raw_hex,
                "source": source,
                "codec": CODEC,
                "decoded": {
                    "status": "unknown",
                    "reason": "NATIVE_TEXT_DECODE_FAILED",
                },
            }
        return {
            "status": "known",
            "raw_hex": raw_hex,
            "source": source,
            "codec": CODEC,
            "decoded": {"status": "known", "value": decoded},
        }

    if raw_hex not in (None, ""):
        raise BattleNativeTextError(f"unobserved_raw_present:{field_name}")
    reason = ("NATIVE_TEXT_FIELD_UNKNOWN" if status == "unknown"
              else "NATIVE_TEXT_FIELD_ABSENT")
    return {
        "status": status,
        "raw_hex": None,
        "source": source,
        "codec": CODEC,
        "decoded": {"status": status, "reason": reason},
    }


def _metadata(decoded: Mapping[str, Any]) -> dict[str, Any]:
    native_text = _mapping(decoded.get("native_text"), "native_text")
    metadata = _mapping(native_text.get("message_metadata"), "message_metadata")
    native_date = _mapping(metadata.get("native_date"), "native_date")
    raw_flags = _mapping(metadata.get("raw_flags"), "raw_flags")
    if native_date.get("status") not in KNOWN_STATES:
        raise BattleNativeTextError("invalid_native_date_status")
    if raw_flags.get("status") not in KNOWN_STATES:
        raise BattleNativeTextError("invalid_raw_flags_status")
    # Keep the decoder's bounded metadata shape, including absent/unknown
    # markers and raw flag bytes.  No display meaning is inferred here.
    return {
        "native_date": dict(native_date),
        "raw_flags": dict(raw_flags),
    }


def project_native_text(decoded: Mapping[str, Any]) -> dict[str, Any]:
    """Return the local B04 projection for a decoder-accepted v6 payload.

    The returned object is inserted under ``details.native_text`` by the
    battle adapter.  It intentionally contains no ``raw_text`` or rendered
    display claim.  A v6 date that disagrees with the embedded v5 observation
    date returns an unknown local projection and leaves the battle record
    available.
    """

    root = _mapping(decoded, "decoded")
    wire = _mapping(root.get("wire6"), "wire6")
    if wire.get("version") != 6:
        raise BattleNativeTextError("native_text_requires_wire_v6")
    native_text = _mapping(root.get("native_text"), "native_text")
    fields = _mapping(native_text.get("text_fields"), "text_fields")
    result = _mapping(_mapping(root.get("observation"), "observation").get("result"),
                      "observation_result")
    metadata = _metadata(root)

    native_date = metadata["native_date"]
    if native_date.get("status") == "known":
        value = native_date.get("value")
        raw_date = result.get("raw_date")
        if type(value) is not int or type(raw_date) is not int or value != raw_date:
            # Keep the captured Line1 bytes inspectable, but explicitly make
            # the section untrusted when its copied metadata belongs to a
            # different native date.  The public raw_text projection below
            # checks this outer status and will not promote the section.
            line1 = _field("line1_text", fields.get("line1_text"))
            if line1["status"] == "known":
                line1 = {
                    **line1,
                    "status": "unknown",
                    "decoded": {
                        "status": "unknown",
                        "reason": "NATIVE_TEXT_DATE_MISMATCH",
                    },
                }
            return {
                "status": "unknown",
                "reason": "NATIVE_TEXT_DATE_MISMATCH",
                "line1_text": line1,
                "metadata": metadata,
                "codec": CODEC,
                "complete": False,
                "full_display_complete": False,
            }

    projected = {
        field_name: _field(field_name, fields.get(field_name))
        for field_name in FIELD_ORDER
    }
    return {
        **projected,
        "metadata": metadata,
        "codec": CODEC,
        "complete": False,
        "full_display_complete": False,
    }


def project_raw_text(native_text: Any, *, wire_version: int) -> dict[str, Any]:
    """Project only a validated native Line1 fragment as partial raw text.

    The field deliberately does not concatenate message-template values or
    infer a missing title, button, layout, or visibility.  Returned ``known``
    means the Line1 fragment itself was copied and decoded, not that the
    battle report is complete.
    """

    def unknown(reason: str) -> dict[str, Any]:
        return {"status": "unknown", "reason": reason}

    if wire_version != 6:
        return unknown("NATIVE_LINE1_NOT_CAPTURED_BY_LEGACY_WIRE")
    if not isinstance(native_text, Mapping):
        return unknown("NATIVE_TEXT_PROJECTION_MISSING")
    if native_text.get("status") == "unknown":
        reason = native_text.get("reason")
        if isinstance(reason, str) and reason:
            return unknown(reason)
        return unknown("NATIVE_TEXT_PROJECTION_UNKNOWN")

    line1 = native_text.get("line1_text")
    if not isinstance(line1, Mapping):
        return unknown("NATIVE_LINE1_FIELD_MISSING")
    if line1.get("source") != FIELD_SOURCES["line1_text"]:
        return unknown("NATIVE_LINE1_SOURCE_MISMATCH")

    status = line1.get("status")
    decoded = line1.get("decoded")
    if status == "absent":
        return unknown("NATIVE_LINE1_ABSENT")
    if status == "unknown":
        decoded_reason = decoded.get("reason") if isinstance(decoded, Mapping) else None
        if decoded_reason == "NATIVE_TEXT_DECODE_FAILED":
            return unknown("NATIVE_LINE1_DECODE_FAILED")
        if decoded_reason == "NATIVE_TEXT_DATE_MISMATCH":
            return unknown("NATIVE_TEXT_DATE_MISMATCH")
        return unknown("NATIVE_LINE1_UNKNOWN")
    if status != "known":
        return unknown("NATIVE_LINE1_STATUS_INVALID")
    if not isinstance(decoded, Mapping) or decoded.get("status") != "known":
        return unknown("NATIVE_LINE1_DECODE_FAILED")

    text = decoded.get("value")
    raw_hex = line1.get("raw_hex")
    if not isinstance(text, str) or not isinstance(raw_hex, str):
        return unknown("NATIVE_LINE1_PROJECTION_INVALID")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return unknown("NATIVE_LINE1_PROJECTION_INVALID")
    if raw.hex() != raw_hex:
        return unknown("NATIVE_LINE1_PROJECTION_INVALID")

    return {
        "status": "known",
        "value": {
            "sections": [{
                "section": "Line1",
                "text": text,
                "raw_hex": raw_hex,
                "source": FIELD_SOURCES["line1_text"],
            }],
            "unit": "native_text_sections",
            "basis": "wire6_native_line1",
            "partial": True,
            "complete": False,
            "missing_sections": ["title", "button_text", "actual_layout_and_visibility"],
            "business_complete": False,
            "full_display_complete": False,
            "native_visibility_verified": False,
        },
    }


__all__ = ["BattleNativeTextError", "CODEC", "project_native_text", "project_raw_text"]
