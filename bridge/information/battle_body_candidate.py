"""Derive a bounded name-line candidate from copied same-event inputs.

Only plain type-2 NAME replacement is implemented. This never invokes the
engine, reconstructs a missing template from today's cache, or promotes the
result to native Line1/raw_text. Other battle-window controls remain separate.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from bridge.native_text import decode_native_text_hex
from .battle_display_context import project_display_context
from .battle_native_text import BattleNativeTextError, project_native_text

MAX_INPUT_BYTES = 8192
OUTPUT_LIMIT_BYTES = 60 * 1024
CODEC = "eu4_escape"
_FLAGS = {
    "semantics": "derived_plain_type2_name_line",
    "not_raw_text": True,
    "native_formatter_invoked": False,
    "native_line1_verified": False,
    "complete": False,
    "full_display_complete": False,
    "runtime_popup_verified": False,
    "visibility_verified": False,
}


def _unknown(reason: str) -> dict[str, Any]:
    return {**_FLAGS, "status": "unknown", "reason": reason,
            "raw_hex": None, "codec": CODEC,
            "native_name_handoff_verified": False,
            "decoded": {"status": "unknown", "reason": reason}}


def _raw(value: Any) -> bytes:
    if (not isinstance(value, str) or len(value) > 2 * MAX_INPUT_BYTES
            or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]*", value) is None):
        raise ValueError("invalid raw bytes")
    result = bytes.fromhex(value)
    if b"\0" in result:
        raise ValueError("embedded NUL")
    return result


def _parts(template: bytes, token: bytes = b"NAME") -> tuple[list[bytes | None], int]:
    parts: list[bytes | None] = []
    cursor = count = 0
    while cursor < len(template):
        opening = template.find(b"$", cursor)
        if opening < 0:
            parts.append(template[cursor:])
            break
        parts.append(template[cursor:opening])
        closing = template.find(b"$", opening + 1)
        if closing < 0:
            # The native outer scan copies an unmatched tail literally.
            parts.append(template[opening:])
            break
        key = template[opening + 1:closing]
        if b"|" in key:
            raise ValueError("MODIFIER_UNSUPPORTED")
        if key != token:
            raise ValueError("TOKEN_UNSUPPORTED")
        parts.append(None)
        count += 1
        cursor = closing + 1
    return parts, count


def _render_parts(parts: list[bytes | None], value: bytes) -> bytes:
    output = bytearray()
    for part in parts:
        piece = value if part is None else part
        if len(output) + len(piece) + 1 >= OUTPUT_LIMIT_BYTES:
            raise ValueError("EXPANSION_LIMIT")
        output.extend(piece)
    return bytes(output)


def _decode_output(raw: bytes) -> str:
    # Keep the shared decoder's 16KiB input ceiling. Escape markers consume
    # three bytes, so chunk boundaries must never split such a sequence.
    pieces: list[str] = []
    cursor = 0
    while cursor < len(raw):
        limit = min(cursor + 16384, len(raw))
        end = cursor
        while end < limit:
            width = 3 if raw[end] in (0x10, 0x11, 0x12, 0x13) else 1
            if end + width > limit:
                break
            end += width
        if end == cursor:
            raise ValueError("truncated output escape")
        pieces.append(decode_native_text_hex(raw[cursor:end].hex(), codec=CODEC,
                      max_bytes=16384, max_bytes_limit=16384))
        cursor = end
    return "".join(pieces)


def _name(decoded: Mapping[str, Any], identity: tuple[int, int, int]
          ) -> tuple[bytes | None, str | None, str | None]:
    """Return bytes/source/error; untrusted helper metadata cannot veto NAME."""
    helper = None
    try:
        native = project_native_text(decoded)
        candidate = native.get("title_helper_candidate")
        if (native.get("status") != "unknown" and isinstance(candidate, Mapping)
                and candidate.get("status") == "known"
                and candidate.get("decoded", {}).get("status") == "known"):
            helper = _raw(candidate.get("raw_hex"))
    except (BattleNativeTextError, ValueError, UnicodeError):
        pass

    handoff = None
    wire8 = decoded.get("wire8")
    if isinstance(wire8, Mapping) and wire8.get("version") == 8:
        item = decoded.get("name_handoff")
        if not isinstance(item, Mapping) or item.get("state") not in ("known", "unknown"):
            return None, None, "BODY_CANDIDATE_NAME_HANDOFF_INVALID"
        if item.get("state") == "known":
            if (item.get("source") != "owned_name_handoff"
                    or item.get("source_name") != "owned_name_handoff"
                    or type(item.get("state_id")) is not int or item["state_id"] != 1):
                return None, None, "BODY_CANDIDATE_NAME_HANDOFF_INVALID"
            actual = tuple(item.get(key) for key in ("sequence", "raw_date", "kind"))
            if not all(type(value) is int for value in actual) or actual != identity:
                return None, None, "BODY_CANDIDATE_NAME_HANDOFF_IDENTITY_MISMATCH"
            try:
                handoff = _raw(item.get("raw_hex"))
                if type(item.get("length")) is not int or item["length"] != len(handoff):
                    return None, None, "BODY_CANDIDATE_NAME_HANDOFF_INVALID"
                decode_native_text_hex(handoff.hex(), codec=CODEC,
                                       max_bytes=MAX_INPUT_BYTES, max_bytes_limit=MAX_INPUT_BYTES)
            except (ValueError, UnicodeError):
                return None, None, "BODY_CANDIDATE_NAME_HANDOFF_TEXT_INVALID"
    # The pre-gate route supplies independently copied raw inputs. Plugin
    # candidates describe the temporary text before game-string assignment;
    # neither path verifies a native NAME or a rendered Line1.
    from .battle_name_sources import project_name_candidate, project_name_sources
    derived = project_name_candidate(decoded)
    source_name = (bytes.fromhex(derived['raw_hex'])
                   if derived.get('status') == 'known' else None)
    language_mismatch = False
    if source_name is not None:
        language = project_name_sources(decoded)['text_fields']['language']['raw_hex']
        display_language = project_display_context(decoded).get('text_fields', {}).get('language', {})
        language_mismatch = (display_language.get('status') != 'known'
                             or bytes.fromhex(language) != bytes.fromhex(display_language.get('raw_hex', '')))
        if language_mismatch:
            source_name = None
    candidates = [item for item in (handoff, helper, source_name) if item is not None]
    if candidates and any(item != candidates[0] for item in candidates[1:]):
        return None, None, "BODY_CANDIDATE_NAME_SOURCE_CONFLICT"
    if handoff is not None:
        return handoff, "owned_name_handoff", None
    if helper is not None:
        return helper, "title_helper_candidate", None
    if source_name is not None:
        source = ("owned_name_sources_plugin_candidate"
                  if derived.get('basis') == 'derived_pinned_plugin_pre_assignment_byte_order'
                  else "owned_name_sources_candidate")
        return source_name, source, None
    if language_mismatch:
        return None, None, "BODY_CANDIDATE_NAME_LANGUAGE_MISMATCH"
    return None, None, "BODY_CANDIDATE_NAME_NOT_CAPTURED"


def project_body_candidate(decoded: Mapping[str, Any]) -> dict[str, Any]:
    """A derived candidate only; direct-participant admission stays upstream."""
    if not isinstance(decoded, Mapping):
        return _unknown("BODY_CANDIDATE_INPUT_INVALID")
    display = project_display_context(decoded)
    if not isinstance(display, Mapping) or display.get("status") != "known":
        return _unknown("BODY_CANDIDATE_SAME_EVENT_CONTEXT_UNKNOWN")
    identity = tuple(display.get(key) for key in ("sequence", "raw_date", "battle_kind"))
    if (not all(type(value) is int for value in identity)
            or not 0 < identity[0] < 1 << 64 or not 0 <= identity[1] < 1 << 31
            or identity[2] not in (1, 2)):
        return _unknown("BODY_CANDIDATE_IDENTITY_INVALID")
    # Preserve the event boundary independently of replacement availability.
    observation = decoded.get("observation")
    result = observation.get("result") if isinstance(observation, Mapping) else None
    context = decoded.get("context")
    if (not isinstance(result, Mapping) or not isinstance(context, Mapping)
            or identity != (observation.get("sequence"), result.get("raw_date"), context.get("kind"))):
        return _unknown("BODY_CANDIDATE_EVENT_IDENTITY_MISMATCH")
    fields = display.get("text_fields")
    if not isinstance(fields, Mapping):
        return _unknown("BODY_CANDIDATE_TEMPLATE_NOT_CAPTURED")
    template_field = fields.get("body_template")
    definition = fields.get("definition_key")
    language = fields.get("language")
    if any(not isinstance(item, Mapping) or item.get("status") != "known"
           for item in (template_field, definition, language)):
        return _unknown("BODY_CANDIDATE_TEMPLATE_NOT_CAPTURED")
    try:
        key = _raw(definition.get("raw_hex"))
        if key != {1: b"LANDBATTLEOVER", 2: b"NAVALBATTLEOVER"}[identity[2]]:
            return _unknown("BODY_CANDIDATE_DEFINITION_KIND_MISMATCH")
        template = _raw(template_field.get("raw_hex"))
        # Validate exact bytes even when a caller supplies a projected object.
        decode_native_text_hex(template.hex(), codec=CODEC,
                               max_bytes=MAX_INPUT_BYTES, max_bytes_limit=MAX_INPUT_BYTES)
    except (ValueError, UnicodeError):
        return _unknown("BODY_CANDIDATE_TEMPLATE_TEXT_INVALID")
    try:
        parts, replacements = _parts(template)
    except ValueError as error:
        return _unknown("BODY_CANDIDATE_" + str(error))
    source = "literal_template"
    name = b""
    if replacements:
        name, source, error = _name(decoded, identity)
        if error:
            return _unknown(error)
    try:
        output = _render_parts(parts, name)
    except ValueError:
        return _unknown("BODY_CANDIDATE_EXPANSION_LIMIT")
    try:
        text = _decode_output(output)
    except (ValueError, UnicodeError):
        return _unknown("BODY_CANDIDATE_OUTPUT_TEXT_INVALID")
    result = {**_FLAGS, "status": "known", "reason": None,
            "raw_hex": output.hex(), "codec": CODEC,
            "decoded": {"status": "known", "value": text},
            "sequence": identity[0], "raw_date": identity[1], "battle_kind": identity[2],
            "input_source": source,
            "input_basis": {"literal_template": "same_event_literal_template",
                            "owned_name_handoff": "copied_native_name_handoff",
                            "owned_name_sources_candidate": "derived_pre_gate_original_helper_inputs",
                            "owned_name_sources_plugin_candidate": "derived_pinned_plugin_pre_assignment_byte_order",
                            "title_helper_candidate": "same_combat_helper_static_NAME_source"}[source],
            "native_name_handoff_verified": source == "owned_name_handoff",
            "replacement_count": replacements}
    if source == "owned_name_sources_plugin_candidate":
        result.update(value_stage="plugin_pre_assignment_text", native_assignment_verified=False,
                      native_assignment_buffer_limit_exceeded=len(name) >= 255)
    return result
