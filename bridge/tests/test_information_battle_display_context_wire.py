"""Strict offline codec/projection tests for IBOW v7 display context."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.battle_display_context import project_display_context
from work import information_battle_native_text_wire as v6_wire
from work import information_battle_display_context_wire as wire
from work.tests.test_information_battle_native_text_wire import _snapshot as native_text_snapshot
from work.tests.test_information_battle_native_text_wire import _v4_payload, _v5_payload


CPP_FIXTURE = ROOT / "work" / "runtime" / "information-battle-display-context-wire-20261028-001" / "owned-wire7-001" / "attempt-003" / "fixture-v7.bin"
CPP_EXPECTED = CPP_FIXTURE.with_name("expected-snapshot.json")


def _v6_base() -> bytes:
    return v6_wire.encode(_v5_payload(), native_text_snapshot())


def _base_identity(base: bytes) -> dict[str, int]:
    decoded = v6_wire.decode(base)
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "battle_kind": decoded["context"]["kind"],
    }


def _observed_snapshot(base: bytes | None = None, **overrides) -> dict:
    identity = _base_identity(_v6_base() if base is None else base)
    snapshot = {
        "state": "observed",
        "capture_stage": 3,
        "failure": 0,
        **identity,
        "popup_kind_raw": 0,
        "layout_raw": 1,
        "button_flag_raw": 1,
        "fields": {
            "definition_key": {"state": "observed", "raw_hex": b"LANDBATTLEOVER".hex()},
            "language": {"state": "observed", "raw_hex": b"l_english".hex()},
            "body_template": {"state": "observed", "raw_hex": b"$NAME$".hex()},
            "button1": {"state": "observed", "raw_hex": "118b59108476"},
            "button2": {"state": "observed", "raw_hex": ""},
            "button3": {"state": "absent"},
            "compact_losses_template": {"state": "unknown"},
        },
    }
    snapshot.update(overrides)
    return snapshot


def _unknown_snapshot() -> dict:
    return {"state": "unknown", "failure": 4}


def _frame(snapshot: dict | None = None, base: bytes | None = None) -> bytes:
    return wire.encode(_v6_base() if base is None else base,
                       _observed_snapshot(base) if snapshot is None else snapshot)


def _offsets(frame: bytes) -> dict[str, int]:
    base_length = struct.unpack_from("<I", frame, 6)[0]
    extension = 10 + base_length
    body = extension + 10
    cursor = body + wire.FIXED_BODY_BYTES
    result = {"base_length": base_length, "extension": extension, "body": body}
    for field in wire.FIELD_ORDER:
        result[f"{field}_header"] = cursor
        length = struct.unpack_from("<I", frame, cursor + 4)[0]
        result[f"{field}_value"] = cursor + wire.ENTRY_HEADER_BYTES
        result[f"{field}_length"] = length
        cursor += wire.ENTRY_HEADER_BYTES + length
    return result


def _changed(frame: bytes, offset: int, value: bytes) -> bytes:
    result = bytearray(frame)
    result[offset:offset + len(value)] = value
    return bytes(result)


def test_v7_roundtrip_contains_exact_v6_keys_and_raw_context_values():
    base = _v6_base()
    snapshot = _observed_snapshot(base)
    frame = wire.encode(base, snapshot)
    decoded_v6 = v6_wire.decode(base)
    decoded_v7 = wire.decode(frame)

    for key, value in decoded_v6.items():
        assert decoded_v7[key] == value
    assert decoded_v7["wire7"]["version"] == 7
    assert decoded_v7["wire7"]["extension_magic"] == "DCTX"
    context = decoded_v7["display_context"]
    assert context["state"] == "observed"
    assert context["capture_stage"] == 3
    assert context["sequence"] == snapshot["sequence"]
    assert context["raw_date"] == snapshot["raw_date"]
    assert context["battle_kind"] == 1
    assert context["popup_kind_raw"] == 0
    assert context["layout_raw"] == 1
    assert context["button_flag_raw"] == 1
    assert context["arena_used"] == sum(
        len(bytes.fromhex(value["raw_hex"]))
        for value in snapshot["fields"].values()
        if value.get("state") == "observed"
    )
    assert context["fields"]["button2"]["state"] == "observed"
    assert context["fields"]["button2"]["raw_hex"] == ""
    assert context["fields"]["button3"]["state"] == "absent"
    assert context["fields"]["compact_losses_template"]["state"] == "unknown"


def test_unknown_context_requires_failure_and_zeroes_all_identity_and_fields():
    frame = wire.encode(_v6_base(), _unknown_snapshot())
    decoded = wire.decode(frame)
    context = decoded["display_context"]
    assert context["state"] == "unknown"
    assert context["failure"] == 4
    assert context["sequence"] == context["raw_date"] == context["battle_kind"] == 0
    assert context["popup_kind_raw"] == context["layout_raw"] == context["button_flag_raw"] == 0
    assert all(value["state"] == "unknown" and value["raw_hex"] is None
               for value in context["fields"].values())
    assert project_display_context(decoded)["status"] == "unknown"


def test_dynamic_popup_kind_zero_and_raw_metadata_project_without_visibility_claim():
    decoded = wire.decode(_frame())
    projected = project_display_context(decoded)
    assert projected["status"] == "known"
    assert projected["popup_kind_raw"] == 0
    assert projected["formatter_kind"] == 1
    assert projected["matches_formatter_kind"] is False
    assert projected["layout_raw"] == 1
    assert projected["button_flag_raw"] == 1
    assert projected["definition"]["key"]["source"] == "native_message_definition"
    assert projected["language"]["source"] == "native_localization_cache"
    assert projected["text_fields"]["body_template"]["decoded"]["value"] == "$NAME$"
    assert projected["text_fields"]["button2"]["status"] == "known"
    assert projected["text_fields"]["button2"]["decoded"]["value"] == ""
    assert projected["text_fields"]["button3"]["status"] == "absent"
    assert projected["text_fields"]["button3"]["cache_absence_is_not_visibility_evidence"]
    assert projected["full_display_complete"] is False
    assert projected["runtime_popup_verified"] is False
    assert projected["visibility_verified"] is False
    assert "raw_text" not in projected


@pytest.mark.parametrize("field,override", [
    ("sequence", {"sequence": 999}),
    ("raw_date", {"raw_date": 56563609}),
    ("battle_kind", {"battle_kind": 2, "fields": {
        "definition_key": {"state": "observed", "raw_hex": b"NAVALBATTLEOVER".hex()},
        "language": {"state": "observed", "raw_hex": b"l_english".hex()},
        "body_template": {"state": "observed", "raw_hex": b"$NAME$".hex()},
        "button1": {"state": "observed", "raw_hex": "118b59108476"},
        "button2": {"state": "observed", "raw_hex": ""},
        "button3": {"state": "absent"},
        "compact_losses_template": {"state": "unknown"},
    }}),
])
def test_event_identity_mismatch_retracts_only_display_projection(field, override):
    base = _v6_base()
    snapshot = _observed_snapshot(base)
    snapshot.update(override)
    decoded = wire.decode(wire.encode(base, snapshot))
    original_sequence = decoded["observation"]["sequence"]
    original_date = decoded["observation"]["result"]["raw_date"]
    projected = project_display_context(decoded)
    assert projected["status"] == "unknown"
    assert projected["reason"] == "DISPLAY_CONTEXT_EVENT_IDENTITY_MISMATCH"
    assert projected["raw_context"]["fields"]["definition_key"]["raw_hex"]
    assert decoded["observation"]["sequence"] == original_sequence
    assert decoded["observation"]["result"]["raw_date"] == original_date
    assert decoded["visibility_verified"] is False


def test_invalid_escape_keeps_raw_bytes_and_projects_unknown():
    base = _v6_base()
    snapshot = _observed_snapshot(base)
    snapshot["fields"]["body_template"] = {"state": "observed", "raw_hex": "10"}
    projected = project_display_context(wire.decode(wire.encode(base, snapshot)))
    field = projected["text_fields"]["body_template"]
    assert projected["status"] == "known"
    assert field["status"] == "unknown"
    assert field["raw_hex"] == "10"
    assert field["decoded"]["reason"] == "DISPLAY_CONTEXT_TEXT_DECODE_FAILED"
    assert projected["full_display_complete"] is False


def test_v1_through_v6_dispatch_is_exactly_delegated():
    sentinel = {"sentinel": object()}
    for version in range(1, 7):
        frame = b"IBOW" + struct.pack("<H", version)
        with pytest.MonkeyPatch.context() as monkeypatch:
            calls = []

            def delegated(value):
                calls.append(value)
                return sentinel

            monkeypatch.setattr(wire._v6, "decode", delegated)
            assert wire.decode(frame) is sentinel
            assert calls == [frame]


def test_real_v4_v5_v6_legacy_frames_match_existing_decoder_exactly():
    frames = (_v4_payload(), _v5_payload(), _v6_base())
    for frame in frames:
        assert wire.decode(frame) == v6_wire.decode(frame)


@pytest.mark.parametrize("mutator", [
    lambda frame, o: _changed(frame, o["extension"] + 4, b"\x02\x00"),
    lambda frame, o: _changed(frame, o["extension"] + 6,
                              struct.pack("<I", struct.unpack_from("<I", frame, o["extension"] + 6)[0] + 1)),
    lambda frame, o: frame + b"\x00",
    lambda frame, o: _changed(frame, o["body"] + 26, b"\x06"),
    lambda frame, o: _changed(frame, o["definition_key_header"], b"\x02"),
    lambda frame, o: _changed(frame, o["language_header"] + 2, b"\x01\x00"),
    lambda frame, o: _changed(frame, o["language_value"], b"x"),
    lambda frame, o: _changed(frame, o["body_template_value"], b"\x00"),
    lambda frame, o: _changed(frame, o["button1_header"] + 1, b"\x00"),
    lambda frame, o: _changed(frame, o["button1_header"] + 1, b"\x03"),
    lambda frame, o: _changed(frame, o["button1_header"] + 4, struct.pack("<I", 8193)),
    lambda frame, o: _changed(frame, o["body"] + 16, b"\x02"),
])
def test_strict_v7_rejects_bad_extension_entries_and_text(mutator):
    frame = _frame()
    with pytest.raises(wire.DisplayContextWireError):
        wire.decode(mutator(frame, _offsets(frame)))


@pytest.mark.parametrize("mutation", [
    lambda frame, o: _changed(frame, o["body"], b"\x00"),  # unknown with nonzero rest
    lambda frame, o: _changed(frame, o["body"] + 4, bytes(8)),  # zero sequence
    lambda frame, o: _changed(frame, o["body"] + 1, b"\x04"),  # stage >3
    lambda frame, o: _changed(frame, o["body"] + 16, b"\x03"),  # kind outside 1/2
    lambda frame, o: _changed(frame, o["body"] + 2, b"\x01\x00"),  # observed failure
])
def test_strict_v7_rejects_noncanonical_context_header(mutation):
    frame = _frame()
    with pytest.raises(wire.DisplayContextWireError):
        wire.decode(mutation(frame, _offsets(frame)))


def test_encoder_rejects_missing_required_key_language_and_kind_mismatch():
    base = _v6_base()
    for field in ("definition_key", "language"):
        snapshot = _observed_snapshot(base)
        snapshot["fields"][field] = {"state": "unknown"}
        with pytest.raises(wire.DisplayContextWireError):
            wire.encode(base, snapshot)
    snapshot = _observed_snapshot(base)
    snapshot["fields"]["language"] = {"state": "observed", "raw_hex": b"english".hex()}
    with pytest.raises(wire.DisplayContextWireError):
        wire.encode(base, snapshot)
    snapshot = _observed_snapshot(base)
    snapshot["battle_kind"] = 2
    with pytest.raises(wire.DisplayContextWireError):
        wire.encode(base, snapshot)


def test_unknown_context_encoder_rejects_nonzero_fields_and_observed_text():
    snapshot = _unknown_snapshot()
    snapshot["sequence"] = 1
    with pytest.raises(wire.DisplayContextWireError):
        wire.encode(_v6_base(), snapshot)
    snapshot = _unknown_snapshot()
    snapshot["fields"] = {"definition_key": {"state": "observed", "raw_hex": ""}}
    with pytest.raises(wire.DisplayContextWireError):
        wire.encode(_v6_base(), snapshot)


def test_encoder_enforces_field_and_total_arena_limits():
    base = _v6_base()
    snapshot = _observed_snapshot(base)
    snapshot["fields"]["body_template"] = {"state": "observed", "raw_bytes": b"x" * 8193}
    with pytest.raises(wire.DisplayContextWireError):
        wire.encode(base, snapshot)

    snapshot = _observed_snapshot(base)
    for field in ("body_template", "button1", "button2", "button3", "compact_losses_template"):
        snapshot["fields"][field] = {"state": "observed", "raw_bytes": b"x" * 8192}
    with pytest.raises(wire.DisplayContextWireError, match="arena_over_bound"):
        wire.encode(base, snapshot)


def test_decoder_enforces_outer_wire_limit():
    oversized_v7 = wire.MAGIC + struct.pack("<H", wire.VERSION) + bytes(wire.MAX_WIRE_BYTES - 5)
    assert len(oversized_v7) == wire.MAX_WIRE_BYTES + 1
    with pytest.raises(wire.DisplayContextWireError, match="wire_size_over_bound"):
        wire.decode(oversized_v7)


def test_cpp_owned_v7_fixture_matches_expected_snapshot():
    assert CPP_FIXTURE.is_file(), f"archive69 fixture not found: {CPP_FIXTURE}"
    assert CPP_EXPECTED.is_file(), f"archive69 expected snapshot not found: {CPP_EXPECTED}"
    frame = CPP_FIXTURE.read_bytes()
    expected = json.loads(CPP_EXPECTED.read_text(encoding="utf-8"))
    decoded = wire.decode(frame)
    context = decoded["display_context"]
    fixture_meta = expected["fixture_v7"]
    expected_context = expected["snapshot"]
    assert len(frame) == fixture_meta["bytes"]
    assert hashlib.sha256(frame).hexdigest() == fixture_meta["sha256"]
    for target_name, source_name in (
        ("state", "context_state_name"), ("capture_stage", "capture_stage"),
        ("sequence", "sequence"), ("raw_date", "raw_date"),
        ("battle_kind", "battle_kind"), ("popup_kind_raw", "popup_kind_raw"),
        ("layout_raw", "layout_raw"), ("button_flag_raw", "button_flag_raw"),
    ):
        assert context[target_name] == expected_context[source_name]
    expected_fields = {field["name"]: field for field in expected_context["fields"]}
    for name in wire.FIELD_ORDER:
        wanted = expected_fields[name]
        actual = context["fields"][name]
        assert actual["field_id"] == wanted["id"]
        assert actual["state"] == wanted["state_name"]
        if wanted["state_name"] == "observed":
            assert actual["raw_hex"] == wanted["bytes_hex"]
        else:
            assert actual["raw_hex"] is None
    base_length = struct.unpack_from("<I", frame, 6)[0]
    base6 = frame[10:10 + base_length]
    assert base6.hex() == fixture_meta["base6_hex"]
    assert hashlib.sha256(base6).hexdigest() == fixture_meta["base6_sha256"]
    assert decoded["base_v5_payload_hex"] == v6_wire.decode(base6)["base_v5_payload_hex"]
