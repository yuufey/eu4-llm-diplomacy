"""Offline tests for the partial, copied battle-body candidate projection.

The fixtures reuse the recorded FRA WARI base from the existing v6/v7 tests.
All NTXT, DCTX, and optional NHND values added here are synthetic test data;
they do not represent a rendered popup or a live battle capture.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.battle_body_candidate import project_body_candidate
from bridge.tests.test_information_battle_display_context_integration import (
    _v7_fixture,
)
from bridge.tests.test_information_battle_name_handoff_integration import (
    _v8_fixture,
)
from bridge.tests.test_information_battle_native_text import (
    _native_snapshot,
    _v6_fixture,
)
from bridge.tests.test_information_battles import (
    battle_topic_query,
    event_id,
    make_source,
)
from bridge.native_text import decode_native_text_hex
from work import information_battle_display_context_wire as display_wire
from work import information_battle_name_handoff_wire as name_wire
from work import information_battle_native_text_wire as native_wire
from work import information_battle_war_identity_wire as war_wire


def _decoded_v7(*, title: bytes = b"BATTLE_OF_PARIS",
                title_state: str = "observed",
                template: bytes = b"$NAME$",
                metadata_known: bool = True,
                native_date_delta: int = 0,
                context_sequence_delta: int = 0) -> tuple[dict, bytes]:
    """Build one valid v7 frame around the repository's recorded WARI base."""
    _fixture, base_v5, _payload_v6 = _v6_fixture()
    base = war_wire.decode(base_v5)
    observation = base["observation"]
    result = observation["result"]
    kind = base["context"]["kind"]

    ntxt = _native_snapshot()
    ntxt["title_helper_candidate"] = {
        "state": title_state,
        "source": "title_helper_candidate",
        "raw_hex": title.hex() if title_state == "observed" else "",
    }
    if metadata_known:
        ntxt["native_date"] = {
            "state": "observed",
            "value": result["raw_date"] + native_date_delta,
        }
        ntxt["raw_flags"] = {
            "state": "observed", "raw_flag_8c": 0xA1, "raw_flag_8d": 0x5E,
        }
    else:
        # These unrelated metadata fields may be unavailable while the helper
        # candidate itself remains a copied, known field.
        ntxt["native_date"] = {"state": "unknown"}
        ntxt["raw_flags"] = {"state": "unknown"}

    payload_v6 = native_wire.encode(base_v5, ntxt)
    dctx = {
        "state": "observed",
        "capture_stage": 3,
        "failure": 0,
        "sequence": observation["sequence"] + context_sequence_delta,
        "raw_date": result["raw_date"],
        "battle_kind": kind,
        "popup_kind_raw": 0,
        "layout_raw": 1,
        "button_flag_raw": 1,
        "fields": {
            "definition_key": {
                "state": "observed",
                "raw_bytes": {1: b"LANDBATTLEOVER", 2: b"NAVALBATTLEOVER"}[kind],
            },
            "language": {"state": "observed", "raw_bytes": b"l_english"},
            "body_template": {"state": "observed", "raw_bytes": template},
            "button1": {"state": "observed", "raw_bytes": b"OK"},
            "button2": {"state": "observed", "raw_bytes": b""},
            "button3": {"state": "absent"},
            "compact_losses_template": {"state": "unknown"},
        },
    }
    payload_v7 = display_wire.encode(payload_v6, dctx)
    return display_wire.decode(payload_v7), payload_v7


def _decoded_v8(*, helper: bytes = b"BATTLE_OF_PARIS",
                handoff: bytes = b"BATTLE_OF_PARIS",
                helper_state: str = "observed") -> dict:
    decoded_v7, payload_v7 = _decoded_v7(
        title=helper, title_state=helper_state,
    )
    observation = decoded_v7["observation"]
    snapshot = {
        "state": "known",
        "sequence": observation["sequence"],
        "raw_date": observation["result"]["raw_date"],
        "kind": decoded_v7["context"]["kind"],
        "raw_bytes": handoff,
    }
    return name_wire.decode(name_wire.encode(payload_v7, snapshot))


def _assert_unknown(result: dict) -> None:
    assert result["status"] == "unknown"
    assert isinstance(result.get("reason"), str)
    assert result["reason"].startswith("BODY_CANDIDATE_")
    assert result["native_name_handoff_verified"] is False
    assert result["native_formatter_invoked"] is False
    assert result["native_line1_verified"] is False
    assert result["not_raw_text"] is True
    assert result["complete"] is False
    assert result["full_display_complete"] is False
    assert result["visibility_verified"] is False


def test_v7_plain_name_token_expands_in_place_and_preserves_partial_flags():
    decoded, _payload = _decoded_v7(
        title=b"PARIS", template=b"Battle at $NAME$; again $NAME$!",
    )

    result = project_body_candidate(decoded)

    expected = "Battle at PARIS; again PARIS!"
    assert result["status"] == "known"
    assert result["raw_hex"] == expected.encode("ascii").hex()
    assert result["decoded"] == {"status": "known", "value": expected}
    assert result["input_source"] == "title_helper_candidate"
    assert result["native_name_handoff_verified"] is False
    assert result["replacement_count"] == 2
    assert result["codec"] == "eu4_escape"
    assert result["native_formatter_invoked"] is False
    assert result["native_line1_verified"] is False
    assert result["not_raw_text"] is True
    assert result["complete"] is False
    assert result["full_display_complete"] is False
    assert result["visibility_verified"] is False
    assert "raw_text" not in result


def test_known_helper_candidate_does_not_require_other_native_metadata():
    decoded, _payload = _decoded_v7(
        title=b"PARIS", template=b"$NAME$", metadata_known=False,
    )
    assert decoded["native_text"]["message_metadata"]["native_date"][
        "status"
    ] == "unknown"
    assert decoded["native_text"]["message_metadata"]["raw_flags"][
        "status"
    ] == "unknown"

    result = project_body_candidate(decoded)

    assert result["status"] == "known"
    assert result["decoded"] == {"status": "known", "value": "PARIS"}
    assert result["input_source"] == "title_helper_candidate"


@pytest.mark.parametrize(
    "decoded",
    [
        _decoded_v7(title=b"PARIS", native_date_delta=1)[0],
        _decoded_v7(title=b"PARIS", context_sequence_delta=1)[0],
    ],
    ids=("native-date-mismatch", "display-context-scope-mismatch"),
)
def test_date_or_event_scope_mismatch_cannot_produce_a_candidate(decoded):
    _assert_unknown(project_body_candidate(decoded))


def test_matching_v8_name_handoff_is_preferred_and_verified():
    result = project_body_candidate(_decoded_v8(
        helper=b"PARIS", handoff=b"PARIS",
    ))

    assert result["status"] == "known"
    assert result["decoded"] == {"status": "known", "value": "PARIS"}
    assert result["input_source"] == "owned_name_handoff"
    assert result["native_name_handoff_verified"] is True
    assert result["native_formatter_invoked"] is False
    assert result["native_line1_verified"] is False
    assert result["not_raw_text"] is True
    assert result["complete"] is False
    assert result["full_display_complete"] is False
    assert result["visibility_verified"] is False


def test_conflicting_v8_name_sources_remain_unknown():
    _assert_unknown(project_body_candidate(_decoded_v8(
        helper=b"PARIS", handoff=b"LYON",
    )))


def test_known_handoff_can_supply_name_when_helper_field_is_unknown():
    result = project_body_candidate(_decoded_v8(
        helper=b"", handoff=b"PARIS", helper_state="unknown",
    ))

    assert result["status"] == "known"
    assert result["decoded"] == {"status": "known", "value": "PARIS"}
    assert result["input_source"] == "owned_name_handoff"
    assert result["native_name_handoff_verified"] is True


@pytest.mark.parametrize(
    "template",
    [b"$OTHER$", b"$NAME|capitalized$"],
    ids=("unknown-token", "pipe-modifier"),
)
def test_unsupported_tokens_and_pipe_modifiers_remain_unknown(template):
    decoded, _payload = _decoded_v7(title=b"PARIS", template=template)
    _assert_unknown(project_body_candidate(decoded))


def test_replacement_value_is_not_recursively_expanded_and_literal_template_is_known():
    decoded, _payload = _decoded_v7(
        title=b"$CITY$", template=b"Result: $NAME$",
    )
    candidate = project_body_candidate(decoded)
    assert candidate["status"] == "known"
    assert candidate["decoded"]["value"] == "Result: $CITY$"

    literal_decoded, _literal_payload = _decoded_v7(
        title=b"", title_state="unknown", template=b"A literal body",
    )
    literal = project_body_candidate(literal_decoded)
    assert literal["status"] == "known"
    assert literal["decoded"] == {"status": "known", "value": "A literal body"}
    assert literal["input_source"] == "literal_template"
    assert literal["replacement_count"] == 0


def test_missing_helper_name_and_malformed_helper_text_remain_unknown():
    missing, _payload = _decoded_v7(
        title=b"", title_state="unknown", template=b"$NAME$",
    )
    _assert_unknown(project_body_candidate(missing))

    bad_codec, _bad_payload = _decoded_v7(
        title=b"\x10\xe3", template=b"$NAME$",
    )
    _assert_unknown(project_body_candidate(bad_codec))

    nul_name, _nul_payload = _decoded_v7(
        title=b"PARIS\x00X", template=b"$NAME$",
    )
    _assert_unknown(project_body_candidate(nul_name))


def test_unmatched_trailing_dollar_is_preserved_as_a_literal():
    decoded, _payload = _decoded_v7(
        title=b"", title_state="unknown", template=b"Body ends with $",
    )
    result = project_body_candidate(decoded)
    assert result["status"] == "known"
    assert result["input_source"] == "literal_template"
    assert result["decoded"] == {
        "status": "known", "value": "Body ends with $",
    }


def test_name_and_template_byte_limits_and_expanded_output_bound():
    # The individual source bound is inclusive at 8192 bytes.
    exactly_bounded, _payload = _decoded_v7(
        title=b"A" * 8192, template=b"$NAME$",
    )
    bounded = project_body_candidate(exactly_bounded)
    assert bounded["status"] == "known"
    assert len(bounded["decoded"]["value"].encode("utf-8")) == 8192

    # Decoder-shaped values can be malformed by upstream callers. Enforce
    # source limits again at this projection boundary.
    oversized_name = deepcopy(exactly_bounded)
    oversized_name["native_text"]["text_fields"]["title_helper_candidate"][
        "raw_hex"
    ] = (b"A" * 8193).hex()
    _assert_unknown(project_body_candidate(oversized_name))

    decoded_template, _template_payload = _decoded_v7(
        title=b"A", template=b"$NAME$",
    )
    oversized_template = deepcopy(decoded_template)
    oversized_template["display_context"]["fields"]["body_template"][
        "raw_hex"
    ] = (b"$NAME$" * 1366).hex()  # 8196 bytes
    _assert_unknown(project_body_candidate(oversized_template))

    large_expansion, _large_payload = _decoded_v7(
        title=b"A" * 8192, template=b"$NAME$" * 8,
    )
    _assert_unknown(project_body_candidate(large_expansion))


def test_escape_sequence_crossing_output_chunk_boundary_decodes_safely():
    name = b"A" * 8189 + b"\x10\x2d\x4e"
    decoded, _payload = _decoded_v7(
        title=name, template=b"X$NAME$$NAME$",
    )

    result = project_body_candidate(decoded)

    name_text = decode_native_text_hex(
        name.hex(), codec="eu4_escape", max_bytes=8192, max_bytes_limit=8192,
    )
    expected = "X" + name_text + name_text
    assert result["status"] == "known"
    assert result["replacement_count"] == 2
    assert result["decoded"] == {"status": "known", "value": expected}
    assert len(bytes.fromhex(result["raw_hex"])) == 1 + 2 * 8192


def test_expansion_limit_accepts_61438_bytes_and_rejects_61439_plus_terminator():
    name = b"A" * 8192
    accepted_decoded, _accepted_payload = _decoded_v7(
        title=name, template=b"$NAME$" * 7 + b"L" * 4094,
    )
    accepted = project_body_candidate(accepted_decoded)
    assert accepted["status"] == "known"
    assert len(bytes.fromhex(accepted["raw_hex"])) == 61438

    rejected_decoded, _rejected_payload = _decoded_v7(
        title=name, template=b"$NAME$" * 7 + b"L" * 4095,
    )
    _assert_unknown(project_body_candidate(rejected_decoded))


def test_v7_and_v8_public_battle_projection_versions_include_body_candidate(tmp_path):
    fixtures = (
        ("v7", _v7_fixture()[0]),
        ("v8", _v8_fixture()[0]),
    )
    for label, fixture in fixtures:
        case_dir = tmp_path / label
        case_dir.mkdir()
        source, _primary, fixture, _db, _payload = make_source(
            case_dir, fixture=fixture, observer="FRA", message_ids=("91",),
        )
        query = battle_topic_query(
            "B04", ["details"], selected_event=event_id(fixture, "91"),
        )
        result = source.read(query, source.context())
        details = result["fields"]["details"]["value"]
        assert result["source"]["projection_version"] == 30
        assert "body_candidate" in details["display_context"]
        assert details["display_context"]["body_candidate"]["not_raw_text"] is True
        assert "raw_text" not in details["display_context"]["body_candidate"]

