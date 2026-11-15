"""Pinned-plugin name candidates remain pre-assignment synthetic projections."""
import pytest

from bridge.information.battle_body_candidate import project_body_candidate
from bridge.information.battle_name_sources import (
    PINNED_PLUGIN_SHA256,
    project_name_candidate,
)
from bridge.tests.test_information_battle_name_sources import (
    _decoded,
    _field,
    _with_synthetic_sources,
)


def _plugin_decoded(*, prefix: bytes, global_name: bytes, owner: bytes,
                    transform_mode: int = 2) -> dict:
    decoded = _decoded(transform_mode=transform_mode)
    decoded["name_sources"]["text_fields"].update(
        battle_of_template=_field(prefix),
        global_name=_field(global_name),
        owner_name=_field(owner),
    )
    return decoded


def _clear_native_helper(decoded: dict) -> None:
    decoded["native_text"]["text_fields"]["title_helper_candidate"].update(
        status="unknown", state="unknown", raw_hex="",
    )


def test_pinned_plugin_strips_one_byte_from_global_plus_owner_before_prefix():
    candidate = project_name_candidate(_plugin_decoded(
        prefix=b" battle", global_name=b" ", owner=b"Paris",
    ))

    assert candidate["status"] == "known"
    assert candidate["raw_hex"] == b"Paris battle".hex()
    assert candidate["decoded"] == {"status": "known", "value": "Paris battle"}
    assert candidate["input_source"] == "owned_name_sources_candidate"
    assert candidate["basis"] == "derived_pinned_plugin_pre_assignment_byte_order"
    assert candidate["plugin_sha256"] == PINNED_PLUGIN_SHA256
    assert candidate["value_stage"] == "plugin_pre_assignment_text"
    assert candidate["native_assignment_verified"] is False
    assert candidate["native_assignment_buffer_limit_exceeded"] is False
    assert candidate["native_helper_invoked"] is False
    assert candidate["native_line1_verified"] is False
    assert candidate["not_raw_text"] is True


def test_plugin_drops_exactly_one_byte_after_joining_the_raw_sources():
    candidate = project_name_candidate(_plugin_decoded(
        prefix=b"suffix", global_name=b"X", owner=b"YParis",
    ))
    assert bytes.fromhex(candidate["raw_hex"]) == b"YParissuffix"


def test_single_byte_tail_becomes_prefix_and_empty_tail_stays_unknown():
    one_byte = project_name_candidate(_plugin_decoded(
        prefix=b"suffix", global_name=b"X", owner=b"",
    ))
    assert one_byte["status"] == "known"
    assert bytes.fromhex(one_byte["raw_hex"]) == b"suffix"

    empty = project_name_candidate(_plugin_decoded(
        prefix=b"suffix", global_name=b"", owner=b"",
    ))
    assert empty["status"] == "unknown"
    assert empty["reason"] == "NAME_SOURCE_PLUGIN_TAIL_EMPTY"


def test_plugin_strips_a_byte_even_when_it_is_an_escape_marker():
    candidate = project_name_candidate(_plugin_decoded(
        prefix=b"suffix", global_name=b"\x10AB", owner=b"",
    ))
    assert candidate["status"] == "known"
    assert bytes.fromhex(candidate["raw_hex"]) == b"ABsuffix"


@pytest.mark.parametrize("output_length", [0, 15, 16, 254, 255, 8192])
def test_plugin_logical_output_is_not_truncated_to_native_assignment_buffer(output_length):
    tail = b"x" + b"A" * output_length
    candidate = project_name_candidate(_plugin_decoded(
        prefix=b"", global_name=tail[:8192], owner=tail[8192:],
    ))
    raw = bytes.fromhex(candidate["raw_hex"])

    assert candidate["status"] == "known"
    assert len(raw) == output_length
    assert raw == b"A" * output_length
    assert candidate["decoded"] == {
        "status": "known", "value": "A" * output_length,
    }
    assert candidate["value_stage"] == "plugin_pre_assignment_text"
    assert candidate["native_assignment_verified"] is False
    assert candidate["native_assignment_buffer_limit_exceeded"] is (output_length >= 255)


def test_original_helper_order_is_preserved_and_unqualified_mode_stays_unknown():
    original = project_name_candidate(_plugin_decoded(
        prefix=b"PRE", global_name=b"GLOBAL", owner=b"OWNER", transform_mode=1,
    ))
    assert original["status"] == "known"
    assert bytes.fromhex(original["raw_hex"]) == b"PREGLOBALOWNER"
    assert original["basis"] == "derived_original_helper_zero_argument_prefix_and_raw_concat"
    assert "value_stage" not in original

    unqualified = project_name_candidate(_plugin_decoded(
        prefix=b"PRE", global_name=b"GLOBAL", owner=b"OWNER", transform_mode=0,
    ))
    assert unqualified["status"] == "unknown"
    assert unqualified["reason"] == "NAME_SOURCE_TRANSFORM_UNQUALIFIED"


def test_body_candidate_uses_plugin_value_when_native_helper_is_unknown():
    decoded = _with_synthetic_sources(
        prefix=b" battle", global_name=b" ", owner=b"Paris",
    )
    decoded["name_sources"]["transform_mode"] = 2
    _clear_native_helper(decoded)

    candidate = project_body_candidate(decoded)
    assert candidate["status"] == "known"
    assert b"Paris battle" in bytes.fromhex(candidate["raw_hex"])
    assert candidate["input_source"] == "owned_name_sources_plugin_candidate"
    assert candidate["input_basis"] == "derived_pinned_plugin_pre_assignment_byte_order"
    assert candidate["value_stage"] == "plugin_pre_assignment_text"
    assert candidate["native_assignment_verified"] is False
    assert candidate["native_assignment_buffer_limit_exceeded"] is False
    assert candidate["native_line1_verified"] is False
    assert candidate["not_raw_text"] is True
    assert candidate["full_display_complete"] is False


def test_body_candidate_keeps_plugin_language_mismatch_and_valid_helper_conflict_unknown():
    mismatch = _with_synthetic_sources(
        prefix=b" battle", global_name=b" ", owner=b"Paris",
    )
    mismatch["name_sources"]["transform_mode"] = 2
    mismatch["name_sources"]["text_fields"]["language"] = _field(b"l_french")
    _clear_native_helper(mismatch)
    candidate = project_body_candidate(mismatch)
    assert candidate["status"] == "unknown"
    assert candidate["reason"] == "BODY_CANDIDATE_NAME_LANGUAGE_MISMATCH"

    conflict = _with_synthetic_sources(
        prefix=b" battle", global_name=b" ", owner=b"Paris",
    )
    conflict["name_sources"]["transform_mode"] = 2
    conflict["native_text"]["text_fields"]["title_helper_candidate"].update(
        status="known", raw_hex=b"different helper value".hex(),
    )
    candidate = project_body_candidate(conflict)
    assert candidate["status"] == "unknown"
    assert candidate["reason"] == "BODY_CANDIDATE_NAME_SOURCE_CONFLICT"
