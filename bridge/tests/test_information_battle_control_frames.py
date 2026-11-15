"""Narrow pure tests for inferred battle numeric/icon virtual setter requests."""
from __future__ import annotations

import pytest

from bridge.information.battle_control_frames import project_native_frame_requests


NUMERIC = "numeric_or_frame"
ICON = "icon_or_frame"


def _binding(key: str, value_kind: str | None = None) -> dict:
    if value_kind is None:
        value_kind = ICON if key in ("OURLEADERICON", "ENEMYLEADERICON") else NUMERIC
    return {"template_key": key, "value_kind": value_kind, "widget": f"widget_{key}"}


def _pair(index: int, value: bytes, *, decoded=None, raw_hex: str | None = None) -> dict:
    return {
        "pair_index": index,
        "value_raw_hex": value.hex() if raw_hex is None else raw_hex,
        "decoded": {"status": "known", "value": "deliberately ignored"} if decoded is None else decoded,
    }


def _item(result: dict, index: int = 0) -> dict:
    assert result["status"] == "known"
    return result["requests"][index]


def _assert_never_observed(result: dict) -> None:
    assert result["native_call_observed"] is False
    assert result["runtime_widget_state_verified"] is False
    assert result["full_display_complete"] is False
    for item in result["requests"]:
        assert item["native_call_observed"] is False
        assert item["runtime_widget_state_verified"] is False


@pytest.mark.parametrize(
    ("kind", "key"),
    [
        ("land", "OURFIRE"), ("land", "ENEMYFIRE"),
        ("land", "OURSHOCK"), ("land", "ENEMYSHOCK"),
        ("land", "OURMANEUVER"), ("land", "ENEMYMANEUVER"),
        ("land", "OURSIEGE"), ("land", "ENEMYSIEGE"),
        ("naval", "OURFIRE"), ("naval", "ENEMYFIRE"),
        ("naval", "OURSHOCK"), ("naval", "ENEMYSHOCK"),
        ("naval", "OURMANEUVER"), ("naval", "ENEMYMANEUVER"),
        ("land", "OURLEADERICON"), ("land", "ENEMYLEADERICON"),
        ("naval", "OURLEADERICON"), ("naval", "ENEMYLEADERICON"),
    ],
)
def test_only_explicit_numeric_and_icon_keys_are_projected(kind: str, key: str) -> None:
    value_kind = ICON if key.endswith("LEADERICON") else NUMERIC
    projected = project_native_frame_requests(
        kind, _binding(key, value_kind), [_pair(4, b"2")],
    )
    assert projected is not None
    assert projected["status"] == "known"
    assert projected["battle_kind"] == kind
    assert projected["template_key"] == key
    assert projected["binding_provenance"]["game_version"] == "1.37.4"
    assert projected["binding_provenance"]["exe_sha256"] == (
        "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    )
    _assert_never_observed(projected)


@pytest.mark.parametrize(
    ("kind", "key", "value_kind"),
    [
        ("land", "OURLOST", "formatted_text"),
        ("land", "OURLEADER", "text"),
        ("naval", "OURSIEGE", "numeric_or_frame"),
        ("land", "OURFIRE", "text"),
        ("other", "OURFIRE", "numeric_or_frame"),
    ],
)
def test_unsupported_key_kind_or_binding_type_returns_none(
    kind: str, key: str, value_kind: str,
) -> None:
    assert project_native_frame_requests(
        kind, _binding(key, value_kind), [_pair(0, b"7")],
    ) is None


def test_numeric_ascii_whitespace_decimal_prefix_and_nul_termination() -> None:
    result = project_native_frame_requests(
        "land",
        _binding("OURFIRE"),
        [
            _pair(3, b" \t\n\v\f\r-12tail"),
            _pair(4, b"0x20"),
            _pair(5, b"123\x00not-a-number"),
        ],
    )
    assert result is not None and result["status"] == "known"
    first, second, third = result["requests"]
    assert first["parsed"]["signed_i32"] == -12
    assert first["parsed"]["bits_u32"] == 0xFFFFFFF4
    assert first["parsed"]["digits"] is True
    assert first["parsed"]["no_digits"] is False
    assert first["virtual_setter_request"] == {
        "vtable_offset": "0xa8",
        "arg_u32": 0xFFFFFFF5,
        "arg_i32": -11,
    }
    # The native conversion is decimal-prefix parsing, not base autodetection.
    assert second["parsed"]["signed_i32"] == 0
    assert second["parsed"]["digit_count"] == 1
    assert second["virtual_setter_request"]["arg_u32"] == 1
    assert second["virtual_setter_request"]["arg_i32"] == 1
    assert third["parsed"]["signed_i32"] == 123
    assert third["parsed"]["c_string_bytes"] == 3
    assert third["virtual_setter_request"]["arg_u32"] == 124
    assert third["virtual_setter_request"]["arg_i32"] == 124
    _assert_never_observed(result)


def test_signed_i32_boundaries_clamp_and_modulo_addition() -> None:
    values = [b"2147483647", b"-2147483648", b"2147483648", b"-2147483649"]
    result = project_native_frame_requests(
        "naval", _binding("ENEMYSHOCK"), [_pair(i, value) for i, value in enumerate(values)],
    )
    assert result is not None and result["status"] == "known"
    items = result["requests"]
    assert [item["parsed"]["signed_i32"] for item in items] == [
        2147483647, -2147483648, 2147483647, -2147483648,
    ]
    assert [item["parsed"]["range_clamped"] for item in items] == [False, False, True, True]
    assert [item["virtual_setter_request"] for item in items] == [
        {"vtable_offset": "0xa8", "arg_u32": 0x80000000, "arg_i32": -2147483648},
        {"vtable_offset": "0xa8", "arg_u32": 0x80000001, "arg_i32": -2147483647},
        {"vtable_offset": "0xa8", "arg_u32": 0x80000000, "arg_i32": -2147483648},
        {"vtable_offset": "0xa8", "arg_u32": 0x80000001, "arg_i32": -2147483647},
    ]
    _assert_never_observed(result)


def test_long_digit_string_is_bounded_and_clamped_without_big_integer_parse() -> None:
    digits = b"9" * 8192
    result = project_native_frame_requests("land", _binding("OURMANEUVER"), [_pair(1, digits)])
    assert result is not None
    item = _item(result)
    assert item["parsed"]["range_clamped"] is True
    assert item["parsed"]["signed_i32"] == 2147483647
    assert item["parsed"]["digit_count"] == 8192
    assert item["raw_input_bytes"] == 8192
    _assert_never_observed(result)


def test_no_digits_and_sign_only_parse_as_zero() -> None:
    result = project_native_frame_requests(
        "land", _binding("ENEMYSIEGE"), [_pair(0, b""), _pair(1, b"-"), _pair(2, b"abc")],
    )
    assert result is not None
    assert all(x["parsed"]["no_digits"] is True for x in result["requests"])
    assert all(x["parsed"]["signed_i32"] == 0 for x in result["requests"])
    assert all(x["virtual_setter_request"]["arg_u32"] == 1 for x in result["requests"])
    assert all(x["virtual_setter_request"]["arg_i32"] == 1 for x in result["requests"])


def test_icon_threshold_uses_no_argument_slot_below_one_and_original_value_above() -> None:
    result = project_native_frame_requests(
        "naval", _binding("OURLEADERICON"),
        [_pair(8, b"0"), _pair(9, b"-1"), _pair(10, b"1"), _pair(11, b"12tail")],
    )
    assert result is not None
    assert [x["virtual_setter_request"] for x in result["requests"]] == [
        {"vtable_offset": "0x90", "arguments": []},
        {"vtable_offset": "0x90", "arguments": []},
        {"vtable_offset": "0xa8", "arg_u32": 1, "arg_i32": 1},
        {"vtable_offset": "0xa8", "arg_u32": 12, "arg_i32": 12},
    ]
    assert result["status"] == "known"
    _assert_never_observed(result)


def test_non_ascii_prefix_is_unknown_but_non_ascii_after_digits_terminates_prefix() -> None:
    result = project_native_frame_requests(
        "land", _binding("OURFIRE"),
        [_pair(2, b" \t\xa7G+0.41"), _pair(3, b"12\xa7G")],
    )
    assert result is not None and result["status"] == "partial"
    prefix, suffix = result["requests"]
    assert prefix["status"] == "unknown"
    assert prefix["reason"] == "NON_ASCII_PREFIX_LOCALE_UNRESOLVED"
    assert prefix["virtual_setter_request"] is None
    assert suffix["status"] == "known"
    assert suffix["parsed"]["signed_i32"] == 12
    assert suffix["virtual_setter_request"]["arg_u32"] == 13
    assert suffix["virtual_setter_request"]["arg_i32"] == 13
    _assert_never_observed(result)


def test_empty_inputs_are_unknown_and_bad_hex_is_local_partial() -> None:
    binding = _binding("OURFIRE")
    missing = project_native_frame_requests("land", binding, [])
    assert missing is not None and missing["status"] == "unknown"
    assert missing["requests"] == [{
        "status": "unknown", "pair_index": None, "reason": "CONTROL_INPUT_MISSING",
        "raw_input_bytes": None, "parsed": None, "virtual_setter_request": None,
        "native_call_observed": False, "runtime_widget_state_verified": False,
    }]
    _assert_never_observed(missing)

    partial = project_native_frame_requests(
        "land", binding,
        [_pair(1, b"3"), _pair(2, b"", raw_hex="3z"), _pair(3, b"7")],
    )
    assert partial is not None and partial["status"] == "partial"
    assert [x["status"] for x in partial["requests"]] == ["known", "unknown", "known"]
    assert partial["requests"][1]["reason"] == "RAW_HEX_INVALID"
    assert partial["requests"][0]["virtual_setter_request"]["arg_u32"] == 4
    assert partial["requests"][0]["virtual_setter_request"]["arg_i32"] == 4
    assert partial["requests"][2]["virtual_setter_request"]["arg_u32"] == 8
    assert partial["requests"][2]["virtual_setter_request"]["arg_i32"] == 8
    _assert_never_observed(partial)


def test_duplicate_pairs_keep_pair_indices_and_source_order_without_last_wins() -> None:
    result = project_native_frame_requests(
        "land", _binding("ENEMYFIRE"),
        [_pair(7, b"4"), _pair(7, b"-2"), _pair(9, b"8")],
    )
    assert result is not None and result["status"] == "known"
    assert [x["pair_index"] for x in result["requests"]] == [7, 7, 9]
    assert [x["virtual_setter_request"]["arg_i32"] for x in result["requests"]] == [5, -1, 9]
    _assert_never_observed(result)


@pytest.mark.parametrize(
    ("raw_hex", "reason"),
    [
        ("f", "RAW_HEX_ODD_LENGTH"),
        ("zz", "RAW_HEX_INVALID"),
        ("61" * 8193, "RAW_INPUT_OVER_BOUND"),
    ],
)
def test_invalid_hex_and_overbound_bytes_are_unknown_locally(raw_hex: str, reason: str) -> None:
    result = project_native_frame_requests(
        "naval", _binding("OURFIRE"), [_pair(4, b"1", raw_hex=raw_hex)],
    )
    assert result is not None and result["status"] == "unknown"
    assert result["requests"][0]["reason"] == reason
    assert result["requests"][0]["virtual_setter_request"] is None
    _assert_never_observed(result)


def test_decoded_claim_is_ignored_and_non_object_input_is_local_unknown() -> None:
    result = project_native_frame_requests(
        "naval", _binding("OURSHOCK"),
        [_pair(1, b"6", decoded={"status": "unknown", "value": "not the source"}), object()],
    )
    assert result is not None and result["status"] == "partial"
    assert result["requests"][0]["parsed"]["signed_i32"] == 6
    assert result["requests"][0]["virtual_setter_request"]["arg_u32"] == 7
    assert result["requests"][0]["virtual_setter_request"]["arg_i32"] == 7
    assert result["requests"][1]["status"] == "unknown"
    assert result["requests"][1]["reason"] == "INPUT_ITEM_NOT_OBJECT"

