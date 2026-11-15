import pytest

from bridge.information import papacy_values as values


def _raw(value):
    return value.to_bytes(4, "little", signed=True)


def _number(name, value):
    return values.number_value(name, _raw(value))


def _controller(country="FRA", is_target=True):
    return {
        "status": "known",
        "country": country,
        "is_target_controller": is_target,
    }


def _known_payload(target="FRA"):
    return {
        "uses_papacy": True,
        "papal_influence": _number("papal_influence", -201),
        "curia_treasury": _number("curia_treasury", 9001),
        "controller": _controller(target, True),
    }


@pytest.mark.parametrize(
    ("name", "unit", "basis"),
    [
        ("papal_influence", "papal_influence", "native_current_papal_influence_cache"),
        ("curia_treasury", "ducats", "native_current_curia_treasury_cache"),
    ],
)
def test_number_value_uses_exact_signed_cache_scalar_contract(name, unit, basis):
    dto = values.number_value(name, _raw(-201))

    assert dto == {
        "status": "known",
        "value": -201,
        "raw": -201,
        "raw_hex": "37ffffff",
        "unit": unit,
        "scale": 1000,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": basis,
        "value_origin": "copied_native_papacy_state",
    }


@pytest.mark.parametrize("number", [-(1 << 31), -1, 0, 201, (1 << 31) - 1])
def test_number_value_preserves_full_signed_i32_without_clamping(number):
    for field in values.NUMBER_SPECS:
        dto = values.number_value(field, _raw(number))
        assert dto["value"] == dto["raw"] == number


def test_number_value_rejects_unknown_field_names():
    for name in ("Papal_influence", "controller", "", None, True):
        with pytest.raises(ValueError):
            values.number_value(name, b"\0\0\0\0")


def test_number_value_requires_exact_bytes_and_four_byte_width():
    for raw in (bytearray(b"\0\0\0\0"), memoryview(b"\0\0\0\0"), b"", b"\0\0\0", b"\0\0\0\0\0", None):
        with pytest.raises(ValueError):
            values.number_value("papal_influence", raw)


def test_public_value_accepts_exact_not_applicable_children_when_papacy_is_unused():
    not_applicable = {"status": "not_applicable", "reason": "PAPACY_NOT_USED"}
    source = {
        "uses_papacy": False,
        "papal_influence": dict(not_applicable),
        "curia_treasury": dict(not_applicable),
        "controller": dict(not_applicable),
    }

    result = values.public_value(source, "FRA")

    assert result == source
    assert result["papal_influence"] is not source["papal_influence"]


@pytest.mark.parametrize("child", ["papal_influence", "curia_treasury", "controller"])
def test_public_value_rejects_each_inconsistent_unused_papacy_child(child):
    source = {
        "uses_papacy": False,
        "papal_influence": {"status": "not_applicable", "reason": "PAPACY_NOT_USED"},
        "curia_treasury": {"status": "not_applicable", "reason": "PAPACY_NOT_USED"},
        "controller": {"status": "not_applicable", "reason": "PAPACY_NOT_USED"},
    }
    source[child] = {"status": "unknown", "reason": "PAPACY_NOT_USED"}
    with pytest.raises(ValueError):
        values.public_value(source, "FRA")


def test_public_value_accepts_and_copies_known_scalars_and_controller():
    source = _known_payload()

    result = values.public_value(source, "FRA")

    assert result == source
    assert result["papal_influence"] is not source["papal_influence"]
    assert result["controller"] is not source["controller"]
    result["papal_influence"]["value"] = 1
    assert source["papal_influence"]["value"] == -201


def test_public_value_accepts_only_the_field_specific_unknown_reasons():
    source = _known_payload()
    source["papal_influence"] = {"status": "unknown", "reason": "PAPAL_INFLUENCE_UNAVAILABLE"}
    source["curia_treasury"] = {"status": "unknown", "reason": "CURIA_TREASURY_UNAVAILABLE"}
    source["controller"] = {"status": "unknown", "reason": "PAPACY_CONTROLLER_UNRESOLVED"}

    assert values.public_value(source, "FRA") == source


@pytest.mark.parametrize("mutation", ["value_bool", "raw_bool", "raw_hex_mismatch", "raw_hex_case", "value_mismatch", "unit", "scale_bool", "scale", "period", "partial", "complete", "basis", "origin", "private_pointer"])
def test_public_value_rejects_malformed_known_number(mutation):
    source = _known_payload()
    number = source["papal_influence"]
    changes = {
        "value_bool": ("value", True),
        "raw_bool": ("raw", False),
        "raw_hex_mismatch": ("raw_hex", "00000000"),
        "raw_hex_case": ("raw_hex", "37FFFFFF"),
        "value_mismatch": ("value", 1),
        "unit": ("unit", "ducats"),
        "scale_bool": ("scale", True),
        "scale": ("scale", 1),
        "period": ("period", "lifetime"),
        "partial": ("partial", False),
        "complete": ("complete", True),
        "basis": ("basis", "native_current_curia_treasury_cache"),
        "origin": ("value_origin", "guessed_from_ui"),
        "private_pointer": ("pointer", "0x12345678"),
    }
    key, bad_value = changes[mutation]
    number[key] = bad_value

    with pytest.raises(ValueError):
        values.public_value(source, "FRA")


@pytest.mark.parametrize("bad_controller", [
    {"status": "known", "country": "fra", "is_target_controller": False},
    {"status": "known", "country": "FRA", "is_target_controller": 1},
    {"status": "known", "country": "FRA", "is_target_controller": False},
    {"status": "unknown", "reason": "NONE"},
    {"status": "unknown", "reason": "PAPACY_CONTROLLER_UNRESOLVED", "address": "0x1234"},
])
def test_public_value_rejects_invalid_controller_claims(bad_controller):
    source = _known_payload()
    source["controller"] = bad_controller

    with pytest.raises(ValueError):
        values.public_value(source, "FRA")


@pytest.mark.parametrize("bad", [
    ("papal_influence", {"status": "unknown", "reason": "CURIA_TREASURY_UNAVAILABLE"}),
    ("curia_treasury", {"status": "unknown", "reason": "PAPAL_INFLUENCE_UNAVAILABLE"}),
    ("papal_influence", {"status": "unknown", "reason": "PAPAL_INFLUENCE_UNAVAILABLE", "value": 0}),
])
def test_public_value_rejects_bad_unknown_number_shape_or_reason(bad):
    name, dto = bad
    source = _known_payload()
    source[name] = dto

    with pytest.raises(ValueError):
        values.public_value(source, "FRA")


def test_public_value_requires_exact_outer_keys_and_boolean_gate():
    source = _known_payload()
    source["debug_pointer"] = "0x12345678"
    with pytest.raises(ValueError):
        values.public_value(source, "FRA")

    source = _known_payload()
    source["uses_papacy"] = 1
    with pytest.raises(ValueError):
        values.public_value(source, "FRA")


def test_public_value_checks_controller_target_binding_and_target_tag():
    source = _known_payload()
    source["controller"] = _controller("ENG", False)
    assert values.public_value(source, "FRA")["controller"]["is_target_controller"] is False

    source["controller"] = _controller("ENG", True)
    with pytest.raises(ValueError):
        values.public_value(source, "FRA")
    for target in ("fra", "FR", "FRA1", None, True):
        with pytest.raises(ValueError):
            values.public_value(_known_payload(), target)


def test_public_value_rejects_pointer_like_scalar_values():
    source = _known_payload()
    source["curia_treasury"]["value"] = "0x12345678"
    with pytest.raises(ValueError):
        values.public_value(source, "FRA")


def test_public_value_rejects_raw_value_mismatch_even_when_raw_hex_matches_raw():
    source = _known_payload()
    source["papal_influence"]["raw"] = 1
    source["papal_influence"]["raw_hex"] = "01000000"

    with pytest.raises(ValueError):
        values.public_value(source, "FRA")

