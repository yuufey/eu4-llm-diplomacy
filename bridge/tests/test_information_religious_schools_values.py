from copy import deepcopy

import pytest

from bridge.information import religious_schools_values as values


def _unknown(reason):
    return {"status": "unknown", "reason": reason}


def _payload(*, has_school=True, school_key="shafi"):
    return {
        "has_school": has_school,
        "religion_key": "catholic",
        "religion_group_key": "christian",
        "current_school": ({"status": "known", "key": school_key}
                           if has_school else dict(values.NONE)),
        "uses_schools": _unknown("RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ"),
        "invited_scholars": _unknown("INVITED_SCHOLARS_NOT_READ"),
        "relations": _unknown("SCHOOL_RELATIONS_NOT_READ"),
    }


def test_public_value_accepts_copied_school_key_and_preserves_unknown_mechanics():
    source = _payload()

    result = values.public_value(source, "POR")

    assert result == source
    assert result is not source
    assert result["current_school"] is not source["current_school"]
    assert result["uses_schools"] is not source["uses_schools"]
    result["current_school"]["key"] = "mutated"
    result["uses_schools"]["reason"] = "changed"
    assert source["current_school"]["key"] == "shafi"
    assert source["uses_schools"]["reason"] == "RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ"


def test_public_value_accepts_native_no_school_sentinel_without_promoting_mechanisms():
    source = _payload(has_school=False)

    result = values.public_value(source, "POR")

    assert result["has_school"] is False
    assert result["current_school"] == {
        "status": "none", "reason": "NATIVE_SCHOOL_SENTINEL"}
    assert result["uses_schools"] == _unknown("RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ")
    assert result["invited_scholars"] == _unknown("INVITED_SCHOLARS_NOT_READ")
    assert result["relations"] == _unknown("SCHOOL_RELATIONS_NOT_READ")


@pytest.mark.parametrize("name", ["uses_schools", "invited_scholars", "relations"])
@pytest.mark.parametrize("claim", [
    {"status": "known", "value": True},
    {"status": "none", "reason": "NATIVE_SCHOOL_SENTINEL"},
    {"status": "not_applicable", "reason": "NO_SCHOOL"},
])
def test_public_value_rejects_unread_activation_scholars_or_relations(name, claim):
    source = _payload()
    source[name] = deepcopy(claim)

    with pytest.raises(ValueError, match="SCHOOL_UNPROVEN_STATE"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("name,reason", [
    ("uses_schools", "RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ"),
    ("invited_scholars", "INVITED_SCHOLARS_NOT_READ"),
    ("relations", "SCHOOL_RELATIONS_NOT_READ"),
])
@pytest.mark.parametrize("mutation", ["wrong_reason", "extra_address", "missing_reason"])
def test_public_value_requires_exact_unknown_shape_for_unread_mechanics(name, reason, mutation):
    source = _payload()
    child = _unknown(reason)
    if mutation == "wrong_reason":
        child["reason"] = "UNKNOWN"
    elif mutation == "extra_address":
        child["address"] = "0x12345678"
    else:
        child.pop("reason")
    source[name] = child

    with pytest.raises(ValueError, match="SCHOOL_UNPROVEN_STATE"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("mutation", ["extra_top_level_address", "missing_field", "extra_field"])
def test_public_value_requires_exact_outer_shape(mutation):
    source = _payload()
    if mutation == "extra_top_level_address":
        source["school_pointer"] = "0x12345678"
    elif mutation == "missing_field":
        source.pop("relations")
    else:
        source["tooltip"] = "derived"

    with pytest.raises(ValueError, match="SCHOOL_VALUE_SHAPE"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("target", ["fra", "FR", "POR1", "A/B", None, True, 47])
def test_public_value_rejects_invalid_target_tag(target):
    with pytest.raises(ValueError, match="SCHOOL_TARGET"):
        values.public_value(_payload(), target)


@pytest.mark.parametrize("bad", [1, 0, None, "true", [], {}])
def test_public_value_requires_a_real_boolean_school_flag(bad):
    source = _payload()
    source["has_school"] = bad

    with pytest.raises(ValueError, match="SCHOOL_FLAG"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("name", ["religion_key", "religion_group_key"])
@pytest.mark.parametrize("bad", ["", "-bad", "bad key", "学派", "x\0y", "a" * 129])
def test_public_value_rejects_malformed_religion_identity_keys(name, bad):
    source = _payload()
    source[name] = bad

    with pytest.raises(ValueError, match="SCHOOL_RELIGION_KEY"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("key", ["a", "School_1", "x" * 128, "foo.bar:baz-qux"])
def test_public_value_accepts_identifier_boundaries(key):
    source = _payload(school_key=key)

    assert values.public_value(source, "POR")["current_school"]["key"] == key


@pytest.mark.parametrize("bad", [None, 1, "", "-bad", "bad key", "学派", "a" * 129])
def test_public_value_rejects_malformed_school_keys(bad):
    source = _payload()
    source["current_school"]["key"] = bad

    with pytest.raises(ValueError, match="SCHOOL_KEY"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("bad_school", [
    {"status": "known"},
    {"status": "known", "key": "shafi", "address": "0x12345678"},
    {"status": "unknown", "key": "shafi"},
    {"status": "none", "reason": "NATIVE_SCHOOL_SENTINEL"},
])
def test_public_value_rejects_inexact_school_dto_or_pointer_injection(bad_school):
    source = _payload()
    source["current_school"] = bad_school

    with pytest.raises(ValueError, match="SCHOOL_KEY"):
        values.public_value(source, "POR")


@pytest.mark.parametrize("bad_school", [
    {"status": "none", "reason": "OTHER"},
    {"status": "none", "reason": "NATIVE_SCHOOL_SENTINEL", "key": "shafi"},
    {"status": "known", "key": "shafi"},
    None,
])
def test_public_value_rejects_school_object_when_native_sentinel_is_false(bad_school):
    source = _payload(has_school=False)
    source["current_school"] = bad_school

    with pytest.raises(ValueError, match="SCHOOL_SENTINEL"):
        values.public_value(source, "POR")


def test_public_value_rejects_none_sentinel_when_school_is_present():
    source = _payload(has_school=True)
    source["current_school"] = dict(values.NONE)

    with pytest.raises(ValueError, match="SCHOOL_KEY"):
        values.public_value(source, "POR")
