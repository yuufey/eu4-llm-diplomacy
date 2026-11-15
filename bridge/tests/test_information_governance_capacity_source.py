"""Offline boundary tests for the N06 governance-capacity source."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information import governance_capacity as governance_module
from bridge.information import governance_capacity_values as values_module
from bridge.information import scalar_capture_source as scalar_module
from bridge.information.catalog import InformationError
from bridge.tests import test_information_relations_capacity as capacity_fixture


FIELD = "governance_capacity"
TOPIC = "N06"
PROFILE_SHA = "e" * 64
PRIVATE_ADDRESS = "0xdeadbeef"
_OUTER_BASIS = "native_governing_capacity_cache_and_limit_arithmetic"
_OUTER_ORIGIN = "derived_from_copied_native_governing_capacity_inputs"


def make_query(*, country="FRA", fields=None, parameters=None):
    return {
        "topic": TOPIC,
        "object": {"type": "country", "country": country},
        "fields": list(fields if fields is not None else (FIELD,)),
        "parameters": deepcopy(parameters if parameters is not None else {}),
    }


def _number(name: str, value: int) -> dict:
    spec = values_module.NUMBER_SPECS[name]
    width = spec["width"]
    return {
        "status": "known",
        "value": value,
        "raw": value,
        "raw_hex": value.to_bytes(width, "little", signed=True).hex(),
        "unit": spec["unit"],
        "scale": spec["scale"],
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": spec["basis"],
        "value_origin": spec["value_origin"],
    }


def _state(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason}


def _known_capacity(*, used=120000, limit=500000, fraction=240, headroom=380000):
    return {
        "status": "known",
        "value": {
            "used": _number("used", used) if type(used) is int else deepcopy(used),
            "limit": _number("limit", limit) if type(limit) is int else deepcopy(limit),
            "used_fraction": (
                _number("used_fraction", fraction)
                if type(fraction) is int else deepcopy(fraction)
            ),
            "headroom": (
                _number("headroom", headroom)
                if type(headroom) is int else deepcopy(headroom)
            ),
        },
        "unit": "governing_capacity_summary",
        "scale": 1,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": _OUTER_BASIS,
        "value_origin": _OUTER_ORIGIN,
    }


def make_source(tmp_path, monkeypatch, *, projected=None, validation=True,
                after_capture=None, capture_error=None, profile_sha=PROFILE_SHA):
    base = capacity_fixture.FakeBase(tmp_path, capacity_fixture.make_context())
    report = {
        "capture_fixture": "synthetic-governance-capacity",
        "raw_inputs": {"private_address": PRIVATE_ADDRESS},
    }
    calls = {"capture": [], "validate": [], "project": []}
    projection = deepcopy(
        projected if projected is not None else {FIELD: _known_capacity()}
    )

    def capture(installation, *, observer):
        calls["capture"].append((installation, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(report_arg, context_arg, creation):
        calls["validate"].append((deepcopy(report_arg), deepcopy(context_arg), creation))
        return validation

    def project_fields(report_arg):
        calls["project"].append(deepcopy(report_arg))
        return deepcopy(projection)

    module = SimpleNamespace(
        PROFILE_SHA256=profile_sha,
        validate_capture=validate_capture,
        project_fields=project_fields,
    )
    monkeypatch.setattr(scalar_module, "import_module", lambda _name: module)
    source = governance_module.NativeGovernanceCapacitySource(base, capture=capture)
    return source, base, report, calls


def test_catalog_and_query_are_fra_only_and_select_governance_capacity(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    topic = source.catalog()[0]
    assert topic["topic_id"] == TOPIC
    assert list(topic["fields"]) == [FIELD]
    assert topic["observer_scope"] == ["FRA"]
    assert topic["triggers"] == ["query", "periodic"]
    assert topic["fields"][FIELD]["unit"] == "governing_capacity_summary"

    normalized = source.validate_query(make_query(), base.context())
    assert normalized["fields"] == [FIELD]
    assert normalized["parameters"] == {}
    with pytest.raises(InformationError):
        source.validate_query(make_query(country="ENG"), base.context())
    with pytest.raises(InformationError):
        source.validate_query(make_query(fields=[FIELD, "prestige"]), base.context())
    with pytest.raises(InformationError):
        source.validate_query(make_query(fields=["used"]), base.context())
    assert calls["capture"] == []


def test_optional_reference_recipient_is_accepted_without_changing_projection(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    omitted = make_query()
    omitted.pop("parameters")
    assert source.validate_query(omitted)["parameters"] == {}

    reference = make_query(parameters={"reference_recipient": "PAP"})
    assert source.validate_query(reference)["parameters"] == {
        "reference_recipient": "PAP",
    }
    field = source.read(reference, base.context())["fields"][FIELD]
    assert field == _known_capacity()
    assert calls["capture"] == [(base.session.directory / "installation.json", "FRA")]

    with pytest.raises(InformationError):
        source.validate_query(make_query(parameters={"reference_recipient": "FRA"}))
    assert len(calls["capture"]) == 1


def test_stale_context_is_rejected_before_capture(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    stale = base.context()
    base.current["game_date"] += 24

    field = source.read(make_query(), stale)["fields"][FIELD]
    assert field["status"] == "stale"
    assert field["reason"] == "NATIVE_SCALAR_CONTEXT_STALE"
    assert calls["capture"] == []


@pytest.mark.parametrize("change", ["date", "session"])
def test_capture_exception_still_rechecks_context_and_session(
        tmp_path, monkeypatch, change):
    def mutate(base):
        if change == "date":
            base.current["game_date"] += 24
        else:
            base.session.creation_filetime += 1
            base.session.record["creation_filetime"] += 1

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=mutate,
        capture_error=RuntimeError("synthetic capture failure"),
    )
    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "stale"
    assert field["reason"] == "NATIVE_SCALAR_CONTEXT_CHANGED_DURING_CAPTURE"
    assert base.context_calls >= 3
    assert calls["validate"] == calls["project"] == []


def test_capture_validator_must_return_exact_true(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch, validation=1)

    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "NATIVE_SCALAR_CAPTURE_NOT_VALIDATED"
    assert len(calls["validate"]) == 1
    assert calls["project"] == []


def test_known_compound_projection_keeps_component_units_and_no_outer_raw(
        tmp_path, monkeypatch):
    source, base, report, calls = make_source(tmp_path, monkeypatch)
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]

    assert field == _known_capacity()
    assert field["status"] == "known"
    assert "raw" not in field and "raw_hex" not in field
    assert field["unit"] == "governing_capacity_summary" and field["scale"] == 1
    assert field["complete"] is False and field["partial"] is True
    assert field["basis"] == _OUTER_BASIS
    assert field["value_origin"] == _OUTER_ORIGIN
    values = field["value"]
    assert values["used"]["value"] == values["used"]["raw"] == 120000
    assert values["limit"]["value"] == values["limit"]["raw"] == 500000
    assert values["used_fraction"]["value"] == values["used_fraction"]["raw"] == 240
    assert values["headroom"]["value"] == values["headroom"]["raw"] == 380000
    assert values["used"]["unit"] == values["limit"]["unit"] == "governing_capacity"
    assert values["used_fraction"]["unit"] == "ratio"
    assert values["headroom"]["unit"] == "governing_capacity"
    assert calls["validate"][0][2] == capacity_fixture.CREATION
    assert len(calls["project"]) == 1
    assert len(result["source"]["provenance"]["capture_report_sha256"]) == 64
    assert result["source"]["provenance"]["profile_sha256"] == PROFILE_SHA
    assert report["capture_fixture"] not in repr(result)
    assert PRIVATE_ADDRESS not in repr(result)


# The largest magnitude is the difference between opposite signed-int32 inputs;
# the public headroom still uses signed 64-bit storage and fraction truncates to zero.
@pytest.mark.parametrize(("used", "limit", "fraction", "headroom", "raw_hex"), [
    (-(1 << 31), (1 << 31) - 1, -1000, (1 << 32) - 1, "ffffffff00000000"),
    ((1 << 31) - 1, -(1 << 31), -999, -((1 << 32) - 1), "01000000ffffffff"),
])
def test_headroom_uses_signed_eight_byte_raw_at_int32_difference_limits(
        tmp_path, monkeypatch, used, limit, fraction, headroom, raw_hex):
    projected = {FIELD: _known_capacity(
        used=used, limit=limit, fraction=fraction, headroom=headroom,
    )}
    source, base, _, _ = make_source(tmp_path, monkeypatch, projected=projected)

    field = source.read(make_query(), base.context())["fields"][FIELD]
    headroom_field = field["value"]["headroom"]
    assert field["status"] == "known"
    assert headroom_field["value"] == headroom_field["raw"] == headroom
    assert len(headroom_field["raw_hex"]) == 16
    assert headroom_field["raw_hex"] == raw_hex
    assert headroom_field["unit"] == "governing_capacity"
    assert headroom_field["scale"] == 1000


def test_unknown_nested_component_and_zero_limit_fraction_are_preserved(
        tmp_path, monkeypatch):
    unknown_used = _state("unknown", "USED_CACHE_UNAVAILABLE")
    unknown_fraction = _state("unknown", "USED_FRACTION_REQUIRES_USED")
    unknown_headroom = _state("unknown", "HEADROOM_REQUIRES_USED")
    projected = {FIELD: _known_capacity(
        used=unknown_used,
        limit=500000,
        fraction=unknown_fraction,
        headroom=unknown_headroom,
    )}
    source, base, _, _ = make_source(tmp_path, monkeypatch, projected=projected)

    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "known"
    assert field["value"]["used"] == unknown_used
    assert field["value"]["used_fraction"] == unknown_fraction
    assert field["value"]["headroom"] == unknown_headroom
    assert field["value"]["limit"]["value"] == 500000

    not_applicable = _state("not_applicable", "GOVERNANCE_CAPACITY_LIMIT_ZERO")
    projected = {FIELD: _known_capacity(
        used=120000, limit=0, fraction=not_applicable, headroom=-120000,
    )}
    source, base, _, _ = make_source(tmp_path, monkeypatch, projected=projected)
    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "known"
    assert field["value"]["used_fraction"] == not_applicable


def test_unknown_outer_projection_is_normalized_without_components(
        tmp_path, monkeypatch):
    source, base, _, _ = make_source(
        tmp_path, monkeypatch,
        projected={FIELD: _state("unknown", "CAPACITY_SOURCE_UNKNOWN")},
    )

    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "CAPACITY_SOURCE_UNKNOWN"
    assert "value" not in field
    assert "raw" not in field and "raw_hex" not in field


@pytest.mark.parametrize("mutation", [
    "not_dict", "missing_component", "extra_component", "outer_scale",
    "outer_raw", "nested_unit", "nested_scale", "bad_hex", "bool_value",
    "bool_raw", "private_key",
])
def test_malformed_compound_projection_is_rejected_without_private_leak(
        tmp_path, monkeypatch, mutation):
    item = _known_capacity()
    if mutation == "not_dict":
        item = ["not", "a", "mapping"]
    elif mutation == "missing_component":
        del item["value"]["used"]
    elif mutation == "extra_component":
        item["value"]["native_pointer"] = PRIVATE_ADDRESS
    elif mutation == "outer_scale":
        item["scale"] = True
    elif mutation == "outer_raw":
        item["raw"] = 120000
    elif mutation == "nested_unit":
        item["value"]["limit"]["unit"] = "diplomats"
    elif mutation == "nested_scale":
        item["value"]["used"]["scale"] = True
    elif mutation == "bad_hex":
        item["value"]["headroom"]["raw_hex"] = "00000000"
    elif mutation == "bool_value":
        item["value"]["used"]["value"] = True
    elif mutation == "bool_raw":
        item["value"]["limit"]["raw"] = True
    elif mutation == "private_key":
        item["value"]["used"]["address"] = PRIVATE_ADDRESS

    source, base, _, _ = make_source(tmp_path, monkeypatch, projected={FIELD: item})
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "NATIVE_SCALAR_CAPTURE_SHAPE_INVALID"
    assert "value" not in field
    assert PRIVATE_ADDRESS not in repr(result)


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


def test_query_report_periodics_share_projection_and_cancel_stops_future_reads(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    clock = FakeClock()
    service = InformationService(
        source, tmp_path / "governance-capacity.sqlite3", clock=clock,
    )
    query = make_query()
    try:
        direct_field = source.read(query, base.context())["fields"][FIELD]
        manual = service.query("governance-manual-query", queries=[query])
        assert manual["items"][0]["fields"][FIELD] == direct_field

        report = service.manage_report(
            "governance-report-create", "create",
            config={"name": "governance capacity", "queries": [query], "detail": "full"},
        )["report"]
        report_result = service.query("governance-report-query", report_id=report["id"])
        assert report_result["items"][0]["fields"][FIELD] == direct_field

        def create_periodic(request_id, name, every):
            return service.manage_subscription(
                request_id, "create",
                config={
                    "name": name,
                    "kind": "periodic",
                    "report_id": report["id"],
                    "schedule": {"basis": "real", "every": every, "unit": "seconds"},
                },
            )["subscription"]

        periodic_two = create_periodic("governance-periodic-two", "two seconds", 2)
        periodic_five = create_periodic("governance-periodic-five", "five seconds", 5)
        assert service.tick()["results"] == []

        clock.advance(2)
        first_tick = service.tick()["results"]
        assert len(first_tick) == 1
        assert first_tick[0]["subscription_id"] == periodic_two["id"]
        assert first_tick[0]["trigger"] == "periodic"
        assert first_tick[0]["items"][0]["fields"][FIELD] == direct_field

        cancelled_two = service.manage_subscription(
            "governance-cancel-two", "cancel", subscription_id=periodic_two["id"],
            expected_version=periodic_two["version"],
        )["subscription"]
        assert cancelled_two["state"] == "cancelled"

        clock.advance(3)
        second_tick = service.tick()["results"]
        assert len(second_tick) == 1
        assert second_tick[0]["subscription_id"] == periodic_five["id"]
        assert second_tick[0]["trigger"] == "periodic"
        assert second_tick[0]["items"][0]["fields"][FIELD] == direct_field

        cancelled_five = service.manage_subscription(
            "governance-cancel-five", "cancel", subscription_id=periodic_five["id"],
            expected_version=periodic_five["version"],
        )["subscription"]
        assert cancelled_five["state"] == "cancelled"
        assert len(calls["capture"]) == 5
        clock.advance(5)
        assert service.tick()["results"] == []
        assert len(calls["capture"]) == 5
    finally:
        service.close()
