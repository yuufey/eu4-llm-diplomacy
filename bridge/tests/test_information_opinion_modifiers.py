from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.opinion_modifiers import NativeOpinionModifiersSource


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CONTEXT = {
    "status": "ready", "mode": "live", "complete": True, "observer": "FRA",
    "game_version": "1.37.4", "game_sha256": GAME_SHA, "dll_sha256": "d" * 64,
    "session_id": "opinion-modifiers-session", "game_date": 56560344,
    "game_date_raw": 56560344, "world_id": "opinion-modifiers-world", "paused": True,
}
OUTGOING = "R04.opinion_modifiers.outgoing"
INCOMING = "R04.opinion_modifiers.incoming"


def _record(modifier_id="friendship_modifier", value=-200, *, date=56560344,
            multiplier=1000, flags=None, raw_hex=None):
    raw = value.to_bytes(4, "little", signed=True).hex() if raw_hex is None else raw_hex
    return {
        "status": "known", "modifier_id": modifier_id,
        "current_opinion_raw": value, "raw_hex": raw,
        "record_date_raw": date, "multiplier_raw": multiplier,
        "flags_raw": {"24": 1, "26": 0} if flags is None else deepcopy(flags),
    }


def _direction(holder, target, records):
    return {
        "status": "known",
        "value": {"holder": holder, "target": target, "records": deepcopy(records)},
        "unit": "opinion_points", "scale": 1000, "complete": False,
    }


def _report(*, outgoing=None, incoming=None):
    if outgoing is None:
        outgoing = [_record()]
    if incoming is None:
        incoming = [_record("royal_marriage", 1250)]
    return {
        "schema": "private-opinion-modifier-report",
        "raw_reads": [{"address": "0xDEADBEEF", "raw_hex": "private-trace"}],
        "observation": {"backend": {
            "status": "observed", "consistency": {"status": "stable"},
            "targets": [{"tag": "ENG", "fields": {
                OUTGOING: _direction("FRA", "ENG", outgoing),
                INCOMING: _direction("ENG", "FRA", incoming),
            }}],
        }},
    }


class Primary:
    def __init__(self, directory, *, context=None):
        self._context = deepcopy(context or CONTEXT)
        self.session = SimpleNamespace(
            directory=directory,
            record={"creation_filetime": 123456789},
            creation_filetime=123456789,
        )

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        return list_topics()


class CaptureHarness:
    def __init__(self, report=None, *, capture_error=None, validator_result=True,
                 validator_error=None, after_capture=None):
        self.report = deepcopy(report or _report())
        self.capture_error = capture_error
        self.validator_result = validator_result
        self.validator_error = validator_error
        self.after_capture = after_capture
        self.capture_calls = []
        self.validator_calls = []

    def capture(self, installation, target):
        self.capture_calls.append((installation, target))
        if self.after_capture is not None:
            self.after_capture()
        if self.capture_error is not None:
            raise RuntimeError(self.capture_error)
        return deepcopy(self.report)

    def validate(self, report, context, creation, target):
        self.validator_calls.append((deepcopy(context), creation, target))
        if self.validator_error is not None:
            raise RuntimeError(self.validator_error)
        return self.validator_result


class DefinitionIndex:
    def __init__(self, declarations=None, *, lookup_status="known", fail=False):
        self.declarations = declarations or {
            "opinion": {"status": "declared", "value": "0"},
            "min": {"status": "not_declared"},
            "max": {"status": "declared", "value": "100"},
            "yearly_decay": {"status": "unknown", "reason": "nonliteral"},
            "years": {"status": "not_declared"},
            "months": {"status": "not_declared"},
        }
        self.lookup_status = lookup_status
        self.fail = fail
        self.calls = []

    def context(self):
        return {
            "status": "ready", "source_basis": "disk_configuration",
            "loaded_membership_verified": False, "conditions_evaluated": False,
            "source_pins": {"definitions_sha256": "a" * 64},
        }

    def lookup(self, key):
        self.calls.append(key)
        if self.fail:
            raise RuntimeError("path C:/private/game installation")
        if self.lookup_status != "known":
            return {"status": self.lookup_status}
        return {
            "status": "known", "key": key,
            "declarations": deepcopy(self.declarations),
            "source_basis": "disk_configuration", "loaded_membership_verified": False,
            "conditions_evaluated": False,
        }


def _query(actor="FRA", recipient="ENG", *, fields=None, parameters=None):
    return {
        "topic": "R04", "object": {"type": "country_pair", "actor": actor, "recipient": recipient},
        "fields": list(fields or ["opinion_modifiers"]),
        "parameters": {} if parameters is None else parameters,
    }


def _source(tmp_path, *, context=None, harness=None, definitions=None):
    primary = Primary(tmp_path, context=context)
    harness = harness or CaptureHarness()
    source = NativeOpinionModifiersSource(
        primary, capture=harness.capture, validator=harness.validate,
        definitions=definitions,
    )
    return source, primary, harness


def _field(result):
    return result["fields"]["opinion_modifiers"]


def test_catalog_adds_only_partial_modifier_field_with_query_and_periodic(tmp_path):
    source, _primary, _harness = _source(tmp_path)
    entries = source.catalog()
    assert len(entries) == 1
    r04 = entries[0]
    assert r04["topic_id"] == "R04"
    assert r04["status"] == "available"
    assert r04["fields"].keys() == {"opinion_modifiers"}
    assert r04["triggers"] == ["query", "periodic"]
    assert "change_scope" not in r04
    meta = r04["fields"]["opinion_modifiers"]
    assert meta["coverage"] == "partial" and meta["complete"] is False
    assert meta["unit"] == "opinion_points" and meta["scale"] == 1000
    assert "OTHER_COMPUTED_OPINION_SOURCES_NOT_COVERED" in meta["gaps"]
    assert "MODIFIER_DURATION_AND_EXPIRY_NOT_PROVEN" in meta["gaps"]
    base_r04 = next(row for row in list_topics() if row["topic_id"] == "R04")
    assert {key for key in base_r04["fields"] if base_r04["fields"][key]["coverage"] == "planned"} == {
        "opinion", "opinion_modifiers", "decay", "end_date",
    }


def test_capture_projects_current_raw_records_in_both_directions_without_private_fields(tmp_path):
    source, _primary, harness = _source(tmp_path)
    result = source.read(_query(), source.context())
    assert len(harness.capture_calls) == len(harness.validator_calls) == 1
    installation, target = harness.capture_calls[0]
    assert installation == tmp_path / "installation.json"
    assert target == "ENG"
    field = _field(result)
    assert field["status"] == "known"
    assert field["unit"] == "opinion_points" and field["scale"] == 1000
    assert field["complete"] is False and field["partial"] is True
    assert field["value"][0] == {
        "holder": "FRA", "target": "ENG", "status": "known",
        "records": [{
            "status": "known", "modifier_id": "friendship_modifier",
            "current_opinion_raw": -200, "current_opinion_decimal": "-0.200",
            "raw_hex": "38ffffff", "unit": "opinion_points", "scale": 1000,
        }],
    }
    assert field["value"][1]["records"][0]["current_opinion_decimal"] == "1.250"
    assert "0xDEADBEEF" not in repr(result)
    assert "private-trace" not in repr(result)
    for private_name in ("record_date_raw", "multiplier_raw", "flags_raw"):
        assert private_name not in repr(result)
    assert "raw_reads" not in result["source"]["provenance"]
    assert result["complete"] is False


def test_reversed_pair_reverses_public_direction_order(tmp_path):
    source, _primary, harness = _source(tmp_path)
    field = _field(source.read(_query("ENG", "FRA"), source.context()))
    assert harness.capture_calls[0][1] == "ENG"
    assert [(row["holder"], row["target"]) for row in field["value"]] == [
        ("ENG", "FRA"), ("FRA", "ENG"),
    ]
    assert [row["records"][0]["modifier_id"] for row in field["value"]] == [
        "royal_marriage", "friendship_modifier",
    ]


def test_repeated_modifier_keys_remain_distinct_records_in_original_order(tmp_path):
    report = _report(outgoing=[_record("stackable_modifier", -200),
                               _record("stackable_modifier", 375)])
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    records = _field(source.read(_query(), source.context()))["value"][0]["records"]
    assert [(record["modifier_id"], record["current_opinion_raw"])
            for record in records] == [
        ("stackable_modifier", -200), ("stackable_modifier", 375),
    ]


def test_unknown_direction_and_unknown_modifier_class_are_preserved_not_empty(tmp_path):
    report = _report(outgoing=[_record(), {
        "status": "unknown", "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED",
    }])
    report["observation"]["backend"]["targets"][0]["fields"][INCOMING] = {
        "status": "unknown", "reason": "admission_unknown",
    }
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "known"
    assert field["value"][0]["records"][1] == {
        "status": "unknown", "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED",
    }
    assert field["value"][1] == {
        "holder": "ENG", "target": "FRA", "status": "unknown",
        "reason": "OPINION_MODIFIERS_BACKEND_FIELD_UNKNOWN",
    }


def test_both_invisible_directions_remain_invisible_without_values(tmp_path):
    report = _report()
    fields = report["observation"]["backend"]["targets"][0]["fields"]
    fields[OUTGOING] = {"status": "invisible", "reason": "admission_denied"}
    fields[INCOMING] = {"status": "invisible", "reason": "admission_denied"}
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "invisible"
    assert "value" not in field
    assert all(row["status"] == "invisible" for row in field["directions"])


@pytest.mark.parametrize("mutate", [
    lambda row: row.update(current_opinion_raw=True),
    lambda row: row.update(raw_hex="zzzzzzzz"),
    lambda row: row.update(raw_hex="39ffffff"),
    lambda row: row.update(record_date_raw=True),
    lambda row: row.update(multiplier_raw=1 << 31),
    lambda row: row.update(flags_raw={"24": True, "26": 0}),
    lambda row: row.update(extra="private"),
])
def test_invalid_record_becomes_unknown_without_dropping_valid_sibling(tmp_path, mutate):
    report = _report(outgoing=[_record(), _record("bad_modifier", 100)])
    mutate(report["observation"]["backend"]["targets"][0]["fields"][OUTGOING]["value"]["records"][1])
    source, _primary, _harness = _source(tmp_path, harness=CaptureHarness(report))
    field = _field(source.read(_query(), source.context()))
    records = field["value"][0]["records"]
    assert records[0]["status"] == "known"
    assert records[1] == {"status": "unknown", "reason": "OPINION_MODIFIER_RECORD_INVALID"}


def test_modifier_key_attaches_only_disk_declarations_and_preserves_missing_vs_zero(tmp_path):
    definitions = DefinitionIndex()
    source, _primary, _harness = _source(tmp_path, definitions=definitions)
    record = _field(source.read(_query(), source.context()))["value"][0]["records"][0]
    assert record["status"] == "known"
    assert record["definition"] == {
        "status": "known",
        "declarations": {
            "opinion": {"status": "declared", "value": "0"},
            "min": {"status": "not_declared"},
            "max": {"status": "declared", "value": "100"},
            "yearly_decay": {"status": "unknown", "reason": "OPINION_DEFINITION_VALUE_UNSUPPORTED"},
            "years": {"status": "not_declared"},
            "months": {"status": "not_declared"},
        },
        "source_basis": "disk_configuration", "loaded_membership_verified": False,
        "conditions_evaluated": False, "effects_executed": False,
        "current_decay_evaluated": False, "end_date_evaluated": False,
    }
    assert definitions.calls == ["friendship_modifier", "royal_marriage"]
    assert record["current_opinion_raw"] == -200


def test_definition_failure_or_input_change_only_withdraws_disk_declarations(tmp_path):
    definitions = DefinitionIndex(fail=True)
    source, _primary, _harness = _source(tmp_path, definitions=definitions)
    field = _field(source.read(_query(), source.context()))
    assert field["status"] == "known"
    record = field["value"][0]["records"][0]
    assert record["current_opinion_raw"] == -200
    assert record["definition"]["status"] == "unknown"
    assert record["definition"]["reason"] == "OPINION_DEFINITION_UNAVAILABLE"

    class ChangingDefinitions(DefinitionIndex):
        def __init__(self):
            super().__init__()
            self.context_calls = 0

        def context(self):
            self.context_calls += 1
            pins = {"definitions_sha256": ("a" if self.context_calls == 1 else "b") * 64}
            return {**super().context(), "source_pins": pins}

    changing = ChangingDefinitions()
    source, _primary, _harness = _source(tmp_path, definitions=changing)
    field = _field(source.read(_query(), source.context()))
    record = field["value"][0]["records"][0]
    assert field["status"] == "known" and record["current_opinion_raw"] == -200
    assert record["definition"]["status"] == "unknown"
    assert changing.context_calls == 2


def test_no_definitions_keeps_native_projection_free_of_static_claims(tmp_path):
    source, _primary, _harness = _source(tmp_path)
    record = _field(source.read(_query(), source.context()))["value"][0]["records"][0]
    assert "definition" not in record


def test_validator_failure_and_capture_exception_retract_native_values(tmp_path):
    source, _primary, harness = _source(
        tmp_path, harness=CaptureHarness(validator_result=False),
    )
    assert _field(source.read(_query(), source.context())) == {
        "status": "unknown", "reason": "OPINION_MODIFIERS_CAPTURE_INVALID",
    }
    assert len(harness.capture_calls) == len(harness.validator_calls) == 1

    source, _primary, _harness = _source(
        tmp_path, harness=CaptureHarness(capture_error="secret path C:/private"),
    )
    result = source.read(_query(), source.context())
    assert _field(result) == {"status": "unknown", "reason": "OPINION_MODIFIERS_CAPTURE_FAILED"}
    assert "private" not in repr(result)


def test_context_drift_during_capture_retracts_observation(tmp_path):
    primary = Primary(tmp_path)
    harness = CaptureHarness(after_capture=lambda: primary._context.update(
        game_date=56560345, game_date_raw=56560345,
    ))
    source = NativeOpinionModifiersSource(
        primary, capture=harness.capture, validator=harness.validate,
    )
    field = _field(source.read(_query(), source.context()))
    assert field == {"status": "unknown", "reason": "CONTEXT_CHANGED_DURING_CAPTURE"}
    assert len(harness.capture_calls) == 1 and harness.validator_calls == []


def test_recorded_context_is_unavailable_and_never_captured(tmp_path):
    source, _primary, harness = _source(tmp_path, context=dict(CONTEXT, mode="recorded"))
    assert _field(source.read(_query(), source.context())) == {
        "status": "unavailable", "reason": "LIVE_CONTEXT_REQUIRED",
    }
    assert harness.capture_calls == []


@pytest.mark.parametrize("query", [
    _query("ENG", "POR"),
    _query("FRA", "FRA"),
    _query(fields=["opinion_modifiers", "opinion"]),
    _query(parameters={"direction": "both"}),
    {**_query(), "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG", "extra": True}},
])
def test_pair_field_and_parameter_contract_is_strict(tmp_path, query):
    source, _primary, _harness = _source(tmp_path)
    with pytest.raises(InformationError):
        source.read(query, source.context())


def test_composite_catalog_keeps_only_the_modifier_field(tmp_path):
    source, primary, _harness = _source(tmp_path)
    composite = CompositeSource(primary, [source])
    r04 = next(row for row in composite.catalog() if row["topic_id"] == "R04")
    assert "opinion_modifiers" in r04["fields"]
    assert r04["triggers"] == ["query", "periodic"]
