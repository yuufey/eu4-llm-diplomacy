"""R03 direct-truce expiry projection tests; no process or native call is opened."""
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_rivals import NativeCountryRivalsSource
from bridge.information.model import InformationError, canonical
from bridge.information.truce_date_math import direct_truce_expiry
from bridge.information.truce_dates import NativeTruceDatesSource
from bridge.information.war_relations import NativeWarRelationsSource


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134381481521109200
INSTALLATION = Path("C:/fixture/install/installation.json")
CONTEXT = {
    "status": "ready", "mode": "live", "observer": "FRA",
    "session_id": "truce-test-session", "game_sha256": GAME_SHA256,
    "game_version": "1.37.4", "game_date": 56556984,
    "dll_sha256": "ab" * 32, "physical_client_country": "POR",
    "world_id": "truce-test-world",
}
_DEFAULT_PARAMETERS = object()


def _raw_i32(value):
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False).hex()


def _raw_i8(value):
    return (value & 0xFF).to_bytes(1, "little", signed=False).hex()


def _record(actor, target, *, flag=True, adjustment=23, date_raw=56551344):
    return {
        "actor": actor,
        "target": target,
        "direct_flag": flag,
        "direct_flag_raw_hex": "01" if flag else "00",
        "adjustment_signed_i8": adjustment,
        "adjustment_raw_hex": _raw_i8(adjustment),
        "date_input_signed_i32": date_raw,
        "date_input_raw_hex": _raw_i32(date_raw),
    }


def _report(target="ENG", *, forward=None, reverse=None):
    return {
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "private_marker": "PRIVATE_RAW_TARGET_POINTER_0x123456789ABC",
        "observation": {
            "backend": {
                "targets": [{
                    "tag": target,
                    "fields": {
                        "R03.truce_until.inputs": {
                            "status": "known",
                            "value": {
                                "configuration_inputs": [
                                    {"rva": "0x233dc88", "signed_i32": 10,
                                     "raw_hex": "0a000000"},
                                    {"rva": "0x233dd8c", "signed_i32": 5,
                                     "raw_hex": "05000000"},
                                ],
                                "directed_records": [
                                    _record("FRA", target) if forward is None else forward,
                                    _record(target, "FRA", adjustment=-1, date_raw=56551344)
                                    if reverse is None else reverse,
                                ],
                            },
                        },
                    },
                }],
            },
        },
    }


def _query(actor="FRA", recipient="ENG", fields=None, parameters=_DEFAULT_PARAMETERS):
    return {
        "topic": "R03",
        "object": {"type": "country_pair", "actor": actor, "recipient": recipient},
        "fields": ["truce_until"] if fields is None else list(fields),
        "parameters": {} if parameters is _DEFAULT_PARAMETERS else parameters,
    }


class Base:
    event_types = ()

    def __init__(self, context=None):
        self.current = deepcopy(CONTEXT if context is None else context)
        self.context_calls = 0
        self.binding = (INSTALLATION, CREATION, None)

    def context(self):
        self.context_calls += 1
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, *_args, **_kwargs):
        raise AssertionError("Truce adapter must not issue a primary read")


class Capture:
    def __init__(self, report=None, *, valid=True):
        self.report = _report() if report is None else deepcopy(report)
        self.valid = valid
        self.capture_calls = []
        self.validate_calls = []
        self.on_capture = None
        self.capture_error = None
        self.validate_error = None

    def capture(self, installation, country, observer="FRA"):
        self.capture_calls.append((installation, country, observer))
        if self.on_capture is not None:
            self.on_capture()
        if self.capture_error is not None:
            raise self.capture_error
        return deepcopy(self.report)

    def validate_capture(self, report, context, creation, country):
        self.validate_calls.append((deepcopy(context), creation, country))
        if self.validate_error is not None:
            raise self.validate_error
        return self.valid


def _source(monkeypatch, *, base=None, capture=None):
    from bridge.information import truce_dates as module

    base = Base() if base is None else base
    capture = Capture() if capture is None else capture
    monkeypatch.setattr(module, "_session_binding", lambda _base: _base.binding)
    return NativeTruceDatesSource(base, capture_module=capture), base, capture


def _field(result):
    return result["fields"]["truce_until"]


def test_direct_fra_to_target_projects_native_model_prediction(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    result = source.read(_query(), CONTEXT)
    field = _field(result)
    expected = direct_truce_expiry(56551344, 23, 10, 5)
    assert (field["status"], field["value"], field["raw"]) == (
        "known", expected["raw"], expected["raw"]
    )
    assert field["date"] == "1463.1.1" and field["hour"] == 0
    assert field["unit"] == "eu4_hour_tick" and field["scale"] == 1
    assert field["period"] == "current" and field["partial"] is True
    assert field["complete"] is False and result["complete"] is False
    assert capture.capture_calls == [(INSTALLATION, "ENG", "FRA")]
    assert capture.validate_calls == [(CONTEXT, CREATION, "ENG")]
    provenance = result["source"]["provenance"]
    assert provenance["capture_report_sha256"] == hashlib.sha256(
        canonical(capture.report).encode("utf-8")
    ).hexdigest()
    assert "PRIVATE_RAW_TARGET_POINTER" not in repr(result)
    assert "raw_hex" not in repr(result)


def test_reverse_direction_selects_its_own_record(monkeypatch):
    report = _report()
    report["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["directed_records"][1] = _record(
        "ENG", "FRA", adjustment=-1, date_raw=56551344
    )
    source, _base, capture = _source(monkeypatch, capture=Capture(report))
    field = _field(source.read(_query("ENG", "FRA"), CONTEXT))
    expected = direct_truce_expiry(56551344, -1, 10, 5)
    assert field["status"] == "known"
    assert field["value"] == expected["raw"]
    assert field["date"] == expected["date"] and field["hour"] == expected["hour"]
    assert capture.capture_calls == [(INSTALLATION, "ENG", "FRA")]


def test_false_direct_flag_is_not_applicable_and_does_not_hide_reverse_record(monkeypatch):
    report = _report(forward=_record("FRA", "ENG", flag=False))
    source, _base, capture = _source(monkeypatch, capture=Capture(report))
    field = _field(source.read(_query(), CONTEXT))
    assert field["status"] == "not_applicable"
    assert field["reason"] == "DIRECT_PAIR_TRUCE_FLAG_NOT_SET"
    assert field["direct_record_flag"] is False and "value" not in field
    reverse = _field(source.read(_query("ENG", "FRA"), CONTEXT))
    assert reverse["status"] == "known"
    assert len(capture.capture_calls) == 2


def test_capture_receives_target_country_and_both_directions_once(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    result = source.read(_query("FRA", "ENG"), CONTEXT)
    assert capture.capture_calls == [(INSTALLATION, "ENG", "FRA")]
    assert len(capture.validate_calls) == 1
    assert result["objects"] == [_query()["object"]]


def test_catalog_is_one_partial_pair_field_and_has_no_change_trigger(monkeypatch):
    source, _base, _capture = _source(monkeypatch)
    topic = source.catalog()[0]
    assert topic["topic_id"] == "R03"
    assert set(topic["fields"]) == {"truce_until"}
    assert topic["fields"]["truce_until"]["coverage"] == "partial"
    assert topic["fields"]["truce_until"]["complete"] is False
    assert topic["object_types"] == ["country_pair"]
    assert topic["triggers"] == ["query", "periodic"]
    assert "change" not in topic["triggers"]


def test_country_selector_is_legal_but_not_implemented_without_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    query = {"topic": "R03", "object": {"type": "country", "country": "FRA"},
             "fields": ["truce_until"], "parameters": {}}
    field = _field(source.read(query, CONTEXT))
    assert field["status"] == "unsupported"
    assert field["reason"] == "TRUCE_COUNTRY_ENUMERATION_NOT_IMPLEMENTED"
    assert capture.capture_calls == []


def test_other_r03_field_is_unsupported_and_does_not_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    result = source.read(_query(fields=["wars"]), CONTEXT)
    assert result["fields"]["wars"] == {
        "status": "unsupported", "reason": "R03_FIELD_NOT_IMPLEMENTED"
    }
    assert capture.capture_calls == []


@pytest.mark.parametrize("status", ["unknown", "unavailable", "invisible"])
def test_capture_unknown_input_state_is_not_replaced_with_a_date(monkeypatch, status):
    report = _report()
    field = report["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]
    field.clear()
    field.update(status=status, reason="NATIVE_INPUT_NOT_ESTABLISHED")
    source, _base, _capture = _source(monkeypatch, capture=Capture(report))
    projected = _field(source.read(_query(), CONTEXT))
    assert projected["status"] == status
    assert projected["reason"] == "NATIVE_INPUT_NOT_ESTABLISHED"
    assert "value" not in projected and "raw" not in projected


def test_unknown_input_state_with_unsafe_reason_is_withheld(monkeypatch):
    report = _report()
    field = report["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]
    field.clear()
    field.update(status="unknown", reason="private pointer 0x123456789abcdef0")
    source, _base, _capture = _source(monkeypatch, capture=Capture(report))
    projected = _field(source.read(_query(), CONTEXT))
    assert projected["status"] == "unknown"
    assert projected["reason"] == "TRUCE_INPUTS_UNAVAILABLE"
    assert "123456789abcdef0" not in repr(projected)


def test_pair_without_fra_is_rejected_before_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    with pytest.raises(InformationError):
        source.read(_query("ENG", "POR"), CONTEXT)
    assert capture.capture_calls == []


def test_identical_pair_is_rejected_before_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    with pytest.raises(InformationError):
        source.read(_query("FRA", "FRA"), CONTEXT)
    assert capture.capture_calls == []


@pytest.mark.parametrize("parameters", [{"extra": 1}, None])
def test_nonempty_or_nonobject_parameters_are_rejected(monkeypatch, parameters):
    source, _base, capture = _source(monkeypatch)
    with pytest.raises(InformationError):
        source.read(_query(parameters=parameters), CONTEXT)
    assert capture.capture_calls == []


@pytest.mark.parametrize("change", [
    lambda q: q.update(fields=["wars", "wars"]),
    lambda q: q["object"].update(actor="France"),
    lambda q: q["object"].update(extra="private"),
])
def test_invalid_selectors_fields_and_topics_do_not_capture(monkeypatch, change):
    source, _base, capture = _source(monkeypatch)
    value = _query()
    change(value)
    with pytest.raises(InformationError):
        source.read(value, CONTEXT)
    assert capture.capture_calls == []


@pytest.mark.parametrize("mutate", [
    lambda r: r["observation"]["backend"]["targets"].append(
        deepcopy(r["observation"]["backend"]["targets"][0])),
    lambda r: r["observation"]["backend"]["targets"][0].update(tag="POR"),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["directed_records"].append(
        _record("FRA", "ENG")),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["directed_records"].__setitem__(
        1, _record("FRA", "ENG")),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["configuration_inputs"][0].update(rva="0x233dd8c"),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["configuration_inputs"][0].update(signed_i32=True),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["configuration_inputs"][0].update(raw_hex="00000000"),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["directed_records"][0].update(direct_flag=1),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["directed_records"][0].update(adjustment_signed_i8=True),
    lambda r: r["observation"]["backend"]["targets"][0]["fields"]["R03.truce_until.inputs"]["value"]["directed_records"][0].update(date_input_signed_i32=False),
])
def test_invalid_or_ambiguous_capture_projection_never_returns_value(monkeypatch, mutate):
    report = _report()
    mutate(report)
    source, _base, _capture = _source(monkeypatch, capture=Capture(report))
    field = _field(source.read(_query(), CONTEXT))
    assert field["status"] == "unavailable"
    assert "value" not in field and "raw" not in field


@pytest.mark.parametrize("valid,raises", [(False, False), (True, True)])
def test_capture_validator_failure_fails_closed(monkeypatch, valid, raises):
    capture = Capture(valid=valid)
    if raises:
        capture.validate_error = RuntimeError("private validator detail")
    source, _base, capture = _source(monkeypatch, capture=capture)
    field = _field(source.read(_query(), CONTEXT))
    assert field["status"] == "unavailable" and "value" not in field
    assert "private validator detail" not in repr(field)


def test_capture_exception_fails_closed_without_private_payload(monkeypatch):
    capture = Capture()
    capture.capture_error = RuntimeError("0x123456789abcdef0 secret")
    source, _base, _capture = _source(monkeypatch, capture=capture)
    result = source.read(_query(), CONTEXT)
    assert _field(result)["status"] == "unavailable"
    assert "value" not in _field(result)
    assert "123456789abcdef0" not in repr(result)


def test_stale_caller_context_does_not_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    caller = deepcopy(CONTEXT)
    caller["game_date"] += 1
    field = _field(source.read(_query(), caller))
    assert field["status"] == "unavailable" and "value" not in field
    assert capture.capture_calls == []


def test_non_fra_caller_is_rejected_without_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    caller = dict(CONTEXT, observer="POR")
    with pytest.raises(InformationError):
        source.read(_query(), caller)
    assert capture.capture_calls == []


def test_base_context_wrong_observer_never_captures(monkeypatch):
    source, base, capture = _source(monkeypatch, base=Base(dict(CONTEXT, observer="POR")))
    field = _field(source.read(_query(), None))
    assert field["status"] == "unavailable" and "value" not in field
    assert capture.capture_calls == []
    assert base.context_calls >= 1


def test_context_change_during_capture_removes_value(monkeypatch):
    base = Base()
    capture = Capture()
    capture.on_capture = lambda: base.current.update(game_date=56556985)
    source, _base, capture = _source(monkeypatch, base=base, capture=capture)
    field = _field(source.read(_query(), CONTEXT))
    assert field["status"] == "unavailable" and "value" not in field
    assert capture.capture_calls == [(INSTALLATION, "ENG", "FRA")]


def test_session_binding_change_during_capture_removes_value(monkeypatch):
    from bridge.information import truce_dates as module

    base = Base()
    capture = Capture()
    capture.on_capture = lambda: setattr(base, "binding", (Path("C:/fixture/other/installation.json"), CREATION, None))
    monkeypatch.setattr(module, "_session_binding", lambda item: item.binding)
    source = NativeTruceDatesSource(base, capture_module=capture)
    field = _field(source.read(_query(), CONTEXT))
    assert field["status"] == "unavailable" and "value" not in field


def test_mixed_r03_composite_routes_existing_rivals_wars_and_truce_owners(monkeypatch):
    base = Base()
    capture = Capture()
    truce, _base, capture = _source(monkeypatch, base=base, capture=capture)

    class ScaleCatalog:
        def context(self):
            return deepcopy(CONTEXT)

        def catalog(self):
            return [{"topic_id": "F01", "fields": {"wars": {"coverage": "partial"}},
                     "supported_versions": ["1.37.4"]}]

        def validate_query(self, query, context=None):
            return deepcopy(query)

    rivals = NativeCountryRivalsSource(base)
    wars = NativeWarRelationsSource(ScaleCatalog())
    routed = {"rivals": [], "wars": []}

    def rivals_read(query, _context=None):
        routed["rivals"].append(deepcopy(query))
        return {"fields": {"rivals": {"status": "known", "value": ["BUR"], "complete": True}},
                "complete": True, "source": {"name": "NativeCountryRivalsSource"}}

    def wars_read(query, _context=None):
        routed["wars"].append(deepcopy(query))
        if query["object"]["type"] == "country_pair":
            return {"fields": {"wars": {"status": "unsupported",
                                          "reason": "WAR_RELATIONS_PAIR_VIEW_NOT_IMPLEMENTED"}},
                    "complete": False, "source": {"name": "NativeWarRelationsSource"}}
        return {"fields": {"wars": {"status": "known", "value": {"wars": []}, "complete": False}},
                "complete": False, "source": {"name": "NativeWarRelationsSource"}}

    rivals.read = rivals_read
    wars.read = wars_read

    class Primary:
        def catalog(self):
            return list_topics()

        def context(self):
            return deepcopy(CONTEXT)

    composite = CompositeSource(Primary(), [rivals, wars, truce])
    topic = next(item for item in composite.catalog() if item["topic_id"] == "R03")
    assert {"rivals", "wars", "truce_until"} <= set(topic["fields"])
    assert set(topic["adapter_sources"]) == {
        "NativeCountryRivalsSource", "NativeWarRelationsSource", "NativeTruceDatesSource"
    }

    country_query = {"topic": "R03", "object": {"type": "country", "country": "FRA"},
                     "fields": ["rivals", "wars", "truce_until"], "parameters": {}}
    country_result = composite.read(composite.validate_query(country_query), CONTEXT)
    assert country_result["fields"]["rivals"]["value"] == ["BUR"]
    assert country_result["fields"]["wars"]["status"] == "known"
    assert country_result["fields"]["truce_until"]["status"] == "not_applicable"
    assert len(routed["rivals"]) == len(routed["wars"]) == 1
    assert capture.capture_calls == []

    pair_query = _query(fields=["rivals", "wars", "truce_until"])
    pair_result = composite.read(composite.validate_query(pair_query), CONTEXT)
    assert pair_result["fields"]["rivals"]["status"] == "not_applicable"
    assert pair_result["fields"]["wars"]["status"] == "unsupported"
    assert pair_result["fields"]["truce_until"]["status"] == "known"
    assert len(routed["rivals"]) == 1 and len(routed["wars"]) == 2
    assert capture.capture_calls == [(INSTALLATION, "ENG", "FRA")]


def test_poll_events_remains_empty_and_does_not_capture(monkeypatch):
    source, _base, capture = _source(monkeypatch)
    cursor = {"offset": 5}
    result = source.poll_events(CONTEXT, cursor)
    assert result == {"events": [], "cursor": cursor, "complete": True, "gaps": []}
    assert capture.capture_calls == []

def test_default_live_factory_registers_truce_and_recorded_factory_excludes_it(tmp_path):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information.truce_dates import NativeTruceDatesSource

    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path / 'live.sqlite')])
    service, _ = _build_runtime(args)
    try:
        owners = [item for item in service.source.adapters if isinstance(item, NativeTruceDatesSource)]
        assert len(owners) == 1 and owners[0].base_source is service.source.primary
    finally:
        service.close()
    archive = tmp_path / 'recorded.json'
    archive.write_text('{}', encoding='utf-8')
    args = build_parser().parse_args(['--recorded-manifest', str(archive),
                                      '--database', str(tmp_path / 'recorded.sqlite')])
    service, _ = _build_runtime(args)
    try:
        assert type(service.source).__name__ == 'RecordedSource'
        assert not any(isinstance(item, NativeTruceDatesSource)
                       for item in getattr(service.source, 'adapters', ()))
    finally:
        service.close()

