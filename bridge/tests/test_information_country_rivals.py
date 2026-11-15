"""Public R03 projection tests; no process or native query is opened."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import country_rivals as m
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError


CONTEXT = {"status": "ready", "mode": "live", "session_id": "rivals-test-session",
           "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
           "game_version": "1.37.4", "observer": "FRA", "game_date": 56562768}


class Base:
    event_types = ()

    def __init__(self, directory):
        self.session = SimpleNamespace(directory=directory, creation_filetime=92,
                                       record={"session_id": CONTEXT["session_id"], "creation_filetime": 92})
        self.calls = 0
        self.after = {}

    def context(self):
        self.calls += 1
        return dict(CONTEXT, **(self.after if self.calls >= 3 else {}))

    def catalog(self):
        return [{"topic_id": "R03", "title": "R03", "status": "planned",
                 "fields": {"rivals": {"coverage": "planned"}, "truce_until": {"coverage": "planned"}},
                 "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                 "object_types": ["country", "country_pair"], "supported_versions": [], "triggers": ["query"]}]

    def read(self, *_args):
        raise AssertionError("No primary/native diplomacy query is allowed")


def query(fields=None):
    return {"topic": "R03", "object": {"type": "country", "country": "FRA"},
            "fields": fields or ["rivals"], "parameters": {}}


def source(tmp_path, monkeypatch, tags=None):
    field = {"status": "known", "value": [] if tags is None else tags,
             "private_nodes": [{"address": "0xdeadbeef", "id": 123}]}
    report = {"before": {"record": {"fields": {"rivals": field}}}, "private": {"head": "0xbeef"}}
    calls = []

    def capture(installation, country):
        calls.append((installation, country))
        return deepcopy(report)

    validator = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(m, "import_module", lambda *_args: validator)
    base = Base(tmp_path)
    return m.NativeCountryRivalsSource(base, capture=capture), base, calls, report, validator


@pytest.mark.parametrize("tags", [[], ["BUR", "ENG", "HAB"], ["C00"]])
def test_exact_outgoing_list_and_real_empty_are_complete(tmp_path, monkeypatch, tags):
    adapter, base, calls, _, _ = source(tmp_path, monkeypatch, tags)
    result = adapter.read(query(), base.context())
    field = result["fields"]["rivals"]
    assert field["value"] == tags and field["complete"] is True and result["complete"] is True
    assert field["direction"] == "outgoing_declared_by_country"
    assert field["unit"] == "country_tags" and field["scale"] == 1
    assert calls == [(tmp_path / "installation.json", "FRA")]
    assert "private_nodes" not in repr(result) and "0xdeadbeef" not in repr(result)
    assert result["source"]["provenance"]["native_function_invoked"] is False


@pytest.mark.parametrize("tags", [["ENG", "BUR"], ["ENG", "ENG"], ["FRA"], ["bad"], [1]])
def test_bad_public_members_are_retracted(tmp_path, monkeypatch, tags):
    adapter, base, _, _, _ = source(tmp_path, monkeypatch, tags)
    result = adapter.read(query(), base.context())
    assert result["fields"]["rivals"] == {"status": "unknown", "reason": "RIVALS_FIELD_INVALID"}
    assert result["complete"] is False


@pytest.mark.parametrize("mode", ["capture_error", "invalid_capture", "date_changed"])
def test_capture_and_context_failures_remain_unknown(tmp_path, monkeypatch, mode):
    adapter, base, _, _, validator = source(tmp_path, monkeypatch)
    if mode == "capture_error":
        def fail(*_args, **_kwargs):
            raise RuntimeError("private pointer must not escape")
        adapter.capture = fail
    elif mode == "invalid_capture":
        validator.validate_capture = lambda *_args: False
    else:
        base.after = {"game_date": CONTEXT["game_date"] + 1}
    result = adapter.read(query(), base.context())
    assert result["fields"]["rivals"]["status"] == "unknown" and result["complete"] is False
    assert "private pointer" not in repr(result)


def test_selectors_reject_foreign_pair_and_parameters_before_capture(tmp_path, monkeypatch):
    adapter, base, calls, _, _ = source(tmp_path, monkeypatch)
    for changes in ({"object": {"type": "country", "country": "ENG"}},
                    {"object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG"}},
                    {"parameters": {"recipient": "ENG"}}, {"fields": ["truce_until"]}):
        with pytest.raises(InformationError):
            adapter.read(dict(query(), **changes), base.context())
    assert calls == []


def test_composite_planned_fields_do_not_trigger_a_rival_capture(tmp_path, monkeypatch):
    adapter, base, calls, _, _ = source(tmp_path, monkeypatch)
    composite = CompositeSource(base, [adapter])
    planned = composite.validate_query(query(["truce_until"]))
    result = composite.read(planned, base.context())
    assert result["fields"]["truce_until"]["status"] == "unsupported" and not calls
    mixed = composite.validate_query(query(["rivals", "truce_until"]))
    result = composite.read(mixed, base.context())
    assert result["fields"]["rivals"]["status"] == "known"
    assert result["fields"]["truce_until"]["status"] == "unsupported"
    assert result["complete"] is False and len(calls) == 1


def test_factory_wires_live_rivals_only(monkeypatch, tmp_path):
    from tools import serve_information
    # Offline discovery constructs the same live adapter set without opening
    # an operator session. Using the real parser catches factory/API drift.
    args = serve_information.build_parser().parse_args(
        ["--database", str(tmp_path / "info.sqlite3"), "--observer", "FRA"])
    service, journal = serve_information._build_runtime(args)
    try:
        built = service.source
        topic = next(t for t in built.catalog() if t["topic_id"] == "R03")
        assert topic["fields"]["rivals"]["coverage"] == "available"
        assert topic["fields"]["truce_until"]["coverage"] == "partial"
        assert topic["fields"]["truce_until"]["complete"] is False
        assert topic["fields"]["truce_until"]["object_types"] == ["country_pair"]
        assert any(isinstance(a, m.NativeCountryRivalsSource) for a in built.adapters)
    finally:
        service.close()
        if journal is not None:
            journal.close()
