"""Date-scope regressions for the two N02 military information sources."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import country_forces, country_forces_memory
from bridge.information import military_resources, military_resources_memory
from bridge.information.observation_time import sampled_read


_ADAPTERS = ("country_forces", "military_resources")


def _context(game_date: int, *, session_id: str = "military-observation-session") -> dict:
    return {
        "status": "ready", "complete": True, "mode": "live",
        "session_id": session_id,
        "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        "game_version": "1.37.4", "observer": "FRA", "game_date": game_date,
        "game_date_raw": game_date, "game_day": game_date // 24,
    }


def _query(adapter: str) -> dict:
    field = "army_size" if adapter == "country_forces" else "sailors"
    return {"topic": "N02", "object": {"type": "country", "country": "FRA"},
            "fields": [field], "parameters": {}}


def _record(adapter: str, game_date: int) -> dict:
    if adapter == "country_forces":
        return {
            "status": "observed", "game_date": {"value": game_date, "raw_hex": f"{game_date:08x}"},
            "records": [{"type_kind": 0, "strength_raw": 950}],
        }
    return {
        "status": "observed", "fields": {"sailors": {"raw": 1000}},
        "private": {
            "game_date": {"value": game_date, "raw_hex": f"{game_date:08x}"},
            "force": {"cached_value": 7, "read_log": [
                {"label": "military_resources.game_date", "address": "0x1000"},
                {"label": "military_resources.modifier_value", "address": "0x2000"},
            ]},
        },
    }


def _make_source(adapter: str, monkeypatch: pytest.MonkeyPatch,
                 contexts: list[dict]):
    source_module = country_forces if adapter == "country_forces" else military_resources
    memory_module = country_forces_memory if adapter == "country_forces" else military_resources_memory
    if adapter == "country_forces":
        first_record, second_record = {"records": []}, {"records": []}
    else:
        fields = {"sailors": {"status": "known", "raw": 1000}}
        first_record, second_record = {"fields": deepcopy(fields)}, {"fields": deepcopy(fields)}
    chosen_report = {
        "before": {"status": "observed", "game_date": {"value": 102},
                   "record": first_record},
        "after": {"status": "observed", "game_date": {"value": 103},
                  "record": second_record},
    }

    class Base:
        def __init__(self):
            self.session = SimpleNamespace(directory=Path("unused"), record={})
            # `read` receives the query-start anchor as its context argument;
            # this sequence is for the subsequent pre/post heartbeat checks.
            self.context_index = 1

        def context(self):
            index = min(self.context_index, len(contexts) - 1)
            self.context_index += 1
            return deepcopy(contexts[index])

    def capture(*_args, **_kwargs):
        return deepcopy(chosen_report)

    monkeypatch.setattr(source_module, "_context_reason", lambda _context: None)
    monkeypatch.setattr(source_module, "_session_binding",
                        lambda _base: (Path("unused/installation.json"), 1, None))
    monkeypatch.setattr(source_module, "import_module",
                        lambda *_args: SimpleNamespace(validate_capture=lambda *_args: True))
    source_type = (country_forces.NativeCountryForcesSource
                   if adapter == "country_forces" else
                   military_resources.NativeMilitaryResourcesSource)
    source = source_type(Base(), capture=capture)
    return source, chosen_report, memory_module


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_active_macro_scope_accepts_forward_dates_without_hiding_business_values(
        adapter: str, monkeypatch: pytest.MonkeyPatch) -> None:
    contexts = [_context(100), _context(100), _context(101)]
    source, report, memory_module = _make_source(adapter, monkeypatch, contexts)
    query = _query(adapter)

    with sampled_read(query, contexts[0]):
        result = source.read(query, contexts[0])
        before = _record(adapter, 100)
        after = _record(adapter, 101)
        stable_before = memory_module._stable_record_for_comparison(before)
        stable_after = memory_module._stable_record_for_comparison(after)

    assert result["fields"][query["fields"][0]]["status"] == "known"
    # The post-capture heartbeat may lag behind the two-pass RPM sample.
    assert contexts[-1]["game_date"] < report["after"]["game_date"]["value"]
    assert memory_module._diff_paths(stable_before, stable_after) == []
    if adapter == "country_forces":
        changed = _record(adapter, 101)
        changed["records"][0]["strength_raw"] = 951
    else:
        changed = _record(adapter, 101)
        changed["private"]["force"]["cached_value"] = 8
    assert memory_module._diff_paths(
        stable_before, memory_module._stable_record_for_comparison(changed))
    if adapter == "military_resources":
        assert [row["label"] for row in stable_after["force"]["read_log"]] == [
            "military_resources.modifier_value"]
        assert len(after["private"]["force"]["read_log"]) == 2


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_without_macro_scope_keeps_date_comparison_strict(
        adapter: str, monkeypatch: pytest.MonkeyPatch) -> None:
    contexts = [_context(100), _context(100), _context(101)]
    source, _report, memory_module = _make_source(adapter, monkeypatch, contexts)
    query = _query(adapter)
    result = source.read(query, contexts[0])

    assert result["fields"][query["fields"][0]]["status"] != "known"
    assert memory_module._diff_paths(
        memory_module._stable_record_for_comparison(_record(adapter, 100)),
        memory_module._stable_record_for_comparison(_record(adapter, 101)))


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_active_macro_scope_rejects_backwards_dates(
        adapter: str, monkeypatch: pytest.MonkeyPatch) -> None:
    contexts = [_context(100), _context(100), _context(99)]
    source, _report, _memory_module = _make_source(adapter, monkeypatch, contexts)
    query = _query(adapter)

    with sampled_read(query, contexts[0]):
        result = source.read(query, contexts[0])

    assert result["fields"][query["fields"][0]]["status"] != "known"


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_active_macro_scope_still_rejects_identity_changes(
        adapter: str, monkeypatch: pytest.MonkeyPatch) -> None:
    contexts = [_context(100), _context(100), _context(101, session_id="other-session")]
    source, _report, _memory_module = _make_source(adapter, monkeypatch, contexts)
    query = _query(adapter)

    with sampled_read(query, contexts[0]):
        result = source.read(query, contexts[0])

    assert result["fields"][query["fields"][0]]["status"] != "known"
