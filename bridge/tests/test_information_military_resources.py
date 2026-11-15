"""Synthetic adapter tests for the N02 military-resource projections.

These tests stop at the adapter seam.  The native memory reader has its own
contract tests; this module supplies a bounded report and a validator module
so no process, game, MCP, or diplomacy operation is involved.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import types

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.country_state import _parameter_schema
from bridge.information.military_resources import NativeMilitaryResourcesSource
from bridge.information.model import InformationError


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SESSION_ID = "session-military-resources-adapter"
CREATION_FILETIME = 134375854500787403
GAME_DATE = 56562768


class _Session:
    def __init__(self, directory: Path):
        self.directory = directory
        self.creation_filetime = CREATION_FILETIME
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
        }


class _Base:
    def __init__(self, directory: Path):
        self.session = _Session(directory)
        self.context_calls = 0
        self.after_context: dict | None = None

    def context(self) -> dict:
        self.context_calls += 1
        context = {
            "status": "ready",
            "complete": True,
            "mode": "live",
            "session_id": SESSION_ID,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": "FRA",
            "game_date": GAME_DATE,
            "game_date_raw": GAME_DATE,
        }
        if self.after_context is not None and self.context_calls >= 3:
            context.update(deepcopy(self.after_context))
        return context


def _raw_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False).hex()


def _sailors_field(raw: int = 2597984) -> dict:
    return {
        "status": "known",
        "raw": raw,
        "private_country_pointer": "0xdeadbeef",
        "private_cache_id": 991,
    }


def _force_limits_field(*, valid: bool = True) -> dict:
    land = {"value": 56, "raw": 56000, "unit": "regiments", "scale": 1000}
    naval = {"value": 25, "raw": 25000, "unit": "ships", "scale": 1000}
    if not valid:
        naval["raw"] = 25001
    return {
        "status": "partial",
        "value": {"land": land, "naval": naval},
        "private_processor_pointer": "0xcafebabe",
        "private_record_id": 77,
    }


def _report(*, sailors: dict | None = None, force_limits: dict | None = None) -> dict:
    fields = {
        "sailors": deepcopy(sailors if sailors is not None else _sailors_field()),
        "force_limits": deepcopy(
            force_limits if force_limits is not None else _force_limits_field()
        ),
    }
    return {
        "before": {"record": {"fields": fields}},
        "after": {"record": {"fields": deepcopy(fields)}},
    }


@pytest.fixture
def fake_memory_module(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[dict, dict, int, str]] = []
    module = types.ModuleType("bridge.information.military_resources_memory")

    def validate_capture(report, context, creation_filetime, country):
        calls.append((report, context, creation_filetime, country))
        return True

    module.validate_capture = validate_capture
    monkeypatch.setitem(
        sys.modules, "bridge.information.military_resources_memory", module
    )
    return calls


def _source(tmp_path: Path, report: dict | None = None):
    base = _Base(tmp_path)
    captures: list[tuple[Path, str]] = []
    chosen = deepcopy(report if report is not None else _report())

    def capture(installation, country):
        captures.append((installation, country))
        return deepcopy(chosen)

    return NativeMilitaryResourcesSource(base, capture=capture), base, captures


def _query(fields: list[str], parameters: dict | None = None, country: str = "FRA") -> dict:
    return {
        "topic": "N02",
        "object": {"type": "country", "country": country},
        "fields": fields,
        "parameters": {} if parameters is None else parameters,
    }


def test_catalog_exposes_only_resources_and_has_optional_recipient(
    fake_memory_module, tmp_path: Path
):
    source, base, _ = _source(tmp_path)
    item = source.catalog()[0]
    assert set(item["fields"]) == {"sailors", "force_limits"}
    assert item["parameters"] == _parameter_schema("N02")
    assert item["parameters"]["required"] == []
    assert source.validate_query(_query(["sailors"]), base.context())["parameters"] == {}
    assert source.validate_query(_query(["force_limits"]), base.context())["parameters"] == {}
    assert source.validate_query(
        _query(["force_limits"], {"reference_recipient": "PAP"}), base.context()
    )["parameters"] == {"reference_recipient": "PAP"}
    with pytest.raises(InformationError):
        source.validate_query(_query(["manpower"]), base.context())
    with pytest.raises(InformationError):
        source.validate_query(
            _query(["sailors"], {"reference_recipient": "FRA"}), base.context()
        )
    with pytest.raises(InformationError):
        source.validate_query(_query(["sailors"], {"unknown": "PAP"}), base.context())


def test_public_allowlist_projects_math_and_capture_contract(
    fake_memory_module, tmp_path: Path
):
    source, base, captures = _source(tmp_path)
    result = source.read(_query(["sailors", "force_limits"]), base.context())

    assert captures == [(tmp_path / "installation.json", "FRA")]
    assert len(fake_memory_module) == 1
    assert fake_memory_module[0][1]["observer"] == "FRA"
    assert fake_memory_module[0][2] == CREATION_FILETIME
    assert fake_memory_module[0][3] == "FRA"

    sailors = result["fields"]["sailors"]
    assert sailors == {
        "status": "known",
        "value": 2597984,
        "raw": 2597984,
        "raw_hex": _raw_hex(2597984),
        "display_value": 2597,
        "unit": "sailors",
        "scale": 1000,
        "period": "current",
        "basis": "native_country_sailors_reserve",
        "value_origin": "copied_native_cache",
        "complete": True,
        "partial": False,
    }
    force = result["fields"]["force_limits"]
    assert force["status"] == "known"
    assert force["value"] == {
        "land": {"value": 56, "raw": 56000, "unit": "regiments", "scale": 1000},
        "naval": {"value": 25, "raw": 25000, "unit": "ships", "scale": 1000},
    }
    assert force["complete"] is False and force["partial"] is True
    assert result["complete"] is False
    public_json = json.dumps(result, ensure_ascii=False)
    for private in (
        "private_country_pointer", "private_cache_id", "private_processor_pointer",
        "private_record_id", "0xdeadbeef", "0xcafebabe",
    ):
        assert private not in public_json


@pytest.mark.parametrize(
    ("raw", "display"),
    [
        (2597984, 2597),
        # The native float32 conversion rounds this boundary upward; integer
        # division alone would incorrectly produce 16777.
        (16777999, 16778),
        (0, 0),
        ((1 << 31) - 1, 2147483),
    ],
)
def test_sailors_display_uses_native_float32_boundary_behavior(
    fake_memory_module, tmp_path: Path, raw: int, display: int
):
    source, base, _ = _source(tmp_path, _report(sailors=_sailors_field(raw)))
    result = source.read(_query(["sailors"]), base.context())
    field = result["fields"]["sailors"]
    assert field["raw"] == raw
    assert field["display_value"] == display


def test_sailors_complete_even_when_force_limit_is_unknown(
    fake_memory_module, tmp_path: Path
):
    unknown_force = {
        "status": "unknown", "reason": "PROCESSOR_UNAVAILABLE", "private_ptr": "0x1"
    }
    source, base, _ = _source(tmp_path, _report(force_limits=unknown_force))
    sailors_only = source.read(_query(["sailors"]), base.context())
    both = source.read(_query(["sailors", "force_limits"]), base.context())
    assert sailors_only["fields"]["sailors"]["status"] == "known"
    assert sailors_only["complete"] is True
    assert both["fields"]["sailors"]["status"] == "known"
    assert both["fields"]["force_limits"] == {
        "status": "unknown", "reason": "PROCESSOR_UNAVAILABLE"
    }
    assert both["complete"] is False


def test_invalid_force_math_is_retracted_without_erasing_sailors(
    fake_memory_module, tmp_path: Path
):
    source, base, _ = _source(tmp_path, _report(force_limits=_force_limits_field(valid=False)))
    result = source.read(_query(["sailors", "force_limits"]), base.context())
    assert result["fields"]["sailors"]["status"] == "known"
    assert result["fields"]["force_limits"] == {
        "status": "unknown", "reason": "MILITARY_RESOURCES_FIELD_INVALID"
    }


def test_partial_native_force_record_preserves_unknown_processor_reason(
    fake_memory_module, tmp_path: Path
):
    force = _force_limits_field()
    force["value"]["land"] = {
        "status": "unknown", "reason": "DYNAMIC_FORCE_LIMIT_PROCESSOR_UNSUPPORTED"
    }
    source, base, _ = _source(tmp_path, _report(force_limits=force))
    result = source.read(_query(["sailors", "force_limits"]), base.context())
    assert result["fields"]["sailors"]["status"] == "known"
    assert result["fields"]["force_limits"] == {
        "status": "unknown", "reason": "DYNAMIC_FORCE_LIMIT_PROCESSOR_UNSUPPORTED"
    }


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("capture_error", "MILITARY_RESOURCES_CAPTURE_FAILED:RuntimeError"),
        ("validator_false", "MILITARY_RESOURCES_CAPTURE_INVALID"),
        ("context_changed", "MILITARY_RESOURCES_CONTEXT_CHANGED_DURING_CAPTURE"),
    ],
)
def test_bad_capture_or_context_retracts_all_requested_fields(
    fake_memory_module, tmp_path: Path, mode: str, expected: str
):
    source, base, _ = _source(tmp_path)
    if mode == "capture_error":
        def fail_capture(_installation, country):
            raise RuntimeError("synthetic")
        source.capture = fail_capture
    elif mode == "validator_false":
        fake_module = sys.modules["bridge.information.military_resources_memory"]
        fake_module.validate_capture = lambda *_args: False
    else:
        base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query(["sailors", "force_limits"]), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert expected in {item["reason"] for item in result["fields"].values()}
    assert result["complete"] is False


class _Primary:
    event_types = ()

    def __init__(self, base: _Base):
        self.base = base

    def context(self):
        return self.base.context()

    def catalog(self):
        return [{
            "topic_id": "N02",
            "fields": {"manpower": {"coverage": "available"}},
            "object_types": ["country"],
            "supported_versions": ["1.37.4"],
            "observer_roles": ["country"],
            "parameters": _parameter_schema("N02"),
        }]

    def poll_events(self, _context, cursor):
        return {"events": [], "cursor": cursor or {}, "complete": True, "gaps": []}


class _ManpowerOwner:
    def __init__(self):
        self.read_calls = 0

    def catalog(self):
        return [{
            "topic_id": "N02",
            "fields": {"manpower": {"coverage": "available"}},
            "parameters": _parameter_schema("N02"),
            "object_types": ["country"],
            "supported_versions": ["1.37.4"],
            "observer_roles": ["country"],
            "triggers": ["query", "periodic"],
            "context_scope": "country_scope",
        }]

    def validate_query(self, query, _context=None):
        if "manpower" in query["fields"] and "reference_recipient" not in query.get("parameters", {}):
            raise InformationError("invalid_parameters", "manpower requires reference_recipient")
        return deepcopy(query)

    def read(self, query, _context):
        self.read_calls += 1
        return {
            "query": deepcopy(query),
            "fields": {"manpower": {"status": "known", "value": 38705, "complete": True}},
            "complete": True,
            "source": {"name": type(self).__name__},
        }


def test_composite_requires_recipient_only_for_mixed_manpower_and_keeps_local_query_local(
    fake_memory_module, tmp_path: Path
):
    source, base, captures = _source(tmp_path)
    manpower = _ManpowerOwner()
    composite = CompositeSource(_Primary(base), [source, manpower])
    mixed = _query(["sailors", "force_limits", "manpower"])
    with pytest.raises(InformationError, match="manpower requires"):
        composite.validate_query(mixed)

    local = composite.validate_query(_query(["sailors"]))
    assert local["parameters"] == {}
    local_result = composite.read(local, base.context())
    assert local_result["fields"]["sailors"]["status"] == "known"
    assert manpower.read_calls == 0
    assert len(captures) == 1

    mixed["parameters"] = {"reference_recipient": "PAP"}
    normalized = composite.validate_query(mixed)
    mixed_result = composite.read(normalized, base.context())
    assert mixed_result["fields"]["manpower"]["value"] == 38705
    assert mixed_result["fields"]["sailors"]["status"] == "known"
    assert mixed_result["complete"] is False
    assert manpower.read_calls == 1


def test_sailors_and_max_sailors_use_normal_tools_without_recipient(
    fake_memory_module, tmp_path, monkeypatch
):
    from contextlib import closing
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information import own_resource_caches
    from bridge.information.service import InformationService
    from bridge.information.tools import InformationTools
    source, base, captures = _source(tmp_path)
    def max_cache(_base, query, context):
        assert query['fields'] == ['max_sailors']
        return {'fields': {'max_sailors': {'status': 'known', 'value': 12000000,
                                          'unit': 'sailors', 'scale': 1000}},
                'complete': True, 'source': {'name': 'OwnResourceCaches'}}
    monkeypatch.setattr(own_resource_caches, 'read', max_cache)
    from bridge.information.catalog import list_topics
    primary = _Primary(base)
    monkeypatch.setattr(primary, "catalog", list_topics)
    composite = CompositeSource(primary, [source, NativeCountryStateSource(base)])
    with closing(InformationService(composite, tmp_path / 'max-sailors.sqlite3')) as service:
        result = InformationTools(service).call('information_query', {
            'request_id': 'sailors-with-capacity', 'queries': [_query(['sailors', 'max_sailors'])]})
    assert result['items'] == [
        {'country': 'FRA', 'sailors': {'current': 2597.984, 'max': 12000}}]
    assert len(captures) == 1


def test_composite_adapter_order_and_disjoint_n02_routes(
    fake_memory_module, tmp_path: Path
):
    source, base, _ = _source(tmp_path)

    class _Forces:
        def catalog(self):
            return [{
                "topic_id": "N02",
                "fields": {"army_size": {"coverage": "partial"}},
                "parameters": _parameter_schema("N02"),
                "object_types": ["country"],
                "supported_versions": ["1.37.4"],
                "observer_roles": ["country"],
            }]

    composite = CompositeSource(_Primary(base), [_Forces(), source, _ManpowerOwner()])
    item = composite.catalog()[0]
    assert item["adapter_sources"] == ["_Forces", "NativeMilitaryResourcesSource", "_ManpowerOwner"]
    assert set(item["fields"]) == {"manpower", "army_size", "sailors", "force_limits"}
