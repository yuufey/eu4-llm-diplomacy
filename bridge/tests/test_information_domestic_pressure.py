"""Offline contract tests for the bounded N04 domestic-pressure adapter."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import domestic_pressure as domestic_module
from bridge.information.composite import CompositeSource
from bridge.information.domestic_pressure import NativeDomesticPressureSource
from bridge.information.model import InformationError


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_DATE = 56553384
CREATION_FILETIME = 134373102720165920
SESSION_ID = "37376-1dd639fff00a820"
FIELDS = ["stability", "war_exhaustion", "corruption"]
UNITS = {
    "stability": "stability",
    "war_exhaustion": "war_exhaustion",
    "corruption": "corruption",
}


class _Session:
    def __init__(self, directory: Path, *, creation: int = CREATION_FILETIME):
        self.directory = directory
        self.session_id = SESSION_ID
        self.creation_filetime = creation
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": creation,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": "FRA",
        }
        self.health_calls = 0
        self.after_context = None

    def health(self) -> dict:
        self.health_calls += 1
        result = {
            "status": "ready",
            "complete": True,
            "mode": "live",
            "session_id": SESSION_ID,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": "FRA",
            "game_date": GAME_DATE,
            "game_date_raw": GAME_DATE,
            "world_id": "world-1",
        }
        if self.after_context is not None and self.health_calls >= 2:
            result.update(deepcopy(self.after_context))
        return result


class _Base:
    def __init__(self, session: _Session | None):
        self.session = session
        self.inspect_called = False

    def context(self) -> dict:
        if self.session is None:
            return {
                "status": "ready", "complete": True, "mode": "live",
                "session_id": SESSION_ID, "game_sha256": GAME_SHA256,
                "game_version": "1.37.4", "observer": "FRA",
                "game_date": GAME_DATE, "game_date_raw": GAME_DATE,
            }
        return self.session.health()

    def inspect_diplomatic_action(self, *args, **kwargs):
        self.inspect_called = True
        raise AssertionError("N04 must not call public diplomacy inspection")


class _PlannedN04Seed:
    """The global catalog's planned N04 seed, kept to test composite gaps."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base: _Base):
        self.base = base

    def context(self) -> dict:
        return self.base.context()

    def catalog(self) -> list[dict]:
        return [{
            "topic_id": "N04",
            "catalog_ids": ["N04"],
            "title": "本国国内压力（规划种子）",
            "status": "planned",
            "fields": {
                field: {"coverage": "planned", "source": "catalog"}
                for field in [*FIELDS, "religious_unity", "overextension", "unrest"]
            },
            "object_types": ["country"],
            "observer_roles": ["country"],
            "observer_scope": ["FRA"],
            "parameters": {
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": False,
            },
            "supported_versions": ["1.37.4"],
            "triggers": ["query", "periodic", "change"],
            "context_scope": "country_scope",
            "visibility": "country_scope",
        }]

    def validate_query(self, query: dict) -> dict:
        return deepcopy(query)

    def read(self, query: dict, context: dict) -> dict:
        raise AssertionError("planned N04 seed must not read directly")

    def poll_events(self, context: dict, cursor):
        return {"events": [], "cursor": cursor, "complete": True, "gaps": []}


def _raw_hex(value: int) -> str:
    return value.to_bytes(4, "little", signed=True).hex()


def _report(session: _Session, *, values: dict[str, int] | None = None) -> dict:
    values = values or {
        "stability": 0,
        "war_exhaustion": -1250,
        "corruption": 320,
    }
    field_results = {
        field: {
            "status": "known",
            "raw": values[field],
            "raw_hex": _raw_hex(values[field]),
            "unit": UNITS[field],
            "scale": 1000,
        }
        for field in FIELDS
    }
    date_hex = _raw_hex(GAME_DATE)
    snapshot = {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": date_hex},
        "field_results": deepcopy(field_results),
    }
    return {
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": "FRA",
        "target_build": {"version": "1.37.4", "expected_exe_sha256": GAME_SHA256},
        "identity": {
            "binding_verified": True,
            "process_path_sha256": GAME_SHA256,
            "process_path_sha256_matches_expected": True,
            "installation_session_id": session.session_id,
            "installation_creation_filetime": session.record["creation_filetime"],
            "process_creation_filetime": session.record["creation_filetime"],
            "process_creation_matches_installation": True,
        },
        "static_contract_guard": {"status": "observed", "checks": {"profile": True}},
        "file_code_guard": {"status": "observed", "checks": {"file": True}},
        "runtime_code_guard": {"status": "observed", "checks": {"runtime": True}},
        "doublepass": {"performed": True, "consistent": True, "mismatches": []},
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": snapshot,
        "after": deepcopy(snapshot),
        "field_results": field_results,
        "values": deepcopy(values),
        "completed": True,
        "profile": {
            "path": "domestic-pressure-memory-1374.json",
            "sha256": getattr(
                __import__("bridge.information.domestic_pressure_memory", fromlist=["EXPECTED_PROFILE_SHA256"]),
                "EXPECTED_PROFILE_SHA256", "0" * 64,
            ),
            "max_bytes": 65536,
        },
        "probe_script_sha256": "b" * 64,
        "access": {"rpm_bytes_requested": 4096, "rpm_calls": 12},
    }


def _query(fields: list[str] | None = None, *, country: str = "FRA", parameters=None) -> dict:
    return {
        "topic": "N04",
        "object": {"type": "country", "country": country},
        "fields": FIELDS[:] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def _source(tmp_path: Path, *, report=None, session: _Session | None = None):
    session = session or _Session(tmp_path)
    base = _Base(session)
    calls = []

    def capture(installation, country, fields):
        calls.append((installation, country, list(fields)))
        if callable(report):
            return report(session)
        return deepcopy(report if report is not None else _report(session))

    return NativeDomesticPressureSource(base, capture=capture), base, session, calls


def test_catalog_exposes_pressure_fields_in_the_current_observer_scope(tmp_path: Path) -> None:
    source, _, _, _ = _source(tmp_path)
    topic = source.catalog()[0]
    assert topic["topic_id"] == "N04"
    assert topic["status"] == "available"
    assert list(topic["fields"]) == [*FIELDS, "religious_unity", "overextension", "unrest"]
    assert all(topic["fields"][field]["coverage"] == "available" for field in FIELDS)
    assert all(topic["fields"][field]["runtime_validation"] == "validated" for field in FIELDS)
    assert topic["observer_roles"] == ["country"]
    assert topic["observer_scope"] == []
    assert topic["supported_versions"] == ["1.37.4"]
    assert [topic["fields"][field]["unit"] for field in FIELDS] == [
        "stability", "war_exhaustion", "corruption"
    ]
    assert all(topic["fields"][field]["scale"] == 1000 for field in FIELDS)
    unity = topic["fields"]["religious_unity"]
    assert unity["coverage"] == "partial"
    assert unity["runtime_validation"] == "normal_cache_without_processors_observed"
    assert unity["unit"] == "fraction"
    assert unity["scale"] == 1000
    assert unity["value_origin"] == "derived_from_copied_native_inputs"
    assert unity["upper_clamp"] is False
    overextension = topic["fields"]["overextension"]
    assert overextension["coverage"] == "available"
    assert overextension["unit"] == "fraction"
    assert overextension["scale"] == 1000
    unrest = topic["fields"]["unrest"]
    assert unrest["coverage"] == "available"
    assert unrest["runtime_validation"] == "validated"
    assert unrest["unit"] == "unrest"
    assert unrest["scale"] == 1000
    assert topic["triggers"] == ["query", "periodic", "change"]
    assert topic["runtime_validation"] == "validated"
    assert "暂停时周期读取已实机核验" in topic["scope_note"]
    assert "不保证主线程原子快照" in topic["scope_note"]
    assert source.validate_query(_query(["religious_unity"]))["fields"] == ["religious_unity"]


def test_religious_unity_is_routed_to_the_partial_native_adapter_in_composite_query(tmp_path: Path) -> None:
    adapter, base, _, calls = _source(tmp_path)
    composite = CompositeSource(_PlannedN04Seed(base), [adapter])

    merged_topic = composite.catalog()[0]
    assert merged_topic["fields"]["religious_unity"]["coverage"] == "partial"
    assert adapter.catalog()[0]["fields"]["religious_unity"]["unit"] == "fraction"

    query = _query(["stability", "religious_unity"])
    normalized = composite.validate_query(query)
    assert normalized["fields"] == ["stability", "religious_unity"]
    result = composite.read(query, base.context())
    assert result["fields"]["stability"]["status"] == "known"
    assert result["fields"]["religious_unity"] == {
        "status": "unknown", "reason": "DOMESTIC_PRESSURE_FIELD_MISSING"
    }
    assert result["complete"] is False
    assert calls == [(tmp_path / "installation.json", "FRA", ["stability", "religious_unity"])]


def test_known_zero_negative_and_raw_hex_are_preserved(tmp_path: Path) -> None:
    def report(session):
        value = _report(session)
        value["file_code_guard"]["checks"].update(
            expected_hex="aabb", actual_hex="aabb", read_log=[{"raw_hex": "deadbeef"}]
        )
        return value

    source, base, session, calls = _source(tmp_path, report=report)
    result = source.read(_query(["stability", "war_exhaustion"]), base.context())
    assert result["fields"]["stability"]["status"] == "known"
    assert result["fields"]["stability"]["value"] == 0
    assert result["fields"]["stability"]["raw_hex"] == "00000000"
    assert result["fields"]["war_exhaustion"]["value"] == -1250
    assert result["fields"]["war_exhaustion"]["raw_hex"] == _raw_hex(-1250)
    assert result["complete"] is True
    assert calls == [(tmp_path / "installation.json", "FRA", ["stability", "war_exhaustion"])]
    assert base.inspect_called is False
    assert result["source"]["provenance"]["capture_report_hash_algorithm"].startswith("sha256(")
    audit_text = str(result["source"]["provenance"]["capture"])
    assert "expected_hex" not in audit_text
    assert "read_log" not in audit_text


@pytest.mark.parametrize(
    "bad_query",
    [
        _query(country="ENG"),
        _query(parameters={"recipient": "PAP"}),
        _query(["field_that_is_not_in_n04"]),
        dict(_query(), object={"type": "country", "country": "FRA", "session_id": "x"}),
    ],
)
def test_scope_and_parameters_are_strict(tmp_path: Path, bad_query: dict) -> None:
    source, base, _, calls = _source(tmp_path)
    with pytest.raises(InformationError):
        source.validate_query(bad_query, base.context())
    assert calls == []


def test_bad_one_field_preserves_other_known_fields(tmp_path: Path) -> None:
    def report(session):
        value = _report(session)
        value["field_results"]["corruption"] = {"status": "unknown", "reason": "NATIVE_FIELD_UNAVAILABLE"}
        value["values"].pop("corruption")
        value["complete"] = False
        return value

    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(), base.context())
    assert result["fields"]["stability"]["status"] == "known"
    assert result["fields"]["stability"]["value"] == 0
    assert result["fields"]["corruption"] == {
        "status": "unknown", "reason": "NATIVE_FIELD_UNAVAILABLE"
    }
    assert result["complete"] is False


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda r: r["runtime_code_guard"].update(status="unknown"), "GUARD"),
        (lambda r: r["cleanup"]["handle_close"].update(status="error", closed=False), "CLEANUP"),
        (lambda r: r["identity"].update(binding_verified=False), "IDENTITY"),
        (lambda r: r["before"]["game_date"].update(value=GAME_DATE + 1), "DATE"),
        (lambda r: r["doublepass"].update(consistent=False), "DOUBLEPASS"),
    ],
)
def test_global_contract_failure_retracts_all_fields(tmp_path: Path, mutation, reason: str) -> None:
    def report(session):
        value = _report(session)
        mutation(value)
        return value

    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(["stability", "corruption"]), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert all(reason in item["reason"] for item in result["fields"].values())
    assert result["complete"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["field_results"]["stability"].update(raw=True),
        lambda r: r["field_results"]["war_exhaustion"].update(raw_hex="00000001"),
        lambda r: r["field_results"]["corruption"].update(unit="ducats"),
        lambda r: r["field_results"]["corruption"].update(scale=1),
    ],
)
def test_bad_scalar_or_unit_is_field_unknown_only(tmp_path: Path, mutation) -> None:
    def report(session):
        value = _report(session)
        mutation(value)
        return value

    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(), base.context())
    bad_field = next(field for field in FIELDS if result["fields"][field]["status"] == "unknown")
    assert result["fields"][bad_field]["status"] == "unknown"
    assert sum(item["status"] == "known" for item in result["fields"].values()) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["field_results"]["stability"].pop("unit"),
        lambda r: r["field_results"]["war_exhaustion"].pop("scale"),
        lambda r: r["before"]["field_results"]["corruption"].update(raw=321),
        lambda r: r["after"]["field_results"]["corruption"].update(scale=1),
        lambda r: r["after"]["field_results"]["stability"].pop("raw_hex"),
    ],
)
def test_missing_or_changed_snapshot_metadata_is_field_local(tmp_path: Path, mutation) -> None:
    def report(session):
        value = _report(session)
        mutation(value)
        return value

    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(), base.context())
    assert sum(item["status"] == "known" for item in result["fields"].values()) == 2
    assert sum(item["status"] == "unknown" for item in result["fields"].values()) == 1


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda r: r["doublepass"].update(mismatches=["$.after.field_results.stability"]), "DOUBLEPASS"),
        (lambda r: r["access"].update(target_memory_writes=True), "READ_ONLY"),
        (lambda r: r["access"].update(native_game_calls=True), "READ_ONLY"),
        (lambda r: r["access"].update(dll_injection=True), "READ_ONLY"),
    ],
)
def test_global_report_rejects_mismatch_or_unsafe_access(tmp_path: Path, mutation, reason: str) -> None:
    def report(session):
        value = _report(session)
        mutation(value)
        return value

    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(["stability", "corruption"]), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert all(reason in item["reason"] for item in result["fields"].values())


def test_profile_sha_is_checked_when_reader_has_a_real_pin(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(domestic_module, "_reader_profile_pin", lambda: "c" * 64)

    def report(session):
        value = _report(session)
        value["profile"]["sha256"] = "d" * 64
        return value

    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(["stability"]), base.context())
    assert result["fields"]["stability"]["status"] == "unknown"
    assert "PROFILE_SHA" in result["fields"]["stability"]["reason"]


def test_missing_session_is_unavailable_and_does_not_invoke_capture(tmp_path: Path) -> None:
    base = _Base(None)
    calls = []
    source = NativeDomesticPressureSource(base, capture=lambda *args: calls.append(args))
    result = source.read(_query(), base.context())
    assert all(item["status"] == "unavailable" for item in result["fields"].values())
    assert all("SESSION" in item["reason"] for item in result["fields"].values())
    assert calls == []


def test_recorded_context_is_rejected_without_fallback(tmp_path: Path) -> None:
    source, base, _, calls = _source(tmp_path)
    context = base.context()
    context.update(mode="recorded")
    result = source.read(_query(["stability"]), context)
    assert result["fields"]["stability"]["status"] == "unavailable"
    assert "LIVE" in result["fields"]["stability"]["reason"]
    assert calls == []


def test_context_change_after_capture_retracts_all_fields(tmp_path: Path) -> None:
    session = _Session(tmp_path)
    session.after_context = {"game_date": GAME_DATE + 24, "game_date_raw": GAME_DATE + 24}
    source, base, _, calls = _source(tmp_path, session=session)
    stable_context = {
        "status": "ready", "complete": True, "mode": "live", "session_id": SESSION_ID,
        "game_sha256": GAME_SHA256, "game_version": "1.37.4", "observer": "FRA",
        "game_date": GAME_DATE, "game_date_raw": GAME_DATE, "world_id": "world-1",
    }
    result = source.read(_query(["stability", "corruption"]), stable_context)
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert all("CONTEXT_CHANGED" in item["reason"] or "GAME_DATE" in item["reason"] for item in result["fields"].values())
    assert calls == [] or len(calls) == 1


def test_capture_receives_only_derived_installation_and_requested_fields(tmp_path: Path) -> None:
    source, base, _, calls = _source(tmp_path)
    context = base.context()
    result = source.read(_query(["corruption"]), context)
    assert result["fields"]["corruption"]["unit"] == "corruption"
    assert calls == [(tmp_path / "installation.json", "FRA", ["corruption"])]
    assert base.inspect_called is False
