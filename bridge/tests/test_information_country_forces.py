"""Focused N02 country-forces adapter and routing contracts.

The captures in this file are deliberately synthetic adapter-seam reports.  They
exercise the public projection and its rejection boundaries without claiming a
new native or live observation.  The memory reader's strict report validator is
owned by the country-forces memory work and is kept replaceable here so these
tests can isolate the information adapter.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.composite import CompositeSource
from bridge.information.country_forces import NativeCountryForcesSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.tools import InformationTools
import bridge.information.country_forces as country_forces
from bridge.information.sources import DiplomacySource


GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
SESSION_ID = "country-forces-test-session"
CREATION_FILETIME = 134375854500787403
GAME_DATE = 56562768


class _Session:
    observer = "FRA"

    def __init__(self, directory: Path, *, change_at: int | None = None):
        self.directory = directory
        self.session_id = SESSION_ID
        self.creation_filetime = CREATION_FILETIME
        self.change_at = change_at
        self.health_calls = 0
        self.record = {
            "observer": "FRA",
            "controlled_countries": ["FRA"],
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
        }

    def health(self) -> dict:
        self.health_calls += 1
        date = GAME_DATE + 1 if self.change_at and self.health_calls >= self.change_at else GAME_DATE
        return {
            "status": "ready",
            "complete": True,
            "date_raw": date,
            "game_date": date,
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA256,
            "observer": "FRA",
            "game_day": date // 24,
            "world_id": "country-forces-world",
            "reasons": [],
        }


class _Tools:
    def __init__(self, session: _Session):
        self.session = session
        self.inspect_calls: list[tuple] = []

    def inspect_diplomatic_action(self, *args, **kwargs):
        self.inspect_calls.append((args, kwargs))
        raise AssertionError("N02 forces-only reads must not inspect diplomacy")


def _base(tmp_path: Path, *, change_at: int | None = None):
    session = _Session(tmp_path, change_at=change_at)
    tools = _Tools(session)
    return DiplomacySource(tools, observer="FRA"), session, tools


def _rows() -> list[dict]:
    return [
        {"id_type": 55, "id": 1001, "type_kind": 0, "strength_raw": 981},
        {"id_type": 55, "id": 1002, "type_kind": 1, "strength_raw": 995},
        {"id_type": 55, "id": 1003, "type_kind": 2, "strength_raw": 500},
        {"id_type": 55, "id": 2001, "type_kind": 3, "strength_raw": 800},
        {"id_type": 55, "id": 2002, "type_kind": 4, "strength_raw": 670},
        {"id_type": 55, "id": 2003, "type_kind": 6, "strength_raw": 930},
    ]


def _report(rows: list[dict] | None = None) -> dict:
    records = deepcopy(_rows() if rows is None else rows)
    return {
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": "FRA",
        "completed": True,
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": {"record": {"records": records}},
        "after": {"record": {"records": deepcopy(records)}},
    }


def _query(fields: list[str], parameters: dict | None = None) -> dict:
    return {
        "topic": "N02",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": {} if parameters is None else dict(parameters),
    }


def _install_validator(monkeypatch: pytest.MonkeyPatch, calls: list,
                       *, accept: bool = True):
    def validate_capture(report, before, creation, country):
        calls.append((deepcopy(report), deepcopy(before), creation, country))
        if not accept:
            return False
        handle_close = report.get("cleanup", {}).get("handle_close", {})
        return (
            report.get("status") == "observed"
            and report.get("read_only") is True
            and report.get("native_function_invoked") is False
            and report.get("country") == country
            and handle_close.get("status") == "closed"
        )

    module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(country_forces, "import_module", lambda *_args: module)
    return module


def _source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, report=None,
            change_at: int | None = None, accept: bool = True):
    base, session, tools = _base(tmp_path, change_at=change_at)
    calls: list = []
    _install_validator(monkeypatch, calls, accept=accept)
    chosen = deepcopy(_report() if report is None else report)

    def capture(_installation, *, country):
        assert country == "FRA"
        return deepcopy(chosen)

    source = NativeCountryForcesSource(base, capture=capture)
    return source, base, session, tools, calls


class _LiteralNames:
    def __init__(self):
        self.calls = []

    def localized_text(self, country, context, keys):
        self.calls.append((country, context, keys))
        return {"status": "known", "language": "l_french",
                "entries": {key: {"status": "known", "text": "Nom " + key} for key in keys},
                "provenance": {"doublepass_consistent": True}}


def test_catalog_is_partial_and_has_explicit_units_and_schema(tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch):
    source, _, _, _, _ = _source(tmp_path, monkeypatch)
    entry = source.catalog()[0]
    assert entry["topic_id"] == "N02"
    assert set(entry["fields"]) == {
        "army_size", "navy_size", "army_composition", "navy_composition",
    }
    assert entry["parameters"]["required"] == []
    assert entry["triggers"] == ["query", "periodic"]
    for field in entry["fields"].values():
        assert field["coverage"] == "partial"
        assert field["complete"] is False
        assert field["triggers"] == ["query", "periodic"]
    assert entry["fields"]["army_size"]["unit"] == "regiments"
    assert entry["fields"]["army_size"]["scale"] == 1
    assert entry["fields"]["navy_size"]["unit"] == "ships"
    assert entry["fields"]["navy_size"]["scale"] == 1


def test_valid_capture_projects_counts_strength_and_redacts_private_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    source, _, _, tools, calls = _source(tmp_path, monkeypatch)
    result = source.read(_query([
        "army_size", "navy_size", "army_composition", "navy_composition",
    ]))

    assert result["complete"] is False
    fields = result["fields"]
    assert all(value["status"] == "known" for value in fields.values())
    assert fields["army_size"]["value"] == 3
    assert fields["army_size"]["unit"] == "regiments"
    assert fields["army_size"]["strength"] == {
        "raw": 2476, "scale": 1000, "unit": "serialized_regiment_strength",
    }
    assert fields["navy_size"]["value"] == 3
    assert fields["navy_size"]["unit"] == "ships"
    assert fields["navy_size"]["strength"] == {
        "raw": 2400, "scale": 1000, "unit": "serialized_ship_strength",
    }
    assert all(field["partial"] is True and field["complete"] is False
               for field in fields.values())
    assert result["source"]["projection_version"] == 4

    army = fields["army_composition"]["value"]
    navy = fields["navy_composition"]["value"]
    assert result["source"]["context_scope"] == "country_scope"
    assert [row["native_kind"] for row in army] == [0, 1, 2]
    assert [row["count"] for row in army] == [1, 1, 1]
    assert [row["native_kind"] for row in navy] == [3, 4, 5, 6]
    assert [row["count"] for row in navy] == [1, 1, 0, 1]
    kind5 = next(row for row in navy if row["native_kind"] == 5)
    assert kind5["category"] == "galley"
    assert kind5["category_name_status"] == "known"
    assert kind5["count"] == 0
    assert calls and calls[0][2:] == (CREATION_FILETIME, "FRA")
    assert tools.inspect_calls == []

    public_text = json.dumps(result, ensure_ascii=False)
    for private_key in ("id_type", "record_pointer", "record_pointer_private", "raw_body"):
        assert private_key not in public_text


def test_composition_exposes_sorted_strengths_with_duplicates_zeros_and_empty_categories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    rows = [
        {"id_type": 55, "id": 1_700_000_001, "type_kind": 0, "strength_raw": 500},
        {"id_type": 55, "id": 1_700_000_002, "type_kind": 0, "strength_raw": 0},
        {"id_type": 55, "id": 1_700_000_003, "type_kind": 0, "strength_raw": 500},
        {"id_type": 55, "id": 1_700_000_004, "type_kind": 1, "strength_raw": 1000},
        {"id_type": 55, "id": 1_700_000_005, "type_kind": 2, "strength_raw": 0},
        {"id_type": 55, "id": 1_700_000_006, "type_kind": 3, "strength_raw": 900},
        {"id_type": 55, "id": 1_700_000_007, "type_kind": 3, "strength_raw": 0},
        {"id_type": 55, "id": 1_700_000_008, "type_kind": 4, "strength_raw": 1200},
        {"id_type": 55, "id": 1_700_000_009, "type_kind": 6, "strength_raw": 1200},
    ]
    source, _, _, _, _ = _source(
        tmp_path, monkeypatch, report=_report(rows),
    )
    result = source.read(_query([
        "army_size", "navy_size", "army_composition", "navy_composition",
    ]))
    fields = result["fields"]
    army = fields["army_composition"]["value"]
    navy = fields["navy_composition"]["value"]

    # Existing count and aggregate-strength meanings remain intact.
    assert fields["army_size"]["value"] == 5
    assert fields["army_size"]["strength"]["raw"] == 2000
    assert fields["navy_size"]["value"] == 4
    assert fields["navy_size"]["strength"]["raw"] == 3300
    assert [row["count"] for row in army] == [3, 1, 1]
    assert [row["strength"]["raw"] for row in army] == [1000, 1000, 0]
    # kind 2 is labeled only as the third country-forces count bucket.
    assert army[2]["category"] == "artillery"
    assert army[2]["category_name_status"] == "known"
    assert [row["count"] for row in navy] == [2, 1, 0, 1]
    assert [row["strength"]["raw"] for row in navy] == [900, 1200, 0, 1200]
    assert navy[2]["category"] == "galley"
    assert navy[2]["category_name_status"] == "known"

    expected = {
        0: ([0, 500, 500], "serialized_regiment_strength"),
        1: ([1000], "serialized_regiment_strength"),
        2: ([0], "serialized_regiment_strength"),
        3: ([0, 900], "serialized_ship_strength"),
        4: ([1200], "serialized_ship_strength"),
        5: ([], "serialized_ship_strength"),
        6: ([1200], "serialized_ship_strength"),
    }
    for row in army + navy:
        raw_values, unit = expected[row["native_kind"]]
        assert row["record_strengths"] == {
            "raw_values": raw_values,
            "scale": 1000,
            "unit": unit,
            "ordering": "ascending_strength",
            "identity_scope": "anonymous_records_current_capture",
        }
        assert set(row) == {
            "category", "native_kind", "category_name_status", "count",
            "count_unit", "strength", "record_strengths", "unit_types",
        }

    public_text = json.dumps(result, ensure_ascii=False)
    for row in rows:
        assert str(row["id"]) not in public_text
    for private_key in ("id_type", "record_pointer", "record_pointer_private",
                        "raw_body", "record_index", "group_index"):
        assert private_key not in public_text


def test_empty_capture_projects_empty_record_strength_lists_and_zero_aggregates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    source, _, _, _, _ = _source(tmp_path, monkeypatch, report=_report([]))
    result = source.read(_query([
        "army_size", "navy_size", "army_composition", "navy_composition",
    ]))
    fields = result["fields"]

    for field in ("army_size", "navy_size"):
        assert fields[field]["value"] == 0
        assert fields[field]["strength"]["raw"] == 0
    for field in ("army_composition", "navy_composition"):
        for row in fields[field]["value"]:
            assert row["count"] == 0
            assert row["strength"]["raw"] == 0
            assert row["record_strengths"]["raw_values"] == []


def test_record_strength_distribution_distinguishes_equal_aggregates_and_ignores_input_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    first = [
        {"id_type": 55, "id": 201, "type_kind": 0, "strength_raw": 100},
        {"id_type": 55, "id": 202, "type_kind": 0, "strength_raw": 900},
        {"id_type": 55, "id": 203, "type_kind": 1, "strength_raw": 200},
    ]
    same_aggregate_different_distribution = [
        {"id_type": 55, "id": 301, "type_kind": 0, "strength_raw": 400},
        {"id_type": 55, "id": 302, "type_kind": 0, "strength_raw": 600},
        {"id_type": 55, "id": 303, "type_kind": 1, "strength_raw": 200},
    ]
    query = _query(["army_size", "army_composition"])
    first_source, *_ = _source(tmp_path / "first", monkeypatch, report=_report(first))
    alternate_source, *_ = _source(
        tmp_path / "alternate", monkeypatch,
        report=_report(same_aggregate_different_distribution),
    )
    reordered_source, *_ = _source(
        tmp_path / "reordered", monkeypatch, report=_report(list(reversed(first))),
    )
    first_fields = first_source.read(query)["fields"]
    alternate_fields = alternate_source.read(query)["fields"]
    reordered_fields = reordered_source.read(query)["fields"]

    assert first_fields["army_size"] == alternate_fields["army_size"]
    for first_row, alternate_row in zip(
            first_fields["army_composition"]["value"],
            alternate_fields["army_composition"]["value"]):
        first_aggregate = {k: v for k, v in first_row.items()
                           if k not in {"record_strengths", "unit_types"}}
        alternate_aggregate = {k: v for k, v in alternate_row.items()
                               if k not in {"record_strengths", "unit_types"}}
        assert first_aggregate == alternate_aggregate
    assert first_fields["army_composition"]["value"][0]["record_strengths"]["raw_values"] == [100, 900]
    assert alternate_fields["army_composition"]["value"][0]["record_strengths"]["raw_values"] == [400, 600]
    assert first_fields == reordered_fields


def test_query_report_and_two_and_five_second_periodic_routes_share_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    rows = _rows()
    rows.append({"id_type": 55, "id": 2004, "type_kind": 5, "strength_raw": 750})
    for row, key in zip(rows, ("infantry_type", "cavalry_type", "artillery_type",
                              "heavy_type", "light_type", "transport_type", "galley_type")):
        row["unit_type"] = {"status": "known", "key": key}
    forces, base, _, _, _ = _source(tmp_path, monkeypatch, report=_report(rows))
    forces.localization_reader = _LiteralNames()
    now = [100]
    service = InformationService(
        CompositeSource(base, [forces]),
        tmp_path / "country-forces-information.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    query = _query(["army_composition", "navy_composition"])
    try:
        direct = tools.call("information_query", {
            "request_id": "country-forces-public-query", "queries": [query],
            "view": "full",
        })
        saved = tools.call("information_manage_report", {
            "request_id": "country-forces-report-create", "operation": "create",
            "config": {"name": "country forces composition", "detail": "raw",
                       "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "request_id": "country-forces-report-query", "report_id": saved["id"],
            "view": "full",
        })
        expected_fields = direct["items"][0]["fields"]
        assert expected_fields["army_composition"]["value"][0]["unit_types"]["value"][0]["key"] == "infantry_type"
        unit_name = expected_fields["army_composition"]["value"][0]["unit_types"]["value"][0]["name"]
        assert unit_name["status"] == "known" and unit_name["value"] == "Nom infantry_type"
        assert unit_name["native_widget_text_verified"] is False
        galley = expected_fields["navy_composition"]["value"][2]
        assert galley["category"] == "galley" and galley["count"] == 1
        assert galley["strength"]["raw"] == 750
        assert galley["unit_types"]["value"][0]["name"]["value"] == "Nom galley_type"
        assert direct["complete"] is False
        assert rendered["items"][0]["fields"] == expected_fields

        for interval in (2, 5):
            subscription = tools.call("information_manage_subscription", {
                "request_id": f"country-forces-subscription-create-{interval}",
                "operation": "create",
                "config": {
                    "name": f"country forces {interval}s periodic",
                    "enabled": True,
                    "kind": "periodic",
                    "report_id": saved["id"],
                    "schedule": {"basis": "real", "unit": "seconds",
                                 "every": interval, "missed": "coalesce"},
                },
            })["subscription"]
            now[0] += interval
            tick = tools.call("information_tick", {"view": "full"})
            assert tick["state"] == "processed"
            assert len(tick["results"]) == 1
            periodic = tick["results"][0]
            assert periodic["items"][0]["fields"] == expected_fields
            assert periodic["status"] == "partial"
            tools.call("information_manage_subscription", {
                "request_id": f"country-forces-subscription-cancel-{interval}",
                "operation": "cancel",
                "subscription_id": subscription["id"],
                "expected_version": subscription["version"],
            })
    finally:
        service.close()


def test_unit_type_keys_group_strengths_and_keep_unresolved_records_anonymous():
    rows = [
        {"id_type": 55, "id": 101, "type_kind": 0, "strength_raw": 900,
         "unit_type": {"status": "known", "key": "zulu"}},
        {"id_type": 55, "id": 102, "type_kind": 0, "strength_raw": 0,
         "unit_type": {"status": "known", "key": "alpha"}},
        {"id_type": 55, "id": 103, "type_kind": 0, "strength_raw": 500,
         "unit_type": {"status": "known", "key": "zulu"}},
        {"id_type": 55, "id": 104, "type_kind": 0, "strength_raw": 700,
         "unit_type": {"status": "unknown", "reason": "private_pointer_0x12345678"}},
    ]
    fields = country_forces._projection(rows)
    assert country_forces._projection(list(reversed(rows))) == fields
    infantry = fields["army_composition"]["value"][0]
    assert infantry["count"] == 4 and infantry["strength"]["raw"] == 2100
    types = infantry["unit_types"]
    assert types["status"] == "partial" and types["complete"] is False
    assert [row["key"] for row in types["value"]] == ["alpha", "zulu"]
    assert [row["count"] for row in types["value"]] == [1, 2]
    assert [row["strength"]["raw"] for row in types["value"]] == [0, 1400]
    assert types["value"][1]["record_strengths"]["raw_values"] == [500, 900]
    assert types["unresolved_records"] == 1
    assert types["unresolved_record_strengths"]["raw_values"] == [700]
    assert types["gaps"] == ["UNIT_TYPE_KEY_UNAVAILABLE"]
    assert "0x12345678" not in json.dumps(fields)


@pytest.mark.parametrize("unit_type", [None, {}, {"status": "known", "key": "../private"},
                                       {"status": "known", "key": "x" * 129},
                                       {"status": "known", "key": 5}])
def test_legacy_or_invalid_unit_type_keys_preserve_counts_and_strength(unit_type):
    rows = _rows()
    if unit_type is not None:
        rows[0]["unit_type"] = unit_type
    fields = country_forces._projection(rows)
    assert fields["army_size"]["value"] == 3
    assert fields["army_size"]["strength"]["raw"] == 2476
    types = fields["army_composition"]["value"][0]["unit_types"]
    assert types["status"] == "unknown" and types["unresolved_records"] == 1
    assert types["value"] == []
    empty = fields["navy_composition"]["value"][2]["unit_types"]
    assert empty["status"] == "known" and empty["complete"] is True
    assert empty["value"] == [] and empty["unresolved_records"] == 0


@pytest.mark.parametrize("fields, expected_keys", [(["army_composition"], True), (["army_size"], False)])
def test_native_default_capture_requests_type_keys_only_for_composition(tmp_path, monkeypatch, fields, expected_keys):
    source, _, _, _, calls = _source(tmp_path, monkeypatch)
    captured = []
    module = country_forces.import_module()

    def capture(installation, *, country, include_type_keys):
        captured.append((country, include_type_keys))
        return _report()

    module.capture = capture
    source.capture = None
    result = source.read(_query(fields))
    assert captured == [("FRA", expected_keys)]
    assert calls and result["source"]["projection_version"] == 4
    assert result["fields"][fields[0]]["status"] == "known"


@pytest.mark.parametrize("failure", ["missing", "template", "exception"])
def test_localization_failure_preserves_native_keys_counts_and_strength(tmp_path, monkeypatch, failure):
    rows = _rows()
    rows[0]["unit_type"] = {"status": "known", "key": "infantry_type"}
    source, *_ = _source(tmp_path, monkeypatch, report=_report(rows))

    def localize(country, context, keys):
        if failure == "exception":
            raise RuntimeError("private_pointer_0x12345678")
        entry = {} if failure == "missing" else {"status": "known", "text": "$DYNAMIC$"}
        return {"status": "known", "entries": {"infantry_type": entry}, "language": "l_french"}

    source.localization_reader = SimpleNamespace(localized_text=localize)
    result = source.read(_query(["army_size", "army_composition"]))
    assert result["fields"]["army_size"]["value"] == 3
    infantry = result["fields"]["army_composition"]["value"][0]
    assert infantry["strength"]["raw"] == 981
    unit_type = infantry["unit_types"]["value"][0]
    assert unit_type["key"] == "infantry_type"
    assert unit_type["name"]["status"] == "unknown"
    assert "0x12345678" not in json.dumps(result)


def test_localization_context_change_retracts_the_whole_result(tmp_path, monkeypatch):
    rows = _rows()
    rows[0]["unit_type"] = {"status": "known", "key": "infantry_type"}
    source, *_ = _source(tmp_path, monkeypatch, report=_report(rows), change_at=4)
    source.localization_reader = _LiteralNames()
    result = source.read(_query(["army_size", "army_composition"]))
    assert all(field == {"status": "unknown", "reason": "COUNTRY_FORCES_CONTEXT_CHANGED_DURING_LOCALIZATION"}
               for field in result["fields"].values())


def test_composition_change_subscription_is_rejected_before_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    forces, base, _, _, calls = _source(tmp_path, monkeypatch)
    service = InformationService(
        CompositeSource(base, [forces, NativeCountryStateSource(base)]),
        tmp_path / "country-forces-change.sqlite3",
    )
    tools = InformationTools(service)
    try:
        report = tools.call("information_manage_report", {
            "request_id": "forces-change-report", "operation": "create",
            "config": {
                "name": "forces change boundary", "detail": "raw",
                "queries": [_query(["army_composition", "navy_composition"])],
            },
        })["report"]
        with pytest.raises(InformationError) as rejected:
            tools.call("information_manage_subscription", {
                "request_id": "forces-unsupported-change", "operation": "create",
                "config": {
                    "name": "unsupported forces change", "enabled": True,
                    "kind": "change", "report_id": report["id"],
                    "schedule": {"basis": "real", "unit": "seconds",
                                 "every": 2, "missed": "coalesce"}},
            })
        assert rejected.value.code == "unsupported_trigger", str(rejected.value)
        assert calls == []
    finally:
        service.close()


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda rows: rows[0].update(type_kind=True), id="boolean-kind"),
        pytest.param(lambda rows: rows[0].update(type_kind=99), id="unknown-kind"),
        pytest.param(lambda rows: rows[1].update(id=rows[0]["id"]), id="duplicate-id"),
    ],
)
def test_unknown_or_ambiguous_native_records_retract_the_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate,
):
    rows = _rows()
    mutate(rows)
    source, _, _, _, calls = _source(
        tmp_path, monkeypatch, report=_report(rows),
    )
    result = source.read(_query(["army_size", "navy_composition"]))
    assert result["complete"] is False
    assert result["fields"]["army_size"] == {
        "status": "unknown", "reason": "COUNTRY_FORCES_RECORDS_INVALID",
    }
    assert result["fields"]["navy_composition"] == {
        "status": "unknown", "reason": "COUNTRY_FORCES_RECORDS_INVALID",
    }
    assert len(calls) == 1


def test_capture_validator_rejects_bad_cleanup_before_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    report = _report()
    report["cleanup"]["handle_close"].update(status="error", closed=False)
    source, _, _, _, calls = _source(
        tmp_path, monkeypatch, report=report, accept=True,
    )
    result = source.read(_query(["army_size"]))
    assert result["fields"]["army_size"] == {
        "status": "unknown", "reason": "COUNTRY_FORCES_CAPTURE_INVALID",
    }
    assert result["complete"] is False
    assert len(calls) == 1


def test_context_change_after_capture_retracts_even_with_valid_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    source, _, session, _, calls = _source(tmp_path, monkeypatch, change_at=3)
    result = source.read(_query(["army_size"]))
    assert session.health_calls >= 3
    assert result["fields"]["army_size"] == {
        "status": "unknown", "reason": "COUNTRY_FORCES_CONTEXT_CHANGED_DURING_CAPTURE",
    }
    assert calls == []


def test_forces_only_is_local_but_mixed_manpower_keeps_state_recipient_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    forces, base, _, tools, _ = _source(tmp_path, monkeypatch)
    state = NativeCountryStateSource(base)
    composite = CompositeSource(base, [forces, state])

    normalized = composite.validate_query(_query(["army_size"]))
    assert normalized["parameters"] == {}
    sample = composite.read(normalized, base.context())
    assert sample["fields"]["army_size"]["status"] == "known"
    assert tools.inspect_calls == []

    with pytest.raises(InformationError) as missing:
        composite.validate_query(_query(["army_size", "manpower"]))
    assert missing.value.code == "invalid_parameters"

    mixed = composite.validate_query(
        _query(["army_size", "manpower"], {"reference_recipient": "PAP"})
    )
    assert mixed["fields"] == ["army_size", "manpower"]
    assert mixed["parameters"] == {"reference_recipient": "PAP"}


def test_planned_only_sailors_remains_unsupported_and_does_not_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    forces, base, _, tools, _ = _source(tmp_path, monkeypatch)
    state = NativeCountryStateSource(base)
    composite = CompositeSource(base, [forces, state])
    service = InformationService(composite, tmp_path / "information.sqlite3")
    try:
        result = service.query("planned-sailors", queries=[_query(["sailors"])])
    finally:
        service.close()
    field = result["items"][0]["fields"]["sailors"]
    assert field == {
        "status": "unsupported", "reason": "FIELD_NOT_IMPLEMENTED_BY_ADAPTER",
    }
    assert result["complete"] is False
    assert tools.inspect_calls == []

