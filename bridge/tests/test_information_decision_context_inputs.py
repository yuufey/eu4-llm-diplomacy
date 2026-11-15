"""Offline contract tests for operator-owned C03 decision-context inputs."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.decision_context_inputs import DecisionContextInputsSource


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _context(**changes):
    value = {
        "status": "ready", "complete": True, "mode": "live", "observer": "VIJ",
        "session_id": "decision-context-session", "game_sha256": GAME_SHA256,
        "game_version": "1.37.4", "game_date": 56556984, "world_id": "world-001",
    }
    value.update(changes)
    return value


class BaseSource:
    def __init__(self, **changes):
        self.current = _context(**changes)
        self.calls = 0
        self.change_on_call = None
        self.raise_on_call = None

    def context(self):
        self.calls += 1
        if self.raise_on_call == self.calls:
            raise RuntimeError("context unavailable")
        if self.change_on_call == self.calls:
            self.current["game_date"] += 1
        return deepcopy(self.current)


def _query(fields=("strategic_goals",), *, session_id=None, parameters=None):
    obj = {"type": "session"}
    if session_id is not None:
        obj["session_id"] = session_id
    return {
        "topic": "C03", "object": obj, "fields": list(fields),
        "parameters": {} if parameters is None else parameters,
    }


def _document(base: BaseSource, **values):
    document = {
        "schema": "EU4-DECISION-CONTEXT/1",
        "binding": {
            "session_id": base.current["session_id"],
            "observer": base.current["observer"],
            "game_sha256": base.current["game_sha256"],
        },
    }
    document.update(values)
    return document


def _write(path: Path, value) -> None:
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _source(tmp_path, *, base=None, value=None):
    base = BaseSource() if base is None else base
    path = tmp_path / "decision-context.json"
    _write(path, _document(base) if value is None else value)
    return DecisionContextInputsSource(base, path), base, path


def test_catalog_is_two_partial_operator_fields_and_context_is_deepcopied(tmp_path):
    source, base, _path = _source(tmp_path)
    entry = source.catalog()[0]

    assert set(entry["fields"]) == {"strategic_goals", "diplomatic_constraints"}
    assert entry["object_types"] == ["session"]
    assert set(entry["triggers"]) == {"query", "periodic", "change"}
    assert entry["source_kind"] == "operator_input"
    assert entry["basis"] == "explicitly_declared_operator_input"
    assert all(field["coverage"] == "partial" and field["complete"] is False
               for field in entry["fields"].values())
    assert all(field["game_fact"] is False for field in entry["fields"].values())

    copied = source.context()
    copied["session_id"] = "changed"
    assert base.current["session_id"] == "decision-context-session"


def test_declared_values_keep_order_empty_list_and_non_fra_observer(tmp_path):
    base = BaseSource(observer="VIJ")
    source, _base, _path = _source(
        tmp_path,
        base=base,
        value=_document(
            base,
            strategic_goals=[{"id": "first", "text": "Secure the strait"},
                             {"id": "second", "text": "Protect trade"}],
            diplomatic_constraints=[],
        ),
    )
    result = source.read(_query(("strategic_goals", "diplomatic_constraints")))
    goals = result["fields"]["strategic_goals"]
    constraints = result["fields"]["diplomatic_constraints"]

    assert goals["status"] == "known"
    assert [item["id"] for item in goals["value"]["declarations"]] == ["first", "second"]
    assert goals["value"]["game_fact"] is False
    assert goals["unit"] == "declared_objectives"
    assert goals["partial"] is True and goals["complete"] is False
    assert constraints["status"] == "known"
    assert constraints["value"]["declarations"] == []
    assert "NO_NATIVE_LEGALITY_OR_STRATEGY_INFERRED" in constraints["gaps"]
    assert "file_sha256" not in goals["value"]
    assert len(result["source"]["provenance"]["file_sha256"]) == 64


def test_missing_field_is_unknown_not_empty_and_result_is_deepcopied(tmp_path):
    base = BaseSource()
    source, _base, _path = _source(
        tmp_path, base=base,
        value=_document(base, strategic_goals=[{"id": "g", "text": "Goal"}]),
    )
    first = source.read(_query(("strategic_goals", "diplomatic_constraints")))
    assert first["fields"]["strategic_goals"]["status"] == "known"
    assert first["fields"]["diplomatic_constraints"]["status"] == "unknown"
    first["fields"]["strategic_goals"]["value"]["declarations"][0]["text"] = "mutated"
    second = source.read(_query())
    assert second["fields"]["strategic_goals"]["value"]["declarations"][0]["text"] == "Goal"


def test_session_selector_and_parameters_are_strict(tmp_path):
    source, base, _path = _source(tmp_path)
    mismatch = source.read(_query(session_id="another-session"))
    assert mismatch["fields"]["strategic_goals"] == {
        "status": "unavailable", "reason": "C03_SESSION_SCOPE_MISMATCH",
        "period": "declared", "complete": False,
    }
    with pytest.raises(InformationError):
        source.read(_query(parameters={"ignored": True}))
    assert base.calls == 1


def test_unsupported_field_returns_without_opening_file(tmp_path):
    base = BaseSource()
    path = tmp_path / "missing.json"
    source = DecisionContextInputsSource(base, path)
    result = source.read(_query(("pending_matters",)))
    assert result["fields"]["pending_matters"] == {
        "status": "unsupported", "reason": "C03_DECISION_CONTEXT_FIELD_NOT_IMPLEMENTED"
    }
    assert base.calls == 1


@pytest.mark.parametrize(
    "raw",
    [
        {"schema": "wrong", "binding": {}, "strategic_goals": []},
        {"schema": "EU4-DECISION-CONTEXT/1", "binding": {}, "extra": 1},
        b'{"schema":"EU4-DECISION-CONTEXT/1","binding":{},'
        b'"strategic_goals":[{"id":"x","text":"a"},{"id":"x","text":"b"}]}',
    ],
)
def test_invalid_schema_unknown_keys_and_duplicate_ids_never_become_empty(tmp_path, raw):
    base = BaseSource()
    source, _base, path = _source(tmp_path, base=base)
    _write(path, raw)
    result = source.read(_query(("strategic_goals", "diplomatic_constraints")))
    assert result["fields"]["strategic_goals"]["status"] == "unknown"
    assert result["fields"]["diplomatic_constraints"]["status"] == "unknown"
    assert "declarations" not in result["fields"]["strategic_goals"]


def test_invalid_declaration_shape_and_oversized_file_are_bounded(tmp_path):
    base = BaseSource()
    source, _base, path = _source(tmp_path, base=base)
    bad = _document(base, strategic_goals=[{"id": "g", "text": ""}])
    _write(path, bad)
    invalid = source.read(_query())
    assert invalid["fields"]["strategic_goals"]["status"] == "unknown"

    path.write_bytes(b"{" + b" " * (64 * 1024))
    oversized = source.read(_query())
    assert oversized["fields"]["strategic_goals"]["status"] == "unknown"

    too_many = _document(base, strategic_goals=[{"id": str(i), "text": "x"} for i in range(65)])
    _write(path, too_many)
    assert source.read(_query())["fields"]["strategic_goals"]["status"] == "unknown"


def test_binding_mismatch_is_unknown_and_observer_is_not_hardcoded(tmp_path):
    base = BaseSource(observer="VIJ")
    wrong = _document(base, strategic_goals=[{"id": "g", "text": "Goal"}])
    wrong["binding"]["observer"] = "FRA"
    source, _base, _path = _source(tmp_path, base=base, value=wrong)
    result = source.read(_query())
    assert result["fields"]["strategic_goals"]["status"] == "unknown"
    assert result["fields"]["strategic_goals"]["reason"] == "C03_INPUT_BINDING_MISMATCH"


def test_context_drift_after_parse_withdraws_supported_fields(tmp_path):
    base = BaseSource()
    base.change_on_call = 2
    source, _base, _path = _source(
        tmp_path, base=base,
        value=_document(base, strategic_goals=[{"id": "g", "text": "Goal"}]),
    )
    result = source.read(_query())
    assert result["fields"]["strategic_goals"]["status"] == "unavailable"
    assert result["fields"]["strategic_goals"]["reason"] == "C03_CONTEXT_CHANGED_DURING_READ"


def test_exception_path_still_checks_after_context(tmp_path):
    base = BaseSource()
    base.change_on_call = 2
    source, _base, path = _source(tmp_path, base=base)
    path.unlink()
    path.mkdir()
    result = source.read(_query())
    assert result["fields"]["strategic_goals"]["status"] == "unavailable"
    assert result["fields"]["strategic_goals"]["reason"] == "C03_CONTEXT_CHANGED_DURING_READ"


def test_two_fields_share_one_bounded_parse(tmp_path):
    source, _base, _path = _source(
        tmp_path,
        value=_document(BaseSource(), strategic_goals=[], diplomatic_constraints=[]),
    )
    original = source._file
    calls = []

    def counted_file():
        calls.append(True)
        return original()

    source._file = counted_file
    result = source.read(_query(("strategic_goals", "diplomatic_constraints")))
    assert len(calls) == 1
    assert all(result["fields"][field]["status"] == "known" for field in
               ("strategic_goals", "diplomatic_constraints"))


def test_information_service_accepts_periodic_and_change_without_game_fact_claim(tmp_path):
    base = BaseSource()
    source, _base, _path = _source(
        tmp_path, base=base,
        value=_document(base, strategic_goals=[{"id": "g", "text": "Goal"}]),
    )
    now = [1000.0]
    service = InformationService(source, tmp_path / "decision-context-service.sqlite3",
                                 clock=lambda: now[0])
    query = _query(("strategic_goals",))
    try:
        report = service.manage_report(
            "decision-context-report", "create", config={"queries": [query], "detail": "full"}
        )["report"]
        periodic = service.manage_subscription(
            "decision-context-periodic", "create",
            config={"kind": "periodic", "report_id": report["id"],
                    "schedule": {"basis": "real", "every": 1, "unit": "seconds"}},
        )["subscription"]
        change = service.manage_subscription(
            "decision-context-change", "create",
            config={"kind": "change", "report_id": report["id"],
                    "schedule": {"basis": "real", "every": 1, "unit": "seconds"}},
        )["subscription"]
        now[0] += 1
        tick = service.tick()
        assert [item["subscription_id"] for item in tick["results"]] == [periodic["id"]]
        assert all(item["subscription_id"] != change["id"] for item in tick["results"])
        assert tick["results"][0]["items"][0]["fields"]["strategic_goals"]["value"]["game_fact"] is False
    finally:
        service.close()

