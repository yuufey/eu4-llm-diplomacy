"""Adapter contract tests for the partial N01 monthly native ledger."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import monthly_economy_memory
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.sources import DiplomacySource


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_DATE = 56557728
CREATION_FILETIME = 134374886912306555
MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x150000000


def _raw_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(4, "little").hex()


def _monthly_record(values: dict[str, int]) -> dict:
    """Build a record through the bounded worker and its real validator shape."""
    assert values["monthly_balance"] == (
        values["monthly_income"] - values["monthly_expenses"]
    )
    payload = bytearray(228)
    payload[0:4] = values["monthly_income"].to_bytes(
        4, "little", signed=True,
    )
    expense_start = 0x7BC - 0x770
    payload[expense_start:expense_start + 4] = values["monthly_expenses"].to_bytes(
        4, "little", signed=True,
    )

    class Reader:
        def __init__(self, raw: bytes):
            self.raw = raw
            profile = monthly_economy_memory._active_profile()
            self.guards = {
                MODULE_BASE + rva: expected
                for _name, rva, expected in
                monthly_economy_memory._profile_code_guards(profile)
            }

        def read(self, address: int, size: int, _label: str) -> bytes:
            if address in self.guards:
                return self.guards[address][:size]
            if address == COUNTRY_POINTER + 0x770 and size == 228:
                return self.raw
            raise AssertionError(f"unexpected bounded read: {address:#x}/{size}")

    record = monthly_economy_memory.read_fields(
        Reader(bytes(payload)), MODULE_BASE, COUNTRY_POINTER,
    )
    assert record["status"] == "observed"
    return record


class _Session:
    observer = "FRA"

    def __init__(self, directory: Path, *, after: dict | None = None, observer: str = "FRA"):
        self.observer = observer
        self.directory = directory
        self.session_id = "31460-1dd653f69242d7b"
        self.creation_filetime = CREATION_FILETIME
        self.after = deepcopy(after)
        self.health_calls = 0
        self.record = {
            "observer": observer,
            "controlled_countries": [observer],
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "session_id": self.session_id,
            "creation_filetime": CREATION_FILETIME,
        }

    def health(self) -> dict:
        self.health_calls += 1
        result = {
            "status": "ready",
            "complete": True,
            "date_raw": GAME_DATE,
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA256,
            "observer": self.observer,
            "reasons": [],
        }
        if self.after and self.health_calls >= 2:
            result.update(deepcopy(self.after))
        return result


class _Tools:
    def __init__(self, session: _Session):
        self.session = session
        self.inspect_calls: list[tuple] = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase,
                                  parameters):
        self.inspect_calls.append(
            (action_id, actor, recipient, phase, deepcopy(parameters))
        )
        return {
            "actor": actor,
            "recipient": recipient,
            "action_id": action_id,
            "gift": {
                "complete": True,
                "controlled_treasury": {
                    "country": actor,
                    "raw": 1234,
                    "unit": "ducats",
                    "scale": 1000,
                },
            },
        }


def _source(tmp_path: Path, *, capture=None, after: dict | None = None, observer: str = "FRA"):
    session = _Session(tmp_path, after=after, observer=observer)
    tools = _Tools(session)
    return (
        NativeCountryStateSource(
            DiplomacySource(tools), monthly_economy_capture=capture,
        ),
        session,
        tools,
    )


def _query(fields: list[str], parameters: dict | None = None, *, observer: str = "FRA") -> dict:
    return {
        "topic": "N01",
        "object": {"type": "country", "country": observer},
        "fields": fields,
        "parameters": {} if parameters is None else parameters,
    }


def _report(session: _Session, record: dict, *, mutate: dict | None = None) -> dict:
    date_hex = GAME_DATE.to_bytes(4, "little", signed=True).hex()
    report = {
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": session.observer,
        "unit": "monarch_points",
        "scale": 1,
        "values": {"administrative": 1, "diplomatic": 2, "military": 3},
        "identity": {
            "binding_verified": True,
            "process_path_sha256": GAME_SHA256,
            "installation_session_id": session.session_id,
            "installation_creation_filetime": CREATION_FILETIME,
            "process_creation_filetime": CREATION_FILETIME,
        },
        "static_contract_guard": {"status": "observed"},
        "file_code_guard": {"status": "observed"},
        "runtime_code_guard": {"status": "observed"},
        "doublepass": {"performed": True, "consistent": True},
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": {
            "status": "observed",
            "game_date": {"value": GAME_DATE, "raw_hex": date_hex},
            "monthly_economy": deepcopy(record),
        },
        "after": {
            "status": "observed",
            "game_date": {"value": GAME_DATE, "raw_hex": date_hex},
            "monthly_economy": deepcopy(record),
        },
        "monthly_economy": deepcopy(record),
        "completed": True,
    }
    if mutate:
        for key, value in mutate.items():
            if isinstance(value, dict) and isinstance(report.get(key), dict):
                report[key].update(deepcopy(value))
            else:
                report[key] = deepcopy(value)
    return report


def test_catalog_and_optional_reference_parameter(tmp_path: Path) -> None:
    source, _, _ = _source(tmp_path, capture=lambda *_args, **_kwargs: {})
    topic = next(item for item in source.catalog() if item["topic_id"] == "N01")
    assert topic["status"] == "available"
    assert topic["source"] == "NativeCountryStateSource"
    assert topic["parameters"]["required"] == []
    assert set(topic["fields"]) == {
        "treasury", "monthly_income", "monthly_expenses", "monthly_balance",
        "war_income",
    }
    for field in ("monthly_income", "monthly_expenses", "monthly_balance"):
        assert topic["fields"][field]["coverage"] == "partial"
        assert topic["fields"][field]["basis"] == "native_recurring_monthly_ledger"
        assert topic["fields"][field]["reference_period"] == "previous_month"
        assert topic["fields"][field]["value_semantics"] == (
            "previous_month_recurring_ledger"
        )
        assert topic["fields"][field]["value_origin"] == "derived_from_copied_native_ledger"
        assert "GUI_DYNAMIC_MONTHLY_ESTIMATE_NOT_CLOSED" in topic["fields"][field]["gaps"]
        assert "上月" in topic["fields"][field]["description"]

    source.validate_query(_query(["monthly_income"]))
    assert source.validate_query(_query(["treasury"]))["parameters"] == {}
    assert source.validate_query(_query(["treasury", "monthly_income"]))["parameters"] == {}
    source.validate_query(_query(["treasury"], {"reference_recipient": "PAP"}))


def test_composite_planned_loan_probe_uses_monthly_field_without_side_effect(
    tmp_path: Path,
) -> None:
    source, _, tools = _source(
        tmp_path,
        capture=lambda *_args, **_kwargs: pytest.fail("monthly capture must not run"),
    )

    primary_n01 = {
        "topic_id": "N01",
        "catalog_ids": ["N01"],
        "title": "primary N01",
        "status": "available",
        "fields": {"loans": {"coverage": "planned"}},
        "object_types": ["country"],
        "observer_roles": ["country"],
        "parameters": {
            "type": "object", "properties": {}, "required": [],
            "additionalProperties": False,
        },
        "supported_versions": ["1.37.4"],
        "triggers": ["query"],
        "source": "primary",
        "visibility": "country_scope",
        "context_scope": "country_scope",
    }
    primary_catalog = [primary_n01] + [
        entry for entry in source.catalog() if entry["topic_id"] != "N01"
    ]

    class Primary:
        def catalog(self):
            return deepcopy(primary_catalog)

    composite = CompositeSource(Primary(), [source])
    query = _query(["loans"])
    normalized = composite.validate_query(query)
    assert normalized["fields"] == ["loans"]
    result = composite.read(query, source.context())
    assert result["fields"]["loans"] == {
        "status": "unsupported", "reason": "FIELD_NOT_IMPLEMENTED_BY_ADAPTER",
    }
    assert tools.inspect_calls == []


@pytest.mark.parametrize("observer", ("FRA", "TUR"))
def test_one_capture_maps_negative_zero_and_balance_as_partial(
    tmp_path: Path, observer: str,
) -> None:
    values = {
        "monthly_income": -12,
        "monthly_expenses": 0,
        "monthly_balance": -12,
    }
    calls: list[tuple] = []
    record = _monthly_record(values)
    assert monthly_economy_memory.validate_record(record) is True
    source, session, tools = _source(tmp_path, observer=observer)

    def capture(installation, country, *, include_monthly_economy):
        calls.append((installation, country, include_monthly_economy))
        return _report(session, record)

    source.monthly_economy_capture = capture
    result = source.read(_query(list(values), observer=observer))

    for field, value in values.items():
        assert result["fields"][field] == {
            "status": "known", "value": value, "raw": value,
            "raw_hex": _raw_hex(value), "unit": "ducats", "scale": 1000,
            "period": "month", "reference_period": "previous_month",
            "basis": "native_recurring_monthly_ledger",
            "value_semantics": "previous_month_recurring_ledger",
            "value_origin": "derived_from_copied_native_ledger", "complete": False,
        }
    assert result["complete"] is False
    assert result["source"]["complete"] is False
    assert result["game_date"] == GAME_DATE
    assert result["source"]["session_id"] == session.session_id
    assert result["source"]["observer"] == observer
    assert len(result["source"]["provenance"]["monthly_economy"]["raw_ledger_hex"]) == 456
    assert result["source"]["provenance"]["reference_period"] == "previous_month"
    assert result["source"]["provenance"]["value_semantics"] == (
        "previous_month_recurring_ledger"
    )
    assert calls == [(tmp_path / "installation.json", observer, True)]
    assert tools.inspect_calls == []


def test_mixed_treasury_keeps_public_value_when_monthly_record_fails(
    tmp_path: Path,
) -> None:
    source, session, tools = _source(
        tmp_path,
        capture=lambda *_args, **_kwargs: _report(
            session, {"status": "unknown", "reason": "runtime_code_guard_failed"}
        ),
    )
    result = source.read(_query(
        ["treasury", "monthly_income"], {"reference_recipient": "PAP"}
    ))
    assert result["fields"]["treasury"] == {"status": "known", "value": 1234}
    assert result["fields"]["monthly_income"]["status"] == "unknown"
    assert result["complete"] is False
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0][0] == "send_gift"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"runtime_code_guard": {"status": "unknown"}}, "PARENT_GUARD_INVALID"),
        ({"identity": {"binding_verified": False}}, "PARENT_IDENTITY_INVALID"),
        ({"doublepass": {"consistent": False}}, "PARENT_DOUBLEPASS_INVALID"),
        ({"cleanup": {"handle_close": {"status": "open"}}}, "PARENT_CLEANUP_INVALID"),
        ({"before": {"game_date": {"value": GAME_DATE + 1}}}, "PARENT_DATE_INVALID"),
    ],
)
def test_parent_guard_date_session_contracts_reject_without_fallback(
    tmp_path: Path, mutation: dict, expected: str,
) -> None:
    values = {"monthly_income": 1, "monthly_expenses": 2, "monthly_balance": -1}
    source, session, _ = _source(
        tmp_path,
        capture=lambda *_args, **_kwargs: _report(
            session, _monthly_record(values), mutate=mutation
        ),
    )
    result = source.read(_query(["monthly_income"]))
    assert result["fields"]["monthly_income"]["status"] == "unknown"
    assert expected in result["fields"]["monthly_income"]["reason"]


def test_raw_or_profile_validation_failure_is_unknown_and_never_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {"monthly_income": 1, "monthly_expenses": 2, "monthly_balance": -1}
    monkeypatch.setattr(monthly_economy_memory, "validate_record", lambda _record: False)
    source, session, _ = _source(
        tmp_path,
        capture=lambda *_args, **_kwargs: _report(session, _monthly_record(values)),
    )
    result = source.read(_query(["monthly_income", "monthly_expenses"]))
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert all("MONTHLY_ECONOMY_RECORD_INVALID" in item["reason"]
               for item in result["fields"].values())


def test_unknown_or_unready_context_does_not_touch_capture(tmp_path: Path) -> None:
    calls: list[tuple] = []

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("capture must not run for non-live context")

    source, session, _ = _source(tmp_path, capture=capture)
    unready = {**source.context(), "status": "unready"}
    result = source.read(_query(["monthly_income"]), unready)
    assert result["fields"]["monthly_income"]["status"] == "unavailable"
    assert calls == []

    recorded = {**source.context(), "mode": "recorded"}
    result = source.read(_query(["monthly_income"]), recorded)
    assert result["fields"]["monthly_income"]["status"] == "unavailable"
    assert calls == []
    assert session.health_calls >= 1


def test_capture_exception_still_rechecks_context_and_reports_change(
    tmp_path: Path,
) -> None:
    source, session, _ = _source(tmp_path, after={"date_raw": GAME_DATE + 24})

    def capture(*_args, **_kwargs):
        raise RuntimeError("reader failure")

    source.monthly_economy_capture = capture
    result = source.read(_query(["monthly_income"]))
    assert result["fields"]["monthly_income"] == {
        "status": "unknown", "reason": "MONTHLY_ECONOMY_CONTEXT_CHANGED",
    }
    assert result["game_date"] == GAME_DATE
    assert result["source"]["session_id"] == session.session_id
    assert session.health_calls >= 2


def test_definition_snapshot_mismatch_invalidates_all_monthly_fields(
    tmp_path: Path,
) -> None:
    values = {"monthly_income": 1, "monthly_expenses": 2, "monthly_balance": -1}
    source, session, _ = _source(tmp_path)
    report = _report(session, _monthly_record(values))
    report["after"]["monthly_economy"] = _monthly_record(
        {"monthly_income": 9, "monthly_expenses": 2, "monthly_balance": 7}
    )
    source.monthly_economy_capture = lambda *_args, **_kwargs: report
    result = source.read(_query(list(values)))
    assert result["complete"] is False
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert all(item["reason"] == "MONTHLY_ECONOMY_SNAPSHOT_MISMATCH"
               for item in result["fields"].values())


def test_report_and_periodic_subscription_keep_partial_result_and_cancel(
    tmp_path: Path,
) -> None:
    values = {"monthly_income": 1, "monthly_expenses": 2, "monthly_balance": -1}
    source, session, _ = _source(tmp_path)
    source.monthly_economy_capture = lambda *_args, **_kwargs: _report(
        session, _monthly_record(values)
    )

    class Clock:
        def __init__(self):
            self.value = 1000.0

        def __call__(self):
            return self.value

    service = InformationService(source, tmp_path / "information.sqlite", clock=Clock())
    try:
        direct = service.query("monthly-direct", queries=[_query(list(values))])
        assert direct["complete"] is False
        assert all(item["status"] == "known"
                   for item in direct["items"][0]["fields"].values())
        report = service.manage_report(
            "monthly-report", "create",
            config={"queries": [_query(list(values))], "detail": "raw"},
        )["report"]
        subscription = service.manage_subscription(
            "monthly-subscription", "create",
            config={
                "kind": "periodic", "report_id": report["id"],
                "schedule": {
                    "basis": "real", "every": 1, "unit": "seconds",
                    "missed": "coalesce",
                },
            },
        )["subscription"]
        assert subscription["state"] == "active"
        cancelled = service.manage_subscription(
            "monthly-cancel", "cancel", subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
    finally:
        service.close()

