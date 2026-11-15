from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import trade_details_memory
from bridge.information import trade_income_memory
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.trade_income import NativeTradeIncomeSource
from bridge.information.trade_transfer import NativeTradeTransferSource
from bridge.tests import test_information_trade_details as details_fixture
from bridge.tests import test_information_trade_income_memory as income_fixture


GAME_SHA256 = trade_income_memory.EXPECTED_EXE_SHA256
SESSION_ID = "session-trade-transfer-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    """Use the pinned trade-income/details profiles with bounded fake memory."""

    trade_profile = income_fixture._profile()
    details_profile = trade_details_memory._load_profile()
    monkeypatch.setattr(trade_income_memory, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade_income_memory, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(trade_details_memory, "_active_profile", lambda: details_profile)
    return trade_profile, details_profile


def _install_nonempty_transfer(reader) -> None:
    foreign = 0x200630000
    fullref = bytearray(b"ENG\0\0\0\0\0")
    fullref[4:6] = (8).to_bytes(2, "little", signed=True)
    # The transfer child reuses the details reader's country-table lookup;
    # install its bounded database/table chain before adding the two tails.
    details_fixture._install_capital(reader, scalar=0)
    details_fixture._install_transfer(
        reader,
        income_fixture.TABLE_ONE,
        to_element=0x200680000,
        from_element=0x200690000,
        country_pointer=foreign,
        fullref=bytes(fullref),
        to_raw=-321,
        from_raw=654,
    )


def _report_with_transfer(configured, tmp_path: Path, *, transfer: bool = True):
    extras = _install_nonempty_transfer if transfer else None
    reader, (trade_record, details_record, _power_record) = details_fixture._records_for(
        configured,
        extras=extras,
    )
    assert trade_income_memory.validate_record(trade_record)
    assert trade_details_memory.validate_record(details_record, trade_record)
    base = details_fixture._Base(tmp_path)
    base.session.record["session_id"] = SESSION_ID
    report = details_fixture._report(trade_record, details_record, base)
    return base, report, trade_record, details_record


def _query(object_: dict, fields=None, parameters=None) -> dict:
    return {
        "topic": "T05",
        "object": object_,
        "fields": ["transfer"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def _source(base, report):
    calls: list[tuple[Path, str, dict]] = []

    def capture(installation, country, **kwargs):
        calls.append((installation, country, dict(kwargs)))
        return deepcopy(report)

    return NativeTradeTransferSource(base, capture=capture), calls


def _expected_item(*, raw: int, direction: str) -> dict:
    return {
        "country": "ENG",
        "fullref_raw_hex": "454e470008000000",
        "slot": 8,
        "raw": raw,
        "raw_hex": ((raw & 0xFFFFFFFF).to_bytes(4, "little")).hex(),
        "unit": "trade_power",
        "scale": 1000,
        "native_key": (
            "TRANSFER_TRADE_POWER_TO"
            if direction == "to" else "TRANSFER_TRADE_POWER_FROM"
        ),
        "direction": direction,
    }


def test_catalog_query_scope_and_parameters_are_strict(tmp_path: Path):
    base = details_fixture._Base(tmp_path)
    source = NativeTradeTransferSource(base, capture=lambda *_args, **_kwargs: None)
    item = source.catalog()[0]
    assert item["topic_id"] == "T05"
    assert list(item["fields"]) == ["transfer"]
    assert item["object_types"] == ["country", "trade_node"]
    assert item["triggers"] == ["query", "periodic"]
    assert item["parameters"] == {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    }
    field = item["fields"]["transfer"]
    assert field["unit"] == "trade_power"
    assert field["scale"] == 1000
    assert field["period"] == "current"
    assert field["basis"] == "native_trade_power_transfer_relations"
    assert field["complete"] is False
    assert source.validate_query(_query({"type": "country", "country": "FRA"}), base.context())
    assert source.validate_query(_query({"type": "trade_node", "node_id": "alpha"}), base.context())

    with pytest.raises(InformationError) as wrong_country:
        source.validate_query(_query({"type": "country", "country": "ENG"}))
    assert wrong_country.value.code == "observer_scope_mismatch"
    with pytest.raises(InformationError) as invalid_parameters:
        source.validate_query(_query({"type": "country", "country": "FRA"}, parameters={"x": 1}))
    assert invalid_parameters.value.code == "invalid_parameters"
    with pytest.raises(InformationError) as invalid_node:
        source.validate_query(_query({"type": "trade_node", "node_id": "Null"}))
    assert invalid_node.value.code == "invalid_object"


def test_country_projection_preserves_native_order_sign_and_empty_containers(
    configured, tmp_path: Path,
):
    base, report, _trade_record, _details_record = _report_with_transfer(configured, tmp_path)
    source, calls = _source(base, report)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())

    assert result["complete"] is False
    field = result["fields"]["transfer"]
    assert field["status"] == "known"
    assert field["unit"] == "trade_power"
    assert field["scale"] == 1000
    assert field["period"] == "current"
    assert field["basis"] == "native_trade_power_transfer_relations"
    assert field["complete"] is False
    assert [node["node_id"] for node in field["value"]] == ["alpha", "beta"]

    alpha = field["value"][0]
    assert alpha["to"] == {
        "status": "known", "items": [_expected_item(raw=-321, direction="to")],
    }
    assert alpha["from"] == {
        "status": "known", "items": [_expected_item(raw=654, direction="from")],
    }
    beta = field["value"][1]
    assert beta["to"] == {"status": "known", "items": []}
    assert beta["from"] == {"status": "known", "items": []}
    assert calls == [
        (
            tmp_path / "installation.json",
            "FRA",
            {"include_trade_income": True, "include_trade_details": True},
        )
    ]


def test_node_projection_is_one_native_shape_and_unknown_node_is_not_empty(
    configured, tmp_path: Path,
):
    base, report, _trade_record, _details_record = _report_with_transfer(configured, tmp_path)
    source, calls = _source(base, report)
    country = source.read(
        _query({"type": "country", "country": "FRA"}), base.context(),
    )
    node = source.read(
        _query({"type": "trade_node", "node_id": "alpha"}), base.context(),
    )
    assert node["fields"]["transfer"]["status"] == "known"
    assert node["fields"]["transfer"]["value"] == country["fields"]["transfer"]["value"][0]

    unknown = source.read(
        _query({"type": "trade_node", "node_id": "not_a_native_node"}), base.context(),
    )
    assert unknown["fields"]["transfer"] == {
        "status": "unknown", "reason": "NODE_NOT_FOUND",
    }
    assert len(calls) == 3


def test_empty_transfer_is_known_empty_but_capture_or_context_failure_is_unknown(
    configured, tmp_path: Path,
):
    base, report, _trade_record, _details_record = _report_with_transfer(
        configured, tmp_path, transfer=False,
    )
    source, calls = _source(base, report)
    empty = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert empty["fields"]["transfer"]["status"] == "known"
    assert all(
        node[direction] == {"status": "known", "items": []}
        for node in empty["fields"]["transfer"]["value"]
        for direction in ("to", "from")
    )
    assert len(calls) == 1

    changed_base, changed_report, _trade, _details = _report_with_transfer(configured, tmp_path / "changed")
    changed_base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    changed_source, changed_calls = _source(changed_base, changed_report)
    changed = changed_source.read(
        _query({"type": "country", "country": "FRA"}), changed_base.context(),
    )
    assert changed["fields"]["transfer"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in changed["fields"]["transfer"]["reason"]
    assert len(changed_calls) == 1


def test_process_session_change_retracts_transfer_without_false(configured, tmp_path: Path):
    base, report, _trade_record, _details_record = _report_with_transfer(configured, tmp_path)
    base.after_context = {"session_id": "different-session"}
    source, calls = _source(base, report)
    result = source.read(
        _query({"type": "country", "country": "FRA"}), base.context(),
    )
    assert result["fields"]["transfer"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["transfer"]["reason"]
    assert len(calls) == 1


class _Primary:
    event_types = ()

    def __init__(self, base):
        self.base = base

    def context(self):
        return self.base.context()

    def catalog(self):
        return [{
            "topic_id": "T05",
            "fields": {},
            "object_types": ["country", "trade_node"],
            "observer_roles": ["country"],
            "observer_scope": ["FRA"],
            "parameters": {
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": False,
            },
            "supported_versions": ["1.37.4"],
            "triggers": ["query", "periodic"],
            "context_scope": "country_scope",
        }]

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": cursor, "complete": True, "gaps": []}


def test_composite_t05_mixed_income_and_transfer_fields_keep_distinct_owners(
    configured, tmp_path: Path,
):
    base, report, _trade_record, _details_record = _report_with_transfer(configured, tmp_path)
    transfer_source, transfer_calls = _source(base, report)
    income_calls = []

    def income_capture(installation, country, **kwargs):
        income_calls.append((installation, country, dict(kwargs)))
        return deepcopy(report)

    income_source = NativeTradeIncomeSource(base, capture=income_capture)
    composite = CompositeSource(_Primary(base), [income_source, transfer_source])
    query = _query(
        {"type": "country", "country": "FRA"},
        fields=["income", "transfer"],
    )
    result = composite.read(query, base.context())

    assert result["fields"]["income"]["status"] == "known"
    assert result["fields"]["transfer"]["status"] == "known"
    assert result["fields"]["transfer"]["value"][0]["to"]["items"][0]["raw"] == -321
    assert len(income_calls) == 1
    assert len(transfer_calls) == 1

