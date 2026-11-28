from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import trade_details_memory as details
from bridge.information import trade_income_memory as trade
from bridge.information import trade_power_memory as power
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.native_localization import NativeLocalizationReader
from bridge.information.trade_details import NativeTradeDetailsSource
from bridge.information.trade_power import NativeTradePowerSource
from bridge.tests import test_information_trade_income_memory as trade_fixture


GAME_SHA256 = trade.EXPECTED_EXE_SHA256
SESSION_ID = "session-details-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728
MODULE_BASE = trade_fixture.MODULE_BASE
COUNTRY_POINTER = trade_fixture.COUNTRY_POINTER
DETAILS_PROFILE_SHA256 = details.EXPECTED_PROFILE_SHA256
POWER_PROFILE_SHA256 = power.EXPECTED_PROFILE_SHA256


class _Session:
    def __init__(self, directory: Path):
        self.directory = directory
        self.creation_filetime = CREATION_FILETIME
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
        }


class _Base:
    def __init__(self, directory: Path, observer: str = "FRA"):
        self.session = _Session(directory)
        self.observer = observer
        self.calls = 0
        self.after_context = None

    def context(self) -> dict:
        self.calls += 1
        context = {
            "status": "ready",
            "complete": True,
            "mode": "live",
            "session_id": SESSION_ID,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": self.observer,
            "game_date": GAME_DATE,
            "game_date_raw": GAME_DATE,
        }
        if self.after_context is not None and self.calls >= 3:
            context.update(deepcopy(self.after_context))
        return context


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    """Use real details/power profiles and both real child validators."""

    trade_profile = trade_fixture._profile()
    details_profile = details._load_profile()
    power_profile = power._load_profile(expected_sha256=POWER_PROFILE_SHA256)
    # The graph fixture has a deliberately bounded layout.  The details and
    # power profiles remain the checked-in pinned profiles and are not faked.
    monkeypatch.setattr(trade, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(details, "_active_profile", lambda: details_profile)
    monkeypatch.setattr(power, "_active_profile", lambda: power_profile)
    return trade_profile, details_profile, power_profile


def _reader_with_guards(details_profile, power_profile=None):
    reader = trade_fixture._build_reader()
    for guard in details_profile["code_guards"]:
        raw = bytes.fromhex(guard["hex"])
        reader.data[(MODULE_BASE + int(guard["rva"], 0), len(raw))] = raw
    if power_profile is not None:
        for guard in power_profile["code_guards"]:
            raw = bytes.fromhex(guard["hex"])
            reader.data[(MODULE_BASE + int(guard["rva"], 0), len(raw))] = raw
        reader.data[(trade_fixture.RUNTIME_ONE + power.RUNTIME_TOTAL_POWER_OFFSET, 4)] = trade_fixture._i32(746110)
        reader.data[(trade_fixture.RUNTIME_TWO + power.RUNTIME_TOTAL_POWER_OFFSET, 4)] = trade_fixture._i32(-42)
    return reader


def _set_entry(reader, table: int, values: dict[int, int]) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    for offset, value in values.items():
        raw[offset:offset + 4] = trade_fixture._i32(value)
    reader.data[(address, 0xC0)] = bytes(raw)


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _install_capital(reader, *, node_runtime=trade_fixture.RUNTIME_ONE, scalar=5000) -> None:
    """Install only the bounded FRA capital identity chain."""

    database_root = 0x200600000
    country_table = 0x200610000
    anchor = 0x200620000
    reader.data[(MODULE_BASE + details.CAPITAL_DATABASE_GLOBAL_RVA, 8)] = _qword(database_root)
    reader.data[(database_root + details.CAPITAL_COUNTRY_TABLE_OFFSET, 8)] = _qword(country_table)
    reader.data[(country_table + 7 * details.CAPITAL_VECTOR_STRIDE, 8)] = _qword(COUNTRY_POINTER)
    reader.data[(COUNTRY_POINTER + 0x14C8, 8)] = _qword(anchor)
    reader.data[(anchor + details.CAPITAL_ANCHOR_NODE_OFFSET, 8)] = _qword(node_runtime)
    reader.data[(MODULE_BASE + details.CAPITAL_SCALAR_RVA, 4)] = trade_fixture._i32(scalar)


def _install_dynamic(reader, table: int, *, head: int, item: int, value: int, label: bytes, heap: bool) -> None:
    entry_address = table + 7 * 0xC0
    entry = bytearray(reader.data[(entry_address, 0xC0)])
    entry[details.DYNAMIC_HEAD_OFFSET:details.DYNAMIC_HEAD_OFFSET + 8] = _qword(head)
    reader.data[(entry_address, 0xC0)] = bytes(entry)
    reader.data[(head, 8)] = _qword(item)
    reader.data[(head + details.DYNAMIC_LINK_NEXT_OFFSET, 8)] = _qword(0)
    reader.data[(item + details.DYNAMIC_ITEM_VALUE_OFFSET, 4)] = trade_fixture._i32(value)
    name_object = bytearray(details.DYNAMIC_NAME_OBJECT_SIZE)
    if heap:
        name_pointer = item + 0x1000
        name_object[:8] = _qword(name_pointer)
        name_object[details.DYNAMIC_NAME_CAPACITY_OFFSET:details.DYNAMIC_NAME_CAPACITY_OFFSET + 8] = _qword(32)
        payload = bytearray(details.MAX_DYNAMIC_NAME_BYTES + 1)
        payload[:len(label)] = label
        reader.data[(name_pointer, len(payload))] = bytes(payload)
    else:
        name_object[:min(len(label), details.DYNAMIC_NAME_INLINE_CAPACITY)] = label[:details.DYNAMIC_NAME_INLINE_CAPACITY]
        name_object[details.DYNAMIC_NAME_CAPACITY_OFFSET:details.DYNAMIC_NAME_CAPACITY_OFFSET + 8] = _qword(15)
    reader.data[(item + details.DYNAMIC_ITEM_NAME_OFFSET, details.DYNAMIC_NAME_OBJECT_SIZE)] = bytes(name_object)


def _set_entry_qword(reader, table: int, offset: int, value: int) -> None:
    entry_address = table + 7 * 0xC0
    entry = bytearray(reader.data[(entry_address, 0xC0)])
    entry[offset:offset + 8] = _qword(value)
    reader.data[(entry_address, 0xC0)] = bytes(entry)


def _install_transfer(reader, table: int, *, to_element: int, from_element: int, country_pointer: int, fullref: bytes, to_raw: int, from_raw: int) -> None:
    entry_address = table + 7 * 0xC0
    entry = bytearray(reader.data[(entry_address, 0xC0)])
    entry[0x60:0x68] = _qword(to_element)
    entry[0x78:0x80] = _qword(from_element)
    reader.data[(entry_address, 0xC0)] = bytes(entry)
    for element, raw in ((to_element, to_raw), (from_element, from_raw)):
        reader.data[(element, 8)] = fullref
        reader.data[(element + 8, 4)] = trade_fixture._i32(raw)
        reader.data[(element + 0x18, 8)] = _qword(0)
    reader.data[(0x200610000 + 8 * 8, 8)] = _qword(country_pointer)
    reader.data[(country_pointer + 0x20, 8)] = fullref


def _records(reader, *, include_power=False, country="FRA"):
    trade_record = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER, country)
    assert trade_record["status"] == "observed"
    assert trade.validate_record(trade_record)
    details_record = details.read_fields(reader, MODULE_BASE, trade_record)
    assert details_record["status"] == "observed"
    assert details.validate_record(details_record, trade_record)
    power_record = None
    if include_power:
        power_record = power.read_fields(reader, MODULE_BASE, trade_record)
        assert power_record["status"] == "observed"
        assert power.validate_record(power_record, trade_record)
    return trade_record, details_record, power_record


def _snapshot(trade_record, details_record, power_record=None):
    result = {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": "a0005f03"},
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "trade_income": deepcopy(trade_record),
        "trade_details": deepcopy(details_record),
    }
    if power_record is not None:
        result["trade_power"] = deepcopy(power_record)
    return result


def _report(trade_record, details_record, base, power_record=None):
    request = {
        "installation": str(base.session.directory / "installation.json"),
        "country": trade_record["country"],
        "include_trade_income": True,
        "include_trade_details": True,
    }
    if power_record is not None:
        request["include_trade_power"] = True
    result = {
        "probe": "information-country-resources-runtime",
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": trade_record["country"],
        "target_build": {"version": "1.37.4", "expected_exe_sha256": GAME_SHA256},
        "request": request,
        "identity": {
            "binding_verified": True,
            "process_path_sha256": GAME_SHA256,
            "installation_session_id": SESSION_ID,
            "installation_creation_filetime": CREATION_FILETIME,
            "process_creation_filetime": CREATION_FILETIME,
        },
        "static_contract_guard": {"status": "observed", "checks": {"profile": True}},
        "file_code_guard": {"status": "observed", "checks": {"file": True}},
        "runtime_code_guard": {"status": "observed", "checks": {"runtime": True}},
        "doublepass": {"performed": True, "consistent": True, "mismatches": []},
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": _snapshot(trade_record, details_record, power_record),
        "after": _snapshot(trade_record, details_record, power_record),
        "trade_income": deepcopy(trade_record),
        "trade_details": deepcopy(details_record),
        "completed": True,
    }
    if power_record is not None:
        result["trade_power"] = deepcopy(power_record)
    return result


def _source(tmp_path: Path, report=None, *, observer="FRA"):
    base = _Base(tmp_path, observer)
    calls = []

    def capture(installation, country, *, include_trade_income=False, include_trade_details=False):
        calls.append((installation, country, include_trade_income, include_trade_details))
        return deepcopy(report)

    return NativeTradeDetailsSource(base, capture=capture), base, calls


def _query(node_id: str, fields=None, parameters=None) -> dict:
    return {
        "topic": "T04",
        "object": {"type": "trade_node", "node_id": node_id},
        "fields": ["shares", "sources"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def _records_for(configured, *, include_power=False, alpha=None, beta=None, extras=None):
    reader = _reader_with_guards(configured[1], configured[2] if include_power else None)
    _set_entry(reader, trade_fixture.TABLE_ONE, alpha or {
        0x2C: 1200, 0x28: 3813, 0x1C: 400, 0x40: 17,
    })
    _set_entry(reader, trade_fixture.TABLE_TWO, beta or {
        0x2C: 0, 0x28: 0, 0x1C: -5, 0x40: -1,
    })
    if extras:
        extras(reader)
    return reader, _records(reader, include_power=include_power)


def test_catalog_strict_scope_and_field_metadata(configured, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    item = source.catalog()[0]
    assert item["topic_id"] == "T04"
    assert list(item["fields"]) == ["shares", "sources"]
    assert item["object_types"] == ["trade_node"]
    assert item["parameters"] == {
        "type": "object", "properties": {}, "required": [], "additionalProperties": False,
    }
    assert item["triggers"] == ["query", "periodic"]
    assert item["fields"]["shares"]["raw"] is False
    assert item["fields"]["shares"]["unit"] == "ratio"
    assert item["fields"]["sources"]["raw"] is False
    assert item["fields"]["sources"]["unit"] == "mixed"
    assert "trade_details.nodes[].dynamic_sources" in item["fields"]["sources"]["paths"]
    assert "trade_details.nodes[].transfer_sources" in item["fields"]["sources"]["paths"]
    assert all(item["fields"][field]["complete"] is False for field in ("shares", "sources"))
    assert source.validate_query(_query("alpha"), base.context())["parameters"] == {}
    with pytest.raises(InformationError) as wrong_object:
        source.validate_query({**_query("alpha"), "object": {"type": "country", "country": "FRA"}})
    assert wrong_object.value.code == "invalid_object"
    with pytest.raises(InformationError) as nonempty_parameters:
        source.validate_query(_query("alpha", parameters={"country": "FRA"}))
    assert nonempty_parameters.value.code == "invalid_parameters"
    with pytest.raises(InformationError) as planned:
        source.validate_query(_query("alpha", fields=["merchant_task"]))
    assert planned.value.code == "unknown_field"


def test_known_values_keep_nested_raw_and_filter_rows_with_one_capture(configured, tmp_path: Path):
    reader, (trade_record, details_record, _power_record) = _records_for(configured)
    base = _Base(tmp_path)
    source, base, calls = _source(tmp_path, _report(trade_record, details_record, base))
    result = source.read(_query("alpha"), base.context())
    assert result["complete"] is False
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]
    alpha = next(node for node in details_record["nodes"] if node["node_id"] == "alpha")
    assert result["fields"]["shares"] == {
        "status": "known",
        "value": {"FRA": {"raw": 1200, "raw_hex": "b0040000", "unit": "ratio", "scale": 1000}},
        "unit": "ratio", "scale": 1000, "period": "current",
        "basis": "native_trade_node_share_and_source_caches",
        "value_origin": "copied_native_cache", "complete": False,
    }
    assert result["fields"]["sources"]["status"] == "known"
    sources = result["fields"]["sources"]
    assert sources["unit"] == "mixed"
    assert sources["scale"] == 1000
    assert sources["period"] == "current"
    assert sources["basis"] == "native_trade_node_share_and_source_caches"
    assert sources["value_origin"] == "copied_native_cache"
    assert sources["complete"] is False
    source_value = sources["value"]["FRA"]
    assert source_value["rows"] == alpha["source_rows"]
    assert source_value["capital_status"]["status"] == "unknown"
    assert source_value["dynamic_sources"] == {"status": "known", "items": []}
    assert source_value["transfer_sources"] == {
        "to": {"status": "known", "items": []},
        "from": {"status": "known", "items": []},
    }
    assert source_value["multiplier"] == {
        "status": "unknown", "reason": "TRADE_MULTIPLIER_NOT_CLOSED",
    }
    assert "raw" not in result["fields"]["shares"]
    assert "raw" not in result["fields"]["sources"]
    assert [row["native_key"] for row in alpha["source_rows"]] == [
        "TP_PROVINCE_POWER", "TP_SHIP_POWER", "MERCHANT_DOWNSTREAM_BONUS",
    ]
    audit = result["source"]["provenance"]["trade_details"]
    assert audit["profile_sha256"] == DETAILS_PROFILE_SHA256
    assert audit["requested_node_id"] == "alpha"
    assert audit["node"]["node_id"] == "alpha"
    assert audit["node"]["source_rows"] == alpha["source_rows"]
    assert "nodes" not in audit
    assert audit["record_canonical_sha256"]
    assert audit["trade_income_record_canonical_sha256"]


@pytest.mark.parametrize("share", [0, -1200])
def test_zero_and_negative_share_are_known_raw_values_without_source_fallback(configured, tmp_path: Path, share):
    reader, (trade_record, details_record, _power_record) = _records_for(
        configured, alpha={0x2C: share, 0x28: 3813, 0x1C: 0, 0x40: 0}
    )
    base = _Base(tmp_path)
    source, base, _ = _source(tmp_path, _report(trade_record, details_record, base))
    result = source.read(_query("alpha"), base.context())
    assert result["fields"]["shares"]["status"] == "known"
    assert result["fields"]["shares"]["value"]["FRA"]["raw"] == share
    assert result["fields"]["shares"]["value"]["FRA"]["raw_hex"] == (
        (share & 0xFFFFFFFF).to_bytes(4, "little").hex()
    )
    assert result["fields"]["sources"]["status"] == "known"
    assert result["fields"]["sources"]["value"]["FRA"]["rows"] == [
        {"native_key": "TP_PROVINCE_POWER", "raw": 3813, "raw_hex": "e50e0000", "unit": "trade_power", "scale": 1000},
    ]


def test_capital_dynamic_and_transfer_containers_preserve_raw_contract(configured, tmp_path: Path):
    foreign = 0x200630000
    fullref = bytearray(b"ENG\0\0\0\0\0")
    fullref[4:6] = (8).to_bytes(2, "little", signed=True)

    def extras(reader):
        _install_capital(reader, node_runtime=trade_fixture.RUNTIME_ONE, scalar=5000)
        _install_dynamic(
            reader, trade_fixture.TABLE_ONE, head=0x200640000, item=0x200650000,
            value=-123, label=b"inline-source\0", heap=False,
        )
        _install_dynamic(
            reader, trade_fixture.TABLE_TWO, head=0x200660000, item=0x200670000,
            value=456, label=b"heap-source\0", heap=True,
        )
        _install_transfer(
            reader, trade_fixture.TABLE_ONE, to_element=0x200680000,
            from_element=0x200690000, country_pointer=foreign, fullref=bytes(fullref),
            to_raw=-321, from_raw=654,
        )

    reader, (trade_record, details_record, _power_record) = _records_for(configured, extras=extras)
    assert details.validate_record(details_record, trade_record)
    base = _Base(tmp_path)
    source, base, _ = _source(tmp_path, _report(trade_record, details_record, base))
    result = source.read(_query("alpha", ["shares", "sources"]), base.context())
    assert result["fields"]["shares"]["status"] == "known"
    value = result["fields"]["sources"]["value"]["FRA"]
    assert [row["native_key"] for row in value["rows"]] == [
        "TP_PROVINCE_POWER", "TP_SHIP_POWER", "TRADE_POWER_CAPITAL", "MERCHANT_DOWNSTREAM_BONUS",
    ]
    assert value["capital_status"] == {
        "status": "known", "included": True, "raw": 5000,
        "raw_hex": "88130000", "unit": "trade_power", "scale": 1000,
    }
    assert value["dynamic_sources"]["status"] == "known"
    assert [item["raw"] for item in value["dynamic_sources"]["items"]] == [-123]
    assert value["dynamic_sources"]["items"][0]["name"] == {
        "status": "unknown", "reason": "DYNAMIC_SOURCE_NAME_LOOKUP_NOT_RESOLVED",
        "raw_hex": "696e6c696e652d736f7572636500",
    }
    transfers = value["transfer_sources"]
    assert transfers["to"]["status"] == "known"
    assert transfers["from"]["status"] == "known"
    to_item, from_item = transfers["to"]["items"][0], transfers["from"]["items"][0]
    assert to_item["fullref_raw_hex"] == bytes(fullref).hex()
    assert to_item["slot"] == 8
    assert to_item["raw"] == -321
    assert to_item["direction"] == "to"
    assert from_item["raw"] == 654
    assert from_item["direction"] == "from"
    # The bounded child exposes the tag only after the country-table/fullref
    # equality check succeeds; the container direction still owns the sign.
    assert to_item["country"] == "ENG"

    beta = next(node for node in details_record["nodes"] if node["node_id"] == "beta")
    beta_value = NativeTradeDetailsSource._field_from_node(beta, "sources", country="FRA")["value"]["FRA"]
    assert beta_value["capital_status"]["status"] == "known"
    assert beta_value["capital_status"]["included"] is False


def test_extra_read_failures_keep_base_values_and_mark_only_extra_unknown(configured, tmp_path: Path):
    def extras(reader):
        _set_entry_qword(reader, trade_fixture.TABLE_TWO, details.DYNAMIC_HEAD_OFFSET, 0xDEAD)
        _set_entry_qword(reader, trade_fixture.TABLE_TWO, 0x60, 0xDEAE)

    reader, (trade_record, details_record, _power_record) = _records_for(configured, extras=extras)
    assert details.validate_record(details_record, trade_record)
    base = _Base(tmp_path)
    source, base, _ = _source(tmp_path, _report(trade_record, details_record, base))
    result = source.read(_query("beta", ["shares", "sources"]), base.context())
    assert result["fields"]["shares"]["status"] == "known"
    sources = result["fields"]["sources"]
    assert sources["status"] == "known"
    selected = sources["value"]["FRA"]
    assert selected["rows"] == [{
        "native_key": "TP_SHIP_POWER", "raw": -5,
        "raw_hex": "fbffffff", "unit": "trade_power", "scale": 1000,
    }]
    assert selected["dynamic_sources"]["status"] == "unknown"
    assert selected["transfer_sources"]["to"]["status"] == "unknown"


def test_unknown_node_is_explicit_after_real_parent_and_child_validation(configured, tmp_path: Path):
    _reader, (trade_record, details_record, _power_record) = _records_for(configured)
    base = _Base(tmp_path)
    source, base, calls = _source(tmp_path, _report(trade_record, details_record, base))
    result = source.read(_query("not_a_native_node"), base.context())
    assert result["fields"] == {
        "shares": {"status": "unknown", "reason": "NODE_NOT_FOUND"},
        "sources": {"status": "unknown", "reason": "NODE_NOT_FOUND"},
    }
    assert calls and calls[0][2:] == (True, True)


def test_parent_or_details_tamper_never_returns_known(configured, tmp_path: Path):
    _reader, (trade_record, details_record, _power_record) = _records_for(configured)
    base = _Base(tmp_path)
    report = _report(trade_record, details_record, base)
    report["after"]["trade_income"]["total_raw"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "TRADE_DETAILS_TRADE_INCOME" in result["fields"]["shares"]["reason"]

    report = _report(trade_record, details_record, base)
    report["after"]["trade_details"]["nodes"][0]["share_raw"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "TRADE_DETAILS_AFTER" in result["fields"]["shares"]["reason"]


def test_context_change_and_capture_exception_are_checked_after_attempt(configured, tmp_path: Path):
    _reader, (trade_record, details_record, _power_record) = _records_for(configured)
    base = _Base(tmp_path)
    report = _report(trade_record, details_record, base)
    source, base, calls = _source(tmp_path, report)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "CONTEXT_CHANGED" in result["fields"]["shares"]["reason"]
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]

    base = _Base(tmp_path)
    calls = []

    def failing_capture(*args, **kwargs):
        calls.append(kwargs)
        raise RuntimeError("reader failed")

    source = NativeTradeDetailsSource(base, capture=failing_capture)
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert result["fields"]["shares"]["reason"] == "TRADE_DETAILS_CAPTURE_FAILED:RuntimeError"
    assert calls == [{"include_trade_income": True, "include_trade_details": True}]


def test_polling_is_query_only(configured, tmp_path: Path):
    source, base, calls = _source(tmp_path)
    assert source.poll_events(base.context(), {"offset": 2}) == {
        "events": [], "cursor": {"offset": 2}, "complete": True, "gaps": [],
    }
    assert calls == []


class _Primary:
    event_types = ()

    def __init__(self, base):
        self.base = base

    def context(self):
        return self.base.context()

    def catalog(self):
        return [{
            "topic_id": "T04",
            "fields": {
                "country_power": {"coverage": "partial"},
                "total_power": {"coverage": "partial"},
            },
            "object_types": ["trade_node"],
            "observer_roles": ["country"],
            "observer_scope": ["FRA"],
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            "supported_versions": ["1.37.4"],
            "triggers": ["query", "periodic"],
            "context_scope": "country_scope",
        }]

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": cursor, "complete": True, "gaps": []}


def test_same_t04_composite_routes_power_and_details_with_identical_empty_schema(configured, tmp_path: Path):
    reader, (trade_record, details_record, power_record) = _records_for(configured, include_power=True)
    base = _Base(tmp_path)
    details_source, _base, details_calls = _source(tmp_path, _report(trade_record, details_record, base, power_record))
    power_calls = []

    def power_capture(installation, country, *, include_trade_income=False, include_trade_power=False):
        power_calls.append((installation, country, include_trade_income, include_trade_power))
        return _report(trade_record, details_record, base, power_record)

    power_source = NativeTradePowerSource(base, capture=power_capture)
    composite = CompositeSource(_Primary(base), [power_source, details_source])
    catalog = composite.catalog()[0]
    assert set(catalog["fields"]) == {"country_power", "total_power", "power_share_percent", "shares", "sources"}
    assert catalog["parameters"]["additionalProperties"] is False
    query = _query("alpha", ["country_power", "shares", "sources"])
    context = base.context()
    result = composite.read(query, context)
    assert result["fields"]["country_power"]["status"] == "known"
    assert result["fields"]["shares"]["status"] == "known"
    assert result["fields"]["sources"]["status"] == "known"
    assert power_calls == [(tmp_path / "installation.json", "FRA", True, True)]
    assert details_calls == [(tmp_path / "installation.json", "FRA", True, True)]


def _install_dynamic_items(reader, table: int, labels: list[bytes]) -> None:
    """Install a bounded multi-item chain for real details validation."""

    entry_address = table + 7 * 0xC0
    entry = bytearray(reader.data[(entry_address, 0xC0)])
    head = 0x200700000
    entry[details.DYNAMIC_HEAD_OFFSET:details.DYNAMIC_HEAD_OFFSET + 8] = _qword(head)
    reader.data[(entry_address, 0xC0)] = bytes(entry)
    for index, label in enumerate(labels):
        link = head + index * 0x100
        item = 0x200720000 + index * 0x2000
        next_link = head + (index + 1) * 0x100 if index + 1 < len(labels) else 0
        reader.data[(link, 8)] = _qword(item)
        reader.data[(link + details.DYNAMIC_LINK_NEXT_OFFSET, 8)] = _qword(next_link)
        reader.data[(item + details.DYNAMIC_ITEM_VALUE_OFFSET, 4)] = trade_fixture._i32(index + 1)
        name_object = bytearray(details.DYNAMIC_NAME_OBJECT_SIZE)
        if len(label) <= details.DYNAMIC_NAME_INLINE_CAPACITY:
            name_object[:len(label)] = label
            name_object[details.DYNAMIC_NAME_CAPACITY_OFFSET:details.DYNAMIC_NAME_CAPACITY_OFFSET + 8] = _qword(15)
        else:
            name_pointer = item + 0x1000
            name_object[:8] = _qword(name_pointer)
            name_object[details.DYNAMIC_NAME_CAPACITY_OFFSET:details.DYNAMIC_NAME_CAPACITY_OFFSET + 8] = _qword(32)
            payload = bytearray(details.MAX_DYNAMIC_NAME_BYTES + 1)
            payload[:len(label)] = label
            reader.data[(name_pointer, len(payload))] = bytes(payload)
        reader.data[(item + details.DYNAMIC_ITEM_NAME_OFFSET, details.DYNAMIC_NAME_OBJECT_SIZE)] = bytes(name_object)


def _localization_entry(key: str, *, text: str | None = None, status: str = "observed", value_hex: str | None = None) -> dict:
    if status == "unknown":
        return {"key": key, "status": "unknown", "unknown_reason": "LOCALIZATION_KEY_UNRESOLVED"}
    if value_hex is None:
        value_hex = (text if text is not None else key).encode("utf-8").hex()
    return {
        "key": key,
        "status": status,
        "value_hex": value_hex,
        "byte_length": len(bytes.fromhex(value_hex)) if all(char in "0123456789abcdefABCDEF" for char in value_hex) and len(value_hex) % 2 == 0 else 0,
    }


def _localization_capture(base: _Base, entries: dict[str, dict], calls: list[list[str]], *, mutate=None, failure=None):
    """Build a real NativeLocalizationReader capture seam."""

    def capture(_installation, country, keys):
        assert country == "FRA"
        calls.append(list(keys))
        if failure is not None:
            raise failure
        selected = {key: deepcopy(entries.get(key, _localization_entry(key, status="unknown"))) for key in keys}
        report = {
            "status": "observed",
            "read_only": True,
            "profile": {"sha256": "trade-details-test-localization-profile"},
            "probe_script_sha256": "trade-details-test-localization-probe",
            "identity": {
                "binding_verified": True,
                "installation_session_id": SESSION_ID,
                "process_path_sha256": GAME_SHA256,
            },
            "request": {"country": country, "keys": list(keys)},
            "static_contract_guard": {"status": "observed"},
            "file_code_guard": {"status": "observed"},
            "runtime_code_guard": {"status": "observed"},
            "doublepass": {"performed": True, "consistent": True},
            "before": {"status": "observed", "game_date": {"raw": GAME_DATE}},
            "after": {"status": "observed", "game_date": {"raw": GAME_DATE}},
            "language": {"status": "observed", "text": "l_english"},
            "entries": selected,
            "cleanup": {"handle_close": {"closed": True}},
        }
        if mutate is not None:
            mutate()
        return report

    return capture


def _localized_trade_source(configured, tmp_path: Path, labels: list[bytes], entries: dict[str, dict], *, mutate=None, failure=None):
    def extras(reader):
        _install_dynamic_items(reader, trade_fixture.TABLE_ONE, labels)

    reader, (trade_record, details_record, _power_record) = _records_for(configured, extras=extras)
    assert details.validate_record(details_record, trade_record)
    base = _Base(tmp_path)
    base.session.record["native_text_codec"] = "utf8"
    report = _report(trade_record, details_record, base)
    parent_calls = []

    def parent_capture(installation, country, *, include_trade_income=False, include_trade_details=False):
        parent_calls.append((installation, country, include_trade_income, include_trade_details))
        return deepcopy(report)

    localization_calls: list[list[str]] = []
    localization_capture = _localization_capture(
        base, entries, localization_calls, mutate=mutate, failure=failure,
    )
    localization_reader = NativeLocalizationReader(base, capture=localization_capture)
    source = NativeTradeDetailsSource(
        base, capture=parent_capture, localization_reader=localization_reader,
    )
    return source, base, parent_calls, localization_calls


def test_dynamic_name_literal_is_localized_by_real_reader_and_keeps_key_provenance(configured, tmp_path: Path):
    key = "dynamic_trade_label"
    source, base, parent_calls, localization_calls = _localized_trade_source(
        configured, tmp_path, [key.encode("ascii") + b"\0"],
        {key: _localization_entry(key, text="动态来源")},
    )
    result = source.read(_query("alpha", ["sources"]), base.context())
    assert result["fields"]["sources"]["status"] == "known"
    name = result["fields"]["sources"]["value"]["FRA"]["dynamic_sources"]["items"][0]["name"]
    assert name["status"] == "known"
    assert name["value"] == "动态来源"
    assert name["key"] == key
    assert name["raw_hex"] == (key.encode("ascii") + b"\0").hex()
    assert name["language"] == "l_english"
    assert name["codec"] == "utf8"
    assert name["raw_template_hex"] == "e58aa8e68081e69da5e6ba90"
    assert name["reader_provenance"]["reader"] == "bounded_ReadProcessMemory"
    assert result["source"]["name_localization"]["keys"] == [key]
    assert localization_calls == [[key]]
    assert parent_calls and parent_calls[0][2:] == (True, True)


def test_dynamic_name_filters_non_ascii_and_deduplicates_reader_keys(configured, tmp_path: Path):
    key = "valid_dynamic_label"
    labels = [
        key.encode("ascii") + b"\0",
        key.encode("ascii") + b"\0",
        b"bad\xff\0",
        b"bad\x01\0",
    ]
    source, base, _parent_calls, localization_calls = _localized_trade_source(
        configured, tmp_path, labels, {key: _localization_entry(key, text="有效")},
    )
    result = source.read(_query("alpha", ["sources"]), base.context())
    items = result["fields"]["sources"]["value"]["FRA"]["dynamic_sources"]["items"]
    assert localization_calls == [[key]]
    assert items[0]["name"]["value"] == "有效"
    assert items[1]["name"]["value"] == "有效"
    for item, raw in zip(items[2:], labels[2:]):
        assert item["name"]["status"] == "unknown"
        assert item["name"]["reason"] == "DYNAMIC_SOURCE_NAME_KEY_INVALID"
        assert item["name"]["raw_hex"] == raw.hex()


@pytest.mark.parametrize(
    ("entry", "reason", "extra"),
    [
        (_localization_entry("dynamic_template", text="[Root.GetName]"), "DYNAMIC_LOCALIZATION_UNRESOLVED", "template"),
        (_localization_entry("missing_dynamic", status="unknown"), "LOCALIZATION_KEY_UNRESOLVED", None),
        (_localization_entry("bad_dynamic", value_hex="zz"), "LOCALIZATION_BYTES_INVALID", None),
    ],
)
def test_dynamic_name_reader_gaps_keep_unknown_name_and_native_sources(
    configured, tmp_path: Path, entry, reason, extra,
):
    key = entry["key"]
    source, base, _parent_calls, localization_calls = _localized_trade_source(
        configured, tmp_path, [key.encode("ascii") + b"\0"], {key: entry},
    )
    result = source.read(_query("alpha", ["sources"]), base.context())
    assert result["fields"]["sources"]["status"] == "known"
    name = result["fields"]["sources"]["value"]["FRA"]["dynamic_sources"]["items"][0]["name"]
    assert name["status"] == "unknown"
    assert name["reason"] == reason
    assert "value" not in name
    assert name["key"] == key and name["raw_hex"] == (key.encode("ascii") + b"\0").hex()
    if extra == "template":
        assert name["template"] == "[Root.GetName]"
        assert name["raw_template_hex"] == "5b526f6f742e4765744e616d655d"
    assert result["fields"]["sources"]["value"]["FRA"]["rows"]
    assert localization_calls == [[key]]


def test_dynamic_name_lookup_exception_keeps_other_source_values(configured, tmp_path: Path):
    key = "lookup_error_dynamic"
    source, base, _parent_calls, localization_calls = _localized_trade_source(
        configured, tmp_path, [key.encode("ascii") + b"\0"], {}, failure=RuntimeError("cache unavailable"),
    )
    result = source.read(_query("alpha", ["shares", "sources"]), base.context())
    assert result["fields"]["shares"]["status"] == "known"
    assert result["fields"]["sources"]["status"] == "known"
    name = result["fields"]["sources"]["value"]["FRA"]["dynamic_sources"]["items"][0]["name"]
    assert name["status"] == "unknown"
    assert name["reason"] == "LOCALIZATION_READ_FAILED"
    assert "value" not in name
    assert result["fields"]["sources"]["value"]["FRA"]["rows"]
    assert localization_calls == [[key]]


def test_dynamic_name_context_change_retracts_all_requested_fields(configured, tmp_path: Path):
    key = "context_change_dynamic"

    def mutate():
        source_base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}

    source, source_base, _parent_calls, localization_calls = _localized_trade_source(
        configured, tmp_path, [key.encode("ascii") + b"\0"],
        {key: _localization_entry(key, text="不应发布")}, mutate=mutate,
    )
    result = source.read(_query("alpha", ["shares", "sources"]), source_base.context())
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert "CONTEXT" in result["fields"]["shares"]["reason"]
    assert localization_calls == [[key]]


def test_dynamic_name_zero_list_and_shares_only_do_not_invoke_reader(configured, tmp_path: Path):
    reader, (trade_record, details_record, _power_record) = _records_for(configured)
    base = _Base(tmp_path)
    base.session.record["native_text_codec"] = "utf8"
    report = _report(trade_record, details_record, base)
    calls: list[list[str]] = []

    class NoCallReader:
        def localized_text(self, *_args):
            calls.append(list(_args[-1]))
            raise AssertionError("empty dynamic list must not localize")

    parent_calls = []

    def parent_capture(*args, **kwargs):
        parent_calls.append(kwargs)
        return deepcopy(report)

    source = NativeTradeDetailsSource(base, capture=parent_capture, localization_reader=NoCallReader())
    source.read(_query("alpha", ["sources"]), base.context())
    source.read(_query("alpha", ["shares"]), base.context())
    assert calls == []
    assert len(parent_calls) == 2
