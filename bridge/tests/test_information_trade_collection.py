from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import types

import pytest

from bridge.information.model import InformationError
from bridge.information.composite import CompositeSource
from bridge.information import trade_income_memory as trade_memory
from bridge.information.static_data import StaticTradeSource
from bridge.information.trade_collection import NativeTradeCollectionSource
from bridge.information.trade_home import NativeTradeHomeSource
from bridge.information.trade_income import NativeTradeIncomeSource
from bridge.tests import test_information_trade_income_memory as old_income


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
# Keep the adapter test pinned to the production 1.37.4 trade-income profile;
# the bounded memory module itself is replaced with the deterministic fake
# below, so these tests never attach to a game process.
PROFILE_SHA256 = "1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd"
SESSION_ID = "session-trade-collection-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728


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
            "observer": "FRA",
            "game_date": GAME_DATE,
            "game_date_raw": GAME_DATE,
        }
        if self.after_context is not None and self.calls >= 3:
            context.update(deepcopy(self.after_context))
        return context


def _raw_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False).hex()


def _node(node_id: str, cache_income_raw: int, *, eligible: bool = True) -> dict:
    income_raw = cache_income_raw if eligible else 0
    predicate_rva = "0x8f440" if eligible else "0x8f450"
    return {
        "node_id": node_id,
        "cache_income_raw": cache_income_raw,
        "cache_income_raw_hex": _raw_hex(cache_income_raw),
        "income_raw": income_raw,
        "income_raw_hex": _raw_hex(income_raw),
        "eligible": eligible,
        "value_origin": (
            "copied_native_cache"
            if eligible else "derived_from_copied_native_caches"
        ),
        "flags": {
            "flag_ac": 0 if eligible else 1,
            "flag_ad": 0,
            "flag_ae": 1 if eligible else 0,
            "predicate_rva": predicate_rva,
        },
        "raw_graph": {
            "definition_pointer_raw_hex": "0011223344556677",
            "predicate_rva": predicate_rva,
        },
    }


def _record(*, nodes: list[dict] | None = None, valid: bool = True) -> dict:
    if nodes is None:
        nodes = [_node("champagne", 3813), _node("lubeck", 0)]
    total = 0
    for node in nodes:
        total = (total + node["income_raw"]) & 0xFFFFFFFF
        if total & 0x80000000:
            total -= 0x100000000
    return {
        "status": "observed",
        "_valid": valid,
        "profile_sha256": PROFILE_SHA256,
        "static_contract_guard": {"status": "observed", "checks": {"profile": True}},
        "runtime_code_guard": {"status": "observed", "checks": {"trade": True}},
        "country": "FRA",
        "country_fullref_raw_hex": "465241007a000001",
        "country_slot": 122,
        "graph": {
            "node_count": len(nodes) + 1,
            "real_node_count": len(nodes),
            "placeholder_count": 1,
        },
        "nodes": deepcopy(nodes),
        "total_raw": total,
        "total_raw_hex": _raw_hex(total),
        "basis": "native_trade_node_country_income_cache",
        "unit": "ducats",
        "scale": 1000,
        "period": "month",
        "value_origin": "derived_from_copied_native_caches",
    }


def _snapshot(record: dict) -> dict:
    return {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": _raw_hex(GAME_DATE)},
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "trade_income": deepcopy(record),
    }


def _report(record: dict, base: _Base) -> dict:
    return {
        "probe": "information-country-resources-runtime",
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": "FRA",
        "target_build": {"version": "1.37.4", "expected_exe_sha256": GAME_SHA256},
        "request": {
            "installation": str(base.session.directory / "installation.json"),
            "country": "FRA",
            "include_trade_income": True,
        },
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
        "before": _snapshot(record),
        "after": _snapshot(record),
        "trade_income": deepcopy(record),
        "completed": True,
    }


@pytest.fixture
def fake_trade_memory(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict] = []
    module = types.ModuleType("bridge.information.trade_income_memory")
    module.EXPECTED_PROFILE_SHA256 = PROFILE_SHA256

    def validate_record(record):
        calls.append(record)
        return isinstance(record, dict) and record.get("_valid") is True

    module.validate_record = validate_record
    monkeypatch.setitem(sys.modules, "bridge.information.trade_income_memory", module)
    return calls


def _source(tmp_path: Path, report=None):
    base = _Base(tmp_path)
    calls: list[tuple[Path, str, bool]] = []

    def capture(installation, country, *, include_trade_income=False):
        calls.append((installation, country, include_trade_income))
        return deepcopy(report if report is not None else _report(_record(), base))

    return NativeTradeIncomeSource(base, capture=capture), base, calls


def _query(object_: dict, fields=None, parameters=None) -> dict:
    return {
        "topic": "T05",
        "object": object_,
        "fields": ["income"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def _put(data: dict[tuple[int, int], bytes], address: int, payload: bytes) -> None:
    data[(address, len(payload))] = payload


def _build_real_profile_reader() -> tuple[old_income.Reader, dict]:
    """Build the old bounded fake reader from the pinned production profile.

    The graph addresses stay synthetic, but every profile layout value and all
    16 production code guards come from ``trade_income_memory._load_profile``.
    This exercises the actual bounded reader and validator without a game/RPM.
    """
    profile = trade_memory._load_profile()
    layout = trade_memory._profile_layout(profile)
    module = old_income.MODULE_BASE
    country = old_income.COUNTRY_POINTER
    manager = old_income.MANAGER
    vector = old_income.VECTOR
    game = old_income.GAME
    province_base = old_income.PROVINCE_BASE
    definitions = (
        (old_income.DEF_ONE, old_income.VTABLE_ONE, 1, b"alpha", old_income.TABLE_ONE, 3813, (0, 0, 1)),
        (old_income.DEF_TWO, old_income.VTABLE_TWO, 2, b"beta", old_income.TABLE_TWO, -17, (1, 0, 1)),
    )
    data: dict[tuple[int, int], bytes] = {}
    for guard in profile["code_guards"]:
        raw = bytes.fromhex(guard["hex"])
        _put(data, module + int(guard["rva"], 0), raw)

    _put(data, module + layout["manager_global_rva"], old_income._qword(manager))
    _put(data, manager + layout["vector_begin_offset"], old_income._qword(vector))
    _put(data, manager + layout["vector_end_offset"], old_income._qword(vector + 3 * layout["vector_stride"]))
    _put(
        data,
        vector,
        old_income._qword(old_income.DEF_ONE)
        + old_income._qword(old_income.DEF_NULL)
        + old_income._qword(old_income.DEF_TWO),
    )
    _put(data, module + layout["game_global_rva"], old_income._qword(game))
    _put(data, game + layout["province_base_offset"], old_income._qword(province_base))
    fullref = bytearray(b"FRA\0\0\0\0\0")
    fullref[layout["country_slot_offset"]:layout["country_slot_offset"] + 2] = (7).to_bytes(2, "little", signed=True)
    _put(data, country + layout["country_fullref_offset"], bytes(fullref))
    _put(data, module + layout["special_slot_global_rva"], old_income._i32(9))

    for definition, vtable, center, key, table, cache, flags in definitions:
        _put(data, definition, old_income._qword(vtable))
        _put(data, vtable + layout["definition_predicate_slot"], old_income._qword(module + layout["predicate_true_rva"]))
        key_object = bytearray(layout["string_size"])
        key_object[:len(key)] = key
        key_object[len(key)] = 0
        key_object[layout["string_length_offset"]:layout["string_length_offset"] + 8] = len(key).to_bytes(8, "little")
        key_object[layout["string_capacity_offset"]:layout["string_capacity_offset"] + 8] = (15).to_bytes(8, "little")
        _put(data, definition + layout["definition_key_offset"], bytes(key_object))
        _put(data, definition + layout["definition_center_offset"], old_income._i32(center))
        province = province_base + center * layout["province_stride"]
        runtime = old_income.RUNTIME_ONE if center == 1 else old_income.RUNTIME_TWO
        _put(data, province + layout["province_trade_node_offset"], old_income._qword(runtime))
        _put(data, runtime + layout["node_definition_offset"], old_income._qword(definition))
        _put(data, runtime + layout["entry_table_offset"], old_income._qword(table))
        entry = bytearray(layout["entry_stride"])
        entry[layout["entry_income_offset"]:layout["entry_income_offset"] + 4] = old_income._i32(cache)
        entry[layout["entry_flags_offset"]:layout["entry_flags_offset"] + 3] = bytes(flags)
        _put(data, table + 7 * layout["entry_stride"], bytes(entry))

    _put(data, old_income.DEF_NULL, old_income._qword(old_income.VTABLE_NULL))
    _put(data, old_income.VTABLE_NULL + layout["definition_predicate_slot"], old_income._qword(module + layout["predicate_false_rva"]))
    return old_income.Reader(data), profile


def _real_report_source(tmp_path: Path, record: dict):
    base = _Base(tmp_path)
    report = _report(record, base)
    source, source_base, capture_calls = _source(tmp_path, report)
    return source, source_base, capture_calls, report


def test_collection_catalog_is_distinct_and_transfer_stays_unsupported(
    fake_trade_memory, tmp_path: Path,
):
    source, base, _ = _source(tmp_path)
    fields = source.catalog()[0]["fields"]
    assert fields["income"]["unit"] == "ducats"
    assert fields["income"]["scale"] == 1000
    assert fields["income"]["period"] == "month"
    assert fields["income"]["value_origin"] == "derived_from_copied_native_caches"
    collection_catalog = fields["collection"]
    assert collection_catalog["coverage"] == "partial"
    assert collection_catalog["unit"] == "state"
    assert collection_catalog["scale"] == 1
    assert collection_catalog["period"] == "current"
    assert collection_catalog["basis"] == "native_trade_node_collection_predicate"
    assert collection_catalog["value_origin"] == "derived_from_copied_native_flags"
    assert collection_catalog["complete"] is False
    assert source.validate_query(
        _query({"type": "country", "country": "FRA"}, fields=["income", "collection"]),
        base.context(),
    )["fields"] == ["income", "collection"]
    with pytest.raises(InformationError) as error:
        source.validate_query(
            _query({"type": "country", "country": "FRA"}, fields=["transfer"])
        )
    assert error.value.code == "unknown_field"


def test_country_collection_keeps_native_order_and_one_capture_for_two_fields(
    fake_trade_memory, tmp_path: Path,
):
    nodes = [
        _node("rheinland", 7, eligible=False),
        _node("champagne", 0, eligible=True),
        _node("lubeck", 3, eligible=True),
    ]
    base = _Base(tmp_path)
    report = _report(_record(nodes=nodes), base)
    source, base, capture_calls = _source(tmp_path, report)
    result = source.read(
        _query(
            {"type": "country", "country": "FRA"},
            fields=["income", "collection"],
        ),
        base.context(),
    )
    assert capture_calls == [(tmp_path / "installation.json", "FRA", True)]
    assert result["fields"]["income"]["value"] == 3
    assert result["fields"]["collection"] == {
        "status": "known",
        "value": ["champagne", "lubeck"],
        "unit": "state",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
    }
    audit_nodes = result["source"]["provenance"]["trade_income"]["nodes"]
    assert [node["node_id"] for node in audit_nodes] == [
        "rheinland", "champagne", "lubeck",
    ]
    assert [node["eligible"] for node in audit_nodes] == [False, True, True]
    assert audit_nodes[0]["flags"]["flag_ac"] == 1
    assert audit_nodes[1]["flags"]["predicate_rva"] == "0x8f440"


@pytest.mark.parametrize(
    ("node_id", "cache", "eligible", "expected_collection", "expected_income"),
    [
        ("champagne", 3813, True, True, 3813),
        ("rheinland", 7, False, False, 0),
        ("lubeck", 0, True, True, 0),
    ],
)
def test_trade_node_collection_reflects_true_false_and_zero_cache(
    fake_trade_memory,
    tmp_path: Path,
    node_id: str,
    cache: int,
    eligible: bool,
    expected_collection: bool,
    expected_income: int,
):
    base = _Base(tmp_path)
    source, base, _ = _source(
        tmp_path,
        _report(_record(nodes=[_node(node_id, cache, eligible=eligible)]), base),
    )
    result = source.read(
        _query(
            {"type": "trade_node", "node_id": node_id},
            fields=["income", "collection"],
        ),
        base.context(),
    )
    assert result["fields"]["collection"]["status"] == "known"
    assert result["fields"]["collection"]["value"] is expected_collection
    assert result["fields"]["income"]["value"] == expected_income
    node_audit = result["source"]["provenance"]["trade_income"]["nodes"]
    assert len(node_audit) == 1
    assert node_audit[0]["eligible"] is eligible


def test_empty_collection_is_known_empty_list(fake_trade_memory, tmp_path: Path):
    nodes = [_node("rheinland", 9, eligible=False), _node("lubeck", 0, eligible=False)]
    base = _Base(tmp_path)
    source, base, _ = _source(tmp_path, _report(_record(nodes=nodes), base))
    result = source.read(
        _query({"type": "country", "country": "FRA"}, fields=["collection"]),
        base.context(),
    )
    assert result["fields"]["collection"] == {
        "status": "known",
        "value": [],
        "unit": "state",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
    }


def test_missing_node_is_unknown_and_not_false(fake_trade_memory, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    result = source.read(
        _query({"type": "trade_node", "node_id": "unknown_node"}, fields=["collection"]),
        base.context(),
    )
    assert result["fields"]["collection"] == {
        "status": "unknown", "reason": "NODE_NOT_FOUND",
    }


def test_corrupt_capture_retracts_income_and_collection(fake_trade_memory, tmp_path: Path):
    base = _Base(tmp_path)
    report = _report(_record(), base)
    report["after"]["trade_income"]["nodes"][0]["eligible"] = "true"
    source, base, _ = _source(tmp_path, report)
    result = source.read(
        _query({"type": "country", "country": "FRA"}, fields=["income", "collection"]),
        base.context(),
    )
    assert result["fields"]["income"]["status"] == "unknown"
    assert result["fields"]["collection"]["status"] == "unknown"
    assert "ELIGIBILITY" in result["fields"]["collection"]["reason"]


def test_context_change_retracts_collection_without_false(fake_trade_memory, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(
        _query({"type": "country", "country": "FRA"}, fields=["collection"]),
        base.context(),
    )
    assert result["fields"]["collection"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["collection"]["reason"]


def test_income_only_query_remains_compatible(fake_trade_memory, tmp_path: Path):
    source, base, capture_calls = _source(tmp_path)
    result = source.read(
        _query({"type": "country", "country": "FRA"}, fields=["income"]),
        base.context(),
    )
    assert set(result["fields"]) == {"income"}
    assert result["fields"]["income"]["value"] == 3813
    assert capture_calls == [(tmp_path / "installation.json", "FRA", True)]


def test_real_pinned_profile_reader_validator_and_collection_projection(tmp_path: Path):
    reader, profile = _build_real_profile_reader()
    assert profile["profile_id"] == "trade-income-memory-1374"
    record = trade_memory.read_fields(reader, old_income.MODULE_BASE, old_income.COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert trade_memory.validate_record(record)
    assert [node["node_id"] for node in record["nodes"]] == ["alpha", "beta"]
    assert [node["eligible"] for node in record["nodes"]] == [True, False]

    source, base, capture_calls, _report_value = _real_report_source(tmp_path, record)
    country = source.read(
        _query(
            {"type": "country", "country": "FRA"},
            fields=["income", "collection"],
        ),
        base.context(),
    )
    assert country["fields"]["collection"]["value"] == ["alpha"]
    assert country["fields"]["income"]["value"] == 3813
    assert capture_calls == [(tmp_path / "installation.json", "FRA", True)]
    audit_nodes = country["source"]["provenance"]["trade_income"]["nodes"]
    assert [(node["node_id"], node["eligible"]) for node in audit_nodes] == [
        ("alpha", True), ("beta", False),
    ]

    alpha = source.read(
        _query({"type": "trade_node", "node_id": "alpha"}, fields=["collection"]),
        base.context(),
    )
    beta = source.read(
        _query({"type": "trade_node", "node_id": "beta"}, fields=["collection"]),
        base.context(),
    )
    assert alpha["fields"]["collection"]["value"] is True
    assert beta["fields"]["collection"]["value"] is False
    assert len(capture_calls) == 3


def test_real_validator_rejects_actual_record_tamper_and_adapter_retracts(tmp_path: Path):
    reader, _profile = _build_real_profile_reader()
    record = trade_memory.read_fields(reader, old_income.MODULE_BASE, old_income.COUNTRY_POINTER)
    assert trade_memory.validate_record(record)
    changed = deepcopy(record)
    changed["nodes"][0]["flag_ac"] = 1
    assert not trade_memory.validate_record(changed)

    source, base, _capture_calls, _report_value = _real_report_source(tmp_path, changed)
    result = source.read(
        _query(
            {"type": "country", "country": "FRA"},
            fields=["income", "collection"],
        ),
        base.context(),
    )
    assert result["fields"]["income"]["status"] == "unknown"
    assert result["fields"]["collection"]["status"] == "unknown"


def test_real_record_context_change_retracts_collection(tmp_path: Path):
    reader, _profile = _build_real_profile_reader()
    record = trade_memory.read_fields(reader, old_income.MODULE_BASE, old_income.COUNTRY_POINTER)
    assert trade_memory.validate_record(record)
    source, base, _capture_calls, _report_value = _real_report_source(tmp_path, record)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(
        _query({"type": "country", "country": "FRA"}, fields=["collection"]),
        base.context(),
    )
    assert result["fields"]["collection"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["collection"]["reason"]


# --- T02.collect_node adapter: a separate owner over the shared T05 source ---


def _collection_query(object_: dict, fields=None, parameters=None) -> dict:
    return {
        "topic": "T02",
        "object": object_,
        "fields": ["collect_node"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def _upstream_result(base: _Base, field: dict, *, source_name="NativeTradeIncomeSource") -> dict:
    return {
        "topic": "T05",
        "fields": {"collection": deepcopy(field)},
        "source": {
            "name": source_name,
            "mode": "live",
            "status": "observed",
            "session_id": SESSION_ID,
            "observer": "FRA",
            "complete": False,
            "provenance": {
                "trade_income": {
                    "record_canonical_sha256": "a" * 64,
                    "nodes": [{"node_id": "alpha", "flags": {"flag_ae": 1}}],
                }
            },
        },
        "complete": False,
        "game_date": GAME_DATE,
        "objects": [{"type": "country", "country": "FRA"}],
    }


def _valid_upstream_field(values=None) -> dict:
    return {
        "status": "known",
        "value": ["alpha", "beta"] if values is None else values,
        "unit": "state",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
    }


def test_t02_collection_catalog_and_strict_owner_contract(fake_trade_memory, tmp_path: Path):
    income, base, _ = _source(tmp_path)
    source = NativeTradeCollectionSource(income)
    item = source.catalog()[0]
    assert list(item["fields"]) == ["collect_node"]
    assert item["fields"]["collect_node"]["unit"] == "trade_node_list"
    assert item["fields"]["collect_node"]["scale"] == 1
    assert item["fields"]["collect_node"]["period"] == "current"
    assert item["fields"]["collect_node"]["basis"] == "native_trade_node_collection_predicate"
    assert item["fields"]["collect_node"]["complete"] is False
    assert item["triggers"] == ["query", "periodic"]
    assert "change" not in item["triggers"]
    assert item["parameters"]["required"] == []
    assert item["parameters"]["additionalProperties"] is False
    assert source.validate_query(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )["parameters"] == {}
    with pytest.raises(InformationError):
        source.validate_query(_collection_query({"type": "country", "country": "POR"}))
    with pytest.raises(InformationError):
        source.validate_query(_collection_query({"type": "trade_node", "node_id": "alpha"}))
    with pytest.raises(InformationError):
        source.validate_query(
            _collection_query({"type": "country", "country": "FRA"}, parameters={"detail": "full"})
        )
    with pytest.raises(InformationError):
        source.validate_query(
            _collection_query({"type": "country", "country": "FRA"}, fields=["collect_node", "home_node"])
        )


def test_t02_collection_reuses_same_income_instance_and_preserves_order_provenance(
    fake_trade_memory, tmp_path: Path,
):
    nodes = [
        _node("rheinland", 7, eligible=False),
        _node("champagne", 0, eligible=True),
        _node("lubeck", 3, eligible=True),
    ]
    income, base, capture_calls = _source(tmp_path, _report(_record(nodes=nodes), _Base(tmp_path)))
    source = NativeTradeCollectionSource(income)
    result = source.read(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )
    assert result["fields"]["collect_node"] == {
        "status": "known",
        "value": ["champagne", "lubeck"],
        "unit": "trade_node_list",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_collection_predicate",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
        "partial": True,
    }
    assert capture_calls == [(tmp_path / "installation.json", "FRA", True)]
    assert source.trade_income_source is income
    provenance = result["source"]["provenance"]
    assert provenance["adapter"] == "NativeTradeCollectionSource"
    assert provenance["unit"] == "trade_node_list" and provenance["scale"] == 1
    assert provenance["period"] == "current"
    assert provenance["basis"] == "native_trade_node_collection_predicate"
    assert provenance["upstream_source"]["provenance"]["unit"] == "ducats"
    assert provenance["upstream_source"]["name"] == "NativeTradeIncomeSource"
    assert provenance["trade_income"]["record_canonical_sha256"]
    assert [node["node_id"] for node in provenance["trade_income"]["nodes"]] == [
        "rheinland", "champagne", "lubeck",
    ]
    assert all(
        "capture_report_sha256" not in value
        for value in provenance.values()
        if isinstance(value, dict)
    )


def test_t02_collection_keeps_known_empty_list(fake_trade_memory, tmp_path: Path):
    nodes = [_node("rheinland", 9, eligible=False), _node("lubeck", 0, eligible=False)]
    income, base, _ = _source(tmp_path, _report(_record(nodes=nodes), _Base(tmp_path)))
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )
    field = result["fields"]["collect_node"]
    assert field["status"] == "known"
    assert field["value"] == []
    assert field["complete"] is False


@pytest.mark.parametrize(
    ("values", "reason"),
    [(["alpha", "alpha"], "TRADE_COLLECTION_NODE_ID_INVALID"),
     (["Null"], "TRADE_COLLECTION_NODE_ID_INVALID"),
     (["bad id"], "TRADE_COLLECTION_NODE_ID_INVALID")],
)
def test_t02_collection_rejects_duplicate_or_invalid_upstream_node_ids(
    fake_trade_memory, tmp_path: Path, values, reason,
):
    income, base, _ = _source(tmp_path)
    payload = _upstream_result(base, _valid_upstream_field(values))
    income.read = lambda _query, _context: deepcopy(payload)
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )
    assert result["fields"]["collect_node"] == {"status": "unknown", "reason": reason}


def test_t02_collection_rejects_wrong_upstream_source_identity(
    fake_trade_memory, tmp_path: Path,
):
    income, base, _ = _source(tmp_path)
    payload = _upstream_result(base, _valid_upstream_field(), source_name="OtherTradeSource")
    income.read = lambda _query, _context: deepcopy(payload)
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )
    assert result["fields"]["collect_node"] == {
        "status": "unknown",
        "reason": "TRADE_COLLECTION_UPSTREAM_SOURCE_NAME_INVALID",
    }


@pytest.mark.parametrize("status", ["unknown", "unavailable"])
def test_t02_collection_preserves_upstream_unknown_or_unavailable_reason(
    fake_trade_memory, tmp_path: Path, status,
):
    income, base, _ = _source(tmp_path)
    payload = _upstream_result(base, {"status": status, "reason": "UPSTREAM_SPECIFIC_REASON"})
    income.read = lambda _query, _context: deepcopy(payload)
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )
    assert result["fields"]["collect_node"] == {
        "status": status, "reason": "UPSTREAM_SPECIFIC_REASON"
    }


def test_t02_collection_preserves_real_unavailable_source_reason(fake_trade_memory, tmp_path):
    income, base, _ = _source(tmp_path)
    payload = _upstream_result(base, {"status": "unavailable", "reason": "SESSION_NOT_BOUND"})
    payload["source"]["status"] = "unavailable"
    income.read = lambda _query, _context: deepcopy(payload)
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["collect_node"] == {"status": "unavailable", "reason": "SESSION_NOT_BOUND"}


def test_t02_collection_rejects_boolean_scale(fake_trade_memory, tmp_path):
    income, base, _ = _source(tmp_path)
    field = _valid_upstream_field()
    field["scale"] = True
    payload = _upstream_result(base, field)
    income.read = lambda _query, _context: deepcopy(payload)
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["collect_node"]["status"] == "unknown"
    assert result["fields"]["collect_node"]["reason"] == "TRADE_COLLECTION_UPSTREAM_FIELD_CONTRACT_INVALID"


def test_t02_collection_supplied_context_stale_does_not_call_upstream(
    fake_trade_memory, tmp_path: Path,
):
    income, base, capture_calls = _source(tmp_path)
    supplied = base.context()
    supplied["game_date"] = GAME_DATE + 1
    supplied["game_date_raw"] = GAME_DATE + 1
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), supplied
    )
    assert result["fields"]["collect_node"]["status"] == "unavailable"
    assert result["fields"]["collect_node"]["reason"] == "TRADE_COLLECTION_CONTEXT_STALE"
    assert capture_calls == []


def test_t02_collection_exception_then_context_drift_retracts_result(
    fake_trade_memory, tmp_path: Path,
):
    income, base, _ = _source(tmp_path)
    upstream_calls = []

    def failing_read(_query, _context):
        upstream_calls.append(True)
        raise RuntimeError("upstream failed")

    income.read = failing_read
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = NativeTradeCollectionSource(income).read(
        _collection_query({"type": "country", "country": "FRA"}), base.context()
    )
    assert upstream_calls == [True]
    assert result["fields"]["collect_node"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["collect_node"]["reason"]


def test_t02_collection_composes_with_home_and_static_without_claiming_other_fields(
    fake_trade_memory, tmp_path: Path,
):
    income, base, _ = _source(tmp_path)
    collection = NativeTradeCollectionSource(income)
    home = NativeTradeHomeSource(base, capture=lambda *_args, **_kwargs: None)
    static = StaticTradeSource(
        game_root=tmp_path / "game", user_data=tmp_path / "user",
        enabled_mods=[], context_provider=base.context,
    )

    class Primary:
        event_types = ()

        def context(self):
            return base.context()

        def catalog(self):
            # The static source is also the primary catalog in this fixture;
            # the adapters then add the two disjoint live T02 owners.
            return static.catalog()

    composite = CompositeSource(Primary(), [static, home, collection])
    query = _collection_query(
        {"type": "country", "country": "FRA"},
        fields=["routes", "home_node", "collect_node"],
    )
    composite.validate_query(query)
    owners = {
        field: type(adapter).__name__
        for adapter, entry in composite._routes["T02"]
        for field in entry["fields"]
    }
    assert owners["routes"] == "StaticTradeSource"
    assert owners["home_node"] == "NativeTradeHomeSource"
    assert owners["collect_node"] == "NativeTradeCollectionSource"
    catalog = next(item for item in composite.catalog() if item["topic_id"] == "T02")
    assert catalog["fields"]["collect_node"]["source"] == "NativeTradeCollectionSource"
    assert catalog["fields"]["home_node"]["source"] == (
        "bridge.information.country_resources_memory.capture"
    )
    assert catalog["fields"]["routes"]["source"] == "StaticTradeSource"
