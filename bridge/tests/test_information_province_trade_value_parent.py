"""Offline composition tests for the owner-scoped trade-value extension."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import foreign_country_memory as shared
from bridge.information import province_trade_power_country_memory as country
from bridge.information import province_trade_value_parent_memory as parent


BASE = 0x140000000
PROVINCE_ID = 184
RECORD = 0x200010000
PARENT_READ_A = 0x200020000
PARENT_READ_B = 0x200020008
LEAF_READ = 0x200030000


def _fullref(tag: str, slot: int) -> bytes:
    return ((1 << 56) | (slot << 32)
            | int.from_bytes(tag.encode("ascii") + b"\0", "little")).to_bytes(8, "little")


def _binding(tag: str, slot: int) -> dict:
    raw = _fullref(tag, slot)
    pointer = 0x210000000 + slot * 0x1000
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "fullref": hex(int.from_bytes(raw, "little")),
        "fullref_raw_hex": raw.hex(),
        "country_fullref_address": hex(pointer + 0x20),
        "table_entry_address": hex(0x220000000 + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


class FakeMemory:
    def __init__(self, owner_tag: str = "POR", controller_tag: str = "POR"):
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.put(PARENT_READ_A, bytes(8))
        self.put(PARENT_READ_B, bytes(8))
        self.put(LEAF_READ, (1234).to_bytes(4, "little", signed=True))
        self.put(RECORD + 0x468, _fullref(owner_tag, {"FRA": 7, "POR": 8, "SWE": 9, "ENG": 10}.get(owner_tag, 11)))
        self.put(RECORD + 0x470, _fullref(controller_tag, {"FRA": 7, "POR": 8, "SWE": 9, "ENG": 10}.get(controller_tag, 11)))

    def put(self, address: int, raw: bytes) -> None:
        for offset, byte in enumerate(raw):
            self.data[address + offset] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected read {label} at {address:#x}+{size:#x}") from exc


def _gate(tag: str, *, admitted: bool = True) -> dict:
    return {
        "status": "known",
        "admitted": admitted,
        "observer_nonplayer_role": {
            "observer": "FRA",
            "verified": True,
            "basis": "synthetic_test_role_gate",
        },
        "tag": tag,
    }


def _make_setup(monkeypatch: pytest.MonkeyPatch, *, owner_tag="POR", controller_tag="POR",
                denied_tags=(), role_fail=False, parent_status="observed"):
    memory_image = FakeMemory(owner_tag, controller_tag)
    bindings = {
        tag: _binding(tag, slot)
        for tag, slot in (("FRA", 7), ("POR", 8), ("SWE", 9), ("ENG", 10))
    }
    state = {"province_changed": False, "discovery_changed": False,
             "admission_calls": [], "rebind_calls": [], "resolve_calls": 0,
             "discovery_calls": 0, "owner_admission_flip": False,
             "observer_binding_changed": False, "owner_canonical_changed": False,
             "owner_generic_rebind_failure": False}
    province_scan = {
        "status": "observed",
        "requested": {str(PROVINCE_ID): {"province_id": PROVINCE_ID,
            "record_id": PROVINCE_ID, "record_pointer": hex(RECORD),
            "id_address": hex(RECORD + 0x20), "id_raw_hex": PROVINCE_ID.to_bytes(4, "little", signed=True).hex()}},
    }
    country_scan = {"status": "observed", "count": 4, "table": hex(0x220000000),
                    "database": hex(0x230000000),
                    "rows": [{"tag": item["tag"], "slot": item["slot"],
                              "fullref": item["fullref"],
                              "fullref_raw_hex": item["fullref_raw_hex"]}
                             for item in bindings.values()],
                    "requested": {}}
    observer_gate = _gate("FRA")
    controller_gate = _gate(controller_tag, admitted=controller_tag not in denied_tags)
    anchors = {}
    country_rounds = {}
    for index, phase in enumerate(("pass1", "pass2")):
        anchors[phase] = {
            "pass": index + 1,
            "status": "observed",
            "country_scan": deepcopy(country_scan),
            "province_scan": deepcopy(province_scan),
            "province_binding": deepcopy(province_scan["requested"][str(PROVINCE_ID)]),
            "discovery": {"status": "known", "value": True,
                          "raw_inputs": {"record_pointer": hex(RECORD), "bit_value": 1}},
            "admission": deepcopy(observer_gate),
            "observer_binding": deepcopy(bindings["FRA"]),
        }
        country_rounds[phase] = {
            "status": "observed",
            "shared_valid": True,
            "bindings": {"observer": deepcopy(bindings["FRA"]),
                         "controller": deepcopy(bindings[controller_tag])},
            "admission_before": {"observer": deepcopy(observer_gate),
                                 "controller": deepcopy(controller_gate)},
            "admission_after": {"observer": deepcopy(observer_gate),
                                "controller": deepcopy(controller_gate)},
            "controller_ref_raw_hex": bindings[controller_tag]["fullref_raw_hex"],
        }

    def resolve_provinces(_limiter, _base, ids):
        state["resolve_calls"] += 1
        assert list(ids) == [PROVINCE_ID]
        copied = deepcopy(province_scan)
        if state["province_changed"]:
            copied["requested"][str(PROVINCE_ID)]["record_pointer"] = hex(RECORD + 0x1000)
        return copied

    def read_discovery(_limiter, record, slot):
        state["discovery_calls"] += 1
        assert record == RECORD and slot == 7
        return {"status": "known", "value": not state["discovery_changed"],
                "raw_inputs": {"record_pointer": hex(record), "bit_value": int(not state["discovery_changed"])}}

    def rebind(_limiter, _base, scan, raw_ref, label):
        state["rebind_calls"].append((label, scan, bytes(raw_ref).hex()))
        tag = bytes(raw_ref)[:3].decode("ascii")
        if tag not in bindings:
            raise ValueError("synthetic binding unavailable")
        if tag == owner_tag and state["owner_canonical_changed"]:
            raise ValueError("COUNTRY_SCAN_ROW_CHANGED")
        if tag == owner_tag and state["owner_generic_rebind_failure"]:
            raise ValueError("COUNTRY_BINDING_UNVERIFIED")
        if tag == "FRA" and state["observer_binding_changed"]:
            changed = deepcopy(bindings[tag])
            changed["country_pointer"] = hex(int(changed["country_pointer"], 0) + 0x1000)
            return changed
        return deepcopy(bindings[tag])

    def admit(_limiter, _base, _scan, binding):
        tag = binding["tag"]
        state["admission_calls"].append(tag)
        if role_fail and tag == "FRA":
            raise country._ObserverFailure("synthetic observer role failure")
        admitted = tag not in denied_tags
        if tag == owner_tag and state["owner_admission_flip"] and state["admission_calls"].count(tag) > 1:
            admitted = False
        return _gate(tag, admitted=admitted)

    monkeypatch.setattr(country._province._province, "resolve_provinces", resolve_provinces)
    monkeypatch.setattr(country._province, "_read_discovery", read_discovery)
    monkeypatch.setattr(country, "_rebind", rebind)
    monkeypatch.setattr(country, "_admit", admit)
    parent_calls = []

    def parent_reader(read, base, province_id, *, observer):
        parent_calls.append({"reader": read, "base": base, "province_id": province_id,
                             "kwargs": {"observer": observer}})
        # Stand in for the existing two country scans. Extension reads must
        # reuse their retained rows rather than issue another full scan.
        read.read(PARENT_READ_A, 8, "country_reference.database_global")
        read.read(PARENT_READ_B, 8, "country_reference.database_global")
        target_fields = {
            "G02.province_trade_power": {"status": "known", "value": {"raw": 2100}},
            country.CONTROLLER_FIELD: {"status": "known", "value": {"raw": 200}},
        }
        result = {
            "status": parent_status,
            "consistency": {"status": "stable" if parent_status == "observed" else "unknown",
                            "shared_mismatch_paths": []},
            "pass_evidence": deepcopy(anchors),
            "country_inputs_evidence": deepcopy(country_rounds),
            "targets": [{"province_id": province_id, "fields": target_fields,
                         "field_consistency": {name: {"status": "stable"} for name in target_fields}}],
            "errors": [],
            "budget": {"calls": 0, "bytes_requested": 0},
        }
        return result

    def run(read_fields):
        return parent.extend(memory_image, BASE, PROVINCE_ID, observer="FRA",
                             parent_reader=parent_reader, read_fields=read_fields)

    return memory_image, state, parent_calls, anchors, country_rounds, bindings, run


def _leaf_field(raw=1234):
    return {"status": "known", "complete": False, "period": "current",
            "basis": "native_province_trade_value_cache_calculation",
            "value": {"raw": raw, "scale": 1000, "unit": "ducats"},
            "raw_inputs": {"synthetic_raw": raw}}


def _target(result):
    return result["targets"][0]


@pytest.mark.parametrize("owner_tag", ["FRA", "POR", "SWE"])
def test_extension_reuses_parent_reader_budget_and_owner_role_binding(monkeypatch, owner_tag):
    memory_image, _state, parent_calls, _anchors, _country_rounds, bindings, run = _make_setup(
        monkeypatch, owner_tag=owner_tag, controller_tag="POR")
    received = []

    def read_fields(read, base, province_binding, province_scan, observer, owner):
        received.append((read, base, deepcopy(province_binding), deepcopy(province_scan),
                         deepcopy(observer), deepcopy(owner)))
        assert read.read(LEAF_READ, 4, "province_trade_value.synthetic_leaf") == (1234).to_bytes(4, "little", signed=True)
        return {parent.FIELD: _leaf_field()}

    result = run(read_fields)

    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert _target(result)["fields"][parent.FIELD]["status"] == "known"
    assert _target(result)["fields"]["G02.province_trade_power"]["status"] == "known"
    assert _target(result)["field_consistency"][parent.FIELD]["status"] == "stable"
    assert len(parent_calls) == 1
    assert parent_calls[0]["kwargs"] == {"observer": "FRA"}
    assert len(received) == 2
    assert all(item[0] is parent_calls[0]["reader"] for item in received)
    assert all(item[1] == BASE and item[2]["province_id"] == PROVINCE_ID for item in received)
    assert all(item[3]["status"] == "observed" for item in received)
    assert all(item[4] == bindings["FRA"] for item in received)
    assert all(item[5] == bindings[owner_tag] for item in received)
    assert sum(label == "country_reference.database_global" for _, _, label in memory_image.reads) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in memory_image.reads)
    assert result["budget"]["calls"] == len(memory_image.reads)
    assert result["budget"]["bytes_requested"] <= 512 * 1024
    assert result["budget"]["limit_bytes"] == 512 * 1024
    evidence = result["province_trade_value_evidence"][parent.FIELD]
    assert set(evidence) == {"pass1", "pass2"}
    assert all(evidence[phase]["shared_valid"] for phase in ("pass1", "pass2"))


def test_denied_owner_is_local_unknown_and_still_runs_all_after_checks(monkeypatch):
    memory_image, state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, owner_tag="SWE", controller_tag="POR", denied_tags={"SWE"})
    child_calls = []
    result = run(lambda *args: child_calls.append(args) or {parent.FIELD: _leaf_field()})

    assert result["status"] == "observed"
    assert _target(result)["fields"]["G02.province_trade_power"]["status"] == "known"
    assert _target(result)["fields"][parent.FIELD]["reason"] == "OWNER_ADMISSION_NOT_ESTABLISHED"
    assert _target(result)["field_consistency"][parent.FIELD]["status"] == "unknown"
    assert child_calls == []
    evidence = result["province_trade_value_evidence"][parent.FIELD]
    assert all(evidence[p]["shared_valid"] for p in ("pass1", "pass2"))
    assert state["resolve_calls"] == 4 and state["discovery_calls"] == 4
    assert sum(label == "province_trade_value.owner_ref" for _, _, label in memory_image.reads) == 4
    assert sum(label == "province_trade_value.controller_ref" for _, _, label in memory_image.reads) == 4


def test_stable_unavailable_owner_is_local_unknown_after_reference_recheck(monkeypatch):
    memory_image, _state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, owner_tag="BAD", controller_tag="POR")
    result = run(lambda *_args: pytest.fail("unavailable owner must not reach the leaf"))

    assert result["status"] == "observed"
    assert _target(result)["fields"][parent.FIELD]["reason"] == "OWNER_ADMISSION_NOT_ESTABLISHED"
    evidence = result["province_trade_value_evidence"][parent.FIELD]
    assert all(evidence[p]["shared_valid"] for p in ("pass1", "pass2"))
    assert sum(label == "province_trade_value.owner_ref" for _, _, label in memory_image.reads) == 4


def test_owner_canonical_row_change_before_leaf_retracts_all_parent_fields(monkeypatch):
    _memory, state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, owner_tag="SWE", controller_tag="POR")
    state["owner_canonical_changed"] = True
    child_calls = []
    result = run(lambda *args: child_calls.append(args) or {parent.FIELD: _leaf_field()})

    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["province_trade_value"]
    assert child_calls == []
    assert all(field["status"] == "unknown" for field in _target(result)["fields"].values())


def test_generic_rebind_failure_for_exact_retained_owner_row_retracts_parent(monkeypatch):
    _memory, state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, owner_tag="SWE", controller_tag="POR")
    state["owner_generic_rebind_failure"] = True
    child_calls = []
    result = run(lambda *args: child_calls.append(args) or {parent.FIELD: _leaf_field()})

    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["province_trade_value"]
    assert child_calls == []
    assert all(field["status"] == "unknown" for field in _target(result)["fields"].values())


@pytest.mark.parametrize("drift", ["controller_ref", "owner_ref", "observer_binding",
                                    "province", "discovery"])
def test_shared_reference_or_discovery_drift_retracts_all_parent_fields(monkeypatch, drift):
    memory_image, state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, owner_tag="SWE", controller_tag="POR")
    leaf_calls = []

    def read_fields(read, _base, _province_binding, _province_scan, _observer, _owner):
        leaf_calls.append(read)
        if len(leaf_calls) == 1:
            if drift == "controller_ref":
                memory_image.put(RECORD + 0x470, _fullref("ENG", 10))
            elif drift == "owner_ref":
                memory_image.put(RECORD + 0x468, _fullref("ENG", 10))
            elif drift == "observer_binding":
                state["observer_binding_changed"] = True
            elif drift == "province":
                state["province_changed"] = True
            else:
                state["discovery_changed"] = True
        return {parent.FIELD: _leaf_field()}

    result = run(read_fields)

    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["province_trade_value"]
    assert leaf_calls
    assert all(field["status"] == "unknown" for field in _target(result)["fields"].values())
    assert all(value["status"] == "unknown"
               for value in _target(result)["field_consistency"].values())


def test_owner_admission_change_is_shared_drift(monkeypatch):
    memory_image, state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, owner_tag="SWE", controller_tag="POR")
    state["owner_admission_flip"] = True
    leaf_calls = []
    result = run(lambda *_args: leaf_calls.append(True) or {parent.FIELD: _leaf_field()})

    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["province_trade_value"]
    assert all(field["status"] == "unknown" for field in _target(result)["fields"].values())


def test_observer_role_failure_retracts_parent_and_never_calls_leaf(monkeypatch):
    _memory, _state, _calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, role_fail=True)
    child_calls = []
    result = run(lambda *args: child_calls.append(args) or {parent.FIELD: _leaf_field()})

    assert result["status"] == "unknown"
    assert child_calls == []
    assert all(field["status"] == "unknown" for field in _target(result)["fields"].values())


def test_leaf_exception_is_local_and_after_validation_still_runs(monkeypatch):
    _memory, state, _calls, _anchors, _rounds, _bindings, run = _make_setup(monkeypatch)
    child_calls = []

    def fail_leaf(*args):
        child_calls.append(args)
        raise RuntimeError("synthetic leaf failure")

    result = run(fail_leaf)

    assert len(child_calls) == 2
    assert result["status"] == "observed"
    assert _target(result)["fields"]["G02.province_trade_power"]["status"] == "known"
    assert _target(result)["fields"][parent.FIELD]["reason"] == "PROVINCE_TRADE_VALUE_FIELD_READ_FAILED"
    assert state["resolve_calls"] == 4 and state["discovery_calls"] == 4


def test_child_value_drift_is_local_and_does_not_change_parent_fields(monkeypatch):
    _memory, _state, _calls, _anchors, _rounds, _bindings, run = _make_setup(monkeypatch)
    values = iter((1234, 1235))
    result = run(lambda *_args: {parent.FIELD: _leaf_field(next(values))})

    assert result["status"] == "observed"
    assert _target(result)["fields"]["G02.province_trade_power"]["status"] == "known"
    assert _target(result)["fields"][parent.FIELD]["reason"] == "PROVINCE_TRADE_VALUE_CHANGED_BETWEEN_PASSES"
    assert _target(result)["field_consistency"][parent.FIELD]["status"] == "changed"


def test_unready_parent_does_not_invoke_child_or_add_scan_reads(monkeypatch):
    memory_image, _state, parent_calls, _anchors, _rounds, _bindings, run = _make_setup(
        monkeypatch, parent_status="unknown")
    child_calls = []
    result = run(lambda *args: child_calls.append(args) or {parent.FIELD: _leaf_field()})

    assert result["status"] == "unknown"
    assert child_calls == []
    assert len(parent_calls) == 1
    assert sum(label == "country_reference.database_global" for _, _, label in memory_image.reads) == 2
    assert _target(result)["fields"][parent.FIELD]["status"] == "unknown"
