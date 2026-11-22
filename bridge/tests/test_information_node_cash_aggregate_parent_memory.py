"""Offline composition tests for the node-cash aggregate parent extension."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import foreign_country_memory as shared
from bridge.information import node_cash_aggregate_memory as leaf
from bridge.information import node_cash_aggregate_parent_memory as parent


BASE = 0x140000000
PROVINCE_ID = 227
COUNTRY_READS = ((0x200020000, 8), (0x200020008, 8))
LEAF_READ = (0x200030000, 4)
ALLOCATION_FIELD = "G02.province_node_allocation"
SIBLING_FIELD = "G02.province_trade_power"


class FakeReader:
    def __init__(self):
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        for address, size in (*COUNTRY_READS, LEAF_READ):
            self.put(address, bytes(range(size)))

    def put(self, address: int, raw: bytes) -> None:
        for offset, byte in enumerate(raw):
            self.data[address + offset] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected read {label} at {address:#x}+{size:#x}") from exc


def _field(value: int = 1234, *, status: str = "known", shared_valid: bool = True,
           reason: str | None = None) -> dict:
    result = {
        "status": status,
        "complete": False,
        "partial": True,
        "period": "current",
        "basis": leaf.BASIS,
        "raw_inputs": {"shared_valid": shared_valid, "synthetic_raw": value},
    }
    if status == "known":
        result["value"] = {"raw": value, "scale": 1000, "unit": "node_cash"}
    else:
        result["reason"] = reason or "NODE_CASH_OWNER_NOT_ADMITTED"
    return result


def _setup(monkeypatch: pytest.MonkeyPatch, *, parent_status: str = "observed",
           parent_consistency: str = "stable", allocation_status: str = "known",
           allocation_consistency: str = "stable", target_id: int = PROVINCE_ID):
    source = FakeReader()
    events: list[tuple] = []
    parent_calls: list[dict] = []
    child_readers = []
    snapshots: list[tuple] = []
    state = {"snapshot_failure_call": None, "snapshot_drift_call": None}

    def shared_snapshot(read, base, province_id, anchor, countries):
        index = len(snapshots) + 1
        phase = anchor["phase"]
        snapshots.append((phase, read, base, province_id, countries))
        events.append(("snapshot", phase, index))
        if index == state["snapshot_failure_call"]:
            raise ValueError("synthetic shared snapshot failure")
        payload = {"phase": phase, "observer": {"binding": {"tag": "FRA"}},
                   "country_scan": deepcopy(countries["country_scan"])}
        if index == state["snapshot_drift_call"]:
            payload["drift"] = True
        return payload

    monkeypatch.setattr(parent._value_parent, "_shared_snapshot", shared_snapshot)

    def parent_reader(read, base, province_id, *, observer):
        parent_calls.append({"reader": read, "base": base, "province_id": province_id,
                             "observer": observer})
        for address, size in COUNTRY_READS:
            read.read(address, size, "country_reference.database_global")
        allocation = {"status": allocation_status,
                      "basis": "native_trade_node_province_component_reconstruction",
                      "value": {"node_id": 1293},
                      "raw_inputs": {"pass_summaries": [{"count": 1}, {"count": 1}]}}
        sibling = {"status": "known", "value": {"raw": 2100}}
        field_consistency = {ALLOCATION_FIELD: {"status": allocation_consistency},
                             SIBLING_FIELD: {"status": "stable"}}
        anchors = {phase: {"phase": phase, "pass": i,
                           "province_scan": {"status": "observed", "phase": phase},
                           "country_scan": {"status": "observed", "rows": []}}
                   for i, phase in enumerate(("pass1", "pass2"), start=1)}
        countries = {phase: {"shared_valid": True,
                             "country_scan": {"status": "observed", "rows": []}}
                     for phase in ("pass1", "pass2")}
        return {
            "status": parent_status,
            "consistency": {"status": parent_consistency, "shared_mismatch_paths": []},
            "pass_evidence": anchors,
            "country_inputs_evidence": countries,
            "targets": [{
                "province_id": target_id,
                "fields": {ALLOCATION_FIELD: allocation, SIBLING_FIELD: sibling},
                "field_consistency": field_consistency,
            }],
            "errors": [],
            "budget": {"calls": -1, "bytes_requested": -1},
        }

    def run(read_fields, *, observer="FRA", province_id=PROVINCE_ID,
            selected_parent_reader=parent_reader):
        return parent.extend(source, BASE, province_id, observer=observer,
                             parent_reader=selected_parent_reader, read_fields=read_fields)

    return source, events, parent_calls, child_readers, snapshots, state, parent_reader, run


def _target(result: dict) -> dict:
    return result["targets"][0]


def _read_known(readers: list, events: list, value: int = 1234):
    def read_fields(read, _base, anchor, _observer, _country_scan, _allocation):
        readers.append(read)
        events.append(("leaf", anchor["phase"]))
        assert read.read(*LEAF_READ, "node_cash.synthetic_leaf") == bytes(range(4))
        return {parent.FIELD: _field(value)}
    return read_fields


def test_extension_reuses_parent_reader_budget_and_snapshots_each_pass(monkeypatch):
    source, events, parent_calls, child_readers, snapshots, _state, _parent_reader, run = _setup(monkeypatch)
    result = run(_read_known(child_readers, events))

    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert _target(result)["fields"][parent.FIELD]["status"] == "known"
    assert _target(result)["fields"][SIBLING_FIELD] == {"status": "known", "value": {"raw": 2100}}
    assert _target(result)["field_consistency"][parent.FIELD] == {"status": "stable"}
    assert len(parent_calls) == 1 and len(child_readers) == 2
    assert all(reader is parent_calls[0]["reader"] for reader in child_readers)
    assert parent_calls[0]["reader"] is not source
    assert parent_calls[0]["base"] == BASE and parent_calls[0]["province_id"] == PROVINCE_ID
    assert parent_calls[0]["observer"] == "FRA"
    assert [event[:2] for event in events] == [
        ("snapshot", "pass1"), ("leaf", "pass1"), ("snapshot", "pass1"),
        ("snapshot", "pass2"), ("leaf", "pass2"), ("snapshot", "pass2"),
    ]
    assert [entry[0] for entry in snapshots] == ["pass1", "pass1", "pass2", "pass2"]
    assert all(entry[1] is parent_calls[0]["reader"] for entry in snapshots)
    assert all(entry[2:4] == (BASE, PROVINCE_ID) for entry in snapshots)
    assert sum(label == "country_reference.database_global" for _, _, label in source.reads) == 2
    assert sum(label == "node_cash.synthetic_leaf" for _, _, label in source.reads) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in source.reads)
    assert result["budget"]["calls"] == len(source.reads)
    assert result["budget"]["limit_bytes"] == 512 * 1024
    assert result["budget"]["bytes_requested"] == sum(size for _, size in COUNTRY_READS) + 2 * LEAF_READ[1]
    evidence = result["node_cash_aggregate_evidence"][parent.FIELD]
    assert set(evidence) == {"pass1", "pass2"}
    assert all(evidence[phase]["shared_valid"] for phase in ("pass1", "pass2"))
    assert all(set(evidence[phase]) >= {"before", "after"} for phase in evidence)


@pytest.mark.parametrize("value", [0, 1234, -57])
def test_stable_known_partial_leaf_preserves_parent_siblings(monkeypatch, value):
    _source, events, _calls, readers, _snapshots, _state, _reader, run = _setup(monkeypatch)
    result = run(_read_known(readers, events, value))

    field = _target(result)["fields"][parent.FIELD]
    assert field["status"] == "known" and field["complete"] is False
    assert field["partial"] is True and field["value"]["raw"] == value
    assert _target(result)["fields"][ALLOCATION_FIELD]["status"] == "known"
    assert _target(result)["fields"][SIBLING_FIELD]["value"]["raw"] == 2100
    assert _target(result)["field_consistency"][parent.FIELD] == {"status": "stable"}


def test_local_unsupported_leaf_still_runs_after_snapshot_and_preserves_siblings(monkeypatch):
    _source, events, _calls, readers, snapshots, _state, _reader, run = _setup(monkeypatch)

    def denied(read, _base, anchor, _observer, _country_scan, _allocation):
        readers.append(read)
        events.append(("leaf", anchor["phase"]))
        return {parent.FIELD: _field(status="unknown", shared_valid=True,
                                     reason="NODE_CASH_OWNER_NOT_ADMITTED")}

    result = run(denied)

    assert _target(result)["fields"][parent.FIELD]["reason"] == "NODE_CASH_OWNER_NOT_ADMITTED"
    assert _target(result)["field_consistency"][parent.FIELD] == {"status": "unknown"}
    assert _target(result)["fields"][ALLOCATION_FIELD]["status"] == "known"
    assert _target(result)["fields"][SIBLING_FIELD]["value"]["raw"] == 2100
    assert len(snapshots) == 4
    assert [event[0] for event in events] == ["snapshot", "leaf", "snapshot"] * 2


@pytest.mark.parametrize("failure", ["snapshot_after_pass1", "leaf_shared_invalid"])
def test_shared_evidence_failure_retracts_every_parent_field(monkeypatch, failure):
    _source, events, _calls, readers, snapshots, state, _reader, run = _setup(monkeypatch)
    if failure == "snapshot_after_pass1":
        state["snapshot_failure_call"] = 2

    def read_fields(read, _base, anchor, _observer, _country_scan, _allocation):
        readers.append(read)
        events.append(("leaf", anchor["phase"]))
        valid = failure != "leaf_shared_invalid"
        return {parent.FIELD: _field(shared_valid=valid)}

    result = run(read_fields)

    assert result["status"] == "unknown"
    assert result["consistency"]["status"] == "unknown"
    assert _target(result)["fields"]
    assert all(value["status"] == "unknown" for value in _target(result)["fields"].values())
    assert all(value["status"] == "unknown"
               for value in _target(result)["field_consistency"].values())
    assert len(snapshots) == 4
    if failure == "leaf_shared_invalid":
        assert [event[0] for event in events] == ["snapshot", "leaf", "snapshot"] * 2
    assert result["node_cash_aggregate_evidence"][parent.FIELD]["pass1"]["shared_valid"] is False


def test_before_after_snapshot_drift_retracts_parent_even_if_leaf_is_known(monkeypatch):
    _source, _events, _calls, readers, _snapshots, state, _reader, run = _setup(monkeypatch)
    state["snapshot_drift_call"] = 2
    result = run(_read_known(readers, [], 1234))

    assert result["status"] == "unknown"
    assert all(value["status"] == "unknown" for value in _target(result)["fields"].values())


def test_child_value_change_is_local_and_preserves_parent_fields(monkeypatch):
    _source, _events, _calls, readers, _snapshots, _state, _reader, run = _setup(monkeypatch)
    values = iter((1234, 1235))

    def changed(read, _base, anchor, _observer, _country_scan, _allocation):
        readers.append(read)
        return {parent.FIELD: _field(next(values))}

    result = run(changed)

    assert result["status"] == "observed"
    assert _target(result)["fields"][parent.FIELD]["reason"] == "NODE_CASH_CHANGED_BETWEEN_PASSES"
    assert _target(result)["field_consistency"][parent.FIELD] == {"status": "changed"}
    assert _target(result)["fields"][ALLOCATION_FIELD]["status"] == "known"
    assert _target(result)["fields"][SIBLING_FIELD]["value"]["raw"] == 2100


@pytest.mark.parametrize("not_ready", [
    "parent_status", "parent_consistency", "allocation_status", "allocation_consistency",
])
def test_unready_parent_or_allocation_skips_leaf_and_shared_snapshots(monkeypatch, not_ready):
    options = {}
    if not_ready == "parent_status":
        options["parent_status"] = "unknown"
    elif not_ready == "parent_consistency":
        options["parent_consistency"] = "unknown"
    elif not_ready == "allocation_status":
        options["allocation_status"] = "unknown"
    else:
        options["allocation_consistency"] = "changed"
    source, _events, calls, readers, snapshots, _state, _reader, run = _setup(monkeypatch, **options)
    result = run(lambda *args: readers.append(args) or {parent.FIELD: _field()})

    assert len(calls) == 1
    assert readers == []
    assert snapshots == []
    assert _target(result)["fields"][parent.FIELD]["status"] == "unknown"
    assert result["budget"]["calls"] == len(source.reads) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in source.reads)


@pytest.mark.parametrize("observer,province_id", [
    ("eng", PROVINCE_ID), ("FRA", 0), ("FRA", 65536), ("FRA", True), ("FRA", "227"),
])
def test_invalid_observer_or_province_scope_is_rejected(monkeypatch, observer, province_id):
    _source, _events, _calls, _readers, _snapshots, _state, _reader, run = _setup(monkeypatch)

    with pytest.raises(ValueError, match="NODE_CASH_PARENT_SCOPE_INVALID"):
        run(lambda *_args: {parent.FIELD: _field()}, observer=observer, province_id=province_id)


def test_parent_target_id_mismatch_is_rejected_before_child(monkeypatch):
    _source, _events, _calls, _readers, _snapshots, _state, _reader, run = _setup(
        monkeypatch, target_id=PROVINCE_ID + 1)

    with pytest.raises(ValueError, match="NODE_CASH_PARENT_TARGET_INVALID"):
        run(lambda *_args: pytest.fail("mismatched target must not reach the leaf"))

