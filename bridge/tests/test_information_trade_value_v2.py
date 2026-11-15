from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import trade_value_capture as v1_capture
from bridge.information import trade_value_capture_v2 as v2_capture
from bridge.information import trade_value_memory as v1_memory
from bridge.information import trade_value_memory_v2 as v2_memory


NODE_ID = "champagne"
BASE = 0x140000000
RUNTIME = 0x70000000
GUARD_RVA = "0x100"
GUARD_BYTES = bytes.fromhex("4883ec28")
GATE_ADDRESS = RUNTIME + 0xDC
GUARD_ADDRESS = BASE + int(GUARD_RVA, 0)
PUBLIC_OLD_FIELDS = v1_memory.FIELDS[:-1]
ALL_FIELDS = v1_memory.FIELDS


def _guard_rows():
    return [{"name": "fixture_retention_guard", "rva": GUARD_RVA,
             "bytes": GUARD_BYTES.hex()}]


class _FakeMemory:
    def __init__(self, *, pull=1200, retention=0, guard=GUARD_BYTES,
                 fail_power_gate=False, change_guard_after_power=False):
        self.bytes = {
            GUARD_ADDRESS: bytes(guard),
            GATE_ADDRESS: (int(pull) & 0xFFFFFFFF).to_bytes(4, "little")
            + (int(retention) & 0xFFFFFFFF).to_bytes(4, "little"),
        }
        self.fail_power_gate = fail_power_gate
        self.change_guard_after_power = change_guard_after_power
        self.reads = []

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        if label == "trade_collected.power_gate_i32_pair":
            if self.fail_power_gate:
                raise OSError("fixture power gate read failure")
            result = self.bytes.get(address, b"\x00" * size)
            if self.change_guard_after_power:
                self.bytes[GUARD_ADDRESS] = b"\x90" * len(GUARD_BYTES)
            return result
        return self.bytes.get(address, b"\x00" * size)


def _money(name, value):
    if name == "T03.outgoing_value":
        return {"status": "known", "value": {"total_raw": value, "routes": []},
                "raw_inputs": {"private_pointer": "0xOUTGOING_PRIVATE"}}
    return {"status": "known", "value": value,
            "raw_inputs": {"private_pointer": "0xFIELD_PRIVATE"}}


def _leaf_values(total=4321):
    raw_inputs = {
        "identity": {"runtime_pointer": hex(RUNTIME)},
        # These tempting but unrelated inputs must not drive collected_value.
        "country_income_raw": 9_999_999,
        "trade_power_percent_raw": 99_999,
        "total_value_raw": total,
    }
    return {
        "T03.local_value": _money("T03.local_value", 12000),
        "T03.incoming_value": _money("T03.incoming_value", 7000),
        "T03.total_value": {"status": "known", "value": total,
                            "raw_inputs": deepcopy(raw_inputs)},
        "T03.outgoing_value": _money("T03.outgoing_value", 1000),
        "T03.collected_value": {"status": "unknown", "reason": "unused"},
    }


def _install_leaf(monkeypatch, values=None):
    selected = []
    snapshot = values or _leaf_values()

    def read_fields(reader, base, binding, fields, *, node_id):
        selected.append((tuple(fields), node_id, base, deepcopy(binding)))
        return {name: deepcopy(snapshot[name]) for name in fields}

    monkeypatch.setattr(v2_memory.legacy, "read_fields", read_fields)
    monkeypatch.setattr(v2_memory, "code_guards", _guard_rows)
    return selected


def _read_v2(reader, fields=ALL_FIELDS):
    return v2_memory.read_fields(reader, BASE, {"province_id": 186}, fields,
                                 node_id=NODE_ID)


@pytest.mark.parametrize(
    ("pull", "retention", "sum_i32", "quotient", "status"),
    [
        (0, 999, 999, 0, "unknown"),
        (0, 1000, 1000, 1, "known"),
        (0, -999, -999, 0, "unknown"),
        (0, -1000, -1000, -1, "known"),
        (0x7FFFFFFF, 1, -0x80000000, -2147483, "known"),
        (-0x80000000, -1, 0x7FFFFFFF, 2147483, "known"),
    ],
)
def test_retention_gate_uses_signed32_wrap_and_truncation_toward_zero(
    monkeypatch, pull, retention, sum_i32, quotient, status
):
    _install_leaf(monkeypatch)
    result = _read_v2(_FakeMemory(pull=pull, retention=retention))
    collected = result["T03.collected_value"]
    gate = collected["raw_inputs"]["power_gate"]
    assert gate["pull_power_raw"] == v1_memory._wrap_i32(pull)
    assert gate["retention_power_raw"] == v1_memory._wrap_i32(retention)
    assert gate["sum_i32"] == sum_i32
    assert gate["quotient_trunc0"] == quotient
    assert collected["status"] == status
    if status == "unknown":
        assert collected["reason"] == "NODE_RETENTION_NO_TRADE_IN_NODE"
    else:
        assert collected["value"] == 4321


def test_collected_value_comes_from_v1_total_inputs_not_income_or_percentage(monkeypatch):
    selected = _install_leaf(monkeypatch, _leaf_values(total=123456))
    result = _read_v2(_FakeMemory(pull=1000, retention=0), ["T03.collected_value"])
    collected = result["T03.collected_value"]
    assert selected[0][0] == ("T03.total_value",)
    assert collected["status"] == "known"
    assert collected["value"] == 123456
    assert collected["basis"] == "native_trade_node_retention_tooltip_amount"
    assert collected["unit"] == "ducats" and collected["scale"] == 1000
    assert collected["raw_inputs"]["value_inputs"]["country_income_raw"] == 9_999_999
    assert collected["raw_inputs"]["value_inputs"]["trade_power_percent_raw"] == 99_999
    assert collected["value"] not in (9_999_999, 99_999)


def test_v1_four_fields_survive_collected_read_failure(monkeypatch):
    selected = _install_leaf(monkeypatch)
    result = _read_v2(_FakeMemory(fail_power_gate=True))
    assert selected[0][0] == PUBLIC_OLD_FIELDS
    assert all(result[name]["status"] == "known" for name in PUBLIC_OLD_FIELDS)
    assert result["T03.collected_value"] == {
        "status": "unknown", "reason": "NODE_RETENTION_READ_FAILED",
        "raw_inputs": {
            "profile_sha256": v2_memory.PROFILE_SHA256,
            "value_inputs": _leaf_values()["T03.total_value"]["raw_inputs"],
            "runtime_code_before": [{
                "address": hex(GUARD_ADDRESS), "name": "fixture_retention_guard",
                "expected_hex": GUARD_BYTES.hex(), "actual_hex": GUARD_BYTES.hex(), "matches": True,
            }],
        },
    }


def test_bad_before_code_guard_only_withholds_collected_and_skips_gate(monkeypatch):
    _install_leaf(monkeypatch)
    reader = _FakeMemory(pull=1000, guard=b"\xCC" * len(GUARD_BYTES))
    result = _read_v2(reader)
    assert all(result[name]["status"] == "known" for name in PUBLIC_OLD_FIELDS)
    assert result["T03.collected_value"]["status"] == "unknown"
    assert result["T03.collected_value"]["reason"] == "NODE_RETENTION_CODE_MISMATCH"
    assert not any(label == "trade_collected.power_gate_i32_pair" for _, _, label in reader.reads)


def test_after_code_guard_drift_retracts_only_collected(monkeypatch):
    _install_leaf(monkeypatch)
    reader = _FakeMemory(pull=1000, change_guard_after_power=True)
    result = _read_v2(reader)
    assert all(result[name]["status"] == "known" for name in PUBLIC_OLD_FIELDS)
    assert result["T03.collected_value"]["status"] == "unknown"
    assert result["T03.collected_value"]["reason"] == "NODE_RETENTION_CODE_CHANGED"
    assert len([row for row in reader.reads if row[2] == "trade_collected.code.fixture_retention_guard"]) == 2


def _capture_report(*, version=2):
    inner_schema = v2_capture.INNER_SCHEMA if version == 2 else v1_capture.INNER_SCHEMA
    outer_schema = v2_capture.SCHEMA if version == 2 else v1_capture.SCHEMA
    fields = {
        "T03.local_value": {"status": "known", "value": 12000, "raw_inputs": {"pointer": "0xLOCAL"}},
        "T03.incoming_value": {"status": "known", "value": 7000},
        "T03.total_value": {"status": "known", "value": 18000},
        "T03.outgoing_value": {"status": "known", "value": {"total_raw": 1000, "routes": []}},
        "T03.collected_value": {"status": "known", "value": 9000,
                                "raw_inputs": {"runtime_pointer": "0xPRIVATE", "memory": "secret"}},
    }
    consistent = {name: {"status": "stable", "raw_inputs": {"address": "0xPRIVATE"}}
                  for name in fields}
    role = {"verified": True, "raw_inputs": {"pointer": "0xROLE"}}
    admitted = {"status": "known", "admitted": True, "observer_nonplayer_role": deepcopy(role)}
    discovery = {"status": "known", "value": True, "raw_inputs": {"pointer": "0xDISCOVERY"}}
    target = {
        "province_id": 186,
        "fields": deepcopy(fields),
        "field_consistency": deepcopy(consistent),
        "admission_by_pass": {"pass1": deepcopy(admitted), "pass2": deepcopy(admitted)},
        "discovery_by_pass": {"pass1": deepcopy(discovery), "pass2": deepcopy(discovery)},
        "private_payload": {"pointer": "0xTARGET_PRIVATE"},
    }
    return {
        "schema": outer_schema,
        "observer": "FRA",
        "object": {"type": "trade_node", "node_id": NODE_ID},
        "capture": {
            "schema": inner_schema,
            "status": "observed",
            "completed": True,
            "observation": {
                "stable": True,
                "backend": {
                    "status": "observed",
                    "consistency": {"status": "stable"},
                    "trade_node": {"node_id": NODE_ID, "center_province_id": 186,
                                   "runtime_pointer": "0xNODE_PRIVATE"},
                    "targets": [target],
                },
            },
        },
    }


def test_v2_projector_requires_both_pass_admission_and_discovery():
    for phase in ("pass1", "pass2"):
        for gate in ("admission", "discovery"):
            report = _capture_report()
            target = report["capture"]["observation"]["backend"]["targets"][0]
            if gate == "admission":
                target["admission_by_pass"][phase]["admitted"] = False
            else:
                target["discovery_by_pass"][phase]["value"] = False
            projected = v2_capture.project_fields(report)
            assert projected["collected_value"] == {
                "status": "unknown", "reason": "TRADE_VALUE_ADMISSION_NOT_ESTABLISHED"}
            assert all(projected[name]["status"] == "unknown"
                       for name in ("local_value", "incoming_value", "total_value", "outgoing_value"))


def test_v2_projector_preserves_old_fields_when_collected_stability_fails_and_hides_raw_payload():
    report = _capture_report()
    target = report["capture"]["observation"]["backend"]["targets"][0]
    target["field_consistency"]["T03.collected_value"]["status"] = "changed"
    projected = v2_capture.project_fields(report)
    assert all(projected[name]["status"] == "known" for name in (
        "local_value", "incoming_value", "total_value", "outgoing_value"))
    assert projected["collected_value"] == {
        "status": "unknown", "reason": "NODE_RETENTION_VALUE_NOT_STABLE"}
    encoded = json.dumps(projected, sort_keys=True)
    for private in ("raw_inputs", "runtime_pointer", "0xPRIVATE", "0xLOCAL", "0xTARGET_PRIVATE", "secret"):
        assert private not in encoded


def test_v2_projector_whitelists_collected_and_rejects_non_signed32_values():
    for bad in (True, 1 << 31, -(1 << 31) - 1):
        report = _capture_report()
        report["capture"]["observation"]["backend"]["targets"][0]["fields"]["T03.collected_value"]["value"] = bad
        projected = v2_capture.project_fields(report)
        assert projected["collected_value"]["status"] == "unknown"
        assert "value" not in projected["collected_value"]
    report = _capture_report()
    projected = v2_capture.project_fields(report)
    assert projected["collected_value"] == {
        "status": "known", "value": 9000, "raw": 9000, "raw_hex": "28230000",
        "scale": 1000, "unit": "ducats", "period": "current", "complete": False,
        "basis": "native_trade_node_retention_tooltip_amount",
        "value_origin": "derived_from_native_ui_cache_inputs",
    }


def test_v2_validator_is_schema_strict_and_uses_v2_capture_contract(monkeypatch):
    report = _capture_report()
    calls = []

    def validate_inner(inner, context, creation, country, **kwargs):
        calls.append((inner, context, creation, country, kwargs))
        return True

    monkeypatch.setattr(v1_capture._owner, "_validate_capture_common", validate_inner)
    assert v2_capture.validate_capture(report, {"observer": "FRA"}, 123, NODE_ID) is True
    assert calls[0][0] == report["capture"]
    assert calls[0][3] == "FRA"
    assert calls[0][4]["schema"] == v2_capture.INNER_SCHEMA
    assert calls[0][4]["allow_observer_target"] is True
    assert calls[0][4]["require_access"] is True

    for mutation in (
        lambda bad: bad.update(schema="information.trade_value_capture.v3"),
        lambda bad: bad.update(observer="ENG"),
        lambda bad: bad["object"].update(extra="no"),
        lambda bad: bad.update(unexpected="no"),
    ):
        malformed = deepcopy(report)
        mutation(malformed)
        assert v2_capture.validate_capture(malformed, {"observer": "FRA"}, 123, NODE_ID) is False
    assert len(calls) == 1


def test_v2_validator_explicitly_delegates_v1_and_v1_projection_keeps_collected_unknown(monkeypatch):
    v1_report = _capture_report(version=1)
    delegated = []

    def old_validate(report, context, creation, node_id):
        delegated.append((report, context, creation, node_id))
        return True

    monkeypatch.setattr(v1_capture, "validate_capture", old_validate)
    assert v2_capture.validate_capture(v1_report, {"observer": "FRA"}, 456, NODE_ID) is True
    assert delegated == [(v1_report, {"observer": "FRA"}, 456, NODE_ID)]

    monkeypatch.undo()
    projected = v2_capture.project_fields(v1_report)
    assert projected["collected_value"] == {
        "status": "unknown", "reason": "NODE_COLLECTED_VALUE_NOT_PROVEN"}
    assert all(projected[name]["status"] == "known" for name in (
        "local_value", "incoming_value", "total_value", "outgoing_value"))


def test_v2_projector_rejects_wrong_schema_and_invalid_shape():
    report = _capture_report()
    wrong_schema = deepcopy(report)
    wrong_schema["schema"] = "information.trade_value_capture.v3"
    for invalid in (wrong_schema, None, []):
        projected = v2_capture.project_fields(invalid)
        assert projected["collected_value"] == {
            "status": "unknown", "reason": "TRADE_VALUE_CAPTURE_SHAPE_INVALID"}

