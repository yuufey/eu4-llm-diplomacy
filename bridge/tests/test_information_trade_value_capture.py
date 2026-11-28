from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest

from bridge.information import trade_value_capture as capture
from bridge.information import trade_value_memory as values


NODE_ID = "alpha_node"
GATE_FIELDS = (
    "G02.t03_local_value",
    "G02.t03_incoming_value",
    "G02.t03_total_value",
    "G02.t03_outgoing_value",
    "G02.t03_collected_value",
)


def _known_field(value):
    return {"status": "known", "value": value,
            "raw_inputs": {"private_address": "0xDEADBEEF"}}


def _target():
    fields = {
        "T03.local_value": _known_field(-2147483648),
        "T03.incoming_value": _known_field(22),
        # wrap_i32(-2147483648 + 22 - 7)
        "T03.total_value": _known_field(-2147483633),
        "T03.outgoing_value": _known_field({
            "total_raw": 7,
            "routes": [{"node_id": "beta_node", "raw": 7, "private_ptr": "0xBAD"}],
            "private_address": "0xC0FFEE",
        }),
        # A forged collected value remains private input and must never publish.
        "T03.collected_value": _known_field(999),
    }
    return {
        "province_id": 17,
        "admission_by_pass": {
            phase: {"status": "known", "admitted": True,
                    "observer_nonplayer_role": {"verified": True}}
            for phase in ("pass1", "pass2")
        },
        "discovery_by_pass": {
            phase: {"status": "known", "value": True}
            for phase in ("pass1", "pass2")
        },
        "fields": fields,
        "field_consistency": {
            name: {"status": "stable"} for name in fields
        },
    }


def _report(target=None):
    target = _target() if target is None else target
    return {
        "schema": capture.SCHEMA,
        "observer": "FRA",
        "object": {"type": "trade_node", "node_id": NODE_ID},
        "capture": {
            "schema": capture.INNER_SCHEMA,
            "status": "observed",
            "completed": True,
            "observation": {
                "stable": True,
                "backend": {
                    "status": "observed",
                    "consistency": {"status": "stable"},
                    "trade_node": {"node_id": NODE_ID, "center_province_id": 17,
                                   "selection_identity": {"private_pointer": "0x1234"}},
                    "targets": [target],
                },
            },
        },
    }


def test_projector_requires_positive_self_admission_and_discovery_each_pass():
    for phase in ("pass1", "pass2"):
        cases = (
            ("admission", lambda row: row["admission_by_pass"][phase].update(admitted=False)),
            ("discovery", lambda row: row["discovery_by_pass"][phase].update(value=False)),
        )
        for _, mutate in cases:
            target = _target()
            mutate(target)
            projected = capture.project_fields(_report(target))
            assert all(projected[name]["status"] == "unknown" for name in (
                "local_value", "incoming_value", "total_value", "outgoing_value"))
            assert projected["collected_value"] == {
                "status": "unknown", "reason": "NODE_COLLECTED_VALUE_NOT_PROVEN"}


def test_projector_rejects_nonpositive_or_missing_gate_evidence():
    target = _target()
    del target["admission_by_pass"]["pass2"]["admitted"]
    projected = capture.project_fields(_report(target))
    assert all(projected[name.removeprefix("T03.")]["status"] == "unknown"
               for name in capture.FIELDS[:-1])

    malformed = _report()
    malformed["capture"]["observation"]["backend"]["consistency"]["status"] = "unstable"
    assert all(field["status"] == "unknown" for field in capture.project_fields(malformed).values())


def test_projector_accepts_human_role_without_changing_role_evidence():
    target = _target()
    for gate in target["admission_by_pass"].values():
        gate["observer_nonplayer_role"]["verified"] = False
    projected = capture.project_fields(_report(target))
    assert projected["local_value"]["status"] == "known"
    assert all(not gate["observer_nonplayer_role"]["verified"]
               for gate in target["admission_by_pass"].values())


def test_field_projection_is_independently_gated_by_two_pass_stability():
    target = _target()
    target["field_consistency"]["T03.incoming_value"] = {"status": "changed"}
    # The computed total uses the incoming input, so its consistency is also
    # unstable in this synthetic snapshot.
    target["field_consistency"]["T03.total_value"] = {"status": "changed"}
    projected = capture.project_fields(_report(target))
    assert projected["local_value"]["status"] == "known"
    assert projected["incoming_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_FIELD_NOT_STABLE"}
    assert projected["total_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_FIELD_NOT_STABLE"}
    assert projected["outgoing_value"]["status"] == "known"


def test_scalar_projection_keeps_signed32_bounds_and_rejects_bool_or_overflow():
    low = capture.project_fields(_report())
    assert low["local_value"]["status"] == "known"
    assert low["local_value"]["raw"] == -(1 << 31)
    assert low["local_value"]["raw_hex"] == "00000080"

    for invalid in (True, 1 << 31, -(1 << 31) - 1):
        target = _target()
        target["fields"]["T03.local_value"]["value"] = invalid
        projected = capture.project_fields(_report(target))
        assert projected["local_value"] == {
            "status": "unknown", "reason": "TRADE_VALUE_SIGNED_RAW_INVALID"}


def test_outgoing_projection_whitelists_route_rows_and_discards_private_payload():
    projected = capture.project_fields(_report())
    outgoing = projected["outgoing_value"]
    assert outgoing["status"] == "known"
    assert outgoing["value"] == {
        "total_raw": 7,
        "routes": [{"node_id": "beta_node", "raw": 7}],
    }
    assert outgoing["raw"] == 7
    assert outgoing["raw_hex"] == "07000000"
    assert "private_address" not in repr(outgoing)
    assert "private_ptr" not in repr(outgoing)

    target = _target()
    target["fields"]["T03.outgoing_value"]["value"]["routes"] = [
        {"node_id": f"node_{index}", "raw": index} for index in range(33)
    ]
    assert capture.project_fields(_report(target))["outgoing_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_OUTGOING_INVALID"}


def test_collected_value_is_unknown_even_when_raw_target_claims_known():
    projected = capture.project_fields(_report())
    assert projected["collected_value"] == {
        "status": "unknown", "reason": "NODE_COLLECTED_VALUE_NOT_PROVEN"}


def test_capture_and_validation_delegate_to_owner_with_trade_node_binding():
    inner = {"schema": capture.INNER_SCHEMA, "status": "observed", "completed": True}
    installation = Path("C:/fake/installation.json")
    with patch.object(capture._owner, "_capture_common", return_value=inner) as owner_capture:
        report = capture.capture(installation, NODE_ID, observer="FRA")
    assert report == {
        "schema": capture.SCHEMA,
        "observer": "FRA",
        "object": {"type": "trade_node", "node_id": NODE_ID},
        "capture": inner,
    }
    owner_capture.assert_called_once()
    args, kwargs = owner_capture.call_args
    assert args == (installation, "FRA")
    assert kwargs["observer"] == "FRA"
    assert kwargs["schema"] == capture.INNER_SCHEMA
    assert kwargs["profile_sha256"] == values.PROFILE_SHA256
    assert kwargs["load_profile"] is capture._load_profile
    assert callable(kwargs["observe"])
    assert kwargs["allow_observer_target"] is True

    context = {"observer": "FRA", "session_id": "s", "game_date": 1,
               "game_version": "1.37.4", "game_sha256": values.EXPECTED_EXE_SHA256}
    with patch.object(capture._owner, "_capture_common", side_effect=AssertionError("must replay")):
        with patch.object(capture._owner, "_validate_capture_common", return_value=True) as owner_validate:
            assert capture.validate_capture(report, context, 123, NODE_ID) is True
    owner_validate.assert_called_once()
    args, kwargs = owner_validate.call_args
    assert args == (inner, context, 123, "FRA")
    assert kwargs["schema"] == capture.INNER_SCHEMA
    assert kwargs["profile_sha256"] == values.PROFILE_SHA256
    assert callable(kwargs["observe"])
    assert kwargs["allow_observer_target"] is True
    assert kwargs["require_access"] is True


@pytest.mark.parametrize("bad_node", ["Null", "../node", "x" * 129])
def test_capture_rejects_invalid_node_before_owner_call(bad_node):
    with patch.object(capture._owner, "_capture_common") as owner_capture:
        with pytest.raises(ValueError):
            capture.capture(Path("unused"), bad_node, observer="FRA")
    owner_capture.assert_not_called()


@pytest.mark.parametrize("gate_positive", [False, True])
def test_observer_resolves_identity_first_and_only_reads_finance_through_province_callback(gate_positive):
    events = []
    reader = object()
    base = 0x140000000
    profile = {"trade_node_scope_rule": {"name": "Trade Node"}}
    identity = {"status": "known", "node_id": NODE_ID,
                "center_province_id": 17, "private_pointer": "0xIDENTITY"}

    def fake_owner_observe(read, module_base, country, selected_profile, *, backend_reader):
        events.append(("owner", country))
        return backend_reader(read, module_base, country)

    def fake_find_node(read, module_base, node_id):
        events.append(("identity", node_id))
        return deepcopy(identity)

    def fake_read_fields(limiter, module_base, province_binding, selected, *, node_id):
        events.append(("financial", tuple(selected), node_id))
        assert tuple(selected) == capture.FIELDS
        return {field: _known_field(index + 1) for index, field in enumerate(capture.FIELDS)}

    def fake_province_read_two_pass(read, module_base, province_id, *, observer, fields, read_fields):
        events.append(("province", province_id, observer))
        assert tuple(fields) == GATE_FIELDS
        assert callable(read_fields)
        # The province gate is evaluated before the callback.  In the denied
        # branch the callback never runs and no financial leaf read is made.
        assert not any(event[0] == "financial" for event in events)
        if not gate_positive:
            target = {
                "fields": {field: {"status": "unknown", "reason": "PROVINCE_DISCOVERY_NOT_ESTABLISHED"}
                           for field in GATE_FIELDS},
                "field_consistency": {field: {"status": "stable"} for field in GATE_FIELDS},
            }
            return {"targets": [target], "status": "observed"}

        values_by_pass = []
        for pass_number in (1, 2):
            events.append(("positive_gate", pass_number))
            values_by_pass.append(read_fields(
                object(), module_base, {"province_id": province_id}, fields))
        assert all(set(row) == set(GATE_FIELDS) for row in values_by_pass)
        target = {
            "fields": values_by_pass[1],
            "field_consistency": {field: {"status": "stable"} for field in GATE_FIELDS},
        }
        return {"targets": [target], "status": "observed"}

    with patch.object(capture._owner, "_observe", side_effect=fake_owner_observe), \
         patch.object(capture._values, "find_node", side_effect=fake_find_node) as find_node, \
         patch.object(capture._values, "read_fields", side_effect=fake_read_fields) as financial_read, \
         patch.object(capture._province, "read_two_pass", side_effect=fake_province_read_two_pass), \
         patch.object(capture, "trade_node_scope_rule", return_value=profile["trade_node_scope_rule"]):
        observation = capture._observe_for(NODE_ID)(reader, base, "FRA", profile)

    find_node.assert_called_once_with(reader, base, NODE_ID)
    assert events[:3] == [("owner", "FRA"), ("identity", NODE_ID), ("province", 17, "FRA")]
    if gate_positive:
        assert financial_read.call_count == 2
        assert [event for event in events if event[0] == "financial"] == [
            ("financial", capture.FIELDS, NODE_ID), ("financial", capture.FIELDS, NODE_ID)]
        target = observation["targets"][0]
        assert set(target["fields"]) == set(capture.FIELDS)
        assert set(target["field_consistency"]) == set(capture.FIELDS)
    else:
        financial_read.assert_not_called()
        assert set(observation["targets"][0]["fields"]) == set(capture.FIELDS)
    assert observation["trade_node"]["node_id"] == NODE_ID
    assert observation["trade_node_scope_rule"] == profile["trade_node_scope_rule"]
