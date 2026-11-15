"""Offline contract tests for the private gate-trace audit and wire6 join.

The v5 battle base is a recorded fixture. The NTXT extension, native gate
samples, trace rows, installation, and SQLite rows are synthetic test inputs.
No fixture result is live qualification evidence.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from bridge.tests.test_information_battle_raw_text import _wire_payload
from bridge.tests.test_information_battles import _war_identity_fixture
from work import audit_information_battle_gate_trace as audit


ROOT = Path(__file__).resolve().parents[2]
AUDIT_SCRIPT = ROOT / "work/audit_information_battle_gate_trace.py"
INSTALLATION_HEX = "f921c23a9c9ecced"
GENERATION_HEX = "01dd64921da9212c"
DLL_SHA256 = "c0" * 32
SESSION_ID = "gate-audit-synthetic-session"
CREATION_FILETIME = "134374142616609068"
OBSERVER_REF = int("0100007a00415246", 16)


def _wire6_decoded() -> tuple[bytes, dict]:
    fixture = _war_identity_fixture()
    base = bytes.fromhex(fixture["payload_hex"])
    payload = _wire_payload(base, state="unknown")
    return payload, audit.decode(payload)


def _sample(default_ref: int, *, mode: int = 0, alternate_flag: int = 0,
            kind: int = 1) -> dict:
    raw = bytearray(default_ref.to_bytes(8, "little")
                    + (0x0000000000000041).to_bytes(8, "little"))
    raw[6] = mode
    raw[15] = alternate_flag
    default_value = int.from_bytes(raw[:8], "little")
    alternate_value = int.from_bytes(raw[8:], "little")
    selected_value = (
        alternate_value if raw[6] == 7 and raw[15] != 0 else default_value
    )
    return {
        "status": 2,
        "failure": 0,
        "kind": kind,
        "current_country_state": 1,
        "current_country_raw": raw.hex(),
        "mode": raw[6],
        "alternate_flag": raw[15],
        "default_ref_state": 1,
        "default_ref": f"{default_value:016x}",
        "alternate_ref_state": 1,
        "alternate_ref": f"{alternate_value:016x}",
        "selected_ref_state": 1,
        "selected_ref": f"{selected_value:016x}",
        "land_enable_state": 0,
        "land_enable_raw": 0,
        "registry_state": 0,
        "slot_state": 0,
        "combat_state": 0,
        "equals_current_combat_known": False,
        "equals_current_combat": False,
        "ui_override_known": False,
        "ui_override_value": False,
        "read_calls": 5,
        "read_bytes": 41,
    }


def _unknown_sample(kind: int = 1) -> dict:
    return {
        "status": 1,
        "failure": 7,
        "kind": kind,
        "current_country_state": 0,
        "current_country_raw": "00" * 16,
        "mode": 0,
        "alternate_flag": 0,
        "default_ref_state": 0,
        "default_ref": "0000000000000000",
        "alternate_ref_state": 0,
        "alternate_ref": "0000000000000000",
        "selected_ref_state": 0,
        "selected_ref": "0000000000000000",
        "land_enable_state": 0,
        "land_enable_raw": 0,
        "registry_state": 0,
        "slot_state": 0,
        "combat_state": 0,
        "equals_current_combat_known": False,
        "equals_current_combat": False,
        "ui_override_known": False,
        "ui_override_value": False,
        "read_calls": 5,
        "read_bytes": 41,
    }


def _expected(decoded: dict) -> dict:
    physical_ref = decoded["context"]["physical_player_full_ref"]
    return {
        "pid": 64201,
        "creation_filetime": CREATION_FILETIME,
        "dll_sha256": DLL_SHA256,
        "installation": INSTALLATION_HEX,
        "generation": GENERATION_HEX,
        "physical_ref": physical_ref,
        "observer_ref": OBSERVER_REF,
    }


def _trace(decoded: dict, expected: dict, *, sequence: str | None = None,
           samples: list[dict | None] | None = None) -> dict:
    observation = decoded["observation"]
    raw_date = observation["result"]["raw_date"]
    kind = decoded["context"]["kind"]
    physical_ref = expected["physical_ref"]
    chosen_samples = samples or [
        _sample(physical_ref, kind=kind),
        _sample(physical_ref, kind=kind),
        _sample(physical_ref, kind=kind),
        _unknown_sample(kind),
    ]
    sequence_text = str(observation["sequence"]) if sequence is None else sequence
    return {
        "schema": "EU4-BATTLE-GATE-TRACE/1",
        "pid": expected["pid"],
        "creation_filetime": expected["creation_filetime"],
        "dll_sha256": expected["dll_sha256"],
        "installation": expected["installation"],
        "generation": expected["generation"],
        "sequence": sequence_text,
        "native_date": raw_date,
        "kind": "land" if kind == 1 else "naval",
        "scope_completed": True,
        "scope_ambiguous": False,
        "counter_overflow": False,
        "scope_guards_before": True,
        "scope_guards_after": True,
        "observation_drops": "0",
        "observation_complete": True,
        "passed_marker_candidates": 0,
        "passed_marker_accepted": 0,
        "message_entries": 0,
        "message_copy_attempts": 0,
        "cleanup_entries": 0,
        "line1_entries": 0,
        "marker_reject_mask": 0,
        "message_reject_mask": 0,
        "line1_reject_mask": 0,
        "cleanup_reject_mask": 0,
        "last_marker_return_rva": 0,
        "last_message_return_rva": 0,
        "sample_mask": sum(1 << index for index, item in enumerate(chosen_samples)
                            if item is not None),
        "samples": chosen_samples,
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n",
                    encoding="utf-8")


def _write_trace(path: Path, rows: list[dict]) -> None:
    with path.open("wb") as stream:
        for row in rows:
            stream.write(json.dumps(row, separators=(",", ":")).encode("ascii")
                         + b"\n")


def test_sample_recomputes_mode_seven_alternate_and_default_rules():
    # Synthetic coherent ref whose byte 6 is the selector mode. This isolates
    # the raw getter projection from the canonical POR binding check below.
    mode_seven_ref = int("000700bd00524f50", 16)
    alternate = int("0100000000000041", 16)
    raw = bytearray(mode_seven_ref.to_bytes(8, "little")
                    + alternate.to_bytes(8, "little"))
    raw[6] = 7
    raw[15] = 1
    alt_case = _sample(mode_seven_ref, mode=7, alternate_flag=1)
    alt_case["current_country_raw"] = raw.hex()
    alt_case["alternate_ref"] = f"{int.from_bytes(raw[8:], 'little'):016x}"
    alt_case["selected_ref"] = alt_case["alternate_ref"]
    assert audit._sample(alt_case)["selected_ref"] == alt_case["alternate_ref"]

    flag_zero = _sample(mode_seven_ref, mode=7, alternate_flag=0)
    assert audit._sample(flag_zero)["selected_ref"] == flag_zero["default_ref"]
    other_mode = _sample(mode_seven_ref, mode=6, alternate_flag=1)
    assert audit._sample(other_mode)["selected_ref"] == other_mode["default_ref"]


def test_four_stage_record_keeps_por_fra_binding_and_unknown_ui():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    result = audit.audit_record(trace, decoded, expected)
    assert trace["samples"][0]["selected_ref"] == trace["samples"][0]["default_ref"]
    assert result["physical_player_full_ref"] == f"{expected['physical_ref']:016x}"
    assert result["native_date"] == decoded["observation"]["result"]["raw_date"]
    assert result["kind"] == "land"
    assert result["observer_participated"] is True
    assert result["observation_complete"] is True
    assert result["native_line1_state"] == "unknown"
    assert result["full_b04_complete"] is False
    assert result["visibility_verified"] is False


def test_router_return_rva_nonzero_is_valid_without_changing_diagnosis():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    legacy_result = audit.audit_record(_trace(decoded, expected), decoded, expected)
    trace = _trace(decoded, expected)
    trace["router_return_rva"] = 0x89ABCDEF
    result = audit.audit_record(trace, decoded, expected)
    assert result["diagnosis"] == legacy_result["diagnosis"]
    assert result["observation_complete"] is True


def test_legacy_trace_without_router_return_rva_remains_accepted():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    assert "router_return_rva" not in trace
    result = audit.audit_record(trace, decoded, expected)
    assert result["diagnosis"] == "unresolved_formatter_completion_binding"


@pytest.mark.parametrize("bad_value", [True, -1, 1 << 32])
def test_router_return_rva_rejects_bool_negative_and_overflow(bad_value):
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace["router_return_rva"] = bad_value
    with pytest.raises(ValueError, match="integer_out_of_bounds"):
        audit.audit_record(trace, decoded, expected)


def test_four_stage_mode_seven_trace_uses_coherent_synthetic_por_ref():
    _, decoded = _wire6_decoded()
    decoded = deepcopy(decoded)
    mode_seven_ref = int("000700bd00524f50", 16)
    decoded["context"]["physical_player_full_ref"] = mode_seven_ref
    expected = _expected(decoded)
    samples = [
        _sample(mode_seven_ref, mode=7, alternate_flag=1),
        _sample(mode_seven_ref, mode=7, alternate_flag=0),
        _sample(mode_seven_ref, mode=7, alternate_flag=1),
        _unknown_sample(1),
    ]
    result = audit.audit_record(_trace(decoded, expected, samples=samples),
                                decoded, expected)
    assert samples[0]["selected_ref"] == samples[0]["alternate_ref"]
    assert samples[1]["selected_ref"] == samples[1]["default_ref"]
    assert result["physical_player_full_ref"] == f"{mode_seven_ref:016x}"
    assert all(sample["ui_override_known"] is False for sample in samples)
    assert result["native_line1_state"] == "unknown"


@pytest.mark.parametrize(
    "key,bad_value",
    [
        ("pid", 64202),
        ("creation_filetime", "134374142616609069"),
        ("dll_sha256", "d1" * 32),
        ("installation", "f921c23a9c9ecc00"),
        ("generation", "01dd64921da92000"),
    ],
)
def test_trace_is_bound_to_process_installation_generation_and_dll(key, bad_value):
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace[key] = bad_value
    with pytest.raises(ValueError, match=f"trace_identity_mismatch:{key}"):
        audit.audit_record(trace, decoded, expected)


def test_sequence_date_kind_and_physical_player_are_bound():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected,
                   sequence=str(int(decoded["observation"]["sequence"]) + 1))
    with pytest.raises(ValueError, match="trace_payload_sequence_mismatch"):
        audit.audit_record(trace, decoded, expected)

    trace = _trace(decoded, expected)
    trace["native_date"] += 1
    with pytest.raises(ValueError, match="trace_payload_date_mismatch"):
        audit.audit_record(trace, decoded, expected)

    trace = _trace(decoded, expected)
    trace["kind"] = "naval"
    with pytest.raises(ValueError, match="trace_payload_kind_mismatch"):
        audit.audit_record(trace, decoded, expected)

    changed_context = deepcopy(decoded)
    changed_context["context"]["physical_player_full_ref"] ^= 0x0100000000000000
    with pytest.raises(ValueError, match="physical_player_changed"):
        audit.audit_record(_trace(decoded, expected), changed_context, expected)

    different_ref = expected["physical_ref"] ^ 0x0100000000000000
    mixed_samples = [
        _sample(expected["physical_ref"], kind=1),
        _sample(expected["physical_ref"], kind=1),
        _sample(different_ref, kind=1),
        _unknown_sample(1),
    ]
    with pytest.raises(ValueError, match="physical_player_changed_inside_scope"):
        audit.audit_record(_trace(decoded, expected, samples=mixed_samples),
                           decoded, expected)


def test_sample_raw_hex_and_unknown_state_are_recomputed():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace["samples"][0]["mode"] = 7
    with pytest.raises(ValueError, match="selector_raw_fields_mismatch"):
        audit.audit_record(trace, decoded, expected)

    trace = _trace(decoded, expected)
    trace["samples"][0]["default_ref"] = "0000000000000001"
    with pytest.raises(ValueError, match="selector_raw_refs_mismatch"):
        audit.audit_record(trace, decoded, expected)

    trace = _trace(decoded, expected)
    trace["samples"][3]["selected_ref"] = "0000000000000001"
    with pytest.raises(ValueError, match="unknown_selector_contains_values"):
        audit.audit_record(trace, decoded, expected)

    trace = _trace(decoded, expected)
    trace["samples"][0]["ui_override_value"] = True
    with pytest.raises(ValueError, match="override_true_without_inputs"):
        audit.audit_record(trace, decoded, expected)


@pytest.mark.parametrize(
    "changes",
    [
        {"scope_completed": False},
        {"scope_ambiguous": True},
        {"counter_overflow": True},
        {"observation_drops": "1"},
    ],
)
def test_incomplete_scope_with_zero_marker_is_not_called_gate_not_reached(changes):
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace.update(changes)
    trace["observation_complete"] = False
    result = audit.audit_record(trace, decoded, expected)
    assert result["observation_complete"] is False
    assert result["diagnosis"] == "unresolved_incomplete_scope_observation"
    assert result["diagnosis"] != "post_gate_call_not_reached_before_formatter_cleanup"


@pytest.mark.parametrize("field", ["scope_guards_before", "scope_guards_after"])
def test_scope_guard_discontinuity_keeps_complete_counters_unresolved(field):
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace[field] = False
    result = audit.audit_record(trace, decoded, expected)
    assert result["observation_complete"] is True
    assert result["diagnosis"] == "unresolved_scope_guard_continuity"
    assert result["native_line1_state"] == "unknown"
    assert result["full_b04_complete"] is False


def test_complete_flag_cannot_overclaim_and_copy_attempts_are_distinct():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace["counter_overflow"] = True
    with pytest.raises(ValueError, match="observation_complete_overclaim"):
        audit.audit_record(trace, decoded, expected)

    trace = _trace(decoded, expected)
    trace["message_entries"] = 1
    trace["message_copy_attempts"] = 0
    trace["message_reject_mask"] = 0
    result = audit.audit_record(trace, decoded, expected)
    assert result["diagnosis"] == "message_entry_seen_copy_not_attempted_reason_unresolved"

    trace["message_reject_mask"] = 1
    result = audit.audit_record(trace, decoded, expected)
    assert result["diagnosis"] == "message_entry_seen_copy_filter_rejected"

    trace["message_copy_attempts"] = 1
    result = audit.audit_record(trace, decoded, expected)
    assert result["diagnosis"] == "message_entry_seen_copy_attempted"

    trace["message_entries"] = 0
    with pytest.raises(ValueError, match="copy_without_message_entry"):
        audit.audit_record(trace, decoded, expected)


def test_rejected_marker_candidate_keeps_line1_and_b04_unknown():
    _, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    trace["passed_marker_candidates"] = 2
    trace["passed_marker_accepted"] = 0
    trace["marker_reject_mask"] = 0x04
    result = audit.audit_record(trace, decoded, expected)
    assert result["diagnosis"] == "post_gate_call_seen_scope_binding_rejected"
    assert result["native_line1_state"] == "unknown"
    assert result["full_b04_complete"] is False
    assert result["visibility_verified"] is False


def test_read_trace_requires_bounded_ascii_complete_lf_and_unique_json_keys(tmp_path, monkeypatch):
    valid = tmp_path / "valid.jsonl"
    valid.write_bytes(b'{"sequence":"7"}\n{"sequence":"7"}\n')
    rows = audit.read_trace(valid)
    assert len(rows) == 2
    assert rows[0]["sequence"] == rows[1]["sequence"] == "7"

    crlf = tmp_path / "crlf.jsonl"
    crlf.write_bytes(b'{"sequence":"7"}\r\n')
    with pytest.raises(ValueError, match="trace_line_not_complete_LF"):
        audit.read_trace(crlf)

    no_final_lf = tmp_path / "no-final-lf.jsonl"
    no_final_lf.write_bytes(b'{"sequence":"7"}')
    with pytest.raises(ValueError, match="trace_line_not_complete_LF"):
        audit.read_trace(no_final_lf)

    duplicate_key = tmp_path / "duplicate-key.jsonl"
    duplicate_key.write_bytes(b'{"sequence":"7","sequence":"8"}\n')
    with pytest.raises(ValueError, match="duplicate_json_key"):
        audit.read_trace(duplicate_key)

    too_long = tmp_path / "too-long.jsonl"
    too_long.write_bytes(b'{"pad":"' + b"a" * audit.MAX_LINE_BYTES + b'"}\n')
    with pytest.raises(ValueError, match="trace_line_not_complete_LF"):
        audit.read_trace(too_long)

    monkeypatch.setattr(audit, "MAX_TRACE_BYTES", 4)
    with pytest.raises(ValueError, match="trace_size_out_of_bounds"):
        audit.read_trace(valid)


def _write_cli_bundle(tmp_path: Path, trace_rows: list[dict], payload: bytes,
                      decoded: dict) -> tuple[list[str], Path, Path, Path]:
    live = tmp_path / "synthetic-install"
    live.mkdir()
    dll_path = live / "eu4_bridge_diplomacy_observer_v32.dll"
    dll_path.write_bytes(b"synthetic-test-only-v32-dll")
    dll_sha = hashlib.sha256(dll_path.read_bytes()).hexdigest()
    for row in trace_rows:
        row["dll_sha256"] = dll_sha
    installation = {
        "pid": 64201,
        "creation_filetime": int(CREATION_FILETIME),
        "session_id": SESSION_ID,
        "dll_sha256": dll_sha,
    }
    _write_json(live / "installation.json", installation)
    _write_json(live / "build-manifest.json", {
        "version": 32,
        "information_battle_gate_trace": True,
        "synthetic_test_only": True,
    })
    _write_json(live / "information-battle-binding.json", {
        "pid": 64201,
        "creation_filetime": CREATION_FILETIME,
        "session_id": SESSION_ID,
        "dll_sha256": dll_sha,
        "installation": int(INSTALLATION_HEX, 16),
        "generation": int(GENERATION_HEX, 16),
        "player_ref": f"{decoded['context']['physical_player_full_ref']:016x}",
    })

    database = tmp_path / "synthetic-battle.sqlite3"
    sequence = str(trace_rows[0]["sequence"])
    payload_sha = hashlib.sha256(payload).hexdigest()
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE fragment_groups (
                group_id INTEGER PRIMARY KEY,
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                message_id TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE complete_messages (
                group_id INTEGER PRIMARY KEY,
                payload BLOB NOT NULL,
                payload_sha256 TEXT NOT NULL,
                total_bytes INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO fragment_groups VALUES(1,?,?,?,?,?)",
            (INSTALLATION_HEX, GENERATION_HEX, sequence, len(payload), "complete"),
        )
        connection.execute(
            "INSERT INTO complete_messages VALUES(1,?,?,?)",
            (sqlite3.Binary(payload), payload_sha, len(payload)),
        )

    stream = tmp_path / "battle-stream.json"
    _write_json(stream, {
        "database": str(database),
        "binding": {
            "installation": INSTALLATION_HEX,
            "generation": GENERATION_HEX,
            "session_id": SESSION_ID,
            "observer_ref": "0100007a00415246",
        },
    })
    trace_path = tmp_path / "synthetic-trace.jsonl"
    _write_trace(trace_path, trace_rows)
    manifest_sha = hashlib.sha256((live / "build-manifest.json").read_bytes()).hexdigest()
    argv = [
        sys.executable, str(AUDIT_SCRIPT),
        "--installation", str(live / "installation.json"),
        "--battle-stream", str(stream),
        "--trace", str(trace_path),
        "--output", str(tmp_path / "audit-output.json"),
        "--expected-manifest-sha256", manifest_sha,
        "--expected-dll-sha256", dll_sha,
    ]
    return argv, database, trace_path, tmp_path / "audit-output.json"


def test_cli_joins_synthetic_wire6_to_real_complete_messages_sqlite_read_only(tmp_path):
    payload, decoded = _wire6_decoded()
    physical = decoded["context"]["physical_player_full_ref"]
    assert physical.to_bytes(8, "little")[:3] == b"POR"
    assert OBSERVER_REF.to_bytes(8, "little")[:3] == b"FRA"
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    argv, database, trace_path, output = _write_cli_bundle(
        tmp_path, [trace], payload, decoded,
    )
    db_before = hashlib.sha256(database.read_bytes()).hexdigest()
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                            timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary == {"status": "joined_with_diagnostic_limits", "records": 1,
                       "FRA_records": 1}
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["identity"]["physical_ref"] == physical
    assert report["identity"]["observer_ref"] == OBSERVER_REF
    assert report["records"][0]["physical_player_full_ref"] == f"{physical:016x}"
    assert report["records"][0]["sequence"] == int(trace["sequence"])
    assert report["records"][0]["native_line1_state"] == "unknown"
    assert report["records"][0]["full_b04_complete"] is False
    assert report["records"][0]["visibility_verified"] is False
    assert report["activity"]["SQLite"] == "mode=ro/query_only/one_read_transaction"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == db_before
    assert not Path(str(database) + "-journal").exists()
    assert trace_path.is_file()


def test_cli_rejects_duplicate_trace_sequence_without_creating_output(tmp_path):
    payload, decoded = _wire6_decoded()
    expected = _expected(decoded)
    trace = _trace(decoded, expected)
    argv, _, _, output = _write_cli_bundle(tmp_path, [trace, trace], payload, decoded)
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                            timeout=30, check=False)
    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["status"] == "failed"
    assert "duplicate_trace_sequence" in error["error"]
    assert not output.exists()
