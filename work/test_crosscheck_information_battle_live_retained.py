"""Offline tests for the independent v23 retained reader.

The seams are local to ``crosscheck_information_battle_live_retained``.  No
game process, control command, REA, or native function is used by this file.
Most normalization assertions use the recorded ``live-fra-bur-002`` result
shape; temporary wire JSON is derived from those recorded bytes and is never
claimed as a new live observation.
"""
from __future__ import annotations

import ctypes as C
import copy
import hashlib
import json
from pathlib import Path

import pytest

from work import crosscheck_information_battle_live_retained as cross
from work import information_battle_war_memory as old
from work import probe_information_battle_v23 as v23


REAL_RETAINED_REPORT = Path(
    "work/runtime/information-battle-war-records-20261025-001/live-fra-bur-002/report.json"
)


def _sso(raw_hex: str, length: int) -> dict:
    return {"status": "observed", "complete": True, "length": length, "capacity": length, "payload_raw_hex": raw_hex, "bytes_hex": raw_hex}


def _real_result() -> dict:
    """Load the recorded live result shape; this is not a synthetic result."""
    assert REAL_RETAINED_REPORT.is_file()
    document = json.loads(REAL_RETAINED_REPORT.read_text(encoding="utf-8"))
    return document["results"][0]["result"]


def _wire_sso(value: dict) -> dict:
    return {"length": value["length"], "raw_hex": value["bytes_hex"]}


def _wire_message_from_real_result(result: dict, *, raw_date: int | None = None) -> dict:
    sides = []
    for side_name in ("side_a", "side_b"):
        side = result[side_name]
        country = side["country"]
        fields = [side["fields"][field]["raw"] for field, _offset in old.SIDE_SCALAR_OFFSETS]
        sides.append(
            {
                # The wire carries the numeric 16-hex reference, not the
                # retained reader's little-endian identity_raw_hex bytes.
                "country_raw_hex": f"{int(country['identity'], 0):016x}",
                "raw_fields": fields,
                "commander": _wire_sso(side["commander"]),
            }
        )
    native = {
        "raw_date": result["timeline_date"]["raw"] if raw_date is None else raw_date,
        "flag108": result["flag"]["raw"],
        "aux100": result["aux"]["first"]["raw"],
        "aux104": result["aux"]["second"]["raw"],
        "province_id": result["province_id"]["raw"],
        "name": _wire_sso(result["name"]),
        "sides": sides,
    }
    return {
        "message_id": "recorded-result-1",
        "decode": {"value": {"observation": {"result": native}}},
    }


def _snapshot(pair: tuple[str, str], *, raw_date: int = 165) -> dict:
    actor, recipient = pair
    side_a = {"status": "observed", "complete": True, "country": {"status": "observed", "tag": actor, "identity_raw_hex": "0100000100414243"}, "commander": _sso("aa", 1)}
    side_b = {"status": "observed", "complete": True, "country": {"status": "observed", "tag": recipient, "identity_raw_hex": "0100000200444546"}, "commander": _sso("bb", 1)}
    result = {
        "status": "observed",
        "complete": True,
        "name": _sso("1020", 2),
        "province_id": {"raw": 123, "raw_hex": "7b000000", "offset": "0x20"},
        "side_a": side_a,
        "side_b": side_b,
        # This is deliberately not used as the public/event date.
        "raw_date": raw_date,
        "timeline_date": {"raw": 56553384, "raw_hex": "a8ef5e03", "offset": "0x10"},
    }
    return {
        "status": "observed",
        "complete": True,
        "pass": 1,
        "wars": [{"status": "observed", "complete": True, "results": {"status": "observed", "complete": True, "results": [result]}}],
        "unknown_conditions": [],
        "read_log": [],
    }


class _Kernel:
    def __init__(self, *, short: bool = False):
        self.short = short
        self.closed = False

    def OpenProcess(self, _mask, _inherit, _pid):
        return 77

    def ReadProcessMemory(self, _handle, address, buffer, size, actual):
        if self.short:
            actual._obj.value = max(0, size - 1)
            return True
        value = int(getattr(address, "value", address)) & 0xFF
        C.memset(buffer, value, size)
        actual._obj.value = size
        return True


def _doc() -> dict:
    return {
        "experiment_id": v23.BUILD_ID,
        "pid": 777,
        "creation_filetime": 123456,
        "session_id": "777-1e240",
        "game_sha256": v23.EXPECTED_EXE_SHA256,
        "dll_sha256": v23.EXPECTED_DLL_SHA256,
        "modules_after_install": [{"name": "eu4_bridge_diplomacy_observer_v23.dll", "path": "fake.dll", "sha256": v23.EXPECTED_DLL_SHA256}],
    }


def _configure_success(monkeypatch: pytest.MonkeyPatch, *, close_status: str = "closed", date_after: int | None = None):
    kernel = _Kernel()
    calls = {"snapshot": 0, "close": 0}
    monkeypatch.setattr(cross, "_load_document", lambda _path: (_doc(), {"status": "observed", "sha256": "install"}))
    monkeypatch.setattr(cross, "_validate_installation", lambda document, expected_exe, build_dir, report: None)
    monkeypatch.setattr(cross, "_manifest_static_guard", lambda _build: {"status": "observed", "checks": {"sources": True}})
    monkeypatch.setattr(cross, "_file_code_guard", lambda _path: {"status": "observed", "records": {}})
    monkeypatch.setattr(cross, "_coff_symbol", lambda _path: {"status": "observed", "rva": "0x20"})
    monkeypatch.setattr(cross, "_configure_kernel", lambda: kernel)
    monkeypatch.setattr(cross, "_capture_identity", lambda _kernel, _handle, document, _exe, phase: {"phase": phase, "status": "observed", "pid": document["pid"], "session_id": document["session_id"], "module_base": "0x100000", "process_path_sha256": v23.EXPECTED_EXE_SHA256})
    monkeypatch.setattr(cross, "_query_loaded_dll", lambda *_args: {"status": "observed", "matching_modules": [{"base": "0x200000", "sha256": v23.EXPECTED_DLL_SHA256}]})
    monkeypatch.setattr(cross, "_runtime_code_guard", lambda _reader, _base, phase, _expect, _stub: {"phase": phase, "status": "observed", "records": {"entry": {"matches": True}, "unwind": {"matches": True}}})

    def fake_context(_reader, _base, phase):
        date = date_after if phase == "after" and date_after is not None else 56553384
        return {
            "phase": phase,
            "status": "observed",
            "physical_player": {"tag": "POR", "complete": True},
            "control": {"status": "observed", "paused": {"value": True}, "speed": {"value": 0}},
            "game_date": {"raw": date, "raw_hex": date.to_bytes(4, "little", signed=True).hex()},
        }

    monkeypatch.setattr(cross, "_context_snapshot", fake_context)

    def fake_retained(reader, _base, actor, recipient, _limit, pass_index):
        calls["snapshot"] += 1
        reader.read(0x200000, 16, f"{('before' if pass_index == 1 else 'after')}.retained.{actor}.{recipient}")
        result = _snapshot((actor, recipient), raw_date=165)
        result["pass"] = pass_index
        return result

    monkeypatch.setattr(cross, "_retained_snapshot", fake_retained)

    def fake_close(_kernel, _handle):
        calls["close"] += 1
        return {"status": close_status, "success": close_status == "closed", "closed": close_status == "closed"}

    monkeypatch.setattr(cross, "_close_process_handle", fake_close)
    return calls


def test_success_two_fixed_pairs_is_paused_and_unmatched_raw(monkeypatch):
    calls = _configure_success(monkeypatch)
    report = cross.capture(Path("synthetic-installation.json"), pairs=cross.ALLOWED_PAIRS, raw_reference=cross.DEFAULT_RAW_REFERENCE)
    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["identity"]["binding_verified"] is True
    assert report["doublepass"]["performed"] is True
    assert report["doublepass"]["consistent"] is True
    assert report["doublepass"]["mismatches"] == []
    assert report["access"]["rpm_bytes_requested"] == 64
    assert report["access"]["rpm_bytes_requested"] <= cross.MAX_TOTAL_RPM
    assert len(report["pairs"]) == 2
    assert report["raw_crosscheck"]["raw_date_not_used_as_date"] is True
    assert report["raw_crosscheck"]["status"] == "unmatched_only"
    assert all(item["records_after"][0]["date"]["raw"] == 56553384 for item in report["pairs"])
    assert all(item["records_after"][0]["retained_raw_date"] == 165 for item in report["pairs"])
    assert calls["snapshot"] == 4
    assert calls["close"] == 1


def test_pair_scope_is_fixed_and_bounded():
    with pytest.raises(cross.ProbeError, match="pair_not_in_fixed_scope"):
        cross._validate_pairs((("FRA", "ENG"),))
    with pytest.raises(cross.ProbeError, match="pairs_count_out_of_bound"):
        cross._validate_pairs((cross.ALLOWED_PAIRS[0], cross.ALLOWED_PAIRS[1], ("FRA", "TYR")))
    with pytest.raises(cross.ProbeError, match="pair_duplicate"):
        cross._validate_pairs((cross.ALLOWED_PAIRS[0], cross.ALLOWED_PAIRS[0]))


def test_context_date_change_retracts_results(monkeypatch):
    _configure_success(monkeypatch, date_after=56553385)
    report = cross.capture(Path("synthetic-installation.json"), pairs=(cross.ALLOWED_PAIRS[0],), raw_reference=cross.DEFAULT_RAW_REFERENCE)
    assert report["status"] == "failed_read_only_crosscheck"
    assert report["pairs"] == []
    assert report["doublepass"]["consistent"] is False
    assert any("game_date_changed_between_passes" in item["error"] for item in report["errors"])


def test_cleanup_failure_retracts_success(monkeypatch):
    _configure_success(monkeypatch, close_status="error")
    report = cross.capture(Path("synthetic-installation.json"), pairs=(cross.ALLOWED_PAIRS[0],), raw_reference=cross.DEFAULT_RAW_REFERENCE)
    assert report["status"] == "cleanup_error"
    assert report["pairs"] == []
    assert report["raw_crosscheck"] is None
    assert report["cleanup"]["handle_close"]["calls"] == 1


def test_identity_and_pause_guards_are_required(monkeypatch):
    calls = _configure_success(monkeypatch)
    monkeypatch.setattr(cross, "_capture_identity", lambda *_args: {"status": "mismatch", "session_id": "wrong", "module_base": "0x100000"})
    report = cross.capture(Path("synthetic-installation.json"), pairs=(cross.ALLOWED_PAIRS[0],), raw_reference=cross.DEFAULT_RAW_REFERENCE)
    assert report["status"] == "failed_read_only_crosscheck"
    assert report["pairs"] == []
    assert calls["close"] == 1


def test_v23_hash_is_independent_from_old_v22_pin():
    assert cross.EXPECTED_DLL_SHA256 == v23.EXPECTED_DLL_SHA256
    assert cross.EXPECTED_DLL_SHA256 != old.EXPECTED_DLL_SHA256
    assert cross.EXPECTED_EXE_SHA256 == v23.EXPECTED_EXE_SHA256


def test_address_reader_rejects_short_read_and_total_budget():
    short = old.AddressBoundedRPM(_Kernel(short=True), 1, 0x100000)
    with pytest.raises(Exception, match="short_read"):
        short.read(0x200000, 8, "short")
    reader = old.AddressBoundedRPM(_Kernel(), 1, 0x100000)
    for _ in range(cross.MAX_TOTAL_RPM // cross.MAX_SINGLE_RPM):
        reader.read(0x200000, cross.MAX_SINGLE_RPM, "budget")
    with pytest.raises(Exception, match="RPM_TOTAL_BUDGET_EXCEEDED"):
        reader.read(0x200000, 1, "budget-over")


def test_invalid_installation_hash_is_rejected_before_process_open(tmp_path):
    exe = tmp_path / "eu4.exe"
    exe.write_bytes(b"synthetic")
    document = _doc()
    document["game_sha256"] = "0" * 64
    report = cross._new_report(tmp_path / "installation.json", cross.ALLOWED_PAIRS[:1], 1, "installed")
    with pytest.raises(cross.ProbeError, match="installation_exe_sha256_mismatch"):
        cross._validate_installation(document, exe, tmp_path, report)


def test_raw_record_keeps_wire_raw_date_separate_from_history_date():
    raw = cross._raw_record({"message_id": "1", "decode": {"value": {"observation": {"result": {"name": {"length": 1, "raw_hex": "aa"}, "province_id": 5, "raw_date": 165, "sides": []}}}}})
    assert raw is not None
    assert raw["date"] is None
    assert raw["raw_date"] == 165
    retained = cross._retained_field_copy(_snapshot(cross.ALLOWED_PAIRS[0])["wars"][0]["results"]["results"][0], cross.ALLOWED_PAIRS[0], index=0)
    assert retained["date"]["raw"] == 56553384
    assert retained["retained_raw_date"] == 165


def _write_raw_reference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, messages: list[dict]) -> Path:
    path = tmp_path / "raw-after-window-002.json"
    payload = (json.dumps({"messages": messages}, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.write_bytes(payload)
    # This patches only the new crosscheck's immutable-reference pin so a
    # temporary copy can exercise the exact parser without changing old v22
    # reader constants or the recorded source file.
    monkeypatch.setattr(cross, "RAW_REFERENCE_SHA256", hashlib.sha256(payload).hexdigest())
    return path


def test_real_record_shape_normalizes_numeric_refs_and_raw_slots():
    result = _real_result()
    retained = cross._retained_field_copy(result, ("FRA", "BUR"), index=0)
    wire = cross._raw_record(_wire_message_from_real_result(result))
    assert wire is not None

    assert cross._tag_from_raw("010000bd00524f50") == "POR"
    assert retained["countryrefs"] == [
        {"ref": "0100007a00415246", "tag": "FRA"},
        {"ref": "0100007500525542", "tag": "BUR"},
    ]
    assert wire["countryrefs"] == retained["countryrefs"]
    assert wire["name"] == retained["name"]
    assert wire["commander"] == retained["commander"]
    assert wire["province"] == 1285
    assert wire["raw_fields"] == retained["raw_fields"] == [
        [0, 0, 0, 0, 3, 0, 0, 3, 0],
        [0, 0, 0, 3, 6, 0, 13, 0, 0],
    ]
    assert wire["raw_count"] == len(old.SIDE_SCALAR_OFFSETS) == 9
    assert wire["aux_raw"] == retained["aux_raw"] == [142000, 147000]
    assert wire["flag_raw"] == retained["flag_raw"] == 0
    assert wire["date"] is None
    assert retained["date"]["raw"] == 56552232
    assert set(retained["name"]) == {"length", "raw_hex"}
    assert set(retained["commander"][0]) == {"length", "raw_hex"}


def test_real_country_handle_fallback_keeps_full_numeric_reference():
    result = copy.deepcopy(_real_result())
    for side_name in ("side_a", "side_b"):
        country = result[side_name]["country"]
        country.pop("identity")
    retained = cross._retained_field_copy(result, ("FRA", "BUR"), index=0)
    assert retained["countryrefs"] == [
        {"ref": "0100007a00415246", "tag": "FRA"},
        {"ref": "0100007500525542", "tag": "BUR"},
    ]
    assert cross._numeric_ref("0100007a00415246") == "0100007a00415246"


def test_real_shape_crosscheck_matches_full_key_and_keeps_date_difference(tmp_path, monkeypatch):
    result = _real_result()
    retained = cross._retained_field_copy(result, ("FRA", "BUR"), index=0)
    message = _wire_message_from_real_result(result, raw_date=56553384)
    path = _write_raw_reference(tmp_path, monkeypatch, [message])

    checked = cross._raw_crosscheck([retained], path)
    assert checked["status"] == "observed"
    assert checked["matched"] and checked["matched"][0]["raw_index"] == 0
    assert checked["mismatches"] == []
    assert checked["matched"][0]["fields"]["date"]["status"] == "post_field_difference"
    assert checked["matched"][0]["fields"]["date"]["retained_history_raw"] == 56552232
    assert checked["matched"][0]["fields"]["date"]["raw_wire_snapshot_raw_date"] == 56553384
    assert checked["raw_date_not_used_as_date"] is True
    assert checked["unmatched_retained"] == []
    assert checked["unmatched_raw"] == []


def test_real_shape_requires_full_countryrefs_and_preserves_ambiguity(tmp_path, monkeypatch):
    result = _real_result()
    retained = cross._retained_field_copy(result, ("FRA", "BUR"), index=0)
    message = _wire_message_from_real_result(result)

    ambiguous_path = _write_raw_reference(tmp_path, monkeypatch, [message, copy.deepcopy(message)])
    ambiguous = cross._raw_crosscheck([retained], ambiguous_path)
    assert ambiguous["matched"] == []
    assert len(ambiguous["ambiguous"]) == 1
    assert ambiguous["ambiguous"][0]["candidate_raw_indices"] == [0, 1]
    assert len(ambiguous["unmatched_raw"]) == 2

    mismatched = copy.deepcopy(message)
    mismatched["decode"]["value"]["observation"]["result"]["sides"][0]["country_raw_hex"] = "0100007a00415247"
    mismatched_path = _write_raw_reference(tmp_path, monkeypatch, [mismatched])
    no_match = cross._raw_crosscheck([retained], mismatched_path)
    assert no_match["matched"] == []
    assert len(no_match["unmatched_retained"]) == 1
    assert no_match["unmatched_retained"][0]["stable_key"][0] != no_match["unmatched_raw"][0]["stable_key"][0]


def test_cli_requires_explicit_authorized_installation():
    with pytest.raises(SystemExit) as exc:
        cross.main([])
    assert exc.value.code == 2
