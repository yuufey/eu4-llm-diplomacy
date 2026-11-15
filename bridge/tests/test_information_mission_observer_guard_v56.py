"""Pinned56 guards recognize both task entry and the conjunction CALL patch."""
import hashlib
import struct

import pytest

from bridge.information import mission_observer_guard as guard
from bridge.information import mission_prerequisite_memory as prerequisite
from bridge.information import mission_trigger_profile as profile
from bridge.information.mission_condition_memory import _TrackingReader
from bridge.tests.test_information_mission_observer_guard import fixture as availability_fixture


def fixture():
    reader, availability, asset, dll_base, _ = availability_fixture(56)
    condition = asset["condition"]
    source = next(row for row in profile.load_profile()["code_guards"] if row["rva"] == guard.CONDITION_RVA)
    original = bytes.fromhex(source["raw_hex"])
    executable = 0x150000000
    hook = dll_base + condition["observe_rva"]
    patch = b"\x90\xe8" + struct.pack("<i", executable - (reader.module_base + guard.CONDITION_RVA + 47))
    reader.put(reader.module_base + guard.CONDITION_RVA, original[:41] + patch + original[47:])
    image = bytearray.fromhex(condition["image_hex"])
    image[70:78] = struct.pack("<Q", hook)
    reader.put(executable, bytes(image))
    reader.put(hook, bytes.fromhex(condition["observe_hex"]))
    reader.put(dll_base + condition["observe_unwind_rva"], bytes.fromhex(condition["observe_unwind_hex"]))
    reader.qword_put(dll_base + condition["game_base_rva"], reader.module_base)
    reader.qword_put(dll_base + condition["executable_rva"], executable)
    reader.put(dll_base + condition["runtime_functions_rva"], b"".join(
        struct.pack("<III", *row) for row in condition["runtime_functions"]))
    reader.put(dll_base + condition["table_registered_rva"], b"\x01")
    return reader, availability, source, condition, dll_base, executable


@pytest.mark.parametrize("tracked", [False, True])
def test_v56_retains_both_actual_patches_and_independent_unwind_proof(tracked):
    reader, availability, condition, _, _, _ = fixture()
    source = _TrackingReader(reader) if tracked else reader
    reports = prerequisite._validate_code_guards(source, reader.module_base, [availability, condition])
    assert [row["observer_patch"]["kind"] for row in reports] == [
        "verified_v56_mission_availability_entry", "verified_v56_mission_condition_callsite"]
    for report in reports:
        assert report["matches"] is False
        assert report["sha256"] == hashlib.sha256(bytes.fromhex(report["raw_hex"])).hexdigest()
        assert report["raw_hex"] != report["expected_raw_hex"]
    assert len(reports[1]["observer_patch"]["reads"]) == 7
    if tracked:
        assert len(source.rawreads) >= 15


@pytest.mark.parametrize("damage", [
    "binding", "unknown_dll", "call_opcode", "call_target", "original_prefix", "test_instruction",
    "executable_alignment", "body", "observer_unwind", "game_base", "hook_immediate",
    "gateway", "relay", "relay_unwind", "gateway_unwind", "runtime_rows", "table_registration",
])
def test_v56_rejects_any_unbound_or_changed_condition_patch(damage):
    reader, _, source, asset, dll_base, executable = fixture()
    addresses = {
        "call_opcode": reader.module_base + guard.CONDITION_RVA + 41,
        "call_target": reader.module_base + guard.CONDITION_RVA + 43,
        "original_prefix": reader.module_base + guard.CONDITION_RVA,
        "test_instruction": reader.module_base + guard.CONDITION_RVA + 47,
        "executable_alignment": dll_base + asset["executable_rva"],
        "body": dll_base + asset["observe_rva"],
        "observer_unwind": dll_base + asset["observe_unwind_rva"],
        "game_base": dll_base + asset["game_base_rva"],
        "hook_immediate": executable + 70,
        "gateway": executable + 29,
        "relay": executable + 112 + 44,
        "relay_unwind": executable + 208,
        "gateway_unwind": executable + 96,
        "runtime_rows": dll_base + asset["runtime_functions_rva"] + 16,
        "table_registration": dll_base + asset["table_registered_rva"],
    }
    if damage == "binding":
        reader.mission_observer_binding = None
    elif damage == "unknown_dll":
        reader.mission_observer_binding["dll_sha256"] = "0" * 64
    else:
        reader.memory[addresses[damage]] ^= 1
    with pytest.raises(ValueError):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


def test_old_observer_binding_does_not_authorize_new_condition_patch():
    reader, _, source, _, _, _ = fixture()
    reader.mission_observer_binding["dll_sha256"] = next(
        key for key, value in guard._BUILDS.items() if value["version"] == 55)
    with pytest.raises(ValueError, match="runtime_mismatch"):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


def test_unpatched_conjunction_keeps_original_guard_without_binding():
    reader, _, source, _, _, _ = fixture()
    reader.mission_observer_binding = None
    reader.put(reader.module_base + guard.CONDITION_RVA, bytes.fromhex(source["raw_hex"]))
    report = prerequisite._validate_code_guards(reader, reader.module_base, [source])[0]
    assert report["matches"] is True and "observer_patch" not in report


def test_m02_profile_loads_current_guard_and_exact56_asset():
    assert profile.load_profile()["profile_revision"] == 11


@pytest.mark.parametrize("change_between_reads", [False, True])
def test_normal_m02_capture_uses_both_guards_and_withdraws_a_changed_runtime_table(monkeypatch, change_between_reads):
    from bridge.information import mission_memory
    from bridge.tests.test_information_mission_trigger_capture import capture, fixture as trigger_fixture

    reader, module, _ = trigger_fixture()
    patched, _, _, asset, dll_base, _ = fixture()
    reader.memory.update(patched.memory)
    reader.mission_observer_binding = patched.mission_observer_binding
    monkeypatch.setattr(guard, "bind_loaded_observer", lambda *args: None)
    original_snapshot = mission_memory._snapshot
    calls = 0

    def snapshot(*args, **kwargs):
        nonlocal calls
        calls += 1
        if change_between_reads and calls == 2:
            reader.memory[dll_base + asset["runtime_functions_rva"] + 16] ^= 1
        return original_snapshot(*args, **kwargs)

    report = capture(reader, module, snapshot=snapshot)
    assert report["doublepass"]["condition_consistent"] is True
    assert report["doublepass"]["trigger_consistent"] is (not change_between_reads)
    if change_between_reads:
        assert report["mission_triggers"]["status"] == "unknown"
    else:
        assert report["mission_triggers"]["status"] == "observed"
        proof = next(row["observer_patch"] for row in report["mission_triggers"]["code_guards"]
            if row["rva"] == hex(guard.CONDITION_RVA))
        assert proof["kind"] == "verified_v56_mission_condition_callsite" and proof["reads"]
