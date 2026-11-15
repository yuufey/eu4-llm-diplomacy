"""Exact60 guards for the province entry, retained task entry and root CALL."""
import json
import struct

import pytest

from bridge.information import mission_observer_guard as guard
from bridge.information import mission_prerequisite_memory as prerequisite
from bridge.information import mission_trigger_profile as profile
from bridge.tests.test_information_mission_observer_guard import fixture as availability_fixture


def fixture():
    reader, _, asset, dll_base, _ = availability_fixture(61)
    reader.mission_observer_binding["build_manifest_sha256"] = guard._BUILDS[asset["dll_sha256"]]["manifest_sha256"]
    reader.mission_observer_binding["build_manifest_sha256"] = guard._BUILDS[asset["dll_sha256"]]["manifest_sha256"]
    sources = json.loads(profile.PROFILE_FILE.read_bytes())["code_guards"]
    conjunction = next(row for row in sources if row["rva"] == guard.CONDITION_RVA)
    condition = asset["condition"]
    executable = 0x150000000
    original = bytes.fromhex(conjunction["raw_hex"])
    hook = dll_base+condition["observe_rva"]
    patch = b"\x90\xe8"+struct.pack("<i", executable-(reader.module_base+guard.CONDITION_RVA+47))
    reader.put(reader.module_base+guard.CONDITION_RVA, original[:41]+patch+original[47:])
    image = bytearray.fromhex(condition["image_hex"])
    image[70:78] = struct.pack("<Q", hook)
    reader.put(executable, bytes(image))
    reader.put(hook, bytes.fromhex(condition["observe_hex"]))
    reader.put(dll_base+condition["observe_unwind_rva"], bytes.fromhex(condition["observe_unwind_hex"]))
    reader.qword_put(dll_base+condition["executable_rva"], executable)
    reader.put(dll_base+condition["runtime_functions_rva"], b"".join(
        struct.pack("<III", *row) for row in condition["runtime_functions"]))
    reader.put(dll_base+condition["table_registered_rva"], b"\x01")
    province = asset["province"]
    source = next(row for row in sources if row["rva"] == guard.PROVINCE_RVA)
    expected = bytes.fromhex(source["raw_hex"])
    trampoline = 0x1B000000000
    hook = dll_base+province["observe_rva"]
    reader.put(reader.module_base+guard.PROVINCE_RVA,
               b"\xff\x25\0\0\0\0"+struct.pack("<Q", hook)+b"\x90"+expected[15:])
    reader.put(hook, bytes.fromhex(province["observe_hex"]))
    reader.put(dll_base+province["observe_unwind_rva"], bytes.fromhex(province["observe_unwind_hex"]))
    reader.qword_put(dll_base+province["original_rva"], trampoline)
    reader.qword_put(dll_base+province["executable_rva"], trampoline)
    continuation = reader.module_base+guard.PROVINCE_RVA+15
    jump = bytes.fromhex("c7842410000000")+struct.pack("<I", continuation&0xFFFFFFFF)
    jump += bytes.fromhex("c7842414000000")+struct.pack("<I", continuation>>32)
    jump += bytes.fromhex("ffa42410000000")
    reader.put(trampoline, bytes.fromhex("48895c2408488974241848897c2420")+jump+bytes(20)
               +bytes.fromhex("010f06000f7404000a64030005340100"))
    reader.put(dll_base+province["runtime_functions_rva"], struct.pack("<III", 0, 44, 64))
    reader.put(dll_base+province["table_registered_rva"], b"\x01")
    return reader, source, province, dll_base, trampoline



def test_v61_asset_loader_and_capture_bind_the_reviewed_manifest():
    import hashlib
    import json

    profile_data = profile.load_profile()
    contract = guard._BUILDS[
        "968ee8e84e0426c86bd8e1e59b4b944cada8f06c90d01540a3c09846a2f14646"
    ]
    asset = json.loads(contract["asset_file"].read_bytes())
    assert profile_data["profile_revision"] == 11
    assert contract["asset_sha256"] == hashlib.sha256(contract["asset_file"].read_bytes()).hexdigest()
    assert asset["build_version"] == contract["build_version"] == 61
    assert asset["build_manifest_sha256"] == contract["manifest_sha256"]
    assert asset["source_count"] == contract["source_count"] == 190
    assert asset["dll_sha256"] == "968ee8e84e0426c86bd8e1e59b4b944cada8f06c90d01540a3c09846a2f14646"
    assert asset["evidence_sha256"] == contract["evidence_sha256"]


def test_v61_province_entry_retains_original_bytes_and_exact_runtime_proof():
    reader, source, _, _, _ = fixture()
    result = prerequisite._validate_code_guards(reader, reader.module_base, [source])[0]
    assert result["matches"] is False and result["raw_hex"] != result["expected_raw_hex"]
    assert result["observer_patch"]["kind"] == "verified_v61_mission_province_condition_entry"
    assert result["observer_patch"]["reads"]


@pytest.mark.parametrize("damage", [
    "binding", "old_dll", "opcode", "hook", "original_tail", "body", "observer_unwind",
    "game_base", "original_pointer", "trampoline_pointer", "trampoline_prefix", "home_slot",
    "continuation", "padding", "projected_unwind", "runtime_functions", "table_registered",
])
def test_v61_province_patch_is_rejected_after_any_owner_or_code_change(damage):
    reader, source, asset, dll_base, trampoline = fixture()
    addresses = {
        "opcode": reader.module_base+guard.PROVINCE_RVA,
        "hook": reader.module_base+guard.PROVINCE_RVA+6,
        "original_tail": reader.module_base+guard.PROVINCE_RVA+20,
        "body": dll_base+asset["observe_rva"],
        "observer_unwind": dll_base+asset["observe_unwind_rva"],
        "game_base": dll_base+asset["game_base_rva"],
        "original_pointer": dll_base+asset["original_rva"],
        "trampoline_pointer": dll_base+asset["executable_rva"],
        "trampoline_prefix": trampoline+1, "home_slot": trampoline+18,
        "continuation": trampoline+22, "padding": trampoline+50,
        "projected_unwind": trampoline+64,
        "runtime_functions": dll_base+asset["runtime_functions_rva"]+4,
        "table_registered": dll_base+asset["table_registered_rva"],
    }
    if damage == "binding":
        reader.mission_observer_binding = None
    elif damage == "old_dll":
        reader.mission_observer_binding["dll_sha256"] = next(
            sha for sha, value in guard._BUILDS.items() if value["version"] == 56)
    else:
        reader.memory[addresses[damage]] ^= 1
    with pytest.raises(ValueError):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


def test_original_province_predicate_needs_no_observer_binding():
    reader, source, _, _, _ = fixture()
    reader.mission_observer_binding = None
    reader.put(reader.module_base+guard.PROVINCE_RVA, bytes.fromhex(source["raw_hex"]))
    result = prerequisite._validate_code_guards(reader, reader.module_base, [source])[0]
    assert result["matches"] is True and "observer_patch" not in result


@pytest.mark.parametrize("change_between_reads", [False, True])
def test_normal_m02_capture_accepts61_and_rejects_changed_province_runtime_row(monkeypatch, change_between_reads):
    from bridge.information import mission_memory
    from bridge.tests.test_information_mission_trigger_capture import capture, fixture as trigger_fixture

    reader, module, _ = trigger_fixture()
    patched, _, asset, dll_base, _ = fixture()
    reader.memory.update(patched.memory)
    reader.mission_observer_binding = patched.mission_observer_binding
    monkeypatch.setattr(guard, "bind_loaded_observer", lambda *args: None)
    original_snapshot = mission_memory._snapshot
    calls = 0

    def snapshot(*args, **kwargs):
        nonlocal calls
        calls += 1
        if change_between_reads and calls == 2:
            reader.memory[dll_base+asset["runtime_functions_rva"]+4] ^= 1
        return original_snapshot(*args, **kwargs)

    report = capture(reader, module, snapshot=snapshot)
    assert report["doublepass"]["condition_consistent"] is True
    assert report["doublepass"]["trigger_consistent"] is (not change_between_reads)
    if change_between_reads:
        assert report["mission_triggers"]["status"] == "unknown"
    else:
        assert report["mission_triggers"]["status"] == "observed"
        proofs = {row["rva"]: row["observer_patch"] for row in report["mission_triggers"]["code_guards"]
                  if "observer_patch" in row}
        assert proofs[hex(guard.CONDITION_RVA)]["kind"] == "verified_v61_mission_condition_callsite"
        assert proofs[hex(guard.PROVINCE_RVA)]["kind"] == "verified_v61_mission_province_condition_entry"
