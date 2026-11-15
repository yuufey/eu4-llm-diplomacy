"""Regression coverage for the observer installed over the M02 code guard."""
import hashlib
import json
import struct

import pytest

from bridge.information import mission_observer_guard as og
from bridge.information import mission_prerequisite_memory as pm
from bridge.information import mission_prerequisite_profile as pp
from bridge.information.mission_condition_memory import _TrackingReader
from bridge.tests.test_information_mission_memory import FakeReader


def fixture(version=54, *, dll_sha256=None):
    if dll_sha256 is None:
        dll_sha256, contract = next((key, value) for key, value in og._BUILDS.items() if value["version"] == version)
    else:
        contract = og._BUILDS[dll_sha256]
        assert contract["version"] == version
    asset = json.loads(contract["asset_file"].read_bytes())
    guard = next(row for row in pp.load_profile()["code_guards"] if row["rva"] == og.ENTRY_RVA)
    expected = bytes.fromhex(guard["raw_hex"])
    reader = FakeReader()
    dll_base = 0x7FF900000000
    trampoline = 0x1A000000000
    reader.mission_observer_binding = {
        "dll_base": dll_base, "dll_path": "bound-observer.dll", "dll_sha256": dll_sha256,
    }
    hook = dll_base + asset["observe_rva"]
    actual = b"\xff\x25\0\0\0\0" + struct.pack("<Q", hook) + b"\x90" + expected[15:]
    reader.put(reader.module_base + og.ENTRY_RVA, actual)
    reader.put(hook, bytes.fromhex(asset["observe_hex"]))
    reader.put(dll_base + asset["observe_unwind_rva"], bytes.fromhex(asset["observe_unwind_hex"]))
    reader.qword_put(dll_base + asset["game_base_rva"], reader.module_base)
    reader.qword_put(dll_base + asset["original_rva"], trampoline)
    reader.qword_put(dll_base + asset["executable_rva"], trampoline)
    continuation = reader.module_base + og.ENTRY_RVA + 15
    jump = bytes.fromhex("c7842420000000") + struct.pack("<I", continuation & 0xFFFFFFFF)
    jump += bytes.fromhex("c7842424000000") + struct.pack("<I", continuation >> 32)
    jump += bytes.fromhex("ffa42420000000")
    reader.put(trampoline, og.PREFIX + jump + bytes(20) + og.PROJECTED_UNWIND)
    return reader, guard, asset, dll_base, trampoline


def test_original_guard_still_passes_without_observer_binding():
    reader, guard, _, _, _ = fixture()
    reader.mission_observer_binding = None
    reader.put(reader.module_base + og.ENTRY_RVA, bytes.fromhex(guard["raw_hex"]))
    report = pm._validate_code_guards(reader, reader.module_base, [guard])[0]
    assert report["matches"] is True
    assert "observer_patch" not in report


@pytest.mark.parametrize("tracked", [False, True])
@pytest.mark.parametrize("version", [54, 55])
def test_exact_installed_patch_retains_actual_bytes_and_proof(tracked, version):
    reader, guard, _, _, _ = fixture(version)
    source = _TrackingReader(reader) if tracked else reader
    report = pm._validate_code_guards(source, reader.module_base, [guard])[0]
    assert report["matches"] is False
    assert report["raw_hex"] != guard["raw_hex"]
    assert report["sha256"] == hashlib.sha256(bytes.fromhex(report["raw_hex"])).hexdigest()
    assert report["observer_patch"]["kind"] == f"verified_v{version}_mission_availability_entry"
    assert len(report["observer_patch"]["reads"]) >= 5
    if tracked:
        assert len(source.rawreads) >= 6


@pytest.mark.parametrize("damage", [
    "binding", "dll_sha", "entry_target", "entry_opcode", "suffix", "body",
    "game_base", "original", "executable", "trampoline_jump", "trampoline_unwind", "observe_unwind",
])
def test_unknown_or_damaged_patch_is_rejected(damage):
    reader, guard, asset, dll_base, trampoline = fixture()
    addresses = {
        "entry_target": reader.module_base + og.ENTRY_RVA + 6,
        "entry_opcode": reader.module_base + og.ENTRY_RVA,
        "suffix": reader.module_base + og.ENTRY_RVA + 15,
        "body": dll_base + asset["observe_rva"],
        "game_base": dll_base + asset["game_base_rva"],
        "original": dll_base + asset["original_rva"],
        "executable": dll_base + asset["executable_rva"],
        "trampoline_jump": trampoline + 22,
        "trampoline_unwind": trampoline + 64,
        "observe_unwind": dll_base + asset["observe_unwind_rva"],
    }
    if damage == "binding":
        reader.mission_observer_binding = None
    elif damage == "dll_sha":
        reader.mission_observer_binding["dll_sha256"] = "0" * 64
    else:
        address = addresses[damage]
        reader.memory[address] ^= 1
    with pytest.raises(ValueError):
        pm._validate_code_guards(reader, reader.module_base, [guard])


def test_asset_tampering_is_rejected(tmp_path, monkeypatch):
    reader, guard, _, _, _ = fixture()
    path = tmp_path / "asset.json"
    path.write_bytes(og.ASSET_FILE.read_bytes() + b" ")
    monkeypatch.setitem(og._BUILDS, og.DLL_SHA256, dict(og._BUILDS[og.DLL_SHA256], asset_file=path))
    with pytest.raises(ValueError, match="asset_pin"):
        pm._validate_code_guards(reader, reader.module_base, [guard])


def test_prerequisite_doublepass_includes_observer_proof(monkeypatch):
    from bridge.tests.test_information_mission_prerequisite_capture import (
        capture, fixture as prerequisite_fixture,
    )

    reader, module = prerequisite_fixture()
    patched, _, _, _, _ = fixture()
    reader.memory.update(patched.memory)
    reader.mission_observer_binding = patched.mission_observer_binding
    monkeypatch.setattr(og, "bind_loaded_observer", lambda *args: None)
    report = capture(reader, module)
    assert report["doublepass"]["prerequisite_consistent"] is True
    before = report["before"]["loaded_prerequisites"]
    assert before["code_guards"][2]["observer_patch"]["reads"]
    assert report["loaded_prerequisites"]["complete"] is True


def test_changed_trampoline_ownership_with_identical_code_fails_doublepass(monkeypatch):
    from bridge.information import mission_memory as mm
    from bridge.tests.test_information_mission_prerequisite_capture import (
        capture, fixture as prerequisite_fixture,
    )

    reader, module = prerequisite_fixture()
    patched, _, asset, dll_base, trampoline = fixture()
    reader.memory.update(patched.memory)
    reader.mission_observer_binding = patched.mission_observer_binding
    monkeypatch.setattr(og, "bind_loaded_observer", lambda *args: None)
    original_snapshot = mm._snapshot
    calls = 0

    def snapshot(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            replacement = trampoline + 0x10000
            reader.put(replacement, reader.read_code(trampoline, 80, "fixture"))
            reader.qword_put(dll_base + asset["original_rva"], replacement)
            reader.qword_put(dll_base + asset["executable_rva"], replacement)
        return original_snapshot(*args, **kwargs)

    report = capture(reader, module, snapshot=snapshot)
    assert report["doublepass"]["consistent"] is True
    assert report["doublepass"]["prerequisite_consistent"] is False
    assert report["loaded_prerequisites"]["status"] == "unknown"


@pytest.mark.parametrize("case", ["valid", "foreign_path", "duplicate", "wrong_file_hash", "wrong_record_hash"])
def test_binding_requires_exact_loaded_module_and_file_hash(tmp_path, monkeypatch, case):
    path = tmp_path / og.DLL_NAME
    path.write_bytes(b"frozen-observer-fixture")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setitem(og._BUILDS, digest, dict(og._BUILDS[og.DLL_SHA256]))
    record = {"dll_sha256": digest}
    modules = [0x7FF900000000]
    names = {modules[0]: str(path)}
    if case == "foreign_path":
        names[modules[0]] = str(tmp_path / "other.dll")
    elif case == "duplicate":
        modules.append(modules[0] + 0x100000)
        names[modules[1]] = str(path)
    elif case == "wrong_file_hash":
        path.write_bytes(b"changed")
    elif case == "wrong_record_hash":
        record["dll_sha256"] = "0" * 64

    class Kernel:
        def _probe_get_module_name(self, handle, module, buffer, size):
            buffer.value = names[module]
            return len(buffer.value)

    reader = FakeReader()
    reader.kernel = Kernel()
    reader.handle = 1
    og.bind_loaded_observer(reader, record, tmp_path / "installation.json", modules, len(modules))
    assert bool(reader.mission_observer_binding) is (case == "valid")
