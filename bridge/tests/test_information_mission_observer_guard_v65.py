"""Exact M02 mission guards for the frozen v65 country-control build."""
import ctypes as C
import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge import mission_availability_observation, mission_condition_observation, mission_observation
from bridge.information import mission_memory
from bridge.information import mission_observer_guard as guard
from bridge.information import mission_prerequisite_memory as prerequisite
from bridge.information import mission_trigger_profile
from bridge.tests.test_information_mission_memory import FakeReader
from bridge.tests.test_information_mission_observer_guard_v57 import fixture as observer_fixture
from bridge.tests.test_information_mission_trigger_capture import capture, fixture as trigger_fixture
from work.find_native_string_references import (
    _file_offset_for_rva, _read_at, parse_pe, read_coff_symbols,
)


ROOT = Path(__file__).resolve().parents[2]
DLL_SHA256 = "4238740233dbb3415c3151e5eace7f41b517a90d8b8843c9b6cff0e6c579dbc8"
BUILD_PATH = ROOT / "work/runtime/diplomacy-observer-20261116-country-control-v65-002"
MANIFEST_SHA256 = "fa142d40ed7f79ab4e509d94dea5b1666eb92bc3f754760ad5340d94fbdaa9ab"
OLD_EVIDENCE = ROOT / "work/runtime/information-mission-guard-subsidy-monthly-sol-20261115-001/pe-review-v64-mission.json"
RVAS = (guard.ENTRY_RVA, guard.CONDITION_RVA, guard.PROVINCE_RVA)


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sources():
    return [row for row in mission_trigger_profile.load_profile()["code_guards"]
            if row["rva"] in RVAS]


def _v65_fixture():
    return observer_fixture(65, dll_sha256=DLL_SHA256)


def _base_relocations(path, pe):
    directory = pe["relocation_directory"]
    if not directory["rva"] or not directory["size"]:
        return []
    start = _file_offset_for_rva(pe["sections"], directory["rva"])
    assert start is not None
    entries = []
    with path.open("rb") as stream:
        cursor = 0
        while cursor < directory["size"]:
            page, block_size = struct.unpack(
                "<II", _read_at(stream, pe["file_size"], start + cursor, 8))
            assert block_size >= 8 and block_size % 2 == 0
            assert cursor + block_size <= directory["size"]
            for index in range((block_size - 8) // 2):
                word = struct.unpack("<H", _read_at(
                    stream, pe["file_size"], start + cursor + 8 + index * 2, 2))[0]
                kind, offset = word >> 12, word & 0xFFF
                if kind:
                    width = {1: 2, 2: 2, 3: 4, 4: 2, 10: 8}.get(kind, 1)
                    entries.append((page + offset, width, kind))
            cursor += block_size
    return entries


def test_v65_asset_matches_final_manifest_symbols_pdata_and_unwind():
    contract = guard._BUILDS[DLL_SHA256]
    asset_path = contract["asset_file"]
    asset_raw = asset_path.read_bytes()
    assert len(asset_raw) < 32 * 1024
    assert hashlib.sha256(asset_raw).hexdigest() == contract["asset_sha256"]
    asset = json.loads(asset_raw)

    manifest_path = BUILD_PATH / "build-manifest.json"
    manifest_raw = manifest_path.read_bytes()
    assert hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA256
    manifest = json.loads(manifest_raw)
    assert manifest["version"] == contract["build_version"] == 65
    assert len(manifest["sources"]) == contract["source_count"] == asset["source_count"] == 207
    assert manifest["dll_sha256"] == DLL_SHA256
    assert asset["build_manifest_sha256"] == MANIFEST_SHA256

    evidence_path = ROOT / asset["evidence_path"]
    evidence_raw = evidence_path.read_bytes()
    assert len(evidence_raw) < 32 * 1024
    assert hashlib.sha256(evidence_raw).hexdigest() == asset["evidence_sha256"]
    evidence = json.loads(evidence_raw)
    old_evidence = json.loads(OLD_EVIDENCE.read_bytes())
    unchanged = old_evidence["unchanged_mission_sources_from_v61"]
    assert evidence["manifest_verified_source_count"] == len(manifest["sources"]) == 207
    assert len(unchanged) == 13
    assert evidence["unchanged_mission_sources_from_v61"] == unchanged
    source_hashes = {row["name"]: row["sha256"] for row in manifest["sources"]}
    assert len(source_hashes) == len(manifest["sources"])
    for source in unchanged:
        assert source_hashes[source["name"]] == source["sha256"]
        assert _sha256(BUILD_PATH / source["name"]) == source["sha256"]

    gateway_path = ROOT / evidence["gateway_template_asset"]
    assert _sha256(gateway_path) == evidence["gateway_template_asset_sha256"]
    gateway = json.loads(gateway_path.read_bytes())
    for section, keys in (
            ("condition", ("image_hex", "hook_immediate_offset", "runtime_functions",
                           "original_guard_sha256")),
            ("province", ("runtime_functions", "original_guard_sha256"))):
        for key in keys:
            assert asset[section][key] == gateway[section][key]

    dll = BUILD_PATH / contract["dll_name"]
    assert _sha256(dll) == DLL_SHA256
    pe = parse_pe(dll)
    assert evidence["preferred_dll_image_base"] == hex(pe["image_base"])
    symbol_names = {key: item["name"] for key, item in evidence["symbols"].items()}
    symbols = read_coff_symbols(dll, pe, names=tuple(symbol_names.values()))
    assert set(symbols) == set(symbol_names.values())
    functions = evidence["functions"]
    targets = (
        ("availability_observe", "availability_observe", asset),
        ("condition_observe", "condition_observe", asset["condition"]),
        ("province_observe", "province_observe", asset["province"]),
    )
    relocations = _base_relocations(dll, pe)
    pdata = pe["exception_directory"]
    pdata_rows = []
    with dll.open("rb") as stream:
        for offset in range(pdata["file_offset"], pdata["file_offset"] + pdata["size"], 12):
            pdata_rows.append(struct.unpack("<III", _read_at(stream, pe["file_size"], offset, 12)))
        for name, symbol_key, profile in targets:
            row = functions[name]
            begin, end = row["rva"], row["end_rva_exclusive"]
            assert symbols[symbol_names[symbol_key]] == begin
            assert (begin, end) in pe["runtime_functions"]
            matching = [item for item in pdata_rows if item[0] == begin]
            assert matching == [(begin, end, row["unwind_rva"])]
            assert row["preferred_va"] == pe["image_base"] + begin
            assert row["preferred_va_end_exclusive"] == pe["image_base"] + end
            body_offset = _file_offset_for_rva(pe["sections"], begin)
            unwind_offset = _file_offset_for_rva(pe["sections"], row["unwind_rva"])
            assert body_offset == row["file_offset"] and unwind_offset is not None
            body = _read_at(stream, pe["file_size"], body_offset, end - begin)
            assert body.hex() == profile["observe_hex"] == row["raw_hex"]
            assert len(body) == row["bytes"]
            assert hashlib.sha256(body).hexdigest() == row["sha256"]
            unwind = bytes.fromhex(profile["observe_unwind_hex"])
            assert _read_at(stream, pe["file_size"], unwind_offset, len(unwind)) == unwind
            assert len(unwind) == row["unwind_bytes"]
            assert row["unwind_preferred_va"] == pe["image_base"] + row["unwind_rva"]
            assert profile["observe_pe_base_relocations"] == row["pe_body_relocations"] == []
            assert not [entry for entry in relocations
                        if entry[0] < end and entry[0] + entry[1] > begin]


def test_v65_all_three_guards_retain_original_bytes_and_exact_runtime_proof():
    reader, _, _, _, _ = _v65_fixture()
    reports = prerequisite._validate_code_guards(reader, reader.module_base, _sources())
    assert len(reports) == 3
    assert {row["observer_patch"]["kind"] for row in reports} == {
        "verified_v65_mission_availability_entry",
        "verified_v65_mission_condition_callsite",
        "verified_v65_mission_province_condition_entry",
    }
    for row in reports:
        assert not row["matches"] and row["raw_hex"] != row["expected_raw_hex"]
        assert row["observer_patch"]["dll_sha256"] == DLL_SHA256
        assert row["observer_patch"]["build_manifest_sha256"] == MANIFEST_SHA256


@pytest.mark.parametrize("kind", ["availability", "condition", "province"])
@pytest.mark.parametrize("damage", ["binding", "manifest", "entry", "body", "unwind", "game_base"])
def test_v65_rejects_unowned_or_changed_guard_components(kind, damage):
    reader, _, _, dll_base, gateway = _v65_fixture()
    contract = guard._BUILDS[DLL_SHA256]
    full_asset = json.loads(contract["asset_file"].read_bytes())
    asset = full_asset if kind == "availability" else full_asset[kind]
    rva = {"availability": guard.ENTRY_RVA, "condition": guard.CONDITION_RVA,
           "province": guard.PROVINCE_RVA}[kind]
    source = next(item for item in _sources() if item["rva"] == rva)
    if damage == "binding":
        reader.mission_observer_binding["dll_sha256"] = "0" * 64
    elif damage == "manifest":
        reader.mission_observer_binding["build_manifest_sha256"] = "0" * 64
    else:
        address = {
            "entry": reader.module_base + rva,
            "body": dll_base + asset["observe_rva"],
            "unwind": dll_base + asset["observe_unwind_rva"],
            "game_base": dll_base + asset["game_base_rva"],
        }[damage]
        if damage == "entry" and kind == "condition":
            address += 1
        reader.memory[address] ^= 1
    with pytest.raises(ValueError):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


@pytest.mark.parametrize("kind,damage", [
    ("condition", "runtime"), ("condition", "registered"), ("condition", "gateway"),
    ("province", "runtime"), ("province", "registered"), ("province", "gateway"),
])
def test_v65_retains_gateway_and_registered_unwind_checks(kind, damage):
    reader, _, province, dll_base, trampoline = _v65_fixture()
    asset = json.loads(guard._BUILDS[DLL_SHA256]["asset_file"].read_bytes())[kind]
    rva = guard.CONDITION_RVA if kind == "condition" else guard.PROVINCE_RVA
    address = {
        "runtime": dll_base + asset["runtime_functions_rva"],
        "registered": dll_base + asset["table_registered_rva"],
        "gateway": 0x150000000 if kind == "condition" else trampoline,
    }[damage]
    reader.memory[address] ^= 1
    source = next(item for item in _sources() if item["rva"] == rva)
    with pytest.raises(ValueError):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


@pytest.mark.parametrize("case", ["exact", "foreign_path", "duplicate", "unknown_hash"])
def test_loaded_v65_binding_uses_exact_frozen_module_path_and_digest(case):
    contract = guard._BUILDS[DLL_SHA256]
    reader = FakeReader()
    path = BUILD_PATH / contract["dll_name"]

    def module_name(_handle, _module, name, _capacity):
        name.value = str(path if case != "foreign_path" else path.with_name("foreign.dll"))
        return len(name.value)

    reader.kernel = SimpleNamespace(_probe_get_module_name=module_name)
    reader.handle = 1
    modules = [C.c_void_p(0x7FF900000000)] * (2 if case == "duplicate" else 1)
    document = {"dll_sha256": "0" * 64 if case == "unknown_hash" else DLL_SHA256}
    guard.bind_loaded_observer(reader, document, BUILD_PATH / "installation.json", modules, len(modules))
    if case == "exact":
        assert reader.mission_observer_binding["dll_sha256"] == DLL_SHA256
        assert reader.mission_observer_binding["build_manifest_sha256"] == MANIFEST_SHA256
    else:
        assert reader.mission_observer_binding is None


@pytest.mark.parametrize("changed", [False, True])
def test_normal_m02_capture_accepts_v65_and_retracts_changed_province_unwind(monkeypatch, changed):
    reader, module, _ = trigger_fixture()
    patched, _, asset, dll_base, _ = _v65_fixture()
    reader.memory.update(patched.memory)
    reader.mission_observer_binding = patched.mission_observer_binding
    monkeypatch.setattr(guard, "bind_loaded_observer", lambda *_: None)
    original_snapshot = mission_memory._snapshot
    calls = 0

    def sampled(*args, **kwargs):
        nonlocal calls
        calls += 1
        if changed and calls == 2:
            reader.memory[dll_base + asset["runtime_functions_rva"] + 4] ^= 1
        return original_snapshot(*args, **kwargs)

    report = capture(reader, module, snapshot=sampled)
    assert report["doublepass"]["condition_consistent"] is True
    assert report["doublepass"]["trigger_consistent"] is (not changed)
    assert report["mission_triggers"]["status"] == ("unknown" if changed else "observed")


def test_v65_preserves_mission_event_capabilities_after_strict_country_control_ack():
    fixture_doc = json.loads((Path(__file__).parent / "fixtures" /
                              "information_mission_FRA_normandy_live_1374.json").read_bytes())
    ack_path = Path(__file__).parent / "fixtures" / fixture_doc["installation_ack_fixture"]
    ack = json.loads(ack_path.read_bytes())["installation_ack"]
    ack.update({
        "version": 65,
        "native_country_control_configuration": True,
        "native_country_control_protocol": "EU4CONTROL1",
        "native_country_control_ack": "native_controlled_countries_set",
        "native_country_control_request": "controlled-countries.req",
    })
    manifest = json.loads((BUILD_PATH / "build-manifest.json").read_bytes())
    assert manifest["dll_sha256"] == DLL_SHA256
    for capability in (
            "native_mission_completion_observation",
            "native_mission_availability_observation",
            "native_mission_condition_observation"):
        assert manifest[capability] is True
    for module in (mission_observation, mission_availability_observation,
                   mission_condition_observation):
        assert module.supported_ack(ack, fixture_doc["game_sha256"])
    incomplete = dict(ack)
    incomplete.pop("native_country_control_protocol")
    for module in (mission_observation, mission_availability_observation,
                   mission_condition_observation):
        assert not module.supported_ack(incomplete, fixture_doc["game_sha256"])
