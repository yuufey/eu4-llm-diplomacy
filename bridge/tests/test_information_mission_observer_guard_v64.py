"""Exact current-v64 mission guards reuse the established B23 readers."""
import ctypes as C
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import mission_observer_guard as guard
from bridge.information import mission_prerequisite_memory as prerequisite
from bridge.information import mission_trigger_profile as trigger_profile
from bridge.tests.test_information_mission_observer_guard_v57 import fixture
from bridge.tests.test_information_mission_memory import FakeReader
from work.find_native_string_references import _file_offset_for_rva, _read_at, parse_pe


ROOT = Path(__file__).resolve().parents[2]
BUILD_CASES = [
    pytest.param(SimpleNamespace(
        dll_sha='f05d9eb9209e8d35f512bd1d066cf5fc6585d66f58786527a86ef27cbddd64e6',
        manifest_sha='64c38d19e2a2decc2a0a039476a33e9f6c8295c7279bec590bdb50649c834f53',
        path=ROOT / 'work/runtime/diplomacy-observer-20261115-subsidy-monthly-v64-001',
    ), id='subsidy-monthly'),
    pytest.param(SimpleNamespace(
        dll_sha='3a9308690aa611b829ad38eb9680666f20f13baa1dd494cf4251c06f2caa705d',
        manifest_sha='8f31a31f2047f55dca591131b20a870da5b53bfe304970a3f7a56c962a7fefa9',
        path=ROOT / 'work/runtime/diplomacy-observer-20261115-land-promise-v64-001',
    ), id='land-promise'),
    pytest.param(SimpleNamespace(
        dll_sha='8db058b325bef33c2ee7fcd1bfa4418c9991ff2fdb0013893c94f97a069ac953',
        manifest_sha='1c6f4c8aa42fd4ac3d52ae657e7fe625c57d0681e131804b4764048ca1f13ca2',
        path=ROOT / 'work/runtime/diplomacy-observer-20261115-pending-clear-v64-001',
    ), id='pending-clear'),
]
RVAS = (guard.ENTRY_RVA, guard.CONDITION_RVA, guard.PROVINCE_RVA)


@pytest.fixture(params=BUILD_CASES)
def build(request):
    return request.param


def sources():
    return [row for row in trigger_profile.load_profile()['code_guards'] if row['rva'] in RVAS]


def test_v64_asset_matches_the_actual_manifest_and_bounded_dll_bodies(build):
    contract = guard._BUILDS[build.dll_sha]
    asset_raw = contract['asset_file'].read_bytes()
    asset = json.loads(asset_raw)
    assert len(asset_raw) < 32 * 1024
    assert hashlib.sha256(asset_raw).hexdigest() == contract['asset_sha256']
    assert hashlib.sha256((build.path / 'build-manifest.json').read_bytes()).hexdigest() == build.manifest_sha
    assert asset['build_version'] == contract['build_version'] == 64
    assert asset['build_manifest_sha256'] == contract['manifest_sha256'] == build.manifest_sha
    assert asset['source_count'] == contract['source_count'] == 206
    evidence_raw = (ROOT / asset['evidence_path']).read_bytes()
    assert hashlib.sha256(evidence_raw).hexdigest() == asset['evidence_sha256'] == contract['evidence_sha256']
    evidence = json.loads(evidence_raw)
    assert evidence['manifest_verified_source_count'] == 206
    assert len(evidence['unchanged_mission_sources_from_v61']) == 13
    dll = build.path / contract['dll_name']
    pe = parse_pe(dll)
    with dll.open('rb') as stream:
        for value in (asset, asset['condition'], asset['province']):
            begin, end = value['observe_rva'], value['observe_end_rva']
            assert (begin, end) in pe['runtime_functions'] and 0 < end - begin < 16384
            actual = _read_at(stream, pe['file_size'], _file_offset_for_rva(pe['sections'], begin), end - begin)
            assert actual.hex() == value['observe_hex']
            unwind = bytes.fromhex(value['observe_unwind_hex'])
            actual_unwind = _read_at(stream, pe['file_size'],
                                     _file_offset_for_rva(pe['sections'], value['observe_unwind_rva']), len(unwind))
            assert actual_unwind == unwind and value['observe_pe_base_relocations'] == []


def test_all_three_current_patches_retain_original_bytes_and_explicit_v64_proofs(build):
    reader, *_ = fixture(64, dll_sha256=build.dll_sha)
    reports = prerequisite._validate_code_guards(reader, reader.module_base, sources())
    assert len(reports) == 3
    assert {row['observer_patch']['kind'] for row in reports} == {
        'verified_v64_mission_availability_entry', 'verified_v64_mission_condition_callsite',
        'verified_v64_mission_province_condition_entry'}
    for row in reports:
        assert not row['matches'] and row['raw_hex'] != row['expected_raw_hex']
        assert row['observer_patch']['dll_sha256'] == build.dll_sha
        assert row['observer_patch']['build_manifest_sha256'] == build.manifest_sha


@pytest.mark.parametrize('kind', ['availability', 'condition', 'province'])
@pytest.mark.parametrize('damage', ['binding', 'manifest', 'entry', 'body', 'unwind', 'game_base'])
def test_v64_rejects_unowned_or_changed_patches(build, kind, damage):
    reader, _, _, dll_base, _ = fixture(64, dll_sha256=build.dll_sha)
    asset = json.loads(guard._BUILDS[build.dll_sha]['asset_file'].read_bytes())
    value = asset if kind == 'availability' else asset[kind]
    rva = {'availability': guard.ENTRY_RVA, 'condition': guard.CONDITION_RVA,
           'province': guard.PROVINCE_RVA}[kind]
    source = next(item for item in sources() if item['rva'] == rva)
    if damage == 'binding':
        reader.mission_observer_binding['dll_sha256'] = '0' * 64
    elif damage == 'manifest':
        reader.mission_observer_binding['build_manifest_sha256'] = '0' * 64
    else:
        address = {'entry': reader.module_base + rva, 'body': dll_base + value['observe_rva'],
                   'unwind': dll_base + value['observe_unwind_rva'],
                   'game_base': dll_base + value['game_base_rva']}[damage]
        reader.memory[address] ^= 1
    with pytest.raises(ValueError):
        prerequisite._validate_code_guards(reader, reader.module_base, [source])


@pytest.mark.parametrize('kind', ['condition', 'province'])
@pytest.mark.parametrize('damage', ['runtime', 'registered', 'gateway'])
def test_v64_retains_gateway_and_registered_unwind_checks(build, kind, damage):
    reader, _, _, dll_base, province_gateway = fixture(64, dll_sha256=build.dll_sha)
    asset = json.loads(guard._BUILDS[build.dll_sha]['asset_file'].read_bytes())[kind]
    rva = guard.CONDITION_RVA if kind == 'condition' else guard.PROVINCE_RVA
    address = {'runtime': dll_base + asset['runtime_functions_rva'],
               'registered': dll_base + asset['table_registered_rva'],
               'gateway': 0x150000000 if kind == 'condition' else province_gateway}[damage]
    reader.memory[address] ^= 1
    with pytest.raises(ValueError):
        prerequisite._validate_code_guards(reader, reader.module_base, [
            next(item for item in sources() if item['rva'] == rva)])


@pytest.mark.parametrize('case', ['exact', 'foreign_path', 'duplicate', 'unknown_hash'])
def test_loaded_v64_binding_uses_the_real_frozen_module_path_and_digest(build, case):
    reader = FakeReader()
    path = build.path / guard._BUILDS[build.dll_sha]['dll_name']

    def module_name(_handle, _module, name, _capacity):
        name.value = str(path if case != 'foreign_path' else path.with_name('foreign.dll'))
        return len(name.value)

    reader.kernel = SimpleNamespace(_probe_get_module_name=module_name)
    reader.handle = 1
    modules = [C.c_void_p(0x7ff900000000)] * (2 if case == 'duplicate' else 1)
    document = {'dll_sha256': '0' * 64 if case == 'unknown_hash' else build.dll_sha}
    guard.bind_loaded_observer(reader, document, build.path / 'installation.json', modules, len(modules))
    if case == 'exact':
        assert reader.mission_observer_binding['dll_sha256'] == build.dll_sha
        assert reader.mission_observer_binding['build_manifest_sha256'] == build.manifest_sha
    else:
        assert reader.mission_observer_binding is None


@pytest.mark.parametrize('changed', [False, True])
def test_normal_m02_capture_accepts_v64_and_retracts_changed_province_unwind(build, monkeypatch, changed):
    from bridge.information import mission_memory
    from bridge.tests.test_information_mission_trigger_capture import capture, fixture as trigger_fixture
    reader, module, _ = trigger_fixture()
    patched, _, asset, dll_base, _ = fixture(64, dll_sha256=build.dll_sha)
    reader.memory.update(patched.memory)
    reader.mission_observer_binding = patched.mission_observer_binding
    monkeypatch.setattr(guard, 'bind_loaded_observer', lambda *_: None)
    original = mission_memory._snapshot
    calls = 0

    def sampled(*args, **kwargs):
        nonlocal calls
        calls += 1
        if changed and calls == 2:
            reader.memory[dll_base + asset['runtime_functions_rva'] + 4] ^= 1
        return original(*args, **kwargs)

    report = capture(reader, module, snapshot=sampled)
    assert report['doublepass']['condition_consistent'] is True
    assert report['doublepass']['trigger_consistent'] is (not changed)
    assert report['mission_triggers']['status'] == ('unknown' if changed else 'observed')


def test_v64_preserves_all_three_existing_mission_event_capabilities(build):
    from bridge import mission_availability_observation, mission_condition_observation, mission_observation
    directory = Path(__file__).parent / 'fixtures'
    fixture_doc = json.loads((directory / 'information_mission_FRA_normandy_live_1374.json').read_bytes())
    ack = json.loads((directory / fixture_doc['installation_ack_fixture']).read_bytes())['installation_ack']
    ack['version'] = 64
    manifest = json.loads((build.path / 'build-manifest.json').read_bytes())
    assert manifest['dll_sha256'] == build.dll_sha
    assert manifest['native_mission_completion_observation'] is True
    assert manifest['native_mission_availability_observation'] is True
    assert manifest['native_mission_condition_observation'] is True
    for module in (mission_observation, mission_availability_observation, mission_condition_observation):
        assert module.supported_ack(ack, fixture_doc['game_sha256'])
