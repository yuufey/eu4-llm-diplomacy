"""Subsidy capture identity, replay and forward-clock regression tests."""
from copy import deepcopy
import struct

import pytest

from bridge.information import economic_commitments_capture as capture
from bridge.information import economic_commitments as memory
from bridge.information.observation_time import sampled_read
from bridge.tests import test_information_country_faith_capture as faith_fixture
from bridge.tests import test_information_foreign_technology_capture as parent_fixture
from bridge.tests import test_information_foreign_economy as economy_fixture


def put_observer_patch(image, profile):
    dll_sha256, hook_rva = next(iter(capture._SUBSIDY_OBSERVER_HOOKS.items()))
    binding = {'dll_base': 0x7FF900000000, 'dll_path': 'bound-observer.dll',
               'dll_sha256': dll_sha256,
               'build_manifest_sha256': capture._observer_guard._BUILDS[dll_sha256]['manifest_sha256']}
    guard = next(row for row in profile['code_guards'] if int(row['rva'], 0) == capture._SUBSIDY_ENTRY_RVA)
    expected = bytes.fromhex(guard['bytes'])
    patched = b'\xff\x25\0\0\0\0' + struct.pack('<Q', binding['dll_base'] + hook_rva) + expected[14:]
    image.put(parent_fixture.MODULE_BASE + capture._SUBSIDY_ENTRY_RVA, patched)
    return binding, expected, patched


def make_capture(*, present=True, advance=False, observer_patch=False):
    profile = capture._load_profile()
    image, fixture = faith_fixture._make_image("ENG", profile)
    image.put_u32 = lambda address, value: image.put(address, value.to_bytes(4, "little"))
    bindings = {tag: {**row, "country_pointer": hex(row["country_pointer"]),
                       "fullref": hex(fixture["refs"][tag])}
                for tag, row in fixture["bindings"].items()}
    economy_fixture._subsidies_bytes(image, bindings["FRA"], bindings["ENG"], present=present,
                                     amount=12_500, start=parent_fixture.GAME_DATE, duration=2)
    admission = parent_fixture.admission
    observer_owner = fixture["observer_pointer"] + 0x14F8
    image.put_u64(observer_owner + admission.RELATION_OWNER_COUNTERS_OFFSET,
                  parent_fixture.RELATION_COUNTERS)
    for tag in ("FRA", "ENG"):
        image.put_u64(fixture["bindings"][tag]["country_pointer"] + 0x18F0, 0)
    if advance:
        def forward(memory_image, address, size, label, count):
            if label == "economic_commitments.current_date" and count == 2:
                memory_image.put_i32(address, parent_fixture.GAME_DATE + 24)
        image.on_read = forward
    binding = put_observer_patch(image, profile)[0] if observer_patch else None
    reader = parent_fixture.RecordingReader(image)
    observation = capture._observe(reader, parent_fixture.MODULE_BASE, "ENG", profile, observer_binding=binding)
    identity = {"binding_verified": True, "process_creation_filetime": parent_fixture.CREATION,
                "process_path": "synthetic-eu4.exe", "process_path_sha256": capture._owner.EXE_SHA256}
    report = {"schema": capture.SCHEMA, "status": "observed", "completed": True,
              "profile_sha256": capture.PROFILE_SHA256,
              "request": {"country": "ENG", "observer": "FRA", "creation_filetime": parent_fixture.CREATION,
                          "session_id": parent_fixture.SESSION_ID},
              "identity": identity, "identity_after": deepcopy(identity),
              "module_base": hex(parent_fixture.MODULE_BASE), "observation": observation,
              "raw_reads": reader.read_log,
              "cleanup": {"status": "closed", "closed": True, "success": True},
              "access": {"read_only": True, "native_function_invoked": False, "writes": False,
                         "UI_control": False, "date_advance": False, "save_or_reload": False,
                         "limit_bytes": capture._owner.MAX_READ_BYTES,
                         "calls": reader.calls, "bytes_requested": reader.bytes_requested}}
    context = {"status": "ready", "mode": "live", "observer": "FRA",
               "session_id": parent_fixture.SESSION_ID, "game_version": "1.37.4",
               "game_sha256": capture._owner.EXE_SHA256, "game_date": parent_fixture.GAME_DATE}
    return report, context


@pytest.mark.parametrize("present", [True, False])
def test_capture_replays_current_terms_and_expiry(present):
    report, context = make_capture(present=present)
    assert capture.validate_capture(report, context, parent_fixture.CREATION, "ENG")
    fields = capture.project_fields(report)
    assert fields["economic_support"]["status"] == "known"
    assert bool(fields["economic_support"]["value"]["active_payment_obligations"]["value"]) is present
    assert bool(fields["expiry"]["value"]) is present


def test_installed_subsidy_observer_keeps_actual_bytes_and_validates_replay():
    report, context = make_capture(observer_patch=True)
    assert capture.validate_capture(report, context, parent_fixture.CREATION, 'ENG')
    for phase in ('runtime_code_before', 'runtime_code_after'):
        guard = next(row for row in report['observation'][phase] if row['name'] == 'subsidy_cancel')
        assert guard['matches'] is False
        assert guard['actual_hex'].startswith('ff2500000000')
        assert guard['observer_patch']['kind'] == 'verified_installed_subsidy_expiry_entry'
        assert guard['observer_patch']['hook_rva'] == '0xbe260'
    assert capture.project_fields(report)['economic_support']['value']['active_payment_obligations']['status'] == 'known'


def test_shared_runtime_guard_requires_explicit_subsidy_patch_verifier():
    profile = capture._load_profile()
    image, _fixture = faith_fixture._make_image('ENG', profile)
    put_observer_patch(image, profile)
    with pytest.raises(ValueError, match='FOREIGN_TECH_RUNTIME_CODE_MISMATCH'):
        capture._owner._guards(parent_fixture.RecordingReader(image), parent_fixture.MODULE_BASE, profile)


@pytest.mark.parametrize('damage', ['target', 'body', 'encoding', 'dll', 'manifest', 'alignment'])
def test_subsidy_observer_rejects_unbound_or_modified_patch(damage):
    profile = capture._load_profile()
    image, _fixture = faith_fixture._make_image('ENG', profile)
    binding, expected, actual = put_observer_patch(image, profile)
    if damage == 'target':
        actual = actual[:6] + struct.pack('<Q', int.from_bytes(actual[6:14], 'little') + 16) + actual[14:]
    elif damage == 'body':
        actual = actual[:14] + bytes([actual[14] ^ 1]) + actual[15:]
    elif damage == 'encoding':
        actual = b'\x90' + actual[1:]
    elif damage == 'dll':
        binding['dll_sha256'] = '0' * 64
    elif damage == 'manifest':
        binding['build_manifest_sha256'] = '0' * 64
    else:
        binding['dll_base'] += 1
    assert capture._verify_subsidy_entry(
        binding, parent_fixture.MODULE_BASE, capture._SUBSIDY_ENTRY_RVA, expected, actual) is None


def test_forward_clock_does_not_change_unchanged_contract_facts():
    query = {"topic": "R07", "fields": ["economic_support", "expiry"]}
    context = {"mode": "live", "game_date": parent_fixture.GAME_DATE}
    with sampled_read(query, context):
        report, context = make_capture(advance=True)
        assert capture.validate_capture(report, context, parent_fixture.CREATION, "ENG")
        fields = capture.project_fields(report)
        assert fields["economic_support"]["value"]["active_payment_obligations"]["status"] == "known"
        assert len(fields["expiry"]["value"]) == 1


@pytest.mark.parametrize("changed", ["value", "creation", "session", "trace"])
def test_capture_rejects_changed_trace_or_identity(changed):
    report, context = make_capture()
    creation = parent_fixture.CREATION
    if changed == "value":
        report["observation"]["backend"]["targets"][0]["fields"][memory.EXPIRY_FIELD]["value"] = []
    elif changed == "creation":
        creation += 1
    elif changed == "session":
        context["session_id"] = "other-session"
    else:
        report["raw_reads"][-1]["raw_hex"] = "00"
    assert not capture.validate_capture(report, context, creation, "ENG")
