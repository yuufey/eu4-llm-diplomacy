"""Identity, exact replay and forward-clock tests for current reparations."""
from copy import deepcopy

import pytest

from bridge.information import reparations_commitments_capture as capture
from bridge.information import reparations_commitments as memory
from bridge.information.observation_time import sampled_read
from bridge.tests import test_information_country_faith_capture as faith_fixture
from bridge.tests import test_information_foreign_technology_capture as parent_fixture
from bridge.tests import test_information_foreign_economy as economy_fixture


def make_capture(*, present=True, advance=False, factor_changes=False):
    image, fixture = faith_fixture._make_image("ENG", capture._load_profile())
    image.put_u32 = lambda address, value: image.put(address, value.to_bytes(4, "little"))
    bindings = {tag: {**row, "country_pointer": hex(row["country_pointer"]),
                       "fullref": hex(fixture["refs"][tag])}
                for tag, row in fixture["bindings"].items()}
    economy_fixture._reparations_bytes(image, bindings["FRA"], bindings["ENG"], present=present)
    observer_owner = fixture["observer_pointer"] + 0x14F8
    image.put_u64(observer_owner + parent_fixture.admission.RELATION_OWNER_COUNTERS_OFFSET,
                  parent_fixture.RELATION_COUNTERS)
    if present:
        image.put(economy_fixture.REPARATIONS_TREATY + 0x28, b"\0")
        image.put_i32(parent_fixture.MODULE_BASE + memory.INCOME_FACTOR_RVA, 100)
    if advance or factor_changes:
        def change(memory_image, address, size, label, count):
            if advance and label == "reparations_commitments.current_date" and count == 2:
                memory_image.put_i32(address, parent_fixture.GAME_DATE + 24)
            if factor_changes and label == "reparations_commitments.income_factor" and count == 2:
                memory_image.put_i32(address, 250)
        image.on_read = change
    reader = parent_fixture.RecordingReader(image)
    observation = capture._observe(reader, parent_fixture.MODULE_BASE, "ENG", capture._load_profile())
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


def test_forward_clock_preserves_unchanged_current_terms():
    query = {"topic": "R07", "fields": ["economic_support", "expiry"]}
    with sampled_read(query, {"mode": "live", "game_date": parent_fixture.GAME_DATE}):
        report, context = make_capture(advance=True)
        assert capture.validate_capture(report, context, parent_fixture.CREATION, "ENG")
        fields = capture.project_fields(report)
        assert fields["economic_support"]["value"]["active_payment_obligations"]["status"] == "known"
        assert len(fields["expiry"]["value"]) == 1


def test_changed_native_rate_withdraws_support_but_keeps_unchanged_expiry():
    report, context = make_capture(factor_changes=True)
    assert capture.validate_capture(report, context, parent_fixture.CREATION, "ENG")
    fields = capture.project_fields(report)
    assert fields["economic_support"]["status"] == "unknown"
    assert fields["expiry"]["status"] == "known"


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
