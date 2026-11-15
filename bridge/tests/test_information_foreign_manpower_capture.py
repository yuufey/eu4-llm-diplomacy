"""Synthetic integration coverage for the identity-bound F02 capture."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from bridge.information import foreign_manpower_capture as capture
from bridge.information import foreign_manpower_memory as manpower
from bridge.information import foreign_military_visibility_memory as visibility
from bridge.information import foreign_technology_capture as owner
from bridge.tests import test_information_foreign_technology_capture as tech_fixture
from bridge.tests import test_information_foreign_technology_memory as memory_fixture


MODULE_BASE = tech_fixture.MODULE_BASE
CREATION = 123456789012345678
SESSION_ID = "foreign-manpower-capture-session"
GAME_DATE = tech_fixture.GAME_DATE
WORLD = tech_fixture.WORLD
SETTINGS = 0x6870000000
DEFINITION = 0x6880000000


class TraceReader:
    """Address-shaped fake reader with the same ordered trace contract."""

    def __init__(self, source: Any) -> None:
        self.source = source
        self.read_log: list[dict[str, Any]] = []
        self.bytes_requested = 0
        self.calls = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls += 1
        self.bytes_requested += size
        try:
            raw = self.source.read(address, size, label)
            if not isinstance(raw, bytes) or len(raw) != size:
                raise OSError("synthetic short read")
        except Exception as exc:
            self.read_log.append({
                "address": hex(address), "size": size, "label": label,
                "status": "error", "error": f"{type(exc).__name__}:{exc}",
            })
            raise
        self.read_log.append({
            "address": hex(address), "size": size, "label": label,
            "status": "observed", "raw_hex": raw.hex(),
        })
        return raw


def _make_image(profile: dict[str, Any], *, stats_allowed: bool = True,
                human_fra: bool = False, manpower_read_failure: bool = False):
    image, bindings, _values = memory_fixture.make_reader({
        "FRA": (122, 0x1200, 5),
        "POR": (189, 0x5500, 3),
        "ENG": (300, 0x4500, 9),
    }, count=310)
    refs = tech_fixture._write_capture_context(
        image, country="ENG", admitted=True, physical_tag="POR", human_fra=human_fra)

    image.put_u64(WORLD + visibility.WORLD_SETTINGS_OFFSET, SETTINGS)
    image.put_i32(SETTINGS + visibility.PUBLIC_OPTIONS_OFFSET,
                  0 if stats_allowed else 1)
    image.put_i32(SETTINGS + visibility.PUBLIC_OPTIONS_SECOND_OFFSET,
                  0 if stats_allowed else 1)
    image.put_u64(refs["target_pointer"] + visibility.TARGET_TIMED_HEAD_OFFSET, 0)

    for offset in manpower.MANPOWER_OFFSETS:
        image.put(refs["target_pointer"] + offset, b"\x00\x00")
    image.put(refs["target_pointer"] + manpower.MANPOWER_OFFSETS[0],
              (2).to_bytes(2, "little"))
    image.put_u64(refs["target_pointer"] + manpower.DEFINITION_POINTER_OFFSETS[0], DEFINITION)
    image.put_i32(DEFINITION + manpower.DEFINITION_COST_OFFSET, 13)
    image.put_i32(refs["target_pointer"] + manpower.RESERVE_OFFSET, 41)
    if manpower_read_failure:
        def fail_reserve(_image, address, _size, _label, _count):
            if address == refs["target_pointer"] + manpower.RESERVE_OFFSET:
                raise OSError("synthetic manpower read failure")
        image.on_read = fail_reserve

    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    return image, bindings, refs


def _make_report(profile: dict[str, Any], *, stats_allowed: bool = True,
                 human_fra: bool = False, manpower_read_failure: bool = False):
    image, bindings, refs = _make_image(
        profile, stats_allowed=stats_allowed, human_fra=human_fra,
        manpower_read_failure=manpower_read_failure)
    return _make_report_from_image(profile, image, {"bindings": bindings, **refs})


def _make_report_from_image(profile: dict[str, Any], image: Any, fixture: dict[str, Any]):
    source = TraceReader(image)
    wrapped = owner._FailureReplayReader(source)
    observation_error = None
    try:
        observation = capture._observe(wrapped, MODULE_BASE, "ENG", profile)
    except Exception as exc:
        observation = None
        observation_error = f"{type(exc).__name__}:{exc}"
    passed = observation_error is None and observation.get("stable") is True
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture.EXE_SHA256,
    }
    report = {
        "schema": capture.SCHEMA,
        "status": "observed" if passed else "unknown",
        "completed": passed,
        "request": {"country": "ENG", "observer": "FRA",
                    "creation_filetime": CREATION, "session_id": SESSION_ID},
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(source.read_log),
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [] if observation_error is None else [{"reason": observation_error}],
        "access": {
            "read_only": True, "native_function_invoked": False, "writes": False,
            "UI_control": False, "date_advance": False, "save_or_reload": False,
            "limit_bytes": owner.MAX_READ_BYTES, "calls": source.calls,
            "bytes_requested": source.bytes_requested,
        },
    }
    context = {
        "observer": "FRA", "session_id": SESSION_ID,
        "game_version": "1.37.4", "game_sha256": capture.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    return report, context, CREATION, {"image": image, "source": source, **fixture}


@pytest.fixture(scope="module")
def pinned_profile():
    return capture._load_profile()


@pytest.fixture(scope="module")
def positive_capture(pinned_profile):
    return _make_report(pinned_profile)


def test_capture_replays_manpower_and_field_local_permission(positive_capture):
    report, context, creation, fixture = positive_capture
    assert capture.validate_capture(report, context, creation, "ENG")
    backend = report["observation"]["backend"]
    assert backend["status"] == "observed"
    assert backend["consistency"] == {"status": "stable", "shared_mismatch_paths": []}
    target = backend["targets"][0]
    assert target["tag"] == "ENG"
    assert target["fields"][manpower.FIELD_ID]["status"] == "known"
    assert target["fields"][manpower.FIELD_ID]["value"]["total_raw"] == 67
    assert target["fields"][manpower.FIELD_ID]["raw_inputs"]["permission"]["admitted"] is True
    visibility_field = target["fields"][capture.VISIBILITY_FIELD]
    assert visibility_field["status"] == "known"
    assert visibility_field["value"] == {
        "admitted": True, "mode": "public_options",
        "basis": capture.VISIBILITY_BASIS,
    }
    assert visibility_field["raw_inputs"]["permission"]["raw_inputs"]["target_binding"]["fullref"] == (
        hex(fixture["target_fullref"]))
    for phase in ("pass1", "pass2"):
        admission = target["admission_by_pass"][phase]
        assert admission["observer_nonplayer_role"]["verified"] is True
        assert "military_resource_visibility" not in admission
    assert fixture["physical_fullref"] != fixture["observer_fullref"]
    assert report["access"]["calls"] == len(report["raw_reads"])


def test_stable_stats_denial_is_visible_and_skips_manpower_reads(pinned_profile):
    report, context, creation, fixture = _make_report(pinned_profile, stats_allowed=False)
    assert capture.validate_capture(report, context, creation, "ENG")
    target = report["observation"]["backend"]["targets"][0]
    visibility_field = target["fields"][capture.VISIBILITY_FIELD]
    assert visibility_field["status"] == "known"
    assert visibility_field["value"]["admitted"] is False
    assert visibility_field["value"]["mode"] == "no_timed_entry"
    assert target["fields"][manpower.FIELD_ID]["status"] == "invisible"
    assert not any("foreign_manpower." in row["label"] for row in report["raw_reads"])
    assert target["field_consistency"][manpower.FIELD_ID]["status"] == "invisible"


def test_field_local_permission_change_does_not_change_shared_admission(pinned_profile):
    image, bindings, refs = _make_image(pinned_profile)
    label = "settings.public_options_primary"
    original = image.on_read

    def change_only_stats_permission(memory, address, size, current_label, count):
        if original is not None:
            original(memory, address, size, current_label, count)
        if current_label == label and count == 2:
            memory.put_i32(SETTINGS + visibility.PUBLIC_OPTIONS_OFFSET, 1)
            memory.put_i32(SETTINGS + visibility.PUBLIC_OPTIONS_SECOND_OFFSET, 1)
            memory.put_u64(refs["target_pointer"] + visibility.TARGET_TIMED_HEAD_OFFSET, 0)

    image.on_read = change_only_stats_permission
    changed, changed_context, changed_creation, _changed_fixture = _make_report_from_image(
        pinned_profile, image, {"bindings": bindings, **refs})
    assert changed["observation"]["stable"] is True
    assert capture.validate_capture(changed, changed_context, changed_creation, "ENG")
    target = changed["observation"]["backend"]["targets"][0]
    assert target["admission_by_pass"]["pass1"] == target["admission_by_pass"]["pass2"]
    assert target["fields"][manpower.FIELD_ID]["status"] == "unknown"
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "unknown"
    assert target["field_consistency"][manpower.FIELD_ID]["status"] == "changed"
    assert target["field_consistency"][capture.VISIBILITY_FIELD]["status"] == "changed"


def test_shared_binding_change_does_not_restore_a_leaf_invisibility(pinned_profile):
    image, bindings, refs = _make_image(pinned_profile, stats_allowed=False)
    changed_fullref = refs["target_fullref"] ^ (1 << 48)
    fullref_label = f"country_reference.slot[{bindings['ENG']['slot']}].fullref"

    def change_target_generation(memory, _address, _size, label, count):
        if label == fullref_label and count == 2:
            memory.put_u64(refs["target_pointer"] + 0x20, changed_fullref)
            recipient_address = (refs["relation_row"]
                                 + tech_fixture.admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET)
            memory.put_u64(recipient_address, changed_fullref)

    image.on_read = change_target_generation
    report, context, creation, _fixture = _make_report_from_image(
        pinned_profile, image, {"bindings": bindings, **refs})
    backend = report["observation"]["backend"]
    assert backend["consistency"]["status"] == "changed"
    assert "country_scan" in backend["consistency"]["shared_mismatch_paths"]
    target = backend["targets"][0]
    assert target["fields"][manpower.FIELD_ID]["status"] == "unknown"
    assert target["fields"][manpower.FIELD_ID]["reason"] == "shared_evidence_changed"
    assert not capture.validate_capture(report, context, creation, "ENG")


def test_role_failure_skips_both_private_field_readers(pinned_profile):
    report, _context, _creation, fixture = _make_report(pinned_profile, human_fra=True)
    assert report["observation"]["stable"] is False
    target = report["observation"]["backend"]["targets"][0]
    assert all(target["admission_by_pass"][phase]["observer_nonplayer_role"]["verified"] is False
               for phase in ("pass1", "pass2"))
    assert not any("settings.public_options_primary" == row["label"]
                   or "foreign_manpower." in row["label"] for row in fixture["source"].read_log)


def test_manpower_leaf_failure_is_field_local_and_replays(pinned_profile):
    report, context, creation, _fixture = _make_report(
        pinned_profile, manpower_read_failure=True)
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = report["observation"]["backend"]["targets"][0]
    assert target["fields"][manpower.FIELD_ID]["status"] == "unknown"
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "known"
    assert report["observation"].get("read_failures")


@pytest.mark.parametrize("tamper", ["manpower_value", "permission_raw", "role", "trace_order",
                                    "cleanup", "profile", "session", "creation", "date"])
def test_validator_rejects_capture_and_permission_tampering(positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report, context = deepcopy(report), deepcopy(context)
    target = report["observation"]["backend"]["targets"][0]
    if tamper == "manpower_value":
        target["fields"][manpower.FIELD_ID]["value"]["total_raw"] += 1
    elif tamper == "permission_raw":
        row = next(row for row in report["raw_reads"]
                   if row["label"] == "settings.public_options_primary")
        row["raw_hex"] = "01000000"
    elif tamper == "role":
        target["admission_by_pass"]["pass2"]["observer_nonplayer_role"]["verified"] = False
    elif tamper == "trace_order":
        report["raw_reads"][0], report["raw_reads"][1] = report["raw_reads"][1], report["raw_reads"][0]
    elif tamper == "cleanup":
        report["cleanup"]["status"] = "open"
    elif tamper == "profile":
        report["profile_sha256"] = "0" * 64
    elif tamper == "session":
        context["session_id"] = "another-session"
    elif tamper == "creation":
        creation += 1
    elif tamper == "date":
        context["game_date"] += 1
    assert not capture.validate_capture(report, context, creation, "ENG")


def test_capture_rejects_observer_as_foreign_target_before_open(monkeypatch):
    def fail_if_open(*_args, **_kwargs):
        raise AssertionError("invalid request must be rejected before process setup")
    monkeypatch.setattr(owner._identity, "_configure_kernel", fail_if_open)
    report = capture.capture(Path("synthetic-installation.json"), "FRA")
    assert report["status"] == "unknown"
    assert report["cleanup"]["status"] == "not_opened"

