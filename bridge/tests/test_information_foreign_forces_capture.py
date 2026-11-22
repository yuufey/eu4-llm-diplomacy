"""Offline integration tests for the identity-bound foreign-force capture."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bridge.information import foreign_force_statistics_memory as force_leaf
from bridge.information import foreign_forces_capture as capture
from bridge.information import foreign_military_visibility_memory as visibility
from bridge.information import foreign_technology_capture as owner
from bridge.tests import test_information_foreign_technology_capture as tech_fixture
from bridge.tests import test_information_foreign_technology_memory as memory_fixture


MODULE_BASE = tech_fixture.MODULE_BASE
CREATION = 123456789012345678
SESSION_ID = "foreign-forces-capture-session"
GAME_DATE = tech_fixture.GAME_DATE
WORLD = tech_fixture.WORLD
SETTINGS = 0x68B0000000

NODE_ARMY = 0x68C0000000
NODE_NAVY = 0x68C0000100
GROUP_ARMY = 0x68D0000000
GROUP_NAVY = 0x68D0000100
ARMY_VECTOR = 0x68E0000000
ARMY_RECORD_0 = 0x68F0000000
ARMY_RECORD_1 = 0x68F0000100
NAVY_VECTOR = 0x6900000000


def test_shared_python_comment_or_equivalent_change_does_not_control_admission(monkeypatch):
    original = capture._sha

    def source_hash(path):
        if Path(path).resolve() == Path(owner.__file__).resolve():
            pytest.fail('ordinary shared Python source was treated as a runtime guard')
        return original(path)

    monkeypatch.setattr(capture, '_sha', source_hash)
    assert capture._load_profile()['profile_id'] == capture.PROFILE_ID


def test_changed_profile_is_still_rejected(tmp_path, monkeypatch):
    changed = tmp_path / 'profile.json'
    changed.write_bytes(capture.PROFILE_FILE.read_bytes() + b' ')
    monkeypatch.setattr(capture, 'PROFILE_FILE', changed)
    with pytest.raises(ValueError, match='FOREIGN_FORCES_PROFILE_PIN'):
        capture._load_profile()


def test_changed_native_force_guard_is_still_rejected():
    profile = capture._load_profile()
    rows = {MODULE_BASE + int(row['rva'], 0): bytes.fromhex(row['bytes']) for row in profile['code_guards']}
    address = MODULE_BASE + int(profile['code_guards'][-1]['rva'], 0)
    rows[address] = bytes([rows[address][0] ^ 1]) + rows[address][1:]
    reader = SimpleNamespace(read=lambda address, _size, _label: rows[address])
    with pytest.raises(ValueError, match='FOREIGN_TECH_RUNTIME_CODE_MISMATCH'):
        owner._guards(reader, MODULE_BASE, profile)


class TraceReader:
    """Sparse fixture adapter with the parent capture's ordered trace shape."""

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


def _put_force_graph(image: Any, target_pointer: int) -> None:
    image.put_u64(target_pointer + force_leaf.COUNTRY_GROUP_HEAD_OFFSET, NODE_ARMY)
    image.put_u64(NODE_ARMY + force_leaf.NODE_GROUP_OFFSET, GROUP_ARMY)
    image.put_u64(NODE_ARMY + force_leaf.NODE_NEXT_OFFSET, NODE_NAVY)
    image.put_u64(NODE_NAVY + force_leaf.NODE_GROUP_OFFSET, GROUP_NAVY)
    image.put_u64(NODE_NAVY + force_leaf.NODE_NEXT_OFFSET, 0)

    image.put_u64(GROUP_ARMY + force_leaf.GROUP_VTABLE_OFFSET,
                  MODULE_BASE + 0x1C42540)
    image.put_u64(GROUP_ARMY + force_leaf.GROUP_VECTOR_BEGIN_OFFSET, ARMY_VECTOR)
    image.put_u64(GROUP_ARMY + force_leaf.GROUP_VECTOR_END_OFFSET, ARMY_VECTOR + 16)
    image.put_u64(ARMY_VECTOR, ARMY_RECORD_0)
    image.put_u64(ARMY_VECTOR + 8, ARMY_RECORD_1)
    image.put_i32(ARMY_RECORD_0 + force_leaf.RECORD_STRENGTH_OFFSET, 12)
    image.put_i32(ARMY_RECORD_1 + force_leaf.RECORD_STRENGTH_OFFSET, 18)

    image.put_u64(GROUP_NAVY + force_leaf.GROUP_VTABLE_OFFSET,
                  MODULE_BASE + 0x1CCA618)
    image.put_u64(GROUP_NAVY + force_leaf.GROUP_VECTOR_BEGIN_OFFSET, NAVY_VECTOR)
    image.put_u64(GROUP_NAVY + force_leaf.GROUP_VECTOR_END_OFFSET, NAVY_VECTOR + 24)


def _make_image(profile: dict[str, Any], *, stats_allowed: bool = True,
                human_fra: bool = False, observer: str = "FRA"):
    image, bindings, _values = memory_fixture.make_reader({
        observer: (122, 0x1200, 5),
        "POR": (189, 0x5500, 3),
        "ENG": (300, 0x4500, 9),
    }, count=310)
    refs = tech_fixture._write_capture_context(
        image, country="ENG", admitted=True, physical_tag="POR", human_fra=human_fra,
        observer=observer)

    image.put_u64(WORLD + visibility.WORLD_SETTINGS_OFFSET, SETTINGS)
    image.put_i32(SETTINGS + visibility.PUBLIC_OPTIONS_OFFSET,
                  0 if stats_allowed else 1)
    image.put_i32(SETTINGS + visibility.PUBLIC_OPTIONS_SECOND_OFFSET,
                  0 if stats_allowed else 1)
    image.put_u64(refs["target_pointer"] + visibility.TARGET_TIMED_HEAD_OFFSET, 0)
    _put_force_graph(image, refs["target_pointer"])

    # The group predicates are virtual calls through the selected vtable.  The
    # fixture must bind both slots to the pinned method bodies, just as a live
    # object would; guarding method bytes alone does not populate these cells.
    for vtable_rva, slots in profile["force_predicates"]["vtable_rvas"].items():
        for slot_name, method_rva in slots.items():
            slot_offset = int(slot_name.removeprefix("slot_"), 16)
            image.put_u64(
                MODULE_BASE + int(vtable_rva, 0) + slot_offset,
                MODULE_BASE + int(method_rva, 0),
            )

    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    for method_rva, guard in profile["force_predicates"]["method_guards"].items():
        image.put(MODULE_BASE + int(method_rva, 0), bytes.fromhex(guard["body_hex"]))
    return image, bindings, refs


def _make_report(profile: dict[str, Any], *, stats_allowed: bool = True,
                 human_fra: bool = False, observer: str = "FRA"):
    image, bindings, refs = _make_image(
        profile, stats_allowed=stats_allowed, human_fra=human_fra, observer=observer)
    return _make_report_from_image(profile, image, {"bindings": bindings, **refs}, observer=observer)


def _make_report_from_image(profile: dict[str, Any], image: Any,
                            fixture: dict[str, Any], *, observer: str = "FRA"):
    source = TraceReader(image)
    wrapped = owner._FailureReplayReader(source)
    observation_error = None
    try:
        observation = capture._observe(wrapped, MODULE_BASE, "ENG", profile, observer=observer)
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
        "request": {"country": "ENG", "observer": observer,
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
        "observer": observer, "session_id": SESSION_ID,
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


def _target(report: dict[str, Any]) -> dict[str, Any]:
    return report["observation"]["backend"]["targets"][0]


def test_capture_replays_field_local_army_and_navy_dtos(positive_capture):
    report, context, creation, fixture = positive_capture
    assert capture.validate_capture(report, context, creation, "ENG")
    backend = report["observation"]["backend"]
    assert backend["status"] == "observed"
    assert backend["consistency"] == {"status": "stable", "shared_mismatch_paths": []}
    target = _target(report)

    army = target["fields"][capture.ARMY_FIELD]
    assert army["status"] == "known"
    assert army["value"] == army["raw"] == 30
    assert army["unit"] == "soldiers" and army["scale"] == 1
    assert army["record_count"] == 2
    assert army["partial"] is True and army["complete"] is False
    assert army["raw_inputs"]["arithmetic"]["display_input_raw"] == 30000

    navy = target["fields"][capture.NAVY_FIELD]
    assert navy["status"] == "known"
    assert navy["value"] == navy["raw"] == 3
    assert navy["unit"] == "ships" and navy["scale"] == 1
    assert navy["partial"] is True and navy["complete"] is False
    assert navy["raw_inputs"]["arithmetic"]["record_elements_read"] is False

    permission = target["fields"][capture.VISIBILITY_FIELD]
    assert permission["status"] == "known"
    assert permission["value"]["admitted"] is True
    assert permission["value"]["mode"] == "public_options"
    for phase in ("pass1", "pass2"):
        assert target["admission_by_pass"][phase]["observer_nonplayer_role"]["verified"] is True
    assert fixture["physical_fullref"] != fixture["observer_fullref"]
    assert report["access"]["calls"] == len(report["raw_reads"])
    assert report["access"]["bytes_requested"] == sum(row["size"] for row in report["raw_reads"])
    assert type(army["value"]) is int and type(navy["value"]) is int
    assert "display_input_raw" not in army


def test_permission_denial_marks_force_fields_invisible_without_reading_groups(
        pinned_profile):
    report, context, creation, fixture = _make_report(pinned_profile, stats_allowed=False)
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    assert target["fields"][capture.VISIBILITY_FIELD]["value"]["admitted"] is False
    assert target["fields"][capture.VISIBILITY_FIELD]["value"]["mode"] == "no_timed_entry"
    for field in capture.FORCE_FIELDS:
        assert target["fields"][field]["status"] == "invisible"
        assert target["field_consistency"][field]["status"] == "invisible"
    assert not any(row["label"].startswith("force_statistics.")
                   for row in fixture["source"].read_log)


@pytest.mark.parametrize('stats_allowed', [True, False])
def test_f02_serves_forces_from_the_configured_observer(tmp_path, pinned_profile, stats_allowed):
    from bridge.information import InformationService
    from bridge.information.composite import CompositeSource
    from bridge.information.foreign_technology import NativeForeignTechnologySource
    from bridge.tests.test_information_foreign_technology import Base

    report, context, creation, _ = _make_report(pinned_profile, observer='TUR',
                                                stats_allowed=stats_allowed)
    assert not capture.validate_capture(report, dict(context, observer='FRA'), creation, 'ENG')
    base = Base(tmp_path, context, creation)
    base.operator_observer = 'TUR'

    def capture_forces(installation, *, country, observer):
        assert (country, observer) == ('ENG', 'TUR')
        return deepcopy(report)

    adapter = NativeForeignTechnologySource(base, forces_capture=capture_forces)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        result = service.query('foreign-forces-tur', [{
            'topic': 'F02', 'object': {'type': 'country', 'country': 'ENG'},
            'fields': ['visible_army', 'visible_navy', 'visibility'],
        }])
        fields = result['items'][0]['fields']
        assert fields['visibility']['value']['army']['country_view']['observer'] == 'TUR'
        if stats_allowed:
            assert fields['visible_army']['value'] == 30
            assert fields['visible_navy']['value'] == 3
        else:
            assert fields['visible_army']['status'] == fields['visible_navy']['status'] == 'invisible'
    finally:
        service.close()


def test_unknown_stats_permission_skips_force_resource_reads(monkeypatch, pinned_profile):
    def unknown_permission(*_args, **_kwargs):
        return {"schema": visibility.SCHEMA, "status": "unknown", "admitted": None,
                "reason": "SYNTHETIC_PERMISSION_UNKNOWN"}
    monkeypatch.setattr(capture._visibility, "read_permission", unknown_permission)
    report, context, creation, fixture = _make_report(pinned_profile)
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "unknown"
    for field in capture.FORCE_FIELDS:
        assert target["fields"][field]["status"] == "unknown"
        assert "value" not in target["fields"][field]
    assert not any(row["label"].startswith("force_statistics.")
                   for row in fixture["source"].read_log)


def test_fra_role_failure_skips_permission_and_force_reads(pinned_profile):
    report, _context, _creation, fixture = _make_report(pinned_profile, human_fra=True)
    target = _target(report)
    assert report["observation"]["stable"] is False
    assert all(target["admission_by_pass"][phase]["observer_nonplayer_role"]["verified"] is False
               for phase in ("pass1", "pass2"))
    assert not any(row["label"].startswith("force_statistics.")
                   or row["label"].startswith("settings.")
                   for row in fixture["source"].read_log)


def test_army_strength_change_does_not_revoke_stable_navy_or_visibility(pinned_profile):
    image, bindings, refs = _make_image(pinned_profile)

    def change_army_record(memory, _address, _size, label, count):
        if (label == "force_statistics.group[0].army.record[0].strength_i32"
                and count == 2):
            memory.put_i32(ARMY_RECORD_0 + force_leaf.RECORD_STRENGTH_OFFSET, 40)

    image.on_read = change_army_record
    report, context, creation, fixture = _make_report_from_image(
        pinned_profile, image, {"bindings": bindings, **refs})
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    assert target["fields"][capture.ARMY_FIELD]["status"] == "unknown"
    assert target["field_consistency"][capture.ARMY_FIELD]["status"] == "changed"
    assert target["fields"][capture.NAVY_FIELD]["status"] == "known"
    assert target["fields"][capture.NAVY_FIELD]["value"] == 3
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "known"
    assert fixture["source"].calls == len(report["raw_reads"])


def test_shared_target_fullref_change_retracts_both_force_fields(pinned_profile):
    image, bindings, refs = _make_image(pinned_profile)
    slot = bindings["ENG"]["slot"]
    fullref_label = f"country_reference.slot[{slot}].fullref"
    changed_fullref = refs["target_fullref"] ^ (1 << 48)

    def change_generation(memory, _address, _size, label, count):
        if label == fullref_label and count == 2:
            memory.put_u64(refs["target_pointer"] + 0x20, changed_fullref)
            recipient = refs["relation_row"] + tech_fixture.admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET
            memory.put_u64(recipient, changed_fullref)

    image.on_read = change_generation
    report, context, creation, _fixture = _make_report_from_image(
        pinned_profile, image, {"bindings": bindings, **refs})
    backend = report["observation"]["backend"]
    assert backend["consistency"]["status"] == "changed"
    assert "country_scan" in backend["consistency"]["shared_mismatch_paths"]
    target = _target(report)
    for field in capture.FIELDS:
        assert target["fields"][field]["status"] == "unknown"
        assert target["fields"][field]["reason"] == "shared_evidence_changed"
    assert not capture.validate_capture(report, context, creation, "ENG")


@pytest.mark.parametrize("tamper", ["army_value", "navy_raw", "permission_raw",
                                    "trace_order", "profile", "cleanup", "session", "date"])
def test_capture_validator_rejects_tampering(positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report, context = deepcopy(report), deepcopy(context)
    target = _target(report)
    if tamper == "army_value":
        target["fields"][capture.ARMY_FIELD]["value"] += 1
    elif tamper == "navy_raw":
        target["fields"][capture.NAVY_FIELD]["raw"] += 1
    elif tamper == "permission_raw":
        row = next(row for row in report["raw_reads"]
                   if row["label"] == "settings.public_options_primary")
        row["raw_hex"] = "01000000"
    elif tamper == "trace_order":
        report["raw_reads"][0], report["raw_reads"][1] = report["raw_reads"][1], report["raw_reads"][0]
    elif tamper == "profile":
        report["profile_sha256"] = "0" * 64
    elif tamper == "cleanup":
        report["cleanup"]["status"] = "open"
    elif tamper == "session":
        context["session_id"] = "another-session"
    elif tamper == "date":
        context["game_date"] += 1
    assert not capture.validate_capture(report, context, creation, "ENG")


def test_saved_json_roundtrip_preserves_strict_replay(positive_capture):
    report, context, creation, _fixture = positive_capture
    saved = json.loads(json.dumps(report, ensure_ascii=False))
    saved_context = json.loads(json.dumps(context, ensure_ascii=False))
    assert capture.validate_capture(saved, saved_context, creation, "ENG")

