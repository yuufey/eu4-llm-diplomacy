from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import empire_capture_v3 as capture
from bridge.tests.test_information_empire_capture_v2 import (
    CREATION, DATE, SESSION, _context, _fullref,
)
from bridge.tests.test_information_empire_memory import BASE, WORLD, make_image
from bridge.tests.test_information_empire_reforms_memory import add_reforms


def _profile() -> dict:
    return capture._load_profile()


def test_reused_mission_pe_guard_reads_only_the_selected_raw_section(tmp_path):
    # V3 reaches mission_memory through the shared process reader.
    image = bytearray(0x300)
    image[:2] = b'MZ'
    image[0x3c:0x40] = (0x80).to_bytes(4, 'little')
    image[0x80:0x84] = b'PE\0\0'
    image[0x86:0x88] = (1).to_bytes(2, 'little')
    section = 0x98
    image[section + 8:section + 12] = (0x20).to_bytes(4, 'little')
    image[section + 12:section + 16] = (0x1000).to_bytes(4, 'little')
    image[section + 16:section + 20] = (0x20).to_bytes(4, 'little')
    image[section + 20:section + 24] = (0x200).to_bytes(4, 'little')
    image[0x204:0x209] = b'guard'
    path = tmp_path / 'bounded.exe'
    path.write_bytes(image)
    assert capture._owner._mm.PROCESS_ACCESS == 0x410
    assert capture._owner._mm._read_pe_rva_bytes(path, 0x1004, 4) == b'guar'
    with pytest.raises(RuntimeError, match='pe_rva_not_in_raw_section'):
        capture._owner._mm._read_pe_rva_bytes(path, 0x101f, 2)


def _stub_runtime(monkeypatch, profile: dict, *, ui_snapshots=None):
    guard = [{"name": "fixture", "rva": "0x10", "actual_hex": "00", "matches": True}]
    context = {
        "world_pointer": hex(WORLD),
        "game_date": DATE,
        "physical_client_reference_raw_hex": _fullref(2, "POR"),
        "physical_client_reference_offset": "0x1e60",
        "client_mode": 0,
        "client_override": 0,
    }
    expected = capture._expected_ui_binding_snapshot(profile)
    snapshots = list(ui_snapshots) if ui_snapshots is not None else [expected, expected]
    calls = {"ui": 0}

    def current_binding(_binding):
        index = min(calls["ui"], len(snapshots) - 1)
        calls["ui"] += 1
        return deepcopy(snapshots[index])

    monkeypatch.setattr(capture._owner, "_guards", lambda reader, base, _profile: deepcopy(guard))
    monkeypatch.setattr(capture._owner, "_context", lambda reader, base: deepcopy(context))
    monkeypatch.setattr(capture, "_current_ui_binding_snapshot", current_binding)
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(profile))
    return guard, context, expected, calls


def _report(image, observation, profile: dict) -> dict:
    game_root = profile["ui_binding"]["game_root"]
    process_path = str(Path(game_root) / "eu4.exe")
    identity = {
        "binding_verified": True,
        "installation_creation_filetime": CREATION,
        "process_creation_filetime": CREATION,
        "process_path_sha256": capture.EXE_SHA256,
        "process_path": process_path,
    }
    rows = deepcopy(image.read_log)
    inner = {
        "schema": capture.INNER_SCHEMA,
        "status": "observed",
        "completed": True,
        "profile_sha256": capture.PROFILE_SHA256,
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "access": {
            "read_only": True,
            "native_function_invoked": False,
            "writes": False,
            "UI_control": False,
            "date_advance": False,
            "save_or_reload": False,
            "limit_bytes": capture._owner.MAX_READ_BYTES,
            "calls": len(rows),
            "bytes_requested": sum(row["size"] for row in rows),
        },
        "request": {
            "country": "HRE", "observer": "FRA", "session_id": SESSION,
            "creation_filetime": CREATION,
        },
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(BASE),
        "raw_reads": rows,
        "observation": deepcopy(observation),
    }
    return {"schema": capture.SCHEMA, "observer": "FRA",
            "object": {"type": "country", "country": "HRE"}, "capture": inner}


def test_v3_profile_admits_only_static_global_widget_binding():
    profile = _profile()
    assert profile["profile_scope"] == "global_hre_record_projection"
    assert profile["publication_admitted"] is True
    assert profile["reforms_publication_admitted"] is True
    assert profile["visibility"]["actual_ui_observed"] is False
    assert profile["visibility"]["visibility_evaluated"] is False
    assert profile["ui_binding"]["engine_loaded_gui_verified"] is False
    assert profile["ui_binding"]["widget"]["name"] == "reform_selected_frame"
    assert profile["ui_binding"]["widget"]["builder_object_offset"] == "+0x28"
    guards = {row["name"]: row for row in profile["code_guards"]}
    assert set(capture._REQUIRED_GUARDS) <= set(guards)
    assert len(bytes.fromhex(guards["hre_ui_selected_frame_table_dispatch"]["bytes"])) == 251
    assert profile["ui_binding"]["effective_gui"]["bytes"] == 18880


def test_v3_profile_rejects_effective_gui_or_configuration_drift(monkeypatch):
    profile = _profile()
    expected = capture._expected_ui_binding_snapshot(profile)
    changed = deepcopy(expected)
    changed["effective_gui"]["sha256"] = "0" * 64
    monkeypatch.setattr(capture, "_current_ui_binding_snapshot", lambda _binding: changed)
    with pytest.raises(ValueError, match="EMPIRE_V3_UI_BINDING_CHANGED"):
        capture._load_profile()


def test_v3_replay_preserves_known_empty_reforms_and_keeps_ui_boundary(monkeypatch):
    profile = _profile()
    _stub_runtime(monkeypatch, profile)
    image = add_reforms(make_image(), [])
    observation = capture._observe(image, BASE, "HRE", profile)
    report = _report(image, observation, profile)

    assert observation["status"] == "observed"
    assert observation["stable"] is True
    assert observation["reforms"]["status"] == "known"
    assert observation["reforms"]["value"] == []
    assert observation["publication_admitted"] is True
    assert observation["visibility_evaluated"] is False
    assert observation["actual_ui_observed"] is False
    assert capture.validate_capture(report, _context(), CREATION) is True

    projected = capture.project_fields(report)
    assert set(projected) == {"emperor", "electors", "reforms"}
    assert projected["emperor"]["value"] == "HAB"
    assert projected["electors"]["value"] == ["BOH", "BRA"]
    assert projected["reforms"]["status"] == "known"
    assert projected["reforms"]["value"] == []
    assert projected["reforms"]["complete"] is False
    assert projected["reforms"]["actual_ui_observed"] is False
    assert projected["reforms"]["visibility_evaluated"] is False
    serialized = repr(projected)
    for forbidden in ("raw_hex", "fullref", "pointer", "ui_binding_before", "process_path"):
        assert forbidden not in serialized


def test_v3_reform_field_drift_does_not_remove_stable_identity_fields(monkeypatch):
    profile = _profile()
    _stub_runtime(monkeypatch, profile)
    image = add_reforms(make_image(), ["hofgericht"])

    class ReformCountDrift:
        def __init__(self, inner):
            self.inner = inner

        @property
        def read_log(self):
            return self.inner.read_log

        @property
        def read_failures(self):
            return self.inner.read_failures

        def read(self, address, size, label):
            if label == "empire.pass2.reforms.count":
                raw = (0).to_bytes(4, "little", signed=True)
                self.inner.read_log.append({"address": hex(address), "size": size,
                                            "label": label, "status": "observed",
                                            "raw_hex": raw.hex()})
                return raw
            return self.inner.read(address, size, label)

    observation = capture._observe(ReformCountDrift(image), BASE, "HRE", profile)
    report = _report(image, observation, profile)
    assert observation["stable"] is True
    assert observation["field_stability"] == {
        "emperor": True, "electors": True, "reforms": False,
    }
    assert capture.validate_capture(report, _context(), CREATION) is True
    projected = capture.project_fields(report)
    assert projected["emperor"]["status"] == "known"
    assert projected["electors"]["status"] == "known"
    assert projected["reforms"]["status"] == "unknown"
    assert "value" not in projected["reforms"]


def test_v3_ui_drift_retracts_the_whole_v3_capture(monkeypatch):
    profile = _profile()
    expected = capture._expected_ui_binding_snapshot(profile)
    changed = deepcopy(expected)
    changed["configuration_sha256"] = "0" * 64
    _stub_runtime(monkeypatch, profile, ui_snapshots=[expected, changed])
    image = add_reforms(make_image(), ["hofgericht"])
    observation = capture._observe(image, BASE, "HRE", profile)

    assert observation["status"] == "unknown"
    assert observation["stable"] is False
    assert observation["ui_binding_stable"] is False
    assert observation["field_stability"]["emperor"] is True
    assert observation["field_stability"]["reforms"] is True
    report = _report(image, observation, profile)
    report["capture"]["status"] = "unknown"
    report["capture"]["completed"] = False
    with pytest.raises(ValueError, match="EMPIRE_V3_CAPTURE_NOT_COMPLETE"):
        capture.project_fields(report)


def test_v3_capture_rejects_same_hash_process_from_another_installation(monkeypatch):
    profile = _profile()
    monkeypatch.setattr(capture, "_load_profile", lambda: profile)
    wrong_identity = {
        "process_path": "C:/alternate-install/eu4.exe",
        "process_path_sha256": capture.EXE_SHA256,
    }

    def fake_capture(_installation, _country, **kwargs):
        kwargs["load_profile"]()
        return {
            "status": "observed", "completed": True,
            "identity": deepcopy(wrong_identity),
            "identity_after": deepcopy(wrong_identity),
            "errors": [], "cleanup": {"status": "closed", "closed": True, "success": True},
        }

    monkeypatch.setattr(capture._owner, "_capture_common", fake_capture)
    report = capture.capture("installation.json")
    assert report["capture"]["status"] == "unknown"
    assert report["capture"]["completed"] is False
    assert report["capture"]["errors"][-1]["reason"] == "EMPIRE_V3_PROCESS_ROOT_MISMATCH"


def test_v3_validate_rejects_typed_creation_and_trace_tail(monkeypatch):
    profile = _profile()
    _stub_runtime(monkeypatch, profile)
    image = add_reforms(make_image(), ["hofgericht"])
    report = _report(image, capture._observe(image, BASE, "HRE", profile), profile)
    assert capture.validate_capture(report, _context(), CREATION) is True

    bad_creation = deepcopy(report)
    bad_creation["capture"]["request"]["creation_filetime"] = True
    assert capture.validate_capture(bad_creation, _context(), CREATION) is False

    tail = deepcopy(report)
    tail["capture"]["raw_reads"].append({
        "address": hex(BASE + 0x100), "size": 1, "label": "unconsumed",
        "status": "observed", "raw_hex": "00",
    })
    tail["capture"]["access"]["calls"] += 1
    tail["capture"]["access"]["bytes_requested"] += 1
    assert capture.validate_capture(tail, _context(), CREATION) is False

