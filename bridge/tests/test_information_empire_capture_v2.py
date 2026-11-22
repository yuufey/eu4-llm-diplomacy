from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import empire_capture_v2 as capture
from bridge.information import empire_memory
from bridge.tests.test_information_empire_memory import BASE, WORLD, make_image
from bridge.tests.test_information_empire_reforms_memory import add_reforms


CREATION = 134380633247930565
SESSION = "25692-1dd6a79556f58c5"
DATE = 56556984


def _fullref(slot: int, tag: str) -> str:
    raw = (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")
    return raw.to_bytes(8, "little").hex()


def _context():
    return {
        "observer": "FRA",
        "session_id": SESSION,
        "game_version": "1.37.4",
        "game_sha256": capture.EXE_SHA256,
        "game_date": DATE,
    }


def _stub_runtime(monkeypatch):
    guard = [{"name": "fixture", "rva": "0x10", "actual_hex": "00", "matches": True}]
    context = {
        "world_pointer": hex(WORLD),
        "game_date": DATE,
        "physical_client_reference_raw_hex": _fullref(2, "POR"),
        "physical_client_reference_offset": "0x1e60",
        "client_mode": 0,
        "client_override": 0,
    }
    monkeypatch.setattr(capture._owner, "_guards", lambda reader, base, profile: deepcopy(guard))
    monkeypatch.setattr(capture._owner, "_context", lambda reader, base: deepcopy(context))
    monkeypatch.setattr(capture, "_load_profile", lambda: {})
    return guard, context


def _report(image, observation):
    identity = {
        "binding_verified": True,
        "installation_creation_filetime": CREATION,
        "process_creation_filetime": CREATION,
        "process_path_sha256": capture.EXE_SHA256,
        "process_path": "C:/game/eu4.exe",
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


def test_two_pass_capture_replays_exact_trace_and_rejects_tail_or_tampering(monkeypatch):
    _stub_runtime(monkeypatch)
    image = add_reforms(make_image(), ["hofgericht", "reichskammergericht"],
                        storage=["inline", "heap"])
    observation = capture._observe(image, BASE, "HRE", {})
    report = _report(image, observation)

    assert observation["status"] == "observed"
    assert observation["field_stability"] == {
        "emperor": True, "electors": True, "reforms": True,
    }
    assert capture.validate_capture(report, _context(), CREATION) is True

    tail = deepcopy(report)
    extra = {"address": hex(BASE + 0x100), "size": 1, "label": "extra",
             "status": "observed", "raw_hex": "00"}
    tail["capture"]["raw_reads"].append(extra)
    tail["capture"]["access"]["calls"] += 1
    tail["capture"]["access"]["bytes_requested"] += 1
    assert capture.validate_capture(tail, _context(), CREATION) is False

    changed = deepcopy(report)
    changed["capture"]["raw_reads"][0]["raw_hex"] = "00" * changed["capture"]["raw_reads"][0]["size"]
    assert capture.validate_capture(changed, _context(), CREATION) is False
    assert capture.validate_capture(report, _context(), True) is False


def test_reform_drift_isolated_from_stable_emperor_and_elector_projection(monkeypatch):
    _stub_runtime(monkeypatch)
    inner = add_reforms(make_image(), ["hofgericht"])

    class ReformCountDrift:
        def __init__(self, image):
            self.image = image

        @property
        def read_log(self):
            return self.image.read_log

        def read(self, address, size, label):
            if label == "empire.pass2.reforms.count":
                raw = (0).to_bytes(4, "little", signed=True)
                self.image.read_log.append({"address": hex(address), "size": size,
                                            "label": label, "status": "observed",
                                            "raw_hex": raw.hex()})
                return raw
            return self.image.read(address, size, label)

    drifting = ReformCountDrift(inner)
    observation = capture._observe(drifting, BASE, "HRE", {})
    report = _report(inner, observation)
    assert observation["status"] == "observed"
    assert observation["stable"] is True
    assert observation["field_stability"] == {
        "emperor": True, "electors": True, "reforms": False,
    }
    assert observation["reforms"]["status"] == "unknown"
    assert "value" not in observation["reforms"]

    projected = capture.project_fields(report)
    assert projected["emperor"]["value"] == "HAB"
    assert projected["electors"]["value"] == ["BOH", "BRA"]
    assert projected["reforms"]["status"] == "unknown"
    assert all(field["complete"] is False for field in projected.values())


def test_projection_exposes_only_reform_identifiers_and_retains_ui_boundary(monkeypatch):
    _stub_runtime(monkeypatch)
    image = add_reforms(make_image(), ["hofgericht"])
    observation = capture._observe(image, BASE, "HRE", {})
    projected = capture.project_fields(_report(image, observation))

    assert projected["reforms"] == {
        "status": "known",
        "value": ["hofgericht"],
        "unit": "reform_id",
        "scale": 1,
        "period": "current",
        "complete": False,
        "basis": "bounded_nul_terminated_hre_passed_reform_string_table",
    }
    assert set(projected) == {"emperor", "electors", "reforms"}
    serialized = repr(projected)
    for forbidden in ("raw_hex", "pointer", "fullref", "country_bindings", "visibility_evaluated"):
        assert forbidden not in serialized


def test_capture_adapter_passes_global_hre_scope_to_shared_owner(monkeypatch):
    calls = {}

    def fake_capture(installation, country, **kwargs):
        calls.update({"installation": installation, "country": country, **kwargs})
        return {"status": "observed", "completed": True}

    monkeypatch.setattr(capture._owner, "_capture_common", fake_capture)
    report = capture.capture("installation.json")
    assert calls["country"] == "HRE"
    assert calls["observer"] == "FRA"
    assert calls["schema"] == capture.INNER_SCHEMA
    assert calls["profile_sha256"] == capture.PROFILE_SHA256
    assert report["object"] == {"type": "country", "country": "HRE"}
    report = capture.capture("installation.json", observer="TUR")
    assert calls["observer"] == report["observer"] == "TUR"
    assert calls["observer_scoped"] is True
    with pytest.raises(ValueError, match="OBSERVER_SCOPE"):
        capture.capture("installation.json", observer="tur")


def test_validate_rejects_typed_identity_tampering(monkeypatch):
    _stub_runtime(monkeypatch)
    image = add_reforms(make_image(), ["hofgericht"])
    report = _report(image, capture._observe(image, BASE, "HRE", {}))
    assert capture.validate_capture(report, _context(), CREATION) is True

    edited = deepcopy(report)
    edited["capture"]["request"]["creation_filetime"] = True
    assert capture.validate_capture(edited, _context(), CREATION) is False

    edited = deepcopy(report)
    edited["capture"]["identity_after"]["installation_creation_filetime"] = str(CREATION)
    assert capture.validate_capture(edited, _context(), CREATION) is False

    assert capture.validate_capture(report, _context() | {"session_id": "stale"}, CREATION) is False


def test_profile_loads_private_layout_but_keeps_reform_publication_closed():
    profile = capture._load_profile()
    assert profile["profile_scope"] == "private_capture_only"
    assert profile["publication_admitted"] is False
    assert profile["reforms_publication_admitted"] is False
    assert profile["visibility"]["actual_ui_observed"] is False
    assert profile["visibility"]["reforms_publication_admitted"] is False
    assert profile["ui_binding"]["status"] == "unresolved"
    guard_by_name = {row["name"]: row for row in profile["code_guards"]}
    assert len(bytes.fromhex(guard_by_name["hre_passed_reforms_table_consumer"]["bytes"])) == 531
    assert len(bytes.fromhex(guard_by_name["hre_passed_reform_string_nul_serializer"]["bytes"])) == 747
