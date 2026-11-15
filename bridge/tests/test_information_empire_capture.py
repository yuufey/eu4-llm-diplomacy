from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import empire_capture as capture
from bridge.information import foreign_technology_capture as owner
from bridge.tests.test_information_empire_memory import BASE, make_image


BASE = 0x140000000
CREATION = 134380633247930565
SESSION = "25692-1dd6a79556f58c5"
DATE = 56556984


def _inner_report(rows=None):
    raw = bytes.fromhex("78563412")
    rows = rows if rows is not None else [{
        "address": hex(BASE + 0x100), "size": 4, "label": "capture.test.value",
        "status": "observed", "raw_hex": raw.hex(),
    }]
    identity = {
        "binding_verified": True,
        "installation_creation_filetime": CREATION,
        "process_creation_filetime": CREATION,
        "process_path_sha256": capture.EXE_SHA256,
        "process_path": "C:/game/eu4.exe",
    }
    return {
        "schema": capture.INNER_SCHEMA,
        "status": "observed",
        "completed": True,
        "profile_sha256": capture.PROFILE_SHA256,
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "access": {"read_only": True, "native_function_invoked": False, "writes": False,
                   "UI_control": False, "date_advance": False, "save_or_reload": False,
                   "limit_bytes": owner.MAX_READ_BYTES,
                   "calls": len(rows), "bytes_requested": sum(row["size"] for row in rows)},
        "request": {"country": "HRE", "observer": "FRA", "session_id": SESSION,
                    "creation_filetime": CREATION},
        "identity": identity,
        "identity_after": deepcopy(identity),
        "module_base": hex(BASE),
        "raw_reads": deepcopy(rows),
        "observation": {
            "stable": True,
            "context_before": {"game_date": DATE},
            "passes": [],
        },
    }


def _context():
    return {"observer": "FRA", "session_id": SESSION, "game_version": "1.37.4",
            "game_sha256": capture.EXE_SHA256, "game_date": DATE}


def _raw_ref(slot, tag):
    return ((slot << 32) | int.from_bytes(tag.encode("ascii"), "little")).to_bytes(8, "little").hex()


def _outer(inner):
    return {"schema": capture.SCHEMA, "observer": "FRA",
            "object": {"type": "country", "country": "HRE"}, "capture": inner}


def test_capture_is_bound_to_one_global_hre_record(monkeypatch):
    calls = {}

    def fake_capture(installation, country, **kwargs):
        calls.update({"installation": installation, "country": country, **kwargs})
        return {"status": "observed", "completed": True}

    monkeypatch.setattr(capture._owner, "_capture_common", fake_capture)
    report = capture.capture("installation.json")
    assert calls["country"] == "HRE"
    assert calls["observer"] == "FRA"
    assert calls["schema"] == capture.INNER_SCHEMA
    assert report["object"] == {"type": "country", "country": "HRE"}
    assert set(report) == {"schema", "observer", "object", "capture"}


def test_validate_capture_replays_exhausted_ordered_trace(monkeypatch):
    monkeypatch.setattr(capture, "_load_profile", lambda: {})

    def observe(reader, base, country, profile):
        raw = reader.read(base + 0x100, 4, "capture.test.value")
        return {"stable": True, "context_before": {"game_date": DATE},
                "context_after": {"game_date": DATE},
                "country": country, "value": int.from_bytes(raw, "little")}

    monkeypatch.setattr(capture, "_observe", observe)
    inner = _inner_report()
    expected = observe(owner._Replay(inner["raw_reads"]), BASE, "HRE", {})
    inner["observation"] = expected
    report = _outer(inner)
    assert capture.validate_capture(report, _context(), CREATION) is True

    appended = deepcopy(report)
    appended["capture"]["raw_reads"].append({
        "address": hex(BASE + 0x104), "size": 4, "label": "extra",
        "status": "observed", "raw_hex": "00000000",
    })
    appended["capture"]["access"]["calls"] += 1
    appended["capture"]["access"]["bytes_requested"] += 4
    assert capture.validate_capture(appended, _context(), CREATION) is False

    altered = deepcopy(report)
    altered["capture"]["raw_reads"][0]["raw_hex"] = "00000000"
    assert capture.validate_capture(altered, _context(), CREATION) is False


def test_validate_capture_rejects_stale_session_creation_and_object(monkeypatch):
    monkeypatch.setattr(capture, "_load_profile", lambda: {})

    def observe(reader, base, country, profile):
        raw = reader.read(base + 0x100, 4, "capture.test.value")
        return {"stable": True, "context_before": {"game_date": DATE},
                "context_after": {"game_date": DATE},
                "country": country, "value": int.from_bytes(raw, "little")}

    monkeypatch.setattr(capture, "_observe", observe)
    inner = _inner_report()
    inner["observation"] = observe(owner._Replay(inner["raw_reads"]), BASE, "HRE", {})
    report = _outer(inner)
    assert capture.validate_capture(report, _context(), CREATION) is True
    assert capture.validate_capture(report, _context() | {"session_id": "stale"}, CREATION) is False
    assert capture.validate_capture(report, _context(), CREATION + 1) is False
    wrong_object = deepcopy(report)
    wrong_object["object"] = {"type": "country", "country": "FRA"}
    assert capture.validate_capture(wrong_object, _context(), CREATION) is False


def test_validate_capture_rejects_bool_and_string_creation_values(monkeypatch):
    monkeypatch.setattr(capture, "_load_profile", lambda: {})

    def observe(reader, base, country, profile):
        raw = reader.read(base + 0x100, 4, "capture.test.value")
        return {"stable": True, "context_before": {"game_date": DATE},
                "context_after": {"game_date": DATE},
                "country": country, "value": int.from_bytes(raw, "little")}

    monkeypatch.setattr(capture, "_observe", observe)
    inner = _inner_report()
    inner["observation"] = observe(owner._Replay(inner["raw_reads"]), BASE, "HRE", {})
    report = _outer(inner)
    assert capture.validate_capture(report, _context(), CREATION) is True
    assert capture.validate_capture(report, _context(), True) is False

    for path, value in [
        (("request", "creation_filetime"), True),
        (("identity", "process_creation_filetime"), str(CREATION)),
        (("identity", "installation_creation_filetime"), True),
        (("identity_after", "process_creation_filetime"), str(CREATION)),
    ]:
        edited = deepcopy(report)
        edited["capture"][path[0]][path[1]] = value
        assert capture.validate_capture(edited, _context(), CREATION) is False


def test_projection_is_whitelist_only_and_preserves_ui_boundary():
    state = {
        "schema": "information.empire_memory.v1",
        "status": "known",
        "observer": "FRA",
        "observer_nonplayer": {"verified": True},
        "physical_client": {"tag": "POR", "fullref_raw_hex": _raw_ref(2, "POR")},
        "emperor": {"tag": "HAB", "fullref_raw_hex": _raw_ref(3, "HAB"), "country_pointer": "private"},
        "electors": [
            {"tag": "BRA", "fullref_raw_hex": _raw_ref(5, "BRA"), "country_pointer": "private"},
            {"tag": "BOH", "fullref_raw_hex": _raw_ref(4, "BOH"), "country_pointer": "private"},
        ],
        "elector_container": {"count": 2, "entries": [{}, {}], "node_plus_8_read": False},
        "country_bindings": {"sensitive": "never project"},
    }
    inner = _inner_report([])
    inner["observation"] = {
        "status": "observed", "stable": True, "visibility_evaluated": False,
        "actual_ui_observed": False,
        "context_before": {"game_date": DATE}, "context_after": {"game_date": DATE},
        "passes": [deepcopy(state), deepcopy(state)],
    }
    projected = capture.project_fields(_outer(inner))

    assert set(projected) == {"emperor", "electors"}
    assert projected["emperor"]["value"] == "HAB"
    assert projected["electors"]["value"] == ["BOH", "BRA"]
    assert all(field["status"] == "known" for field in projected.values())
    assert all(field["complete"] is False for field in projected.values())
    assert "publication_admitted" not in repr(projected)
    text = repr(projected)
    assert "country_pointer" not in text and "fullref" not in text and "sensitive" not in text


def test_projection_rejects_unstable_or_unbound_role():
    inner = _inner_report([])
    one = {"status": "known", "observer": "FRA",
           "observer_nonplayer": {"verified": True},
           "physical_client": {"tag": "POR", "fullref_raw_hex": _raw_ref(2, "POR")},
           "emperor": {"tag": "HAB"}, "electors": []}
    two = deepcopy(one)
    two["emperor"]["tag"] = "BOH"
    inner["observation"] = {"status": "unknown", "stable": False,
                            "visibility_evaluated": False,
                            "context_before": {"game_date": DATE}, "context_after": {"game_date": DATE},
                            "actual_ui_observed": False, "passes": [one, two]}
    with pytest.raises(ValueError, match="NOT_STABLE"):
        capture.project_fields(_outer(inner))

    one = deepcopy(one)
    one["observer_nonplayer"]["verified"] = False
    two = deepcopy(one)
    inner["observation"] = {"status": "observed", "stable": True,
                            "visibility_evaluated": False,
                            "context_before": {"game_date": DATE}, "context_after": {"game_date": DATE},
                            "actual_ui_observed": False, "passes": [one, two]}
    with pytest.raises(ValueError, match="NOT_VERIFIED"):
        capture.project_fields(_outer(inner))


def test_observe_requires_two_identical_memory_passes(monkeypatch):
    fixed_guard = [{"name": "fixture", "rva": "0x10", "actual_hex": "00", "matches": True}]
    monkeypatch.setattr(capture._owner, "_guards", lambda reader, base, profile: deepcopy(fixed_guard))
    image = make_image()
    observed = capture._observe(image, BASE, "HRE", {"code_guards": []})
    assert observed["status"] == "observed"
    assert observed["stable"] is True
    assert len(observed["passes"]) == 2
    assert observed["read_budget"]["calls"] == len(image.read_log)

    stable = make_image()

    class OpaqueHeaderDrift:
        def __init__(self, inner):
            self.inner = inner

        def read(self, address, size, label):
            raw = self.inner.read(address, size, label)
            if label == "empire.pass2.elector_header":
                changed = bytearray(raw)
                changed[8] ^= 1  # opaque header bytes are still part of the two-pass identity
                return bytes(changed)
            return raw

    drifted = capture._observe(OpaqueHeaderDrift(stable), BASE, "HRE", {"code_guards": []})
    assert drifted["status"] == "unknown"
    assert drifted["stable"] is False
