"""Synthetic integration tests for the identity-bound foreign-tech capture."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from bridge.information import country_view_admission_memory as admission
from bridge.information import foreign_technology_capture as capture
from bridge.tests import test_information_foreign_technology_memory as backend_fixture


MODULE_BASE = backend_fixture.MODULE_BASE
CREATION = 123456789012345678
SESSION_ID = "foreign-tech-capture-session"
GAME_DATE = 56_564_448
WORLD = 0x6800000000
RELATION_TABLE = 0x6810000000
RELATION_OWNER = 0x6820000000
RELATION_COUNTERS = 0x6830000000
CAPITAL = 0x6840000000
OBSERVER_BITSET = 0x6850000000
CONTROLLER_TYPES = 0x6860000000


class RecordingReader:
    """Trace-shaped fake RPM reader used by observe, replay, and capture tests."""

    def __init__(self, source: Any) -> None:
        self.source = source
        self.read_log: list[dict[str, Any]] = []
        self.bytes_requested = 0
        self.calls = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = self.source.read(address, size, label)
        self.read_log.append({
            "address": hex(address), "size": size, "label": label,
            "status": "observed", "raw_hex": raw.hex(),
        })
        self.bytes_requested += size
        self.calls += 1
        return raw


def _fullref(tag: str, slot: int, generation: int) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _write_capture_context(image: Any, *, country: str, admitted: bool,
                           physical_tag: str = "POR", human_fra: bool = False) -> dict[str, int]:
    bindings = {
        "FRA": {"slot": 122, "generation": 0x1200},
        "POR": {"slot": 189, "generation": 0x5500},
        country: {"slot": 300, "generation": 0x4500},
    }
    refs = {tag: _fullref(tag, row["slot"], row["generation"])
            for tag, row in bindings.items()}
    pointers = {
        tag: backend_fixture.COUNTRY_BASE + row["slot"] * 0x1000
        for tag, row in bindings.items()
    }

    # Parent context is the physical POR identity.  FRA remains the logical
    # observer passed independently to the foreign technology backend.
    image.put_u64(MODULE_BASE + 0x233FE58, WORLD)
    image.put_i32(WORLD + 0x1DD0, GAME_DATE)
    image.put_u64(WORLD + 0x1E60, refs[physical_tag])
    image.put_u64(WORLD + 0x1E68, 0)
    image.put_u64(WORLD + 0xA60, 1)
    image.put_u64(WORLD + 0x1D48, CONTROLLER_TYPES)
    image.put(CONTROLLER_TYPES + bindings["FRA"]["slot"] * 4,
              (1 if human_fra else 0).to_bytes(4, "little", signed=True))

    # Make the actual observer->target relation-counter path known.  The
    # relation row carries the complete target fullref, not a tag-only stub.
    observer_pointer = pointers["FRA"]
    target_pointer = pointers[country]
    target_ref = refs[country]
    image.put_u64(observer_pointer + admission.RELATION_TABLE_OFFSET, RELATION_TABLE)
    row = RELATION_TABLE + bindings[country]["slot"] * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, target_ref)
    image.put_u64(RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET, RELATION_COUNTERS)
    counter_address = (RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
                       + bindings[country]["slot"] * admission.RELATION_COUNTER_STRIDE)
    image.put_i32(counter_address, 1 if admitted else 0)

    for index, (_name, rva) in enumerate(admission.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(MODULE_BASE + rva, -10 - index)

    if not admitted:
        image.put_u64(target_pointer + admission.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(CAPITAL + admission.CAPITAL_VIEW_FLAGS_OFFSET, b"\x10")
        image.put_u64(CAPITAL + admission.CAPITAL_OBSERVER_BITSET_OFFSET, OBSERVER_BITSET)
        word_address = (OBSERVER_BITSET + (bindings["FRA"]["slot"] >> 5)
                        * admission.CAPITAL_OBSERVER_BITSET_WORD_STRIDE)
        image.put(word_address, b"\x00" * admission.CAPITAL_OBSERVER_BITSET_WORD_STRIDE)
    return {"physical_fullref": refs[physical_tag], "observer_fullref": refs["FRA"],
            "target_fullref": target_ref, "target_pointer": target_pointer,
            "relation_row": row, "relation_counter_address": counter_address,
            "human_count": 1, "controller_types_pointer": CONTROLLER_TYPES,
            "fra_controller_type": 1 if human_fra else 0}


def _make_fixture(country: str = "ENG", *, admitted: bool = True,
                  physical_tag: str = "POR", human_fra: bool = False,
                  profile: dict[str, Any] | None = None):
    profile = capture._load_profile() if profile is None else profile
    image, bindings, value_addresses = backend_fixture.make_reader({
        "FRA": (122, 0x1200, 5),
        "POR": (189, 0x5500, 3),
        country: (300, 0x4500, 9),
    }, count=310)
    refs = _write_capture_context(image, country=country, admitted=admitted,
                                  physical_tag=physical_tag, human_fra=human_fra)
    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    reader = RecordingReader(image)
    observation_error = None
    try:
        observation = capture._observe(reader, MODULE_BASE, country, profile)
    except Exception as exc:
        observation = None
        observation_error = f"{type(exc).__name__}:{exc}"
    observation_passed = observation_error is None and observation.get("stable") is True
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture.EXE_SHA256,
    }
    report = {
        "schema": "information.foreign_technology_capture.v1",
        "status": "observed" if observation_passed else "unknown",
        "completed": observation_passed,
        "request": {"country": country, "observer": "FRA", "creation_filetime": CREATION,
                    "session_id": SESSION_ID},
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(reader.read_log),
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [] if observation_error is None else [{"reason": observation_error}],
    }
    context = {
        "observer": "FRA", "session_id": SESSION_ID,
        "game_version": "1.37.4", "game_sha256": capture.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    fixture = {"image": image, "reader": reader, "bindings": bindings,
               "value_addresses": value_addresses, **refs}
    return report, context, CREATION, fixture


def make_valid_capture(country: str = "ENG", admitted: bool = True,
                       physical_tag: str = "POR", human_fra: bool = False):
    """Shared helper for public-source tests: report, context, creation, fixture."""
    return _make_fixture(country, admitted=admitted, physical_tag=physical_tag,
                         human_fra=human_fra)


@pytest.fixture(scope="module")
def pinned_profile():
    return capture._load_profile()


@pytest.fixture(scope="module")
def positive_capture(pinned_profile):
    return _make_fixture(profile=pinned_profile)


def _assert_valid(report: dict[str, Any], context: dict[str, Any], creation: int) -> bool:
    return capture.validate_capture(report, context, creation, report["request"]["country"])


def test_replayed_capture_binds_target_gate_date_and_physical_por_separately(positive_capture):
    report, context, creation, fixture = positive_capture

    assert _assert_valid(report, context, creation)
    observation = report["observation"]
    assert observation["stable"] is True
    assert all(item["matches"] is True for item in observation["runtime_code_before"])
    assert all(item["matches"] is True for item in observation["runtime_code_after"])
    assert observation["context_before"]["game_date"] == GAME_DATE
    physical_raw = observation["context_before"]["physical_client_reference_raw_hex"]
    assert physical_raw == fixture["physical_fullref"].to_bytes(8, "little").hex()
    assert backend_fixture.foreign._tag_from_fullref(int.from_bytes(bytes.fromhex(physical_raw), "little")) == "POR"

    backend = observation["backend"]
    assert backend["observer"]["tag"] == "FRA"
    assert backend["observer"]["fullref"] == hex(fixture["observer_fullref"])
    assert backend["observer"]["fullref"] != hex(fixture["physical_fullref"])
    target = backend["targets"][0]
    assert target["tag"] == "ENG"
    assert target["fullref"] == hex(fixture["target_fullref"])
    assert target["technology"]["value"] == 9
    assert target["technology"]["raw_hex"] == "09000000"

    gate = target["admission_by_pass"]
    for pass_name in ("pass1", "pass2"):
        assert gate[pass_name]["status"] == "known"
        assert gate[pass_name]["admitted"] is True
        assert gate[pass_name]["target"]["relation_counter_signed_i32"] == 1
        assert gate[pass_name]["refs"]["row_recipient_fullref"] == hex(fixture["target_fullref"])
        assert gate[pass_name]["refs"]["target_binding_fullref"] == hex(fixture["target_fullref"])
        assert gate[pass_name]["actual_UI_observed"] is False
        assert gate[pass_name]["observer_nonplayer_role"] == {
            "observer": "FRA", "slot": 122, "human_count": 1, "controller_type": 0,
            "human_count_raw_hex": "01000000", "controller_type_raw_hex": "00000000",
            "controllers_pointer_raw_hex": CONTROLLER_TYPES.to_bytes(8, "little").hex(),
            "verified": True, "basis": "copied_native_controller_array_not_UI_current_country",
        }
    assert backend["visibility"]["status"] == "unknown"
    assert backend["visibility"]["public_export_ready"] is False
    assert all(row["status"] == "observed" for row in report["raw_reads"])


def test_known_negative_gate_remains_a_valid_private_observation(pinned_profile):
    report, context, creation, _fixture = _make_fixture(admitted=False, profile=pinned_profile)

    assert _assert_valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    assert target["technology"]["value"] == 9
    assert target["admission_by_pass"]["pass1"]["status"] == "known"
    assert target["admission_by_pass"]["pass1"]["admitted"] is False
    assert report["observation"]["backend"]["visibility"]["public_export_ready"] is False


def test_raw_current_ref_does_not_replace_controller_type_as_human_authority(pinned_profile):
    report, context, creation, fixture = _make_fixture(
        physical_tag="FRA", human_fra=False, profile=pinned_profile)

    assert _assert_valid(report, context, creation)
    assert fixture["physical_fullref"] == fixture["observer_fullref"]
    assert fixture["fra_controller_type"] == 0
    assert report["observation"]["backend"]["observer"]["tag"] == "FRA"


def test_human_fra_controller_is_rejected_even_with_physical_por_reference(pinned_profile):
    report, context, creation, fixture = _make_fixture(
        physical_tag="POR", human_fra=True, profile=pinned_profile)

    assert fixture["physical_fullref"] != fixture["observer_fullref"]
    assert fixture["fra_controller_type"] == 1
    assert not _assert_valid(report, context, creation)
    if report["observation"] is not None:
        role = report["observation"]["backend"]["targets"][0]["admission_by_pass"]["pass1"]["observer_nonplayer_role"]
        assert role["verified"] is False


def test_capture_entrypoint_uses_only_fake_process_and_closes_successfully(monkeypatch, pinned_profile):
    image, _bindings, _values = backend_fixture.make_reader({
        "FRA": (122, 0x1200, 5), "POR": (189, 0x5500, 3), "ENG": (300, 0x4500, 9),
    }, count=310)
    refs = _write_capture_context(image, country="ENG", admitted=True)
    for guard in pinned_profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))

    class FakeKernel:
        def __init__(self):
            self.open_calls = 0
            self.close_calls = 0
            self.open_arguments = None

        def OpenProcess(self, access, inherit, pid):
            self.open_calls += 1
            self.open_arguments = (access, inherit, pid)
            return object()

        def CloseHandle(self, _handle):
            self.close_calls += 1
            return True

    kernel = FakeKernel()
    document = {"pid": 777, "creation_filetime": CREATION,
                "session_id": SESSION_ID, "game_sha256": capture.EXE_SHA256}
    identity_calls = 0
    readers: list[RecordingReader] = []
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(pinned_profile))
    monkeypatch.setattr(capture._identity, "_load_installation", lambda _path: dict(document))
    monkeypatch.setattr(capture._identity, "_configure_kernel", lambda: kernel)

    def fake_identity(target_report, _document, _kernel, _handle):
        nonlocal identity_calls
        identity_calls += 1
        target_report["identity"].update({
            "binding_verified": True,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": capture.EXE_SHA256,
        })
        return MODULE_BASE

    monkeypatch.setattr(capture._identity, "_capture_identity", fake_identity)
    expected_by_rva = {int(item["rva"], 0): bytes.fromhex(item["bytes"])
                       for item in pinned_profile["code_guards"]}
    monkeypatch.setattr(capture._mm, "_read_pe_rva_bytes",
                        lambda _path, rva, size: expected_by_rva[rva][:size])

    def fake_rpm(_kernel, _handle, _base):
        reader = RecordingReader(image)
        readers.append(reader)
        return reader

    monkeypatch.setattr(capture._parent, "AddressBoundedRPM", fake_rpm)
    report = capture.capture(Path("synthetic-installation.json"), "ENG")
    context = {"observer": "FRA", "session_id": SESSION_ID,
               "game_version": "1.37.4", "game_sha256": capture.EXE_SHA256,
               "game_date": GAME_DATE}

    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["cleanup"]["status"] == "closed"
    assert kernel.open_calls == 1
    assert kernel.close_calls == 1
    assert kernel.open_arguments == (capture._mm.PROCESS_ACCESS, False, 777)
    assert identity_calls == 2
    assert readers and readers[0].bytes_requested <= capture.MAX_READ_BYTES
    assert report["observation"]["context_before"]["physical_client_reference_raw_hex"] == (
        refs["physical_fullref"].to_bytes(8, "little").hex())
    assert capture.validate_capture(report, context, CREATION, "ENG")


@pytest.mark.parametrize("tamper", [
    "value_raw", "target_fullref", "gate", "trace_order", "cleanup", "profile",
    "session", "creation", "date", "physical_ref",
])
def test_capture_validator_rejects_projection_trace_and_identity_tampering(positive_capture, tamper):
    report, context, creation, fixture = positive_capture
    report = deepcopy(report)
    context = deepcopy(context)
    if tamper == "value_raw":
        row = next(item for item in report["raw_reads"]
                   if item["label"] == "military_quality.technology.level")
        row["raw_hex"] = "0a000000"
    elif tamper == "target_fullref":
        report["observation"]["backend"]["targets"][0]["fullref"] = hex(fixture["physical_fullref"])
    elif tamper == "gate":
        report["observation"]["backend"]["targets"][0]["admission_by_pass"]["pass2"]["admitted"] = False
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
    elif tamper == "physical_ref":
        report["observation"]["context_before"]["physical_client_reference_raw_hex"] = (
            fixture["observer_fullref"].to_bytes(8, "little").hex()
        )

    assert not capture.validate_capture(report, context, creation, "ENG")


@pytest.mark.parametrize("failure", ["open", "file_guard", "runtime_guard", "cleanup"])
def test_process_capture_failures_are_closed_and_never_completed(monkeypatch, pinned_profile, failure):
    image, _bindings, _values = backend_fixture.make_reader({
        "FRA": (122, 0x1200, 5), "POR": (189, 0x5500, 3), "ENG": (300, 0x4500, 9),
    }, count=310)
    refs = _write_capture_context(image, country="ENG", admitted=True)
    for guard in pinned_profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))

    class FakeKernel:
        def __init__(self):
            self.open_calls = 0
            self.close_calls = 0
            self.open_ok = failure != "open"
            self.close_ok = failure != "cleanup"

        def OpenProcess(self, _access, _inherit, _pid):
            self.open_calls += 1
            return object() if self.open_ok else None

        def CloseHandle(self, _handle):
            self.close_calls += 1
            return self.close_ok

    kernel = FakeKernel()
    document = {"pid": 777, "creation_filetime": CREATION,
                "session_id": SESSION_ID, "game_sha256": capture.EXE_SHA256}
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(pinned_profile))
    monkeypatch.setattr(capture._identity, "_load_installation", lambda _path: dict(document))
    monkeypatch.setattr(capture._identity, "_configure_kernel", lambda: kernel)

    def fake_identity(target_report, _document, _kernel, _handle):
        target_report["identity"].update({
            "binding_verified": True,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": capture.EXE_SHA256,
        })
        return MODULE_BASE

    monkeypatch.setattr(capture._identity, "_capture_identity", fake_identity)
    expected_by_rva = {int(item["rva"], 0): bytes.fromhex(item["bytes"])
                       for item in pinned_profile["code_guards"]}
    first_guard_rva = int(pinned_profile["code_guards"][0]["rva"], 0)

    def read_pe(_path, rva, size):
        raw = expected_by_rva[rva]
        if failure == "file_guard" and rva == first_guard_rva:
            return bytes([raw[0] ^ 1]) + raw[1:size]
        return raw[:size]

    monkeypatch.setattr(capture._mm, "_read_pe_rva_bytes", read_pe)

    def fake_rpm(_kernel, _handle, _base):
        if failure == "runtime_guard":
            guard = pinned_profile["code_guards"][0]
            address = MODULE_BASE + int(guard["rva"], 0)
            raw = bytes.fromhex(guard["bytes"])
            image.put(address, bytes([raw[0] ^ 1]) + raw[1:])
        return RecordingReader(image)

    monkeypatch.setattr(capture._parent, "AddressBoundedRPM", fake_rpm)

    report = capture.capture(Path("synthetic-installation.json"), "ENG")

    assert report["status"] == "unknown"
    assert report["completed"] is False
    assert kernel.open_calls == 1
    if failure == "open":
        assert report["cleanup"]["status"] == "not_opened"
        assert kernel.close_calls == 0
        assert report["observation"] is None
    elif failure in ("file_guard", "runtime_guard"):
        assert report["cleanup"]["status"] == "closed"
        assert kernel.close_calls == 1
        assert report["observation"] is None
    else:
        assert report["cleanup"]["status"] != "closed"
        assert kernel.close_calls == 1
        assert report["observation"]["backend"]["status"] == "observed"

