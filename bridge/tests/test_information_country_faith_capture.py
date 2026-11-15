"""Synthetic ordered-trace tests for the country-faith parent capture."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from bridge.information import country_faith_capture as capture
from bridge.information import country_faith_memory as faith
from bridge.information import country_view_admission_memory as admission
from bridge.tests import test_information_foreign_technology_capture as parent_fixture
from bridge.tests import test_information_foreign_technology_memory as backend_fixture


MODULE_BASE = backend_fixture.MODULE_BASE
CREATION = parent_fixture.CREATION
SESSION_ID = "country-faith-capture-session"
GAME_DATE = parent_fixture.GAME_DATE
WORLD = parent_fixture.WORLD
RELATION_TABLE = parent_fixture.RELATION_TABLE
RELATION_OWNER = parent_fixture.RELATION_OWNER
RELATION_COUNTERS = parent_fixture.RELATION_COUNTERS
CAPITAL = parent_fixture.CAPITAL
OBSERVER_BITSET = parent_fixture.OBSERVER_BITSET
CONTROLLER_TYPES = parent_fixture.CONTROLLER_TYPES
RELIGION_BASE = 0x6870000000
FAITH_NAME_RAW = bytes.fromhex("10295911494e105965")
FAITH_NAME_TEXT = "天主教"


def _fullref(tag: str, slot: int, generation: int) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _make_image(country: str, profile: dict[str, Any], *, admitted: bool = True):
    entries = {
        "FRA": (122, 0x1200, 5),
        "POR": (189, 0x5500, 3),
    }
    if country != "FRA":
        entries[country] = (300, 0x4500, 9)
    image, bindings, _technology_values = backend_fixture.make_reader(entries, count=310)
    refs = {tag: _fullref(tag, row[0], row[1]) for tag, row in entries.items()}

    # The physical player stays POR; FRA is the separate logical observer.
    image.put_u64(MODULE_BASE + 0x233FE58, WORLD)
    image.put_i32(WORLD + 0x1DD0, GAME_DATE)
    image.put_u64(WORLD + 0x1E60, refs["POR"])
    image.put_u64(WORLD + 0x1E68, 0)
    image.put_i32(WORLD + 0xA60, 1)
    image.put_u64(WORLD + 0x1D48, CONTROLLER_TYPES)
    image.put_i32(CONTROLLER_TYPES + 122 * 4, 0)
    for index, (_name, rva) in enumerate(admission.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(MODULE_BASE + rva, -10 - index)

    observer_pointer = bindings["FRA"]["country_pointer"]
    target_pointer = bindings[country]["country_pointer"]
    target_slot = entries[country][0]
    row = RELATION_TABLE + target_slot * admission.RELATION_ROW_STRIDE
    counter = (RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
               + target_slot * admission.RELATION_COUNTER_STRIDE)
    image.put_u64(observer_pointer + admission.RELATION_TABLE_OFFSET, RELATION_TABLE)
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, refs[country])
    image.put_u64(RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET, RELATION_COUNTERS)
    image.put_i32(counter, 1 if admitted else 0)
    if not admitted:
        image.put_u64(target_pointer + admission.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(CAPITAL + admission.CAPITAL_VIEW_FLAGS_OFFSET, b"\x10")
        image.put_u64(CAPITAL + admission.CAPITAL_OBSERVER_BITSET_OFFSET, OBSERVER_BITSET)
        bit_word = OBSERVER_BITSET + (122 >> 5) * admission.CAPITAL_OBSERVER_BITSET_WORD_STRIDE
        image.put(bit_word, b"\x00" * admission.CAPITAL_OBSERVER_BITSET_WORD_STRIDE)

    religion_pointer = RELIGION_BASE + target_slot * 0x1000
    name = FAITH_NAME_RAW
    header = bytearray(faith.STRING32_SIZE)
    header[:len(name) + 1] = name + b"\0"
    header[faith.STRING32_LENGTH_OFFSET:faith.STRING32_LENGTH_OFFSET + 8] = len(name).to_bytes(8, "little")
    header[faith.STRING32_CAPACITY_OFFSET:faith.STRING32_CAPACITY_OFFSET + 8] = (15).to_bytes(8, "little")
    image.put_u64(target_pointer + faith.COUNTRY_RELIGION_POINTER_OFFSET, religion_pointer)
    image.put(religion_pointer + faith.RELIGION_KEY_OFFSET, bytes(header))
    image.put(religion_pointer + faith.RELIGION_ICON_FRAME_OFFSET, (1).to_bytes(4, "little"))

    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    fixture = {
        "bindings": bindings,
        "refs": refs,
        "observer_pointer": observer_pointer,
        "target_pointer": target_pointer,
        "target_slot": target_slot,
        "target_fullref": refs[country],
        "physical_fullref": refs["POR"],
        "religion_pointer": religion_pointer,
        "faith_pointer_address": target_pointer + faith.COUNTRY_RELIGION_POINTER_OFFSET,
        "relation_counter_address": counter,
    }
    return image, fixture


def _bundle(country: str = "ENG", *, admitted: bool = True,
            profile: dict[str, Any] | None = None):
    profile = capture._load_profile() if profile is None else profile
    image, fixture = _make_image(country, profile, admitted=admitted)
    reader = parent_fixture.RecordingReader(image)
    observation = capture._observe(reader, MODULE_BASE, country, profile)
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture._owner.EXE_SHA256,
    }
    report = {
        "schema": capture.SCHEMA,
        "status": "observed" if observation.get("stable") is True else "unknown",
        "completed": observation.get("stable") is True,
        "request": {"country": country, "observer": "FRA", "creation_filetime": CREATION,
                    "session_id": SESSION_ID},
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(reader.read_log),
        "access": {"read_only": True, "native_function_invoked": False, "writes": False,
                   "UI_control": False, "date_advance": False, "save_or_reload": False,
                   "limit_bytes": capture._owner.MAX_READ_BYTES,
                   "bytes_requested": reader.bytes_requested, "calls": reader.calls},
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [],
    }
    context = {
        "observer": "FRA", "session_id": SESSION_ID,
        "game_version": "1.37.4", "game_sha256": capture._owner.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    return report, context, CREATION, {"image": image, "reader": reader, **fixture}


@pytest.fixture(scope="module")
def pinned_profile():
    return capture._load_profile()


@pytest.fixture(scope="module")
def positive_capture(pinned_profile):
    return _bundle(profile=pinned_profile)


def _valid(report: dict[str, Any], context: dict[str, Any], creation: int,
           country: str | None = None) -> bool:
    return capture.validate_capture(report, context, creation,
                                    country if country is not None else report["request"]["country"])


class _ErrorRecordingReader(parent_fixture.RecordingReader):
    """Fake RPM reader that logs failed calls in AddressBoundedRPM shape."""
    def __init__(self, source: Any, fail_label: str):
        super().__init__(source)
        self.fail_label = fail_label

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == self.fail_label:
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "error", "error": "synthetic read failure"})
            self.bytes_requested += size
            self.calls += 1
            raise OSError("synthetic read failure")
        return super().read(address, size, label)


def _capture_with_fake_process(monkeypatch, profile, image, *, fail_label: str,
                               close_ok: bool = True):
    class FakeKernel:
        def __init__(self):
            self.open_calls = 0
            self.close_calls = 0

        def OpenProcess(self, _access, _inherit, _pid):
            self.open_calls += 1
            return object()

        def CloseHandle(self, _handle):
            self.close_calls += 1
            return close_ok

    kernel = FakeKernel()
    document = {"pid": 777, "creation_filetime": CREATION,
                "session_id": SESSION_ID, "game_sha256": capture._owner.EXE_SHA256}
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(profile))
    monkeypatch.setattr(capture._owner._identity, "_load_installation", lambda _path: dict(document))
    monkeypatch.setattr(capture._owner._identity, "_configure_kernel", lambda: kernel)

    def fake_identity(target_report, _document, _kernel, _handle):
        target_report["identity"].update({
            "binding_verified": True,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": capture._owner.EXE_SHA256,
        })
        return MODULE_BASE

    monkeypatch.setattr(capture._owner._identity, "_capture_identity", fake_identity)
    expected = {int(item["rva"], 0): bytes.fromhex(item["bytes"])
                for item in profile["code_guards"]}
    monkeypatch.setattr(capture._owner._mm, "_read_pe_rva_bytes",
                        lambda _path, rva, size: expected[rva][:size])
    readers = []

    def fake_rpm(_kernel, _handle, _base):
        reader = _ErrorRecordingReader(image, fail_label)
        readers.append(reader)
        return reader

    monkeypatch.setattr(capture._owner._parent, "AddressBoundedRPM", fake_rpm)
    report = capture.capture(Path("synthetic-installation.json"), "ENG")
    return report, kernel, readers


def test_replay_binds_foreign_eng_slot_300_and_keeps_faith_partial(positive_capture, pinned_profile):
    report, context, creation, fixture = positive_capture

    assert _valid(report, context, creation)
    observation = report["observation"]
    assert observation["stable"] is True
    assert len(observation["runtime_code_before"]) == len(pinned_profile["code_guards"])
    assert all(item["matches"] is True for item in observation["runtime_code_before"])
    assert all(item["matches"] is True for item in observation["runtime_code_after"])
    assert observation["context_before"]["game_date"] == GAME_DATE
    assert observation["context_before"]["physical_client_reference_raw_hex"] == (
        fixture["physical_fullref"].to_bytes(8, "little").hex())

    backend = observation["backend"]
    assert backend["observer"]["tag"] == "FRA"
    assert backend["observer"]["fullref"] == hex(fixture["refs"]["FRA"])
    target = backend["targets"][0]
    assert target["tag"] == "ENG"
    assert target["bindings_by_pass"]["pass2"]["slot"] == 300
    assert target["fullref"] == hex(fixture["target_fullref"])
    field = target["fields"]["S02.faith"]
    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["value"] == {
        "primary_religion_name": {
            "text": FAITH_NAME_TEXT,
            "raw_hex": FAITH_NAME_RAW.hex(),
            "encoding": "eu4_escape",
        },
        "icon_frame_request": 1,
    }
    assert field["raw_inputs"]["primary_religion_name_raw_hex"] == FAITH_NAME_RAW.hex()
    assert field["raw_inputs"]["primary_religion_pointer_raw_hex"] == (
        fixture["religion_pointer"].to_bytes(8, "little").hex())
    for pass_name in ("pass1", "pass2"):
        gate = target["admission_by_pass"][pass_name]
        assert gate["status"] == "known" and gate["admitted"] is True
        assert gate["refs"]["row_recipient_fullref"] == hex(fixture["target_fullref"])
        assert gate["observer_nonplayer_role"]["verified"] is True
    assert backend["visibility"]["status"] == "unknown"
    assert backend["public_export_ready"] is False
    assert backend["complete"] is False
    assert all(row["status"] == "observed" for row in report["raw_reads"])


def test_self_target_fra_deduplicates_binding_and_does_not_replace_physical_por(pinned_profile):
    report, context, creation, fixture = _bundle("FRA", profile=pinned_profile)
    assert _valid(report, context, creation, "FRA")
    observation = report["observation"]
    backend = observation["backend"]
    target = backend["targets"][0]
    assert target["tag"] == "FRA"
    assert target["bindings_by_pass"]["pass1"]["slot"] == 122
    assert target["fullref"] == backend["observer"]["fullref"]
    assert target["fields"]["S02.faith"]["value"]["primary_religion_name"] == {
        "text": FAITH_NAME_TEXT,
        "raw_hex": FAITH_NAME_RAW.hex(),
        "encoding": "eu4_escape",
    }
    assert observation["context_before"]["physical_client_reference_raw_hex"] == (
        fixture["physical_fullref"].to_bytes(8, "little").hex())
    assert sum(row["label"] == "country_reference.slot[122].pointer"
               for row in report["raw_reads"]) == 2


def test_denied_gate_does_not_read_faith_private_inputs(pinned_profile):
    report, context, creation, _fixture = _bundle(admitted=False, profile=pinned_profile)
    assert report["observation"]["stable"] is True
    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    assert target["admission_by_pass"]["pass1"]["status"] == "known"
    assert target["admission_by_pass"]["pass1"]["admitted"] is False
    assert target["fields"]["S02.faith"]["status"] == "invisible"
    assert not any(row["label"].startswith("country_faith.") for row in report["raw_reads"])


@pytest.mark.parametrize("tamper", ["raw_input", "observation", "bool_int_value"])
def test_capture_replay_rejects_raw_and_observation_tampering(positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report = deepcopy(report)
    if tamper == "raw_input":
        row = next(item for item in report["raw_reads"]
                   if item["label"] == "country_faith.primary_religion_pointer")
        row["raw_hex"] = "00" * 8
    else:
        field = report["observation"]["backend"]["targets"][0]["fields"]["S02.faith"]
        if tamper == "observation":
            field["value"]["primary_religion_name"]["text"] = "Protestant"
        else:
            assert field["value"]["icon_frame_request"] == 1
            # Python would normally compare True == 1; replay must compare types.
            field["value"]["icon_frame_request"] = True
    assert not _valid(report, context, creation)


@pytest.mark.parametrize("tamper", [
    "read_only", "native_function_invoked", "writes", "UI_control", "date_advance",
    "save_or_reload", "limit", "calls", "calls_float", "bytes", "bytes_float",
    "cleanup_status", "cleanup_closed", "cleanup_success",
])
def test_capture_rejects_access_budget_and_cleanup_metadata_tampering(positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report = deepcopy(report)
    if tamper in {"read_only", "native_function_invoked", "writes", "UI_control",
                  "date_advance", "save_or_reload"}:
        report["access"][tamper] = not report["access"][tamper]
    elif tamper == "limit":
        report["access"]["limit_bytes"] -= 1
    elif tamper == "calls":
        report["access"]["calls"] += 1
    elif tamper == "calls_float":
        report["access"]["calls"] = float(report["access"]["calls"])
    elif tamper == "bytes":
        report["access"]["bytes_requested"] += 1
    elif tamper == "bytes_float":
        report["access"]["bytes_requested"] = float(report["access"]["bytes_requested"])
    elif tamper == "cleanup_status":
        report["cleanup"]["status"] = "open"
    elif tamper == "cleanup_closed":
        report["cleanup"]["closed"] = False
    else:
        report["cleanup"]["success"] = False
    assert not _valid(report, context, creation)


@pytest.mark.parametrize("tamper", ["target", "date", "rom", "role", "session"])
def test_target_date_rom_role_and_session_changes_retract_capture(positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report = deepcopy(report)
    context = deepcopy(context)
    if tamper == "target":
        assert not _valid(report, context, creation, "POR")
        return
    if tamper == "date":
        context["game_date"] += 1
    elif tamper == "session":
        context["session_id"] = "different-session"
    elif tamper == "role":
        gate = report["observation"]["backend"]["targets"][0]["admission_by_pass"]["pass1"]
        gate["observer_nonplayer_role"]["verified"] = False
    else:
        row = next(item for item in report["raw_reads"]
                   if item["label"].startswith("foreign_tech.code."))
        raw = bytearray.fromhex(row["raw_hex"])
        raw[0] ^= 1
        row["raw_hex"] = raw.hex()
    assert not _valid(report, context, creation)


def test_closehandle_failure_retracts_capture(monkeypatch, pinned_profile):
    image, _fixture = _make_image("ENG", pinned_profile)

    class FakeKernel:
        def __init__(self):
            self.open_calls = 0
            self.close_calls = 0

        def OpenProcess(self, _access, _inherit, _pid):
            self.open_calls += 1
            return object()

        def CloseHandle(self, _handle):
            self.close_calls += 1
            return False

    kernel = FakeKernel()
    document = {"pid": 777, "creation_filetime": CREATION,
                "session_id": SESSION_ID, "game_sha256": capture._owner.EXE_SHA256}
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(pinned_profile))
    monkeypatch.setattr(capture._owner._identity, "_load_installation", lambda _path: dict(document))
    monkeypatch.setattr(capture._owner._identity, "_configure_kernel", lambda: kernel)

    def fake_identity(target_report, _document, _kernel, _handle):
        target_report["identity"].update({
            "binding_verified": True,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": capture._owner.EXE_SHA256,
        })
        return MODULE_BASE

    monkeypatch.setattr(capture._owner._identity, "_capture_identity", fake_identity)
    expected = {int(item["rva"], 0): bytes.fromhex(item["bytes"])
                for item in pinned_profile["code_guards"]}
    monkeypatch.setattr(capture._owner._mm, "_read_pe_rva_bytes",
                        lambda _path, rva, size: expected[rva][:size])
    monkeypatch.setattr(capture._owner._parent, "AddressBoundedRPM",
                        lambda _kernel, _handle, _base: parent_fixture.RecordingReader(image))

    report = capture.capture(Path("synthetic-installation.json"), "ENG")
    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["observation"]["stable"] is True
    assert report["cleanup"]["status"] != "closed"
    assert report["completed"] is False and report["status"] == "unknown"
    context = {"observer": "FRA", "session_id": SESSION_ID,
               "game_version": "1.37.4", "game_sha256": capture._owner.EXE_SHA256,
               "game_date": GAME_DATE}
    assert not capture.validate_capture(report, context, CREATION, "ENG")


def test_field_only_rpm_error_is_replayed_and_reason_or_raw_tampering_is_rejected(
        monkeypatch, pinned_profile):
    image, fixture = _make_image("ENG", pinned_profile)
    report, kernel, readers = _capture_with_fake_process(
        monkeypatch, pinned_profile, image,
        fail_label="country_faith.primary_religion.String32_header",
    )
    context = {"observer": "FRA", "session_id": SESSION_ID,
               "game_version": "1.37.4", "game_sha256": capture._owner.EXE_SHA256,
               "game_date": GAME_DATE}

    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["status"] == "observed" and report["completed"] is True
    assert report["observation"]["stable"] is True
    field = report["observation"]["backend"]["targets"][0]["fields"]["S02.faith"]
    assert field["status"] == "unknown"
    row = next(item for item in report["raw_reads"]
               if item["label"] == "country_faith.primary_religion.String32_header")
    assert row == {"address": hex(fixture["religion_pointer"] + faith.RELIGION_KEY_OFFSET),
                   "size": faith.STRING32_SIZE,
                   "label": "country_faith.primary_religion.String32_header",
                   "status": "error", "error": "synthetic read failure"}
    assert _valid(report, context, CREATION)

    altered_reason = deepcopy(report)
    error_row = next(item for item in altered_reason["raw_reads"] if item["status"] == "error")
    error_row["error"] = "different read failure"
    assert not _valid(altered_reason, context, CREATION)

    forged_raw = deepcopy(report)
    error_row = next(item for item in forged_raw["raw_reads"] if item["status"] == "error")
    error_row["raw_hex"] = "00" * error_row["size"]
    assert not _valid(forged_raw, context, CREATION)
    assert readers and readers[0].read_log == report["raw_reads"]


def test_rom_guard_read_failure_invalidates_entire_capture(monkeypatch, pinned_profile):
    image, _fixture = _make_image("ENG", pinned_profile)
    first_guard = pinned_profile["code_guards"][0]
    report, kernel, readers = _capture_with_fake_process(
        monkeypatch, pinned_profile, image,
        fail_label="foreign_tech.code." + first_guard["name"],
    )

    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["status"] == "unknown" and report["completed"] is False
    assert report["observation"] is None
    assert report["cleanup"]["status"] == "closed"
    assert any(row["status"] == "error" for row in report["raw_reads"])
    context = {"observer": "FRA", "session_id": SESSION_ID,
               "game_version": "1.37.4", "game_sha256": capture._owner.EXE_SHA256,
               "game_date": GAME_DATE}
    assert not capture.validate_capture(report, context, CREATION, "ENG")
    assert readers and readers[0].read_log == report["raw_reads"]

