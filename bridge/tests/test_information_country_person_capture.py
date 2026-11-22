"""Synthetic ordered-trace tests for the S04 country-person capture.

These tests build owned in-memory country/person records and replay the exact
RPM-shaped read log. They never attach to a game process or execute a game
function. The profile fixture must be ready and pinned before the suite runs.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import pytest

from bridge.information import country_person_capture as capture
from bridge.information import country_person_memory as person_fields
from bridge.information import country_view_admission_memory as admission
from bridge.information import person_age_memory as ages
from bridge.information import person_claim_memory as claims
from bridge.information import person_name_memory as names
from bridge.information import person_panel_conditions_memory as panels
from bridge.tests import test_information_foreign_technology_capture as parent_fixture
from bridge.tests import test_information_foreign_technology_memory as backend_fixture


MODULE_BASE = backend_fixture.MODULE_BASE
PLUGIN_BASE = 0x68E0000000
CREATION = 134376782534496994
SESSION_ID = "country-person-capture-session"
GAME_DATE = 56_564_448
WORLD = 0x6800000000
RELATION_TABLE = 0x6810000000
RELATION_OWNER = 0x6820000000
RELATION_COUNTERS = 0x6830000000
CAPITAL = 0x6840000000
OBSERVER_BITSET = 0x6850000000
CONTROLLER_TYPES = 0x6860000000
PERSON_BASE = 0x6880000000
DYNASTY_BASE = 0x6890000000
PERSON_VTABLE_BASE = 0x68A0000000
DYNASTY_VTABLE_BASE = 0x68B0000000
PANEL_OWNER_BASE = 0x68C0000000
PANEL_PROPERTY_BASE = 0x68D0000000
WEAK_CLAIM_THRESHOLD = 40
STRONG_CLAIM_THRESHOLD = 80


def _fullref(tag: str, slot: int, generation: int) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(
        tag.encode("ascii"), "little")


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


def _string32(text: str | bytes) -> bytes:
    raw = text.encode("ascii") if isinstance(text, str) else bytes(text)
    if len(raw) > 15:
        raise ValueError("fixture String32 inline text too long")
    header = bytearray(names.STRING32_SIZE)
    header[:len(raw) + 1] = raw + b"\0"
    header[0x10:0x18] = len(raw).to_bytes(8, "little")
    header[0x18:0x20] = (15).to_bytes(8, "little")
    return bytes(header)


def _put_person(image: Any, country_pointer: int, country_ref: int, *,
                label: str, slot: int, text: str, age_years: int,
                skills: tuple[int, int, int], claim_raw: int,
                present: bool = True, include_dynasty: bool = False,
                dynasty_text: str | bytes = "House",
                regency_pointer: int = 0) -> dict[str, int]:
    person = PERSON_BASE + slot * 0x10000 + (0x1000 if label == "heir" else 0)
    vtable = PERSON_VTABLE_BASE + slot * 0x1000 + (0x100 if label == "heir" else 0)
    dynasty = DYNASTY_BASE + slot * 0x1000 + (0x100 if label == "heir" else 0)
    dynasty_vtable = DYNASTY_VTABLE_BASE + slot * 0x1000 + (
        0x100 if label == "heir" else 0)

    # read_person_name copies a complete 0x80-byte person header, including
    # padding and fields this projection does not interpret.
    image.put(person, bytes(names.PERSON_HEADER_SIZE))
    image.put_u64(country_pointer + (0x1280 if label == "ruler" else 0x1298), person)
    image.put_u64(person, vtable)
    image.put_u64(person + names.PERSON_COUNTRY_FULLREF_OFFSET, country_ref)
    image.put(person + names.PERSON_BASE_NAME_OFFSET, _string32(text))
    image.put_u64(person + names.PERSON_DYNASTY_POINTER_OFFSET, dynasty)
    image.put_u64(person + names.PERSON_REGENCY_POINTER_OFFSET, regency_pointer)
    image.put(person + 0x48, b"".join(_i32(value) for value in skills))
    birth_date = GAME_DATE - age_years * 365 * 24
    image.put(person + 0x70, _i32(birth_date))
    image.put(person + claims.PERSON_CLAIM_RAW_OFFSET, _i32(claim_raw))

    image.put_u64(vtable + 0x58,
                  MODULE_BASE + (0x8F440 if present else 0x8F450))
    image.put_u64(vtable + claims.PERSON_CLAIM_GETTER_VTABLE_OFFSET,
                  MODULE_BASE + claims.PERSON_CLAIM_GETTER_RVA)
    image.put_u64(dynasty, dynasty_vtable)
    image.put_u64(dynasty_vtable + names.DYNASTY_PREDICATE_OFFSET,
                  MODULE_BASE + (names.DYN_APPEND_TRUE_RVA
                                 if include_dynasty else names.DYN_APPEND_FALSE_RVA))
    image.put(dynasty + names.DYNASTY_NAME_OFFSET, _string32(dynasty_text))
    return {
        "person": person,
        "vtable": vtable,
        "dynasty": dynasty,
        "dynasty_vtable": dynasty_vtable,
    }


def _make_image(country: str, profile: dict[str, Any], *,
                admitted: bool = True, hidden_heir: bool = False,
                no_heir: bool = False, ruler_regency: int = 0,
                heir_regency: int = 0, name_runtime_layout: str = "vanilla",
                name_runtime_tamper: str | None = None, observer='FRA'):
    entries = {
        observer: (122, 0x1200, 5),
        "POR": (189, 0x5500, 3),
    }
    if country != observer:
        entries[country] = (300, 0x4500, 9)
    image, bindings, _unused_vectors = backend_fixture.make_reader(entries, count=310)
    refs = {
        tag: backend_fixture.fullref(tag, row[0], row[1])
        for tag, row in entries.items()
    }

    # Keep POR as the physical player with another country as the observer.
    image.put_u64(MODULE_BASE + 0x233FE58, WORLD)
    image.put_i32(WORLD + 0x1DD0, GAME_DATE)
    image.put_u64(WORLD + 0x1E60, refs["POR"])
    image.put_u64(WORLD + 0x1E68, 0)
    image.put_i32(WORLD + 0xA60, 1)
    image.put_u64(WORLD + 0x1D48, CONTROLLER_TYPES)
    image.put_i32(CONTROLLER_TYPES + 122 * 4, 0)

    for index, (_name, rva) in enumerate(admission.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(MODULE_BASE + rva, -10 - index)

    observer_pointer = bindings[observer]["country_pointer"]
    target_pointer = bindings[country]["country_pointer"]
    target_slot = entries[country][0]
    relation_row = RELATION_TABLE + target_slot * admission.RELATION_ROW_STRIDE
    counter_address = (
        RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
        + target_slot * admission.RELATION_COUNTER_STRIDE
    )
    image.put_u64(observer_pointer + admission.RELATION_TABLE_OFFSET, RELATION_TABLE)
    image.put_u64(relation_row + admission.RELATION_ROW_OWNER_OFFSET, RELATION_OWNER)
    image.put_u64(
        relation_row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET,
        refs[country],
    )
    image.put_u64(
        RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET,
        RELATION_COUNTERS,
    )
    image.put_i32(counter_address, 1 if admitted else 0)
    if not admitted:
        image.put_u64(target_pointer + admission.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(
            CAPITAL + admission.CAPITAL_VIEW_FLAGS_OFFSET,
            b"\x10",
        )
        image.put_u64(
            CAPITAL + admission.CAPITAL_OBSERVER_BITSET_OFFSET, OBSERVER_BITSET)
        bit_word = (
            OBSERVER_BITSET
            + (122 >> 5) * admission.CAPITAL_OBSERVER_BITSET_WORD_STRIDE
        )
        image.put(
            bit_word,
            b"\x00" * admission.CAPITAL_OBSERVER_BITSET_WORD_STRIDE,
        )

    # A zero high discriminator byte follows the native non-union display path.
    image.put_u64(
        target_pointer + 0x18F0,
        backend_fixture.fullref(country, target_slot, generation=0),
    )

    panel_owner = PANEL_OWNER_BASE + target_slot * 0x1000
    panel_attributes = panel_owner + panels.PANEL_ATTRIBUTES_BASE_OFFSET
    image.put_u64(
        target_pointer + panels.COUNTRY_PANEL_ATTRIBUTES_POINTER_OFFSET,
        panel_owner,
    )
    panel_values = {
        "heir_panel": 0 if hidden_heir else 1,
        "heir_special_name": 0,
        "monarchists": 0,
    }
    for index, (name, offset) in enumerate((
        ("heir_panel", panels.HEIR_PANEL_SLOT_OFFSET),
        ("heir_special_name", panels.HEIR_SPECIAL_NAME_SLOT_OFFSET),
        ("monarchists", panels.MONARCHISTS_SLOT_OFFSET),
    )):
        property_pointer = PANEL_PROPERTY_BASE + target_slot * 0x1000 + index * 0x100
        image.put_u64(panel_attributes + offset, property_pointer)
        image.put_i32(property_pointer, 0)
        image.put(property_pointer + panels.PROPERTY_VALUE_OFFSET,
                  bytes([panel_values[name]]))

    ruler = _put_person(
        image,
        target_pointer,
        refs[country],
        label="ruler",
        slot=target_slot,
        text="Edward",
        age_years=34,
        skills=(4, 3, 5),
        claim_raw=50,
        present=True,
        include_dynasty=False,
        dynasty_text="York",
        regency_pointer=ruler_regency,
    )
    heir = _put_person(
        image,
        target_pointer,
        refs[country],
        label="heir",
        slot=target_slot,
        text="Arthur",
        age_years=17,
        skills=(1, 2, 3),
        claim_raw=60,
        present=not no_heir,
        include_dynasty=True,
        dynasty_text=b"\xbfTudor" if name_runtime_layout == "plugin64" else "Tudor",
        regency_pointer=heir_regency,
    )
    image.put_i32(MODULE_BASE + claims.WEAK_THRESHOLD_RVA, WEAK_CLAIM_THRESHOLD)
    image.put_i32(MODULE_BASE + claims.STRONG_THRESHOLD_RVA, STRONG_CLAIM_THRESHOLD)
    image.put(
        MODULE_BASE + 0x1C3A5C8,
        b"".join(_i32(value) for value in ages.MONTHS),
    )

    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))

    runtime = profile.get("name_runtime")
    if runtime is not None:
        patch_rva = _profile_int(runtime["patch_rva"])
        original_patch = bytes.fromhex(runtime["original_bytes"])
        patch_address = MODULE_BASE + patch_rva
        if name_runtime_layout == "vanilla":
            image.put(patch_address, original_patch)
        elif name_runtime_layout == "plugin64":
            plugin = runtime["plugin"]
            hook_rva = _profile_int(plugin["hook_rva"])
            callback_rva = _profile_int(plugin["callback_rva"])
            return_rva = _profile_int(plugin["return_rva"])
            slots_rva = _profile_int(plugin["slots_rva"])
            image.put(
                patch_address,
                bytes.fromhex("ff2500000000")
                + (PLUGIN_BASE + hook_rva).to_bytes(8, "little"),
            )
            plugin_header = bytearray(bytes.fromhex(plugin["header_bytes"]))
            image_base_offset = plugin.get("header_image_base_offset")
            if image_base_offset is not None:
                image_base_offset = _profile_int(image_base_offset)
                if image_base_offset < 0 or image_base_offset + 8 > len(plugin_header):
                    raise ValueError("profile plugin ImageBase field is outside fake header")
                preferred_image_base = plugin.get("preferred_image_base")
                if preferred_image_base is not None:
                    preferred_image_base = _profile_int(preferred_image_base)
                    if plugin_header[image_base_offset:image_base_offset + 8] != (
                            preferred_image_base.to_bytes(8, "little")):
                        raise ValueError("profile plugin ImageBase bytes disagree with preferred base")
                plugin_header[image_base_offset:image_base_offset + 8] = (
                    PLUGIN_BASE.to_bytes(8, "little"))
            image.put(PLUGIN_BASE, bytes(plugin_header))
            for guard in plugin["code_guards"]:
                image.put(
                    PLUGIN_BASE + _profile_int(guard["rva"]),
                    bytes.fromhex(guard["bytes"]),
                )
            return_pointer = MODULE_BASE + return_rva
            callback_pointer = PLUGIN_BASE + callback_rva
            if name_runtime_tamper == "return":
                return_pointer += 1
            elif name_runtime_tamper == "callback":
                callback_pointer += 1
            image.put(
                PLUGIN_BASE + slots_rva,
                return_pointer.to_bytes(8, "little")
                + callback_pointer.to_bytes(8, "little"),
            )
            if name_runtime_tamper == "guard":
                first_guard = plugin["code_guards"][0]
                guard_address = PLUGIN_BASE + _profile_int(first_guard["rva"])
                actual = bytearray(bytes.fromhex(first_guard["bytes"]))
                actual[0] ^= 1
                image.put(guard_address, bytes(actual))
        else:
            raise ValueError(f"unsupported fixture name runtime layout: {name_runtime_layout}")
    elif name_runtime_layout != "vanilla" or name_runtime_tamper is not None:
        raise ValueError("runtime chooser fixture requires profile name_runtime")

    fixture = {
        "bindings": bindings,
        "refs": refs,
        "observer_pointer": observer_pointer,
        "target_pointer": target_pointer,
        "target_slot": target_slot,
        "target_fullref": refs[country],
        "physical_fullref": refs["POR"],
        "relation_counter_address": counter_address,
        "panel_owner": panel_owner,
        "panel_attributes": panel_attributes,
        "ruler": ruler,
        "heir": heir,
    }
    return image, fixture


def _bundle(country: str = "ENG", *, profile: dict[str, Any] | None = None,
            admitted: bool = True, hidden_heir: bool = False,
            no_heir: bool = False, ruler_regency: int = 0,
            heir_regency: int = 0, reader: Any | None = None,
            name_runtime_layout: str = "vanilla",
            name_runtime_tamper: str | None = None, observer='FRA'):
    profile = capture._load_profile() if profile is None else profile
    image, fixture = _make_image(
        country,
        profile,
        admitted=admitted,
        hidden_heir=hidden_heir,
        no_heir=no_heir,
        ruler_regency=ruler_regency,
        heir_regency=heir_regency,
        name_runtime_layout=name_runtime_layout,
        name_runtime_tamper=name_runtime_tamper, observer=observer,
    )
    reader = parent_fixture.RecordingReader(image) if reader is None else reader(image)
    observation = capture._observe(reader, MODULE_BASE, country, profile, observer=observer)
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
        "request": {
            "country": country,
            "observer": observer,
            "creation_filetime": CREATION,
            "session_id": SESSION_ID,
        },
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": deepcopy(identity),
        "identity_after": deepcopy(identity),
        "module_base": hex(MODULE_BASE),
        "observation": observation,
        "raw_reads": deepcopy(reader.read_log),
        "access": {
            "read_only": True,
            "native_function_invoked": False,
            "writes": False,
            "UI_control": False,
            "date_advance": False,
            "save_or_reload": False,
            "limit_bytes": capture._owner.MAX_READ_BYTES,
            "bytes_requested": reader.bytes_requested,
            "calls": reader.calls,
        },
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "errors": [],
    }
    context = {
        "observer": observer,
        "session_id": SESSION_ID,
        "game_version": "1.37.4",
        "game_sha256": capture._owner.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    return report, context, CREATION, {"image": image, "reader": reader, **fixture}


def test_non_french_observer_replays_person_and_ruler_binding(pinned_profile):
    report, context, creation, _ = _bundle('ENG', profile=pinned_profile, observer='TUR')
    assert capture.validate_capture(report, context, creation, 'ENG')
    target = report['observation']['backend']['targets'][0]
    assert target['tag'] == 'ENG' and target['fields']['S04.ruler']['status'] == 'known'
    assert not capture.validate_capture(report, dict(context, observer='FRA'), creation, 'ENG')


def _profile_int(value: Any) -> int:
    return value if type(value) is int else int(value, 0)


@pytest.fixture(scope="module")
def pinned_profile():
    return capture._load_profile()


@pytest.fixture(scope="module")
def positive_capture(pinned_profile):
    return _bundle(profile=pinned_profile)


def _valid(report: dict[str, Any], context: dict[str, Any], creation: int,
           country: str | None = None) -> bool:
    return capture.validate_capture(
        report,
        context,
        creation,
        country if country is not None else report["request"]["country"],
    )


class _MutatingReader(parent_fixture.RecordingReader):
    """Alter selected read results without changing the backing memory image."""

    def __init__(self, source: Any, *, label: str, occurrence: int,
                 mutate: Callable[[bytes], bytes], address: int | None = None):
        super().__init__(source)
        self.label = label
        self.occurrence = occurrence
        self.mutate = mutate
        self.address = address
        self.count = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = self.source.read(address, size, label)
        if label == self.label and (self.address is None or address == self.address):
            self.count += 1
            if self.count == self.occurrence:
                raw = self.mutate(raw)
        self.read_log.append({
            "address": hex(address), "size": size, "label": label,
            "status": "observed", "raw_hex": raw.hex(),
        })
        self.bytes_requested += size
        self.calls += 1
        return raw


class _ErrorRecordingReader(parent_fixture.RecordingReader):
    """Record one real-shaped read error for ordered-trace replay."""

    def __init__(self, source: Any, fail_label: str):
        super().__init__(source)
        self.fail_label = fail_label

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == self.fail_label:
            self.read_log.append({
                "address": hex(address),
                "size": size,
                "label": label,
                "status": "error",
                "error": "synthetic read failure",
            })
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
    document = {
        "pid": 777,
        "creation_filetime": CREATION,
        "session_id": SESSION_ID,
        "game_sha256": capture._owner.EXE_SHA256,
    }
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(profile))
    monkeypatch.setattr(
        capture._owner._identity,
        "_load_installation",
        lambda _path: dict(document),
    )
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
    expected = {
        int(item["rva"], 0): bytes.fromhex(item["bytes"])
        for item in profile["code_guards"]
    }
    monkeypatch.setattr(
        capture._owner._mm,
        "_read_pe_rva_bytes",
        lambda _path, rva, size: expected[rva][:size],
    )
    readers = []

    def fake_rpm(_kernel, _handle, _base):
        reader = _ErrorRecordingReader(image, fail_label)
        readers.append(reader)
        return reader

    monkeypatch.setattr(capture._owner._parent, "AddressBoundedRPM", fake_rpm)
    report = capture.capture(Path("synthetic-installation.json"), "ENG")
    return report, kernel, readers


def test_replay_binds_foreign_eng_slot_300_and_all_four_partial_fields(
        positive_capture, pinned_profile):
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
    target = backend["targets"][0]
    assert target["tag"] == "ENG"
    assert target["bindings_by_pass"]["pass2"]["slot"] == 300
    assert target["fullref"] == hex(fixture["target_fullref"])
    assert target["admission_by_pass"]["pass2"]["observer_nonplayer_role"]["verified"] is True
    assert target["admission_by_pass"]["pass1"]["person_name_runtime"]["status"] == "known"
    assert target["admission_by_pass"]["pass1"]["person_name_runtime"]["layout"] == "vanilla"
    assert target["admission_by_pass"]["pass2"]["person_name_runtime"]["status"] == "known"
    assert target["admission_by_pass"]["pass2"]["person_name_runtime"]["layout"] == "vanilla"

    fields = target["fields"]
    assert fields["S04.ruler"]["status"] == "known"
    assert fields["S04.ruler"]["value"]["display_mode"] == "person"
    assert fields["S04.ruler"]["value"]["name"]["status"] == "known"
    assert fields["S04.ruler"]["value"]["name"]["value"]["text"] == "Edward"
    assert fields["S04.ruler"]["value"]["skills"]["value"] == {
        "administrative": 4, "diplomatic": 3, "military": 5,
    }
    assert fields["S04.ruler"]["value"]["age"]["value"] == 34
    assert fields["S04.ruler"]["value"]["full_ui_label_complete"] is False
    assert fields["S04.heir"]["status"] == "known"
    assert fields["S04.heir"]["value"]["mode"] == "character"
    assert fields["S04.heir"]["value"]["present"] is True
    assert fields["S04.heir"]["value"]["name"]["value"]["text"] == "Arthur Tudor"
    assert fields["S04.heir"]["value"]["age"]["value"] == 17
    assert fields["S04.heir"]["value"]["claim"]["value"] == {
        "raw": 60,
        "scale": 1000,
        "category": "average",
        "weak_threshold_raw": WEAK_CLAIM_THRESHOLD,
        "strong_threshold_raw": STRONG_CLAIM_THRESHOLD,
    }
    assert fields["S04.heir"]["value"]["full_ui_label_complete"] is False
    assert fields["S04.dynasty"]["status"] == "known"
    assert fields["S04.dynasty"]["value"]["ruler"]["value"] == {
        "included_in_name": False, "name": None,
    }
    assert fields["S04.dynasty"]["value"]["heir"]["value"] == {
        "included_in_name": True,
        "name": {"text": "Tudor", "raw_hex": "5475646f72", "encoding": "eu4_escape"},
    }
    assert fields["S04.personal_union"]["status"] == "known"
    assert fields["S04.personal_union"]["value"] == {
        "uses_senior_ruler": False, "senior_country": None,
    }
    assert backend["visibility"]["status"] == "unknown"
    assert backend["public_export_ready"] is False
    assert backend["complete"] is False
    assert all(row["status"] == "observed" for row in report["raw_reads"])


def test_profiled_plugin64_runtime_path_replays_and_projects_marker_name(pinned_profile):
    report, context, creation, fixture = _bundle(
        "ENG", profile=pinned_profile, name_runtime_layout="plugin64")

    assert _valid(report, context, creation, "ENG")
    target = report["observation"]["backend"]["targets"][0]
    for pass_name in ("pass1", "pass2"):
        runtime = target["admission_by_pass"][pass_name]["person_name_runtime"]
        assert runtime["status"] == "known"
        assert runtime["layout"] == "plugin64"
        assert runtime["raw_inputs"]["plugin"]["status"] == "verified_profiled_ranges"
        assert runtime["raw_inputs"]["plugin"]["slots"]["return_matches"] is True
        assert runtime["raw_inputs"]["plugin"]["slots"]["callback_matches"] is True

    fields = target["fields"]
    assert fields["S04.heir"]["value"]["name"]["status"] == "known"
    assert fields["S04.heir"]["value"]["name"]["value"]["text"] == "TudorArthur"
    assert fields["S04.heir"]["value"]["age"]["status"] == "known"
    assert fields["S04.heir"]["value"]["claim"]["status"] == "known"
    assert fields["S04.dynasty"]["value"]["heir"]["value"] == {
        "included_in_name": True,
        "name": {"text": "Tudor", "raw_hex": "5475646f72", "encoding": "eu4_escape"},
    }
    assert fixture["physical_fullref"] == fixture["refs"]["POR"]
    assert target["fields"]["S04.ruler"]["value"]["skills"]["status"] == "known"
    assert target["fields"]["S04.ruler"]["value"]["age"]["status"] == "known"


@pytest.mark.parametrize("tamper", ["return", "callback", "guard"])
def test_unverified_plugin_runtime_withdraws_names_only_and_replays_unknown(
        pinned_profile, tamper):
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, name_runtime_layout="plugin64",
        name_runtime_tamper=tamper)

    assert _valid(report, context, creation, "ENG")
    target = report["observation"]["backend"]["targets"][0]
    for pass_name in ("pass1", "pass2"):
        runtime = target["admission_by_pass"][pass_name]["person_name_runtime"]
        assert runtime["status"] == "unknown"
        assert runtime["reason"].startswith("person.name_runtime.")
        plugin = runtime["raw_inputs"]["plugin"]
        if tamper == "return":
            assert plugin["slots"]["return_matches"] is False
            assert plugin["slots"]["callback_matches"] is True
        elif tamper == "callback":
            assert plugin["slots"]["return_matches"] is True
            assert plugin["slots"]["callback_matches"] is False
        else:
            assert plugin["header"]["matches"] is False or any(
                guard["matches_bytes"] is False for guard in plugin["code_guards"])

    fields = target["fields"]
    ruler = fields["S04.ruler"]["value"]
    heir = fields["S04.heir"]["value"]
    assert ruler["name"]["status"] == "unknown"
    assert "value" not in ruler["name"]
    assert ruler["skills"]["status"] == "known"
    assert ruler["age"]["status"] == "known"
    assert heir["name"]["status"] == "unknown"
    assert "value" not in heir["name"]
    assert heir["age"]["status"] == "known"
    assert heir["claim"]["status"] == "known"
    assert fields["S04.dynasty"]["value"]["ruler"]["status"] == "unknown"
    assert fields["S04.dynasty"]["value"]["heir"]["status"] == "unknown"
    assert "value" not in fields["S04.dynasty"]["value"]["heir"]


def test_self_target_fra_deduplicates_binding_and_keeps_physical_por(pinned_profile):
    report, context, creation, fixture = _bundle("FRA", profile=pinned_profile)

    assert _valid(report, context, creation, "FRA")
    observation = report["observation"]
    target = observation["backend"]["targets"][0]
    assert target["tag"] == "FRA"
    assert target["bindings_by_pass"]["pass1"]["slot"] == 122
    assert target["fullref"] == observation["backend"]["observer"]["fullref"]
    assert observation["context_before"]["physical_client_reference_raw_hex"] == (
        fixture["physical_fullref"].to_bytes(8, "little").hex())
    assert sum(row["label"] == "country_reference.slot[122].pointer"
               for row in report["raw_reads"]) == 2


def test_hidden_heir_panel_does_not_read_any_heir_person_data(pinned_profile):
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, hidden_heir=True)

    assert report["observation"]["stable"] is True
    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    heir = target["fields"]["S04.heir"]
    assert heir["status"] == "known"
    assert heir["value"]["mode"] == "hidden"
    assert heir["value"]["present"] is None
    assert heir["value"]["name"]["status"] == "not_applicable"
    assert heir["value"]["name"]["reason"] == "NATIVE_HEIR_CHARACTER_PANEL_HIDDEN"
    assert not any(row["label"].startswith("person.heir.")
                   for row in report["raw_reads"])
    assert target["fields"]["S04.dynasty"]["value"]["heir"]["status"] == "not_applicable"


def test_no_heir_constant_false_presence_method_returns_no_heir_not_hidden(pinned_profile):
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, no_heir=True)

    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    heir = target["fields"]["S04.heir"]
    assert heir["status"] == "known"
    assert heir["value"]["mode"] == "no_heir"
    assert heir["value"]["present"] is False
    assert "person.heir.presence_method" in {
        row["label"] for row in report["raw_reads"]}
    assert "person.heir.owner_reference" not in {
        row["label"] for row in report["raw_reads"]}
    assert all(heir["value"][name]["status"] == "not_applicable"
               for name in ("name", "age", "claim"))


def test_regency_or_bad_name_keeps_independent_age_skills_claim_and_dynasty(pinned_profile):
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, ruler_regency=0x68E0000000,
        heir_regency=0x68E0000010)

    assert _valid(report, context, creation)
    fields = report["observation"]["backend"]["targets"][0]["fields"]
    ruler = fields["S04.ruler"]["value"]
    heir = fields["S04.heir"]["value"]
    assert ruler["name"]["status"] == "unknown"
    assert ruler["skills"]["status"] == "known"
    assert ruler["age"]["status"] == "known"
    assert fields["S04.dynasty"]["value"]["ruler"]["status"] == "unknown"
    assert heir["mode"] == "character"
    assert heir["name"]["status"] == "unknown"
    assert heir["age"]["status"] == "known"
    assert heir["claim"]["status"] == "known"


def test_claim_change_withdraws_heir_only_and_replays_ordered_trace(pinned_profile):
    image, fixture = _make_image("ENG", pinned_profile)

    def change_claim(raw: bytes) -> bytes:
        return _i32(70)

    mutator = lambda source: _MutatingReader(
        source,
        label="person.claim_raw",
        occurrence=2,
        mutate=change_claim,
    )
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, reader=mutator)

    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    assert target["field_consistency"]["S04.heir"]["status"] == "changed"
    assert target["fields"]["S04.heir"]["status"] == "unknown"
    assert target["fields"]["S04.heir"]["reason"] == "field_raw_data_changed"
    assert target["fields"]["S04.ruler"]["status"] == "known"
    assert target["fields"]["S04.dynasty"]["status"] == "known"
    assert target["fields"]["S04.personal_union"]["status"] == "known"
    assert fixture["heir"]["person"] != fixture["ruler"]["person"]


def test_ruler_name_change_withdraws_ruler_but_not_independent_dynasty(pinned_profile):
    image, fixture = _make_image("ENG", pinned_profile)

    def change_first_letter(raw: bytes) -> bytes:
        changed = bytearray(raw)
        changed[names.PERSON_BASE_NAME_OFFSET] = ord("F")
        return bytes(changed)

    reader = lambda source: _MutatingReader(
        source,
        label="person.header",
        occurrence=2,
        mutate=change_first_letter,
        address=fixture["ruler"]["person"],
    )
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, reader=reader)

    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    assert target["field_consistency"]["S04.ruler"]["status"] == "changed"
    assert target["fields"]["S04.ruler"]["status"] == "unknown"
    assert target["fields"]["S04.dynasty"]["status"] == "known"
    assert target["fields"]["S04.dynasty"]["value"]["ruler"]["status"] == "known"
    assert target["fields"]["S04.heir"]["status"] == "known"
    assert target["fields"]["S04.personal_union"]["status"] == "known"


@pytest.mark.parametrize("tamper", [
    "profile", "raw_type", "access_calls", "date", "session", "role", "target",
])
def test_capture_replay_rejects_profile_trace_metadata_and_identity_tampering(
        positive_capture, tamper):
    report, context, creation, _fixture = positive_capture
    report = deepcopy(report)
    context = deepcopy(context)
    if tamper == "profile":
        report["profile_sha256"] = "0" * 64
    elif tamper == "raw_type":
        report["raw_reads"][0]["size"] = str(report["raw_reads"][0]["size"])
    elif tamper == "access_calls":
        report["access"]["calls"] = float(report["access"]["calls"])
    elif tamper == "date":
        context["game_date"] += 1
    elif tamper == "session":
        context["session_id"] = "different-session"
    elif tamper == "role":
        report["observation"]["backend"]["targets"][0]["admission_by_pass"][
            "pass1"]["observer_nonplayer_role"]["verified"] = False
    else:
        assert not _valid(report, context, creation, "POR")
        return
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
    document = {
        "pid": 777,
        "creation_filetime": CREATION,
        "session_id": SESSION_ID,
        "game_sha256": capture._owner.EXE_SHA256,
    }
    monkeypatch.setattr(capture, "_load_profile", lambda: deepcopy(pinned_profile))
    monkeypatch.setattr(
        capture._owner._identity, "_load_installation", lambda _path: dict(document))
    monkeypatch.setattr(
        capture._owner._identity, "_configure_kernel", lambda: kernel)

    def fake_identity(target_report, _document, _kernel, _handle):
        target_report["identity"].update({
            "binding_verified": True,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": capture._owner.EXE_SHA256,
        })
        return MODULE_BASE

    monkeypatch.setattr(
        capture._owner._identity, "_capture_identity", fake_identity)
    expected = {
        int(item["rva"], 0): bytes.fromhex(item["bytes"])
        for item in pinned_profile["code_guards"]
    }
    monkeypatch.setattr(
        capture._owner._mm,
        "_read_pe_rva_bytes",
        lambda _path, rva, size: expected[rva][:size],
    )
    monkeypatch.setattr(
        capture._owner._parent,
        "AddressBoundedRPM",
        lambda _kernel, _handle, _base: parent_fixture.RecordingReader(image),
    )

    report = capture.capture(Path("synthetic-installation.json"), "ENG")
    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["observation"]["stable"] is True
    assert report["cleanup"]["status"] != "closed"
    assert report["completed"] is False and report["status"] == "unknown"
    context = {
        "observer": "FRA",
        "session_id": SESSION_ID,
        "game_version": "1.37.4",
        "game_sha256": capture._owner.EXE_SHA256,
        "game_date": GAME_DATE,
    }
    assert not capture.validate_capture(report, context, CREATION, "ENG")


def test_component_read_error_replays_without_erasing_other_known_fields(
        monkeypatch, pinned_profile):
    image, fixture = _make_image("ENG", pinned_profile)
    fail_label = "person.claim_raw"
    report, kernel, readers = _capture_with_fake_process(
        monkeypatch, pinned_profile, image, fail_label=fail_label)
    context = {
        "observer": "FRA",
        "session_id": SESSION_ID,
        "game_version": "1.37.4",
        "game_sha256": capture._owner.EXE_SHA256,
        "game_date": GAME_DATE,
    }

    assert kernel.open_calls == 1 and kernel.close_calls == 1
    assert report["status"] == "observed" and report["completed"] is True
    assert report["observation"]["stable"] is True
    target = report["observation"]["backend"]["targets"][0]
    assert target["fields"]["S04.heir"]["status"] == "known"
    assert target["fields"]["S04.heir"]["value"]["claim"]["status"] == "unknown"
    assert target["fields"]["S04.heir"]["value"]["name"]["status"] == "known"
    assert target["fields"]["S04.heir"]["value"]["age"]["status"] == "known"
    assert target["fields"]["S04.ruler"]["status"] == "known"
    assert target["fields"]["S04.dynasty"]["status"] == "known"
    assert target["fields"]["S04.personal_union"]["status"] == "known"
    failed_rows = [row for row in report["raw_reads"] if row.get("status") == "error"]
    assert len(failed_rows) == 2
    assert all(row["label"] == fail_label for row in failed_rows)
    assert _valid(report, context, CREATION)

    changed_reason = deepcopy(report)
    changed_reason["raw_reads"][next(
        index for index, row in enumerate(changed_reason["raw_reads"])
        if row.get("status") == "error"
    )]["error"] = "different failure reason"
    assert not _valid(changed_reason, context, CREATION)
    assert readers and fixture["heir"]["person"] > 0


def test_denied_country_view_does_not_read_any_person_fields(pinned_profile):
    report, context, creation, _fixture = _bundle(
        "ENG", profile=pinned_profile, admitted=False)

    assert report["observation"]["stable"] is True
    assert _valid(report, context, creation)
    target = report["observation"]["backend"]["targets"][0]
    assert all(target["fields"][field]["status"] == "invisible"
               for field in person_fields.FIELDS)
    assert not any(row["label"].startswith("person.") for row in report["raw_reads"])

