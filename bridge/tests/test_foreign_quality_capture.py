"""Offline integration checks for identity-bound foreign quality capture."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from bridge.information import foreign_quality_capture as capture
from bridge.information import foreign_quality_memory as quality
from bridge.information import foreign_quality_visibility_memory as quality_visibility
from bridge.information import country_ledger_membership_memory as ledger_membership
from bridge.information import foreign_technology_capture as owner
from bridge.tests import test_information_foreign_technology_capture as tech_fixture
from bridge.tests import test_information_foreign_technology_memory as memory_fixture


MODULE_BASE = tech_fixture.MODULE_BASE
CREATION = 123456789012345678
SESSION_ID = "foreign-quality-capture-session"
GAME_DATE = tech_fixture.GAME_DATE
WORLD = tech_fixture.WORLD
SETTINGS = 0x6A10000000
CAPITAL = 0x6A20000000
BITSET = 0x6A30000000
COUNTRY_CANDIDATES = 0x6A40000000
GUARD_RVA = 0x2200
GUARD_BYTES = b"\xCC\x90\xC3"


class TraceReader:
    """Fake RPM reader that records the owner replay format in call order."""

    def __init__(self, image: Any) -> None:
        self.image = image
        self.read_log: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls += 1
        self.bytes_requested += size
        try:
            raw = self.image.read(address, size, label)
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


@pytest.fixture
def fixture_profile(monkeypatch):
    """Use a test-only ROM guard; never depend on the pending production pin."""
    model_profile: dict[str, Any] = {"fixture_model_contract": "no-model-getter"}
    profile = {
        "profile_id": capture.PROFILE_ID,
        "game_version": "1.37.4",
        "executable": {"sha256": capture.EXE_SHA256},
        "code_guards": [{
            "name": "capture_test_guard",
            "rva": hex(GUARD_RVA),
            "end_rva_exclusive": hex(GUARD_RVA + len(GUARD_BYTES)),
            "bytes": GUARD_BYTES.hex(),
            "sha256": hashlib.sha256(GUARD_BYTES).hexdigest(),
        }],
        "model_profile": model_profile,
    }
    monkeypatch.setattr(capture, "_load_profile", lambda: profile)
    # Keep unrelated components unknown without causing reads through the
    # separate discipline/model helpers. The direct quality cache remains real.
    monkeypatch.setattr(quality, "_read_discipline",
                        lambda *_args, **_kwargs: {"status": "unknown",
                                                   "reason": "FIXTURE_DISCIPLINE_PENDING"})
    monkeypatch.setattr(quality, "_read_models",
                        lambda *_args, **_kwargs: {
                            name: {"status": "unknown", "reason": "FIXTURE_MODEL_PENDING"}
                            for name in quality.MODEL_COMPONENTS
                        })
    return profile


def _make_image(profile: dict[str, Any], *, country_view_admitted: bool = True,
                quality_allowed: bool = True, human_fra: bool = False,
                target_in_ledger: bool = True):
    image, bindings, _values = memory_fixture.make_reader({
        "FRA": (122, 0x1200, 5),
        "POR": (189, 0x5500, 3),
        "ENG": (300, 0x4500, 9),
    }, count=310)
    refs = tech_fixture._write_capture_context(
        image, country="ENG", admitted=country_view_admitted,
        physical_tag="POR", human_fra=human_fra)

    target = refs["target_pointer"]
    observer = bindings["FRA"]["country_pointer"]
    candidate_pointers = [observer]
    if target_in_ledger:
        candidate_pointers.append(target)
    image.put_u64(WORLD + ledger_membership.WORLD_COUNTRY_POINTERS_OFFSET,
                  COUNTRY_CANDIDATES)
    image.put_i32(WORLD + ledger_membership.WORLD_COUNTRY_COUNT_OFFSET,
                  len(candidate_pointers))
    image.put(COUNTRY_CANDIDATES,
              b"".join(pointer.to_bytes(8, "little") for pointer in candidate_pointers))

    # The quality-ledger permission is deliberately independent from the
    # generic country-view admission established above.
    image.put_u64(WORLD + quality_visibility.WORLD_OPTIONS_POINTER_OFFSET, SETTINGS)
    image.put_i32(SETTINGS + quality_visibility.OPTIONS_QUALITY_INDEX * 4,
                  0 if quality_allowed else 1)
    image.put(MODULE_BASE + quality_visibility.WORLD_PAGE_ENABLE_RVA, b"\x01")
    image.put(MODULE_BASE + quality_visibility.WORLD_PAGE_TLS_RVA, b"\x00")
    for index, (_name, rva) in enumerate(quality_visibility.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(MODULE_BASE + rva, -20 - index)

    if country_view_admitted:
        image.put_u64(target + quality_visibility.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(CAPITAL + quality_visibility.CAPITAL_QUALITY_FLAGS_OFFSET, b"\x00")
        image.put_u64(CAPITAL + quality_visibility.CAPITAL_OBSERVER_BITSET_OFFSET, BITSET)
        observer_slot = bindings["FRA"]["slot"]
        word_address = BITSET + (observer_slot >> 5) * quality_visibility.OBSERVER_BITSET_WORD_STRIDE
        image.put(word_address, (1 << (observer_slot & 31)).to_bytes(4, "little"))

    # Calculating cache state keeps modifier values unknown while preserving
    # independent direct cache components for the aggregate partial field.
    image.put_i32(target + quality.COUNTRY_CACHE_STATE_OFFSET, 1)
    image.put_i32(target + 0x9874, 1125)
    image.put_i32(target + 0x987C, 875)
    image.put(target + 0x50, (32768 * 3).to_bytes(8, "little", signed=True))
    image.put_i32(target + 0x0E40, 24500)
    image.put_i32(target + 0x0E44, 18600)

    image.put(MODULE_BASE + GUARD_RVA, GUARD_BYTES)
    return image, bindings, refs


def _make_capture(profile: dict[str, Any], *, country_view_admitted: bool = True,
                  quality_allowed: bool = True, human_fra: bool = False,
                  target_in_ledger: bool = True,
                  image: Any | None = None, bindings: dict[str, Any] | None = None,
                  refs: dict[str, Any] | None = None):
    if image is None:
        image, bindings, refs = _make_image(
            profile, country_view_admitted=country_view_admitted,
            quality_allowed=quality_allowed, human_fra=human_fra,
            target_in_ledger=target_in_ledger)
    assert bindings is not None and refs is not None
    source = TraceReader(image)
    wrapped = owner._FailureReplayReader(source)
    observation_error = None
    try:
        observation = capture._observe(wrapped, MODULE_BASE, "ENG", profile)
    except Exception as exc:
        observation = None
        observation_error = f"{type(exc).__name__}:{exc}"
    completed = observation_error is None and observation.get("stable") is True
    identity = {
        "binding_verified": True,
        "process_creation_filetime": CREATION,
        "process_path": "synthetic-eu4.exe",
        "process_path_sha256": capture.EXE_SHA256,
    }
    report = {
        "schema": capture.SCHEMA,
        "status": "observed" if completed else "unknown",
        "completed": completed,
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
    return report, context, CREATION, {
        "image": image, "source": source, "bindings": bindings, **refs,
    }


def _target(report: dict[str, Any]) -> dict[str, Any]:
    return report["observation"]["backend"]["targets"][0]


def test_two_pass_quality_capture_binds_full_scan_role_and_profile_object(
        fixture_profile, monkeypatch):
    profile = fixture_profile
    passed_profiles: list[Any] = []
    original = quality.read_fields

    def record_profile(*args, **kwargs):
        passed_profiles.append(kwargs.get("model_profile"))
        return original(*args, **kwargs)

    monkeypatch.setattr(capture._quality, "read_fields", record_profile)
    report, context, creation, fixture = _make_capture(profile)

    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    backend = report["observation"]["backend"]
    assert backend["status"] == "observed"
    assert backend["consistency"] == {"status": "stable", "shared_mismatch_paths": []}
    target = _target(report)
    assert target["binding_status"] == "observed"
    assert target["fullref"] == hex(fixture["target_fullref"])
    assert target["fields"][capture.QUALITY_FIELD]["status"] == "known"
    assert target["fields"][capture.QUALITY_FIELD]["complete"] is False
    assert target["fields"][capture.QUALITY_FIELD]["partial"] is True
    assert target["fields"][capture.VISIBILITY_FIELD]["value"]["admitted"] is True
    assert target["fields"][capture.VISIBILITY_FIELD]["value"]["mode"] == (
        "projected_quality_ledger_gate")
    for phase in ("pass1", "pass2"):
        admission = target["admission_by_pass"][phase]
        assert admission["observer_nonplayer_role"]["verified"] is True
        scan = backend["pass_evidence"][phase]["country_scan"]
        assert scan["status"] == "observed"
        assert scan["requested"]["FRA"]["fullref"] == hex(fixture["observer_fullref"])
        assert scan["requested"]["ENG"]["fullref"] == hex(fixture["target_fullref"])
    assert fixture["physical_fullref"] != fixture["observer_fullref"]
    assert passed_profiles and all(item is profile["model_profile"] for item in passed_profiles)
    assert report["access"]["calls"] == len(report["raw_reads"])
    assert report["access"]["bytes_requested"] == sum(row["size"] for row in report["raw_reads"])


def test_quality_permission_denial_is_separate_and_skips_quality_cache_reads(fixture_profile):
    report, context, creation, fixture = _make_capture(
        fixture_profile, country_view_admitted=True, quality_allowed=False)
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    permission = target["fields"][capture.VISIBILITY_FIELD]
    assert permission["status"] == "known"
    assert permission["value"]["admitted"] is False
    assert target["fields"][capture.QUALITY_FIELD]["status"] == "unknown"
    assert "value" not in target["fields"][capture.QUALITY_FIELD]
    assert target["admission_by_pass"]["pass1"]["admitted"] is True
    assert not any(row["label"].startswith("quality.army.")
                   or row["label"].startswith("quality.navy.")
                   for row in fixture["source"].read_log)


def test_target_absent_from_world_ledger_candidates_is_denied_without_quality_reads(fixture_profile):
    report, context, creation, fixture = _make_capture(
        fixture_profile, country_view_admitted=True, target_in_ledger=False)
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    permission_field = target["fields"][capture.VISIBILITY_FIELD]
    permission = permission_field["raw_inputs"]["permission"]
    assert permission["status"] == "known"
    assert permission["admitted"] is False
    assert permission["reason"] == "TARGET_NOT_LEDGER_CANDIDATE"
    assert permission["raw_inputs"]["ledger_membership"]["member"] is False
    assert target["fields"][capture.QUALITY_FIELD]["status"] == "unknown"
    assert not any(row["label"].startswith(("quality.", "options.quality_option",
                                              "target.capital."))
                   for row in fixture["source"].read_log)


def test_country_view_denial_skips_quality_permission_and_all_quality_resources(fixture_profile):
    report, context, creation, fixture = _make_capture(
        fixture_profile, country_view_admitted=False, quality_allowed=True)
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    for field in capture.FIELDS:
        assert target["fields"][field]["status"] == "invisible"
        assert target["field_consistency"][field]["status"] == "invisible"
    for phase in ("pass1", "pass2"):
        assert target["admission_by_pass"][phase]["status"] == "known"
        assert target["admission_by_pass"][phase]["admitted"] is False
    assert not any(row["label"].startswith("quality.")
                   for row in fixture["source"].read_log)


def test_fra_human_role_failure_prevents_both_quality_gates_and_values(fixture_profile):
    report, _context, _creation, fixture = _make_capture(fixture_profile, human_fra=True)
    assert report["observation"]["stable"] is False
    target = _target(report)
    assert all(target["admission_by_pass"][phase]["observer_nonplayer_role"]["verified"] is False
               for phase in ("pass1", "pass2"))
    assert not any(row["label"].startswith("quality.")
                   or row["label"].startswith("settings.")
                   for row in fixture["source"].read_log)


def test_one_quality_component_change_withdraws_only_quality_field(fixture_profile):
    image, bindings, refs = _make_image(fixture_profile)
    target_pointer = refs["target_pointer"]

    def alter_morale(memory, _address, _size, label, count):
        if label == "quality.army.morale.cache_i32" and count == 2:
            memory.put_i32(target_pointer + 0x9874, 1300)

    image.on_read = alter_morale
    report, context, creation, fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs)
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    assert target["fields"][capture.QUALITY_FIELD]["status"] == "unknown"
    assert target["field_consistency"][capture.QUALITY_FIELD]["status"] == "changed"
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "known"
    assert target["fields"][capture.VISIBILITY_FIELD]["value"]["admitted"] is True
    assert target["field_consistency"][capture.VISIBILITY_FIELD]["status"] == "stable"
    assert fixture["source"].calls == len(report["raw_reads"])


def test_quality_cache_read_failures_stay_field_local_and_replay(fixture_profile):
    image, bindings, refs = _make_image(fixture_profile)
    target_pointer = refs["target_pointer"]
    bad_addresses = {target_pointer + offset for offset, *_ in quality.DIRECT_COMPONENTS.values()}

    def fail_direct_quality(memory, address, _size, _label, _count):
        if address in bad_addresses:
            raise OSError("synthetic quality cache read failure")

    image.on_read = fail_direct_quality
    report, context, creation, fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs)
    assert report["observation"]["stable"] is True
    assert capture.validate_capture(report, context, creation, "ENG")
    target = _target(report)
    assert target["fields"][capture.QUALITY_FIELD]["status"] == "unknown"
    assert target["fields"][capture.VISIBILITY_FIELD]["status"] == "known"
    assert any(row["status"] == "error" and row["label"].startswith("quality.")
               for row in fixture["source"].read_log)
    assert report["observation"].get("read_failures")


def test_shared_target_fullref_change_withdraws_quality_and_visibility(fixture_profile):
    image, bindings, refs = _make_image(fixture_profile)
    slot = bindings["ENG"]["slot"]
    label = f"country_reference.slot[{slot}].fullref"
    changed_ref = refs["target_fullref"] ^ (1 << 48)

    def change_generation(memory, _address, _size, current_label, count):
        if current_label == label and count == 2:
            memory.put_u64(refs["target_pointer"] + 0x20, changed_ref)
            recipient = (refs["relation_row"]
                         + tech_fixture.admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET)
            memory.put_u64(recipient, changed_ref)

    image.on_read = change_generation
    report, _context, _creation, _fixture = _make_capture(
        fixture_profile, image=image, bindings=bindings, refs=refs)
    backend = report["observation"]["backend"]
    assert backend["consistency"]["status"] == "changed"
    assert "country_scan" in backend["consistency"]["shared_mismatch_paths"]
    target = _target(report)
    for field in capture.FIELDS:
        assert target["fields"][field]["status"] == "unknown"
        assert target["fields"][field]["reason"] == "shared_evidence_changed"
    assert report["observation"]["stable"] is False


@pytest.mark.parametrize("tamper", [
    "quality_value", "quality_permission_raw", "trace_order", "target_ref",
    "membership_index", "profile_pin", "session", "creation", "date", "cleanup",
])
def test_capture_validator_rejects_raw_projection_order_and_identity_tampering(
        fixture_profile, tamper):
    report, context, creation, _fixture = _make_capture(fixture_profile)
    report, context = deepcopy(report), deepcopy(context)
    target = _target(report)
    if tamper == "quality_value":
        quality_field = target["fields"][capture.QUALITY_FIELD]
        quality_field["value"]["army"]["morale"]["value"] += 1
    elif tamper == "quality_permission_raw":
        row = next(row for row in report["raw_reads"]
                   if row["label"] == "options.quality_option_17_u32")
        row["raw_hex"] = "01000000"
    elif tamper == "membership_index":
        permission = target["fields"][capture.VISIBILITY_FIELD]["raw_inputs"]["permission"]
        permission["raw_inputs"]["ledger_membership"]["matching_indices"] = [0]
    elif tamper == "trace_order":
        report["raw_reads"][0], report["raw_reads"][1] = report["raw_reads"][1], report["raw_reads"][0]
    elif tamper == "target_ref":
        target["fullref"] = hex(int(target["fullref"], 0) ^ (1 << 48))
    elif tamper == "profile_pin":
        report["profile_sha256"] = "0" * 64
    elif tamper == "session":
        context["session_id"] = "stale-session"
    elif tamper == "creation":
        creation += 1
    elif tamper == "date":
        context["game_date"] += 1
    elif tamper == "cleanup":
        report["cleanup"]["success"] = False
    assert not capture.validate_capture(report, context, creation, "ENG")


def test_saved_json_roundtrip_preserves_ordered_replay(fixture_profile):
    report, context, creation, _fixture = _make_capture(fixture_profile)
    saved_report = json.loads(json.dumps(report, ensure_ascii=False))
    saved_context = json.loads(json.dumps(context, ensure_ascii=False))
    assert capture.validate_capture(saved_report, saved_context, creation, "ENG")
