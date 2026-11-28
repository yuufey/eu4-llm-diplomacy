"""Literal fake-memory tests for the private target-principal adapter."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import target_debt_principal_memory_v34 as memory


BASE = 0x140000000
DATABASE = 0x60000000
TABLE = 0x61000000
WORLD = 0x62000000
CONTROLLERS = 0x63000000
OTHER_WORLD = 0x62010000
OTHER_CONTROLLERS = 0x63010000
OBSERVER_SLOT = 19
TARGET_SLOT = 41
OBSERVER_POINTER = 0x50000000
TARGET_POINTER = 0x50001000
TARGET_TABLE_COUNT = 42
DATE_RAW = 56_556_984
HOOK_DLL_BASE = 0x7FFA07C70000
HOOK_POINTER = HOOK_DLL_BASE + 0x59690
HOOK_ASSET_PATH = (Path(__file__).resolve().parents[1]
                   / "information/profiles/native-ai-choice-hook-v34.json")
HOOK_ASSET_SHA256 = "0c7431ff6aa035804950c142c38b905e91b5b6d672737aa8fc20c4c3a40c6413"


def _fullref(tag: str, slot: int, generation: int) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    """Sparse bytes, ordered read log, and nth-read drift injections."""

    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.counts: dict[str, int] = {}
        self.changed_reads: dict[tuple[str, int], bytes] = {}
        self.short_reads: set[tuple[str, int]] = set()
        self.error_reads: set[tuple[str, int]] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: value for offset, value in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        ordinal = self.counts.get(label, 0) + 1
        self.counts[label] = ordinal
        if (label, ordinal) in self.error_reads:
            raise OSError("synthetic read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc
        raw = self.changed_reads.get((label, ordinal), raw)
        if (label, ordinal) in self.short_reads:
            return raw[:-1]
        return raw


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict[str, object]:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + 0x20),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _install_hook_mapping(image: MemoryImage) -> None:
    raw_asset = HOOK_ASSET_PATH.read_bytes()
    assert hashlib.sha256(raw_asset).hexdigest() == HOOK_ASSET_SHA256
    asset = json.loads(raw_asset.decode("utf-8"))
    image.put(HOOK_DLL_BASE, bytes.fromhex(asset["dos_prefix_hex"]))
    image.put(HOOK_DLL_BASE + 0x80, bytes.fromhex(asset["coff_prefix_hex"]))
    image.put(HOOK_DLL_BASE + 0x98, bytes.fromhex(asset["optional_header_magic_hex"]))
    image.put_u32(HOOK_DLL_BASE + 0xD0, 0xD52000)
    image.put(HOOK_DLL_BASE + 0x59690, bytes.fromhex(asset["body_hex"]))
    image.put_u64(HOOK_DLL_BASE + 0xD3D560, BASE)
    image.put_u64(HOOK_DLL_BASE + 0x7350B8, BASE + 0x8F440)
    image.put(BASE + 0x8F440, b"\xB0\x01\xC3")
    image.put_u64(BASE + 0x1C80A50, HOOK_POINTER)


def _environment(*, observer_tag: str = "FRA", target_tag: str = "ENG",
                 human_count: int = 1, observer_controller: int = 0,
                 target_controller: int = 0, date: int = DATE_RAW,
                 choice_mapping: str = "stock",
                 ) -> tuple[MemoryImage, dict, dict]:
    image = MemoryImage()
    observer = _binding(observer_tag, OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    target = _binding(target_tag, TARGET_SLOT, TARGET_POINTER, 0x2345)
    observer_ref = int(str(observer["fullref"]), 0)
    target_ref = int(str(target["fullref"]), 0)

    # Literal B23 country-database layout used by _common._binding_evidence.
    image.put_u64(BASE + 0x233D8B0, DATABASE)
    image.put_u64(DATABASE + 0x118, TABLE)
    image.put_i32(DATABASE + 0x124, TARGET_TABLE_COUNT)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, OBSERVER_POINTER)
    image.put_u64(TABLE + TARGET_SLOT * 8, TARGET_POINTER)
    image.put_u64(OBSERVER_POINTER + 0x20, observer_ref)
    image.put_u64(TARGET_POINTER + 0x20, target_ref)

    # Literal current-B23 mapping cells: action getter and principal reason.
    image.put_u64(BASE + 0x1C80A18, BASE + 0x004F5960)
    image.put_u64(BASE + 0x1C80AA0, BASE + 0x004F5E90)
    if choice_mapping == "hook":
        _install_hook_mapping(image)
    else:
        image.put(BASE + 0x8F440, b"\xB0\x01\xC3")
        image.put_u64(BASE + 0x1C80A50, BASE + 0x0008F440)
    # Literal 12-entry u32 exclusion table, independent of adapter constants.
    image.put(BASE + 0x1C35460, bytes.fromhex(
        "28300000292a0000cc3b0000e02d0000da2d00003c29000007330000b9330000"
        "75330000cb3b0000cd3b000066380000"))

    # Literal world offsets: date +1dd0, human count +a60, controller vector +1d48.
    image.put_u64(BASE + 0x233FE58, WORLD)
    image.put_i32(WORLD + 0x1DD0, date)
    image.put_i32(WORLD + 0x0A60, human_count)
    image.put_u64(WORLD + 0x1D48, CONTROLLERS)
    image.put_i32(CONTROLLERS + OBSERVER_SLOT * 4, observer_controller)
    image.put_i32(CONTROLLERS + TARGET_SLOT * 4, target_controller)
    return image, observer, target


def _permission(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_permission(image, BASE, observer, target)


def _field(image: MemoryImage, observer: dict, target: dict,
           permission: dict, fields=memory.FIELD) -> dict:
    return memory.read_fields(image, BASE, observer, target, fields,
                              permission=permission)[memory.FIELD]


def _deny_leaf_if_called(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    calls: list[tuple] = []

    def unexpected(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("principal leaf must not run")

    monkeypatch.setattr(memory._leaf, "read_state", unexpected)
    return calls


def _assert_permission_budget(permission: dict) -> None:
    budget = permission["raw_inputs"]["read_budget"]
    assert budget["max_calls"] == 128
    assert budget["max_bytes"] == 64 * 1024
    assert budget["max_single_read_bytes"] == 1024
    assert budget["calls"] <= budget["max_calls"]
    assert budget["bytes_requested"] <= budget["max_bytes"]
    assert max((row["size"] for row in permission["raw_inputs"]["ordered_read_trace"]), default=0) <= 1024


def test_permission_binds_fra_candidate_to_database_world_date_human_and_controllers():
    image, observer, target = _environment()
    permission = _permission(image, observer, target)

    assert permission["schema"] == "information.target_debt_principal_memory.v3"
    assert permission["basis"] == "private_native_diplomatic_target_principal"
    assert permission["scope"] == "native_negotiated_ai_recipient_principal_candidate"
    assert permission["status"] == "known" and permission["admitted"] is True
    assert permission["publication_admitted"] is False
    assert permission["actual_UI_observed"] is False
    assert permission["observer"]["tag"] == "FRA"
    assert permission["target"]["tag"] == "ENG"
    assert permission["raw_inputs"]["world"]["date_raw_i32"] == DATE_RAW
    assert permission["raw_inputs"]["world"]["human_count_i32"] == 1
    assert permission["raw_inputs"]["world"]["observer_controller_i32"] == 0
    assert permission["raw_inputs"]["world"]["target_controller_i32"] == 0
    assert permission["raw_inputs"]["candidate_gates"]["decision"] == "admitted_candidate"
    assert permission["raw_inputs"]["controlled_countries_evaluated"] is False
    assert permission["raw_inputs"]["scope_evidence"]["does_not_establish"]

    labels = [label for _address, _size, label in image.reads]
    for label in (
            "bindings.database_global", "bindings.country_table", "bindings.country_count",
            "bindings.observer.table_entry", "bindings.observer.fullref",
            "bindings.target.table_entry", "bindings.target.fullref"):
        assert labels.count(label) == 2
    for label in (
            "native_map.action_getter_before", "native_map.principal_reason_before",
            "native_map.validity_helper_before", "native_map.action_getter_after",
            "native_map.principal_reason_after", "native_map.validity_helper_after",
            "choice_mapping.native_true_body_before",
            "choice_mapping.native_true_body_after",
            "native_exclusions.table_before", "native_exclusions.table_after",
            "world.global_pointer", "world.date_i32", "world.human_count_i32",
            "world.controllers_pointer", "world.observer_controller_i32",
            "world.target_controller_i32", "world.fresh_global_pointer",
            "world.fresh_date_i32", "world.fresh_human_count_i32",
            "world.fresh_controllers_pointer", "world.fresh_observer_controller_i32",
            "world.fresh_target_controller_i32"):
        assert labels.count(label) == 1
    assert permission["raw_inputs"]["country_database_binding_before"] == (
        permission["raw_inputs"]["country_database_binding_after"]
    )
    exclusion = permission["raw_inputs"]["current_action_exclusion_table"]
    assert exclusion["before"]["size"] == 48
    assert len(exclusion["before"]["tokens_u32"]) == 12
    assert exclusion["before"]["current_action_token"] == 15310
    assert exclusion["before"]["current_action_token_excluded"] is False
    assert exclusion["before"] == exclusion["after"]
    mapping = permission["raw_inputs"]["current_algorithm_mapping"]
    assert mapping["before"]["validity_helper_pointer"] == hex(BASE + 0x8F440)
    proof = mapping["before"]["validity_helper_proof"]
    assert proof["mode"] == "native_true"
    assert proof["predicate_body_hex"] == "b001c3"
    assert proof == mapping["after"]["validity_helper_proof"]
    _assert_permission_budget(permission)


def test_permission_accepts_only_the_pinned_gui_forwarding_hook_mapping():
    image, observer, target = _environment(choice_mapping="hook")

    permission = _permission(image, observer, target)

    assert permission["status"] == "known" and permission["admitted"] is True
    mapping = permission["raw_inputs"]["current_algorithm_mapping"]
    before = mapping["before"]["validity_helper_proof"]
    after = mapping["after"]["validity_helper_proof"]
    assert mapping["before"]["validity_helper_pointer"] == hex(HOOK_POINTER)
    assert before["mode"] == "installed_observer_gui_forwarding_v34"
    assert before["module_base"] == hex(HOOK_DLL_BASE)
    assert before["body_matches_pinned_asset"] is True
    assert before["whole_loaded_dll_hash_verified"] is False
    assert before == after
    assert memory.validate_permission(permission) is True
    _assert_permission_budget(permission)


def test_hook_body_drift_between_permission_passes_returns_unknown():
    image, observer, target = _environment(choice_mapping="hook")
    changed = bytearray(bytes.fromhex(
        json.loads(HOOK_ASSET_PATH.read_text(encoding="utf-8"))["body_hex"]))
    changed[7] ^= 0x01
    image.changed_reads[("choice_mapping.hook_body_0_after", 1)] = bytes(changed[:1024])

    permission = _permission(image, observer, target)

    assert permission["status"] == "unknown"
    assert permission["admitted"] is None
    assert permission["publication_admitted"] is False
    assert memory.validate_permission(permission) is True
    _assert_permission_budget(permission)


@pytest.mark.parametrize(("observer_tag", "target_tag", "reason"), [
    ("FRA", "FRA", "OBSERVER_TARGET_SAME_TAG"),
])
def test_known_tag_exclusions_are_denied_without_memory_or_leaf_reads(
        monkeypatch: pytest.MonkeyPatch, observer_tag: str, target_tag: str, reason: str):
    image, observer, target = _environment(observer_tag=observer_tag, target_tag=target_tag)
    permission = _permission(image, observer, target)
    calls = _deny_leaf_if_called(monkeypatch)

    assert permission["status"] == "known" and permission["admitted"] is False
    assert permission["reason"] == reason
    assert image.reads == []
    assert memory.validate_permission(permission) is True
    field = _field(image, observer, target, permission)
    assert field["status"] == "unknown" and "value" not in field
    assert field["reason"] == "TARGET_DEBT_PERMISSION_NOT_ADMITTED"
    assert calls == [] and image.reads == []


@pytest.mark.parametrize(("config", "reason"), [
    ({"target_controller": -1}, "TARGET_CONTROLLER_NOT_ZERO"),
    ({"target_controller": 1}, "TARGET_CONTROLLER_NOT_ZERO"),
])
def test_known_human_or_controller_mismatch_denies_after_stable_rechecks(
        monkeypatch: pytest.MonkeyPatch, config: dict, reason: str):
    image, observer, target = _environment(**config)
    permission = _permission(image, observer, target)
    calls = _deny_leaf_if_called(monkeypatch)

    assert permission["status"] == "known" and permission["admitted"] is False
    assert permission["reason"] == reason
    world = permission["raw_inputs"]["world"]
    assert world["pointer"] == world["fresh_pointer"]
    assert world["date_raw_i32"] == world["fresh_date_raw_i32"]
    assert world["human_count_i32"] == world["fresh_human_count_i32"]
    assert world["controllers_pointer"] == world["fresh_controllers_pointer"]
    assert world["observer_controller_i32"] == world["fresh_observer_controller_i32"]
    assert world["target_controller_i32"] == world["fresh_target_controller_i32"]
    assert memory.validate_permission(permission) is True
    before = len(image.reads)
    field = _field(image, observer, target, permission)
    assert field["status"] == "unknown" and "value" not in field
    assert calls == [] and len(image.reads) == before
    _assert_permission_budget(permission)


@pytest.mark.parametrize(("observer_tag", "target_tag", "observer_controller"), [
    ("ENG", "CAN", 0), ("POR", "FRA", 1), ("FRA", "POR", 1),
])
def test_distinct_bound_tags_and_player_observer_are_admitted(observer_tag, target_tag, observer_controller):
    image, observer, target = _environment(observer_tag=observer_tag, target_tag=target_tag,
                                            human_count=2, observer_controller=observer_controller)
    permission = _permission(image, observer, target)
    assert permission["status"] == "known" and permission["admitted"] is True
    assert memory.validate_permission(permission) is True


def _drift_bytes(image: MemoryImage, case: str) -> None:
    if case == "world_pointer":
        image.changed_reads[("world.fresh_global_pointer", 1)] = OTHER_WORLD.to_bytes(8, "little")
    elif case == "date":
        image.changed_reads[("world.fresh_date_i32", 1)] = (DATE_RAW + 1).to_bytes(4, "little", signed=True)
    elif case == "human_count":
        image.changed_reads[("world.fresh_human_count_i32", 1)] = (2).to_bytes(4, "little", signed=True)
    elif case == "controllers_pointer":
        image.changed_reads[("world.fresh_controllers_pointer", 1)] = OTHER_CONTROLLERS.to_bytes(8, "little")
    elif case == "observer_controller":
        image.changed_reads[("world.fresh_observer_controller_i32", 1)] = (1).to_bytes(4, "little", signed=True)
    elif case == "target_controller":
        image.changed_reads[("world.fresh_target_controller_i32", 1)] = (-1).to_bytes(4, "little", signed=True)
    elif case == "country_fullref":
        changed = _fullref("FRA", OBSERVER_SLOT, 0x1235)
        image.changed_reads[("bindings.observer.fullref", 2)] = changed.to_bytes(8, "little")
    elif case == "country_table_entry":
        image.changed_reads[("bindings.target.table_entry", 2)] = (TARGET_POINTER + 0x1000).to_bytes(8, "little")
    elif case == "database_pointer":
        other_database = DATABASE + 0x1000
        image.put_u64(other_database + 0x118, TABLE)
        image.put_i32(other_database + 0x124, TARGET_TABLE_COUNT)
        image.changed_reads[("bindings.database_global", 2)] = other_database.to_bytes(8, "little")
    elif case == "action_map_wrong_before":
        image.put_u64(BASE + 0x1C80A18, BASE + 0x004F5968)
    elif case == "reason_map_wrong_before":
        image.put_u64(BASE + 0x1C80AA0, BASE + 0x004F5E98)
    elif case == "validity_map_wrong_before":
        image.put_u64(BASE + 0x1C80A50, BASE + 0x0008F448)
    elif case == "action_map_drift":
        image.changed_reads[("native_map.action_getter_after", 1)] = (
            BASE + 0x004F5968).to_bytes(8, "little")
    elif case == "reason_map_drift":
        image.changed_reads[("native_map.principal_reason_after", 1)] = (
            BASE + 0x004F5E98).to_bytes(8, "little")
    elif case == "validity_map_drift":
        image.changed_reads[("native_map.validity_helper_after", 1)] = (
            BASE + 0x0008F448).to_bytes(8, "little")
    elif case == "exclusion_table_drift":
        changed = bytearray(bytes.fromhex(
            "28300000292a0000cc3b0000e02d0000da2d00003c29000007330000b9330000"
            "75330000cb3b0000cd3b000066380000"))
        changed[0] ^= 1
        image.changed_reads[("native_exclusions.table_after", 1)] = bytes(changed)


@pytest.mark.parametrize("case", [
    "world_pointer", "date", "human_count", "controllers_pointer",
    "observer_controller", "target_controller", "country_fullref",
    "country_table_entry", "database_pointer", "action_map_wrong_before",
    "reason_map_wrong_before", "validity_map_wrong_before", "action_map_drift",
    "reason_map_drift", "validity_map_drift", "exclusion_table_drift",
])
def test_any_world_role_or_database_binding_drift_returns_unknown(case: str):
    image, observer, target = _environment()
    _drift_bytes(image, case)
    permission = _permission(image, observer, target)
    assert permission["status"] == "unknown"
    assert permission["admitted"] is None
    assert permission["publication_admitted"] is False
    assert permission["actual_UI_observed"] is False
    assert permission["reason"]
    assert memory.validate_permission(permission) is True
    _assert_permission_budget(permission)


def test_current_action_token_in_stable_exclusion_table_is_known_denied():
    image, observer, target = _environment()
    excluded = bytearray(bytes.fromhex(
        "28300000292a0000cc3b0000e02d0000da2d00003c29000007330000b9330000"
        "75330000cb3b0000cd3b000066380000"))
    excluded[0:4] = (15310).to_bytes(4, "little")
    image.put(BASE + 0x1C35460, bytes(excluded))

    permission = _permission(image, observer, target)

    assert permission["status"] == "known" and permission["admitted"] is False
    assert permission["reason"] == "CURRENT_ACTION_TOKEN_EXCLUDED"
    table = permission["raw_inputs"]["current_action_exclusion_table"]
    assert table["before"]["current_action_token_excluded"] is True
    assert table["before"] == table["after"]
    assert memory.validate_permission(permission) is True
    _assert_permission_budget(permission)


@pytest.mark.parametrize("tamper", ["bool_calls", "date_bool", "trace_order", "trace_hex"])
def test_permission_saved_json_replays_strictly_and_rejects_type_or_trace_tampering(tamper: str):
    image, observer, target = _environment()
    permission = _permission(image, observer, target)
    saved = json.loads(json.dumps(permission))
    assert memory.validate_permission(saved) is True

    changed = deepcopy(saved)
    if tamper == "bool_calls":
        changed["raw_inputs"]["read_budget"]["calls"] = True
    elif tamper == "date_bool":
        changed["raw_inputs"]["world"]["date_raw_i32"] = True
    elif tamper == "trace_order":
        changed["raw_inputs"]["ordered_read_trace"][0:2] = reversed(
            changed["raw_inputs"]["ordered_read_trace"][0:2])
    else:
        row = changed["raw_inputs"]["ordered_read_trace"][0]
        row["raw_hex"] = "00" * row["size"]
    assert memory.validate_permission(changed) is False


def test_irrelevant_field_request_performs_no_reads_or_leaf_call(monkeypatch: pytest.MonkeyPatch):
    image, observer, target = _environment()
    permission = _permission(image, observer, target)
    image.reads.clear()
    calls = _deny_leaf_if_called(monkeypatch)
    assert memory.read_fields(image, BASE, observer, target, "F03.debt",
                              permission=permission) == {}
    assert image.reads == [] and calls == []


def test_read_fields_fresh_rebinds_same_reader_then_projects_leaf_value(monkeypatch: pytest.MonkeyPatch):
    image, observer, target = _environment()
    permission = _permission(image, observer, target)
    image.reads.clear()
    fake_value = {
        "loan_count": 2,
        "principal_total": {"status": "known", "raw": 75, "value": 75,
                             "unit": "ducats", "scale": 1},
        "diplomatic_principal_total": {"status": "known", "raw": 75_000,
                                        "value": 75.0, "unit": "ducats", "scale": 1000},
    }
    calls: list[tuple] = []

    def fake_leaf(reader, base, observer_binding, target_binding):
        calls.append((reader, base, observer_binding, target_binding))
        assert reader is image
        assert any(label == "world.fresh_target_controller_i32"
                   for _address, _size, label in image.reads)
        return {
            "schema": "information.foreign_debt_principal_memory.v1",
            "status": "known", "complete_loan_list": True,
            "publication_admitted": False, "value": fake_value,
        }

    monkeypatch.setattr(memory._leaf, "read_state", fake_leaf)
    field = _field(image, observer, target, permission)
    assert field["status"] == "known"
    assert field["basis"] == "private_native_diplomatic_target_principal"
    assert field["scope"] == "native_negotiated_ai_recipient_principal_candidate"
    assert field["unit"] == "loan_principal_totals"
    assert field["scale"] == 1 and field["period"] == "current"
    assert field["partial"] is True and field["complete"] is False
    assert field["publication_admitted"] is False
    assert field["value"] == fake_value
    assert field["raw_inputs"]["permission"] == permission
    assert field["raw_inputs"]["state"]["value"] == fake_value
    assert len(calls) == 1 and calls[0][0] is image and calls[0][1] == BASE
    assert image.reads


@pytest.mark.parametrize("change", ["base", "binding", "stale_date", "invalid_permission"])
def test_base_binding_stale_or_invalid_permission_never_enters_leaf(
        monkeypatch: pytest.MonkeyPatch, change: str):
    image, observer, target = _environment()
    permission = _permission(image, observer, target)
    image.reads.clear()
    calls = _deny_leaf_if_called(monkeypatch)
    base = BASE
    selected_target = target
    selected_permission = permission
    if change == "base":
        base = BASE + 0x1000
    elif change == "binding":
        selected_target = deepcopy(target)
        selected_target["fullref"] = hex(_fullref("ENG", TARGET_SLOT, 0x2346))
        selected_target["fullref_raw_hex"] = int(selected_target["fullref"], 0).to_bytes(8, "little").hex()
    elif change == "stale_date":
        image.put_i32(WORLD + 0x1DD0, DATE_RAW + 1)
    else:
        selected_permission = deepcopy(permission)
        selected_permission["raw_inputs"]["read_budget"]["calls"] = True

    result = memory.read_fields(image, base, observer, selected_target, memory.FIELD,
                                permission=selected_permission)[memory.FIELD]
    assert result["status"] == "unknown" and "value" not in result
    assert calls == []
    if change in ("base", "binding", "invalid_permission"):
        assert image.reads == []
    else:
        assert any(label == "world.fresh_date_i32" for _a, _s, label in image.reads)


def test_leaf_unknown_is_mapped_without_a_value(monkeypatch: pytest.MonkeyPatch):
    image, observer, target = _environment()
    permission = _permission(image, observer, target)
    image.reads.clear()

    def unknown_leaf(reader, base, observer_binding, target_binding):
        assert reader is image and base == BASE
        return {
            "schema": "information.foreign_debt_principal_memory.v1",
            "status": "unknown", "complete_loan_list": False,
            "publication_admitted": False,
            "reason": "LOAN_NODE_CYCLE",
        }

    monkeypatch.setattr(memory._leaf, "read_state", unknown_leaf)
    field = _field(image, observer, target, permission)
    assert field["status"] == "unknown"
    assert "value" not in field
    assert field["reason"] == "TARGET_DEBT_PRINCIPAL_STATE_UNKNOWN"
    assert field["raw_inputs"]["state"]["reason"] == "LOAN_NODE_CYCLE"

