"""TEST_ONLY live acceptance for W01 war participants and its scheduler.

The checker is intentionally one-shot and read-only.  It performs one W01
discovery/query, one report/subscription path, and a bounded scheduler poll.
The independent native comparison uses only bounded ``ReadProcessMemory``
reads of the audited country/war vectors; it never calls a game function and
does not use the retained-result/history reader.
"""
from __future__ import annotations

import argparse
import copy
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_peace_overextension_live import _ImmediateClient
from work.verify_information_battle_autonomous import pin, put, read
from work import information_battle_war_memory as _memory


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
ACTOR = "FRA"
RECIPIENT = "BUR"
WAR_ID_RE = re.compile(r"war_[0-9a-f]{16}_[0-9a-f]{8}\Z")
TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
NATIVE_EVENTS = {"native_peace_context_inspection", "native_peace_context_private"}
W01_FIELDS = ("war_id", "leaders", "participants", "join_dates",
              "co_belligerent_roles")
MAX_LOG_SUFFIX = 2 * 1024 * 1024


class AcceptanceError(RuntimeError):
    """A bounded live or raw-observation contract failed."""


def _require(value: object, message: str) -> None:
    if not value:
        raise AcceptanceError(message)


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _json_size(path: Path, limit: int = 4 * 1024 * 1024) -> None:
    _require(path.is_file(), f"missing_file:{path}")
    _require(0 < path.stat().st_size <= limit,
             f"file_size_out_of_bound:{path}:{path.stat().st_size}")


def _events_since(path: Path, offset: int) -> list[dict[str, Any]]:
    _require(path.is_file(), f"observer_log_missing:{path}")
    size = path.stat().st_size
    _require(size >= offset, "observer_log_went_backwards")
    length = size - offset
    _require(length <= MAX_LOG_SUFFIX, f"native_suffix_over_bound:{length}")
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    rows: list[dict[str, Any]] = []
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("event") in NATIVE_EVENTS:
            rows.append(value)
    return rows


def _manifest_pin(path: Path) -> dict[str, Any]:
    _json_size(path, 4 * 1024 * 1024)
    return pin(path)


def _manifest_identity(installation: Path, expected_dll: str,
                       expected_manifest: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity = read(installation)
    _require(isinstance(identity, dict), "installation_not_object")
    _require(identity.get("game_sha256", "").lower() == GAME_SHA,
             "installation_game_sha_mismatch")
    _require(identity.get("dll_sha256", "").lower() == expected_dll,
             "installation_dll_sha_mismatch")
    manifest_path = installation.parent / "build-manifest.json"
    manifest_pin = _manifest_pin(manifest_path)
    _require(manifest_pin["sha256"] == expected_manifest,
             "build_manifest_sha_mismatch")
    manifest = read(manifest_path)
    _require(isinstance(manifest, dict), "build_manifest_not_object")
    _require(manifest.get("game_sha256", "").lower() == GAME_SHA,
             "build_manifest_game_sha_mismatch")
    _require(manifest.get("dll_sha256", "").lower() == expected_dll,
             "build_manifest_dll_sha_mismatch")
    return identity, manifest, manifest_pin


def _module_path_candidates(document: Mapping[str, Any], manifest: Mapping[str, Any],
                            expected_dll: str, base_dir: Path) -> tuple[Path, str]:
    records = document.get("modules_after_install") or document.get("modules") or []
    paths: list[Path] = []
    names: list[str] = []
    if isinstance(records, list):
        for item in records:
            if not isinstance(item, Mapping):
                continue
            if str(item.get("sha256", "")).lower() != expected_dll:
                continue
            if isinstance(item.get("path"), str) and item["path"]:
                paths.append(Path(item["path"]).resolve())
            if isinstance(item.get("name"), str) and item["name"]:
                names.append(Path(item["name"]).name)
    raw_dll = manifest.get("dll")
    if isinstance(raw_dll, str) and raw_dll:
        candidate = Path(raw_dll)
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        paths.append(candidate.resolve())
        names.append(candidate.name)
    if not paths:
        raise AcceptanceError("expected_observer_dll_path_missing")
    return paths[0], (names[0] if names else paths[0].name)


def _loaded_module_health(kernel: Any, handle: Any, document: Mapping[str, Any],
                          manifest: Mapping[str, Any], expected_dll: str,
                          phase: str, base_dir: Path) -> dict[str, Any]:
    """Hash only the expected loaded DLL and bound the module enumeration."""
    result: dict[str, Any] = {"phase": phase, "status": "unknown",
                              "expected_sha256": expected_dll,
                              "loaded_module_count": None, "matching_modules": [],
                              "unknown_conditions": []}
    try:
        expected_path, expected_name = _module_path_candidates(
            document, manifest, expected_dll, base_dir)
        result.update(expected_path=str(expected_path), expected_name=expected_name)
        modules = (W.HMODULE * _memory.MAX_LOADED_MODULES)()
        needed = W.DWORD()
        if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise C.WinError(C.get_last_error())
        if not needed.value or needed.value % C.sizeof(W.HMODULE):
            raise AcceptanceError("loaded_module_list_invalid")
        count = needed.value // C.sizeof(W.HMODULE)
        _require(count <= _memory.MAX_LOADED_MODULES, "loaded_module_count_out_of_bound")
        result["loaded_module_count"] = count
        expected_key = str(expected_path).casefold()
        for index in range(count):
            name_buffer = C.create_unicode_buffer(32768)
            length = int(kernel._probe_get_module_name(handle, modules[index], name_buffer, len(name_buffer)))
            if length <= 0 or length >= len(name_buffer):
                continue
            module_path = Path(name_buffer.value).resolve()
            if str(module_path).casefold() != expected_key and module_path.name.casefold() != expected_name.casefold():
                continue
            actual = _memory._sha256_file(module_path).lower()
            record = {"index": index, "path": str(module_path), "sha256": actual,
                      "sha256_matches_expected": actual == expected_dll}
            result["matching_modules"].append(record)
        if len(result["matching_modules"]) == 1 and result["matching_modules"][0]["sha256_matches_expected"]:
            result["status"] = "observed"
        elif not result["matching_modules"]:
            result["unknown_conditions"].append("expected_observer_dll_not_loaded")
        else:
            result["unknown_conditions"].append("expected_observer_dll_hash_or_count_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"module_health_failed:{type(exc).__name__}:{exc}")
    return result


def _as_address(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("va")
    return _int_value(value)


def _member_tags(vector: Mapping[str, Any]) -> tuple[list[str], list[int], list[str]]:
    tags: list[str] = []
    handles: list[int] = []
    pointers: list[str] = []
    members = vector.get("members")
    _require(isinstance(members, list) and len(members) <= 256,
             "war_member_vector_missing_or_over_bound")
    for item in members:
        _require(isinstance(item, Mapping), "war_member_record_invalid")
        tag = item.get("tag")
        handle = _int_value(item.get("handle"))
        lookup = item.get("country_lookup")
        _require(isinstance(tag, str) and TAG_RE.fullmatch(tag),
                 "war_member_tag_not_uppercase")
        _require(handle is not None, "war_member_handle_missing")
        _require(isinstance(lookup, Mapping) and lookup.get("status") == "observed",
                 "war_member_country_identity_unobserved")
        tags.append(tag)
        handles.append(handle)
        pointer = lookup.get("country_pointer")
        pointers.append(str(pointer.get("va")) if isinstance(pointer, Mapping) else "")
    _require(len(tags) == len(set(tags)) and len(handles) == len(set(handles)),
             "war_member_duplicate")
    _require(len(pointers) == len(set(pointers)), "war_member_duplicate_country_pointer")
    return tags, handles, pointers


def _raw_war(reader: Any, module_base: int, database: int, reference: int,
             actor_handle: int, recipient_handle: int, label: str) -> dict[str, Any]:
    side_a = _memory._read_member_vector(reader, database, reference, 0x48, 0x50, 0x58,
                                         f"{label}.side_a")
    side_b = _memory._read_member_vector(reader, database, reference, 0x78, 0x80, 0x88,
                                         f"{label}.side_b")
    result: dict[str, Any] = {"native_reference": hex(reference), "side_a": side_a,
                              "side_b": side_b, "status": "unknown",
                              "unknown_conditions": []}
    _require(side_a.get("status") == "observed" and side_a.get("complete") is True,
             f"{label}.side_a_unobserved")
    _require(side_b.get("status") == "observed" and side_b.get("complete") is True,
             f"{label}.side_b_unobserved")
    tags_a, handles_a, pointers_a = _member_tags(side_a)
    tags_b, handles_b, pointers_b = _member_tags(side_b)
    _require(set(tags_a).isdisjoint(tags_b), f"{label}.cross_side_tag_duplicate")
    _require(set(handles_a).isdisjoint(handles_b), f"{label}.cross_side_handle_duplicate")
    _require(set(pointers_a).isdisjoint(pointers_b), f"{label}.cross_side_country_duplicate")
    actor_a, actor_b = actor_handle in handles_a, actor_handle in handles_b
    recipient_a, recipient_b = recipient_handle in handles_a, recipient_handle in handles_b
    _require(int(actor_a) + int(actor_b) == 1, f"{label}.actor_side_membership_invalid")
    _require(int(recipient_a) + int(recipient_b) == 1, f"{label}.recipient_side_membership_invalid")
    _require(actor_a != recipient_a, f"{label}.pair_not_opposite")
    result.update({"tags_a": tags_a, "tags_b": tags_b,
                   "actor_side": "side_a" if actor_a else "side_b",
                   "recipient_side": "side_a" if recipient_a else "side_b",
                   "status": "observed"})
    return result


def _rpm_pair_snapshot(reader: Any, module_base: int, actor: str, recipient: str,
                       expected_date: int, label: str) -> dict[str, Any]:
    """Read only current pair references and side vectors, never history."""
    result: dict[str, Any] = {"phase": label, "status": "unknown", "wars": [],
                              "unknown_conditions": [], "history_reader_used": False}
    try:
        # The new native query reads side vectors directly.  The old retained
        # battle/history instruction guard covers unrelated functions, one of
        # which the installed battle observer legitimately patches.
        result["retained_history_reader_and_guard_used"] = False
        game, game_raw = reader.qword(module_base + _memory.GAME_RVA, "globals.game")
        database, database_raw = reader.qword(module_base + _memory.DATABASE_RVA, "globals.database")
        _require(_memory._valid_pointer(game) and _memory._valid_pointer(database),
                 "game_or_database_pointer_invalid")
        date_raw = reader.read(game + _memory.GAME_DATE_OFFSET, 4, "game.raw_date")
        date = int.from_bytes(date_raw, "little", signed=True)
        _require(date == expected_date, f"rpm_date_mismatch:{date}")
        control = _memory._control_state(reader, module_base, game)
        _require(control.get("status") == "observed", "rpm_control_unobserved")
        _require(control["speed"]["value"] == 0 and control["paused"]["value"] is True,
                 "rpm_world_not_paused")
        actor_scan = _memory._country_scan(reader, database, actor)
        recipient_scan = _memory._country_scan(reader, database, recipient)
        _require(actor_scan.get("status") == "observed" and recipient_scan.get("status") == "observed",
                 "rpm_country_identity_unobserved")
        actor_handle = _as_address((actor_scan.get("country_handle") or {}).get("value"))
        recipient_handle = _as_address((recipient_scan.get("country_handle") or {}).get("value"))
        actor_pointer = _as_address((actor_scan.get("country_pointer") or {}).get("va"))
        recipient_pointer = _as_address((recipient_scan.get("country_pointer") or {}).get("va"))
        _require(all(isinstance(value, int) and value for value in
                     (actor_handle, recipient_handle, actor_pointer, recipient_pointer)),
                 "rpm_country_handles_missing")
        left = _memory._read_pair_references(reader, actor_pointer, recipient_handle,
                                              "pair.actor_to_recipient")
        right = _memory._read_pair_references(reader, recipient_pointer, actor_handle,
                                               "pair.recipient_to_actor")
        left_refs = [_int_value(item.get("native_reference")) for item in left.get("references", [])]
        right_refs = [_int_value(item.get("native_reference")) for item in right.get("references", [])]
        left_refs = [item for item in left_refs if item is not None]
        right_refs = [item for item in right_refs if item is not None]
        _require(left.get("complete") is True and right.get("complete") is True,
                 "rpm_pair_references_incomplete")
        _require(set(left_refs) == set(right_refs)
                 and len(left_refs) == len(set(left_refs))
                 and len(right_refs) == len(set(right_refs)),
                 "rpm_pair_reference_sets_mismatch")
        result.update({
            "game": {"address": hex(module_base + _memory.GAME_RVA), "raw_hex": game_raw.hex(), "value": hex(game)},
            "database": {"address": hex(module_base + _memory.DATABASE_RVA), "raw_hex": database_raw.hex(), "value": hex(database)},
            "game_date": {"raw": date, "raw_hex": date_raw.hex()},
            "control": control,
            "country_identity": {"actor": actor_scan, "recipient": recipient_scan},
            "pair_references": {"actor_to_recipient": left, "recipient_to_actor": right,
                                 "references_equal": True, "reference_count": len(left_refs)},
        })
        for index, reference in enumerate(left_refs):
            first = _raw_war(reader, module_base, database, reference,
                             actor_handle, recipient_handle, f"war[{index}]")
            second = _raw_war(reader, module_base, database, reference,
                              actor_handle, recipient_handle, f"war[{index}]")
            _require(first == second, f"rpm_war_vectors_changed:{index}")
            first["two_complete_raw_passes_identical"] = True
            result["wars"].append(first)
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"rpm_pair_snapshot_failed:{type(exc).__name__}:{exc}")
        return result


class _RPMProbe:
    """One process handle and bounded fresh readers for before/after passes."""

    def __init__(self, installation: Path, document: Mapping[str, Any],
                 manifest: Mapping[str, Any], expected_dll: str):
        self.installation = installation
        self.document = document
        self.manifest = manifest
        self.expected_dll = expected_dll
        self.kernel = _memory._configure_kernel()
        pid = _int_value(document.get("pid"))
        _require(pid is not None and pid > 0, "installation_pid_invalid")
        self.handle = self.kernel.OpenProcess(_memory.PROCESS_ACCESS, False, pid)
        if not self.handle:
            raise C.WinError(C.get_last_error())
        self.module_base: int | None = None
        self.creation_filetime: int | None = None

    def snapshot(self, phase: str, expected_date: int) -> dict[str, Any]:
        identity_report = {"identity": {"installation_path": str(self.installation),
                                        "installation_pid": None,
                                        "installation_creation_filetime": None,
                                        "installation_session_id": None,
                                        "process_path": None,
                                        "process_path_sha256": None,
                                        "process_path_sha256_matches_expected": None,
                                        "process_creation_filetime": None,
                                        "process_creation_matches_installation": None,
                                        "module_path": None,
                                        "module_path_matches_process": None,
                                        "binding_verified": False},
                          "module_base": None}
        base = _memory._capture_identity(identity_report, self.document, self.kernel, self.handle)
        if self.module_base is None:
            self.module_base = base
        _require(base == self.module_base, "rpm_module_base_changed")
        identity = identity_report["identity"]
        if self.creation_filetime is None:
            self.creation_filetime = identity.get("process_creation_filetime")
        _require(identity.get("process_creation_filetime") == self.creation_filetime,
                 "rpm_process_creation_changed")
        module = _loaded_module_health(self.kernel, self.handle, self.document,
                                       self.manifest, self.expected_dll, phase,
                                       self.installation.parent)
        _require(module.get("status") == "observed", "rpm_module_health_unobserved")
        reader = _memory.AddressBoundedRPM(self.kernel, self.handle, base)
        value = _rpm_pair_snapshot(reader, base, ACTOR, RECIPIENT, expected_date, phase)
        value.update({"identity": copy.deepcopy(identity),
                      "module_base": hex(base), "module_health": module,
                      "rpm_access": {"bytes_requested": reader.bytes_requested,
                                     "calls": reader.calls,
                                     "read_log": copy.deepcopy(reader.read_log)}})
        return value

    def close(self) -> dict[str, Any]:
        outcome = _memory._close_process_handle(self.kernel, self.handle)
        self.handle = None
        return outcome


def _public_item(result: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    _require(result.get("delivery", {}).get("status") == "delivered",
             "w01_delivery_not_delivered")
    items = result.get("items")
    _require(isinstance(items, list) and len(items) == 1, "w01_item_count_not_one")
    item = items[0]
    _require(isinstance(item, dict) and item.get("complete") is False,
             "w01_item_not_partial")
    fields = item.get("fields")
    _require(isinstance(fields, dict), "w01_fields_missing")
    war = fields.get("war_id")
    _require(isinstance(war, dict) and war.get("status") == "known"
             and isinstance(war.get("value"), str) and WAR_ID_RE.fullmatch(war["value"]),
             "w01_war_id_not_known")
    participant = fields.get("participants")
    _require(isinstance(participant, dict) and participant.get("status") == "known",
             "w01_participants_not_known")
    for field in ("leaders", "join_dates", "co_belligerent_roles"):
        _require(fields.get(field) == {"status": "unknown", "reason": "WAR_CONTEXT_FIELD_UNVERIFIED"},
                 f"w01_{field}_not_unknown")
    return item, participant["value"]


def _event_binding(events: list[dict[str, Any]], war_id: str, session_id: str,
                   date: int, expected_raw: Mapping[str, Any] | None = None,
                   *, require_fresh: str | None = None) -> dict[str, Any]:
    inspections = [row for row in events
                   if row.get("event") == "native_peace_context_inspection"
                   and row.get("war_id") is None]
    # The event stores wars as a list; bind by query/session/date before using
    # the selected row.  Private rows bind the corresponding native pointer.
    inspections = [row for row in inspections
                   if row.get("session_id") == session_id
                   and row.get("date_raw") == date
                   and row.get("query_id")]
    _require(inspections, "native_w01_inspection_missing")
    chosen = None
    selected_row = None
    for inspection in inspections:
        wars = inspection.get("wars")
        if not isinstance(wars, list):
            continue
        row = next((item for item in wars if isinstance(item, Mapping)
                    and item.get("war_id") == war_id), None)
        if row is not None:
            chosen, selected_row = inspection, row
            break
    _require(chosen is not None and selected_row is not None,
             "native_w01_selected_war_missing")
    _require(chosen.get("query_id") != require_fresh if require_fresh is not None else True,
             "native_w01_query_id_reused")
    _require(chosen.get("family") == "peace" and chosen.get("action_id") == "white_peace"
             and chosen.get("actor") == ACTOR and chosen.get("recipient") == RECIPIENT
             and chosen.get("phase") == "initiate" and chosen.get("discovery") is True
             and chosen.get("query_complete") is True
             and chosen.get("enumeration_complete") is True
             and chosen.get("native_offer_inspected") is False
             and chosen.get("submitted") is False,
             "native_w01_inspection_identity_invalid")
    _require(selected_row.get("identity_scope") == "observer_session"
             and selected_row.get("actor") == ACTOR
             and selected_row.get("recipient") == RECIPIENT
             and selected_row.get("pair_at_war") is True
             and selected_row.get("actor_war_role") is None
             and selected_row.get("recipient_war_role") is None
             and selected_row.get("roles_verified") is False
             and selected_row.get("actor_is_war_leader") is None
             and selected_row.get("recipient_is_war_leader") is None
             and selected_row.get("leaders_verified") is False
             and selected_row.get("context_complete") is False,
             "native_w01_selected_row_contract_invalid")
    private = [row for row in events
               if row.get("event") == "native_peace_context_private"
               and row.get("query_id") == chosen.get("query_id")
               and row.get("war_id") == war_id]
    _require(len(private) == 1, "native_w01_private_binding_not_unique")
    private_row = private[0]
    _require(private_row.get("private") is True
             and private_row.get("association_verified") is True
             and isinstance(private_row.get("native_war_reference"), str),
             "native_w01_private_contract_invalid")
    if expected_raw is not None:
        expected_ref = expected_raw.get("native_reference")
        _require(private_row["native_war_reference"].lower() == str(expected_ref).lower(),
                 "native_w01_private_reference_not_rpm_reference")
        native_participants = selected_row.get("participants")
        _require(isinstance(native_participants, Mapping),
                 "native_w01_participants_missing")
        _require(native_participants.get("side_a") == expected_raw.get("tags_a")
                 and native_participants.get("side_b") == expected_raw.get("tags_b"),
                 "native_w01_participants_not_rpm_exact")
    return {"inspection": chosen, "war": selected_row, "private": private_row,
            "query_id": chosen.get("query_id")}


def _raw_war_for_reference(snapshot: Mapping[str, Any], reference: str) -> dict[str, Any]:
    for war in snapshot.get("wars", []):
        if isinstance(war, Mapping) and str(war.get("native_reference", "")).lower() == reference.lower():
            return dict(war)
    raise AcceptanceError("rpm_war_reference_not_found")


def _check_rpm_pair(snapshot: Mapping[str, Any], expected_date: int) -> None:
    _require(snapshot.get("status") == "observed", "rpm_pair_snapshot_not_observed")
    _require(snapshot.get("history_reader_used") is False, "history_reader_used")
    _require(snapshot.get("game_date", {}).get("raw") == expected_date,
             "rpm_snapshot_date_mismatch")
    _require(snapshot.get("wars") is not None, "rpm_wars_missing")


def run(args: argparse.Namespace) -> int:
    _require(args.test_only is True, "test_only_required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    installation = args.installation.resolve(strict=True)
    expected_dll = args.expected_dll_sha256.lower()
    expected_manifest = args.expected_manifest_sha256.lower()
    _require(SHA_RE.fullmatch(expected_dll) is not None, "expected_dll_sha256_invalid")
    _require(SHA_RE.fullmatch(expected_manifest) is not None, "expected_manifest_sha256_invalid")
    identity, manifest, manifest_pin = _manifest_identity(installation, expected_dll, expected_manifest)
    _require(identity.get("pid") == args.pid and identity.get("creation_filetime") == args.creation_filetime,
             "installation_pid_or_creation_pin_mismatch")
    log = installation.parent / "control-probe.jsonl"
    _require(log.is_file(), "control_probe_missing")
    initial_offset = log.stat().st_size
    namespace = "war-participants-v30-004-" + hashlib.sha256(str(output).encode()).hexdigest()[:16]
    report: dict[str, Any] = {
        "schema": "information.war_participants.live.v1",
        "status": "running", "checks": {},
        "installation": pin(installation), "identity": identity,
        "build_manifest": manifest_pin,
        "expected": {"game_sha256": GAME_SHA, "dll_sha256": expected_dll,
                      "manifest_sha256": expected_manifest, "date_raw": args.expected_date},
        "native_layout": {
            "evidence": "independent_bounded_RPM_only; no_game_function_calls",
            "country_database_global_rva": hex(_memory.DATABASE_RVA),
            "country_table_offset": hex(_memory.COUNTRY_TABLE_OFFSET),
            "country_handle_offset": hex(_memory.COUNTRY_HANDLE_OFFSET),
            "pair_rows_offset": hex(_memory.COUNTRY_RELATION_ROWS_OFFSET),
            "pair_count_offset": hex(_memory.COUNTRY_RELATION_COUNT_OFFSET),
            "war_side_a_offsets": [hex(value) for value in (0x48, 0x50, 0x58)],
            "war_side_b_offsets": [hex(value) for value in (0x78, 0x80, 0x88)],
            "max_members_per_side": 256,
        },
        "business_dispatch": False, "date_advance_save_restart_install": False,
        "information_tick_sent": False, "computer_use": False,
        "native_read_only_queries": True,
    }
    client = None
    subscription: dict[str, Any] | None = None
    cancel_started = False
    rpm: _RPMProbe | None = None
    before_control: dict[str, Any] | None = None
    session: ObserverSession | None = None

    def save_control(label: str) -> dict[str, Any]:
        value = control_snapshot(args.pid, output / f"{label}-control.json")
        return value

    def call(label: str, name: str, **arguments: Any) -> Any:
        definition = next(tool for tool in TOOL_DEFINITIONS if tool["name"] == name)
        validate_schema(arguments, definition["inputSchema"], "arguments")
        put(output / f"{label}-request.json", {"name": name, "arguments": arguments})
        offset = log.stat().st_size
        try:
            value = client.call(name, **arguments)
        except Exception as exc:
            put(output / f"{label}-failure.json", {"type": type(exc).__name__, "message": str(exc)})
            try:
                put(output / f"{label}-native-events.json", _events_since(log, offset))
            except Exception as suffix_error:
                put(output / f"{label}-native-events-failure.json",
                    {"type": type(suffix_error).__name__, "message": str(suffix_error)})
            raise
        put(output / f"{label}-response.json", value)
        put(output / f"{label}-native-events.json", _events_since(log, offset))
        return value

    try:
        before_control = save_control("before")
        _require(tuple(before_control[key] for key in ("player_slot", "date_raw", "speed", "paused_flag"))
                 == (189, args.expected_date, 0, 1), "before_control_not_paused_por")
        session = ObserverSession(installation, game_exe())
        health = session.health()
        put(output / "before-health.json", health)
        _require(health.get("status") == "ready" and health.get("date_raw") == args.expected_date,
                 "before_health_not_ready")
        capabilities = sorted(session.installation_capabilities())
        put(output / "before-capabilities.json", {"capabilities": capabilities})
        _require("native_war_participants_query" in capabilities,
                 "native_war_participants_query_capability_missing")
        report["checks"]["fresh_health_and_participant_capability"] = True

        document = read(installation)
        rpm = _RPMProbe(installation, document, manifest, expected_dll)
        rpm_before = rpm.snapshot("before", args.expected_date)
        put(output / "rpm-before.json", rpm_before)
        _check_rpm_pair(rpm_before, args.expected_date)
        report["checks"]["independent_rpm_before_pair_vectors"] = True

        client = _ImmediateClient(installation, output, tick=1)
        discovery = call("01-discover", "information_discover")
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "W01")
        _require(topic["source"] == "ObserverSession.inspect_peace_contexts", "w01_source_changed")
        query = {"topic": "W01", "object": {"type": "country_pair", "actor": ACTOR,
                                                "recipient": RECIPIENT},
                 "fields": list(topic["fields"]), "parameters": {}}
        _require(set(query["fields"]) == set(W01_FIELDS), "w01_discovery_fields_changed")
        active = call("02-w01-query", "information_query", request_id=namespace + "-query",
                      queries=[query])
        item, public_participants = _public_item(active)
        war_id = item["fields"]["war_id"]["value"]
        _require(item["objects"] == [{"type": "war", "war_id": war_id,
                                       "actor": ACTOR, "recipient": RECIPIENT}],
                 "w01_selected_object_not_exact")
        provenance = item.get("source", {}).get("provenance", {})
        _require(provenance.get("enumeration_complete") is True
                 and provenance.get("candidate_count") == 1,
                 "w01_current_war_not_unique")
        _require(isinstance(provenance.get("query_id"), str), "w01_native_query_id_missing")
        active_events = read(output / "02-w01-query-native-events.json")
        active_binding = _event_binding(active_events, war_id, identity["session_id"],
                                        args.expected_date)
        raw_ref = active_binding["private"]["native_war_reference"]
        raw_after_active = rpm.snapshot("after-active", args.expected_date)
        put(output / "rpm-after-active.json", raw_after_active)
        _check_rpm_pair(raw_after_active, args.expected_date)
        expected_raw = _raw_war_for_reference(raw_after_active, raw_ref)
        if any(isinstance(row, Mapping)
               and str(row.get("native_reference", "")).lower() == raw_ref.lower()
               for row in rpm_before.get("wars", [])):
            raw_before = _raw_war_for_reference(rpm_before, raw_ref)
            _require(raw_before["tags_a"] == expected_raw["tags_a"]
                     and raw_before["tags_b"] == expected_raw["tags_b"],
                     "rpm_before_after_active_vectors_changed")
            report["checks"]["independent_rpm_before_after_active_vectors_stable"] = True
        _require(public_participants == {
            "source": "native_war_side_vectors", "status": "available", "complete": True,
            "side_a": expected_raw["tags_a"], "side_b": expected_raw["tags_b"],
            "actor_side": expected_raw["actor_side"], "recipient_side": expected_raw["recipient_side"],
            "reason": None}, "public_w01_participants_not_rpm_exact")
        report.update({"war_id": war_id, "active_native_query_id": active_binding["query_id"],
                       "active_rpm_reference": raw_ref})
        report["checks"].update({"active_w01_unique_war_partial_projection": True,
                                  "active_native_suffix_exact_and_private_bound": True,
                                  "active_public_participants_exact_rpm": True})

        configured = call("03-report", "information_manage_report", request_id=namespace + "-report",
                          operation="create", config={"name": "war-participants-v30-004-live",
                                                       "queries": [query], "detail": "raw"})
        periodic_offset = log.stat().st_size
        put(output / "periodic-offset.json", {"offset": periodic_offset})
        created = call("04-subscribe", "information_manage_subscription",
                       request_id=namespace + "-subscribe", operation="create",
                       config={"name": "war-participants-v30-004-periodic", "kind": "periodic",
                               "report_id": configured["report"]["id"], "enabled": True,
                               "schedule": {"basis": "real", "every": 2, "unit": "seconds",
                                             "missed": "coalesce"}})
        subscription = created["subscription"]
        periodic_item = None
        for index in range(12):
            time.sleep(0.5)
            listed = call(f"05-results-{index:02d}", "information_list_results", limit=50)
            periodic_item = next((row for row in listed["results"]
                                  if row.get("subscription_id") == subscription["id"]), None)
            if periodic_item is not None:
                break
        _require(periodic_item is not None, "periodic_w01_result_missing")
        put(output / "periodic-result.json", periodic_item)
        _, periodic_participants = _public_item(periodic_item)
        _require(periodic_item["items"][0]["fields"] == item["fields"],
                 "periodic_w01_fields_differ_from_active")
        _require(periodic_participants == public_participants,
                 "periodic_w01_participants_differ_from_active")
        periodic_events = _events_since(log, periodic_offset)
        put(output / "periodic-native-events.json", periodic_events)
        periodic_binding = _event_binding(periodic_events, war_id,
                                           identity["session_id"], args.expected_date,
                                           expected_raw, require_fresh=active_binding["query_id"])
        _require(periodic_binding["query_id"] != active_binding["query_id"],
                 "periodic_native_query_id_not_fresh")
        report.update({"periodic_native_query_id": periodic_binding["query_id"],
                       "periodic_result_id": periodic_item.get("result_id")})
        report["checks"].update({"scheduler_periodic_w01_matches_active": True,
                                  "scheduler_native_query_fresh_and_rpm_bound": True})

        cancel_started = True
        cancelled = call("06-cancel", "information_manage_subscription",
                         request_id=namespace + "-cancel", operation="cancel",
                         subscription_id=subscription["id"],
                         expected_version=subscription["version"])
        subscription = cancelled["subscription"]
        _require(subscription.get("state") == "cancelled", "subscription_not_cancelled")
        states = call("07-subscriptions", "information_manage_subscription",
                      request_id=namespace + "-subscriptions", operation="list")
        _require(all(row.get("state") != "active" for row in states["subscriptions"]),
                 "active_subscription_remains")
        report["checks"]["cancelled_once_no_active_subscription"] = True
        rpm_after = rpm.snapshot("after", args.expected_date)
        put(output / "rpm-after.json", rpm_after)
        _check_rpm_pair(rpm_after, args.expected_date)
        _require(_raw_war_for_reference(rpm_after, raw_ref)["tags_a"] == expected_raw["tags_a"]
                 and _raw_war_for_reference(rpm_after, raw_ref)["tags_b"] == expected_raw["tags_b"],
                 "rpm_after_participants_changed")
        report["checks"]["independent_rpm_doublepass_and_identity_stable"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        if subscription is not None and subscription.get("state") == "active" and client is not None and not cancel_started:
            try:
                cancel_started = True
                cleanup = call("cleanup-cancel", "information_manage_subscription",
                               request_id=namespace + "-cleanup-cancel", operation="cancel",
                               subscription_id=subscription["id"],
                               expected_version=subscription["version"])
                subscription = cleanup.get("subscription", subscription)
            except Exception as exc:
                report["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report["close_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
            report["server_exit_code"] = client.process.returncode
            if client.process.returncode != 0:
                report["status"] = "failed"
        if rpm is not None:
            try:
                report["rpm_handle_close"] = rpm.close()
            except Exception as exc:
                report["rpm_handle_close"] = {"status": "error", "error": str(exc)}
                report["status"] = "failed"
        if session is not None:
            try:
                after_health = session.health()
                put(output / "after-health.json", after_health)
                if after_health.get("status") != "ready" or after_health.get("date_raw") != args.expected_date:
                    report["status"] = "failed"
                    report["checks"]["after_health_ready_same_date"] = False
                else:
                    report["checks"]["after_health_ready_same_date"] = True
            except Exception as exc:
                report["after_health_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
        try:
            after_control = save_control("after")
            report["checks"]["paused_world_preserved"] = (
                tuple(after_control[key] for key in ("player_slot", "date_raw", "speed", "paused_flag"))
                == (189, args.expected_date, 0, 1))
            if not report["checks"]["paused_world_preserved"]:
                report["status"] = "failed"
        except Exception as exc:
            report["after_control_error"] = {"type": type(exc).__name__, "message": str(exc)}
            report["status"] = "failed"
        try:
            put(output / "native-events.json", _events_since(log, initial_offset))
        except Exception as exc:
            report["native_events_error"] = {"type": type(exc).__name__, "message": str(exc)}
            report["status"] = "failed"
        put(output / "report.json", report)
    print(json.dumps({key: report.get(key) for key in
                      ("status", "checks", "error", "server_exit_code", "war_id")}))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--creation-filetime", type=int, required=True)
    parser.add_argument("--expected-date", type=int, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    parser.add_argument("--test-only", action="store_true", required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
