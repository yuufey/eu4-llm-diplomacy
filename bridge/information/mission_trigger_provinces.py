"""Read verified owner/controller state for one mission-trigger province.

This is a narrow adapter over ``province_state_memory``. The supplied reader
must already be tracked by its caller; this module never opens a process,
reads saves, drives the UI, or calls native game functions.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import province_state_memory


SOURCE = "province_state_memory.read_two_pass"
FIELDS = ("G02.owner", "G02.controller")
_MAX_U64 = 0xFFFFFFFFFFFFFFFF
MAX_PROVINCE_ID = 0xFFFF
_COUNTRY_SCAN_MARKER = "country_reference.database_global"
MAX_CACHED_ENTRIES = 2 * (2 * province_state_memory.MAX_COUNTRY_SLOTS + 3 + 64)
MAX_CACHED_BYTES = MAX_CACHED_ENTRIES * 8
IDENTITY_SAMPLING = "shared_two_pass_country_scan_per_trigger_snapshot"
COMMON_INPUT_SAMPLING = "shared_two_pass_observer_and_domain_inputs_per_trigger_snapshot"

# These reads depend on the same FRA observer/country table/province domain,
# not on the selected province. Keep this an exact whitelist: province ID,
# discovery and source owner/controller fullrefs must still be read afresh.
_SHARED_INPUT_LABELS = frozenset({
    "foreign_tech.role.world", "foreign_tech.role.human_count",
    "foreign_tech.role.controllers_pointer", "foreign_tech.role.observer_controller",
    "province_reference.world_global", "province_reference.array_begin",
    "province_reference.array_end", "province_reference.records_pointer",
    "DAT_14233d884", "DAT_14233d8b8", "DAT_14233d8bc",
    "observer.relation_table_pointer", "relation_row.recipient_fullref",
    "relation_row.owner_pointer", "relation_owner.counters_pointer",
    "relation_recipient.counter_signed_i32", "target_country.capital_pointer",
    "target_capital.view_flags_u8", "target_capital.observer_bitset_pointer",
    "target_capital.observer_bitset_word_u32",
})
_FIELD_IDENTITY_LABELS = frozenset(
    f"province_state.{field}.{part}"
    for field in ("G02_owner", "G02_controller")
    for part in ("database_global", "table_pointer", "count_i32",
                 "country_pointer", "canonical_fullref")
)


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _hex_u64(value: Any) -> int | None:
    if type(value) is not str or not value.startswith("0x"):
        return None
    digits = value[2:]
    if not digits or any(char not in "0123456789abcdefABCDEF" for char in digits):
        return None
    try:
        parsed = int(digits, 16)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= _MAX_U64 else None


def _bytes_hex(value: Any, width: int = 8) -> bytes | None:
    if type(value) is not str or len(value) != width * 2:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _province_binding_is_valid(binding: Any, province_id: int) -> bool:
    if not isinstance(binding, Mapping):
        return False
    if (type(binding.get("province_id")) is not int
            or binding.get("province_id") != province_id
            or type(binding.get("record_id")) is not int
            or binding.get("record_id") != province_id):
        return False
    record_pointer = _hex_u64(binding.get("record_pointer"))
    if (record_pointer is None or record_pointer < province_state_memory.MIN_USER_ADDRESS
            or record_pointer >= province_state_memory.MAX_USER_ADDRESS_EXCLUSIVE
            or record_pointer & 7):
        return False
    raw_id = _bytes_hex(binding.get("id_raw_hex"), width=4)
    return raw_id is not None and int.from_bytes(raw_id[:4], "little", signed=True) == province_id


def _observer_identity(bindings: Any, observer: str) -> tuple[int, int] | None:
    """Return the stable canonical observer pointer/fullref when safely bound."""
    if not isinstance(bindings, Mapping):
        return None
    rows = [bindings.get("pass1"), bindings.get("pass2")]
    parsed: list[tuple[int, int, int, str]] = []
    for row in rows:
        if not isinstance(row, Mapping) or row.get("tag") != observer:
            return None
        pointer = _hex_u64(row.get("country_pointer"))
        reference = _hex_u64(row.get("fullref"))
        slot = row.get("slot")
        raw = _bytes_hex(row.get("fullref_raw_hex"))
        if (pointer is None or pointer < province_state_memory.MIN_USER_ADDRESS
                or pointer >= province_state_memory.MAX_USER_ADDRESS_EXCLUSIVE or pointer & 7
                or reference is None or type(slot) is not int or not 0 <= slot < 0x10000
                or (reference >> 32) & 0xFFFF != slot
                or raw is None or int.from_bytes(raw, "little") != reference):
            return None
        if (((reference >> 56) & 0xFF) == 0 or ((reference >> 48) & 0xFF) == 7
                or (reference & 0xFFFFFFFF).to_bytes(4, "little")
                != observer.encode("ascii") + b"\0"):
            return None
        parsed.append((pointer, reference, slot, row.get("tag")))
    if parsed[0] != parsed[1]:
        return None
    return parsed[0][0], parsed[0][1]


def _validated_field_reference(item: Mapping[str, Any], tag: str) -> int | None:
    """Use the field reader's explicit raw_inputs only when all echoed bytes agree."""
    raw = item.get("raw_inputs")
    if not isinstance(raw, Mapping) or raw.get("tag") != tag:
        return None
    reference = _hex_u64(raw.get("fullref"))
    canonical = _hex_u64(raw.get("canonical_fullref"))
    source_raw = _bytes_hex(raw.get("reference_raw_hex"))
    decoded_raw = _bytes_hex(raw.get("fullref_raw_hex"))
    canonical_raw = _bytes_hex(raw.get("canonical_fullref_raw_hex"))
    if (reference is None or canonical is None or reference != canonical
            or source_raw is None or decoded_raw is None or canonical_raw is None
            or int.from_bytes(source_raw, "little") != reference
            or int.from_bytes(decoded_raw, "little") != reference
            or int.from_bytes(canonical_raw, "little") != reference):
        return None
    if (((reference >> 56) & 0xFF) == 0 or ((reference >> 48) & 0xFF) == 7
            or type(raw.get("slot")) is not int
            or raw.get("slot") != (reference >> 32) & 0xFFFF):
        return None
    low_tag = (reference & 0xFFFFFFFF).to_bytes(4, "little")
    if low_tag != tag.encode("ascii") + b"\0":
        return None
    return reference


def _validated_field_country_pointer(item: Mapping[str, Any], reference: int) -> int | None:
    """Expose only the country record pointer echoed by the validated table row."""
    raw = item.get("raw_inputs")
    if not isinstance(raw, Mapping):
        return None
    pointer = _hex_u64(raw.get("country_pointer"))
    canonical_address = _hex_u64(raw.get("canonical_fullref_address"))
    table = _hex_u64(raw.get("table"))
    entry_address = _hex_u64(raw.get("table_entry_address"))
    entry_raw = _bytes_hex(raw.get("table_entry_raw_hex"))
    canonical_raw = _bytes_hex(raw.get("canonical_fullref_raw_hex"))
    slot = raw.get("slot")
    if (pointer is None or pointer < province_state_memory.MIN_USER_ADDRESS
            or pointer >= province_state_memory.MAX_USER_ADDRESS_EXCLUSIVE or pointer & 7
            or canonical_address != pointer + province_state_memory.COUNTRY_FULLREF_OFFSET
            or _hex_u64(raw.get("canonical_fullref")) != reference
            or canonical_raw is None or int.from_bytes(canonical_raw, "little") != reference
            or table is None or type(slot) is not int or not 0 <= slot < 0x10000
            or entry_address != table + slot * 8
            or entry_raw is None or int.from_bytes(entry_raw, "little") != pointer):
        return None
    return pointer


def _field_result(fields: Any, consistency: Any, field: str) -> dict[str, Any]:
    item = fields.get(field) if isinstance(fields, Mapping) else None
    if not isinstance(item, Mapping):
        return {"status": "unknown", "reason": "FIELD_RESULT_MISSING"}
    if item.get("status") == "unknown":
        reason = item.get("reason")
        return {"status": "unknown", "reason": reason if type(reason) is str
                else "FIELD_RESULT_UNKNOWN"}
    field_check = consistency.get(field) if isinstance(consistency, Mapping) else None
    if not isinstance(field_check, Mapping) or field_check.get("status") != "stable":
        return {"status": "unknown", "reason": "FIELD_CONSISTENCY_NOT_STABLE"}
    tag = item.get("value")
    if (item.get("status") != "known" or type(tag) is not str or len(tag) != 3
            or not tag.isascii() or not tag.isalnum() or tag.upper() != tag):
        return {"status": "unknown", "reason": "FIELD_RESULT_INVALID"}
    result: dict[str, Any] = {"status": "known", "tag": tag}
    reference = _validated_field_reference(item, tag)
    if reference is not None:
        result["reference"] = reference
        country_pointer = _validated_field_country_pointer(item, reference)
        if country_pointer is not None:
            result["country_pointer"] = country_pointer
    return result


def _first_error_reason(result: Mapping[str, Any], fallback: str) -> str:
    errors = result.get("errors")
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, Mapping) and type(error.get("code")) is str:
                return error["code"]
    return fallback


def _read_province_state(read: Any, module_base: int, province_id: int,
                         observer: str = "FRA") -> dict[str, Any]:
    """Project one province's canonically bound owner/controller tags.

    A known result requires stable two-pass identity, positive admission and
    discovery in both passes, and the requested province ID echoed by both
    indexed-record bindings. Each owner/controller value remains independently
    unknown if its own canonical country fullref did not validate.
    """
    if type(province_id) is not int or not 1 <= province_id <= MAX_PROVINCE_ID:
        return _unknown("province_id_invalid")
    if type(observer) is not str or observer != "FRA":
        return _unknown("observer_scope_invalid")

    try:
        report = province_state_memory.read_two_pass(
            read, module_base, province_id, observer=observer, fields=FIELDS)
    except Exception:
        return _unknown("province_state_read_failed")
    if not isinstance(report, Mapping):
        return _unknown("province_state_result_invalid")
    if report.get("schema") != province_state_memory.SCHEMA:
        return _unknown("province_state_schema_invalid")
    if report.get("status") != "observed":
        return _unknown(_first_error_reason(report, "province_state_unobserved"))

    consistency = report.get("consistency")
    if (not isinstance(consistency, Mapping) or consistency.get("status") != "stable"
            or consistency.get("shared_mismatch_paths") != []):
        return _unknown("province_state_two_pass_unstable")

    targets = report.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        return _unknown("province_state_target_binding_unverified")
    target = targets[0]
    if (not isinstance(target, Mapping) or type(target.get("province_id")) is not int
            or target.get("province_id") != province_id):
        return _unknown("province_state_target_id_mismatch")

    pass_evidence = report.get("pass_evidence")
    bindings = target.get("bindings_by_pass")
    admissions = target.get("admission_by_pass")
    discoveries = target.get("discovery_by_pass")
    for phase in ("pass1", "pass2"):
        evidence = pass_evidence.get(phase) if isinstance(pass_evidence, Mapping) else None
        binding_row = bindings.get(phase) if isinstance(bindings, Mapping) else None
        province_binding = (binding_row.get("province")
                            if isinstance(binding_row, Mapping) else None)
        if (not isinstance(evidence, Mapping) or evidence.get("status") != "observed"
                or not _province_binding_is_valid(province_binding, province_id)):
            return _unknown("province_state_target_binding_unverified")

        admission = admissions.get(phase) if isinstance(admissions, Mapping) else None
        role = admission.get("observer_nonplayer_role") if isinstance(admission, Mapping) else None
        if (not isinstance(admission, Mapping) or admission.get("status") != "known"
                or admission.get("admitted") is not True
                or not isinstance(role, Mapping) or role.get("verified") is not True):
            reason = admission.get("reason") if isinstance(admission, Mapping) else None
            return _unknown(reason if type(reason) is str else "province_admission_not_established")

        discovery = discoveries.get(phase) if isinstance(discoveries, Mapping) else None
        if (not isinstance(discovery, Mapping) or discovery.get("status") != "known"
                or discovery.get("value") is not True):
            reason = discovery.get("reason") if isinstance(discovery, Mapping) else None
            return _unknown(reason if type(reason) is str else "province_discovery_not_established")

    # Require the target's two indexed bindings to identify the same record.
    province_rows = [bindings[phase]["province"] for phase in ("pass1", "pass2")]
    if province_rows[0].get("record_pointer") != province_rows[1].get("record_pointer"):
        return _unknown("province_state_target_binding_changed")

    output: dict[str, Any] = {
        "status": "known",
        "province_id": province_id,
        "owner": _field_result(target.get("fields"), target.get("field_consistency"),
                               "G02.owner"),
        "controller": _field_result(target.get("fields"), target.get("field_consistency"),
                                     "G02.controller"),
        "source": SOURCE,
    }

    # This exact binding is returned by country_reference_memory and is
    # cross-pass checked by province_state_memory. It lets the caller compare
    # this observer with its separately tracked task-root country pointer.
    observer = "FRA"
    observer_bindings = report.get("observer", {}).get("bindings_by_pass") if isinstance(
        report.get("observer"), Mapping) else None
    observer_identity = _observer_identity(observer_bindings, observer)
    target_observer_bindings = {
        phase: bindings[phase].get("observer") for phase in ("pass1", "pass2")
    }
    target_observer_identity = _observer_identity(target_observer_bindings, observer)
    if (observer_identity is not None and target_observer_identity == observer_identity):
        output["observer_pointer"] = observer_identity[0]
        output["observer_reference"] = observer_identity[1]
    return output


def read_province_state(read: Any, module_base: int, province_id: int,
                        observer: str = "FRA") -> dict[str, Any]:
    """Fail closed while adapting a tracked read into mission-trigger input."""
    try:
        return _read_province_state(read, module_base, province_id, observer)
    except Exception:
        return _unknown("province_state_projection_failed")


def make_province_reader():
    """Create bounded shared-input caches for one outer trigger snapshot.

    Every target still passes through the existing two-pass reader. Country
    identity, observer self-admission and domain headers share distinct pass1
    and pass2 caches. Province IDs, discovery and owner/controller references
    are freshly read per target/pass. Callers create a new factory for each
    outer snapshot; shared admission is not a fresh per-province observation.
    """
    committed_caches: list[dict[tuple[int, int], bytes]] = [{}, {}]
    context_base: int | None = None

    def read_target(read: Any, module_base: int, province_id: int) -> dict[str, Any]:
        nonlocal context_base
        if context_base is None:
            context_base = module_base
        elif context_base != module_base:
            return _unknown("province_state_cache_context_changed")
        working_caches = [dict(committed_caches[0]), dict(committed_caches[1])]
        entry_count = sum(len(cache) for cache in working_caches)
        byte_count = sum(len(value) for cache in working_caches for value in cache.values())
        phase = -1
        marker_count = 0
        phase_error: str | None = None

        def tracked_read(address: int, size: int, label: str) -> bytes:
            nonlocal phase, marker_count, phase_error, entry_count, byte_count
            if phase_error is not None:
                raise ValueError(phase_error)
            if label == _COUNTRY_SCAN_MARKER:
                if marker_count >= 2:
                    phase_error = "province_state_country_scan_phase_overflow"
                    raise ValueError(phase_error)
                phase = marker_count
                marker_count += 1
            if (not isinstance(label, str)
                    or not (label.startswith("country_reference.")
                            or label in _SHARED_INPUT_LABELS or label in _FIELD_IDENTITY_LABELS)):
                return read(address, size, label)
            if phase not in (0, 1):
                phase_error = "province_state_country_scan_phase_missing"
                raise ValueError(phase_error)

            # The country scan and field resolver use different labels for
            # identical canonical identity bytes. Only whitelisted inputs may
            # reuse by address/width; a province source reference never may.
            key = (address, size)
            phase_cache = working_caches[phase]
            cached = phase_cache.get(key)
            if cached is not None:
                return cached

            raw = read(address, size, label)
            if type(raw) is bytes and len(raw) == size:
                if entry_count >= MAX_CACHED_ENTRIES or byte_count + size > MAX_CACHED_BYTES:
                    phase_error = "province_state_country_scan_cache_budget_exceeded"
                    raise ValueError(phase_error)
                phase_cache[key] = raw
                entry_count += 1
                byte_count += size
            return raw

        result = read_province_state(tracked_read, module_base, province_id)
        if phase_error is not None:
            return _unknown(phase_error)
        if result.get("status") != "known":
            return result
        if marker_count != 2:
            return _unknown("province_state_country_scan_phase_incomplete")
        committed_caches[:] = working_caches
        result["identity_sampling"] = IDENTITY_SAMPLING
        result["common_input_sampling"] = COMMON_INPUT_SAMPLING
        return result

    return read_target


__all__ = ["SOURCE", "FIELDS", "MAX_PROVINCE_ID", "IDENTITY_SAMPLING", "COMMON_INPUT_SAMPLING",
           "read_province_state", "make_province_reader"]
