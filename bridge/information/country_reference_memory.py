"""Resolve country tags through the bounded 1.37.4 country database.

This is a pure memory-reader leaf.  It does not open a process or validate an
installation/profile/session.  Its result proves only that requested tags bind
to rows in the current country manager and that each row's full reference
encodes the same slot.  A parent must validate EXE/profile/session identity and
compare two captures before using it; this scan is not atomic and says nothing
about foreign-country visibility or public API availability.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any


DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE_TABLE_OFFSET = 0x118
DATABASE_TABLE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20

# The current country-rivals profile permits 4096 entries (slot indices
# 0..4095).  The loans profile's max slot value is 4095, the same bound.
MAX_COUNTRY_SLOTS = 4096
MAX_REQUESTED_TAGS = 4096
MAX_TOTAL_READ_BYTES = 256 * 1024
MAX_SINGLE_READ_BYTES = 8
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class CountryReferenceError(ValueError):
    """A requested country could not be bound safely to the country manager."""


def _fail(reason: str) -> None:
    raise CountryReferenceError(reason)


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(base: int, offset: int, *, label: str) -> int:
    if not _is_user_address(base) or type(offset) is not int or offset < 0:
        _fail(f"invalid_pointer_arithmetic:{label}")
    result = base + offset
    if result > MAX_U64 or not _is_user_address(result):
        _fail(f"pointer_arithmetic_out_of_range:{label}")
    return result


def _checked_range(address: int, size: int, *, label: str) -> tuple[int, int]:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or address > MAX_U64 - (size - 1)):
        _fail(f"address_range_invalid:{label}")
    last = address + size - 1
    if not _is_user_address(last):
        _fail(f"address_range_invalid:{label}")
    return address, last + 1


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _read_exact(read: Callable[[int, int, str], bytes], address: int, size: int,
                label: str, state: dict[str, Any]) -> bytes:
    if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
        _fail(f"read_size_out_of_range:{label}")
    _checked_range(address, size, label=label)
    if state["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
        _fail("read_budget_exceeded")
    state["bytes_requested"] += size
    state["calls"] += 1
    try:
        raw = read(address, size, label)
    except Exception as exc:
        state["reads"].append({"address": hex(address), "size": size,
                               "label": label, "status": "failed",
                               "error_type": type(exc).__name__})
        raise CountryReferenceError(f"read_failed:{label}:{type(exc).__name__}") from exc
    if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
        state["reads"].append({"address": hex(address), "size": size,
                               "label": label, "status": "failed",
                               "error_type": "short_or_invalid_read"})
        _fail(f"short_or_invalid_read:{label}")
    raw = bytes(raw)
    state["reads"].append({"address": hex(address), "size": size, "label": label,
                           "status": "ok", "raw_hex": raw.hex()})
    return raw


def _read_u64(read: Callable[[int, int, str], bytes], address: int, label: str,
              state: dict[str, Any]) -> tuple[int, bytes]:
    raw = _read_exact(read, address, 8, label, state)
    return int.from_bytes(raw, "little", signed=False), raw


def _tag_from_fullref(fullref: int) -> str | None:
    raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A for byte in raw):
        return None
    return raw.decode("ascii")


def _parse_expected_ref(value: Any, tag: str) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise CountryReferenceError(f"expected_ref_invalid:{tag}") from exc
    else:
        _fail(f"expected_ref_invalid:{tag}")
    if type(result) is not int or not 0 <= result <= MAX_U64:
        _fail(f"expected_ref_invalid:{tag}")
    if _tag_from_fullref(result) != tag:
        _fail(f"expected_ref_tag_mismatch:{tag}")
    return result


def resolve_countries(read: Callable[[int, int, str], bytes], module_base: int,
                      tags: Iterable[str], *,
                      expected_refs: Mapping[str, int | str] | None = None) -> dict[str, Any]:
    """Resolve requested three-character tags in the B23 country manager.

    `read(address, size, label)` must return exactly `size` bytes.  The full
    database is scanned, up to 4096 slots; reads are at most 8 bytes each and
    are capped at 256 KiB total.  `expected_refs`, when supplied, maps any
    requested subset of tags to exact u64 references (integer or ``0x`` text),
    including opaque generation/flag bits.

    The result is private evidence for a parent reader.  It intentionally does
    not infer visibility, cache eligibility, observer semantics, or API
    availability, and one scan is not an atomic snapshot.
    """
    if not callable(read):
        _fail("reader_not_callable")
    if not _is_user_address(module_base) or module_base & 7:
        _fail("module_base_invalid")

    requested: list[str] = []
    seen_requested: set[str] = set()
    try:
        iterator = iter(tags)
    except TypeError as exc:
        raise CountryReferenceError("requested_tags_not_iterable") from exc
    if isinstance(tags, (str, bytes, bytearray, Mapping)):
        _fail("requested_tags_shape_invalid")
    for tag in iterator:
        if len(requested) >= MAX_REQUESTED_TAGS:
            _fail("requested_tag_count_out_of_range")
        if (not isinstance(tag, str) or len(tag) != 3 or
                not all("A" <= char <= "Z" or "0" <= char <= "9" for char in tag)):
            _fail("requested_tag_invalid")
        if tag in seen_requested:
            _fail(f"duplicate_requested_tag:{tag}")
        seen_requested.add(tag)
        requested.append(tag)
    if not requested:
        _fail("requested_tags_empty")

    if expected_refs is None:
        expected_refs = {}
    if not isinstance(expected_refs, Mapping):
        _fail("expected_refs_shape_invalid")
    if any(tag not in seen_requested for tag in expected_refs):
        _fail("expected_ref_not_requested")
    normalized_expected = {
        tag: _parse_expected_ref(value, tag) for tag, value in expected_refs.items()
    }

    state: dict[str, Any] = {"calls": 0, "bytes_requested": 0, "reads": []}
    global_cell = _checked_add(module_base, DATABASE_GLOBAL_RVA, label="database_global")
    global_range = _checked_range(global_cell, 8, label="database_global")
    database, database_raw = _read_u64(read, global_cell, "country_reference.database_global", state)
    if not _is_user_address(database) or database & 7:
        _fail("database_pointer_invalid")
    if database == module_base or _overlaps((database, database + 1), global_range):
        _fail("database_pointer_alias")

    table_cell = _checked_add(database, DATABASE_TABLE_OFFSET, label="database_table_cell")
    count_cell = _checked_add(database, DATABASE_TABLE_COUNT_OFFSET, label="database_count_cell")
    table_cell_range = _checked_range(table_cell, 8, label="database_table_cell")
    count_cell_range = _checked_range(count_cell, 4, label="database_count_cell")
    if _overlaps(table_cell_range, count_cell_range):
        _fail("database_metadata_alias")
    table, table_raw = _read_u64(read, table_cell, "country_reference.database_table", state)
    count_raw = _read_exact(read, count_cell, 4, "country_reference.database_count", state)
    count = int.from_bytes(count_raw, "little", signed=True)
    if not _is_user_address(table) or table & 7:
        _fail("table_pointer_invalid")
    if table in (module_base, database) or table == global_cell:
        _fail("table_pointer_alias")
    if not 1 <= count <= MAX_COUNTRY_SLOTS:
        _fail("country_count_out_of_range")

    table_size = count * 8
    table_range = _checked_range(table, table_size, label="country_table")
    metadata_ranges = (global_range, table_cell_range, count_cell_range)
    if any(_overlaps(table_range, item) for item in metadata_ranges):
        _fail("country_table_alias")

    rows: list[dict[str, Any]] = []
    seen_pointers: set[int] = set()
    candidates: dict[str, list[dict[str, Any]]] = {tag: [] for tag in requested}
    for slot in range(count):
        entry_address = _checked_add(table, slot * 8, label=f"slot[{slot}]")
        entry_range = _checked_range(entry_address, 8, label=f"slot[{slot}]")
        if any(_overlaps(entry_range, item) for item in metadata_ranges):
            _fail(f"country_table_entry_alias:{slot}")
        pointer, pointer_raw = _read_u64(
            read, entry_address, f"country_reference.slot[{slot}].pointer", state)
        row: dict[str, Any] = {
            "slot": slot,
            "table_entry_address": hex(entry_address),
            "table_entry_raw_hex": pointer_raw.hex(),
            "country_pointer": hex(pointer) if pointer else None,
            "fullref_address": None,
            "fullref": None,
            "fullref_raw_hex": None,
            "tag": None,
            "fullref_slot": None,
        }
        if pointer:
            if not _is_user_address(pointer) or pointer & 7:
                _fail(f"country_pointer_invalid:{slot}")
            if pointer in seen_pointers:
                _fail(f"country_pointer_alias:{slot}")
            if pointer in (module_base, database, table, global_cell):
                _fail(f"country_pointer_alias:{slot}")
            seen_pointers.add(pointer)
            ref_address = _checked_add(pointer, COUNTRY_FULLREF_OFFSET,
                                       label=f"country_ref[{slot}]")
            ref_range = _checked_range(ref_address, 8, label=f"country_ref[{slot}]")
            if any(_overlaps(ref_range, item) for item in metadata_ranges) or _overlaps(ref_range, table_range):
                _fail(f"country_fullref_alias:{slot}")
            fullref, fullref_raw = _read_u64(
                read, ref_address, f"country_reference.slot[{slot}].fullref", state)
            tag = _tag_from_fullref(fullref)
            # The native table also contains special rows such as slot0
            # with raw tag "---". Preserve those rows as unclassified;
            # only an exact requested ordinary tag may become a match.
            ref_slot = (fullref >> 32) & 0xFFFF
            row.update({"fullref_address": hex(ref_address), "fullref": hex(fullref),
                        "fullref_raw_hex": fullref_raw.hex(), "tag": tag,
                        "fullref_slot": ref_slot})
            if tag in candidates:
                candidates[tag].append(row)
        rows.append(row)

    matches: dict[str, dict[str, Any]] = {}
    for tag in requested:
        found = candidates[tag]
        if len(found) == 0:
            _fail(f"requested_country_missing:{tag}")
        if len(found) != 1:
            _fail(f"requested_country_duplicate:{tag}")
        row = found[0]
        if row["fullref_slot"] != row["slot"]:
            _fail(f"requested_country_slot_mismatch:{tag}")
        actual_fullref = int(row["fullref"], 16)
        if tag in normalized_expected and actual_fullref != normalized_expected[tag]:
            _fail(f"expected_fullref_mismatch:{tag}")
        matches[tag] = {
            "tag": tag,
            "slot": row["slot"],
            "country_pointer": row["country_pointer"],
            "country_fullref_address": row["fullref_address"],
            "fullref": row["fullref"],
            "fullref_raw_hex": row["fullref_raw_hex"],
            "table_entry_address": row["table_entry_address"],
            "table_entry_raw_hex": row["table_entry_raw_hex"],
        }

    return {
        "status": "observed",
        "basis": "country_manager_table_tag_slot_binding",
        "module_base": hex(module_base),
        "database_global_rva": hex(DATABASE_GLOBAL_RVA),
        "database_global_address": hex(global_cell),
        "database_global_raw_hex": database_raw.hex(),
        "database": hex(database),
        "table_pointer_address": hex(table_cell),
        "table_pointer_raw_hex": table_raw.hex(),
        "table": hex(table),
        "count_address": hex(count_cell),
        "count_raw_hex": count_raw.hex(),
        "count": count,
        "rows": rows,
        "requested": matches,
        "read_summary": {
            "calls": state["calls"],
            "bytes_requested": state["bytes_requested"],
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
            "max_total_read_bytes": MAX_TOTAL_READ_BYTES,
        },
        "reads": state["reads"],
    }

