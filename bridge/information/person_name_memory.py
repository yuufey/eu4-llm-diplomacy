"""Bounded projection of the native normal person-name helper inputs.

This leaf copies a person's base String32 and, only for the two statically
identified dynasty predicates, optionally appends its dynasty String32.  It
does not call native code, resolve a country, establish visibility, or produce
the person's complete UI label.
"""
from __future__ import annotations

from typing import Any

from bridge.native_text import EU4_ESCAPE_CODEC, NativeTextError, decode_native_text


SCHEMA = "information.person_name_memory.v1"
BASIS = "projected_a4b130_normal_name_component"
PLUGIN64_BASIS = "projected_a4b130_plugin64_callback_component"
SUPPORTED_NAME_LAYOUTS = ("vanilla", "plugin64")
PERSON_HEADER_SIZE = 0x80
STRING32_SIZE = 0x20
MAX_STRING_LENGTH = 256
MAX_STRING_CAPACITY = 4096
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
MIN_USER_ADDRESS = 0x10000
MAX_READ_CALLS = 16
MAX_TOTAL_READ_BYTES = 4096
MAX_SINGLE_READ_BYTES = MAX_STRING_LENGTH + 1

PERSON_COUNTRY_FULLREF_OFFSET = 0x20
PERSON_BASE_NAME_OFFSET = 0x28
PERSON_DYNASTY_POINTER_OFFSET = 0x68
PERSON_REGENCY_POINTER_OFFSET = 0x78
DYNASTY_NAME_OFFSET = 0x08
DYNASTY_PREDICATE_OFFSET = 0x08
DYN_APPEND_TRUE_RVA = 0x8F440
DYN_APPEND_FALSE_RVA = 0x8F450


class _LeafFailure(ValueError):
    pass


def _parse_u64(value: Any, label: str, *, nonzero: bool = False) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and 1 <= len(value) <= 20:
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise _LeafFailure(f"{label}_invalid") from exc
    else:
        raise _LeafFailure(f"{label}_invalid")
    if not 0 <= parsed <= 0xFFFFFFFFFFFFFFFF or (nonzero and parsed == 0):
        raise _LeafFailure(f"{label}_out_of_range")
    return parsed


def _user_pointer(value: int, label: str, *, aligned: bool = False) -> int:
    if not MIN_USER_ADDRESS <= value <= MAX_USER_ADDRESS:
        raise _LeafFailure(f"{label}_invalid")
    if aligned and value & 7:
        raise _LeafFailure(f"{label}_unaligned")
    return value


def _checked_range(address: int, size: int, label: str) -> None:
    if type(address) is not int or type(size) is not int or size <= 0:
        raise _LeafFailure(f"{label}_range_invalid")
    end = address + size - 1
    if (address < MIN_USER_ADDRESS or end > MAX_USER_ADDRESS
            or end < address):
        raise _LeafFailure(f"{label}_range_out_of_bounds")


def _name_value(raw: bytes, decoded: str) -> dict[str, str]:
    return {
        "text": decoded,
        "raw_hex": raw.hex(),
        "encoding": EU4_ESCAPE_CODEC,
    }


def _unknown(reason: str, raw_inputs: dict[str, Any], basis: str = BASIS) -> dict[str, Any]:
    raw_inputs.setdefault("read_budget", {
        "calls": 0,
        "bytes_requested": 0,
        "max_single_read": 0,
        "limit_calls": MAX_READ_CALLS,
        "limit_bytes": MAX_TOTAL_READ_BYTES,
        "limit_single_read": MAX_SINGLE_READ_BYTES,
    })
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "reason": reason,
        "raw_inputs": raw_inputs,
        "basis": basis,
        "full_ui_label": False,
    }


def _basis_for_layout(name_layout: str) -> str:
    return PLUGIN64_BASIS if name_layout == "plugin64" else BASIS


def _valid_name_layout(name_layout: Any, raw_inputs: dict[str, Any]) -> bool:
    if type(name_layout) is str and name_layout in SUPPORTED_NAME_LAYOUTS:
        if name_layout != "vanilla":
            raw_inputs["name_layout"] = name_layout
        return True
    raw_inputs["name_layout"] = name_layout if type(name_layout) in (str, type(None)) else type(name_layout).__name__
    return False


def _decode_projected_name(raw: bytes, label: str) -> str:
    try:
        return decode_native_text(
            raw, codec=EU4_ESCAPE_CODEC,
            max_bytes=MAX_STRING_LENGTH, max_bytes_limit=MAX_STRING_LENGTH)
    except NativeTextError as exc:
        raise _LeafFailure(f"{label}_decode_invalid") from exc


def _plugin64_marker_selected(dynasty_raw: bytes) -> bool:
    # The callback receives right = b" " + dynasty_raw and checks right[1]
    # only when right's length is at least three bytes.
    right = b" " + dynasty_raw
    return len(right) >= 3 and right[1] == 0xBF


def _decode_dynasty_string32(read_exact: Any, header: bytes,
                             header_address: int, raw_inputs: dict[str, Any]
                             ) -> tuple[bytes, str, dict[str, Any]]:
    """Decode only a dynasty object's String32, with the shared bounded rules."""
    label = "dynasty.name"
    if len(header) != STRING32_SIZE:
        raise _LeafFailure("dynasty.name_header_size_invalid")
    length = int.from_bytes(header[0x10:0x18], "little")
    capacity = int.from_bytes(header[0x18:0x20], "little")
    details: dict[str, Any] = {
        "header_address": hex(header_address),
        "header_raw_hex": header.hex(),
        "length_raw_hex": header[0x10:0x18].hex(),
        "capacity_raw_hex": header[0x18:0x20].hex(),
        "length": length,
        "capacity": capacity,
    }
    if length > MAX_STRING_LENGTH:
        raise _LeafFailure("dynasty.name_length_out_of_bound")
    if capacity > MAX_STRING_CAPACITY:
        raise _LeafFailure("dynasty.name_capacity_out_of_bound")
    if capacity < length:
        raise _LeafFailure("dynasty.name_capacity_below_length")

    if capacity < 16:
        details["storage"] = "inline"
        if length > 15:
            raise _LeafFailure("dynasty.name_inline_length_invalid")
        payload = header[:length + 1]
        details["payload_address"] = hex(header_address)
        details["payload_raw_hex"] = payload.hex()
    else:
        details["storage"] = "heap"
        pointer_raw = header[:8]
        pointer = int.from_bytes(pointer_raw, "little")
        details["heap_pointer_raw_hex"] = pointer_raw.hex()
        details["heap_pointer"] = hex(pointer) if pointer else None
        _user_pointer(pointer, "dynasty.name_heap_pointer")
        payload = read_exact(pointer, length + 1, "dynasty.name.payload")
        details["payload_address"] = hex(pointer)
        details["payload_raw_hex"] = payload.hex()

    if len(payload) != length + 1 or payload[length] != 0:
        raise _LeafFailure("dynasty.name_terminator_invalid")
    if b"\x00" in payload[:length]:
        raise _LeafFailure("dynasty.name_embedded_nul")
    value_raw = payload[:length]
    details["value_raw_hex"] = value_raw.hex()
    try:
        decoded = decode_native_text(
            value_raw,
            codec=EU4_ESCAPE_CODEC,
            max_bytes=MAX_STRING_LENGTH,
            max_bytes_limit=MAX_STRING_LENGTH,
        )
    except NativeTextError as exc:
        details["decode_error_type"] = type(exc).__name__
        raw_inputs["dynasty_string32"] = details
        raise _LeafFailure("dynasty.name_decode_invalid") from exc
    details["decoded"] = True
    raw_inputs["dynasty_string32"] = details
    return value_raw, decoded, details


def read_dynasty_component(limiter: Any, base: Any, person_pointer: Any, *,
                           expected_country_fullref: Any,
                           name_layout: str = "vanilla") -> dict[str, Any]:
    """Project only the normal-path dynasty-name component.

    Unlike :func:`read_person_name`, this helper never reads or decodes the
    base name (person+0x28), age, or claim fields. It independently binds the
    person's complete country reference and checks regency and dynasty method
    inputs before returning the dynasty component. ``name_layout`` is an
    explicit caller attestation selector: only ``vanilla`` and ``plugin64``
    are accepted, and this leaf does not establish which layout is active.
    """
    raw: dict[str, Any] = {"read_trace": [], "read_failures": []}
    budget = {
        "calls": 0,
        "bytes_requested": 0,
        "max_single_read": 0,
        "limit_calls": MAX_READ_CALLS,
        "limit_bytes": MAX_TOTAL_READ_BYTES,
        "limit_single_read": MAX_SINGLE_READ_BYTES,
    }
    raw["read_budget"] = budget
    if not _valid_name_layout(name_layout, raw):
        return _unknown("name_layout_unsupported", raw, "unsupported_name_layout")
    basis = _basis_for_layout(name_layout)

    def read_exact(address: int, size: int, label: str) -> bytes:
        _checked_range(address, size, label)
        if size > MAX_SINGLE_READ_BYTES:
            raise _LeafFailure(f"{label}_read_size_out_of_bound")
        if budget["calls"] + 1 > MAX_READ_CALLS:
            raise _LeafFailure("read_call_budget_exceeded")
        if budget["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
            raise _LeafFailure("read_byte_budget_exceeded")
        budget["calls"] += 1
        budget["bytes_requested"] += size
        budget["max_single_read"] = max(budget["max_single_read"], size)
        row = {"address": hex(address), "size": size, "label": label}
        try:
            method = getattr(limiter, "read", None)
            if not callable(method):
                raise TypeError("limiter_read_unavailable")
            result = method(address, size, label)
            if not isinstance(result, (bytes, bytearray, memoryview)):
                raise TypeError("read_result_not_bytes")
            data = bytes(result)
            if len(data) != size:
                raise ValueError(f"short_read:{len(data)}:{size}")
        except Exception as exc:
            row.update({"status": "failed", "error": f"{type(exc).__name__}:{str(exc)[:160]}"})
            raw["read_trace"].append(row)
            raw["read_failures"].append(dict(row))
            raise _LeafFailure(f"{label}_read_failed") from exc
        row.update({"status": "observed", "raw_hex": data.hex()})
        raw["read_trace"].append(row)
        return data

    try:
        module_base = _user_pointer(_parse_u64(base, "module_base"), "module_base")
        person = _user_pointer(
            _parse_u64(person_pointer, "person_pointer", nonzero=True),
            "person_pointer", aligned=True)
        expected_ref = _parse_u64(
            expected_country_fullref, "expected_country_fullref", nonzero=True)
        raw["module_base"] = hex(module_base)
        raw["person_pointer"] = hex(person)
        raw["expected_country_fullref"] = hex(expected_ref)
        raw["expected_country_fullref_raw_hex"] = expected_ref.to_bytes(8, "little").hex()

        owner_address = person + PERSON_COUNTRY_FULLREF_OFFSET
        _checked_range(owner_address, 8, "person.country_fullref")
        owner_raw = read_exact(owner_address, 8, "person.country_fullref")
        owner_ref = int.from_bytes(owner_raw, "little")
        raw["person_country_fullref_address"] = hex(owner_address)
        raw["person_country_fullref_raw_hex"] = owner_raw.hex()
        raw["person_country_fullref"] = hex(owner_ref)
        raw["person_country_fullref_matches_expected"] = owner_ref == expected_ref
        if owner_ref != expected_ref:
            raise _LeafFailure("person_country_fullref_mismatch")

        regency_address = person + PERSON_REGENCY_POINTER_OFFSET
        _checked_range(regency_address, 8, "person.regency_pointer")
        regency_raw = read_exact(regency_address, 8, "person.regency_pointer")
        regency = int.from_bytes(regency_raw, "little")
        raw["regency_pointer_address"] = hex(regency_address)
        raw["regency_pointer_raw_hex"] = regency_raw.hex()
        raw["regency_pointer"] = hex(regency) if regency else None
        if regency != 0:
            raise _LeafFailure("regency_name_path_unsupported")

        dynasty_address = person + PERSON_DYNASTY_POINTER_OFFSET
        _checked_range(dynasty_address, 8, "person.dynasty_pointer")
        dynasty_raw = read_exact(dynasty_address, 8, "person.dynasty_pointer")
        dynasty_pointer = int.from_bytes(dynasty_raw, "little")
        raw["dynasty_pointer_address"] = hex(dynasty_address)
        raw["dynasty_pointer_raw_hex"] = dynasty_raw.hex()
        raw["dynasty_pointer"] = hex(dynasty_pointer) if dynasty_pointer else None
        if dynasty_pointer == 0:
            raise _LeafFailure("dynasty_pointer_null")
        dynasty = _user_pointer(dynasty_pointer, "dynasty_pointer", aligned=True)

        vtable_raw = read_exact(dynasty, 8, "dynasty.vtable")
        vtable = int.from_bytes(vtable_raw, "little")
        raw["dynasty_vtable_raw_hex"] = vtable_raw.hex()
        raw["dynasty_vtable"] = hex(vtable) if vtable else None
        if vtable == 0:
            raise _LeafFailure("dynasty_vtable_null")
        vtable = _user_pointer(vtable, "dynasty_vtable", aligned=True)

        method_address = vtable + DYNASTY_PREDICATE_OFFSET
        _checked_range(method_address, 8, "dynasty.predicate")
        method_raw = read_exact(method_address, 8, "dynasty.predicate")
        method_pointer = int.from_bytes(method_raw, "little")
        true_method = module_base + DYN_APPEND_TRUE_RVA
        false_method = module_base + DYN_APPEND_FALSE_RVA
        _checked_range(true_method, 1, "dynasty.true_method")
        _checked_range(false_method, 1, "dynasty.false_method")
        raw["dynasty_predicate_address"] = hex(method_address)
        raw["dynasty_predicate_raw_hex"] = method_raw.hex()
        raw["dynasty_method_pointer"] = hex(method_pointer)
        raw["dynasty_method_candidates"] = {
            "append_true": hex(true_method),
            "append_false": hex(false_method),
        }
        if method_pointer == true_method:
            included = True
        elif method_pointer == false_method:
            included = False
        else:
            raise _LeafFailure("dynasty_method_unrecognized")
        raw["dynasty_included_in_name"] = included

        name: dict[str, str] | None = None
        if included:
            name_address = dynasty + DYNASTY_NAME_OFFSET
            _checked_range(name_address, STRING32_SIZE, "dynasty.String32")
            header = read_exact(name_address, STRING32_SIZE, "dynasty.String32_header")
            name_raw, decoded, _ = _decode_dynasty_string32(
                read_exact, header, name_address, raw)
            if name_layout == "plugin64":
                right = b" " + name_raw
                marker_selected = _plugin64_marker_selected(name_raw)
                display_raw = name_raw[1:] if marker_selected else name_raw
                raw["plugin64_callback_right_raw_hex"] = right.hex()
                raw["plugin64_callback_right_length"] = len(right)
                raw["plugin64_marker_byte"] = hex(right[1]) if len(right) > 1 else None
                raw["plugin64_marker_selected"] = marker_selected
                raw["plugin64_callback_path"] = (
                    "dynasty_suffix_then_base" if marker_selected else "base_then_space_dynasty")
                raw["plugin64_projected_dynasty_raw_hex"] = display_raw.hex()
                if len(display_raw) > 254:
                    raw["plugin64_projected_output_length"] = len(display_raw)
                    raise _LeafFailure("NATIVE_PLUGIN_NAME_SIZE_UNSUPPORTED")
                if marker_selected:
                    decoded = _decode_projected_name(display_raw, "plugin64.dynasty_component")
                name = _name_value(display_raw, decoded)
            else:
                name = _name_value(name_raw, decoded)
        else:
            raw["dynasty_string32_read"] = False
            if name_layout == "plugin64":
                raw.update({"plugin64_callback_right_raw_hex": None,
                            "plugin64_callback_right_length": 0,
                            "plugin64_marker_byte": None,
                            "plugin64_marker_selected": False,
                            "plugin64_callback_path": "dynasty_not_appended"})

        raw["read_budget"] = budget
        return {
            "schema": SCHEMA,
            "status": "known",
            "value": {"included_in_name": included, "name": name},
            "raw_inputs": raw,
            "basis": basis,
            "full_ui_label": False,
        }
    except _LeafFailure as exc:
        raw["read_budget"] = budget
        return _unknown(str(exc), raw, basis)
    except Exception as exc:
        raw["read_budget"] = budget
        return _unknown(f"leaf_failure:{type(exc).__name__}", raw, basis)


def read_person_name(limiter: Any, base: Any, person_pointer: Any, *,
                     expected_country_fullref: Any,
                     name_layout: str = "vanilla") -> dict[str, Any]:
    """Project the bounded normal-path name component from one person object.

    ``limiter`` must expose ``read(address, size, label)``. The expected
    country reference is compared as an exact unsigned 64-bit value with the
    complete reference embedded at person+0x20. Regency-backed and unknown
    dynasty-method paths return unknown without following a regency object or
    guessing a rendered label. ``name_layout`` is an explicit caller
    attestation selector: only ``vanilla`` and ``plugin64`` are accepted; this
    leaf does not establish which layout is active.
    """
    raw: dict[str, Any] = {"read_trace": [], "read_failures": []}
    budget = {
        "calls": 0,
        "bytes_requested": 0,
        "max_single_read": 0,
        "limit_calls": MAX_READ_CALLS,
        "limit_bytes": MAX_TOTAL_READ_BYTES,
        "limit_single_read": MAX_SINGLE_READ_BYTES,
    }
    raw["read_budget"] = budget
    if not _valid_name_layout(name_layout, raw):
        return _unknown("name_layout_unsupported", raw, "unsupported_name_layout")
    basis = _basis_for_layout(name_layout)

    def read_exact(address: int, size: int, label: str) -> bytes:
        _checked_range(address, size, label)
        if size > MAX_SINGLE_READ_BYTES:
            raise _LeafFailure(f"{label}_read_size_out_of_bound")
        if budget["calls"] + 1 > MAX_READ_CALLS:
            raise _LeafFailure("read_call_budget_exceeded")
        if budget["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
            raise _LeafFailure("read_byte_budget_exceeded")
        budget["calls"] += 1
        budget["bytes_requested"] += size
        budget["max_single_read"] = max(budget["max_single_read"], size)
        row = {"address": hex(address), "size": size, "label": label}
        try:
            method = getattr(limiter, "read", None)
            if not callable(method):
                raise TypeError("limiter_read_unavailable")
            result = method(address, size, label)
            if not isinstance(result, (bytes, bytearray, memoryview)):
                raise TypeError("read_result_not_bytes")
            data = bytes(result)
            if len(data) != size:
                raise ValueError(f"short_read:{len(data)}:{size}")
        except Exception as exc:
            detail = f"{type(exc).__name__}:{str(exc)[:160]}"
            row.update({"status": "failed", "error": detail})
            raw["read_trace"].append(row)
            raw["read_failures"].append(dict(row))
            raise _LeafFailure(f"{label}_read_failed") from exc
        row.update({"status": "observed", "raw_hex": data.hex()})
        raw["read_trace"].append(row)
        return data

    def decode_string32(header: bytes, header_address: int, label: str) -> tuple[bytes, str, dict[str, Any]]:
        if len(header) != STRING32_SIZE:
            raise _LeafFailure(f"{label}_header_size_invalid")
        length = int.from_bytes(header[0x10:0x18], "little")
        capacity = int.from_bytes(header[0x18:0x20], "little")
        details: dict[str, Any] = {
            "header_address": hex(header_address),
            "header_raw_hex": header.hex(),
            "length_raw_hex": header[0x10:0x18].hex(),
            "capacity_raw_hex": header[0x18:0x20].hex(),
            "length": length,
            "capacity": capacity,
        }
        if length > MAX_STRING_LENGTH:
            raise _LeafFailure(f"{label}_length_out_of_bound")
        if capacity > MAX_STRING_CAPACITY:
            raise _LeafFailure(f"{label}_capacity_out_of_bound")
        if capacity < length:
            raise _LeafFailure(f"{label}_capacity_below_length")

        if capacity < 16:
            details["storage"] = "inline"
            if length > 15:
                raise _LeafFailure(f"{label}_inline_length_invalid")
            payload = header[:length + 1]
            details["payload_address"] = hex(header_address)
            details["payload_raw_hex"] = payload.hex()
        else:
            details["storage"] = "heap"
            pointer_raw = header[:8]
            pointer = int.from_bytes(pointer_raw, "little")
            details["heap_pointer_raw_hex"] = pointer_raw.hex()
            details["heap_pointer"] = hex(pointer) if pointer else None
            try:
                _user_pointer(pointer, f"{label}_heap_pointer")
            except _LeafFailure as exc:
                raise _LeafFailure(str(exc)) from exc
            payload = read_exact(pointer, length + 1, f"{label}.payload")
            details["payload_address"] = hex(pointer)
            details["payload_raw_hex"] = payload.hex()

        if len(payload) != length + 1 or payload[length] != 0:
            raise _LeafFailure(f"{label}_terminator_invalid")
        if b"\x00" in payload[:length]:
            raise _LeafFailure(f"{label}_embedded_nul")
        value_raw = payload[:length]
        details["value_raw_hex"] = value_raw.hex()
        try:
            decoded = decode_native_text(
                value_raw,
                codec=EU4_ESCAPE_CODEC,
                max_bytes=MAX_STRING_LENGTH,
                max_bytes_limit=MAX_STRING_LENGTH,
            )
        except NativeTextError as exc:
            details["decode_error_type"] = type(exc).__name__
            raw.setdefault("invalid_strings", {})[label] = details
            raise _LeafFailure(f"{label}_decode_invalid") from exc
        details["decoded"] = True
        raw.setdefault("strings", {})[label] = details
        return value_raw, decoded, details

    try:
        module_base = _user_pointer(_parse_u64(base, "module_base"), "module_base")
        person = _user_pointer(
            _parse_u64(person_pointer, "person_pointer", nonzero=True),
            "person_pointer", aligned=True)
        expected_ref = _parse_u64(
            expected_country_fullref, "expected_country_fullref", nonzero=True)
        raw["module_base"] = hex(module_base)
        raw["person_pointer"] = hex(person)
        raw["expected_country_fullref"] = hex(expected_ref)
        raw["expected_country_fullref_raw_hex"] = expected_ref.to_bytes(8, "little").hex()

        person_head = read_exact(person, PERSON_HEADER_SIZE, "person.header")
        raw["person_header_raw_hex"] = person_head.hex()
        vtable = int.from_bytes(person_head[:8], "little")
        country_ref_raw = person_head[PERSON_COUNTRY_FULLREF_OFFSET:PERSON_COUNTRY_FULLREF_OFFSET + 8]
        country_ref = int.from_bytes(country_ref_raw, "little")
        raw["person_vtable_raw_hex"] = person_head[:8].hex()
        raw["person_vtable"] = hex(vtable) if vtable else None
        raw["person_country_fullref_raw_hex"] = country_ref_raw.hex()
        raw["person_country_fullref"] = hex(country_ref)
        raw["person_country_fullref_matches_expected"] = country_ref == expected_ref
        if vtable == 0:
            raise _LeafFailure("person_vtable_null")
        try:
            _user_pointer(vtable, "person_vtable", aligned=True)
        except _LeafFailure as exc:
            raise _LeafFailure(str(exc)) from exc
        if country_ref != expected_ref:
            raise _LeafFailure("person_country_fullref_mismatch")

        dynasty_ptr_raw = person_head[PERSON_DYNASTY_POINTER_OFFSET:PERSON_DYNASTY_POINTER_OFFSET + 8]
        dynasty_ptr = int.from_bytes(dynasty_ptr_raw, "little")
        regency_ptr_raw = person_head[PERSON_REGENCY_POINTER_OFFSET:PERSON_REGENCY_POINTER_OFFSET + 8]
        regency_ptr = int.from_bytes(regency_ptr_raw, "little")
        raw["dynasty_pointer_raw_hex"] = dynasty_ptr_raw.hex()
        raw["dynasty_pointer"] = hex(dynasty_ptr) if dynasty_ptr else None
        raw["regency_pointer_raw_hex"] = regency_ptr_raw.hex()
        raw["regency_pointer"] = hex(regency_ptr) if regency_ptr else None
        raw["person_raw_74_hex"] = person_head[0x74:0x75].hex()
        if regency_ptr != 0:
            raise _LeafFailure("regency_name_path_unsupported")

        base_address = person + PERSON_BASE_NAME_OFFSET
        base_header = person_head[PERSON_BASE_NAME_OFFSET:PERSON_BASE_NAME_OFFSET + STRING32_SIZE]
        base_raw, base_text, base_details = decode_string32(
            base_header, base_address, "person.base_name")
        raw["base_name"] = base_details

        if dynasty_ptr == 0:
            raise _LeafFailure("dynasty_pointer_null")
        try:
            dynasty = _user_pointer(dynasty_ptr, "dynasty_pointer", aligned=True)
        except _LeafFailure as exc:
            raise _LeafFailure(str(exc)) from exc

        dynasty_vtable_raw = read_exact(dynasty, 8, "dynasty.vtable")
        dynasty_vtable = int.from_bytes(dynasty_vtable_raw, "little")
        raw["dynasty_vtable_raw_hex"] = dynasty_vtable_raw.hex()
        raw["dynasty_vtable"] = hex(dynasty_vtable) if dynasty_vtable else None
        if dynasty_vtable == 0:
            raise _LeafFailure("dynasty_vtable_null")
        try:
            _user_pointer(dynasty_vtable, "dynasty_vtable", aligned=True)
        except _LeafFailure as exc:
            raise _LeafFailure(str(exc)) from exc

        predicate_address = dynasty_vtable + DYNASTY_PREDICATE_OFFSET
        _checked_range(predicate_address, 8, "dynasty.predicate")
        predicate_raw = read_exact(predicate_address, 8, "dynasty.predicate")
        predicate = int.from_bytes(predicate_raw, "little")
        raw["dynasty_predicate_address"] = hex(predicate_address)
        raw["dynasty_predicate_raw_hex"] = predicate_raw.hex()
        true_method = module_base + DYN_APPEND_TRUE_RVA
        false_method = module_base + DYN_APPEND_FALSE_RVA
        _checked_range(true_method, 1, "dynasty.true_method")
        _checked_range(false_method, 1, "dynasty.false_method")
        raw["dynasty_method_candidates"] = {
            "append_true": hex(true_method),
            "append_false": hex(false_method),
        }
        if predicate == true_method:
            include_dynasty = True
        elif predicate == false_method:
            include_dynasty = False
        else:
            raw["dynasty_method_pointer"] = hex(predicate)
            raise _LeafFailure("dynasty_method_unrecognized")
        raw["dynasty_method_pointer"] = hex(predicate)
        raw["dynasty_included_in_name"] = include_dynasty

        dynasty_dto: dict[str, str] | None = None
        dynasty_raw = b""
        dynasty_text = ""
        if include_dynasty:
            dynasty_name_address = dynasty + DYNASTY_NAME_OFFSET
            _checked_range(dynasty_name_address, STRING32_SIZE, "dynasty.String32")
            dynasty_header = read_exact(
                dynasty_name_address, STRING32_SIZE, "dynasty.String32_header")
            dynasty_raw, dynasty_text, dynasty_details = decode_string32(
                dynasty_header, dynasty_name_address, "dynasty.name")
            raw["dynasty_name"] = dynasty_details
            dynasty_dto = _name_value(dynasty_raw, dynasty_text)
        else:
            raw["dynasty_name_read"] = False

        if name_layout == "plugin64":
            if include_dynasty:
                callback_right = b" " + dynasty_raw
                marker_selected = _plugin64_marker_selected(dynasty_raw)
                raw["plugin64_callback_right_raw_hex"] = callback_right.hex()
                raw["plugin64_callback_right_length"] = len(callback_right)
                raw["plugin64_marker_byte"] = (
                    hex(callback_right[1]) if len(callback_right) > 1 else None)
                raw["plugin64_marker_selected"] = marker_selected
                raw["plugin64_callback_path"] = (
                    "dynasty_suffix_then_base" if marker_selected else "base_then_space_dynasty")
                if marker_selected:
                    projected_dynasty = dynasty_raw[1:]
                    raw["plugin64_projected_dynasty_raw_hex"] = projected_dynasty.hex()
                    projected_dynasty_text = _decode_projected_name(
                        projected_dynasty, "plugin64.dynasty_component")
                    dynasty_dto = _name_value(projected_dynasty, projected_dynasty_text)
                    combined_raw = projected_dynasty + base_raw
                else:
                    raw["plugin64_projected_dynasty_raw_hex"] = dynasty_raw.hex()
                    combined_raw = base_raw + callback_right
            else:
                raw.update({"plugin64_callback_right_raw_hex": None,
                            "plugin64_callback_right_length": 0,
                            "plugin64_marker_byte": None,
                            "plugin64_marker_selected": False,
                            "plugin64_callback_path": "dynasty_not_appended",
                            "plugin64_projected_dynasty_raw_hex": None})
                combined_raw = base_raw
            raw["plugin64_base_cached_raw_hex"] = base_raw.hex()
            raw["plugin64_dynasty_cached_raw_hex"] = dynasty_raw.hex() if include_dynasty else None
            raw["plugin64_native_callback_invoked"] = False
            raw["plugin64_output_length"] = len(combined_raw)
            raw["plugin64_output_max_bytes"] = 254
            if len(combined_raw) > 254:
                raise _LeafFailure("NATIVE_PLUGIN_NAME_SIZE_UNSUPPORTED")
        else:
            combined_raw = base_raw + (b" " + dynasty_raw if include_dynasty else b"")
        try:
            combined_text = decode_native_text(
                combined_raw,
                codec=EU4_ESCAPE_CODEC,
                max_bytes=MAX_STRING_LENGTH * 2 + 1,
                max_bytes_limit=MAX_STRING_LENGTH * 2 + 1,
            )
        except NativeTextError as exc:
            raw["combined_decode_error_type"] = type(exc).__name__
            raise _LeafFailure("combined_name_decode_invalid") from exc
        raw["combined_name_raw_hex"] = combined_raw.hex()
        raw["combined_name_decoded"] = True
        raw["read_budget"] = budget
        return {
            "schema": SCHEMA,
            "status": "known",
            "value": _name_value(combined_raw, combined_text),
            "base_name": _name_value(base_raw, base_text),
            "dynasty": {
                "included_in_name": include_dynasty,
                "name": dynasty_dto,
            },
            "raw_inputs": raw,
            "basis": basis,
            "full_ui_label": False,
        }
    except _LeafFailure as exc:
        raw["read_budget"] = budget
        return _unknown(str(exc), raw, basis)
    except Exception as exc:
        raw["read_budget"] = budget
        return _unknown(f"leaf_failure:{type(exc).__name__}", raw, basis)


__all__ = ["read_dynasty_component", "read_person_name"]
