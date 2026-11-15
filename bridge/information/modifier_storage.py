"""Raw modifier dictionary lookup for explicitly qualified typed processors.

The object-address API is shared by readers that already resolved a modifier
object. The country API below keeps its legacy inline-country binding and
trace contract. These helpers read raw storage only; they neither check nor
execute a modifier processor. The caller must qualify the processor and
interpret the returned raw value itself.
"""
from typing import Any

from .foreign_quality_memory import (
    _add, _valid_pointer, _Failure, _known_component, _empty_component,
    _component_read_slice, COUNTRY_MODIFIER_OBJECT_OFFSET,
    MODIFIER_DENSE_FLAG_OFFSET, MODIFIER_VALUES_POINTER_OFFSET,
    MODIFIER_SPARSE_COUNT_OFFSET, MAX_SPARSE_ENTRIES, SPARSE_CHUNK_BYTES,
)


MAX_MODIFIER_ID = 0x286


def _empty_result(trace, start, inputs, exc, name):
    reason = exc.reason if isinstance(exc, _Failure) else f"READ_FAILED:{name}"
    inputs["reads"] = _component_read_slice(trace, start)
    return _empty_component(reason, inputs)


def _read_modifier_object_core(trace, modifier_object, modifier_id, unit, *,
                                name, forbidden_pointers, start, inputs,
                                validate_object, validate_id, country_pointer=None):
    try:
        if validate_id and (type(modifier_id) is not int
                            or not 0 <= modifier_id <= MAX_MODIFIER_ID):
            raise _Failure("MODIFIER_ID_INVALID")
        if validate_object:
            modifier = _valid_pointer(modifier_object, "MODIFIER_OBJECT")
        else:
            # The country wrapper already applied its legacy checked addition,
            # which intentionally does not impose a new alignment rule.
            modifier = modifier_object

        dense_address = _add(modifier, MODIFIER_DENSE_FLAG_OFFSET, 1)
        values_cell = _add(modifier, MODIFIER_VALUES_POINTER_OFFSET, 8)
        count_address = _add(modifier, MODIFIER_SPARSE_COUNT_OFFSET, 4)
        dense_flag = trace.u8(dense_address, f"modifier_storage.{name}.dense_flag_u8")
        values_pointer = trace.u64(values_cell, f"modifier_storage.{name}.values_pointer")
        count = trace.u32(count_address, f"modifier_storage.{name}.sparse_count_u32")
        inputs.update({"dense_flag_address": hex(dense_address), "dense_flag": dense_flag,
                       "values_pointer_cell": hex(values_cell),
                       "values_pointer": hex(values_pointer),
                       "count_address": hex(count_address), "count": count})
        if dense_flag not in (0, 1):
            raise _Failure("MODIFIER_DENSE_FLAG_INVALID")
        if count > MAX_SPARSE_ENTRIES:
            raise _Failure("MODIFIER_COUNT_OUT_OF_RANGE")

        if dense_flag == 1:
            values = _valid_pointer(values_pointer, "MODIFIER_VALUES")
            if values in (country_pointer, modifier, *forbidden_pointers):
                raise _Failure("MODIFIER_VALUES_POINTER_ALIAS")
            value_address = _add(values, modifier_id * 8 + 4, 4)
            value = trace.i32(value_address, f"modifier_storage.{name}.dense_value_i32")
            inputs.update({"mode": "dense", "storage_address": hex(value_address),
                           "storage_raw_hex": trace.reads[-1]["raw_hex"],
                           "first_match_index": None, "modifier_raw": value})
            return _known_component(value, value, unit, 1000, inputs)

        if count == 0:
            inputs.update({"mode": "sparse", "first_match_index": None,
                           "entries_examined": [], "blocks": []})
            return _known_component(0, 0, unit, 1000, inputs)
        values = _valid_pointer(values_pointer, "MODIFIER_VALUES")
        if values in (country_pointer, modifier, *forbidden_pointers):
            raise _Failure("MODIFIER_VALUES_POINTER_ALIAS")
        blocks: list[dict[str, Any]] = []
        examined: list[dict[str, Any]] = []
        first_index: int | None = None
        modifier_raw = 0
        index = 0
        max_entries_per_chunk = SPARSE_CHUNK_BYTES // 8
        while index < count:
            chunk_entries = min(max_entries_per_chunk, count - index)
            chunk_address = _add(values, index * 8, chunk_entries * 8)
            chunk = trace.exact(chunk_address, chunk_entries * 8,
                                f"modifier_storage.{name}.sparse_entries[{index}:{index + chunk_entries}]")
            blocks.append({"start_index": index, "entry_count": chunk_entries,
                           "address": hex(chunk_address), "raw_hex": chunk.hex()})
            for within in range(chunk_entries):
                entry_index = index + within
                raw_entry = chunk[within * 8:(within + 1) * 8]
                entry_id = int.from_bytes(raw_entry[:4], "little", signed=True)
                entry_value = int.from_bytes(raw_entry[4:], "little", signed=True)
                examined.append({"index": entry_index, "id": entry_id,
                                 "id_raw_hex": raw_entry[:4].hex(),
                                 "value": entry_value,
                                 "value_raw_hex": raw_entry[4:].hex()})
                if entry_id == modifier_id:
                    first_index = entry_index
                    modifier_raw = entry_value
                    break
            if first_index is not None:
                break
            index += chunk_entries
        inputs.update({"mode": "sparse", "storage_address": hex(values),
                       "first_match_index": first_index,
                       "modifier_raw": modifier_raw,
                       "entries_examined": examined, "blocks": blocks})
        return _known_component(modifier_raw, modifier_raw, unit, 1000, inputs)
    except Exception as exc:
        return _empty_result(trace, start, inputs, exc, name)
    finally:
        inputs["reads"] = _component_read_slice(trace, start)


def read_raw_modifier_object(trace, modifier_object, modifier_id, unit, *, name,
                              forbidden_pointers=()):
    """Read one raw dense/sparse value from a validated modifier object address.

    IDs are native indexed-storage keys in the closed range 0..0x286. This
    function does not inspect or execute the object's processor; callers remain
    responsible for validating processor semantics before using this raw value.
    """
    start = len(trace.reads)
    inputs = {"modifier_id": modifier_id, "semantics": "raw_storage_only",
              "modifier_object_storage": "explicit_address"}
    return _read_modifier_object_core(
        trace, modifier_object, modifier_id, unit, name=name,
        forbidden_pointers=forbidden_pointers, start=start, inputs=inputs,
        validate_object=True, validate_id=True,
    )


def read_raw_modifier(trace, country_pointer, modifier_id, unit, *, name,
                      forbidden_pointers=()):
    """Read raw storage through the legacy inline country modifier object.

    The country address remains the binding input. It is never synthesized by
    subtracting an inline-object offset from a modifier-object address.
    """
    start = len(trace.reads)
    inputs = {"modifier_id": modifier_id, "semantics": "raw_storage_only",
              "modifier_object_storage": "inline"}
    try:
        modifier_object = _add(country_pointer, COUNTRY_MODIFIER_OBJECT_OFFSET, 0x68)
    except Exception as exc:
        return _empty_result(trace, start, inputs, exc, name)
    return _read_modifier_object_core(
        trace, modifier_object, modifier_id, unit, name=name,
        forbidden_pointers=forbidden_pointers, start=start, inputs=inputs,
        validate_object=False, validate_id=False, country_pointer=country_pointer,
    )
