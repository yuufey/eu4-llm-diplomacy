"""Offline tests for shared selected-country binding and field collection."""
from __future__ import annotations

import pytest

from bridge.information import country_reference_memory
from bridge.information import foreign_country_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
TABLE = 0x6300000000
COUNTRY_BASE = 0x6400000000
OBSERVER_SLOT = 189


def fullref(tag: str, slot: int, generation: int = 0) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.overrides: dict[tuple[int, int], list[bytes]] = {}
        self.override_counts: dict[tuple[int, int], int] = {}
        self.short_at: set[int] = set()
        self.fail_at: set[int] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.bytes.update({address + index: value for index, value in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_country(self, slot: int, tag: str, generation: int, value: int) -> int:
        pointer = COUNTRY_BASE + slot * 0x1000
        self.put_u64(TABLE + slot * 8, pointer)
        self.put_u64(pointer + country_reference_memory.COUNTRY_FULLREF_OFFSET,
                     fullref(tag, slot, generation))
        self.put_i32(pointer + 0x80, value)
        return pointer

    def queue_reads(self, address: int, size: int, *raw_values: bytes) -> None:
        self.overrides[(address, size)] = list(raw_values)

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.fail_at:
            raise OSError("synthetic read failure")
        key = (address, size)
        if key in self.overrides:
            index = self.override_counts.get(key, 0)
            self.override_counts[key] = index + 1
            values = self.overrides[key]
            raw = values[min(index, len(values) - 1)]
        else:
            raw = bytes(self.bytes.get(address + index, 0) for index in range(size))
        return raw[:-1] if address in self.short_at else raw


def make_image(*, count: int = 301, observer_generation: int = 0x1234,
               target_generation: int = 0x4567,
               observer_value: int = 11, target_value: int = 22) -> MemoryImage:
    image = MemoryImage()
    image.put_u64(MODULE_BASE + country_reference_memory.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + country_reference_memory.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + country_reference_memory.DATABASE_TABLE_COUNT_OFFSET, count)
    image.put_country(OBSERVER_SLOT, "FRA", observer_generation, observer_value)
    image.put_country(300, "ENG", target_generation, target_value)
    return image


def admission_reader(_read, _base, bindings, observer, target):
    return {
        "status": "known",
        "admitted": True,
        "observer": observer,
        "target": target,
        "raw_operands": [bindings["requested"][target]["fullref_raw_hex"]],
    }


def field_reader(limiter, _base, binding, fields):
    pointer = int(binding["country_pointer"], 16)
    output = {}
    for index, field in enumerate(fields):
        address = pointer + 0x80 + index * 4
        raw = limiter.read(address, 4, f"test.field.{field}")
        output[field] = {
            "status": "known",
            "value": int.from_bytes(raw, "little", signed=True),
            "state": {"address": hex(address)},
            "raw_inputs": {"raw_hex": raw.hex()},
        }
    return output


def call(image, targets=("ENG",), fields=("F01.a", "F01.b"), **kwargs):
    return memory.read_two_pass(
        image, MODULE_BASE, "FRA", list(targets), list(fields),
        read_fields=kwargs.pop("read_fields", field_reader),
        admission_reader=kwargs.pop("admission_reader", admission_reader),
        **kwargs,
    )


def target_record(result, tag="ENG"):
    return next(item for item in result["targets"] if item["tag"] == tag)


def test_targets_over_256_keep_distinct_values_and_self_target_is_resolved_once():
    image = make_image(count=301)
    result = call(image, targets=("FRA", "ENG"), fields=("S04.ruler",),
                  expected_refs={"FRA": fullref("FRA", OBSERVER_SLOT, 0x1234)})

    own = target_record(result, "FRA")
    foreign = target_record(result, "ENG")
    assert result["status"] == "observed"
    assert result["consistency"] == {"status": "stable", "shared_mismatch_paths": []}
    assert own["bindings_by_pass"]["pass1"]["slot"] == OBSERVER_SLOT
    assert foreign["bindings_by_pass"]["pass2"]["slot"] == 300
    assert own["fields"]["S04.ruler"]["value"] == 11
    assert foreign["fields"]["S04.ruler"]["value"] == 22
    # Each pass resolves FRA once although it is both observer and target.
    assert sum(label == f"country_reference.slot[{OBSERVER_SLOT}].pointer"
               for _, _, label in image.reads) == 2
    assert result["observer"]["fullref"] == hex(fullref("FRA", OBSERVER_SLOT, 0x1234))
    assert result["complete"] is False
    assert result["public_export_ready"] is False
    assert result["visibility"]["status"] == "unknown"


def test_one_changed_field_is_retracted_without_losing_stable_field():
    image = make_image()
    pointer = COUNTRY_BASE + 300 * 0x1000
    image.queue_reads(pointer + 0x80, 4,
                      (22).to_bytes(4, "little", signed=True),
                      (23).to_bytes(4, "little", signed=True))

    result = call(image, fields=("F01.a", "F01.b"))
    target = target_record(result)
    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert target["fields"]["F01.a"] == {
        "status": "unknown", "reason": "field_raw_data_changed"
    }
    assert target["field_consistency"]["F01.a"]["status"] == "changed"
    assert target["fields"]["F01.b"]["status"] == "known"
    assert target["fields"]["F01.b"]["value"] == 0


def test_same_value_but_changed_raw_inputs_retract_only_that_field():
    image = make_image()
    calls = {"n": 0}

    def collector(limiter, base, binding, fields):
        calls["n"] += 1
        result = field_reader(limiter, base, binding, fields)
        result["F01.a"]["state"]["source_generation"] = calls["n"]
        return result

    result = call(image, fields=("F01.a", "F01.b"), read_fields=collector)
    target = target_record(result)
    assert target["fields"]["F01.a"]["status"] == "unknown"
    assert target["field_consistency"]["F01.a"]["status"] == "changed"
    assert target["fields"]["F01.b"]["status"] == "known"


def test_raw_dictionary_comparison_distinguishes_bool_from_int():
    image = make_image()
    calls = {"n": 0}

    def collector(limiter, base, binding, fields):
        calls["n"] += 1
        result = field_reader(limiter, base, binding, fields)
        result["F01.a"]["value"] = True if calls["n"] == 1 else 1
        return result

    result = call(image, fields=("F01.a", "F01.b"), read_fields=collector)
    target = target_record(result)
    assert target["fields"]["F01.a"] == {
        "status": "unknown", "reason": "field_raw_data_changed"
    }
    assert target["fields"]["F01.b"]["status"] == "known"


def test_collector_field_unknown_does_not_hide_known_peer():
    image = make_image()

    def collector(limiter, base, binding, fields):
        raw = field_reader(limiter, base, binding, fields)
        raw["F01.a"] = {"status": "unknown", "reason": "field_specific_missing"}
        return raw

    result = call(image, fields=("F01.a", "F01.b"), read_fields=collector)
    target = target_record(result)
    assert target["fields"]["F01.a"] == {
        "status": "unknown", "reason": "field_specific_missing"
    }
    assert target["field_consistency"]["F01.a"]["status"] == "unknown"
    assert target["fields"]["F01.b"]["status"] == "known"


def test_country_fullref_generation_change_retracts_every_field():
    image = make_image()
    pointer = COUNTRY_BASE + 300 * 0x1000
    address = pointer + country_reference_memory.COUNTRY_FULLREF_OFFSET
    image.queue_reads(
        address, 8,
        fullref("ENG", 300, 0x4567).to_bytes(8, "little"),
        fullref("ENG", 300, 0x5678).to_bytes(8, "little"),
    )

    result = call(image)
    target = target_record(result)
    assert result["status"] == "unknown"
    assert result["consistency"]["status"] == "changed"
    assert target["fields"]["F01.a"]["status"] == "unknown"
    assert target["fields"]["F01.b"]["status"] == "unknown"
    assert any("country_scan" in path for path in result["consistency"]["shared_mismatch_paths"])
    assert target["fullref"] is None


def test_admission_change_retracts_every_target_field_and_stops_commit():
    image = make_image()
    admission_calls = {"n": 0}
    collector_calls = {"n": 0}

    def changing_gate(_read, _base, _bindings, observer, target):
        admission_calls["n"] += 1
        return {"status": "known", "admitted": admission_calls["n"] == 1,
                "observer": observer, "target": target,
                "raw_operands": [admission_calls["n"]]}

    def collector(*args):
        collector_calls["n"] += 1
        return field_reader(*args)

    result = call(image, read_fields=collector, admission_reader=changing_gate)
    target = target_record(result)
    assert result["status"] == "unknown"
    assert result["consistency"]["status"] == "changed"
    assert target["fields"]["F01.a"]["status"] == "unknown"
    assert collector_calls["n"] == 1


def test_denied_or_unknown_admission_never_calls_field_collector():
    image = make_image()
    calls = {"collector": 0}

    def denied(_read, _base, _bindings, observer, target):
        return {"status": "known", "admitted": False,
                "observer": observer, "target": target}

    def forbidden(*_args):
        calls["collector"] += 1
        raise AssertionError("field collector must not run behind denied gate")

    result = call(image, read_fields=forbidden, admission_reader=denied)
    target = target_record(result)
    assert calls["collector"] == 0
    assert target["fields"]["F01.a"] == {"status": "invisible", "reason": "admission_denied"}

    result = call(image, read_fields=forbidden,
                  admission_reader=lambda *_: {"status": "unknown", "admitted": True})
    target = target_record(result)
    assert calls["collector"] == 0
    assert target["fields"]["F01.a"]["status"] == "unknown"


def test_collector_exception_and_missing_or_invalid_field_are_local():
    image = make_image()
    calls = {"n": 0}

    def partly_failing(limiter, base, binding, fields):
        tag = binding["tag"]
        if tag == "ENG":
            raise RuntimeError("private collector failed")
        calls["n"] += 1
        return {
            "F01.a": {"status": "known"},  # known without a value is rejected
            # F01.b is missing and must remain unknown without hiding other tags.
        }

    result = call(image, targets=("ENG", "FRA"), fields=("F01.a", "F01.b"),
                  read_fields=partly_failing)
    eng = target_record(result, "ENG")
    fra = target_record(result, "FRA")
    assert eng["fields"]["F01.a"]["status"] == "unknown"
    assert eng["fields"]["F01.b"]["status"] == "unknown"
    assert fra["fields"]["F01.a"]["status"] == "unknown"
    assert fra["fields"]["F01.b"]["status"] == "unknown"
    assert calls["n"] == 2
    assert any(error["code"] == "field_collector_failed" for error in result["errors"])


def test_total_budget_is_shared_across_passes_and_fail_closed():
    image = make_image()

    def exhaust(limiter, _base, _binding, _fields):
        for index in range(16):
            limiter.read(0x7000000000 + index * memory.MAX_SINGLE_READ_BYTES,
                         memory.MAX_SINGLE_READ_BYTES, f"budget.{index}")
        return {"F01.a": {"status": "known", "value": 1}}

    result = call(image, fields=("F01.a",), read_fields=exhaust)
    assert result["budget"]["bytes_requested"] <= memory.MAX_TOTAL_READ_BYTES
    assert result["budget"]["rejected_bytes"] > 0
    assert result["targets"][0]["fields"]["F01.a"]["status"] == "unknown"
    assert any(error["code"] == "read_budget_exceeded" for error in result["errors"])


def test_duplicate_input_and_invalid_known_gate_are_rejected():
    image = make_image()
    duplicate = memory.read_two_pass(
        image, MODULE_BASE, "FRA", ["ENG", "ENG"], ["F01.a"],
        read_fields=field_reader, admission_reader=admission_reader,
    )
    assert duplicate["status"] == "unknown"
    assert duplicate["errors"][0]["code"] == "invalid_request"

    result = call(image, admission_reader=lambda *_: {"status": "known", "admitted": 1})
    assert target_record(result)["fields"]["F01.a"]["status"] == "unknown"
    assert target_record(result)["admission_by_pass"]["pass1"]["status"] == "unknown"

