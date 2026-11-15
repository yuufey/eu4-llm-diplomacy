"""Literal memory images for the private forecast input boundary."""
import struct

import pytest

from bridge.information import bankruptcy_forecast_memory as memory

BASE = 0x140000000
OBSERVER = 0x50000000
TARGET = 0x50010000
MANAGER = 0x60000000
VALUES = 0x61000000
NODES = 0x70000000
RECORDS = 0x71000000


class Image:
    def __init__(self):
        self.data = {}
        self.calls = []
        self.drift = {}

    def put(self, address, raw):
        self.data.update({address + i: v for i, v in enumerate(raw)})

    def i32(self, address, value):
        self.put(address, struct.pack("<i", value))

    def u64(self, address, value):
        self.put(address, struct.pack("<Q", value))

    def read(self, address, size, label):
        self.calls.append((address, size, label))
        if label in self.drift:
            return self.drift[label]
        return bytes(self.data[address + i] for i in range(size))


def binding(tag, slot, pointer):
    ref = (0x1234 << 48) | (slot << 32) | int.from_bytes(tag.encode(), "little")
    return {"tag": tag, "slot": slot, "country_pointer": hex(pointer),
            "country_fullref_address": hex(pointer + 0x20), "fullref": hex(ref),
            "fullref_raw_hex": ref.to_bytes(8, "little").hex(),
            "table_entry_address": hex(0x62000000 + slot * 8),
            "table_entry_raw_hex": pointer.to_bytes(8, "little").hex()}


def environment(count=0):
    image = Image()
    observer = binding("FRA", 122, OBSERVER)
    target = binding("ENG", 46, TARGET)
    for item in (observer, target):
        image.u64(int(item["country_pointer"], 0) + 0x20, int(item["fullref"], 0))
    # Literal byte layout, intentionally independent of implementation constants.
    for offset in (0x770, 0x774, 0x778, 0x77C, 0x780, 0x784, 0x788, 0x78C,
                   0x790, 0x7AC, 0x7B0, 0x7B4, 0x7B8, 0x7BC, 0x7C4, 0x7C8,
                   0x7CC, 0x7D0, 0x7D4, 0x7D8, 0x7DC, 0x7E0, 0x7E4,
                   0x824, 0x828, 0x834):
        image.i32(TARGET + offset, 0)
    image.i32(TARGET + 0x7BC, 1000)
    image.i32(TARGET + 0xBB0, 0)
    image.put(TARGET + 0x1105, b"\x01")
    image.i32(TARGET + 0xE3C, 1000)
    image.u64(TARGET + 0xDE8, NODES if count else 0)
    image.i32(TARGET + 0xDF8, count)
    for index in range(count):
        node = NODES + index * 0x100
        record = RECORDS + index * 0x100
        following = node + 0x100 if index + 1 < count else 0
        image.put(node, struct.pack("<QQQ", record, 0xAAAAAAAAAAAAAAAA, following))
        image.put(record + 0x27, b"\x00")
        image.i32(record + 0x28, 1000)
        image.i32(record + 0x2C, 0)
        image.put(record + 0x35, b"\x00")
    image.i32(BASE + 0x233E128, 1000)
    image.i32(BASE + 0x233E124, 0)
    image.i32(TARGET + 0x28C8, 0)
    image.put(TARGET + 0x28E0, b"\x01")
    image.u64(TARGET + 0x2928, VALUES)
    image.i32(VALUES + 0xF4, 0)
    image.u64(BASE + 0x2358060, MANAGER)
    image.u64(MANAGER + 0xB80, 0)
    return image, observer, target


def run(env):
    return memory.read_state(env[0], BASE, env[1], env[2])


def assert_unknown(result):
    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["publication_admitted"] is False
    assert result["native_fp_environment_verified"] is False


def test_literal_deficit_captures_three_month_private_model():
    result = run(environment())
    assert result["status"] == "known", result.get("reason")
    assert result["value"]["months_raw_i32"] == 3
    assert result["value"]["warning"] is True
    assert result["publication_admitted"] is False
    assert result["visibility"]["status"] == "unknown"
    assert result["native_execution_observed"] is False
    assert result["native_fp_environment_verified"] is False


def test_two_epochs_do_not_disclose_unused_loan_identity_or_date_words():
    env = environment(1)
    result = run(env)
    assert result["status"] == "known", result.get("reason")
    loan_reads = [(a, n) for a, n, _ in env[0].calls if RECORDS <= a < RECORDS + 0x100]
    assert loan_reads == [(RECORDS + 0x27, 1), (RECORDS + 0x28, 4),
                          (RECORDS + 0x2C, 4), (RECORDS + 0x35, 1)] * 2
    node_reads = [(a, n) for a, n, _ in env[0].calls if NODES <= a < NODES + 0x100]
    assert node_reads == [(NODES, 8), (NODES + 0x10, 8)] * 2


def test_maximum_list_fits_bound_and_exhausted_capacity_is_imminent():
    result = run(environment(64))
    assert result["status"] == "known", result.get("reason")
    assert result["value"]["months_raw_i32"] == 0
    assert result["value"]["imminent"] is True
    budget = result["raw_inputs"]["read_budget"]
    assert budget["calls"] <= 1024
    assert budget["bytes_requested"] <= 65536


@pytest.mark.parametrize("offset,raw", [(0xDF8, struct.pack("<i", 65)),
                                        (0xDF8, struct.pack("<i", -1)),
                                        (0xDE8, struct.pack("<Q", NODES))])
def test_invalid_header_is_rejected_before_ledger_reads(offset, raw):
    env = environment()
    env[0].put(TARGET + offset, raw)
    result = run(env)
    assert_unknown(result)
    assert not any("ledger" in label for _, _, label in env[0].calls)


def test_cycle_does_not_loop_or_return_partial_value():
    env = environment(2)
    env[0].u64(NODES + 0x10, NODES)
    result = run(env)
    assert_unknown(result)
    assert result["reason"] == "LOAN_NODE_CYCLE"


def test_duplicate_payload_is_rejected():
    env = environment(2)
    env[0].u64(NODES + 0x100, RECORDS)
    result = run(env)
    assert_unknown(result)
    assert result["reason"] == "LOAN_RECORD_DUPLICATE"


@pytest.mark.parametrize("label,raw", [
    ("after.ledger.7bc", struct.pack("<i", 1001)),
    ("after.loan_count", struct.pack("<i", 0)),
    ("after.loan.0.principal", struct.pack("<i", 1)),
    ("after.treasury", struct.pack("<i", 10)),
])
def test_changed_input_or_path_retracts_entire_model(label, raw):
    env = environment(1)
    env[0].drift[label] = raw
    result = run(env)
    assert_unknown(result)


def test_changed_observer_identity_retracts_even_equal_arithmetic():
    env = environment()
    env[0].drift["after.observer.fullref"] = b"\x00" * 8
    result = run(env)
    assert_unknown(result)
    assert result["reason"] == "OBSERVER_FULLREF_ECHO_MISMATCH"


def test_equal_ledger_total_cannot_hide_offsetting_source_changes():
    env = environment()
    env[0].drift["after.ledger.770"] = struct.pack("<i", 1)
    env[0].drift["after.ledger.774"] = struct.pack("<i", -1)
    result = run(env)
    assert_unknown(result)
    assert result["reason"] == "FORECAST_INPUTS_CHANGED_AFTER_READ"


def test_nonempty_processor_never_enters_native_callback():
    env = environment()
    env[0].u64(MANAGER + 0xB80, 0x72000000)
    result = run(env)
    assert_unknown(result)
    assert result["reason"].startswith("HELPER_UNAVAILABLE:")
    assert not any(0x72000000 <= a < 0x72001000 for a, _, _ in env[0].calls)


def test_alias_binding_does_not_read_memory():
    env = environment()
    result = memory.read_state(env[0], BASE, env[1], env[1])
    assert_unknown(result)
    assert env[0].calls == []


def test_short_read_retracts_model():
    env = environment()
    env[0].drift["before.treasury"] = b"\x00" * 3
    result = run(env)
    assert_unknown(result)
    assert result["reason"] == "READ_FAILED:before.treasury"


def test_invalid_native_integer_conversion_never_becomes_published_imminence():
    env = environment()
    env[0].i32(TARGET + 0x770, 110_000_000)
    env[0].i32(TARGET + 0x7BC, 110_000_051)
    env[0].i32(BASE + 0x233E128, 1200)
    env[0].i32(TARGET + 0xE3C, 1_100_000)
    result = run(env)
    assert_unknown(result)
    assert result["reason"] == "NATIVE_FLOAT_CONVERSION_INVALID"
