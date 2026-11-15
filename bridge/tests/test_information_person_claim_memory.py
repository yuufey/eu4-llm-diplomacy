from __future__ import annotations

import pytest

from bridge.information import person_claim_memory as claims


BASE = 0x140000000
PERSON = 0x200000
VTABLE = 0x300000
WEAK_ADDRESS = BASE + claims.WEAK_THRESHOLD_RVA
STRONG_ADDRESS = BASE + claims.STRONG_THRESHOLD_RVA
GETTER = BASE + claims.PERSON_CLAIM_GETTER_RVA


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


class FakeLimiter:
    def __init__(self, regions: dict[int, bytes], *, fail_labels: set[str] | None = None,
                 short_labels: set[str] | None = None):
        self.regions = dict(regions)
        self.fail_labels = set(fail_labels or ())
        self.short_labels = set(short_labels or ())
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture read failure: {label}")
        for start, data in self.regions.items():
            offset = address - start
            if offset >= 0 and offset + size <= len(data):
                result = data[offset:offset + size]
                if label in self.short_labels:
                    return result[:-1]
                return result
        raise OSError(f"fixture unmapped read: {label}")


def _fixture(*, raw: int = 0, weak: int = 0, strong: int = 100,
             method: int | None = None, person_pointer: int = PERSON,
             vtable: int = VTABLE, fail_labels: set[str] | None = None,
             short_labels: set[str] | None = None) -> FakeLimiter:
    getter = GETTER if method is None else method
    return FakeLimiter({
        PERSON: vtable.to_bytes(8, "little"),
        PERSON + claims.PERSON_CLAIM_RAW_OFFSET: _i32(raw),
        VTABLE + claims.PERSON_CLAIM_GETTER_VTABLE_OFFSET: getter.to_bytes(8, "little"),
        WEAK_ADDRESS: _i32(weak),
        STRONG_ADDRESS: _i32(strong),
    }, fail_labels=fail_labels, short_labels=short_labels)


def _read(reader: FakeLimiter, *, base: int = BASE, person: int = PERSON):
    return claims.read_claim(reader, base, person)


@pytest.mark.parametrize(
    ("raw", "weak", "strong", "category"),
    [
        (-11, -10, -1, "weak"),
        (-10, -10, -1, "average"),
        (-1, -10, -1, "strong"),
        (-1, 0, 10, "weak"),
        (0, 0, 10, "average"),
        (10, 0, 10, "strong"),
    ],
)
def test_signed_claim_and_exact_formatter_boundaries(raw, weak, strong, category):
    result = _read(_fixture(raw=raw, weak=weak, strong=strong))
    assert result["status"] == "known"
    assert result["value"] == {
        "raw": raw,
        "scale": 1000,
        "category": category,
        "weak_threshold_raw": weak,
        "strong_threshold_raw": strong,
    }
    assert result["raw_inputs"]["claim_raw_i32_hex"] == _i32(raw).hex()
    assert result["raw_inputs"]["weak_threshold_raw_hex"] == _i32(weak).hex()
    assert result["raw_inputs"]["strong_threshold_raw_hex"] == _i32(strong).hex()


def test_inverted_thresholds_keep_native_if_else_order_without_reordering():
    weak = _read(_fixture(raw=99, weak=100, strong=-100))
    boundary = _read(_fixture(raw=100, weak=100, strong=-100))
    assert weak["value"]["category"] == "weak"
    # The second branch is raw < strong only after the first branch fails.
    assert boundary["value"]["category"] == "strong"
    assert boundary["value"]["weak_threshold_raw"] == 100
    assert boundary["value"]["strong_threshold_raw"] == -100


def test_zero_and_large_fixed_point_raw_value_remain_unrounded():
    zero = _read(_fixture(raw=0, weak=-1, strong=1))
    assert zero["status"] == "known"
    assert zero["value"]["raw"] == 0
    assert zero["value"]["scale"] == 1000
    assert zero["value"]["category"] == "average"

    large = _read(_fixture(raw=100000, weak=-100000, strong=100000))
    assert large["status"] == "known"
    assert large["value"]["raw"] == 100000
    assert large["value"]["category"] == "strong"


def test_unknown_vtable_method_is_unknown_and_does_not_read_claim_or_thresholds():
    reader = _fixture(method=BASE + 0x123456)
    result = _read(reader)
    assert result["status"] == "unknown"
    assert result["reason"] == "person_claim_getter_unrecognized"
    assert "value" not in result
    assert result["raw_inputs"]["claim_getter_pointer"] == hex(BASE + 0x123456)
    assert not any(label in {"person.claim_raw", "claim.weak_threshold", "claim.strong_threshold"}
                   for _, _, label in reader.reads)


@pytest.mark.parametrize(
    ("label", "short"),
    [
        ("person.vtable_pointer", False),
        ("person.claim_getter_slot", True),
        ("person.claim_raw", False),
        ("claim.weak_threshold", True),
        ("claim.strong_threshold", False),
    ],
)
def test_read_exception_or_short_read_fails_closed_and_keeps_ordered_evidence(label, short):
    reader = _fixture(
        fail_labels=set() if short else {label},
        short_labels={label} if short else set(),
    )
    result = _read(reader)
    assert result["status"] == "unknown"
    assert "_read_failed" in result["reason"]
    assert "value" not in result
    assert result["raw_inputs"]["read_failures"][-1]["label"] == label
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] == sum(
        size for _, size, _ in reader.reads)


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"person_pointer": 0}, "person_pointer_out_of_range"),
        ({"person_pointer": 7}, "person_pointer_invalid"),
        ({"vtable": 0}, "person_vtable_null"),
        ({"vtable": 7}, "person_vtable_pointer_invalid"),
    ],
)
def test_null_or_invalid_object_pointers_are_unknown(kwargs, reason):
    reader = _fixture(**kwargs)
    result = _read(reader, person=kwargs.get("person_pointer", PERSON))
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "value" not in result


def test_bad_global_range_is_unknown_and_budget_stays_small():
    reader = _fixture()
    result = _read(reader, base=0x00007FFFFFFFF000)
    assert result["status"] == "unknown"
    assert "range_out_of_bounds" in result["reason"] or "_read_failed" in result["reason"]
    assert result["raw_inputs"]["read_budget"]["calls"] <= 8
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] <= 64


def test_success_trace_is_ordered_and_within_leaf_budget():
    reader = _fixture(raw=123, weak=0, strong=500)
    result = _read(reader)
    assert result["status"] == "known"
    trace = result["raw_inputs"]["read_trace"]
    assert [item["label"] for item in trace] == [
        "person.vtable_pointer",
        "person.claim_getter_slot",
        "person.claim_raw",
        "claim.weak_threshold",
        "claim.strong_threshold",
    ]
    assert result["raw_inputs"]["read_budget"]["calls"] == 5
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] == 28
    assert result["raw_inputs"]["read_budget"]["max_single_read"] == 8
