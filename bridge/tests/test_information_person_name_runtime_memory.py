"""Bounded tests for person-name runtime patch/plugin layout classification."""
from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from bridge.information import person_name_runtime_memory as runtime


EXE_BASE = 0x140000000
PLUGIN_BASES = (0x7FFB34E90000, 0x7FFA00300000)
PATCH_RVA = 0xA4B2FC
HOOK_RVA = 0x3DD84
CALLBACK_RVA = 0x38410
RETURN_RVA = 0xA4B316
SLOTS_RVA = 0x820A8
IMAGE_SIZE = 561152
HEADER = bytes(range(256)) * 4
HEADER_IMAGE_BASE_OFFSET = 0x140
PREFERRED_IMAGE_BASE = 0x180000000
GUARD_A = bytes.fromhex("48895c24")
GUARD_B = bytes.fromhex("488b4120c3")


def _guard(name: str, rva: int, raw: bytes) -> dict[str, str]:
    return {"name": name, "rva": hex(rva), "bytes": raw.hex(),
            "sha256": hashlib.sha256(raw).hexdigest()}


def _spec(*, image_base_fields: bool = False) -> dict:
    plugin = {
        "hook_rva": hex(HOOK_RVA),
        "callback_rva": hex(CALLBACK_RVA),
        "return_rva": hex(RETURN_RVA),
        "slots_rva": hex(SLOTS_RVA),
        "image_size": IMAGE_SIZE,
        "header_bytes": HEADER.hex(),
        "code_guards": [
            _guard("hook_window", HOOK_RVA, GUARD_A),
            _guard("name_callback", CALLBACK_RVA, GUARD_B),
        ],
    }
    if image_base_fields:
        header = bytearray(HEADER)
        header[HEADER_IMAGE_BASE_OFFSET:HEADER_IMAGE_BASE_OFFSET + 8] = (
            PREFERRED_IMAGE_BASE.to_bytes(8, "little"))
        plugin["header_bytes"] = bytes(header).hex()
        plugin["header_image_base_offset"] = hex(HEADER_IMAGE_BASE_OFFSET)
        plugin["preferred_image_base"] = hex(PREFERRED_IMAGE_BASE)
    return {
        "patch_rva": hex(PATCH_RVA),
        "original_bytes": bytes(range(14)).hex(),
        "plugin": plugin,
    }


class FakeReader:
    def __init__(self, *, fail_label: str | None = None,
                 short_label: str | None = None):
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_label = fail_label
        self.short_label = short_label

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: value for index, value in enumerate(raw)})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label == self.fail_label:
            raise OSError("synthetic read failure")
        raw = bytes(self.memory[address + index] for index in range(size))
        return raw[:-1] if label == self.short_label else raw


def _plugin_reader(*, exe_base: int = EXE_BASE, plugin_base: int = PLUGIN_BASES[0],
                   spec: dict | None = None, patch: bytes | None = None,
                   header: bytes | None = None, guard_overrides: dict | None = None,
                   return_pointer: int | None = None, callback_pointer: int | None = None,
                   fail_label: str | None = None, short_label: str | None = None):
    spec = _spec() if spec is None else spec
    image = FakeReader(fail_label=fail_label, short_label=short_label)
    target = plugin_base + HOOK_RVA
    patch_bytes = (b"\xff\x25\0\0\0\0" + target.to_bytes(8, "little")
                   if patch is None else patch)
    image.put(exe_base + PATCH_RVA, patch_bytes)
    profile_header = bytes.fromhex(spec["plugin"]["header_bytes"])
    if "header_image_base_offset" in spec["plugin"]:
        offset = int(spec["plugin"]["header_image_base_offset"], 0)
        profile_header = (profile_header[:offset] + plugin_base.to_bytes(8, "little")
                          + profile_header[offset + 8:])
    image.put(plugin_base, profile_header if header is None else header)
    guard_overrides = guard_overrides or {}
    for item in spec["plugin"]["code_guards"]:
        raw = bytes.fromhex(item["bytes"])
        image.put(plugin_base + int(item["rva"], 0), guard_overrides.get(item["name"], raw))
    expected_return = exe_base + RETURN_RVA
    expected_callback = plugin_base + CALLBACK_RVA
    slot_bytes = (expected_return if return_pointer is None else return_pointer).to_bytes(8, "little")
    slot_bytes += (expected_callback if callback_pointer is None else callback_pointer).to_bytes(8, "little")
    image.put(plugin_base + SLOTS_RVA, slot_bytes)
    return image, spec


def test_vanilla_patch_is_known_without_any_plugin_read():
    spec = _spec()
    reader = FakeReader()
    original = bytes.fromhex(spec["original_bytes"])
    reader.put(EXE_BASE + PATCH_RVA, original)

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "known" and result["layout"] == "vanilla"
    assert result["raw_inputs"]["plugin"] == {"status": "not_read", "reason": "vanilla_patch"}
    assert len(reader.reads) == 1
    assert reader.reads[0] == (
        EXE_BASE + PATCH_RVA, 14, "person.name_runtime.exe_patch")


@pytest.mark.parametrize("plugin_base", PLUGIN_BASES)
def test_plugin64_layout_is_verified_at_multiple_aslr_bases(plugin_base: int):
    reader, spec = _plugin_reader(
        plugin_base=plugin_base, spec=_spec(image_base_fields=True))

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "known" and result["layout"] == "plugin64"
    raw = result["raw_inputs"]
    assert raw["plugin"]["derived_base"] == hex(plugin_base)
    assert raw["plugin"]["hook_target"] == hex(plugin_base + HOOK_RVA)
    assert raw["plugin"]["header"]["matches"] is True
    assert raw["plugin"]["header"]["image_base"] == {
        "offset": hex(HEADER_IMAGE_BASE_OFFSET),
        "preferred_image_base": hex(PREFERRED_IMAGE_BASE),
        "observed_image_base": hex(plugin_base),
        "derived_expected_image_base": hex(plugin_base),
        "matches_derived_base": True,
    }
    assert [item["matches_bytes"] for item in raw["plugin"]["code_guards"]] == [True, True]
    assert raw["plugin"]["slots"]["return_matches"] is True
    assert raw["plugin"]["slots"]["callback_matches"] is True
    assert all("invoke" not in label for _address, _size, label in reader.reads)
    assert [label for _address, _size, label in reader.reads] == [
        "person.name_runtime.exe_patch",
        "person.name_runtime.plugin_header",
        "person.name_runtime.guard.hook_window",
        "person.name_runtime.guard.name_callback",
        "person.name_runtime.slots",
    ]


def test_plugin_runtime_header_must_use_derived_image_base():
    spec = _spec(image_base_fields=True)
    pinned_header = bytes.fromhex(spec["plugin"]["header_bytes"])
    reader, _ = _plugin_reader(spec=spec, header=pinned_header)

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "unknown"
    assert result["reason"] == "person.name_runtime.plugin_header_image_base_mismatch"
    image_base = result["raw_inputs"]["plugin"]["header"]["image_base"]
    assert image_base["offset"] == hex(HEADER_IMAGE_BASE_OFFSET)
    assert image_base["preferred_image_base"] == hex(PREFERRED_IMAGE_BASE)
    assert image_base["observed_image_base"] == hex(PREFERRED_IMAGE_BASE)
    assert image_base["derived_expected_image_base"] == hex(PLUGIN_BASES[0])
    assert image_base["matches_derived_base"] is False


def test_plugin_runtime_header_still_requires_all_other_bytes_exact():
    spec = _spec(image_base_fields=True)
    reader, _ = _plugin_reader(spec=spec)
    actual_header = bytearray(bytes.fromhex(spec["plugin"]["header_bytes"]))
    actual_header[HEADER_IMAGE_BASE_OFFSET:HEADER_IMAGE_BASE_OFFSET + 8] = (
        PLUGIN_BASES[0].to_bytes(8, "little"))
    actual_header[0x100] ^= 1
    reader.put(PLUGIN_BASES[0], bytes(actual_header))

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "unknown"
    assert result["reason"] == "person.name_runtime.plugin_header_mismatch"
    assert result["raw_inputs"]["plugin"]["header"]["image_base"][
        "matches_derived_base"] is True
    assert result["raw_inputs"]["plugin"]["header"]["matches"] is False


def test_unknown_jump_does_not_follow_an_unrecognized_target():
    bad = b"\xe9\0\0\0\0" + bytes(9)
    reader, spec = _plugin_reader(patch=bad)

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "unknown" and "layout" not in result
    assert result["reason"] == "person.name_runtime.patch_encoding_unknown"
    assert len(reader.reads) == 1


def test_noncanonical_jump_target_is_rejected_before_plugin_reads():
    bad = b"\xff\x25\0\0\0\0" + (0x0000800000000000).to_bytes(8, "little")
    reader, spec = _plugin_reader(patch=bad)

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "unknown" and "layout" not in result
    assert result["reason"] == "plugin_hook_target_not_canonical_user_address"
    assert len(reader.reads) == 1


def test_plugin_header_and_code_guards_are_exact():
    reader, spec = _plugin_reader(header=bytes([0xAB]) * len(HEADER))
    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)
    assert result["status"] == "unknown"
    assert result["reason"] == "person.name_runtime.plugin_header_mismatch"
    assert len(reader.reads) == 2

    reader, spec = _plugin_reader(guard_overrides={"hook_window": b"\x90" * len(GUARD_A)})
    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)
    assert result["status"] == "unknown"
    assert result["reason"] == "person.name_runtime.guard_mismatch:hook_window"
    assert result["raw_inputs"]["plugin"]["code_guards"][0]["matches_bytes"] is False
    assert len(reader.reads) == 3


@pytest.mark.parametrize(("slot_change", "reason"), [
    ({"return_pointer": EXE_BASE + RETURN_RVA + 1},
     "person.name_runtime.return_pointer_mismatch"),
    ({"callback_pointer": PLUGIN_BASES[0] + CALLBACK_RVA + 1},
     "person.name_runtime.callback_pointer_mismatch"),
])
def test_slots_must_bind_exact_return_and_callback(slot_change: dict, reason: str):
    reader, spec = _plugin_reader(**slot_change)
    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)
    assert result["status"] == "unknown" and result["reason"] == reason
    assert result["raw_inputs"]["plugin"]["slots"] is not None


@pytest.mark.parametrize("failure", ["exception", "short"])
def test_patch_read_failures_are_structured_unknown(failure: str):
    reader, spec = _plugin_reader(
        fail_label="person.name_runtime.exe_patch" if failure == "exception" else None,
        short_label="person.name_runtime.exe_patch" if failure == "short" else None,
    )
    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)
    assert result["status"] == "unknown" and "layout" not in result
    assert result["reason"] == (
        "person.name_runtime.exe_patch_read_failed" if failure == "exception"
        else "person.name_runtime.exe_patch_short_read")
    assert result["raw_inputs"]["read_trace"][-1]["status"] == (
        "error" if failure == "exception" else "short")


@pytest.mark.parametrize("bad_spec,reason", [
    (lambda spec: spec.update(original_bytes="00" * 13), "original_bytes_width_invalid"),
    (lambda spec: spec["plugin"].update(header_bytes="00" * (MAX_HEADER + 1)),
     "header_bytes_size_exceeded"),
    (lambda spec: spec["plugin"].update(code_guards=spec["plugin"]["code_guards"] * 17),
     "code_guards_shape_invalid"),
    (lambda spec: spec["plugin"]["code_guards"][0].update(rva=hex(IMAGE_SIZE - 1)),
     "code_guard_hook_window_outside_image"),
    (lambda spec: spec["plugin"].update(slots_rva=hex(IMAGE_SIZE - 8)),
     "slots_outside_image"),
    (lambda spec: spec["plugin"]["code_guards"][0].update(sha256="0" * 64),
     "code_guard_hook_window_sha_pin_mismatch"),
    (lambda spec: spec["plugin"].update(header_image_base_offset=hex(IMAGE_SIZE - 7),
                                        preferred_image_base=hex(PREFERRED_IMAGE_BASE)),
     "header_image_base_offset_outside_header"),
    (lambda spec: spec["plugin"].update(header_image_base_offset=hex(HEADER_IMAGE_BASE_OFFSET),
                                        preferred_image_base=hex(PREFERRED_IMAGE_BASE)),
     "header_preferred_image_base_mismatch"),
    (lambda spec: spec["plugin"].update(header_image_base_offset=hex(HEADER_IMAGE_BASE_OFFSET)),
     "header_image_base_spec_incomplete"),
])
def test_invalid_spec_is_rejected_before_any_memory_read(bad_spec, reason: str):
    spec = _spec()
    bad_spec(spec)
    reader, _ = _plugin_reader(spec=spec)
    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)
    assert result["status"] == "unknown" and "layout" not in result
    assert result["reason"] == reason
    assert reader.reads == []


def test_read_budget_is_validated_before_memory_reads():
    spec = _spec()
    large = b"\x90" * 65_536
    spec["plugin"]["image_size"] = 0x90000
    spec["plugin"]["code_guards"] = [
        _guard("large_a", 0x10000, large),
        _guard("large_b", 0x20000, large),
    ]
    reader, _ = _plugin_reader(spec=spec)

    result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)

    assert result["status"] == "unknown"
    assert result["reason"] == "planned_read_budget_exceeded"
    assert reader.reads == []


def test_short_or_failed_plugin_reads_never_return_a_layout():
    for label, mode, reason in (
        ("person.name_runtime.plugin_header", "short",
         "person.name_runtime.plugin_header_short_read"),
        ("person.name_runtime.guard.name_callback", "error",
         "person.name_runtime.guard.name_callback_read_failed"),
    ):
        reader, spec = _plugin_reader(
            short_label=label if mode == "short" else None,
            fail_label=label if mode == "error" else None)
        result = runtime.read_person_name_layout(reader.read, EXE_BASE, spec)
        assert result["status"] == "unknown" and "layout" not in result
        assert result["reason"] == reason


MAX_HEADER = 4096
