"""Regression tests for the bounded custom-localisation reader."""
from __future__ import annotations

import ctypes as C
from pathlib import Path
import unittest
from unittest.mock import patch

from bridge.information import custom_localization_memory as cm
from bridge.information import mission_memory as mm
from bridge.tests.test_information_mission_memory import FakeReader, base_reader


def _qword(reader: FakeReader, address: int, value: int) -> None:
    reader.qword_put(address, value)


def _string32(reader: FakeReader, address: int, text: bytes, heap_address: int) -> None:
    payload = text + b"\x00"
    length = len(text)
    capacity = max(length, 1)
    header = bytearray(32)
    if length <= 15:
        header[: len(payload)] = payload
    else:
        capacity = max(16, length)
        header[:8] = int(heap_address).to_bytes(8, "little")
        reader.put(heap_address, payload)
    header[0x10:0x18] = length.to_bytes(8, "little")
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    reader.put(address, header)


def custom_fixture(
    *,
    predicate_count: int = 0,
    weight: int = 1000,
    modifier_span: tuple[int, int] = (0, 0),
    duplicate_title: bool = False,
    duplicate_root: bool = False,
    root_enum: int = 3,
    random_flag: int = 1,
    builtin_count: int = 1,
    common_epoch: int = -2147483618,
    builtin_epoch: int = -2147483617,
) -> tuple[FakeReader, int, dict[str, int]]:
    reader, module, country = base_reader()
    for _name, rva, expected in cm._profile_code_guards():
        reader.put(module + rva, expected)
    reader.dword_put(module + cm.COMMON_INIT_GUARD_RVA, common_epoch, signed=True)
    reader.dword_put(module + cm.BUILTIN_INIT_GUARD_RVA, builtin_epoch, signed=True)

    registry = 0x900000
    vector = 0x910000
    title_definition = 0x920000
    desc_definition = 0x930000
    duplicate_definition = 0x970000
    title_option = 0x940000
    desc_option = 0x950000
    title_vector = 0x990000
    desc_vector = 0x9A0000
    _qword(reader, module + cm.CUSTOM_GLOBAL_RVA, registry)
    _qword(reader, registry, vector)
    definitions = [title_definition, desc_definition]
    if duplicate_title:
        definitions.append(duplicate_definition)
    _qword(reader, registry + 8, vector + len(definitions) * 8)
    for index, pointer in enumerate(definitions):
        _qword(reader, vector + index * 8, pointer)

    method_defs = [
        (title_definition, b"GetSelectableMissionTitle", title_option, b"SELECTABLE_MISSION_TITLE"),
        (desc_definition, b"GetSelectableMissionDescription", desc_option, b"SELECTABLE_MISSION_DESCRIPTION"),
    ]
    if duplicate_title:
        method_defs.append((duplicate_definition, b"GetSelectableMissionTitle", 0x980000, b"DUPLICATE"))
    for definition, name, option, key in method_defs:
        option_vector = title_vector if option == title_option else desc_vector
        if option not in (title_option, desc_option):
            option_vector = option + 0x1000
        _qword(reader, option_vector, option)
        reader.put(definition, bytes(0x48))
        reader.put(definition + cm.DEFINITION_RANDOM_OFFSET, bytes([random_flag & 0xFF]))
        _string32(reader, definition + cm.DEFINITION_NAME_OFFSET, name, definition + 0x2000)
        _qword(reader, definition + cm.DEFINITION_OPTIONS_BEGIN, option_vector)
        _qword(reader, definition + cm.DEFINITION_OPTIONS_END, option_vector + 8)
        reader.put(option, bytes(0xD0))
        _string32(reader, option + cm.OPTION_KEY_OFFSET, key, option + 0x2000)
        reader.dword_put(option + cm.OPTION_PREDICATE_COUNT_OFFSET, predicate_count)
        reader.dword_put(option + cm.OPTION_WEIGHT_OFFSET, weight & 0xFFFFFFFF)
        _qword(reader, option + cm.OPTION_MODIFIERS_BEGIN, modifier_span[0])
        _qword(reader, option + cm.OPTION_MODIFIERS_END, modifier_span[1])

    common_names = [(b"Player", 0), (b"This", 1), (b"Root", root_enum), (b"From", 4), (b"FromFrom", 5), (b"Prev", 6)]
    if duplicate_root:
        common_names[1] = (b"Root", 1)
    for index, (name, enum) in enumerate(common_names):
        address = module + cm.COMMON_PROMOTIONS_RVA + index * cm.COMMON_STRIDE
        reader.put(address, bytes(cm.COMMON_STRIDE))
        _string32(reader, address, name, address + 0x1000)
        reader.dword_put(address + cm.COMMON_ENUM_OFFSET, enum)
        reader.put(address + cm.COMMON_ENUM_OFFSET + 4, b"\xA5\x5A\xC3\x3C")

    # The table must be initialized and non-empty before exact raw-name absence
    # can be published.  The unrelated name exercises byte-preserving matching.
    builtin_header = module + cm.BUILTIN_GLOBAL_RVA
    reader.put(builtin_header, bytes(16))
    builtin_records = 0x9B0000
    _qword(reader, builtin_header, builtin_records)
    reader.dword_put(builtin_header + cm.BUILTIN_COUNT_HEADER_OFFSET, builtin_count, signed=True)
    if builtin_count:
        _string32(reader, builtin_records, b"\xff\x01", builtin_records + 0x2000)
    return reader, module, {"title": title_definition, "description": desc_definition, "country": country}


class FakeKernel:
    def __init__(self, close_result: bool = True, memory: dict[int, int] | None = None):
        self.close_result = close_result
        self.closed: list[int] = []
        self.memory = memory if memory is not None else {}

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return 0x1234

    def ReadProcessMemory(self, _handle: int, address: object, buffer: object, size: int, actual: object) -> bool:
        value = int(getattr(address, "value", address))
        raw = bytes(self.memory.get(value + offset, 0) for offset in range(size))
        C.memmove(buffer, raw, size)
        getattr(actual, "_obj").value = size
        return True

    def CloseHandle(self, handle: int) -> bool:
        self.closed.append(int(handle))
        return self.close_result


def _observed_guard() -> dict[str, object]:
    return {"status": "observed", "checks": {}, "records": {}, "unknown_conditions": []}


def _identity(report: dict[str, object], _document: dict[str, object], _kernel: object, _handle: object, module: int) -> int:
    identity = report["identity"]
    assert isinstance(identity, dict)
    identity.update({
        "installation_pid": 123,
        "installation_creation_filetime": 987,
        "installation_session_id": "fake-session",
        "process_path": "fake-eu4.exe",
        "process_path_sha256": cm.EXPECTED_EXE_SHA256,
        "process_path_sha256_matches_expected": True,
        "process_creation_filetime": 987,
        "process_creation_matches_installation": True,
        "module_path": "fake-eu4.exe",
        "module_path_matches_process": True,
        "binding_verified": True,
    })
    report["module_base"] = cm._address(module)
    return module


class CustomLocalizationMemoryTests(unittest.TestCase):
    def _capture(self, reader: FakeReader, module: int, *, kernel: FakeKernel | None = None, file_guard: dict[str, object] | None = None, **kwargs):
        kernel = kernel or FakeKernel(memory=reader.memory)
        kernel.memory = reader.memory
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": cm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        identity = lambda report, doc, k, h: _identity(report, doc, k, h, module)
        with patch.object(cm, "_load_installation", return_value=document), \
             patch.object(cm, "_configure_kernel", return_value=kernel), \
             patch.object(cm, "_capture_identity", side_effect=identity), \
             patch.object(cm, "_sha256_file", return_value=cm.EXPECTED_EXE_SHA256), \
             patch.object(cm, "_file_code_guard", return_value=file_guard or _observed_guard()):
            return cm.capture(Path("fake-installation.json"), "FRA", list(cm.METHODS), **kwargs), kernel

    def test_profile_and_all_runtime_guards(self):
        self.assertEqual(cm._static_contract_guard()["status"], "observed")
        self.assertTrue(all(cm._static_contract_guard()["checks"].values()))
        reader, module, _ = custom_fixture()
        self.assertEqual(cm._runtime_code_guard(reader, module)["status"], "observed")
        name, rva, _raw = cm._profile_code_guards()[0]
        reader.memory[module + rva] ^= 1
        guard = cm._runtime_code_guard(reader, module)
        self.assertEqual(guard["status"], "mismatch")
        self.assertFalse(guard["checks"][name])

    def test_snapshot_derives_only_unique_unconditional_positive_options(self):
        reader, module, _ = custom_fixture()
        snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
        self.assertEqual(snapshot["status"], "observed")
        for method in cm.METHODS:
            item = snapshot["methods"][method]
            self.assertEqual(item["status"], "observed")
            self.assertEqual(item["text_key"]["text"], "SELECTABLE_MISSION_TITLE" if "Title" in method else "SELECTABLE_MISSION_DESCRIPTION")
            self.assertEqual(item["selection"]["kind"], "single_unconditional_positive_weight")
            self.assertFalse(item["selection"]["ui_root_scope_verified"])
            self.assertEqual(item["selection"]["root_promotion_enum"], 3)
        self.assertEqual(snapshot["country_builtins"]["requested_matches"][cm.METHODS[0]], [])
        self.assertEqual(snapshot["country_builtins"]["entries"][0]["name"]["raw_hex"], "ff01")
        self.assertIsNone(snapshot["country_builtins"]["entries"][0]["name"]["text"])
        self.assertEqual(snapshot["common_promotions"]["entries"][2]["enum_raw_hex"], "03000000")

    def test_predicate_weight_modifier_and_duplicate_fail_closed(self):
        for kwargs, reason in (
            ({"predicate_count": 1}, "predicate_count_not_zero"),
            ({"weight": 0}, "weight_not_positive_bounded"),
            ({"weight": 0x80000000}, "weight_not_positive_bounded"),
            ({"modifier_span": (0xA00000, 0xA00008)}, "modifiers_not_empty"),
            ({"duplicate_title": True}, "customloc_method_name_not_unique"),
        ):
            with self.subTest(reason=reason):
                reader, module, _ = custom_fixture(**kwargs)
                snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
                self.assertEqual(snapshot["methods"][cm.METHODS[0]]["status"], "unknown")
                self.assertEqual(snapshot["methods"][cm.METHODS[0]]["unknown_reason"], reason)
                self.assertEqual(snapshot["status"], "observed")

    def test_root_selection_requires_unique_raw_name_and_enum_three(self):
        reader, module, _ = custom_fixture(duplicate_root=True)
        snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
        self.assertEqual(snapshot["common_promotions"]["unknown_reason"], "root_promotion_not_unique")
        self.assertEqual(snapshot["status"], "unknown")

        reader, module, _ = custom_fixture(root_enum=2)
        snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
        self.assertEqual(snapshot["common_promotions"]["root_matches"][0]["enum"], 2)
        self.assertEqual(snapshot["common_promotions"]["unknown_reason"], "root_promotion_enum_mismatch")
        self.assertEqual(snapshot["status"], "unknown")

    def test_initialization_and_empty_builtin_states_are_unknown(self):
        reader, module, _ = custom_fixture(builtin_epoch=0)
        snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
        self.assertEqual(snapshot["country_builtins"]["unknown_reason"], "country_builtin_table_uninitialized_or_initializing")
        self.assertEqual(snapshot["status"], "unknown")

        reader, module, _ = custom_fixture(builtin_count=0)
        snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
        self.assertEqual(snapshot["country_builtins"]["unknown_reason"], "country_builtins_count_zero_or_uninitialized")
        self.assertEqual(snapshot["status"], "unknown")

        reader, module, _ = custom_fixture(random_flag=2)
        snapshot = cm._snapshot(reader, module, "FRA", list(cm.METHODS), {"records": {}})
        self.assertEqual(snapshot["methods"][cm.METHODS[0]]["unknown_reason"], "random_flag_invalid")
        self.assertEqual(snapshot["status"], "observed")

    def test_capture_full_control_flow_and_cleanup_failure(self):
        reader, module, _ = custom_fixture()
        report, kernel = self._capture(reader, module)
        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["doublepass"]["consistent"])
        self.assertEqual(report["methods"][cm.METHODS[0]]["status"], "observed")
        self.assertGreater(report["access"]["rpm_calls"], 0)
        self.assertGreater(report["access"]["rpm_bytes_requested"], 0)
        self.assertEqual(kernel.closed, [0x1234])

        reader, module, _ = custom_fixture()
        report, kernel = self._capture(reader, module, kernel=FakeKernel(close_result=False))
        self.assertEqual(report["status"], "cleanup_error")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "error")
        self.assertTrue(all(value["status"] == "unknown" for value in report["methods"].values()))
        self.assertEqual(kernel.closed, [0x1234])

    def test_capture_second_pass_runtime_guard_mutation_is_terminal(self):
        reader, module, _ = custom_fixture()
        original = cm._runtime_code_guard
        calls = 0

        def changing(probe_reader, probe_module):
            nonlocal calls
            result = original(probe_reader, probe_module)
            calls += 1
            if calls == 1:
                _name, rva, _expected = cm._profile_code_guards()[0]
                address = probe_module + rva
                probe_reader.kernel.memory[address] ^= 1
            return result

        with patch.object(cm, "_runtime_code_guard", side_effect=changing):
            report, kernel = self._capture(reader, module)
        self.assertEqual(report["status"], "runtime_code_mismatch")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "closed")
        self.assertTrue(all(value["status"] == "unknown" for value in report["methods"].values()))
        self.assertEqual(kernel.closed, [0x1234])

    def test_capture_identity_file_runtime_failures_close_and_publish_unknown(self):
        reader, module, _ = custom_fixture()
        kernel = FakeKernel()
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": cm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        with patch.object(cm, "_load_installation", return_value=document), patch.object(cm, "_configure_kernel", return_value=kernel), patch.object(cm, "_capture_identity", side_effect=cm.ProbeError("identity_mismatch")):
            report = cm.capture(Path("fake.json"), "FRA", list(cm.METHODS))
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "closed")
        self.assertTrue(all(value["status"] == "unknown" for value in report["methods"].values()))

        for failure, expected in (({"status": "mismatch", "checks": {"x": False}, "records": {}, "unknown_conditions": ["tampered"]}, "file_code_mismatch"),):
            reader, module, _ = custom_fixture()
            with patch.object(cm, "_file_code_guard", return_value=failure):
                report, kernel = self._capture(reader, module, file_guard=failure)
            self.assertEqual(report["status"], expected)
            self.assertEqual(kernel.closed, [0x1234])
            self.assertTrue(all(value["status"] == "unknown" for value in report["methods"].values()))

        reader, module, _ = custom_fixture()
        runtime_bad = {"status": "mismatch", "checks": {"x": False}, "records": {}, "unknown_conditions": ["tampered"]}
        with patch.object(cm, "_runtime_code_guard", return_value=runtime_bad):
            report, kernel = self._capture(reader, module)
        self.assertEqual(report["status"], "runtime_code_mismatch")
        self.assertEqual(kernel.closed, [0x1234])

    def test_capture_date_and_payload_mutation_becomes_doublepass_unknown(self):
        reader, module, _ = custom_fixture()
        original = cm._snapshot
        calls = 0

        def changing(probe_reader, probe_module, country, methods, runtime_guard=None):
            nonlocal calls
            value = original(probe_reader, probe_module, country, methods, runtime_guard)
            calls += 1
            if calls == 1:
                changed = (56553385).to_bytes(4, "little", signed=True)
                for offset, byte in enumerate(changed):
                    probe_reader.kernel.memory[0x200000 + cm.GAME_DATE_OFFSET + offset] = byte
            return value

        with patch.object(cm, "_snapshot", side_effect=changing):
            report, kernel = self._capture(reader, module)
        self.assertEqual(report["status"], "doublepass_mismatch")
        self.assertFalse(report["doublepass"]["consistent"])
        self.assertEqual(kernel.closed, [0x1234])
        self.assertTrue(all(value["status"] == "unknown" for value in report["methods"].values()))

    def test_request_unknown_and_bounded_address_fail_without_process(self):
        unsupported = cm.capture(Path("missing.json"), "eng", [cm.METHODS[0]])
        self.assertEqual(unsupported["status"], "unsupported_country")
        self.assertEqual(unsupported["cleanup"]["handle_close"]["status"], "not_opened")
        invalid = cm.capture(Path("missing.json"), "FRA", ["Unsupported"])
        self.assertEqual(invalid["status"], "invalid_request")
        self.assertEqual(invalid["methods"]["Unsupported"]["status"], "unknown")

        for bad_methods in (None, [], [[]], [{}]):
            with self.subTest(bad_methods=bad_methods):
                report = cm.capture(Path("missing.json"), "FRA", bad_methods)
                self.assertEqual(report["status"], "invalid_request")
                self.assertEqual(report["cleanup"]["handle_close"]["status"], "not_opened")

    def test_capture_identity_mismatch_and_budget_fail_closed_with_real_reader(self):
        reader, module, _ = custom_fixture()
        kernel = FakeKernel(memory=reader.memory)

        def mismatched(report, document, fake_kernel, handle):
            module_base = _identity(report, document, fake_kernel, handle, module)
            report["identity"]["process_creation_matches_installation"] = False
            raise cm.ProbeError("process_creation_mismatch")

        document = {"pid": 123, "creation_filetime": 987, "game_sha256": cm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        with patch.object(cm, "_load_installation", return_value=document), \
             patch.object(cm, "_configure_kernel", return_value=kernel), \
             patch.object(cm, "_capture_identity", side_effect=mismatched), \
             patch.object(cm, "_sha256_file", return_value=cm.EXPECTED_EXE_SHA256):
            report = cm.capture(Path("fake-installation.json"), "FRA", list(cm.METHODS))
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "closed")
        self.assertEqual(kernel.closed, [0x1234])

        reader, module, _ = custom_fixture()
        with patch.object(mm, "MAX_TOTAL_RPM", 4096):
            report, kernel = self._capture(reader, module)
        self.assertEqual(report["status"], "runtime_code_mismatch")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "closed")
        self.assertGreater(report["access"]["rpm_bytes_requested"], 0)
        self.assertEqual(kernel.closed, [0x1234])

        reader = cm.AddressBoundedRPM(FakeKernel(), 0x1234, 0x140000000)
        with self.assertRaises(cm.ProbeError):
            cm.AddressBoundedRPM._read(reader, cm.MAX_USER_ADDRESS - 2, 8, "high", aligned=False)
        reader.bytes_requested = cm.MAX_TOTAL_RPM
        with self.assertRaises(cm.ProbeError):
            cm.AddressBoundedRPM._read(reader, 0x10000, 8, "budget", aligned=False)


if __name__ == "__main__":
    unittest.main()
