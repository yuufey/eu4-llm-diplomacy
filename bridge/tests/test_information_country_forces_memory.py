"""Synthetic bounded-reader tests for the country force record memory seam.

These tests never open a process, call MCP, call a game function, or use the
raw receipt as expected public output.  The final test only checks that the
already archived receipt remains a well-formed offline evidence input.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import country_forces_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
TABLE = 0x6300000000
GAME = 0x6500000000
COUNTRY = 0x6400000000
GROUP_HEAD = 0x6100000000
GROUP_OBJECT = 0x6100001000
VECTOR = 0x6100002000
COUNTRY2 = 0x6400010000
RECORD1 = 0x6700000000
RECORD2 = 0x6700001000
TYPE1 = 0x6800000000
TYPE2 = 0x6800001000


class BoundedReader:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: byte for index, byte in enumerate(raw)})

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def i32(self, address: int, value: int) -> None:
        self.put(address, (int(value) & 0xFFFFFFFF).to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected synthetic read {label} {address:#x} {size}") from exc

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)


class MutatingCountryReader(BoundedReader):
    """Mutate the country identity only after the first pass observed it."""

    def __init__(self, mode: str) -> None:
        super().__init__()
        self.mode = mode
        self.changed = False

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = super().read(address, size, label)
        if not self.changed and label == "country_forces.country_table[5]" and self.mode == "pointer":
            self.qword(TABLE + 5 * 8, COUNTRY2)
            self.qword(COUNTRY2 + 0x20, _fullref("FRA", 5))
            self.changed = True
        elif not self.changed and label == "country_forces.country_handle" and self.mode == "handle":
            self.qword(COUNTRY + 0x20, _fullref("BUR", 5))
            self.changed = True
        return raw


def _fullref(tag: str, slot: int) -> int:
    return (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _reader(*, empty: bool = False, duplicate_pointer: bool = False,
            duplicate_id: bool = False, cross_group_duplicate: bool = False,
            bad_pointer: bool = False, cycle: bool = False,
            oversized: bool = False, negative_strength: bool = False,
            guard_tamper: bool = False) -> BoundedReader:
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        reader.put(MODULE_BASE + rva, (bytes([raw[0] ^ 1]) + raw[1:]) if guard_tamper and not reader.memory else raw)
    reader.qword(MODULE_BASE + layout["database_global_rva"], DATABASE)
    reader.qword(DATABASE + layout["database_table_offset"], TABLE)
    reader.i32(DATABASE + layout["database_table_count_offset"], 6)
    fra = _fullref("FRA", 5)
    for slot in range(6):
        reader.qword(TABLE + slot * 8, COUNTRY if slot == 5 else 0)
    reader.qword(COUNTRY + layout["country_fullref_offset"], fra)
    reader.qword(MODULE_BASE + layout["game_global_rva"], GAME)
    reader.i32(GAME + layout["game_date_offset"], 56562768)
    reader.qword(COUNTRY + layout["country_group_offset"], 0 if empty else GROUP_HEAD)
    if empty:
        return reader
    reader.qword(GROUP_HEAD + layout["group_object_offset"], GROUP_OBJECT)
    reader.qword(GROUP_HEAD + layout["group_next_offset"], GROUP_HEAD if cycle else (0 if not cross_group_duplicate else GROUP_HEAD + 0x1000))
    reader.qword(GROUP_OBJECT + layout["group_vector_begin_offset"], VECTOR)
    first_end = VECTOR + (1025 if oversized else 2) * layout["vector_entry_stride"]
    reader.qword(GROUP_OBJECT + layout["group_vector_end_offset"], first_end)
    if oversized:
        return reader
    reader.qword(VECTOR, 0 if bad_pointer else RECORD1)
    reader.qword(VECTOR + 8, RECORD1 if duplicate_pointer else RECORD2)
    if cross_group_duplicate:
        second_head = GROUP_HEAD + 0x1000
        second_object = GROUP_OBJECT + 0x1000
        second_vector = VECTOR + 0x1000
        reader.qword(second_head + layout["group_object_offset"], second_object)
        reader.qword(second_head + layout["group_next_offset"], 0)
        reader.qword(second_object + layout["group_vector_begin_offset"], second_vector)
        reader.qword(second_object + layout["group_vector_end_offset"], second_vector + 8)
        reader.qword(second_vector, RECORD1)
    for address, type_object, identity, kind, strength in (
        (RECORD1, TYPE1, (55, 13512), 0, -1 if negative_strength else 981),
        (RECORD2, TYPE2, ((55, 13512) if duplicate_id else (55, 13513)), 3, 670),
    ):
        body = bytearray(0x30)
        body[0x10:0x14] = int(identity[0]).to_bytes(4, "little")
        body[0x14:0x18] = int(identity[1]).to_bytes(4, "little")
        body[0x20:0x28] = int(type_object).to_bytes(8, "little")
        body[0x28:0x2C] = int(strength).to_bytes(4, "little", signed=True)
        reader.put(address, bytes(body))
        reader.i32(type_object + layout["type_kind_offset"], kind)
    return reader


def _mutating_reader(mode: str) -> MutatingCountryReader:
    reader = MutatingCountryReader(mode)
    reader.memory = _reader().memory.copy()
    return reader


def test_profile_pin_and_empty_chain_are_bounded() -> None:
    profile = memory._load_profile()
    assert profile["profile_id"] == memory.EXPECTED_PROFILE_ID
    assert memory._static_contract_guard(profile)["status"] == "observed"
    record = memory.read_fields(_reader(empty=True), MODULE_BASE, COUNTRY)
    assert record["status"] == "observed"
    assert record["record"]["records"] == []
    assert record["record"]["record_count"] == 0
    assert memory.validate_record(record["record"])
    assert record["read_budget"]["bytes_reserved"] <= memory.READ_BUDGET_BYTES


def test_python_analysis_reference_preserves_fixed_evidence_validation(tmp_path, monkeypatch):
    source = tmp_path / "reader.py"
    source.write_text("current implementation\n", encoding="utf-8")
    evidence = tmp_path / "native-proof.json"
    raw = b'{"native_layout":1}'
    evidence.write_bytes(raw)
    python_reference = {"path": source.name, "sha256": "0" * 64, "bytes": 1}
    fixed_reference = {"path": evidence.name, "sha256": hashlib.sha256(raw).hexdigest(),
                       "bytes": len(raw), "role": "fixed native proof"}
    profile = {"source_evidence": [python_reference, fixed_reference]}
    monkeypatch.setattr(memory, "_workspace_root", lambda: tmp_path)

    assert memory._source_evidence(profile) == [fixed_reference]
    evidence.write_bytes(raw.replace(b"1", b"2"))
    with pytest.raises(memory.ProfileError, match="source_evidence_sha256_mismatch"):
        memory._source_evidence(profile)
    with pytest.raises(memory.ProfileError, match="source_evidence_duplicate"):
        memory._source_evidence({"source_evidence": [python_reference, python_reference]})
    with pytest.raises(memory.ProfileError, match="source_evidence_outside_workspace"):
        memory._source_evidence({"source_evidence": [{**python_reference, "path": "../reader.py"}]})


@pytest.mark.parametrize("country", ["FRA", "TUR", "D01"])
def test_normal_information_query_uses_current_force_profile(tmp_path, monkeypatch, country):
    from bridge.information import InformationService
    from bridge.information.composite import CompositeSource
    from bridge.information.country_forces import NativeCountryForcesSource
    from bridge.information.tools import InformationTools
    from bridge.tests import test_information_country_force_types_memory as capture_fixture
    from bridge.tests import test_information_country_forces as source_fixture

    reader = capture_fixture._reader()
    layout = memory._profile_layout(memory._load_profile())
    reader.qword(capture_fixture.COUNTRY + layout["country_fullref_offset"], _fullref(country, 5))
    capture_fixture._fake_capture_environment(monkeypatch, reader)
    base, session, diplomacy_tools = source_fixture._base(tmp_path, observer=country)
    session.session_id = capture_fixture.SESSION
    session.record["session_id"] = session.session_id
    source = NativeCountryForcesSource(base)
    service = InformationService(CompositeSource(base, [source]), tmp_path / "current-forces.sqlite3")
    try:
        tools = InformationTools(service)
        query = source_fixture._query(["army_size", "navy_size", "army_composition"])
        query["object"]["country"] = country
        result = tools.call("information_query", {
            "request_id": "current-force-profile", "queries": [query],
        })
        assert result["items"][0]["army_regiments"]["current"] == 1
        assert result["items"][0]["navy_ships"]["current"] == 1
        full = tools.call("information_get_result", {"result_id": result["result_id"], "view": "full"})
        fields = full["items"][0]["fields"]
        assert all(field["status"] == "known" for field in fields.values())
        assert fields["army_composition"]["value"][0]["unit_types"]["value"][0]["key"] == "infantry"
        assert diplomacy_tools.inspect_calls == []
    finally:
        service.close()


def test_records_keep_private_identity_raw_body_kind_and_strength() -> None:
    record = memory.read_fields(_reader(), MODULE_BASE, COUNTRY)
    assert record["status"] == "observed"
    rows = record["record"]["records"]
    assert [(row["id_type"], row["id"], row["type_kind"], row["strength_raw"]) for row in rows] == [(55, 13512, 0, 981), (55, 13513, 3, 670)]
    assert all(len(row["record_body_raw_hex"]) == 0x60 for row in rows)
    assert all(len(row["type_kind_raw_hex"]) == 8 for row in rows)
    assert memory.validate_record(record["record"])


def test_duplicate_pointer_id_and_cross_group_overlap_fail_closed() -> None:
    for kwargs, expected in (
        ({"duplicate_pointer": True}, "repeated"),
        ({"duplicate_id": True}, "repeated"),
        ({"cross_group_duplicate": True}, "repeated"),
        ({"bad_pointer": True}, "invalid"),
    ):
        record = memory.read_fields(_reader(**kwargs), MODULE_BASE, COUNTRY)
        assert record["status"] == "unknown"
        assert expected in str(record["reason"])


def test_cycle_oversize_negative_strength_and_runtime_guard_fail_closed() -> None:
    for kwargs, expected in (
        ({"cycle": True}, "repeated"),
        ({"oversized": True}, "out_of_bound"),
        ({"negative_strength": True}, "negative"),
        ({"guard_tamper": True}, "runtime_code_guard"),
    ):
        record = memory.read_fields(_reader(**kwargs), MODULE_BASE, COUNTRY)
        assert record["status"] == "unknown"
        assert expected in str(record["reason"])


def test_validator_rejects_tampered_private_record() -> None:
    record = memory.read_fields(_reader(), MODULE_BASE, COUNTRY)
    assert memory.validate_record(record["record"])
    tampered = deepcopy(record["record"])
    tampered["records"][0]["strength_raw"] += 1
    assert not memory.validate_record(tampered)


def test_capture_validator_checks_identity_date_cleanup_and_double_pass(monkeypatch) -> None:
    creation = 134375854500787403
    session = "42960-1dd6600b1e8b4cb"
    fake_reader = _reader()

    class FakeKernel:
        def OpenProcess(self, _mask, _inherit, _pid):
            return object()

        def CloseHandle(self, _handle):
            return True

    def fake_identity(report, _document, _kernel, _handle):
        report["identity"].update({
            "installation_pid": 42960,
            "installation_creation_filetime": creation,
            "installation_session_id": session,
            "process_creation_filetime": creation,
            "process_path": "fake-eu4.exe",
            "process_path_sha256": memory.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_matches_installation": True,
            "module_path": "fake-eu4.exe",
            "module_path_matches_process": True,
            "binding_verified": True,
        })
        return MODULE_BASE

    monkeypatch.setattr(memory, "_load_installation", lambda _path: {"pid": 42960, "creation_filetime": creation, "session_id": session, "game_sha256": memory.EXPECTED_EXE_SHA256})
    monkeypatch.setattr(memory, "_configure_kernel", lambda: FakeKernel())
    monkeypatch.setattr(memory, "_capture_identity", fake_identity)
    monkeypatch.setattr(memory, "_file_code_guard", lambda _path, _profile=None: {"status": "observed", "checks": {"synthetic": True}})
    monkeypatch.setattr(memory, "AddressBoundedRPM", lambda _kernel, _handle, _module_base: fake_reader)
    report = memory.capture(Path("synthetic-installation.json"))
    assert report["status"] == "observed", report["errors"]
    assert report["cleanup"]["handle_close"] == {"status": "closed", "success": True, "closed": True}
    context = {"session_id": session, "game_sha256": memory.EXPECTED_EXE_SHA256, "game_date": 56562768}
    assert memory.validate_capture(report, context, creation)
    stale = deepcopy(report)
    stale["after"]["record"]["records"][0]["strength_raw"] += 1
    assert not memory.validate_capture(stale, context, creation)
    assert not memory.validate_capture(report, {**context, "game_date": 56562769}, creation)
    stale = deepcopy(report)
    stale["before"]["country_pointer"] = "0x6400001000"
    assert not memory.validate_capture(stale, context, creation)
    stale = deepcopy(report)
    stale["before"]["record"]["game_date"]["value"] += 1
    assert not memory.validate_capture(stale, context, creation)
    stale = deepcopy(report)
    stale["module_base"] = "0x150000000"
    assert not memory.validate_capture(stale, context, creation)


def test_capture_second_country_scan_rejects_pointer_or_handle_change(monkeypatch) -> None:
    creation = 134375854500787403
    session = "42960-1dd6600b1e8b4cb"

    class FakeKernel:
        def OpenProcess(self, _mask, _inherit, _pid):
            return object()

        def CloseHandle(self, _handle):
            return True

    def fake_identity(report, _document, _kernel, _handle):
        report["identity"].update({
            "installation_pid": 42960,
            "installation_creation_filetime": creation,
            "installation_session_id": session,
            "process_creation_filetime": creation,
            "process_path": "fake-eu4.exe",
            "process_path_sha256": memory.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_matches_installation": True,
            "module_path": "fake-eu4.exe",
            "module_path_matches_process": True,
            "binding_verified": True,
        })
        return MODULE_BASE

    for mode in ("pointer", "handle"):
        monkeypatch.setattr(memory, "_load_installation", lambda _path: {"pid": 42960, "creation_filetime": creation, "session_id": session, "game_sha256": memory.EXPECTED_EXE_SHA256})
        monkeypatch.setattr(memory, "_configure_kernel", lambda: FakeKernel())
        monkeypatch.setattr(memory, "_capture_identity", fake_identity)
        monkeypatch.setattr(memory, "_file_code_guard", lambda _path, _profile=None: {"status": "observed", "checks": {"synthetic": True}})
        reader = _mutating_reader(mode)
        monkeypatch.setattr(memory, "AddressBoundedRPM", lambda _kernel, _handle, _module_base, reader=reader: reader)
        report = memory.capture(Path("synthetic-installation.json"))
        assert report["status"] == "unknown"
        assert report["completed"] is True
        assert report["cleanup"]["handle_close"]["status"] == "closed"
        assert report["doublepass"]["performed"] is False or report["doublepass"]["consistent"] is False


def test_cleanup_failure_downgrades_capture(monkeypatch) -> None:
    creation = 134375854500787403
    session = "42960-1dd6600b1e8b4cb"

    class FakeKernel:
        def OpenProcess(self, _mask, _inherit, _pid):
            return object()

        def CloseHandle(self, _handle):
            return False

    def fake_identity(report, _document, _kernel, _handle):
        report["identity"].update({
            "installation_pid": 42960,
            "installation_creation_filetime": creation,
            "installation_session_id": session,
            "process_creation_filetime": creation,
            "process_path": "fake-eu4.exe",
            "process_path_sha256": memory.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_matches_installation": True,
            "module_path": "fake-eu4.exe",
            "module_path_matches_process": True,
            "binding_verified": True,
        })
        return MODULE_BASE

    monkeypatch.setattr(memory, "_load_installation", lambda _path: {"pid": 42960, "creation_filetime": creation, "session_id": session, "game_sha256": memory.EXPECTED_EXE_SHA256})
    monkeypatch.setattr(memory, "_configure_kernel", lambda: FakeKernel())
    monkeypatch.setattr(memory, "_capture_identity", fake_identity)
    monkeypatch.setattr(memory, "_file_code_guard", lambda _path, _profile=None: {"status": "observed", "checks": {"synthetic": True}})
    monkeypatch.setattr(memory, "AddressBoundedRPM", lambda _kernel, _handle, _module_base: _reader())
    report = memory.capture(Path("synthetic-installation.json"))
    assert report["status"] == "unknown"
    assert report["completed"] is True
    cleanup = report["cleanup"]["handle_close"]
    assert cleanup["status"] == "error"
    assert cleanup["success"] is False and cleanup["closed"] is False
    assert isinstance(cleanup.get("error"), str)
    assert any(error.get("stage") == "cleanup" for error in report["errors"])


def test_existing_raw_receipt_is_only_replayed_as_offline_evidence() -> None:
    path = Path("work/runtime/information-country-forces-20261027-001/country-forces-raw-rpm-001.json")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "073ef90db0e83b316d6576fecacbe62f7da0e33428ef2f16948aa4f1e1bba12f"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    rows = receipt["snapshot_before"]["force_chain"]["records"]
    assert receipt["status"] == "observed_raw_candidate"
    assert len(rows) == receipt["snapshot_before"]["force_chain"]["unique_record_count"] == 60
    assert all({"record_pointer", "record_body_raw_hex", "type_kind", "raw_amount_signed_i32"} <= set(row) for row in rows)
    assert receipt["access"]["native_game_calls"] is False
