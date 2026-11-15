"""Offline synthetic tests for the bounded outgoing-rival memory seam."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import country_rivals as adapter
from bridge.information import country_rivals_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
TABLE = 0x6300000000
GAME = 0x6500000000
FRA = 0x6400000000
BUR = 0x6400010000
ORL = 0x6400020000
PAP = 0x6400030000
C00 = 0x6400040000
NODE1 = 0x6100000000
NODE2 = 0x6100001000
NODE3 = 0x6100002000
CREATION = 92
SESSION_ID = "rivals-test-session"
GAME_DATE = 56_562_768
CONTEXT = {
    "status": "ready", "mode": "live", "session_id": SESSION_ID,
    "game_sha256": memory.EXPECTED_EXE_SHA256, "game_version": memory.EXPECTED_VERSION,
    "observer": "FRA", "game_date": GAME_DATE,
}


class BoundedReader:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: byte for index, byte in enumerate(raw)})

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def i32(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected synthetic read {label} {address:#x} {size}") from exc


class MutatingReader(BoundedReader):
    def __init__(self, mode: str) -> None:
        super().__init__()
        self.mode = mode
        self.changed = False

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = super().read(address, size, label)
        if self.changed:
            return raw
        if self.mode == "date" and label == "country_rivals.game_date":
            self.i32(GAME + 0x1DD0, GAME_DATE + 1)
            self.changed = True
        elif self.mode == "node" and label == "country_rivals.node[0].since_date":
            self.i32(NODE1 + 0x18, 56_560_002)
            self.changed = True
        return raw


def _fullref(tag: str, slot: int) -> int:
    return (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _reader(*, targets: list[str] | None = None, empty: bool = False,
            cycle: bool = False, duplicate_country: bool = False,
            count_override: int | None = None, over_count: int | None = None,
            nonnull_empty_head: bool = False, bad_next_pointer: bool = False,
            bad_head_pointer: bool = False, target_fullref_mismatch: bool = False,
            target_generation_mismatch: bool = False, special_tag: bool = False,
            self_rival: bool = False,
            country_fullref_mismatch: bool = False, guard_tamper: bool = False,
            mutating: str | None = None) -> BoundedReader:
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader: BoundedReader = MutatingReader(mutating) if mutating else BoundedReader()
    for index, (_name, rva, _end, raw) in enumerate(memory._profile_code_guards(profile)):
        guarded = (bytes([raw[0] ^ 1]) + raw[1:]) if guard_tamper and index == 0 else raw
        reader.put(MODULE_BASE + rva, guarded)
    reader.qword(MODULE_BASE + layout["database_global_rva"], DATABASE)
    reader.qword(DATABASE + layout["database_table_offset"], TABLE)
    reader.i32(DATABASE + layout["database_table_count_offset"], 9)
    country_rows = {1: ("BUR", BUR), 2: ("ORL", ORL), 3: ("PAP", PAP),
                    4: ("C00", C00), 5: ("FRA", FRA)}
    for slot in range(9):
        tag_pointer = country_rows.get(slot)
        pointer = tag_pointer[1] if tag_pointer else 0
        reader.qword(TABLE + slot * 8, pointer)
        if tag_pointer:
            tag = tag_pointer[0]
            fullref_slot = slot + 1 if country_fullref_mismatch and tag == "FRA" else slot
            reader.qword(pointer + layout["country_fullref_offset"], _fullref(tag, fullref_slot))
    reader.qword(MODULE_BASE + layout["game_global_rva"], GAME)
    reader.i32(GAME + layout["game_date_offset"], GAME_DATE)

    if targets is None:
        targets = ["PAP", "BUR"]
    if self_rival:
        targets = ["FRA"]
    if duplicate_country and len(targets) >= 2:
        targets = [targets[0], targets[0], *targets[2:]]
    node_addresses = [NODE1, NODE2, NODE3]
    if empty:
        targets = []
    count = len(targets) if count_override is None else count_override
    if over_count is not None:
        count = over_count
    head = 0 if not targets and not nonnull_empty_head else NODE1
    if bad_head_pointer:
        head = 0x1
    reader.qword(FRA + layout["country_rivals_head_offset"], head)
    reader.i32(FRA + layout["country_rivals_count_offset"], count)
    if count == 0:
        return reader
    for index, tag in enumerate(targets[:3]):
        node = node_addresses[index]
        slot_by_tag = {"BUR": 1, "ORL": 2, "PAP": 3, "C00": 4, "FRA": 5}
        slot = slot_by_tag[tag]
        fullref = _fullref(tag, slot)
        if target_fullref_mismatch and index == 0:
            fullref = _fullref("BUR", 2)  # valid tag bytes, wrong database slot/tag pair
        if target_generation_mismatch and index == 0:
            fullref ^= 1 << 48  # same slot/tag, different opaque high reference bits
        if special_tag and index == 0:
            fullref = _fullref("---", slot)
        reader.qword(node + layout["rival_node_fullref_offset"], fullref)
        reader.i32(node + layout["rival_node_since_date_offset"], 56_560_001 + index)
        next_node = node_addresses[index + 1] if index + 1 < len(targets) else 0
        if cycle and index + 1 == len(targets):
            next_node = NODE1
        if bad_next_pointer and index + 1 == len(targets):
            next_node = 0x1
        reader.qword(node + layout["rival_node_next_offset"], next_node)
    return reader


def _profile_file_guard(path: Path, profile):
    records, checks = {}, {}
    for name, rva, end, raw in memory._profile_code_guards(profile):
        digest = hashlib.sha256(raw).hexdigest()
        records[name] = {"rva": hex(rva), "rva_end_exclusive": hex(end),
                         "expected_hex": raw.hex(), "actual_hex": raw.hex(),
                         "expected_sha256": digest, "actual_sha256": digest}
        checks[name] = True
    return {"status": "observed", "path": str(path), "checks": checks, "records": records,
            "unknown_conditions": []}


def _install_capture(monkeypatch, reader: BoundedReader, *, close_ok: bool = True) -> None:
    class FakeKernel:
        def OpenProcess(self, _mask, _inherit, _pid):
            return object()

        def CloseHandle(self, _handle):
            return close_ok

    kernel = FakeKernel()
    process_path = str(Path("synthetic-eu4.exe"))
    document = {"pid": 7, "creation_filetime": CREATION, "session_id": SESSION_ID,
                "game_sha256": memory.EXPECTED_EXE_SHA256}

    def identity(report, _document, _kernel, _handle):
        report["identity"].update({
            "installation_pid": 7,
            "installation_creation_filetime": CREATION,
            "installation_session_id": SESSION_ID,
            "process_path": process_path,
            "process_path_sha256": memory.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_filetime": CREATION,
            "process_creation_matches_installation": True,
            "module_path": process_path,
            "module_path_matches_process": True,
            "binding_verified": True,
        })
        return MODULE_BASE

    monkeypatch.setattr(memory, "_load_installation", lambda _path: document)
    monkeypatch.setattr(memory, "_configure_kernel", lambda: kernel)
    monkeypatch.setattr(memory, "_capture_identity", identity)
    monkeypatch.setattr(memory, "AddressBoundedRPM", lambda *_args: reader)
    monkeypatch.setattr(memory, "_file_code_guard",
                        lambda path, profile=None: _profile_file_guard(Path(path), profile or memory._load_profile()))


def _read_result(**kwargs):
    reader = _reader(**kwargs)
    result = memory.read_fields(reader, MODULE_BASE, FRA)
    return reader, result


def test_profile_pin_and_sorted_public_members_preserve_private_native_order() -> None:
    profile = memory._load_profile()
    assert profile["profile_id"] == memory.EXPECTED_PROFILE_ID
    assert memory._static_contract_guard(profile)["status"] == "observed"
    _, result = _read_result(targets=["PAP", "C00", "BUR"])
    assert result["status"] == "observed"
    record = result["record"]
    assert record["fields"]["rivals"]["value"] == ["BUR", "C00", "PAP"]
    assert [row["tag"] for row in record["private"]["native_entries"]] == ["PAP", "C00", "BUR"]
    assert all("address" not in key and "pointer" not in key for key in record["fields"]["rivals"])
    assert record["fields"]["rivals"]["direction"] == "outgoing_declared_by_country"
    assert memory.validate_record(record)
    assert result["read_budget"]["bytes_reserved"] <= memory.READ_BUDGET_BYTES


def test_real_empty_list_requires_both_null_head_and_zero_count() -> None:
    _, result = _read_result(empty=True)
    assert result["status"] == "observed"
    assert result["fields"]["rivals"]["value"] == []
    assert result["record"]["private"]["rival_list_head"] is None
    assert result["record"]["private"]["rival_count"] == 0
    assert memory.validate_record(result["record"])
    _, invalid = _read_result(empty=True, nonnull_empty_head=True)
    assert invalid["status"] == "unknown"
    assert "empty_rival_list_head_nonnull" in invalid["reason"]


@pytest.mark.parametrize(("kwargs", "reason"), [
    ({"cycle": True}, "cycle"),
    ({"duplicate_country": True}, "duplicate_country"),
    ({"count_override": 1}, "detached_tail"),
    ({"count_override": 3}, "chain_short"),
    ({"over_count": 65}, "out_of_bound"),
    ({"over_count": -1}, "out_of_bound"),
    ({"bad_head_pointer": True}, "head_invalid"),
    ({"bad_next_pointer": True}, "pointer_invalid"),
    ({"target_fullref_mismatch": True}, "database_binding_mismatch"),
    ({"target_generation_mismatch": True}, "database_binding_mismatch"),
    ({"special_tag": True}, "fullref_invalid"),
    ({"self_rival": True}, "self_membership"),
    ({"country_fullref_mismatch": True}, "identity_match_count_invalid"),
    ({"guard_tamper": True}, "runtime_code_guard"),
])
def test_invalid_graphs_fail_closed(kwargs, reason) -> None:
    _, result = _read_result(**kwargs)
    assert result["status"] == "unknown"
    assert reason in result["reason"]


def test_record_validator_binds_target_fullref_and_source_trace_bytes() -> None:
    _, result = _read_result()
    record = result["record"]
    assert memory.validate_record(record)

    tampered = deepcopy(record)
    tampered["private"]["native_entries"][0]["fullref_raw_hex"] = "0000000000000000"
    assert not memory.validate_record(tampered)

    tampered_trace = deepcopy(record)
    item = next(row for row in tampered_trace["observation"]["read_log"]
                if row["label"] == "country_rivals.node[0].fullref")
    item["raw_hex"] = "0000000000000000"
    item["sha256"] = hashlib.sha256(bytes.fromhex(item["raw_hex"])).hexdigest()
    assert not memory.validate_record(tampered_trace)

    tampered_database = deepcopy(record)
    slot = tampered_database["private"]["country_scan"]["slots"][1]
    slot["fullref_raw_hex"] = "0000000000000000"
    assert not memory.validate_record(tampered_database)


def test_trace_rejects_nonunique_labels_and_address_tampering() -> None:
    _, result = _read_result()
    record = result["record"]
    trace = record["observation"]["read_log"]
    assert memory.validate_record(record)
    duplicate = deepcopy(record)
    duplicate["observation"]["read_log"].append(deepcopy(trace[0]))
    duplicate["observation"]["read_budget"]["bytes_reserved"] += trace[0]["size"]
    assert not memory.validate_record(duplicate)
    bad_address = deepcopy(record)
    label = next(row for row in bad_address["observation"]["read_log"]
                 if row["label"] == "country_rivals.list_head")
    label["address"] = "0x1"
    assert not memory.validate_record(bad_address)


def test_two_pass_detects_date_and_node_changes(monkeypatch, tmp_path: Path) -> None:
    for mode in ("date", "node"):
        _install_capture(monkeypatch, _reader(mutating=mode))
        report = memory.capture(tmp_path / "installation.json")
        assert report["status"] == "doublepass_mismatch"
        assert report["doublepass"]["consistent"] is False
        assert report["cleanup"]["handle_close"] == {"status": "closed", "success": True, "closed": True}


def test_capture_validator_checks_session_creation_date_and_cleanup(monkeypatch, tmp_path: Path) -> None:
    _install_capture(monkeypatch, _reader())
    report = memory.capture(tmp_path / "installation.json")
    assert report["status"] == "observed"
    assert memory.validate_capture(report, CONTEXT, CREATION)
    assert not memory.validate_capture(report, {**CONTEXT, "session_id": "other"}, CREATION)
    assert not memory.validate_capture(report, {**CONTEXT, "game_date": GAME_DATE + 1}, CREATION)
    assert not memory.validate_capture(report, CONTEXT, CREATION + 1)


def test_cleanup_failure_downgrades_report(monkeypatch, tmp_path: Path) -> None:
    _install_capture(monkeypatch, _reader(), close_ok=False)
    report = memory.capture(tmp_path / "installation.json")
    assert report["status"] == "unknown"
    assert report["completed"] is False
    assert report["fields"]["rivals"]["status"] == "unknown"
    assert not memory.validate_capture(report, CONTEXT, CREATION)


def test_real_validator_and_adapter_project_synthetic_capture(monkeypatch, tmp_path: Path) -> None:
    """Exercise adapter -> real capture -> real validator without target access."""
    _install_capture(monkeypatch, _reader(targets=["PAP", "BUR"]))
    base = SimpleNamespace(
        context=lambda: dict(CONTEXT),
        session=SimpleNamespace(
            directory=tmp_path, creation_filetime=CREATION,
            record={"session_id": SESSION_ID, "creation_filetime": CREATION},
        ),
        read=lambda *_args: (_ for _ in ()).throw(AssertionError("no diplomacy inspection")),
    )
    source = adapter.NativeCountryRivalsSource(
        base, capture=lambda installation, country: memory.capture(installation, country))
    query = {"topic": "R03", "object": {"type": "country", "country": "FRA"},
             "fields": ["rivals"], "parameters": {}}
    result = source.read(query, base.context())
    assert result["fields"]["rivals"]["status"] == "known"
    assert result["fields"]["rivals"]["value"] == ["BUR", "PAP"]
    assert result["fields"]["rivals"]["direction"] == "outgoing_declared_by_country"
    assert result["complete"] is True
    assert "0x" not in repr(result)
