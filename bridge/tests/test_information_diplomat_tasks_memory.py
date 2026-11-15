from __future__ import annotations

import json
import hashlib
from copy import deepcopy
from pathlib import Path

from bridge.information import diplomat_tasks_memory as memory


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x6000000000
HOLDER = 0x6100000000
MANAGER = 0x6100001000
VECTOR = 0x6100002000
DATABASE = 0x6200000000
TABLE = 0x6300000000
FRA_COUNTRY = 0x6400000000
BUR_COUNTRY = 0x6400001000
ORL_COUNTRY = 0x6400002000


class BoundedReader:
    def __init__(self):
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.change_after: dict[int, bytes] | None = None
        self.bytes_requested = 0
        self.calls = 0

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: value for index, value in enumerate(raw)})

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def i32(self, address: int, value: int) -> None:
        self.put(address, (int(value) & 0xFFFFFFFF).to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        self.bytes_requested += size
        self.calls += 1
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected bounded read: {label} {address:#x} {size}") from exc

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)


def _fullref(tag: str, slot: int) -> int:
    return (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _reader(*, entries: list[dict] | None = None, bad_fullref: bool = False, oversized: bool = False) -> BoundedReader:
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        reader.put(MODULE_BASE + rva, raw)

    reader.qword(MODULE_BASE + layout["database_global_rva"], DATABASE)
    reader.qword(DATABASE + layout["database_table_offset"], TABLE)
    reader.i32(DATABASE + layout["database_table_count_offset"], 256)
    fra = _fullref("FRA", 122)
    bur = _fullref("BUR", 46)
    orl = _fullref("ORL", 47)
    reader.qword(TABLE + 122 * 8, FRA_COUNTRY)
    reader.qword(TABLE + 46 * 8, BUR_COUNTRY)
    reader.qword(TABLE + 47 * 8, ORL_COUNTRY)
    for slot in range(256):
        if slot not in {46, 47, 122}:
            reader.qword(TABLE + slot * 8, 0)
    reader.qword(FRA_COUNTRY + layout["country_fullref_offset"], fra)
    reader.qword(BUR_COUNTRY + layout["country_fullref_offset"], 0 if bad_fullref else bur)
    reader.qword(ORL_COUNTRY + layout["country_fullref_offset"], orl)

    reader.qword(MODULE_BASE + layout["game_global_rva"], 0x6500000000)
    reader.i32(0x6500000000 + layout["game_date_offset"], 56559408)
    reader.qword(COUNTRY_POINTER + layout["country_tasks_offset"], HOLDER)
    reader.qword(FRA_COUNTRY + layout["country_tasks_offset"], HOLDER)
    reader.qword(HOLDER + layout["holder_manager_offset"], MANAGER)
    if oversized:
        reader.qword(MANAGER + layout["vector_begin_offset"], VECTOR)
        reader.qword(MANAGER + layout["vector_end_offset"], VECTOR + 257 * 8)
        return reader

    if entries is None:
        entries = [
            {"state": 2, "id": 0, "actor": fra, "recipient": bur, "selector": memory.KNOWN_SELECTOR, "date20": 56559000, "date24": 56559048, "raw2c": 4},
            {"state": 1, "id": 1, "actor": fra, "recipient": orl, "selector": 10559, "date20": 56559000, "date24": 56559048, "raw2c": 6},
            {"state": 0, "id": 2, "record": 0},
        ]
    reader.qword(MANAGER + layout["vector_begin_offset"], VECTOR)
    reader.qword(MANAGER + layout["vector_end_offset"], VECTOR + len(entries) * 8)
    for index, item in enumerate(entries):
        entry = 0x6600000000 + index * 0x1000
        record = item["record"] if "record" in item else (0x6700000000 + index * 0x1000)
        reader.qword(VECTOR + index * 8, entry)
        reader.qword(entry + layout["entry_record_offset"], record)
        reader.put(entry + layout["entry_state_offset"], bytes([item.get("state", 0) & 0xFF]))
        reader.i32(entry + layout["entry_id_offset"], item.get("id", index))
        if record:
            reader.qword(record + layout["record_actor_offset"], item["actor"])
            reader.qword(record + layout["record_recipient_offset"], item["recipient"])
            reader.i32(record + layout["record_selector_offset"], item["selector"])
            reader.i32(record + layout["record_date_begin_offset"], item["date20"])
            reader.i32(record + layout["record_date_end_offset"], item["date24"])
            reader.i32(record + layout["record_raw_unknown_offset"], item["raw2c"])
    return reader


def _archived_raw_reader() -> tuple[BoundedReader, dict]:
    """Replay the raw snapshot offline; raw001 itself does not name this child profile."""
    source = Path("work/runtime/information-diplomat-favor-tasks-20261027-001/independent-raw-001.json")
    assert hashlib.sha256(source.read_bytes()).hexdigest() == "b40c1638bf227fff1734a0930ca91beda4900345e8b6fbc2567eca8c2a529528"
    payload = json.loads(source.read_text(encoding="utf-8"))
    raw_pass = payload["diplomat_tasks_inputs"][0]
    profile = memory._load_legacy_archive_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        reader.put(MODULE_BASE + rva, raw)

    reader.qword(MODULE_BASE + layout["database_global_rva"], DATABASE)
    reader.qword(DATABASE + layout["database_table_offset"], TABLE)
    reader.i32(DATABASE + layout["database_table_count_offset"], 256)
    instances = raw_pass["instances"]
    fullrefs = {raw_pass["country_fullref_raw_hex"]}
    for item in instances:
        record_raw = item.get("record_raw") or {}
        fullrefs.update((record_raw.get("actor"), record_raw.get("recipient")))
    country_ptrs = {
        raw_pass["country_fullref_raw_hex"]: FRA_COUNTRY,
        "4255520075000001": BUR_COUNTRY,
        "4f524c007e000001": ORL_COUNTRY,
    }
    for fullref_hex in fullrefs:
        if not fullref_hex:
            continue
        fullref = int.from_bytes(bytes.fromhex(fullref_hex), "little")
        slot = (fullref >> 32) & 0xFFFF
        pointer = country_ptrs[fullref_hex]
        reader.qword(TABLE + slot * 8, pointer)
        reader.qword(pointer + layout["country_fullref_offset"], fullref)

    holder = int(raw_pass["holder"], 16)
    manager = int(raw_pass["manager"], 16)
    reader.qword(COUNTRY_POINTER + layout["country_tasks_offset"], holder)
    reader.qword(holder + layout["holder_manager_offset"], manager)
    vector = VECTOR
    reader.qword(manager + layout["vector_begin_offset"], vector)
    reader.qword(manager + layout["vector_end_offset"], vector + len(instances) * layout["entry_stride"])
    for index, item in enumerate(instances):
        entry = int(item["entry"], 16)
        reader.qword(vector + index * layout["entry_stride"], entry)
        record = int(item["record"], 16)
        reader.qword(entry + layout["entry_record_offset"], record)
        reader.put(entry + layout["entry_state_offset"], bytes.fromhex(item["state_raw_hex"]))
        reader.put(entry + layout["entry_id_offset"], bytes.fromhex(item["id_raw_hex"]))
        if record:
            record_raw = item["record_raw"]
            reader.put(record + layout["record_actor_offset"], bytes.fromhex(record_raw["actor"]))
            reader.put(record + layout["record_recipient_offset"], bytes.fromhex(record_raw["recipient"]))
            reader.put(record + layout["record_selector_offset"], bytes.fromhex(record_raw["token"]))
            reader.put(record + layout["record_date_begin_offset"], bytes.fromhex(record_raw["date_20"]))
            reader.put(record + layout["record_date_end_offset"], bytes.fromhex(record_raw["date_24"]))
            reader.put(record + layout["record_raw_unknown_offset"], bytes.fromhex(record_raw["unknown_2c"]))
    return reader, profile


def _immutable_snapshot(reader: BoundedReader) -> memory.OfflineArchiveSnapshotReader:
    segments: list[tuple[int, bytes]] = []
    start = previous = None
    chunk = bytearray()
    for address, value in sorted(reader.memory.items()):
        if start is None or address != previous + 1 or len(chunk) >= memory.MAX_SINGLE_RPM:
            if chunk:
                segments.append((start, bytes(chunk)))
            start = address
            chunk = bytearray()
        chunk.append(value)
        previous = address
        if len(chunk) == memory.MAX_SINGLE_RPM:
            segments.append((start, bytes(chunk)))
            start = previous = None
            chunk = bytearray()
    if chunk:
        segments.append((start, bytes(chunk)))
    return memory.OfflineArchiveSnapshotReader(segments)


def test_profile_guard_and_empty_graph_are_bounded_and_known() -> None:
    reader = _reader(entries=[])
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert record["profile_id"] == memory.EXPECTED_PROFILE_ID
    assert record["profile_sha256"] == memory.EXPECTED_PROFILE_SHA256
    assert record["values"]["diplomat_tasks"] == []
    assert record["instance_count_observed"] == 0
    assert memory.validate_record(record)
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_active_returning_idle_and_selector_semantics_remain_raw() -> None:
    record = memory.read_fields(_reader(), MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    items = record["values"]["diplomat_tasks"]
    assert [item["state"] for item in items] == ["active", "returning", "idle"]
    assert items[0]["task_family"] == "build_spy_network"
    assert items[1]["task_family"] is None
    assert items[1]["task_family_status"] == "unknown"
    assert items[1]["lifecycle_date_raw"]["raw_20"] == 56559000
    assert items[1]["raw_2c"] == 6
    assert items[2]["record_address"] is None
    assert items[2]["raw_action_type_a8"] is None
    assert memory.validate_record(record)


def test_archived_raw001_replays_two_active_task_records_and_two_idle_entries() -> None:
    fixture_reader, legacy_profile = _archived_raw_reader()
    reader = _immutable_snapshot(fixture_reader)
    assert type(reader) is memory.OfflineArchiveSnapshotReader
    assert reader.byte_count <= memory.READ_BUDGET_BYTES
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER, profile=legacy_profile, offline_legacy_archive=True)
    assert record["status"] == "observed"
    assert record["profile_id"] == memory.LEGACY_PROFILE_ID
    assert record["profile_sha256"] == memory.LEGACY_PROFILE_SHA256
    items = record["values"]["diplomat_tasks"]
    assert len(items) == 4
    assert [item["state"] for item in items] == ["active", "active", "idle", "idle"]
    assert [item["raw_id_44"] for item in items] == [0, 1, 2, 3]
    assert [item["task_family"] for item in items[:2]] == ["build_spy_network", None]
    assert [(item["actor"], item["recipient"]) for item in items[:2]] == [("FRA", "BUR"), ("FRA", "ORL")]
    assert [item["raw_2c"] for item in items[:2]] == [2, 1]
    assert memory.validate_record(record, profile=legacy_profile, offline_legacy_archive=True)
    assert not memory.validate_record(record)


def test_v1_profile_is_explicit_archive_only_and_never_the_live_default() -> None:
    current = memory._load_profile()
    assert current["profile_id"] == "diplomat-tasks-memory-1374-v2"
    assert current["profile_version"] == 2
    assert memory.PROFILE_FILE.name == "diplomat-tasks-memory-1374-v2-sampling-r1.json"
    assert memory._source_evidence(current)[-1]["sha256"] == "eea57aab848003a97e63138e093b9146a100e6cf9dd86ae7adaddbc3fc636380"

    legacy = memory._load_legacy_archive_profile()
    assert legacy["profile_id"] == memory.LEGACY_PROFILE_ID
    assert legacy["_validated_source_evidence"][-1]["verified_from_archive_path"] == memory.LEGACY_ARCHIVE_NATIVE_SOURCE.as_posix()
    try:
        memory._load_profile(memory.LEGACY_PROFILE_FILE, memory.LEGACY_PROFILE_SHA256)
    except memory.ProfileError as exc:
        assert str(exc) == "profile_selection_invalid"
    else:
        raise AssertionError("v1 was loaded through the live/default profile loader")

    reader = _reader(entries=[])
    rejected = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER, profile=legacy, offline_legacy_archive=True)
    assert rejected["status"] == "unknown"
    assert "legacy_offline_snapshot_reader_required" in rejected["reason"]
    assert reader.calls == 0

    rpm = memory.AddressBoundedRPM(None, None, MODULE_BASE)
    rejected_rpm = memory.read_fields(rpm, MODULE_BASE, COUNTRY_POINTER, profile=legacy, offline_legacy_archive=True)
    assert rejected_rpm["status"] == "unknown"
    assert "legacy_offline_snapshot_reader_required" in rejected_rpm["reason"]
    assert rpm.calls == 0 and rpm.bytes_requested == 0

    invalid_flag = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER, profile=legacy, offline_legacy_archive=1)
    assert invalid_flag["status"] == "unknown"
    assert "offline_archive_flag_invalid" in invalid_flag["reason"]


def test_offline_snapshot_reader_is_immutable_and_enforces_byte_address_bounds() -> None:
    snapshot = memory.OfflineArchiveSnapshotReader(((0x7000000000, b"snapshot"),))
    assert snapshot.read(0x7000000000, 8, "test.snapshot") == b"snapshot"
    assert snapshot.byte_count == 8
    try:
        snapshot._segments = ()
    except AttributeError:
        pass
    else:
        raise AssertionError("offline snapshot reader accepted mutation")

    rejected_segments = [
        ((True, b"x"),),
        ((0x7000000000, b"x" * (memory.MAX_SINGLE_RPM + 1)),),
        ((0x800000000001, b"x"),),
        ((0x7000000000, b"ab"), (0x7000000001, b"cd")),
        tuple((0x7100000000 + i * 0x10000, b"x" * memory.MAX_SINGLE_RPM) for i in range(5)),
    ]
    for segments in rejected_segments:
        try:
            memory.OfflineArchiveSnapshotReader(segments)
        except ValueError:
            continue
        raise AssertionError("offline snapshot accepted an invalid segment set")


def test_fullref_mismatch_retracts_task_values_instead_of_tag_only_known() -> None:
    record = memory.read_fields(_reader(bad_fullref=True), MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "unknown"
    assert record["values"] is None
    assert "fullref" in record["reason"]


def test_vector_limit_and_tamper_are_fail_closed() -> None:
    oversized = memory.read_fields(_reader(oversized=True), MODULE_BASE, COUNTRY_POINTER)
    assert oversized["status"] == "unknown"
    record = memory.read_fields(_reader(), MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    record["values"]["diplomat_tasks"][0]["raw_2c"] += 1
    assert not memory.validate_record(record)


def test_null_entry_pointer_is_unknown_instead_of_synthetic_idle() -> None:
    reader = _reader(entries=[])
    layout = memory._profile_layout(memory._load_profile())
    reader.qword(MANAGER + layout["vector_begin_offset"], VECTOR)
    reader.qword(MANAGER + layout["vector_end_offset"], VECTOR + layout["entry_stride"])
    reader.qword(VECTOR, 0)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "unknown"
    assert record["values"] is None
    assert "entry_pointer_null" in record["reason"]


def test_retract_record_removes_consumable_values() -> None:
    record = memory.read_fields(_reader(entries=[]), MODULE_BASE, COUNTRY_POINTER)
    retracted = memory.retract_record(record, "doublepass_mismatch")
    assert retracted["status"] == "unknown"
    assert retracted["values"] is None
    assert retracted["fields"]["diplomat_tasks"]["status"] == "unknown"


def test_capture_validate_lifecycle_checks_cleanup_date_and_top_projection(monkeypatch) -> None:
    creation_filetime = 134375498253940149
    session_id = "17112-1dd65cdbff135b5"
    fake_reader = _reader()

    class FakeKernel:
        def OpenProcess(self, _mask, _inherit, _pid):
            return object()

        def CloseHandle(self, _handle):
            return True

    def fake_identity(report, _document, _kernel, _handle):
        report["identity"].update(
            {
                "installation_creation_filetime": creation_filetime,
                "installation_session_id": session_id,
                "process_creation_filetime": creation_filetime,
                "process_path": "fake-eu4.exe",
                "process_path_sha256": memory.EXPECTED_EXE_SHA256,
                "process_path_sha256_matches_expected": True,
                "process_creation_matches_installation": True,
                "binding_verified": True,
            }
        )
        return MODULE_BASE

    fake_reader.bytes_requested = 0
    fake_reader.calls = 0
    monkeypatch.setattr(memory, "_load_installation", lambda _path: {"pid": 17112})
    monkeypatch.setattr(memory, "_configure_kernel", lambda: FakeKernel())
    monkeypatch.setattr(memory, "_capture_identity", fake_identity)
    monkeypatch.setattr(memory, "_file_code_guard", lambda _path, _profile=None: {"status": "observed", "checks": {}})
    monkeypatch.setattr(memory, "AddressBoundedRPM", lambda _kernel, _handle, _module_base: fake_reader)

    report = memory.capture(Path("fake-installation.json"))
    context = {"session_id": session_id, "game_sha256": memory.EXPECTED_EXE_SHA256, "game_date": 56559408}
    assert report["status"] == "observed", report["errors"]
    assert report["completed"] is True
    assert report["profile"] == {"path": str(memory.PROFILE_FILE), "sha256": memory.EXPECTED_PROFILE_SHA256, "profile_id": memory.EXPECTED_PROFILE_ID, "max_bytes": memory.PROFILE_MAX_BYTES}
    assert report["cleanup"]["handle_close"] == {"status": "closed", "success": True, "closed": True}
    assert memory.validate_capture(report, context, creation_filetime)

    stale = deepcopy(report)
    stale["values"]["diplomat_tasks"][0]["raw_2c"] += 1
    assert not memory.validate_capture(stale, context, creation_filetime)
    assert not memory.validate_capture(report, {**context, "game_date": 56559409}, creation_filetime)

