from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path

from bridge.information import directed_relation_memory as subject


BASE = 0x140000000
DATABASE = 0x500000
GAME = 0x600000
TABLE = 0x700000
COUNTRIES = {"FRA": 0x800000, "SAV": 0x810000, "ENG": 0x820000}
RELATION_TABLES = {"FRA": 0x900000, "SAV": 0x910000, "ENG": 0x920000}
OWNERS = {
    ("FRA", "SAV"): 0xA00000,
    ("SAV", "FRA"): 0xA10000,
    ("FRA", "ENG"): 0xA20000,
    ("ENG", "FRA"): 0xA30000,
    ("SAV", "ENG"): 0xA40000,
    ("ENG", "SAV"): 0xA50000,
}
VECTORS = {
    ("FRA", "SAV", "guarantee"): 0xB00000,
    ("SAV", "FRA", "guarantee"): 0xB10000,
    ("FRA", "ENG", "guarantee"): 0xB20000,
    ("ENG", "FRA", "guarantee"): 0xB30000,
    ("SAV", "ENG", "guarantee"): 0xB40000,
    ("ENG", "SAV", "guarantee"): 0xB50000,
    ("FRA", "SAV", "military_access"): 0xB60000,
    ("SAV", "FRA", "military_access"): 0xB70000,
    ("FRA", "ENG", "military_access"): 0xB80000,
    ("ENG", "FRA", "military_access"): 0xB90000,
    ("SAV", "ENG", "military_access"): 0xBA0000,
    ("ENG", "SAV", "military_access"): 0xBB0000,
}
RECORDS = {key: 0xC00000 + index * 0x1000 for index, key in enumerate(OWNERS)}
REAL_REPLAY = Path(__file__).resolve().parents[2] / "work" / "runtime" / "information-directed-relations-20261027-001" / "replay_directed_relation_witness.py"
_REAL_RECEIPT = None


def _fullref(tag: str, slot: int) -> int:
    return int.from_bytes(tag.encode("ascii") + b"\0" + slot.to_bytes(2, "little") + b"\0\0", "little")


FULLREFS = {tag: _fullref(tag, slot) for slot, tag in enumerate(COUNTRIES)}


class BoundedMemory:
    def __init__(self, segments: dict[int, bytes], *, failures: set[int] | None = None):
        self.segments = dict(segments)
        self.failures = set(failures or set())
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if any(start <= address and address + size <= start + len(raw) for start, raw in self.segments.items()):
            if address in self.failures or any(address <= bad < address + size for bad in self.failures):
                raise OSError(f"fixture_read_failed:{label}")
            for start, raw in self.segments.items():
                if start <= address and address + size <= start + len(raw):
                    offset = address - start
                    return raw[offset:offset + size]
        raise OSError(f"fixture_unmapped:{hex(address)}:{label}")


def _write(segments: dict[int, bytearray], address: int, raw: bytes) -> None:
    for start, segment in segments.items():
        if start <= address and address + len(raw) <= start + len(segment):
            segment[address - start:address - start + len(raw)] = raw
            return
    segments[address] = bytearray(raw)


def _qword(segments: dict[int, bytearray], address: int, value: int) -> None:
    _write(segments, address, int(value).to_bytes(8, "little", signed=False))


def _i32(segments: dict[int, bytearray], address: int, value: int) -> None:
    _write(segments, address, int(value).to_bytes(4, "little", signed=True))


def build_fixture(*, guarantee_reverse: bool = True, guarantee_record_null: bool = False) -> BoundedMemory:
    segments: dict[int, bytearray] = {}
    for item in subject._profile_code_guards(subject._load_profile()):
        _write(segments, BASE + item["rva"], item["expected"])
    _qword(segments, BASE + 0x233D8B0, DATABASE)
    _qword(segments, BASE + 0x233FE58, GAME)
    _i32(segments, GAME + 0x1DD0, 56557728)
    _qword(segments, DATABASE + 0x118, TABLE)
    _i32(segments, DATABASE + 0x124, len(COUNTRIES))
    segments.setdefault(TABLE, bytearray(len(COUNTRIES) * 8))
    for slot, (tag, pointer) in enumerate(COUNTRIES.items()):
        _qword(segments, TABLE + slot * 8, pointer)
        _qword(segments, pointer + 0x20, FULLREFS[tag])
        _qword(segments, pointer + 0x1510, RELATION_TABLES[tag])
    tags = list(COUNTRIES)
    for source in tags:
        for target in tags:
            row = RELATION_TABLES[source] + list(COUNTRIES).index(target) * 0x48
            owner = OWNERS.get((source, target))
            if owner is None:
                owner = 0xD00000 + (list(COUNTRIES).index(source) * 3 + list(COUNTRIES).index(target)) * 0x1000
            segments.setdefault(row, bytearray(0x20))
            _qword(segments, row + 0x0, owner)
            _qword(segments, row + 0x10, FULLREFS[target])
            for family in subject.FAMILIES:
                vector = VECTORS.get((source, target, family), owner + (0x200 if family == "guarantee" else 0x300))
                spec = subject._profile_layout(subject._load_profile())["families"][family]
                _qword(segments, owner + spec["vector_begin_offset"], vector)
                active = (source, target, family) == ("FRA", "SAV", "guarantee") or (source, target, family) == ("SAV", "FRA", "military_access") or (source, target, family) == ("SAV", "FRA", "guarantee") and guarantee_reverse
                _i32(segments, owner + spec["vector_count_offset"], 1)
                key = list(COUNTRIES).index(target) if active else 99
                record = RECORDS.get((source, target)) or (owner + 0x500)
                segments.setdefault(vector, bytearray(0x10))
                _write(segments, vector, int(key).to_bytes(4, "little") + b"\xaa\xbb\xcc\xdd")
                if family == "guarantee":
                    pointer = 0 if guarantee_record_null and active else record
                    _qword(segments, vector + 8, pointer)
                    if pointer:
                        _qword(segments, pointer + 0x18, FULLREFS[target])
    return BoundedMemory({start: bytes(raw) for start, raw in segments.items()})


def _make_report(reader: BoundedMemory, *, actor: str = "FRA", recipient: str | None = "SAV",
                 families: list[str] | None = None) -> dict:
    families = list(subject.FIELDS if families is None else families)
    network = recipient is None
    profile = subject._load_profile()
    budget = subject._rel._ReadBudget(subject.NETWORK_MAX_TOTAL_RPM if network else subject.MAX_TOTAL_RPM)
    first = subject._network_pass(reader, budget, BASE, actor, families, profile) if network else subject._pair_pass(reader, budget, BASE, actor, recipient, families, profile)
    second = subject._network_pass(reader, budget, BASE, actor, families, profile) if network else subject._pair_pass(reader, budget, BASE, actor, recipient, families, profile)
    report = subject._base_report(Path("fixture.json"), actor, recipient, families)
    report.update({
        "probe_script_sha256": subject._sha256_file(Path(subject.__file__).resolve()),
        "profile": {"path": str(subject.PROFILE_FILE), "profile_id": subject.EXPECTED_PROFILE_ID, "sha256": subject.EXPECTED_PROFILE_SHA256, "max_bytes": subject.PROFILE_MAX_BYTES},
        "target_build": {"version": subject.EXPECTED_VERSION, "expected_exe_sha256": subject.EXPECTED_EXE_SHA256, "image_base": "0x140000000"},
        "static_contract_guard": subject._static_contract_guard(profile),
        "file_code_guard": {"status": "observed", "path": "synthetic-current-pe"},
        "identity": {"binding_verified": True, "process_path_sha256_matches_expected": True, "process_creation_matches_installation": True, "process_creation_filetime": 123, "installation_session_id": "fixture-session", "installation_creation_filetime": 123},
        "module_base": {"va": hex(BASE)},
        "before": first,
        "after": second,
        "context_before": deepcopy(first.get("context")),
        "context_after": deepcopy(second.get("context")),
        "doublepass": {"performed": True, "consistent": not subject._diff_paths(subject._without_volatile(first), subject._without_volatile(second)), "mismatches": subject._diff_paths(subject._without_volatile(first), subject._without_volatile(second))},
        "fields": deepcopy(second.get("fields", {})),
        "relation_row": deepcopy(second.get("relation_row")),
        "owner_cache": deepcopy(second.get("owner_cache", {})),
        "targets": deepcopy(second.get("targets", [])),
        "network_stats": deepcopy(second.get("network_stats")),
        "status": "observed",
        "completed": True,
        "cleanup": {"handle_close": {"status": "closed", "success": True, "closed": True}},
    })
    report["runtime_code_guard"] = {"status": "observed", "passes": [first["runtime_code_guard"], second["runtime_code_guard"]]}
    report["access"]["rpm_bytes_requested"] = second["read_budget"]["bytes_reserved"]
    report["access"]["rpm_calls"] = second["read_budget"]["calls_reserved"]
    return report


def test_profile_source_and_guards_are_current():
    profile = subject._load_profile()
    assert subject._static_contract_guard(profile)["status"] == "observed"
    assert subject.EXPECTED_EXE_SHA256 == "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    assert set(subject._profile_layout(profile)["families"]) == set(subject.FIELDS)


def test_pair_replays_both_families_and_accepts_distinct_owner():
    reader = build_fixture()
    report = _make_report(reader, recipient="SAV")
    assert report["doublepass"]["consistent"] is True
    assert subject.validate_capture(report, actor="FRA", recipient="SAV")
    assert report["fields"]["guarantee"]["value"] is True
    assert report["fields"]["military_access"]["value"] is False
    assert report["relation_row"]["owner"]["va"] != report["context_after"]["actor"]["pointer"]["va"]


def test_network_preserves_forward_reverse_direction_and_empty_false_rows():
    reader = build_fixture()
    report = _make_report(reader, recipient=None)
    assert subject.validate_capture(report, actor="FRA", recipient=None)
    guarantee = report["fields"]["guarantee"]["value"]
    military = report["fields"]["military_access"]["value"]
    assert {row["operand_direction"] for row in guarantee} == {"forward", "reverse"}
    assert any(row["country"] == "SAV" and row["direction"] == "granted" and row["operand_direction"] == "forward" for row in guarantee)
    assert any(row["country"] == "SAV" and row["direction"] == "received" and row["operand_direction"] == "reverse" for row in guarantee)
    assert any(row["country"] == "SAV" and row["direction"] == "granted" and row["operand_direction"] == "reverse" for row in military)


def test_guarantee_null_record_is_known_false_not_unknown():
    reader = build_fixture(guarantee_record_null=True)
    report = _make_report(reader, recipient="SAV", families=["guarantee"])
    assert subject.validate_capture(report, actor="FRA", recipient="SAV")
    field = report["fields"]["guarantee"]
    assert field["status"] == "known" and field["value"] is False
    assert field["proof"]["record_status"] == "null"


def test_unreadable_guarantee_record_keeps_sibling_and_direction_unknown():
    reader = build_fixture()
    reader.failures.add(RECORDS[("FRA", "SAV")] + 0x18)
    report = _make_report(reader, recipient="SAV")
    assert subject.validate_capture(report, actor="FRA", recipient="SAV")
    assert report["fields"]["guarantee"]["status"] == "unknown"
    assert report["fields"]["military_access"]["status"] == "known"


def test_network_unknown_row_is_partial_and_does_not_erase_known_partner():
    reader = build_fixture()
    reader.failures.add(RECORDS[("FRA", "SAV")] + 0x18)
    report = _make_report(reader, recipient=None, families=["guarantee"])
    assert subject.validate_capture(report, actor="FRA", recipient=None)
    field = report["fields"]["guarantee"]
    assert field["status"] == "partial"
    assert any(item["country"] == "SAV" and item["operand_direction"] == "forward" for item in field["unknown_rows"])
    assert any(item["country"] == "ENG" and item["status"] == "known" for item in field["rows"])


def test_network_validates_shared_owner_elements_once_and_keeps_row_checks(monkeypatch):
    reader = build_fixture()
    segments = {start: bytearray(raw) for start, raw in reader.segments.items()}
    _qword(segments, RELATION_TABLES["FRA"] + 2 * 0x48, OWNERS[("FRA", "SAV")])
    report = _make_report(BoundedMemory({start: bytes(raw) for start, raw in segments.items()}), recipient=None)
    calls = []
    original = subject._validate_elements

    def counted(raw, owner, family, layout):
        calls.append((owner, family))
        return original(raw, owner, family, layout)

    monkeypatch.setattr(subject, "_validate_elements", counted)
    assert subject.validate_capture(report)
    assert len(calls) == len(set(calls)) == len(report["owner_cache"])
    tampered = deepcopy(report)
    for fields in (tampered["fields"], tampered["before"]["fields"], tampered["after"]["fields"]):
        fields["guarantee"]["rows"][2]["predicate"]["comparison_slot_signed_i16"] = -1
    assert not subject.validate_capture(tampered)


def test_network_index_keeps_all_duplicate_matches_and_guarantee_first_match():
    reader = build_fixture()
    segments = {start: bytearray(raw) for start, raw in reader.segments.items()}
    owner = OWNERS[("FRA", "SAV")]
    layout = subject._profile_layout(subject._load_profile())
    for family in subject.FAMILIES:
        first = (1).to_bytes(4, "little") + b"\0" * 12
        second = (1).to_bytes(4, "little") + b"\0" * 4 + RECORDS[("FRA", "SAV")].to_bytes(8, "little")
        _write(segments, VECTORS[("FRA", "SAV", family)], first + second)
        _i32(segments, owner + layout["families"][family]["vector_count_offset"], 2)
    report = _make_report(BoundedMemory({start: bytes(raw) for start, raw in segments.items()}), recipient=None)
    assert subject.validate_capture(report)
    guarantee = report["fields"]["guarantee"]["rows"][0]
    military = report["fields"]["military_access"]["rows"][0]
    assert guarantee["active"] is False
    assert guarantee["predicate"]["first_matching_element_index"] == 0
    assert guarantee["predicate"]["record_status"] == "null"
    assert military["active"] is True
    assert military["predicate"]["matching_element_indices"] == [0, 1]


def test_indexed_cache_still_rejects_corrupt_element_bytes():
    report = _make_report(build_fixture(), recipient=None)
    key = next(iter(report["owner_cache"]))
    for cache in (report["owner_cache"], report["before"]["owner_cache"], report["after"]["owner_cache"]):
        cache[key]["raw"]["elements"][0]["first_dword"] += 1
    assert not subject.validate_capture(report)


def test_json_evidence_copy_keeps_each_mutable_child_independent():
    original = {"rows": [{"proof": {"active": False, "amount": 1}}], "empty": [], "missing": None}
    copied = subject._copy_evidence(original)
    assert copied == deepcopy(original)
    copied["rows"][0]["proof"]["active"] = True
    copied["empty"].append(2)
    assert original == {"rows": [{"proof": {"active": False, "amount": 1}}], "empty": [], "missing": None}


def test_tamper_context_guard_and_retract_are_rejected():
    report = _make_report(build_fixture(), recipient="SAV")
    assert subject.validate_capture(report)
    tampered = deepcopy(report)
    tampered["context_after"]["game_date"]["value"] += 1
    assert not subject.validate_capture(tampered)
    withdrawn = subject.retract_record(report, "session_changed")
    assert withdrawn["status"] == "unknown" and withdrawn["completed"] is False
    assert withdrawn["fields"]["guarantee"]["value"] is None


def test_strict_request_and_budget_precharge():
    bad = subject.capture(Path("missing.json"), "FRA", None, ["alliance"])
    assert bad["status"] == "invalid_request" and bad["completed"] is True
    class Failing:
        def read(self, address, size, label):
            raise OSError("failed")
    budget = subject._rel._ReadBudget(8)
    try:
        budget.read(Failing(), 0x10000, 8, "failed")
    except OSError:
        pass
    assert budget.reserved == 8
    try:
        budget.read(Failing(), 0x10008, 1, "second")
    except subject.ProbeError as exc:
        assert "RPM_TOTAL_BUDGET_EXCEEDED" in str(exc)
    else:
        raise AssertionError("failed read reservation was not retained")


def _real_replay_receipt():
    global _REAL_RECEIPT
    if _REAL_RECEIPT is None:
        spec = importlib.util.spec_from_file_location("directed_relation_real_replay", REAL_REPLAY)
        helper = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(helper)
        _REAL_RECEIPT = helper.replay_fixture()
    return _REAL_RECEIPT


def test_real_network_fixture_validates_and_matches_compact_empty_projection():
    receipt = _real_replay_receipt()
    assert receipt["status"] == "passed"
    checks = receipt["checks"]
    assert checks["network_validate_capture"] is True
    assert checks["network_expected_compact_empty"] is True
    assert receipt["observed"]["network"]["guarantee_rows"] == 2756
    assert receipt["observed"]["network"]["military_access_rows"] == 2756


def test_real_pair_witnesses_validate_and_preserve_operand_direction():
    receipt = _real_replay_receipt()
    checks = receipt["checks"]
    assert checks["guarantee_forward_validate_capture"] is True
    assert checks["guarantee_reverse_validate_capture"] is True
    assert checks["guarantee_forward_false"] is True
    assert checks["guarantee_reverse_true"] is True
    assert checks["guarantee_expected_reverse_row"] is True
    assert checks["military_forward_validate_capture"] is True
    assert checks["military_reverse_validate_capture"] is True
    assert checks["military_both_true"] is True
    assert checks["military_expected_both_directions"] is True

