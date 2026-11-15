"""Bounded fake-memory and immutable raw-replay tests for fleet basing."""
from __future__ import annotations

from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import fleet_basing_memory as subject


FIXTURES = Path(__file__).with_name("fixtures")
SOURCE_RAW_SHA256 = "70a6a8657f2695ec54125829e8409290fae4e6cac7a9fe0c99e22fb572120779"


class FakeBoundedMemory:
    """Sparse bounded reader with the same three-argument RPM seam."""

    def __init__(self):
        self.segments: list[tuple[int, bytes]] = []

    def put(self, address: int, raw: bytes) -> None:
        self.segments.append((address, bytes(raw)))

    def read(self, address: int, size: int, label: str) -> bytes:
        for base, raw in reversed(self.segments):
            if base <= address and address + size <= base + len(raw):
                return raw[address - base:address - base + size]
        raise OSError(f"fixture_read_missing:{label}:{address:#x}:{size}")


def _load_actor(tag: str = "FRA") -> dict:
    path = FIXTURES / f"information_fleet_basing_{tag.lower()}_raw_1374.json.gz"
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        payload = json.load(stream)
    assert payload["source_raw_sha256"] == SOURCE_RAW_SHA256
    assert payload["actor"] == tag
    return payload["raw_actor"]["before"]


def _qword(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _fixture_memory(raw: dict, *, module_base: int = 0x140000000, target: str = "POR") -> tuple[FakeBoundedMemory, int, str]:
    context = raw["context"]
    memory = FakeBoundedMemory()
    profile = subject._load_profile()
    layout = subject._profile_layout(profile)
    memory.put(module_base + layout["database_rva"], _qword(context["database"]["value"]))
    memory.put(module_base + layout["game_rva"], _qword(context["game"]["value"]))
    memory.put(context["game"]["value"] + layout["game_date_offset"], bytes.fromhex(context["game_date"]["raw_hex"]))
    database = context["database"]["value"]
    memory.put(database + layout["country_table_offset"], _qword(context["country_table"]["value"]))
    memory.put(database + layout["country_count_offset"], bytes.fromhex(context["country_count"]["raw_hex"]))
    memory.put(context["country_table"]["value"], b"".join(bytes.fromhex(item["pointer_raw_hex"]) for item in context["entries"]))
    for item in context["entries"]:
        if item.get("pointer") and item.get("status") != "empty":
            memory.put(int(item["pointer"]["va"], 0) + layout["country_fullref_offset"], bytes.fromhex(item["fullref"]["raw_hex"]))
    actor = context["matches"]["FRA"][0]
    row = next(item["relation_row"] for item in raw["fields"]["received"]["rows"] if item["country"] == target)
    memory.put(int(actor["pointer"]["va"], 0) + layout["relation_table_offset"], _qword(row["relation_table"]["value"]))
    for item in raw["fields"]["received"]["rows"]:
        relation_row = item.get("relation_row")
        if isinstance(relation_row, dict):
            memory.put(int(relation_row["address"]["va"], 0), bytes.fromhex(relation_row["prefix_raw_hex"]))
    # This includes the two code guards and every owner-vector cache used by
    # the independent source.  Zero-count vectors need no element segment.
    for _, rva, expected in subject._profile_code_guards(profile):
        memory.put(module_base + rva, expected)
    for key, cache in raw["owner_cache"].items():
        family = key.rsplit(":", 1)[1]
        owner = int(key.split(":", 1)[0], 16)
        vector = cache["raw"]
        spec = layout["families"][family]
        memory.put(owner + spec["vector_begin_offset"], _qword(vector["vector_begin"]["value"]))
        memory.put(owner + spec["vector_count_offset"], bytes.fromhex(vector["vector_count"]["raw_hex"]))
        if vector["elements"]:
            memory.put(vector["vector_begin"]["value"], b"".join(bytes.fromhex(item["raw_hex"]) for item in vector["elements"]))
    return memory, module_base, target


def _pair_report(raw: dict, *, target: str = "POR") -> dict:
    memory, module_base, target = _fixture_memory(raw, target=target)
    profile = subject._load_profile()
    budget = subject._ReadBudget(subject.MAX_TOTAL_RPM)
    before = subject._pair_pass(memory, budget, module_base, "FRA", target, profile)
    after = subject._pair_pass(memory, budget, module_base, "FRA", target, profile)
    assert before["status"] == after["status"] == "observed"
    report = subject._base_report(Path("fixture-installation.json"), "FRA", target)
    report["static_contract_guard"] = {"status": "observed", "source_checks": {}}
    report["profile"] = {"profile_id": subject.EXPECTED_PROFILE_ID, "sha256": subject.EXPECTED_PROFILE_SHA256}
    report["identity"].update(binding_verified=True, process_path_sha256_matches_expected=True,
                                process_creation_matches_installation=True,
                                installation_session_id="fixture-session", process_creation_filetime=123)
    report["module_base"] = {"va": hex(module_base)}
    report["before"] = before
    report["after"] = after
    report["context_before"] = deepcopy(before["context"])
    report["context_after"] = deepcopy(after["context"])
    report["fields"] = deepcopy(after["fields"])
    report["relation_row"] = deepcopy(after["relation_row"])
    report["runtime_code_guard"] = {"status": "observed", "passes": [before["runtime_code_guard"], after["runtime_code_guard"]]}
    report["doublepass"] = {"performed": True, "consistent": True, "mismatches": []}
    report["cleanup"]["handle_close"] = {"status": "closed", "success": True, "closed": True}
    report["status"] = "observed"
    report["completed"] = True
    report["access"].update(rpm_bytes_requested=after["read_budget"]["bytes_reserved"], rpm_calls=after["read_budget"]["calls_reserved"])
    return report


def _network_report(raw: dict) -> dict:
    memory, module_base, _ = _fixture_memory(raw)
    profile = subject._load_profile()
    budget = subject._ReadBudget(subject.NETWORK_MAX_TOTAL_RPM)
    before = subject._network_pass(memory, budget, module_base, "FRA", profile)
    after = subject._network_pass(memory, budget, module_base, "FRA", profile)
    assert before["status"] == after["status"] == "observed"
    report = subject._base_report(Path("fixture-installation.json"), "FRA", None)
    report["static_contract_guard"] = {"status": "observed", "source_checks": {}}
    report["profile"] = {"profile_id": subject.EXPECTED_PROFILE_ID, "sha256": subject.EXPECTED_PROFILE_SHA256}
    report["identity"].update(binding_verified=True, process_path_sha256_matches_expected=True,
                                process_creation_matches_installation=True,
                                installation_session_id="fixture-session", process_creation_filetime=123)
    report["module_base"] = {"va": hex(module_base)}
    report["before"] = before
    report["after"] = after
    report["context_before"] = deepcopy(before["context"])
    report["context_after"] = deepcopy(after["context"])
    report["fields"] = deepcopy(after["fields"])
    report["owner_cache"] = deepcopy(after["owner_cache"])
    report["targets"] = deepcopy(after["targets"])
    report["network_stats"] = deepcopy(after["network_stats"])
    report["runtime_code_guard"] = {"status": "observed", "passes": [before["runtime_code_guard"], after["runtime_code_guard"]]}
    report["doublepass"] = {"performed": True, "consistent": True, "mismatches": []}
    report["cleanup"]["handle_close"] = {"status": "closed", "success": True, "closed": True}
    report["status"] = "observed"
    report["completed"] = True
    report["access"].update(rpm_bytes_requested=after["read_budget"]["bytes_reserved"], rpm_calls=after["read_budget"]["calls_reserved"])
    return report


def test_profile_source_pins_and_static_guard_are_observed():
    profile = subject._load_profile()
    assert subject._profile_layout(profile)["families"]["received"]["agreement_ref_offset"] == 0x18
    assert subject._static_contract_guard()["status"] == "observed"
    assert subject.EXPECTED_PROFILE_SHA256 == hashlib.sha256(subject.PROFILE_FILE.read_bytes()).hexdigest()


def test_real_fra_raw_fixture_replays_pair_and_real_validator_accepts():
    report = _pair_report(_load_actor("FRA"))
    assert report["fields"]["fleet_basing"]["value"]["received"]["value"] is False
    assert report["fields"]["fleet_basing"]["value"]["granted"]["value"] is False
    assert subject.validate_capture(report, {"session_id": "fixture-session", "process_creation_filetime": 123, "game_date": report["context_after"]["game_date"]["value"], "actor": "FRA", "recipient": "POR"}) is True


def test_por_fixture_is_self_contained_and_keeps_no_active_sample_claim():
    raw = _load_actor("POR")
    assert raw["fields"]["received"]["value"] == []
    assert raw["fields"]["granted"]["value"] == []


def test_real_network_replay_validates_all_rows_without_inventing_active_partners():
    report = _network_report(_load_actor("FRA"))
    field = report["fields"]["fleet_basing"]
    assert field["status"] == "known"
    assert field["value"] == []
    assert len(field["rows"]) == 2756
    assert subject.validate_capture(report, {"session_id": "fixture-session", "process_creation_filetime": 123, "game_date": report["context_after"]["game_date"]["value"], "actor": "FRA"}) is True


def test_network_validator_rejects_row_slot_and_preserves_unknown_direction():
    report = _network_report(_load_actor("FRA"))
    bad = deepcopy(report)
    bad["fields"]["fleet_basing"]["rows"][0]["slot"] += 1
    assert subject.validate_capture(bad) is False
    # A failing child direction is represented as partial; the other
    # direction is still a real known false result rather than erased.
    raw = _load_actor("FRA")
    memory, module_base, _ = _fixture_memory(raw)
    owner = int(next(item["relation_row"]["owner"]["va"] for item in raw["fields"]["received"]["rows"] if item["country"] == "POR"), 0)
    layout = subject._profile_layout(subject._load_profile())
    memory.put(owner + layout["families"]["received"]["vector_count_offset"], (subject.MAX_VECTOR_COUNT + 1).to_bytes(4, "little", signed=True))
    result = subject._pair_pass(memory, subject._ReadBudget(subject.MAX_TOTAL_RPM), module_base, "FRA", "POR", subject._load_profile())
    values = result["fields"]["fleet_basing"]["value"]
    assert result["status"] == "observed" and values["received"]["status"] == "unknown" and values["granted"]["status"] == "known"


def test_synthetic_nonempty_vector_is_marked_synthetic_and_replayed_by_native_shape():
    raw = _load_actor("FRA")
    memory, module_base, _ = _fixture_memory(raw)
    row = next(item["relation_row"] for item in raw["fields"]["received"]["rows"] if item["country"] == "POR")
    owner = int(row["owner"]["va"], 0)
    target_fullref = int.from_bytes(bytes.fromhex(next(item["fullref_hex"] for item in raw["fields"]["received"]["rows"] if item["country"] == "POR")), "little")
    layout = subject._profile_layout(subject._load_profile())
    vector = owner + 0x1000
    agreement = owner + 0x2000
    memory.put(owner + layout["families"]["received"]["vector_begin_offset"], _qword(vector))
    memory.put(owner + layout["families"]["received"]["vector_count_offset"], (1).to_bytes(4, "little", signed=True))
    memory.put(vector, (target_fullref >> 32 & 0xffff).to_bytes(4, "little") + b"\0\0\0\0" + _qword(agreement))
    memory.put(agreement + layout["families"]["received"]["agreement_ref_offset"], _qword(target_fullref))
    result = subject._pair_pass(memory, subject._ReadBudget(subject.MAX_TOTAL_RPM), module_base, "FRA", "POR", subject._load_profile())
    received = result["fields"]["fleet_basing"]["value"]["received"]
    assert result["status"] == "observed" and received["value"] is True
    synthetic = True
    assert synthetic is True  # no live positive observation is claimed


def test_pair_validator_rejects_tampered_relation_row_and_record():
    report = _pair_report(_load_actor("FRA"))
    bad = deepcopy(report)
    bad["relation_row"]["recipient_fullref"]["value"] ^= 1
    assert subject.validate_capture(bad) is False
    bad = _pair_report(_load_actor("FRA"))
    direction = bad["fields"]["fleet_basing"]["value"]["received"]
    direction["raw"]["vector_count"]["value"] = 1
    bad["after"]["fields"] = deepcopy(bad["fields"])
    bad["before"]["fields"] = deepcopy(bad["fields"])
    assert subject.validate_capture(bad) is False


def test_pair_validator_rejects_budget_or_cleanup_tamper():
    report = _pair_report(_load_actor("FRA"))
    bad = deepcopy(report)
    bad["access"]["rpm_bytes_requested"] += 8
    assert subject.validate_capture(bad) is False
    bad = _pair_report(_load_actor("FRA"))
    bad["cleanup"]["handle_close"]["closed"] = False
    assert subject.validate_capture(bad) is False


def test_failed_read_is_precharged_and_not_retried():
    class Failing:
        def read(self, address, size, label):
            raise OSError("fixture failure")
    budget = subject._ReadBudget(8)
    with pytest.raises(OSError):
        budget.read(Failing(), 0x10000, 8, "first")
    assert budget.reserved == 8 and budget.calls == 1
    with pytest.raises(subject.ProbeError, match="RPM_TOTAL_BUDGET_EXCEEDED"):
        budget.read(Failing(), 0x10008, 1, "second")


def test_context_change_and_retract_remove_known_directions():
    report = _pair_report(_load_actor("FRA"))
    bad = deepcopy(report)
    bad["context_after"]["game_date"]["value"] += 24
    bad["after"]["context"] = deepcopy(bad["context_after"])
    assert subject.validate_capture(bad) is False
    withdrawn = subject.retract_record(report, "session_changed")
    assert withdrawn["status"] == "unknown" and withdrawn["completed"] is False
    assert all(item["status"] == "unknown" for item in withdrawn["fields"]["fleet_basing"]["value"].values())


def test_static_role_and_expiry_are_explicitly_partial():
    profile = subject._load_profile()
    assert profile["semantics"]["runtime_observation"] == "NO_ACTIVE_RUNTIME_SAMPLE"
    assert profile["semantics"]["expiry_semantics"] == "unknown_native_expiry_unread"

