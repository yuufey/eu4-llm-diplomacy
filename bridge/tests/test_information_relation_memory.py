from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import MappingProxyType

import pytest

from bridge.information import relation_memory as subject
from bridge.information.observation_time import sampled_read


@pytest.mark.parametrize('sampling', [False, True])
def test_comparison_projection_preserves_diagnostics_clock_and_tuple_semantics(sampling):
    tuple_value = ({'read_budget': 8, 'game_date': 10, 'active': True},)
    source = {'read_log': ['private'], 'game_date': 10,
              'rows': [{'label': 'game.raw_date', 'value': 10},
                       MappingProxyType({'label': 'game.raw_date', 'value': 10}),
                       {'active': True, 'count': 1, 'read_budget': 4, 'game_day': 20}],
              'mapping': MappingProxyType({'game_date': 10, 'read_budget': 5, 'amount': 2.5}),
              'tuple': tuple_value}
    with sampled_read({'topic': 'R01'}, {'mode': 'live', 'game_date': 10}, enabled=sampling):
        result = subject._without_volatile(source)
    expected_rows = [{'active': True, 'count': 1}]
    if not sampling:
        expected_rows = [{'label': 'game.raw_date', 'value': 10},
                         {'label': 'game.raw_date', 'value': 10},
                         {'active': True, 'count': 1, 'game_day': 20}]
    assert result['rows'] == expected_rows
    assert result['mapping'] == ({'amount': 2.5} if sampling else {'game_date': 10, 'amount': 2.5})
    assert result['tuple'] == (({'read_budget': 8, 'active': True},) if sampling else tuple_value)
    assert ('game_date' in result) is not sampling
    assert 'read_log' not in result and source['read_log'] == ['private']
    assert type(result['rows'][-1]['active']) is bool
    assert type(result['rows'][-1]['count']) is int


def test_fast_comparison_keeps_strict_leaf_types_and_exact_mismatch_paths():
    first = {'same': 'text', 'rows': [True, 2, {'value': 3.0}], 'nan': float('nan')}
    second = {'same': 'text', 'rows': [1, 2, {'value': 3}], 'nan': first['nan']}
    assert subject._diff_paths(first, second) == ['$.nan', '$.rows[0]', '$.rows[2].value']
    assert subject._diff_paths({'rows': [1]}, {'rows': [1, 2]}) == ['$.rows[1]']
    assert subject._diff_paths({'value': 1}, {}) == ['$.value']


def _field(family: str, owner: int, row_address: int, recipient_fullref: int, begin: int, slot: int, *, present: bool = True) -> dict:
    chunks = []
    if present:
        chunks.append((slot & 0xFFFFFFFF).to_bytes(4, "little") + bytes.fromhex("aabbccddeeff001122334455"))
    else:
        chunks.append((0x12345678).to_bytes(4, "little") + bytes.fromhex("aabbccddeeff001122334455"))
    elements = []
    for index, chunk in enumerate(chunks):
        elements.append({"index": index, "address": {"va": hex(begin + index * 16)}, "raw_hex": chunk.hex(), "first_dword_raw_hex": chunk[:4].hex(), "first_dword": int.from_bytes(chunk[:4], "little"), "unread_tail_raw_hex": chunk[4:].hex(), "unread_tail_semantics": "+0x4..+0xf_unread_by_direct_leaf"})
    spec = subject._profile_layout(subject._load_profile())["families"][family]
    return {
        "status": "known", "family": family, "value": present, "unit": "relation_state", "scale": 1, "period": "current", "partial": True, "complete": False,
        "basis": "native_current_selected_pair_relation_predicate", "value_origin": "derived_from_copied_relation_row_and_owner_vector",
        "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
        "raw": {
            "owner_pointer": {"va": hex(owner)}, "owner_pointer_raw_hex": owner.to_bytes(8, "little").hex(),
            "recipient_fullref": {"address": {"va": hex(row_address + 0x10)}, "raw_hex": recipient_fullref.to_bytes(8, "little").hex(), "value": recipient_fullref},
            "recipient_slot_signed_i16": slot,
            "vector_begin": {"address": {"va": hex(owner + spec["begin_offset"])}, "raw_hex": begin.to_bytes(8, "little").hex(), "value": begin},
            "vector_count": {"address": {"va": hex(owner + spec["count_offset"])}, "raw_hex": (1).to_bytes(4, "little", signed=True).hex(), "value": 1},
            "element_stride": 16, "elements": elements,
        },
        "proof": {"selector": hex(spec["selector"]), "selector_case_rva": hex(spec["selector_case_rva"]), "call_rva": hex(spec["call_rva"]), "leaf_rva": hex(spec["leaf_rva"]), "leaf_va": hex(0x140000000 + spec["leaf_rva"]), "offer": False, "matching_element_indices": [0] if present else [], "unread_element_bytes": "+0x4..+0xf"},
    }


def _valid_report(*, marriage_unknown: bool = False) -> dict:
    actor_pointer = 0x100000
    recipient_pointer = 0x100100
    relation_table = 0x180000
    owner = 0x200000
    row_address = relation_table + 7 * 0x48
    actor_handle = (5 << 32) | int.from_bytes(b"FRA", "little")
    recipient_handle = (7 << 32) | int.from_bytes(b"SAV", "little")
    actor = {"index": 5, "pointer": {"va": hex(actor_pointer)}, "fullref": {"value": actor_handle, "raw_hex": actor_handle.to_bytes(8, "little").hex()}, "tag": "FRA", "slot": 5}
    recipient = {"index": 7, "pointer": {"va": hex(recipient_pointer)}, "fullref": {"value": recipient_handle, "raw_hex": recipient_handle.to_bytes(8, "little").hex()}, "tag": "SAV", "slot": 7}
    context = {"status": "observed", "database": {"value": 0x500000, "raw_hex": "0000500000000000", "address": {"va": "0x140233d8b0"}}, "game": {"value": 0x600000, "raw_hex": "0000600000000000", "address": {"va": "0x140233fe58"}}, "game_date": {"value": 56557728, "raw_hex": "a0f4?".replace("?", ""), "address": {"va": "0x600000"}}, "country_scan": {"status": "observed", "matches": {"FRA": actor, "SAV": recipient}}, "actor": actor, "recipient": recipient, "unknown_conditions": []}
    # The validator compares date values and relation bindings, not a date
    # encoding guessed by the test; use a valid four-byte raw representation.
    context["game_date"]["raw_hex"] = (56557728).to_bytes(4, "little", signed=True).hex()
    relation_row = {"address": {"va": hex(row_address)}, "relation_table": {"address": {"va": hex(actor_pointer + 0x1510)}, "raw_hex": relation_table.to_bytes(8, "little").hex(), "value": relation_table}, "prefix_raw_hex": owner.to_bytes(8, "little").hex() + bytes(8).hex() + recipient_handle.to_bytes(8, "little").hex() + bytes(8).hex(), "owner": {"va": hex(owner)}, "owner_raw_hex": owner.to_bytes(8, "little").hex(), "recipient_fullref": {"address": {"va": hex(row_address + 0x10)}, "raw_hex": recipient_handle.to_bytes(8, "little").hex(), "value": recipient_handle}, "recipient_slot": 7, "row_stride": 0x48}
    alliance = _field("alliance", owner, row_address, recipient_handle, 0x300000, 7, present=True)
    marriage = _field("royal_marriage", owner, row_address, recipient_handle, 0x400000, 7, present=False)
    if marriage_unknown:
        marriage = {"status": "unknown", "family": "royal_marriage", "value": None, "reason": "bounded_read_failed", "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}
    fields = {"alliance": alliance, "royal_marriage": marriage}
    before = {"status": "observed", "runtime_code_guard": {"status": "observed", "checks": {}}, "context": deepcopy(context), "relation_row": deepcopy(relation_row), "fields": deepcopy(fields), "complete": not marriage_unknown}
    after = deepcopy(before)
    identity = {"binding_verified": True, "process_path_sha256_matches_expected": True, "process_creation_matches_installation": True, "process_creation_filetime": 123, "installation_session_id": "session-1"}
    return {"schema": "information_relation_current_runtime.v1", "status": "observed", "completed": True, "profile": {"profile_id": subject.EXPECTED_PROFILE_ID, "sha256": subject.EXPECTED_PROFILE_SHA256}, "target_build": {"expected_exe_sha256": subject.EXPECTED_EXE_SHA256}, "request": {"installation": "fixture", "actor": "FRA", "recipient": "SAV", "families": ["alliance", "royal_marriage"]}, "identity": identity, "static_contract_guard": {"status": "observed"}, "runtime_code_guard": {"status": "observed"}, "context_before": deepcopy(context), "context_after": deepcopy(context), "before": before, "after": after, "fields": fields, "relation_row": relation_row, "doublepass": {"performed": True, "consistent": True, "mismatches": []}, "access": {"native_game_calls": False, "target_memory_writes": False}, "cleanup": {"handle_close": {"status": "closed", "success": True, "closed": True}}}


def test_profile_and_static_source_pins_are_observed():
    profile = subject._load_profile()
    assert set(subject._profile_layout(profile)["families"]) == {"alliance", "royal_marriage"}
    guard = subject._static_contract_guard()
    assert guard["status"] == "observed", guard


@pytest.mark.parametrize('archive', [False, True])
def test_frozen_execution_evidence_still_rejects_tampered_bytes(tmp_path, monkeypatch, archive):
    profile = subject._load_legacy_archive_profile() if archive else subject._load_profile()
    tampered = tmp_path / 'tampered-execution.inc'
    tampered.write_bytes(b'changed frozen source evidence')
    resolve = subject._workspace_path

    def resolve_evidence(path):
        if path == subject.RELATION_EVIDENCE_EXECUTION_SOURCE.as_posix():
            return tampered
        return resolve(path)

    monkeypatch.setattr(subject, '_workspace_path', resolve_evidence)
    ok, checks, reasons = subject._dependency_checks(profile, offline_legacy_archive=archive)
    assert not ok and checks['work/native/alliance-execution.inc'] is False
    assert 'source_evidence_sha_mismatch:work/native/alliance-execution.inc' in reasons


def test_validate_real_shape_with_row_owner_distinct_from_country():
    report = _valid_report()
    assert subject.validate_capture(report)


def test_unknown_sibling_does_not_invalidate_identity_bound_capture():
    report = _valid_report(marriage_unknown=True)
    assert subject.validate_capture(report)


def test_tampered_row_recipient_and_context_are_rejected():
    report = _valid_report()
    report["relation_row"]["recipient_fullref"]["value"] ^= 1
    assert not subject.validate_capture(report)
    report = _valid_report()
    report["relation_row"]["relation_table"]["value"] ^= 0x48
    assert not subject.validate_capture(report)
    report = _valid_report()
    report["context_after"]["game_date"]["value"] += 1
    report["after"]["context"]["game_date"]["value"] += 1
    assert not subject.validate_capture(report)


def test_retract_withdraws_both_current_values():
    report = _valid_report()
    withdrawn = subject.retract_record(report, "session_changed")
    assert withdrawn["status"] == "unknown"
    assert withdrawn["completed"] is False
    assert all(item["status"] == "unknown" and item["value"] is None for item in withdrawn["fields"].values())


def test_invalid_actor_is_rejected_before_installation_open():
    report = subject.capture(Path("does-not-exist.json"), "ORL", "SAV", ["alliance"])
    assert report["status"] == "unsupported_request"
    assert report["completed"] is True
    assert report["cleanup"]["handle_close"]["status"] == "not_opened"


def test_network_invalid_actor_is_rejected_before_installation_open():
    report = subject.capture_network(Path("does-not-exist.json"), "ORL", ["alliance", "royal_marriage"])
    assert report["status"] == "unsupported_request"
    assert report["completed"] is True
    assert report["cleanup"]["handle_close"]["status"] == "not_opened"


def test_read_budget_precharges_a_failed_request():
    class FailingReader:
        def read(self, address, size, label):
            raise OSError("fixture_failure")

    budget = subject._ReadBudget(8)
    try:
        budget.read(FailingReader(), 0x10000, 8, "failed")
    except OSError:
        pass
    assert budget.reserved == 8
    try:
        budget.read(FailingReader(), 0x10008, 1, "second")
    except subject.ProbeError as exc:
        assert "RPM_TOTAL_BUDGET_EXCEEDED" in str(exc)
    else:
        raise AssertionError("failed precharge was not retained")
