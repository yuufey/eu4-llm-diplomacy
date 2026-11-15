from copy import deepcopy
from collections import Counter

import pytest

from bridge.information import mission_trigger_provinces as adapter
from bridge.information import province_state_memory


MODULE_BASE = 0x140000000
PROVINCE_ID = 31
RECORD = 0x61000000
OBSERVER_POINTER = 0x62000000
OBSERVER_SLOT = 17
COUNTRY_TABLE = 0x64000000


def _fullref(tag: str, slot: int) -> int:
    return ((0x1200 << 48) | (slot << 32)
            | int.from_bytes(tag.encode("ascii") + b"\0", "little"))


def _observer_binding() -> dict:
    reference = _fullref("FRA", OBSERVER_SLOT)
    return {
        "tag": "FRA",
        "slot": OBSERVER_SLOT,
        "country_pointer": hex(OBSERVER_POINTER),
        "fullref": hex(reference),
        "fullref_raw_hex": reference.to_bytes(8, "little").hex(),
    }


def _province_binding(province_id=PROVINCE_ID) -> dict:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(RECORD + province_id * 0x1000),
        "id_raw_hex": province_id.to_bytes(4, "little", signed=True).hex(),
    }


def _known_field(tag: str, slot: int) -> dict:
    reference = _fullref(tag, slot)
    raw = reference.to_bytes(8, "little").hex()
    country_pointer = 0x63000000 + slot * 0x100
    return {
        "status": "known",
        "value": tag,
        "raw_inputs": {
            "tag": tag,
            "fullref": hex(reference),
            "canonical_fullref": hex(reference),
            "slot": slot,
            "table": hex(COUNTRY_TABLE),
            "table_entry_address": hex(COUNTRY_TABLE + slot * 8),
            "table_entry_raw_hex": country_pointer.to_bytes(8, "little").hex(),
            "country_pointer": hex(country_pointer),
            "canonical_fullref_address": hex(
                country_pointer + province_state_memory.COUNTRY_FULLREF_OFFSET),
            "reference_raw_hex": raw,
            "fullref_raw_hex": raw,
            "canonical_fullref_raw_hex": raw,
        },
    }


def _report(province_id=PROVINCE_ID) -> dict:
    observer = _observer_binding()
    province = _province_binding(province_id)
    gate = {
        "status": "known",
        "admitted": True,
        "observer_nonplayer_role": {"verified": True},
    }
    discovery = {"status": "known", "value": True}
    observer_passes = {"pass1": observer, "pass2": deepcopy(observer)}
    target_bindings = {
        phase: {"observer": deepcopy(observer), "province": deepcopy(province)}
        for phase in ("pass1", "pass2")
    }
    return {
        "schema": province_state_memory.SCHEMA,
        "status": "observed",
        "observer": {"tag": "FRA", "bindings_by_pass": observer_passes},
        "pass_evidence": {
            "pass1": {"status": "observed"},
            "pass2": {"status": "observed"},
        },
        "consistency": {"status": "stable", "shared_mismatch_paths": []},
        "targets": [{
            "province_id": province_id,
            "bindings_by_pass": target_bindings,
            "admission_by_pass": {"pass1": deepcopy(gate), "pass2": deepcopy(gate)},
            "discovery_by_pass": {
                "pass1": deepcopy(discovery), "pass2": deepcopy(discovery),
            },
            "fields": {
                "G02.owner": _known_field("FRA", OBSERVER_SLOT),
                "G02.controller": _known_field("ENG", 23),
            },
            "field_consistency": {
                "G02.owner": {"status": "stable"},
                "G02.controller": {"status": "stable"},
            },
        }],
        "errors": [],
    }


def _install_report(monkeypatch, report=None, *, exception=None):
    calls = []

    def fake_read_two_pass(read, module_base, province_id, *, observer, fields):
        calls.append((read, module_base, province_id, observer, fields))
        if exception is not None:
            raise exception
        return deepcopy(_report() if report is None else report)

    monkeypatch.setattr(province_state_memory, "read_two_pass", fake_read_two_pass)
    return calls


def test_projects_only_stable_discovered_bindings_and_canonical_references(monkeypatch):
    calls = _install_report(monkeypatch)
    tracked_read = lambda *_args: b""

    result = adapter.read_province_state(tracked_read, MODULE_BASE, PROVINCE_ID)

    assert result == {
        "status": "known",
        "province_id": PROVINCE_ID,
        "owner": {"status": "known", "tag": "FRA", "reference": _fullref("FRA", OBSERVER_SLOT),
                  "country_pointer": 0x63000000 + OBSERVER_SLOT * 0x100},
        "controller": {"status": "known", "tag": "ENG", "reference": _fullref("ENG", 23),
                       "country_pointer": 0x63000000 + 23 * 0x100},
        "source": adapter.SOURCE,
        "observer_pointer": OBSERVER_POINTER,
        "observer_reference": _fullref("FRA", OBSERVER_SLOT),
    }
    assert calls == [(tracked_read, MODULE_BASE, PROVINCE_ID, "FRA", adapter.FIELDS)]


@pytest.mark.parametrize("field,output_key", [
    ("G02.owner", "owner"),
    ("G02.controller", "controller"),
])
def test_unknown_owner_or_controller_remains_local(monkeypatch, field, output_key):
    report = _report()
    report["targets"][0]["fields"][field] = {
        "status": "unknown", "reason": "COUNTRY_FULLREF_ECHO_MISMATCH",
    }
    calls = _install_report(monkeypatch, report)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)

    assert result["status"] == "known"
    assert result[output_key] == {
        "status": "unknown", "reason": "COUNTRY_FULLREF_ECHO_MISMATCH",
    }
    other = "controller" if output_key == "owner" else "owner"
    assert result[other]["status"] == "known"
    assert calls


def test_undiscovered_province_is_overall_unknown(monkeypatch):
    report = _report()
    report["targets"][0]["discovery_by_pass"] = {
        "pass1": {"status": "known", "value": False},
        "pass2": {"status": "known", "value": False},
    }
    _install_report(monkeypatch, report)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)

    assert result["status"] == "unknown"
    assert result["reason"] == "province_discovery_not_established"


def test_inconsistent_two_pass_result_is_overall_unknown(monkeypatch):
    report = _report()
    report["consistency"] = {
        "status": "changed", "shared_mismatch_paths": ["province_scan"],
    }
    _install_report(monkeypatch, report)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)

    assert result["status"] == "unknown"
    assert result["reason"] == "province_state_two_pass_unstable"


@pytest.mark.parametrize("mutate,reason", [
    (lambda report: report["targets"][0].update(province_id=PROVINCE_ID + 1),
     "province_state_target_id_mismatch"),
    (lambda report: report["targets"][0]["bindings_by_pass"]["pass2"]["province"].update(
        record_id=PROVINCE_ID + 1), "province_state_target_binding_unverified"),
    (lambda report: report["targets"][0]["admission_by_pass"]["pass2"].update(
        admitted=False), "province_admission_not_established"),
])
def test_identity_or_admission_failure_is_overall_unknown(monkeypatch, mutate, reason):
    report = _report()
    mutate(report)
    _install_report(monkeypatch, report)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)

    assert result["status"] == "unknown"
    assert result["reason"] == reason


@pytest.mark.parametrize("province_id", [True, False, "31", 1.5, None])
def test_bool_and_noninteger_ids_are_rejected_before_read(monkeypatch, province_id):
    calls = _install_report(monkeypatch)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, province_id)

    assert result["status"] == "unknown"
    assert result["reason"] == "province_id_invalid"
    assert calls == []


@pytest.mark.parametrize("province_id", [65536, 70000])
def test_out_of_range_province_ids_are_rejected_before_read(monkeypatch, province_id):
    calls = _install_report(monkeypatch)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, province_id)

    assert result["status"] == "unknown"
    assert result["reason"] == "province_id_invalid"
    assert calls == []


def test_missing_safe_raw_reference_keeps_verified_tag_and_exception_fails_closed(monkeypatch):
    report = _report()
    del report["targets"][0]["fields"]["G02.owner"]["raw_inputs"]
    _install_report(monkeypatch, report)
    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)
    assert result["status"] == "known"
    assert result["owner"] == {"status": "known", "tag": "FRA"}

    _install_report(monkeypatch, exception=RuntimeError("reader failure"))
    failed = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)
    assert failed["status"] == "unknown"
    assert failed["reason"] == "province_state_read_failed"


def test_unmatched_country_table_pointer_is_omitted(monkeypatch):
    report = _report()
    report["targets"][0]["fields"]["G02.owner"]["raw_inputs"][
        "table_entry_raw_hex"] = "0000000000000000"
    _install_report(monkeypatch, report)

    result = adapter.read_province_state(lambda *_args: b"", MODULE_BASE, PROVINCE_ID)

    assert result["status"] == "known"
    assert result["owner"] == {
        "status": "known", "tag": "FRA", "reference": _fullref("FRA", OBSERVER_SLOT),
    }


def _simulate_inner_scan(read, extra_label=None):
    labels = (
        ("country_reference.database_global", 0x65000000),
        ("country_reference.slot[17].pointer", 0x65000008),
        ("country_reference.slot[17].fullref", 0x65000010),
        ("province_state.discovery.word_u32", 0x65000018),
        ("province_state.G02_owner.canonical_fullref", 0x65000020),
        ("province_state.G02.owner.province_fullref", 0x65000028),
    )
    for phase in range(2):
        for label, address in labels:
            read(address, 8 if not label.endswith("word_u32") else 4, label)
        if extra_label is not None:
            read(0x66000000 + phase * 8, 8, extra_label)


def test_snapshot_factory_reuses_only_two_country_scans_across_provinces(monkeypatch):
    underlying_reads = []

    def fake_read_two_pass(read, _base, province_id, *, observer, fields):
        assert observer == "FRA" and fields == adapter.FIELDS
        _simulate_inner_scan(read)
        return _report(province_id)

    monkeypatch.setattr(province_state_memory, "read_two_pass", fake_read_two_pass)

    def tracked_read(address, size, label):
        underlying_reads.append((address, size, label))
        return bytes([size]) * size

    snapshot_reader = adapter.make_province_reader()
    first = snapshot_reader(tracked_read, MODULE_BASE, PROVINCE_ID)
    second = snapshot_reader(tracked_read, MODULE_BASE, PROVINCE_ID + 1)
    counts = Counter(label for _, _, label in underlying_reads)

    assert first["status"] == second["status"] == "known"
    assert first["identity_sampling"] == second["identity_sampling"] == (
        "shared_two_pass_country_scan_per_trigger_snapshot")
    assert counts["country_reference.database_global"] == 2
    assert counts["country_reference.slot[17].pointer"] == 2
    assert counts["country_reference.slot[17].fullref"] == 2
    assert counts["province_state.discovery.word_u32"] == 4
    assert counts["province_state.G02_owner.canonical_fullref"] == 2
    assert counts["province_state.G02.owner.province_fullref"] == 4


def test_each_snapshot_factory_starts_with_fresh_country_caches(monkeypatch):
    underlying_reads = []

    def fake_read_two_pass(read, _base, province_id, *, observer, fields):
        _simulate_inner_scan(read)
        return _report(province_id)

    monkeypatch.setattr(province_state_memory, "read_two_pass", fake_read_two_pass)
    tracked_read = lambda address, size, label: (
        underlying_reads.append((address, size, label)) or bytes([size]) * size)

    adapter.make_province_reader()(tracked_read, MODULE_BASE, PROVINCE_ID)
    adapter.make_province_reader()(tracked_read, MODULE_BASE, PROVINCE_ID)

    counts = Counter(label for _, _, label in underlying_reads)
    assert counts["country_reference.database_global"] == 4
    assert counts["country_reference.slot[17].pointer"] == 4
    assert counts["province_state.discovery.word_u32"] == 4


def test_unknown_partial_scan_is_not_committed_and_previous_cache_is_retained(monkeypatch):
    mode = {"value": "known"}
    underlying_reads = []
    extra_label = "country_reference.slot[99].pointer"

    def fake_read_two_pass(read, _base, province_id, *, observer, fields):
        _simulate_inner_scan(
            read, extra_label if mode["value"] != "known" else None)
        result = _report(province_id)
        if mode["value"] == "unknown":
            result["status"] = "unknown"
            result["consistency"] = {"status": "unknown", "shared_mismatch_paths": []}
        return result

    monkeypatch.setattr(province_state_memory, "read_two_pass", fake_read_two_pass)

    def tracked_read(address, size, label):
        underlying_reads.append((address, size, label))
        return bytes([size]) * size

    snapshot_reader = adapter.make_province_reader()
    assert snapshot_reader(tracked_read, MODULE_BASE, PROVINCE_ID)["status"] == "known"
    mode["value"] = "unknown"
    assert snapshot_reader(tracked_read, MODULE_BASE, PROVINCE_ID)["status"] == "unknown"
    mode["value"] = "known_after_partial"
    recovered = snapshot_reader(tracked_read, MODULE_BASE, PROVINCE_ID)
    counts = Counter(label for _, _, label in underlying_reads)

    assert recovered["status"] == "known"
    # The first complete cache remained available through the failed request.
    assert counts["country_reference.database_global"] == 2
    assert counts["country_reference.slot[17].pointer"] == 2
    # Newly read bytes from the unknown call were discarded and had to be read again.
    assert counts[extra_label] == 4


def test_snapshot_factory_fails_closed_on_unexpected_third_phase(monkeypatch):
    def fake_read_two_pass(read, _base, _province_id, *, observer, fields):
        for index in range(3):
            read(0x67000000 + index * 8, 8, "country_reference.database_global")
        return _report()

    monkeypatch.setattr(province_state_memory, "read_two_pass", fake_read_two_pass)
    result = adapter.make_province_reader()(
        lambda _address, size, _label: bytes(size), MODULE_BASE, PROVINCE_ID)

    assert result == {
        "status": "unknown",
        "reason": "province_state_country_scan_phase_overflow",
    }


def test_real_two_pass_reader_shares_common_inputs_but_keeps_province_values_fresh():
    from bridge.tests import test_information_province_state_memory as fixture

    image = fixture.make_image()
    base = fixture.BASES[0]
    second_id = fixture.PROVINCE_ID + 1
    record = fixture.RECORDS + second_id * fixture.province_memory.RECORD_STRIDE
    image.put_i32(record + fixture.province_memory.RECORD_ID_OFFSET, second_id)
    image.put_u64(record + fixture.memory.DISCOVERY_BITSET_POINTER_OFFSET,
                  fixture.DISCOVERY_BITS + 0x100)
    image.put_u32(fixture.DISCOVERY_BITS + 0x100, 1 << fixture.FRA_SLOT)
    image.put_u64(record + fixture.memory.OWNER_FULLREF_OFFSET,
                  fixture._fullref("DEN", fixture.DEN_SLOT))
    image.put_u64(record + fixture.memory.CONTROLLER_FULLREF_OFFSET,
                  fixture._fullref("FRA", fixture.FRA_SLOT))

    reader = adapter.make_province_reader()
    first = reader(image.read, base, fixture.PROVINCE_ID)
    second = reader(image.read, base, second_id)
    assert first["status"] == second["status"] == "known"
    assert first["owner"]["tag"] == "ENG"
    assert second["owner"]["tag"] == "DEN"
    assert second["controller"]["tag"] == "FRA"
    counts = Counter(label for _, _, label in image.reads)
    assert counts["foreign_tech.role.human_count"] == 2
    assert counts["province_reference.world_global"] <= 2
    assert counts["province_state.G02.owner.province_fullref"] == 4
    assert counts["province_state.G02.controller.province_fullref"] == 4
    assert counts["province_state.discovery.word_u32"] == 4
    assert counts[f"province_reference.id[{second_id}]"] == 2

    # An outer snapshot must start new shared samples. A new player controller
    # cannot inherit the preceding snapshot's non-player admission.
    image.put_i32(fixture.CONTROLLERS + fixture.FRA_SLOT * 4, 1)
    fresh = adapter.make_province_reader()(image.read, base, fixture.PROVINCE_ID)
    assert fresh["status"] == "unknown"

