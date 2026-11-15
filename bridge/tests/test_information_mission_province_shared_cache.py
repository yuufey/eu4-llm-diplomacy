"""Focused snapshot-cache tests for mission-trigger province input reads."""
from collections import Counter

from bridge.information import mission_trigger_provinces as adapter
from bridge.information import province_state_memory
from bridge.tests.test_information_mission_trigger_provinces import (
    MODULE_BASE,
    PROVINCE_ID,
    _report,
)


MARKER = "country_reference.database_global"
EXTRA_LABEL = "country_reference.slot[99].pointer"

SHARED_READS = (
    ("foreign_tech.role.human_count", 0x65000080, 4),
    ("province_reference.array_begin", 0x65000088, 8),
    ("province_reference.array_end", 0x65000090, 8),
    ("province_reference.records_pointer", 0x65000098, 8),
)
PROVINCE_READS = (
    ("province_state.G02.owner.province_fullref", 0x650000A0, 8),
    ("province_state.discovery.word_u32", 0x650000B0, 4),
)


def _simulate_inputs(read, province_id, *, include_identity=False, extra=False):
    """Exercise each inner phase through the adapter's tracked reader."""
    observed = {label: [] for label, _address, _size in (*SHARED_READS, *PROVINCE_READS)}
    if include_identity:
        observed.update({
            "country_reference.slot[17].fullref": [],
            "province_state.G02_owner.canonical_fullref": [],
            "province_state.G02.owner.province_fullref": [],
        })
    if extra:
        observed[EXTRA_LABEL] = []

    for _phase in range(2):
        read(0x65000070, 8, MARKER)
        phase_reads = SHARED_READS
        if include_identity:
            phase_reads += (
                ("country_reference.slot[17].fullref", 0x650000C0, 8),
                # This label aliases the exact canonical country bytes above.
                ("province_state.G02_owner.canonical_fullref", 0x650000C0, 8),
                # Province source bytes remain target/pass-specific even here.
                ("province_state.G02.owner.province_fullref", 0x650000C0, 8),
            )
        for label, address, size in phase_reads:
            observed[label].append(read(address, size, label))
        for label, address, size in PROVINCE_READS:
            observed[label].append(read(address, size, label))
        if extra:
            observed[EXTRA_LABEL].append(read(0x650000D0, 8, EXTRA_LABEL))
    return observed


def _install_scanner(monkeypatch, *, status_for=None, include_identity=False,
                     extra_when=None, bases=None):
    observations = []

    def fake_read_two_pass(read, module_base, province_id, *, observer, fields):
        assert observer == "FRA"
        assert fields == adapter.FIELDS
        if bases is not None:
            bases.append(module_base)
        values = _simulate_inputs(
            read, province_id,
            include_identity=include_identity,
            extra=bool(extra_when and extra_when(province_id)),
        )
        observations.append((province_id, values))
        result = _report(province_id)
        if status_for is not None:
            result["status"] = status_for(province_id)
        return result

    monkeypatch.setattr(province_state_memory, "read_two_pass", fake_read_two_pass)
    return observations


def _tracked_reader(underlying_reads):
    counts = Counter()

    def read(address, size, label):
        underlying_reads.append((address, size, label))
        counts[label] += 1
        # Per-label changing bytes make phase separation and fresh target reads
        # observable without depending on native pointers or game state.
        return bytes([counts[label] & 0xFF]) * size

    return read


def test_shared_inputs_are_cached_per_phase_but_province_values_are_fresh(monkeypatch):
    observations = _install_scanner(monkeypatch)
    underlying_reads = []
    reader = _tracked_reader(underlying_reads)
    snapshot = adapter.make_province_reader()

    first = snapshot(reader, MODULE_BASE, PROVINCE_ID)
    second = snapshot(reader, MODULE_BASE, PROVINCE_ID + 1)

    counts = Counter(label for _address, _size, label in underlying_reads)
    assert first["status"] == second["status"] == "known"
    assert counts["foreign_tech.role.human_count"] == 2
    assert [values["foreign_tech.role.human_count"] for _, values in observations] == [
        [b"\x01" * 4, b"\x02" * 4],
        [b"\x01" * 4, b"\x02" * 4],
    ]
    for label in ("province_state.G02.owner.province_fullref",
                  "province_state.discovery.word_u32"):
        assert counts[label] == 4
        assert len({raw for _, values in observations for raw in values[label]}) == 4
    for label in ("province_reference.array_begin", "province_reference.array_end",
                  "province_reference.records_pointer"):
        assert counts[label] == 2
    assert counts[MARKER] == 2


def test_canonical_country_aliases_share_by_address_and_width_only(monkeypatch):
    observations = _install_scanner(monkeypatch, include_identity=True)
    underlying_reads = []
    snapshot = adapter.make_province_reader()

    result = snapshot(_tracked_reader(underlying_reads), MODULE_BASE, PROVINCE_ID)

    counts = Counter(label for _address, _size, label in underlying_reads)
    address_counts = Counter((address, label)
                             for address, _size, label in underlying_reads)
    assert result["status"] == "known"
    assert counts["country_reference.slot[17].fullref"] == 2
    assert counts["province_state.G02_owner.canonical_fullref"] == 0
    assert counts["province_state.G02.owner.province_fullref"] == 4
    assert address_counts[(0x650000C0,
                           "province_state.G02.owner.province_fullref")] == 2
    assert address_counts[(0x650000A0,
                           "province_state.G02.owner.province_fullref")] == 2
    values = observations[0][1]
    assert values["country_reference.slot[17].fullref"] == [b"\x01" * 8, b"\x02" * 8]
    assert values["province_state.G02_owner.canonical_fullref"] == [
        b"\x01" * 8, b"\x02" * 8,
    ]
    assert values["province_state.G02.owner.province_fullref"] == [
        b"\x01" * 8, b"\x02" * 8, b"\x03" * 8, b"\x04" * 8,
    ]


def test_cache_is_fresh_per_factory_and_rejects_module_base_change(monkeypatch):
    observations = _install_scanner(monkeypatch)
    underlying_reads = []
    read = _tracked_reader(underlying_reads)
    second_base = MODULE_BASE + 0x100000

    first_snapshot = adapter.make_province_reader()
    first = first_snapshot(read, MODULE_BASE, PROVINCE_ID)
    changed = first_snapshot(read, second_base, PROVINCE_ID + 1)
    fresh = adapter.make_province_reader()(read, second_base, PROVINCE_ID + 1)

    counts = Counter(label for _address, _size, label in underlying_reads)
    assert first["status"] == fresh["status"] == "known"
    assert changed == {
        "status": "unknown",
        "reason": "province_state_cache_context_changed",
    }
    assert counts[MARKER] == 4
    assert counts["foreign_tech.role.human_count"] == 4
    assert len(observations) == 2


def test_unknown_target_discards_new_shared_bytes_and_keeps_committed_cache(monkeypatch):
    mode = {"value": "known"}
    observations = _install_scanner(
        monkeypatch,
        status_for=lambda _province_id: "unknown" if mode["value"] == "unknown" else "observed",
        extra_when=lambda _province_id: mode["value"] != "known",
    )
    underlying_reads = []
    read = _tracked_reader(underlying_reads)
    snapshot = adapter.make_province_reader()

    initial = snapshot(read, MODULE_BASE, PROVINCE_ID)
    mode["value"] = "unknown"
    partial = snapshot(read, MODULE_BASE, PROVINCE_ID)
    mode["value"] = "recovered"
    recovered = snapshot(read, MODULE_BASE, PROVINCE_ID)

    counts = Counter(label for _address, _size, label in underlying_reads)
    assert initial["status"] == recovered["status"] == "known"
    assert partial["status"] == "unknown"
    assert counts["foreign_tech.role.human_count"] == 2
    assert counts["province_reference.array_begin"] == 2
    assert counts[EXTRA_LABEL] == 4
    assert counts[MARKER] == 2
    assert len(observations) == 3
