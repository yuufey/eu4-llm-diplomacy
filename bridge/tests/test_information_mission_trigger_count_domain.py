import pytest

from bridge.information import mission_trigger_count_domain as count_domain
from bridge.information import mission_trigger_memory


MODULE_BASE = 0x140000000


def _fullref(slot, tag, *, high=0x12, byte48=0x01):
    low = int.from_bytes(tag.encode("ascii") + b"\0", "little")
    return (high << 56) | (byte48 << 48) | (slot << 32) | low


class MemoryReader:
    def __init__(self, *, short_label=None, error_label=None):
        self.blocks = {}
        self.short_label = short_label
        self.error_label = error_label
        self.reads = []

    def put(self, address, raw):
        self.blocks[address] = bytes(raw)

    def read_code(self, address, size, label):
        self.reads.append((address, size, label))
        if label == self.error_label:
            raise OSError("fixture_read_error")
        if address not in self.blocks:
            raise AssertionError(f"unexpected fixture read: {label} @ {address:#x}")
        raw = self.blocks[address]
        if label == self.short_label:
            return raw[: max(0, size - 1)]
        return raw[:size]

    def read(self, address, size, label):
        return self.read_code(address, size, label)


class Fixture:
    def __init__(self, monkeypatch, *, mock_subject_helper=True):
        self.reader = MemoryReader()
        self.bindings = {}
        self.subject_types = {}
        self.bind_calls = []
        self.subject_calls = []
        self.next_owned = 0x300000
        self.next_subjects = 0x400000

        def bind_country_scope(reader, module_base, fullref):
            self.bind_calls.append((reader, module_base, fullref))
            item = self.bindings.get(fullref)
            if item is None:
                return {"status": "unknown", "reason": "fixture_binding_missing"}
            pointer, tag = item
            return {
                "status": "known",
                "tag": tag,
                "pointer": pointer,
                "fullref": fullref,
            }

        def subject_type_pointer(reader, owner_pointer, parent, label):
            self.subject_calls.append((reader, owner_pointer, parent, label))
            return self.subject_types.get(owner_pointer, (0, None))

        monkeypatch.setattr(
            count_domain.mission_trigger_country_scope,
            "bind_country_scope",
            bind_country_scope,
        )
        if mock_subject_helper:
            monkeypatch.setattr(
                mission_trigger_memory,
                "_subject_type_pointer",
                subject_type_pointer,
            )

    def add_country(self, pointer, tag, slot, province_ids=(), subject_refs=(),
                    parent_reference=0):
        fullref = _fullref(slot, tag)
        self.bindings[fullref] = (pointer, tag)
        self.reader.put(pointer + 0x20, fullref.to_bytes(8, "little"))
        self.reader.put(pointer + 0x18F0, parent_reference.to_bytes(8, "little"))

        ids = list(province_ids)
        if ids:
            data_pointer = self.next_owned
            self.next_owned += 0x1000
            raw_ids = b"".join(int(value).to_bytes(4, "little", signed=True)
                                for value in ids)
            self.reader.put(data_pointer, raw_ids)
        else:
            data_pointer = 0
        self.reader.put(pointer + 0x1338, data_pointer.to_bytes(8, "little"))
        self.reader.put(pointer + 0x1344,
                        len(ids).to_bytes(4, "little", signed=True))

        refs = list(subject_refs)
        if refs:
            begin = self.next_subjects
            self.next_subjects += 0x1000
            raw_refs = b"".join(int(value).to_bytes(8, "little") for value in refs)
            self.reader.put(begin, raw_refs)
            end = begin + len(raw_refs)
        else:
            begin = end = 0
        self.reader.put(pointer + 0x1A18,
                        begin.to_bytes(8, "little") + end.to_bytes(8, "little"))
        return fullref

    def add_type(self, owner_pointer, type_pointer, flag=0):
        self.subject_types[owner_pointer] = (type_pointer, None)
        self.reader.put(type_pointer + 0x11B, bytes([flag]))


def test_mode_zero_empty_and_modes_are_strict(monkeypatch):
    fx = Fixture(monkeypatch)
    root = fx.add_country(0x200000, "FRA", 1)

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, 0x200000, 0)

    assert result == {
        "status": "known",
        "province_ids": [],
        "country_pointer": 0x200000,
        "root_reference": root,
        "country": "FRA",
        "source": count_domain.SOURCE,
    }
    read_count = len(fx.reader.reads)
    for bad_mode in (True, False, 3, "1", None):
        invalid = count_domain.read_count_domain(
            fx.reader, MODULE_BASE, 0x200000, bad_mode
        )
        assert invalid == {"status": "unknown", "reason": "count_domain_mode_invalid"}
        assert len(fx.reader.reads) == read_count
    assert not any("subject_" in label for _, _, label in fx.reader.reads)


def test_owned_ids_keep_native_order_duplicates_and_skip_capacity(monkeypatch):
    fx = Fixture(monkeypatch)
    fx.add_country(0x200000, "FRA", 1, province_ids=[5, 2, 5])

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, 0x200000, 0)

    assert result["status"] == "known"
    assert result["province_ids"] == [5, 2, 5]
    assert not any(address == 0x200000 + 0x1340 for address, _, _ in fx.reader.reads)


def test_mode_one_filters_only_type_flag_zero_and_skips_zero_parent(monkeypatch):
    fx = Fixture(monkeypatch)
    root = 0x200000
    zero_parent = 0x210000
    included = 0x220000
    excluded = 0x230000
    no_type = 0x240000
    zero_parent_ref = fx.add_country(zero_parent, "ENG", 2, province_ids=[90])
    included_ref = fx.add_country(
        included, "PRO", 3, province_ids=[2],
        parent_reference=_fullref(99, "PAP"),
    )
    excluded_ref = fx.add_country(
        excluded, "SCO", 4, province_ids=[3],
        parent_reference=_fullref(98, "NAP"),
    )
    no_type_ref = fx.add_country(
        no_type, "HSC", 5, province_ids=[4],
        parent_reference=_fullref(97, "BUR"),
    )
    fx.add_country(root, "FRA", 1, province_ids=[1],
                   subject_refs=[zero_parent_ref, included_ref,
                                 excluded_ref, no_type_ref])
    fx.add_type(included, 0x500000, flag=0)
    fx.add_type(excluded, 0x510000, flag=1)
    fx.subject_types[no_type] = (0, None)

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, root, 1)

    assert result["status"] == "known"
    assert result["province_ids"] == [1, 2]
    assert [owner for _, owner, _, _ in fx.subject_calls] == [included, excluded, no_type]
    assert any(label.endswith("type_flag_11b") for _, _, label in fx.reader.reads)
    assert all(owner != zero_parent for _, owner, _, _ in fx.subject_calls)


def test_mode_two_recurses_all_valid_types_in_native_order_without_flag_read(monkeypatch):
    fx = Fixture(monkeypatch)
    root, child_a, grandchild, child_b = 0x200000, 0x210000, 0x220000, 0x230000
    grandchild_ref = fx.add_country(
        grandchild, "PRO", 4, province_ids=[12],
        parent_reference=_fullref(50, "PAP"),
    )
    child_a_ref = fx.add_country(
        child_a, "ENG", 2, province_ids=[11], subject_refs=[grandchild_ref],
        parent_reference=_fullref(51, "NAP"),
    )
    child_b_ref = fx.add_country(
        child_b, "SCO", 3, province_ids=[13],
        parent_reference=_fullref(52, "BUR"),
    )
    fx.add_country(root, "FRA", 1, province_ids=[10],
                   subject_refs=[child_a_ref, child_b_ref])
    fx.add_type(child_a, 0x500000, flag=1)
    fx.add_type(grandchild, 0x510000, flag=1)
    fx.add_type(child_b, 0x520000, flag=1)

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, root, 2)

    assert result["status"] == "known"
    assert result["province_ids"] == [10, 11, 12, 13]
    assert len(fx.subject_calls) == 3
    assert not any(label.endswith("type_flag_11b") for _, _, label in fx.reader.reads)


def test_recursive_subject_cycle_fails_whole_result(monkeypatch):
    fx = Fixture(monkeypatch)
    root, child = 0x200000, 0x210000
    root_ref = fx.add_country(
        root, "FRA", 1, province_ids=[1],
        parent_reference=_fullref(70, "PAP"),
    )
    child_ref = fx.add_country(
        child, "ENG", 2, province_ids=[2], subject_refs=[root_ref],
        parent_reference=_fullref(71, "NAP"),
    )
    # Replace the root's subject vector with its child after both refs exist.
    fx.reader.put(root + 0x1A18,
                  (0x400000).to_bytes(8, "little") + (0x400008).to_bytes(8, "little"))
    fx.reader.put(0x400000, child_ref.to_bytes(8, "little"))
    fx.add_type(child, 0x500000)
    fx.add_type(root, 0x510000)

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, root, 2)

    assert result["status"] == "unknown"
    assert result["reason"] == "subject_cycle_detected"
    assert "province_ids" not in result


def test_subject_and_total_id_bounds_fail_closed(monkeypatch):
    fx = Fixture(monkeypatch)
    too_many_refs = [_fullref(index + 1, "ENG") for index in range(65)]
    fx.add_country(0x200000, "FRA", 1, subject_refs=too_many_refs)
    too_many = count_domain.read_count_domain(fx.reader, MODULE_BASE, 0x200000, 2)
    assert too_many == {"status": "unknown", "reason": "subject_count_out_of_bound"}

    fx2 = Fixture(monkeypatch)
    root, child = 0x200000, 0x210000
    child_ref = fx2.add_country(
        child, "ENG", 2, province_ids=list(range(1, 58)),
        parent_reference=_fullref(80, "PAP"),
    )
    fx2.add_country(root, "FRA", 1, province_ids=list(range(1, 201)),
                    subject_refs=[child_ref])
    fx2.add_type(child, 0x500000)
    total = count_domain.read_count_domain(fx2.reader, MODULE_BASE, root, 2)
    assert total == {
        "status": "unknown",
        "reason": "total_province_id_count_out_of_bound",
    }


def test_child_canonical_binding_failure_fails_whole_result(monkeypatch):
    fx = Fixture(monkeypatch)
    root, child = 0x200000, 0x210000
    child_ref = fx.add_country(
        child, "ENG", 2, province_ids=[2],
        parent_reference=_fullref(80, "PAP"),
    )
    fx.add_country(root, "FRA", 1, province_ids=[1], subject_refs=[child_ref])
    fx.add_type(child, 0x500000)
    fx.bindings[child_ref] = (child, "ENG")
    original_bind = count_domain.mission_trigger_country_scope.bind_country_scope

    def bad_child_bind(reader, module_base, fullref):
        if fullref == child_ref:
            return {"status": "known", "tag": "ENG", "pointer": child,
                    "fullref": child_ref + 1}
        return original_bind(reader, module_base, fullref)

    monkeypatch.setattr(
        count_domain.mission_trigger_country_scope,
        "bind_country_scope",
        bad_child_bind,
    )

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, root, 2)

    assert result == {"status": "unknown", "reason": "country_binding_echo_invalid"}
    assert "province_ids" not in result


def test_short_read_fails_closed_without_partial_ids(monkeypatch):
    fx = Fixture(monkeypatch)
    fx.add_country(0x200000, "FRA", 1, province_ids=[1, 2])
    fx.reader.short_label = "count_domain.owned_count_i32"

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, 0x200000, 0)

    assert result == {
        "status": "unknown",
        "reason": "short_or_invalid_read:count_domain.owned_count_i32",
    }
    assert "province_ids" not in result


def test_real_subject_type_helper_uses_tracked_qword_and_mode1_flag_11b(monkeypatch):
    fx = Fixture(monkeypatch, mock_subject_helper=False)
    root, child = 0x200000, 0x210000
    parent_reference = _fullref(7, "PAP")
    child_ref = fx.add_country(
        child, "ENG", 2, province_ids=[22], parent_reference=parent_reference
    )
    fx.add_country(root, "FRA", 1, province_ids=[11], subject_refs=[child_ref])

    table = 0x600000
    relation = 0x610000
    records = 0x620000
    holder = 0x630000
    subject_type = 0x640000
    key = 42
    pair = table + 7 * 72
    fx.reader.put(child + 0x1510, table.to_bytes(8, "little"))
    fx.reader.put(pair, relation.to_bytes(8, "little"))
    lookup_reference = key << 32
    fx.reader.put(pair + 0x10, lookup_reference.to_bytes(8, "little"))
    fx.reader.put(relation + 0x128, records.to_bytes(8, "little"))
    fx.reader.put(relation + 0x134, (1).to_bytes(4, "little", signed=True))
    entry = (key.to_bytes(4, "little", signed=True) + b"\0" * 4
             + holder.to_bytes(8, "little"))
    fx.reader.put(records, entry)
    fx.reader.put(holder + 0x40, subject_type.to_bytes(8, "little"))
    fx.reader.put(subject_type + 0x11B, b"\0")
    # The old held predicate flags are deliberately nonzero; they are not the
    # count-domain mode-1 recursion filter.
    fx.reader.put(subject_type + 0x151, b"\x01\x01")

    result = count_domain.read_count_domain(fx.reader, MODULE_BASE, root, 1)

    assert result["status"] == "known"
    assert result["province_ids"] == [11, 22]
    labels = [label for _, _, label in fx.reader.reads]
    assert "count_domain.subject[0].owner_relation_table" in labels
    assert "count_domain.subject[0].relation_record_entries" in labels
    assert "count_domain.subject[0].subject_type" in labels
    assert "count_domain.subject[0].type_flag_11b" in labels
    assert not any("subject_type_native_flags" in label for label in labels)
