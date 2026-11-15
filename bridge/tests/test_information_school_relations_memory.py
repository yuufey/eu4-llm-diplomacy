from __future__ import annotations

import pytest

from bridge.information import school_relations_memory as memory
from bridge.tests.test_information_religious_schools_memory import (
    DEFINITION, GROUP, SCHOOL, SCHOOL_ARRAY, _qword,
)
from bridge.tests.test_information_religious_scholars_memory import ScholarReader


WORLD = 0xE00000
MANAGER = 0xE01000
GROUP_TABLE = 0xE02000
GROUP_STATE = 0xE03000
DECOY_STATE = 0xE04000
PAIR_ARRAY = 0xE10000
PAIR_BASE = 0xE11000
PEER_BASE = 0xA00000
INVALID_A = 0xFFFFFFFFFFFFF000
INVALID_B = 0xFFFFFFFFFFFFF008


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def _string32(key: bytes) -> bytes:
    if len(key) > 15:
        raise ValueError("peer key must fit the inline test header")
    header = bytearray(32)
    header[:len(key)] = key
    header[len(key)] = 0
    header[16:24] = len(key).to_bytes(8, "little")
    header[24:32] = (15).to_bytes(8, "little")
    return bytes(header)


class RelationReader:
    """Run the actual 173 scholar reader plus the 174 relation leaf."""

    def __init__(self, *, peer_keys=("peer_a", "peer_b"), group_id=2,
                 pair_rows=(), pair_count=None, invalid=None, no_school=False,
                 install_graph=True, shared_budget=False, parent_drift=None):
        self.scholar = ScholarReader()
        self.module_base = self.scholar.module_base
        self.binding = self.scholar.parent.binding
        self.parent = self.scholar.parent
        self.overrides: dict[str, list[bytes | BaseException]] = {}
        self.shared_budget = shared_budget
        self.parent_drift = parent_drift
        self.calls: list[tuple[int, int, str]] = []
        self.school_pointers: dict[str, int] = {"shafi": SCHOOL}

        self._install_group_schools(list(peer_keys), invalid=invalid)
        self.parent.regions[GROUP + 0x58] = _u32(group_id)
        if no_school:
            false_vtable = self.module_base + 0x1C48598
            self.parent.regions[SCHOOL] = _qword(false_vtable)
            self.parent.regions[false_vtable + 0x88] = _qword(
                self.module_base + 0x8F450)

        if install_graph:
            self._install_graph(group_id, list(pair_rows), pair_count)

    def _install_group_schools(self, peer_keys, *, invalid=None):
        # Put the current school at ordinal zero; peers remain in the same
        # native group array and their concrete school objects are readable.
        ordered = [("shafi", SCHOOL)]
        for index, key in enumerate(peer_keys):
            pointer = PEER_BASE + index * 0x200
            ordered.append((key, pointer))
            self.school_pointers[key] = pointer

        count = len(ordered)
        self.parent.regions[DEFINITION + 0x28] = _u32(count)
        self.parent.regions[DEFINITION + 0x2C] = _u32(count)
        self.parent.regions[SCHOOL + 0x178] = _u32(0)
        vtable = self.module_base + 0x1D21740
        for ordinal, (key, pointer) in enumerate(ordered):
            self.parent.regions[SCHOOL_ARRAY + ordinal * 8] = _qword(pointer)
            if pointer == SCHOOL:
                continue
            wrong = invalid if ordinal == 1 else None
            school_vtable = vtable + (8 if wrong == "other_vtable" else 0)
            school_group = GROUP + 8 if wrong == "other_owner" else GROUP
            school_ordinal = ordinal + 1 if wrong == "other_ordinal" else ordinal
            self.parent.regions[pointer] = _qword(school_vtable)
            self.parent.regions[pointer + 0x170] = _qword(school_group)
            self.parent.regions[pointer + 0x178] = _u32(school_ordinal)
            header = bytearray(_string32(key.encode("ascii")))
            if wrong == "other_key":
                header[len(key.encode("ascii"))] = 0x41
            self.parent.regions[pointer + 0x150] = bytes(header)

    def _install_graph(self, group_id, pair_rows, pair_count):
        self.parent.regions[self.module_base + 0x233FE58] = _qword(WORLD)
        self.parent.regions[WORLD + 0x25A8] = _qword(MANAGER)
        self.parent.regions[MANAGER + 0x18] = _qword(GROUP_TABLE)
        # A decoy at slot zero detects accidentally treating a one-based ID as
        # a zero-based index when group_id is two.
        self.parent.regions[GROUP_TABLE] = _qword(DECOY_STATE)
        if 1 <= group_id <= 256:
            self.parent.regions[GROUP_TABLE + (group_id - 1) * 8] = _qword(GROUP_STATE)
        if pair_count is None:
            pair_count = len(pair_rows)
        self.parent.regions[GROUP_STATE + 0x2C] = _i32(pair_count)
        if pair_count > 0:
            self.parent.regions[GROUP_STATE + 0x20] = _qword(PAIR_ARRAY)
            for index, (a, b, value) in enumerate(pair_rows):
                row = PAIR_BASE + index * 0x40
                self.parent.regions[PAIR_ARRAY + index * 8] = _qword(row)
                row_bytes = bytearray(0x2C)
                row_bytes[0x18:0x20] = _qword(a)
                row_bytes[0x20:0x28] = _qword(b)
                row_bytes[0x28:0x2C] = _i32(value)
                self.parent.regions[row] = bytes(row_bytes)

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        scripted = self.overrides.get(label)
        if scripted:
            value = scripted.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        if self.shared_budget and label.startswith("school_relations.relation."):
            raise ValueError("shared_read_budget_exceeded")
        if (self.parent_drift is not None
                and label.startswith("school_relations.")
                and self.parent_drift in label
                and label.endswith("_relations_after")):
            inner_label = label[len("school_relations."):]
            original = self.scholar.read(address, size, inner_label)
            changed = bytearray(original)
            changed[0] ^= 1
            return bytes(changed)
        if not label.startswith("school_relations."):
            raise AssertionError(f"unexpected relation reader label: {label}")
        return self.scholar.read(address, size, label[len("school_relations."):])


def _field(reader: RelationReader):
    return memory.read_fields(reader, reader.module_base, reader.binding,
                              (memory.FIELD_ID,))[memory.FIELD_ID]


def _known(reader: RelationReader) -> dict:
    field = _field(reader)
    assert field["status"] == "known"
    assert field["complete"] is False
    return field


def _relation_error(field: dict, detail: str) -> None:
    assert field["status"] == "known"
    assert field["value"]["has_school"] is True
    relation = field["value"]["relations"]
    assert relation == {"status": "unknown", "reason": "SCHOOL_RELATIONS_UNAVAILABLE"}
    assert field["raw_inputs"]["relation_error"]["detail"] == detail


def test_symmetric_pair_uses_first_duplicate_and_preserves_signed_values_and_irrelevant_rows():
    peer_keys = ("peer_negative", "peer_positive", "peer_minus_one", "peer_zero", "peer_one")
    pointers = {key: PEER_BASE + index * 0x200
                for index, key in enumerate(peer_keys)}
    rows = [
        (INVALID_A, INVALID_B, 99),
        (pointers["peer_negative"], SCHOOL, -2345),
        (SCHOOL, pointers["peer_negative"], 6789),
        (SCHOOL, pointers["peer_positive"], 3456),
        (pointers["peer_minus_one"], SCHOOL, -1),
        (SCHOOL, pointers["peer_zero"], 0),
        (SCHOOL, pointers["peer_one"], 1),
    ]
    reader = RelationReader(peer_keys=peer_keys, group_id=2, pair_rows=rows)

    field = _known(reader)
    relation = field["value"]["relations"]

    assert relation["status"] == "known"
    assert relation["religion_group_key"] == "christian"
    assert relation["source_school_key"] == "shafi"
    assert relation["symmetric"] is True and relation["complete"] is False
    assert relation["basis"] == "native_school_pair_relation_cache"
    assert [(entry["school_key"], entry["value"]) for entry in relation["entries"]] == [
        ("peer_negative", -2345), ("peer_positive", 3456),
        ("peer_minus_one", -1), ("peer_zero", 0), ("peer_one", 1)]
    assert relation["entries"][0]["raw_hex"] == (-2345).to_bytes(
        4, "little", signed=True).hex()
    assert field["raw_inputs"]["relation_group_id"] == 2
    assert field["raw_inputs"]["relation_pair_count"] == len(rows)
    group_state_read = next(row for row in field["raw_inputs"]["reads"]
                            if row["label"] == "school_relations.relation.group_state")
    assert group_state_read["address"] == hex(GROUP_TABLE + 8)
    addresses = {row["address"] for row in field["raw_inputs"]["reads"]}
    assert hex(INVALID_A) not in addresses and hex(INVALID_B) not in addresses


def test_missing_pair_stays_unknown_and_zero_count_does_not_read_an_array():
    reader = RelationReader(peer_keys=("peer_a", "peer_b"), pair_rows=[], pair_count=0)

    relation = _known(reader)["value"]["relations"]

    assert relation["status"] == "known"
    assert relation["entries"] == [
        {"school_key": "peer_a", "status": "unknown", "reason": "SCHOOL_RELATION_NOT_FOUND"},
        {"school_key": "peer_b", "status": "unknown", "reason": "SCHOOL_RELATION_NOT_FOUND"},
    ]
    assert "value" not in relation["entries"][0]
    assert not any(label == "school_relations.relation.pair_array"
                   for _address, _size, label in reader.calls)


def test_native_no_school_is_not_applicable_and_does_not_read_relation_graph():
    reader = RelationReader(peer_keys=(), no_school=True, install_graph=False)

    field = _known(reader)

    assert field["value"]["has_school"] is False
    assert field["value"]["relations"] == {
        "status": "not_applicable", "reason": "NO_CURRENT_RELIGIOUS_SCHOOL"}
    assert not any(label.startswith("school_relations.relation.")
                   for _address, _size, label in reader.calls)


@pytest.mark.parametrize(("invalid", "group_id", "pair_count", "detail"), [
    ("other_owner", 2, 0, "relation_school_owner_mismatch"),
    ("other_ordinal", 2, 0, "relation_school_ordinal_mismatch"),
    ("other_vtable", 2, 0, "unsupported_relation_school_type"),
    ("other_key", 2, 0, "relation_school_1_key_terminator_invalid"),
    (None, 0, 0, "relation_group_id_out_of_bound"),
    (None, 257, 0, "relation_group_id_out_of_bound"),
    (None, 2, -1, "relation_pair_count_out_of_bound"),
    (None, 2, 2049, "relation_pair_count_out_of_bound"),
])
def test_bad_school_identity_group_id_or_signed_pair_count_is_child_unknown(
        invalid, group_id, pair_count, detail):
    reader = RelationReader(
        peer_keys=("peer_a",), invalid=invalid, group_id=group_id,
        pair_count=pair_count, pair_rows=[])

    field = _field(reader)

    _relation_error(field, detail)
    if group_id in (0, 257):
        assert not any(row["label"] == "school_relations.relation.group_state"
                       for row in field["raw_inputs"]["reads"])
    if pair_count in (-1, 2049):
        assert not any(row["label"] == "school_relations.relation.pair_array"
                       for row in field["raw_inputs"]["reads"])


def test_relation_dependency_change_revokes_only_relations_child():
    rows = [(SCHOOL, PEER_BASE, 1234)]
    reader = RelationReader(peer_keys=("peer_a",), pair_rows=rows)
    reader.overrides["school_relations.relation.pair_0.value_relations_after"] = [
        _i32(1235)]

    field = _known(reader)

    assert field["value"]["current_school"] == {"status": "known", "key": "shafi"}
    assert field["value"]["relations"] == {
        "status": "unknown", "reason": "SCHOOL_RELATIONS_CHANGED"}


def test_parent_school_identity_change_revokes_whole_field():
    reader = RelationReader(peer_keys=("peer_a",), pair_rows=[], parent_drift="school_pointer")

    field = _field(reader)

    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field
    assert "school_relations_parent_changed" in field["reason"]


def test_parent_owned_shared_budget_failure_bubbles_through_scholar_child():
    reader = RelationReader(peer_keys=("peer_a",), pair_rows=[(SCHOOL, PEER_BASE, 1)],
                            shared_budget=True)

    with pytest.raises(ValueError, match="school_relation_shared_read_budget_exceeded"):
        _field(reader)


def test_local_budget_failure_caught_by_parent_leaf_still_bubbles(monkeypatch):
    probe = RelationReader(peer_keys=("peer_a",), pair_rows=[(SCHOOL, PEER_BASE, 1)])
    parent_field = _known(probe)
    parent_bytes = parent_field["raw_inputs"]["parent"]["raw_inputs"]["budget"][
        "bytes_requested"]

    monkeypatch.setattr(memory, "MAX_READ_BYTES", parent_bytes)
    reader = RelationReader(peer_keys=("peer_a",), pair_rows=[(SCHOOL, PEER_BASE, 1)])

    with pytest.raises(ValueError, match="school_relation_shared_read_budget_exceeded"):
        _field(reader)

