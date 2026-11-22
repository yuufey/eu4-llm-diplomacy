from __future__ import annotations

import json
import unittest
from unittest import mock

from bridge.information import country_reference_memory as country_refs
from bridge.information import country_wars_memory as wars_memory
from bridge.information import foreign_country_memory as shared
from bridge.information import observer_registry_memory
from bridge.information import province_state_memory as province_state


BASE = 0x140000000
DATABASE = 0x20000000
TABLE = 0x20010000
COUNTRY_COUNT = 130
FRA_SLOT = 122
CREATION = 134376782534496994


class FakeMemory:
    def __init__(self):
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_address: int | None = None
        self.fail_label: str | None = None
        self.short_address: int | None = None
        self.fail_after: int | None = None

    def put(self, address: int, raw: bytes | bytearray):
        for offset, value in enumerate(bytes(raw)):
            self.bytes[address + offset] = value

    def put_u32(self, address: int, value: int, *, signed: bool = False):
        self.put(address, int(value).to_bytes(4, "little", signed=signed))

    def put_u64(self, address: int, value: int):
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if self.fail_after is not None and len(self.reads) > self.fail_after:
            raise OSError("fixture read failure")
        if self.fail_address == address or self.fail_label == label:
            raise OSError("fixture read failure")
        try:
            raw = bytes(self.bytes[address + i] for i in range(size))
        except KeyError as exc:
            raise OSError(f"unmapped fixture byte: {exc.args[0]:x}") from exc
        if self.short_address == address and size:
            return raw[:-1]
        return raw


def _fullref(tag: str, slot: int, *, generation: int = 1, byte48: int = 0) -> int:
    low = int.from_bytes((tag + "\0").encode("ascii"), "little")
    return (generation << 56) | (byte48 << 48) | (slot << 32) | low


class WarFixture:
    def __init__(self, wars: list[dict[str, list[str]]] | None = None,
                 *, target: str = "FRA"):
        self.memory = FakeMemory()
        self.target = target
        self.tags = {"FRA": FRA_SLOT, "BUR": 45, "ENG": 46, "ORL": 47}
        self.country_pointers = {tag: 0x30000000 + slot * 0x1000
                                 for tag, slot in self.tags.items()}
        self.fullrefs = {tag: _fullref(tag, slot) for tag, slot in self.tags.items()}
        self.war_specs = wars if wars is not None else [
            {"side_a": ["FRA"], "side_b": ["BUR"]}
        ]
        self.war_pointers = [0x40000000 + index * 0x1000
                             for index in range(len(self.war_specs))]
        self._make_country_database()
        self._make_wars()
        self.scan = country_refs.resolve_countries(
            self.memory.read, BASE, list(self.tags))
        self.registry_calls = 0

    def _make_country_database(self):
        memory = self.memory
        memory.put_u64(BASE + province_state.DATABASE_GLOBAL_RVA, DATABASE)
        memory.put_u64(DATABASE + country_refs.DATABASE_TABLE_OFFSET, TABLE)
        memory.put_u32(DATABASE + country_refs.DATABASE_TABLE_COUNT_OFFSET, COUNTRY_COUNT,
                       signed=True)
        table_bytes = bytearray(COUNTRY_COUNT * 8)
        for tag, slot in self.tags.items():
            if slot >= COUNTRY_COUNT:
                raise AssertionError("fixture slot outside country table")
            pointer = self.country_pointers[tag]
            table_bytes[slot * 8:(slot + 1) * 8] = pointer.to_bytes(8, "little")
            memory.put(pointer + province_state.COUNTRY_FULLREF_OFFSET,
                       self.fullrefs[tag].to_bytes(8, "little"))
        memory.put(TABLE, table_bytes)

    def _put_country_cache(self, tag: str, rows: list[tuple[int, int]], at_war: bool):
        memory = self.memory
        pointer = self.country_pointers[tag]
        index_pointer = 0x42000000 if tag == "FRA" else 0x43000000 + self.tags[tag] * 0x1000
        if rows:
            raw = bytearray()
            for slot, war_pointer in rows:
                raw += int(slot).to_bytes(4, "little", signed=False)
                raw += b"\0" * 4
                raw += int(war_pointer).to_bytes(8, "little", signed=False)
            memory.put(index_pointer, raw)
        else:
            index_pointer = 0
        memory.put(pointer + wars_memory.AT_WAR_OFFSET, bytes([1 if at_war else 0]))
        memory.put_u64(pointer + wars_memory.WAR_INDEX_POINTER_OFFSET, index_pointer)
        memory.put_u32(pointer + wars_memory.WAR_INDEX_COUNT_OFFSET, len(rows), signed=True)

    def _put_vector(self, address: int, refs: list[int]):
        raw = b"".join(value.to_bytes(8, "little") for value in refs)
        self.memory.put(address, raw)
        self.memory.put_u64(address - 0x1000, address)
        self.memory.put_u64(address - 0x1000 + 8, address + len(raw))
        self.memory.put_u64(address - 0x1000 + 16, address + len(raw))

    def _make_wars(self):
        target_slot = self.tags[self.target]
        target_rows: list[tuple[int, int]] = []
        reverse_rows: dict[str, list[tuple[int, int]]] = {tag: [] for tag in self.tags}
        for index, spec in enumerate(self.war_specs):
            war_pointer = self.war_pointers[index]
            prefix = bytearray(wars_memory.WAR_PREFIX_SIZE)
            prefix[:8] = (BASE + wars_memory.WAR_VTABLE_RVA).to_bytes(8, "little")
            prefix[wars_memory.WAR_MARKER_OFFSET:wars_memory.WAR_MARKER_OFFSET + 4] = \
                wars_memory.WAR_MARKER.to_bytes(4, "little")
            side_a_tags = list(spec["side_a"])
            side_b_tags = list(spec["side_b"])
            vec_a = 0x41000000 + index * 0x2000
            vec_b = vec_a + 0x1000
            self.memory.put(vec_a, b"".join(self.fullrefs[tag].to_bytes(8, "little")
                                            for tag in side_a_tags))
            self.memory.put(vec_b, b"".join(self.fullrefs[tag].to_bytes(8, "little")
                                            for tag in side_b_tags))
            prefix[wars_memory.SIDE_A_VECTOR_OFFSET:wars_memory.SIDE_A_VECTOR_OFFSET + 24] = (
                vec_a.to_bytes(8, "little") + (vec_a + len(side_a_tags) * 8).to_bytes(8, "little")
                + (vec_a + len(side_a_tags) * 8).to_bytes(8, "little"))
            prefix[wars_memory.SIDE_B_VECTOR_OFFSET:wars_memory.SIDE_B_VECTOR_OFFSET + 24] = (
                vec_b.to_bytes(8, "little") + (vec_b + len(side_b_tags) * 8).to_bytes(8, "little")
                + (vec_b + len(side_b_tags) * 8).to_bytes(8, "little"))
            self.memory.put(war_pointer, prefix)
            if self.target in side_a_tags:
                opponents = side_b_tags
            elif self.target in side_b_tags:
                opponents = side_a_tags
            else:
                opponents = []
            for opponent in opponents:
                target_rows.append((self.tags[opponent], war_pointer))
                reverse_rows[opponent].append((target_slot, war_pointer))
        self._put_country_cache(self.target, target_rows, bool(target_rows))
        for tag, rows in reverse_rows.items():
            if tag != self.target and rows:
                self._put_country_cache(tag, rows, True)
            elif tag != self.target:
                self._put_country_cache(tag, [], False)

    def registry_reader(self, read, base):
        self.registry_calls += 1
        entries = []
        epoch = observer_registry_memory.epoch(CREATION)
        for serial, pointer in enumerate(self.war_pointers, start=1):
            entries.append({
                "native_reference": hex(pointer),
                "war_id": f"war_{epoch:016x}_{serial:08x}",
                "serial": serial,
            })
        return {"status": "known", "entries": entries, "count": len(entries),
                "creation_matches": True, "lifetime_binding_verified": False,
                "raw_inputs": {"creation_raw_hex": CREATION.to_bytes(8, "little").hex(),
                               "reads": []}}

    def read(self, *, target: str | None = None, observer: str = "FRA",
             fields=(wars_memory.FIELD_WARS,), with_scan: bool = True,
             gate_result: bool | None = True, registry=True, registry_reader=None):
        target = target or self.target
        gate_calls = []

        def gate(reader, base, bindings, observer_tag, target_tag):
            gate_calls.append((bindings, observer_tag, target_tag))
            if bindings is not None:
                if bindings.get("rows") is not self.scan["rows"]:
                    raise AssertionError("full observed scan rows were copied/replaced")
                if set(bindings["requested"]) != {"FRA", target_tag}:
                    raise AssertionError("requested selector is not narrowed to FRA/member")
                if bindings.get("selector_basis") != \
                        "revalidated_member_from_complete_observed_scan":
                    raise AssertionError("selector basis missing")
            if gate_result is None:
                return {"status": "unknown", "admitted": None,
                        "observer_nonplayer_role": {"verified": True}}
            return {"status": "known", "admitted": gate_result,
                    "observer_nonplayer_role": {"verified": True}}

        out = wars_memory.read_fields(
            self.memory.read, BASE, self.scan["requested"][target], fields,
            observer_binding=self.scan["requested"].get(observer),
            registry_reader=(registry_reader if registry_reader is not None
                             else self.registry_reader if registry else None),
            member_admission_reader=gate,
            admission_bindings=self.scan if with_scan else None)
        return out, gate_calls


class CountryWarsMemoryTests(unittest.TestCase):
    def _field(self, result):
        return result[wars_memory.FIELD_WARS]

    def test_empty_index_returns_known_empty_current_scope(self):
        fixture = WarFixture(wars=[])
        result, calls = fixture.read()
        field = self._field(result)
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"], {
            "at_war": False, "war_count": 0, "wars": [],
            "enumeration_scope": "current_country_opponent_index",
            "global_membership_verified": False, "lifetime_verified": False,
        })
        self.assertEqual(calls, [])
        self.assertEqual(fixture.registry_calls, 1)

    def test_positive_projection_has_exact_public_shape_and_registry_id(self):
        fixture = WarFixture()
        result, calls = fixture.read()
        field = self._field(result)
        self.assertEqual(field["status"], "known")
        self.assertEqual(set(field["value"]), {
            "at_war", "war_count", "wars", "enumeration_scope",
            "global_membership_verified", "lifetime_verified"})
        value = field["value"]
        self.assertTrue(value["at_war"])
        self.assertEqual(value["war_count"], 1)
        self.assertEqual(len(value["wars"]), 1)
        war = value["wars"][0]
        self.assertEqual(set(war), {
            "war_id", "target_side", "side_a", "side_b", "membership_complete",
            "identities_complete", "roles_verified"})
        epoch = observer_registry_memory.epoch(CREATION)
        self.assertEqual(epoch, 0x1C5B10C9B19CE405)
        self.assertNotEqual(epoch, fixture.war_pointers[0])
        self.assertEqual(war["war_id"], {
            "status": "known", "value": f"war_{epoch:016x}_00000001",
            "identity_scope": "observer_session", "lifetime_verified": False})
        self.assertEqual(war["target_side"], "side_a")
        self.assertEqual(war["side_a"], [{"status": "known", "country": "FRA"}])
        self.assertEqual(war["side_b"], [{"status": "known", "country": "BUR"}])
        self.assertTrue(war["membership_complete"])
        self.assertTrue(war["identities_complete"])
        self.assertFalse(war["roles_verified"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(fixture.registry_calls, 1)
        self.assertEqual(field["unit"], "native_country_wars")
        self.assertEqual(field["scale"], 1)
        self.assertTrue(field["partial"])
        self.assertFalse(field["complete"])
        self.assertEqual(field["basis"], "current_country_war_index_and_side_vector_projection")
        self.assertNotIn("raw_inputs", value)
        self.assertEqual(json.loads(json.dumps(field)), field)

    def test_target_can_be_on_side_b(self):
        fixture = WarFixture(wars=[{"side_a": ["BUR"], "side_b": ["FRA"]}])
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["wars"][0]["target_side"], "side_b")

    def test_at_war_flag_and_index_must_agree(self):
        fixture = WarFixture()
        target = fixture.country_pointers["FRA"]
        fixture.memory.put(target + wars_memory.AT_WAR_OFFSET, b"\0")
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertEqual(field["reason"], "AT_WAR_CACHE_CONTRADICTION")

    def test_target_index_must_match_opposite_side_union(self):
        fixture = WarFixture()
        target = fixture.country_pointers["FRA"]
        index = int.from_bytes(fixture.memory.read(
            target + wars_memory.WAR_INDEX_POINTER_OFFSET, 8, "test"), "little")
        fixture.memory.put_u32(index, fixture.tags["ENG"])
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertEqual(field["reason"], "WAR_INDEX_SIDE_SET_MISMATCH:0")

    def test_reverse_pair_must_point_to_same_war(self):
        fixture = WarFixture()
        bur = fixture.country_pointers["BUR"]
        reverse = int.from_bytes(fixture.memory.read(
            bur + wars_memory.WAR_INDEX_POINTER_OFFSET, 8, "test"), "little")
        fixture.memory.put_u64(reverse + wars_memory.WAR_INDEX_WAR_POINTER_OFFSET, 0x40009000)
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertIn("REVERSE_WAR_POINTER_MISMATCH", field["reason"])

    def test_duplicate_counterpart_key_is_rejected(self):
        fixture = WarFixture()
        target = fixture.country_pointers["FRA"]
        index = int.from_bytes(fixture.memory.read(
            target + wars_memory.WAR_INDEX_POINTER_OFFSET, 8, "test"), "little")
        row = fixture.memory.read(index, wars_memory.WAR_INDEX_STRIDE, "test")
        fixture.memory.put(index + wars_memory.WAR_INDEX_STRIDE, row)
        fixture.memory.put_u32(target + wars_memory.WAR_INDEX_COUNT_OFFSET, 2, signed=True)
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertEqual(field["reason"], "WAR_INDEX_COUNTERPART_DUPLICATE")

    def test_member_generation_must_match_canonical_fullref(self):
        fixture = WarFixture()
        war = fixture.war_pointers[0]
        side_b_begin = int.from_bytes(fixture.memory.read(
            war + wars_memory.SIDE_B_VECTOR_OFFSET, 8, "test"), "little")
        wrong_generation = _fullref("BUR", fixture.tags["BUR"], generation=2)
        fixture.memory.put(side_b_begin, wrong_generation.to_bytes(8, "little"))
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertIn("COUNTRY_REFERENCE", field["reason"])

    def test_registry_unknown_does_not_hide_membership_or_count(self):
        fixture = WarFixture()
        field = self._field(fixture.read(registry=False)[0])
        self.assertEqual(field["status"], "known")
        value = field["value"]
        self.assertEqual(value["war_count"], 1)
        self.assertEqual(value["wars"][0]["war_id"], {
            "status": "unknown", "reason": "WAR_ID_REGISTRY_UNKNOWN"})
        self.assertEqual(value["wars"][0]["side_b"], [{"status": "known", "country": "BUR"}])

    def test_retired_registry_slot_binds_only_the_new_public_id(self):
        fixture = WarFixture()

        def current_registry(read, base):
            result = fixture.registry_reader(read, base)
            result["allocated_count"] = 2
            result["entries"][0]["serial"] = 2
            result["entries"][0]["war_id"] = "war_1c5b10c9b19ce405_00000002"
            return result

        field = self._field(fixture.read(registry_reader=current_registry)[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["wars"][0]["war_id"]["value"],
                         "war_1c5b10c9b19ce405_00000002")

    def test_recycled_physical_slot_binds_lifetime_serial_above_256(self):
        fixture = WarFixture()

        def current_registry(read, base):
            result = fixture.registry_reader(read, base)
            result["allocated_count"] = 1
            result["serial_scope"] = "observer_lifetime"
            result["entries"][0]["serial"] = 600
            result["entries"][0]["war_id"] = "war_1c5b10c9b19ce405_00000258"
            return result

        field = self._field(fixture.read(registry_reader=current_registry)[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["wars"][0]["war_id"]["value"],
                         "war_1c5b10c9b19ce405_00000258")

    def test_admission_false_redacts_member_tag_and_keeps_graph(self):
        fixture = WarFixture()
        field = self._field(fixture.read(gate_result=False)[0])
        self.assertEqual(field["status"], "known")
        war = field["value"]["wars"][0]
        self.assertEqual(war["side_b"], [{"status": "invisible", "reason": "NOT_ADMITTED"}])
        self.assertFalse(war["identities_complete"])
        self.assertNotIn("BUR", repr(field["value"]))
        self.assertNotIn("0x", repr(field["value"]))

    def test_unknown_admission_redacts_member_tag(self):
        fixture = WarFixture()
        field = self._field(fixture.read(gate_result=None)[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["wars"][0]["side_b"], [
            {"status": "unknown", "reason": "MEMBER_ADMISSION_UNKNOWN"}])

    def test_full_scan_is_preserved_and_selector_is_exactly_pair_scoped(self):
        fixture = WarFixture()
        original_requested = dict(fixture.scan["requested"])
        _, calls = fixture.read()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1:], ("FRA", "FRA"))
        self.assertEqual(calls[1][1:], ("FRA", "BUR"))
        self.assertEqual(fixture.scan["requested"], original_requested)

    def test_default_gate_without_real_scan_is_unknown_not_synthetic(self):
        fixture = WarFixture()
        result = wars_memory.read_fields(
            fixture.memory.read, BASE, fixture.scan["requested"]["FRA"],
            (wars_memory.FIELD_WARS,), observer_binding=fixture.scan["requested"]["FRA"],
            registry_reader=fixture.registry_reader, admission_bindings=None)
        field = self._field(result)
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["wars"][0]["side_b"], [
            {"status": "unknown", "reason": "MEMBER_ADMISSION_UNKNOWN"}])

    def test_registry_callback_once_per_leaf_call(self):
        fixture = WarFixture(wars=[
            {"side_a": ["FRA"], "side_b": ["BUR"]},
            {"side_a": ["FRA"], "side_b": ["ENG"]},
        ])
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["war_count"], 2)
        epoch = observer_registry_memory.epoch(CREATION)
        self.assertEqual([war["war_id"]["value"] for war in field["value"]["wars"]], [
            f"war_{epoch:016x}_00000001", f"war_{epoch:016x}_00000002"])
        self.assertEqual(fixture.registry_calls, 1)

    def test_registry_epoch_is_not_mistaken_for_pointer(self):
        fixture = WarFixture()
        epoch = observer_registry_memory.epoch(CREATION)
        result, _ = fixture.read()
        descriptor = self._field(result)["value"]["wars"][0]["war_id"]
        self.assertEqual(descriptor["value"].split("_")[1], f"{epoch:016x}")
        self.assertNotEqual(int(descriptor["value"].split("_")[1], 16),
                            fixture.war_pointers[0])

    def test_bad_registry_epoch_serial_and_binding_flags_hide_only_id(self):
        fixture = WarFixture()
        good_registry = fixture.registry_reader

        def wrong_epoch(read, base):
            result = good_registry(read, base)
            for entry in result["entries"]:
                entry["war_id"] = f"war_{fixture.war_pointers[0]:016x}_{entry['serial']:08x}"
            return result

        field = self._field(fixture.read(registry_reader=wrong_epoch)[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["war_count"], 1)
        self.assertEqual(field["value"]["wars"][0]["war_id"], {
            "status": "unknown", "reason": "WAR_ID_REGISTRY_UNKNOWN"})

        fixture = WarFixture()

        def bad_serial(read, base):
            result = fixture.registry_reader(read, base)
            result["entries"][0]["serial"] = True
            return result

        field = self._field(fixture.read(registry_reader=bad_serial)[0])
        self.assertEqual(field["status"], "known")
        self.assertEqual(field["value"]["wars"][0]["war_id"], {
            "status": "unknown", "reason": "WAR_ID_REGISTRY_UNKNOWN"})

        for change in (
            lambda result: result.update(creation_matches=False),
            lambda result: result.update(lifetime_binding_verified=True),
            lambda result: result.update(count=result["count"] + 1),
        ):
            fixture = WarFixture()

            def malformed_registry(read, base, change=change, fixture=fixture):
                result = fixture.registry_reader(read, base)
                change(result)
                return result

            field = self._field(fixture.read(registry_reader=malformed_registry)[0])
            self.assertEqual(field["status"], "known")
            self.assertEqual(field["value"]["wars"][0]["war_id"], {
                "status": "unknown", "reason": "WAR_ID_REGISTRY_UNKNOWN"})

    def test_noncanonical_native_reference_is_rejected(self):
        for malformed in ("missing_prefix", "extra_leading_zero", "oversized"):
            fixture = WarFixture()

            def malformed_registry(read, base, malformed=malformed, fixture=fixture):
                result = fixture.registry_reader(read, base)
                native_reference = result["entries"][0]["native_reference"]
                if malformed == "missing_prefix":
                    result["entries"][0]["native_reference"] = native_reference[2:]
                elif malformed == "extra_leading_zero":
                    result["entries"][0]["native_reference"] = "0x0" + native_reference[2:]
                else:
                    result["entries"][0]["native_reference"] = "0x1" + "0" * 16
                return result

            field = self._field(fixture.read(registry_reader=malformed_registry)[0])
            self.assertEqual(field["status"], "known")
            self.assertEqual(field["value"]["war_count"], 1)
            self.assertEqual(field["value"]["wars"][0]["war_id"], {
                "status": "unknown", "reason": "WAR_ID_REGISTRY_UNKNOWN"})

    def test_unsupported_field_performs_zero_reads(self):
        fixture = WarFixture()
        fixture.memory.reads.clear()
        result = wars_memory.read_fields(
            fixture.memory.read, BASE, fixture.scan["requested"]["FRA"],
            ("F01.territory",), observer_binding=fixture.scan["requested"]["FRA"])
        self.assertEqual(result["F01.territory"], {
            "status": "unknown", "reason": "UNSUPPORTED_FIELD_READER"})
        self.assertEqual(fixture.memory.reads, [])

    def test_duplicate_wars_field_is_rejected_without_reads(self):
        fixture = WarFixture()
        fixture.memory.reads.clear()
        result = wars_memory.read_fields(
            fixture.memory.read, BASE, fixture.scan["requested"]["FRA"],
            (wars_memory.FIELD_WARS, wars_memory.FIELD_WARS),
            observer_binding=fixture.scan["requested"]["FRA"])
        self.assertEqual(result[wars_memory.FIELD_WARS]["reason"], "DUPLICATE_FIELD_REQUESTED")
        self.assertEqual(fixture.memory.reads, [])

    def test_short_read_and_exception_fail_closed(self):
        fixture = WarFixture()
        fixture.memory.short_address = BASE + province_state.DATABASE_GLOBAL_RVA
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertIn("BINDING_DATABASE_MISMATCH", field["reason"])

        fixture = WarFixture()
        fixture.memory.fail_address = BASE + province_state.DATABASE_GLOBAL_RVA
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")

    def test_shared_read_budget_is_enforced(self):
        fixture = WarFixture()
        with mock.patch.object(shared, "MAX_READ_CALLS", 2):
            field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")

    def test_invalid_vector_capacity_fails_closed(self):
        fixture = WarFixture()
        war = fixture.war_pointers[0]
        cap_address = war + wars_memory.SIDE_B_VECTOR_OFFSET + 16
        fixture.memory.put_u64(cap_address, 0x41000000 + 0x300000)
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertIn("WAR_VECTOR", field["reason"])

    def test_target_must_appear_exactly_once(self):
        fixture = WarFixture()
        war = fixture.war_pointers[0]
        side_a_begin = int.from_bytes(fixture.memory.read(
            war + wars_memory.SIDE_A_VECTOR_OFFSET, 8, "test"), "little")
        fixture.memory.put(side_a_begin, fixture.fullrefs["ENG"].to_bytes(8, "little"))
        field = self._field(fixture.read()[0])
        self.assertEqual(field["status"], "unknown")
        self.assertIn("WAR_TARGET_NOT_EXACTLY_ONCE", field["reason"])

    def test_observer_must_match_expected_binding(self):
        fixture = WarFixture()
        field = self._field(fixture.read(observer="BUR")[0])
        self.assertEqual(field["status"], "unknown")
        self.assertEqual(field["reason"], "OBSERVER_BINDING_SCOPE_MISMATCH")


if __name__ == "__main__":
    unittest.main()
