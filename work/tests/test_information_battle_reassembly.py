"""Contract tests for opaque owned-battle fragment reassembly."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zlib

import work.information_battle_reassembly as reassembly_module
from work.information_battle_reassembly import (
    FRAGMENT_CAPACITY_BYTES,
    FRAGMENT_HEADER_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PENDING_BYTES,
    MAX_PENDING_GROUPS,
    BattleReassemblyStore,
    FragmentValidationError,
    SourceBindingError,
    build_fragment_payload,
    parse_fragment_payload,
)
from work.information_battle_transport import (
    EVENT,
    BattleTransportStore,
)
from work.information_battle_log_reader import BattleLogTailer


INSTALLATION = "1111222233334444"
WORLD = "00000000feedbeef"
NATIVE_LOG = Path(
    "work/runtime/information-battle-fragments-20261025-001/"
    "native-fragment-test-001/fragmented-battle-001.log"
)


def wire_line(
        payload: bytes, sequence: str, *, installation: str = INSTALLATION,
        world_generation: str = WORLD,
) -> bytes:
    value = {
        "event": EVENT,
        "wire_version": 1,
        "installation": installation,
        "world_generation": world_generation,
        "attempt_sequence": sequence,
        "payload_encoding": "hex",
        "payload_bytes": len(payload),
        "payload_hex": payload.hex(),
    }
    return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def fragments_for(
        data: bytes, message_id: int, *, crc_data: bytes | None = None,
        installation: str = INSTALLATION, world_generation: str = WORLD,
) -> list[bytes]:
    crc = zlib.crc32(data if crc_data is None else crc_data) & 0xFFFFFFFF
    total = len(data)
    count = (total + FRAGMENT_CAPACITY_BYTES - 1) // FRAGMENT_CAPACITY_BYTES
    return [
        build_fragment_payload(
            installation=installation,
            world_generation=world_generation,
            message_id=message_id,
            total_bytes=total,
            fragment_index=index,
            data=data[index * FRAGMENT_CAPACITY_BYTES:(index + 1) * FRAGMENT_CAPACITY_BYTES],
            whole_crc32=crc,
        )
        for index in range(count)
    ]


def ingest_rows(
        transport: BattleTransportStore, payloads: list[bytes],
        *, start_sequence: int = 1,
) -> None:
    for offset, payload in enumerate(payloads):
        result = transport.ingest_line(wire_line(payload, str(start_sequence + offset)))
        if not result["ack"]:
            raise AssertionError(result)


class FragmentFormatTests(unittest.TestCase):
    def test_fixed_header_and_uint64_message_id_are_exact(self) -> None:
        data = b"opaque-fragment"
        payload = build_fragment_payload(
            installation=INSTALLATION,
            world_generation=WORLD,
            message_id=(1 << 64) - 1,
            total_bytes=len(data),
            fragment_index=0,
            data=data,
            whole_crc32=zlib.crc32(data) & 0xFFFFFFFF,
        )
        self.assertEqual(len(payload), FRAGMENT_HEADER_BYTES + len(data))
        parsed = parse_fragment_payload(memoryview(payload))
        self.assertEqual(parsed.message_id, str((1 << 64) - 1))
        self.assertEqual(parsed.fragment_bytes, data)

    def test_header_bounds_and_reserved_bytes_are_rejected(self) -> None:
        data = b"x"
        payload = bytearray(fragments_for(data, 1)[0])
        cases = {
            "magic": (0, b"X"),
            "header": (8, (63).to_bytes(2, "little")),
            "flags": (10, (1).to_bytes(2, "little")),
            "reserved": (44, b"\x01"),
        }
        for name, (offset, replacement) in cases.items():
            with self.subTest(name=name):
                changed = bytearray(payload)
                changed[offset:offset + len(replacement)] = replacement
                with self.assertRaises(FragmentValidationError):
                    parse_fragment_payload(changed)
        with self.assertRaises(FragmentValidationError):
            parse_fragment_payload(payload + b"x")
        with self.assertRaises(FragmentValidationError):
            parse_fragment_payload(payload[:FRAGMENT_HEADER_BYTES - 1])


class ReassemblyTests(unittest.TestCase):
    def make_stores(self, root: Path):
        transport = BattleTransportStore(root / "transport.sqlite3")
        reassembly = BattleReassemblyStore(root / "reassembly.sqlite3")
        return transport, reassembly

    def test_out_of_order_duplicate_restart_and_explicit_get(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                data = bytes((index * 17 + 3) & 0xFF for index in range(9000))
                parts = fragments_for(data, 7)
                ingest_rows(transport, [parts[2], parts[0], parts[1], parts[0]])
                result = reassembly.poll_from_store(transport, limit=256)
                self.assertEqual(result["status"], "advanced")
                self.assertEqual(result["processed"], 4)
                self.assertEqual(result["completed"], 1)
                self.assertEqual(result["duplicates"], 1)
                message = reassembly.get_message(INSTALLATION, WORLD, "7")
                self.assertIsNotNone(message)
                assert message is not None
                self.assertEqual(message["payload"], data)
                self.assertTrue(message["transport_complete"])
                self.assertFalse(message["battle_complete"])
                self.assertFalse(message["overall_complete"])
                self.assertEqual(reassembly.poll_from_store(transport)["status"], "idle")
                cursor = reassembly.cursor()
                self.assertEqual(cursor["received_order"], 4)
                attempts = reassembly._connection.execute(
                    "SELECT source_received_order, transport_attempt_sequence "
                    "FROM fragment_attempts ORDER BY source_received_order"
                ).fetchall()
                self.assertEqual(
                    attempts,
                    [(1, "1"), (2, "2"), (3, "3"), (4, "4")],
                )
                listed = reassembly.list_groups(limit=1)
                self.assertNotIn("payload", listed["groups"][0])
                reassembly.close()
                reassembly = BattleReassemblyStore(root / "reassembly.sqlite3")
                self.assertEqual(reassembly.poll_from_store(transport)["status"], "idle")
                self.assertEqual(reassembly.get_message(INSTALLATION, WORLD, "7")["payload"], data)
            finally:
                reassembly.close()
                transport.close()

    def test_conflict_latches_without_overwrite_or_cursor_advance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-conflict-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                original = b"original"
                conflict = b"changed!"
                crc = zlib.crc32(original) & 0xFFFFFFFF
                first = build_fragment_payload(
                    installation=INSTALLATION, world_generation=WORLD,
                    message_id=9, total_bytes=len(original), fragment_index=0,
                    data=original, whole_crc32=crc,
                )
                second = build_fragment_payload(
                    installation=INSTALLATION, world_generation=WORLD,
                    message_id=9, total_bytes=len(conflict), fragment_index=0,
                    data=conflict, whole_crc32=crc,
                )
                ingest_rows(transport, [first, second])
                self.assertEqual(reassembly.poll_from_store(transport)["processed"], 1)
                cursor_before = reassembly.cursor()["received_order"]
                stopped = reassembly.poll_from_store(transport)
                self.assertEqual(stopped["status"], "stopped_conflict")
                self.assertEqual(stopped["received_order"], cursor_before)
                self.assertIsNone(reassembly.get_message(INSTALLATION, WORLD, "9"))
                group = reassembly.status()["groups"][0]
                self.assertEqual(group["status"], "conflicted")
                self.assertEqual(group["received_count"], 1)
                retained = reassembly._connection.execute(
                    "SELECT payload FROM complete_messages WHERE group_id=?",
                    (group["group_id"],),
                ).fetchone()
                self.assertIsNotNone(retained)
                assert retained is not None
                self.assertEqual(bytes(retained[0]), original)
                again = reassembly.poll_from_store(transport)
                self.assertEqual(again["status"], "stopped_conflict")
                self.assertEqual(again["received_order"], cursor_before)
            finally:
                reassembly.close()
                transport.close()

    def test_crc_error_latches_and_does_not_publish(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-crc-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                data = b"crc-check"
                bad = build_fragment_payload(
                    installation=INSTALLATION, world_generation=WORLD,
                    message_id=10, total_bytes=len(data), fragment_index=0,
                    data=data, whole_crc32=(zlib.crc32(data) + 1) & 0xFFFFFFFF,
                )
                ingest_rows(transport, [bad])
                stopped = reassembly.poll_from_store(transport)
                self.assertEqual(stopped["status"], "stopped_crc_error")
                self.assertEqual(stopped["received_order"], 0)
                self.assertIsNone(reassembly.get_message(INSTALLATION, WORLD, "10"))
                self.assertEqual(reassembly.status()["groups"][0]["status"], "crc_error")
                self.assertEqual(reassembly.poll_from_store(transport)["status"], "stopped_crc_error")
            finally:
                reassembly.close()
                transport.close()

    def test_capacity_stops_without_dropping_or_advancing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-capacity-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                payloads = [
                    fragments_for(bytes([index & 0xFF]) * 4033, index + 1)[0]
                    for index in range(MAX_PENDING_GROUPS + 1)
                ]
                ingest_rows(transport, payloads)
                first = reassembly.poll_from_store(transport, limit=MAX_PENDING_GROUPS)
                self.assertEqual(first["processed"], MAX_PENDING_GROUPS)
                stopped = reassembly.poll_from_store(transport)
                self.assertEqual(stopped["status"], "stopped_capacity")
                self.assertEqual(stopped["received_order"], MAX_PENDING_GROUPS)
                self.assertEqual(reassembly.status()["unfinished_groups"], MAX_PENDING_GROUPS)

                with mock.patch(
                        "work.information_battle_reassembly.MAX_PENDING_BYTES", 4,
                ):
                    transport2 = BattleTransportStore(root / "transport2.sqlite3")
                    reassembly2 = BattleReassemblyStore(root / "reassembly2.sqlite3")
                    try:
                        ingest_rows(transport2, [fragments_for(b"1234", 99)[0]])
                        self.assertEqual(reassembly2.poll_from_store(transport2)["processed"], 1)
                        ingest_rows(transport2, [fragments_for(b"12345", 100)[0]], start_sequence=2)
                        stopped_bytes = reassembly2.poll_from_store(transport2)
                        self.assertEqual(stopped_bytes["status"], "stopped_capacity")
                        self.assertEqual(stopped_bytes["received_order"], 1)
                    finally:
                        reassembly2.close()
                        transport2.close()
            finally:
                reassembly.close()
                transport.close()

    def test_source_replacement_rejected_and_pages_bound_missing_indices(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-source-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                data = b"x" * MAX_MESSAGE_BYTES
                parts = fragments_for(data, 12)
                ingest_rows(transport, [parts[0]])
                self.assertEqual(reassembly.poll_from_store(transport)["processed"], 1)
                status = reassembly.status(limit=1)
                self.assertEqual(status["groups_returned"], 1)
                self.assertEqual(len(status["groups"][0]["missing_indices"]), len(parts) - 1)
                self.assertLessEqual(len(status["groups"][0]["missing_indices"]), 261)
                with self.assertRaises(ValueError):
                    reassembly.status(limit=0)
                with self.assertRaises(ValueError):
                    reassembly.list_groups(limit=257)

                replacement = root / "replacement.sqlite3"
                other = BattleTransportStore(replacement)
                try:
                    other.ingest_line(wire_line(b"x", "1"))
                    transport.close()
                    replacement_path = Path(transport.database)
                    replacement_path.unlink()
                    replacement_path.write_bytes(replacement.read_bytes())
                    with self.assertRaises(SourceBindingError):
                        reassembly.status()
                    with self.assertRaises(SourceBindingError):
                        reassembly.poll_from_store(transport)
                finally:
                    other.close()
            finally:
                reassembly.close()
                # The source object is intentionally closed above before its
                # path replacement; close is idempotent for this test cleanup.
                try:
                    transport.close()
                except Exception:
                    pass

    def test_missing_source_schema_probe_is_read_only_and_typed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-missing-") as directory:
            missing = Path(directory) / "source.sqlite3"
            fake_store = mock.Mock(database=str(missing))
            # Simulate the source disappearing after the identity stat but
            # before the schema connection.  mode=ro must not create it.
            with mock.patch.object(
                    reassembly_module, "_stable_file_identity",
                    return_value=("fake-device:fake-inode", "fake-creation"),
            ):
                with self.assertRaises(SourceBindingError):
                    reassembly_module.BattleReassemblyStore._source_snapshot(fake_store)
            self.assertFalse(missing.exists())

    def test_completed_conflict_latches_when_pending_admission_is_full(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-terminal-conflict-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                original = b"original"
                crc = zlib.crc32(original) & 0xFFFFFFFF
                first = build_fragment_payload(
                    installation=INSTALLATION, world_generation=WORLD,
                    message_id=90, total_bytes=len(original), fragment_index=0,
                    data=original, whole_crc32=crc,
                )
                ingest_rows(transport, [first])
                self.assertEqual(reassembly.poll_from_store(transport)["completed"], 1)

                pending = [
                    fragments_for(bytes([index & 0xFF]) * 4033, 1000 + index)[0]
                    for index in range(MAX_PENDING_GROUPS)
                ]
                ingest_rows(transport, pending, start_sequence=2)
                admitted = reassembly.poll_from_store(
                    transport, limit=MAX_PENDING_GROUPS,
                )
                self.assertEqual(admitted["processed"], MAX_PENDING_GROUPS)
                self.assertEqual(reassembly.status()["unfinished_groups"], MAX_PENDING_GROUPS)

                conflict = build_fragment_payload(
                    installation=INSTALLATION, world_generation=WORLD,
                    message_id=90, total_bytes=len(original), fragment_index=0,
                    data=b"changed!", whole_crc32=crc,
                )
                ingest_rows(transport, [conflict], start_sequence=MAX_PENDING_GROUPS + 2)
                stopped = reassembly.poll_from_store(transport)
                self.assertEqual(stopped["status"], "stopped_conflict")
                self.assertEqual(stopped["received_order"], MAX_PENDING_GROUPS + 1)
                group = next(
                    item for item in reassembly.status(limit=MAX_PENDING_GROUPS + 1)["groups"]
                    if item["message_id"] == "90"
                )
                self.assertEqual(group["status"], "conflicted")
                self.assertIsNone(reassembly.get_message(INSTALLATION, WORLD, "90"))
            finally:
                reassembly.close()
                transport.close()

    def test_invalid_fragment_does_not_advance_source_cursor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-invalid-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                ingest_rows(transport, [b"bad-fragment"])
                stopped = reassembly.poll_from_store(transport)
                self.assertEqual(stopped["status"], "stopped_invalid_fragment")
                self.assertEqual(stopped["received_order"], 0)
                self.assertEqual(reassembly.cursor()["received_order"], 0)
            finally:
                reassembly.close()
                transport.close()

    def test_sql_commit_failure_rolls_back_cursor_and_fragment_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-sql-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                data = b"z" * (FRAGMENT_CAPACITY_BYTES + 1)
                parts = fragments_for(data, 21)
                ingest_rows(transport, parts)
                self.assertEqual(reassembly.poll_from_store(transport, limit=1)["processed"], 1)
                original_commit = reassembly._commit
                calls = 0

                def flaky_commit() -> None:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise RuntimeError("commit-fail")
                    original_commit()

                with mock.patch.object(reassembly, "_commit", side_effect=flaky_commit):
                    failed = reassembly.poll_from_store(transport)
                self.assertEqual(failed["status"], "persistence_failed")
                self.assertEqual(failed["received_order"], 1)
                self.assertEqual(reassembly.cursor()["received_order"], 1)
                self.assertEqual(reassembly.status()["groups"][0]["received_count"], 1)
                retried = reassembly.poll_from_store(transport)
                self.assertEqual(retried["status"], "advanced")
                self.assertIsNotNone(reassembly.get_message(INSTALLATION, WORLD, "21"))
            finally:
                reassembly.close()
                transport.close()

    def test_cursor_compare_and_swap_failure_has_no_progress(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-reassembly-cas-") as directory:
            root = Path(directory)
            transport, reassembly = self.make_stores(root)
            try:
                ingest_rows(transport, [fragments_for(b"cas", 22)[0]])
                from work.information_battle_reassembly import ReassemblyCursorConflict
                with mock.patch.object(
                        reassembly, "_advance_cursor",
                        side_effect=ReassemblyCursorConflict("cas"),
                ):
                    failed = reassembly.poll_from_store(transport)
                self.assertEqual(failed["status"], "cursor_conflict")
                self.assertEqual(reassembly.cursor()["received_order"], 0)
                self.assertEqual(reassembly.status()["unfinished_groups"], 0)
                retried = reassembly.poll_from_store(transport)
                self.assertEqual(retried["processed"], 1)
            finally:
                reassembly.close()
                transport.close()


class NativeFragmentTests(unittest.TestCase):
    def test_native_fragment_log_tail_transport_and_reassembly(self) -> None:
        if not NATIVE_LOG.exists():
            self.fail(f"required native fragment log is missing: {NATIVE_LOG}")
        if NATIVE_LOG.stat().st_size > 4 * 1024 * 1024:
            self.fail("native fragment log exceeds bounded offline test size")
        with tempfile.TemporaryDirectory(prefix="information-battle-native-fragments-") as directory:
            root = Path(directory)
            transport = BattleTransportStore(root / "transport.sqlite3")
            tailer = BattleLogTailer(
                NATIVE_LOG, root / "tailer.sqlite3", receiver=transport,
                max_frames=256,
            )
            reassembly = BattleReassemblyStore(root / "reassembly.sqlite3")
            try:
                first = tailer.poll()
                second = tailer.poll()
                self.assertEqual(first["status"], "budget_exhausted")
                self.assertEqual(second["status"], "advanced")
                self.assertEqual(tailer.cursor()["offset"], NATIVE_LOG.stat().st_size)
                reassembly_results = []
                for _ in range(4):
                    result = reassembly.poll_from_store(transport)
                    reassembly_results.append(result)
                    if result["status"] == "idle":
                        break
                self.assertIn("idle", [item["status"] for item in reassembly_results])
                groups = reassembly.list_groups(limit=256)["groups"]
                complete = [group for group in groups if group["status"] == "complete"]
                self.assertEqual(len(complete), 5)
                expected_sizes = [1, 4032, 4033, 10037, 1048576]
                self.assertEqual(sorted(item["total_bytes"] for item in complete), expected_sizes)
                for group in complete:
                    message = reassembly.get_message(
                        group["installation"], group["world_generation"], group["message_id"]
                    )
                    self.assertIsNotNone(message)
                    assert message is not None
                    expected = bytes(
                        (index * 37 + 11) & 0xFF
                        for index in range(message["payload_bytes"])
                    )
                    self.assertEqual(message["payload"], expected)
                    self.assertFalse(message["battle_complete"])
                self.assertEqual(reassembly.status()["overall_complete"], False)
            finally:
                reassembly.close()
                tailer.close()
                transport.close()


if __name__ == "__main__":
    unittest.main()
