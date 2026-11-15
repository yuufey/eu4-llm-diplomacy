"""Contract tests for the offline owned-battle JSONL receiver.

These tests deliberately treat the payload as opaque bytes.  They verify the
wire envelope, durable acknowledgement boundary, stream identity, and
sequence observations without claiming anything about B01--B04 semantics.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from work.information_battle_transport import (
    EVENT,
    MAX_PAYLOAD_BYTES,
    UINT64_MAX,
    BattleTransportStore,
    FrameValidationError,
    parse_wire_frame,
)


INSTALLATION = "0123456789abcdef"
WORLD = "fedcba9876543210"
OTHER_INSTALLATION = "1111111111111111"
OTHER_WORLD = "2222222222222222"


def make_wire(
    sequence: str = "1",
    payload: bytes = b"\x01\x02opaque",
    *,
    installation: str = INSTALLATION,
    world_generation: str = WORLD,
    **overrides: object,
) -> bytes:
    """Make a canonical test frame, with explicit overrides for negatives."""

    value: dict[str, object] = {
        "event": EVENT,
        "wire_version": 1,
        "installation": installation,
        "world_generation": world_generation,
        "attempt_sequence": sequence,
        "payload_encoding": "hex",
        "payload_bytes": len(payload),
        "payload_hex": payload.hex(),
    }
    value.update(overrides)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    ) + b"\n"


@contextmanager
def temporary_store():
    with tempfile.TemporaryDirectory(prefix="information-battle-transport-") as directory:
        store = BattleTransportStore(Path(directory) / "records.sqlite3")
        try:
            yield store, Path(directory) / "records.sqlite3"
        finally:
            store.close()


class WireValidationTests(unittest.TestCase):
    def test_valid_frame_copies_wire_and_payload(self) -> None:
        original = bytearray(make_wire(payload=b"copy-me"))
        frame = parse_wire_frame(memoryview(original))
        original[0] = ord("{") ^ 1

        self.assertEqual(frame.payload, b"copy-me")
        self.assertEqual(frame.payload_bytes, 7)
        self.assertEqual(frame.attempt_sequence, "1")
        self.assertEqual(frame.wire, make_wire(payload=b"copy-me"))
        self.assertEqual(frame.payload_sha256, hashlib.sha256(b"copy-me").hexdigest())

    def test_crlf_is_accepted_but_original_wire_is_retained(self) -> None:
        line = make_wire(payload=b"crlf").replace(b"\n", b"\r\n")
        frame = parse_wire_frame(line)
        self.assertEqual(frame.payload, b"crlf")
        self.assertEqual(frame.wire, line)

    def test_malformed_frames_are_rejected_without_guessing(self) -> None:
        invalid: list[bytes] = [
            make_wire(payload=b"x")[:-1],  # incomplete frame
            make_wire(payload=b"x") + b"\n",  # two physical lines
            b"{\xff}\n",  # invalid UTF-8
            make_wire(payload=b"x", extra="nope"),  # unknown key
            make_wire(payload=b"x", payload_bytes=True),  # numeric bool
            make_wire(payload=b"x", payload_hex="AA"),  # uppercase hex
            make_wire(payload=b"x", sequence="01"),  # non-canonical decimal
            make_wire(payload=b"x", sequence="0"),
            make_wire(payload=b"x", sequence=str(UINT64_MAX + 1)),
            make_wire(payload=b"x", installation="0123456789ABCDEF"),
            make_wire(payload=b"x", installation="0000000000000000"),
            make_wire(payload=b"x", payload_bytes=0, payload_hex=""),
            make_wire(payload=b"x", payload_bytes=2, payload_hex="00"),
            make_wire(payload=b"x", event="other_event"),
        ]
        for line in invalid:
            with self.subTest(line=line[:80]):
                with self.assertRaises(FrameValidationError):
                    parse_wire_frame(line)

        duplicate = (
            b'{"event":"information_owned_battle_record",'
            b'"event":"information_owned_battle_record"}\n'
        )
        with self.assertRaises(FrameValidationError):
            parse_wire_frame(duplicate)

        # A deeply nested but small JSON value must be reported as a typed
        # frame rejection rather than leaking RecursionError from json.loads.
        deep = b"[" * 2000 + b"]" * 2000 + b"\n"
        with self.assertRaises(FrameValidationError):
            parse_wire_frame(deep)

    def test_oversized_memoryview_is_rejected_before_buffer_copy(self) -> None:
        oversized = memoryview(bytearray(1024 * 1024))

        real_bytes = bytes

        class BytesGuardMeta(type):
            def __instancecheck__(self, value: object) -> bool:
                return isinstance(value, real_bytes)

        class BytesGuard(metaclass=BytesGuardMeta):
            def __new__(cls, *args: object, **kwargs: object):
                raise AssertionError("oversized input was copied")

        with mock.patch(
            "work.information_battle_transport.bytes",
            BytesGuard,
        ):
            with self.assertRaises(FrameValidationError) as raised:
                parse_wire_frame(oversized)
        self.assertEqual(str(raised.exception), "wire_too_large")

    def test_sequence_text_longer_than_uint64_is_rejected_before_conversion(self) -> None:
        with self.assertRaises(FrameValidationError) as raised:
            parse_wire_frame(make_wire(sequence="1" + "0" * 20))
        self.assertEqual(str(raised.exception), "attempt_sequence_too_long")

    def test_valid_max_payload_and_wire_bounds(self) -> None:
        payload = bytes(range(256)) * (MAX_PAYLOAD_BYTES // 256)
        self.assertEqual(len(payload), MAX_PAYLOAD_BYTES)
        frame = parse_wire_frame(make_wire(payload=payload))
        self.assertEqual(frame.payload_bytes, MAX_PAYLOAD_BYTES)


class DurableReceiverTests(unittest.TestCase):
    def test_sqlite_uses_full_synchronous_mode(self) -> None:
        with temporary_store() as (store, _database):
            synchronous = store._connection.execute("PRAGMA synchronous").fetchone()[0]
            self.assertEqual(synchronous, 2)  # SQLITE_FULL

    def test_commit_precedes_ack_and_failed_commit_leaves_no_half_record(self) -> None:
        with temporary_store() as (store, _database):
            line = make_wire(payload=b"transaction")
            with mock.patch.object(store, "_commit", side_effect=RuntimeError("commit-fail")):
                failed = store.ingest_line(line)
            self.assertFalse(failed["ack"])
            self.assertEqual(failed["status"], "persistence_failed")
            self.assertEqual(store.list_records(), [])
            self.assertEqual(store.stream_status(INSTALLATION, WORLD)["received_count"], 0)

            inserted = store.ingest_line(line)
            self.assertTrue(inserted["ack"])
            self.assertTrue(inserted["inserted"])
            self.assertEqual(len(store.list_records()), 1)

    def test_restart_preserves_opaque_payload_wire_and_decimal_uint64_max(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-restart-") as directory:
            database = Path(directory) / "records.sqlite3"
            line = make_wire(sequence=str(UINT64_MAX), payload=b"max-sequence")
            first = BattleTransportStore(database)
            result = first.ingest_line(line)
            self.assertTrue(result["ack"])
            first.close()

            second = BattleTransportStore(database)
            record = second.get_record(INSTALLATION, WORLD, str(UINT64_MAX))
            self.assertIsNotNone(record)
            assert record is not None
            self.assertIs(type(record["attempt_sequence"]), str)
            self.assertEqual(record["attempt_sequence"], str(UINT64_MAX))
            self.assertEqual(record["payload"], b"max-sequence")
            self.assertEqual(record["wire"], line)
            second.close()

    def test_duplicate_is_idempotent_and_conflict_cannot_overwrite(self) -> None:
        with temporary_store() as (store, _database):
            line = make_wire(payload=b"original")
            self.assertEqual(store.ingest_line(line)["status"], "inserted")

            duplicate = store.ingest_line(line.replace(b"\n", b"\r\n"))
            self.assertTrue(duplicate["ack"])
            self.assertTrue(duplicate["idempotent"])
            self.assertEqual(duplicate["status"], "duplicate")
            self.assertEqual(
                store.get_record(INSTALLATION, WORLD, "1")["wire"], line
            )

            conflict = store.ingest_line(make_wire(payload=b"different"))
            self.assertFalse(conflict["ack"])
            self.assertTrue(conflict["conflict"])
            self.assertEqual(store.get_record(INSTALLATION, WORLD, "1")["payload"], b"original")
            self.assertEqual(store.stream_status(INSTALLATION, WORLD)["received_count"], 1)

    def test_observed_gap_is_stream_local_and_history_survives_late_fill(self) -> None:
        with temporary_store() as (store, _database):
            self.assertEqual(store.ingest_line(make_wire(sequence="3"))["status"], "inserted")
            after_jump = store.stream_status(INSTALLATION, WORLD)
            self.assertEqual(after_jump["continuity"], "observed_gap")
            self.assertFalse(after_jump["complete"])
            self.assertEqual(after_jump["observed_gaps"][0]["start_sequence"], "1")
            self.assertEqual(after_jump["observed_gaps"][0]["end_sequence"], "2")
            self.assertEqual(
                [(item["start_sequence"], item["end_sequence"])
                 for item in after_jump["open_gap_ranges"]],
                [("1", "2")],
            )

            self.assertEqual(store.ingest_line(make_wire(sequence="1"))["status"], "inserted")
            mid = store.stream_status(INSTALLATION, WORLD)
            self.assertEqual([(item["start_sequence"], item["end_sequence"])
                              for item in mid["open_gap_ranges"]], [("2", "2")])
            self.assertEqual(store.ingest_line(make_wire(sequence="2"))["status"], "inserted")
            filled = store.stream_status(INSTALLATION, WORLD)
            self.assertEqual(filled["continuity"], "observed_gap")
            self.assertEqual(filled["open_gap_ranges"], [])
            self.assertEqual(len(filled["observed_gaps"]), 1)
            self.assertFalse(filled["complete"])

            duplicate = store.ingest_line(make_wire(sequence="2"))
            self.assertTrue(duplicate["idempotent"])
            self.assertEqual(store.stream_status(INSTALLATION, WORLD)["received_count"], 3)

    def test_installation_and_generation_are_independent_streams(self) -> None:
        with temporary_store() as (store, _database):
            self.assertTrue(store.ingest_line(make_wire(sequence="2"))["ack"])
            self.assertTrue(store.ingest_line(make_wire(
                sequence="1", installation=OTHER_INSTALLATION))["ack"])
            self.assertTrue(store.ingest_line(make_wire(
                sequence="1", world_generation=OTHER_WORLD))["ack"])

            first = store.stream_status(INSTALLATION, WORLD)
            other_installation = store.stream_status(OTHER_INSTALLATION, WORLD)
            other_generation = store.stream_status(INSTALLATION, OTHER_WORLD)
            self.assertTrue(first["observed_gap"])
            self.assertFalse(other_installation["observed_gap"])
            self.assertFalse(other_generation["observed_gap"])
            self.assertEqual(other_installation["received_count"], 1)
            self.assertEqual(other_generation["received_count"], 1)

    def test_identities_remain_isolated_after_restart(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-isolation-") as directory:
            database = Path(directory) / "records.sqlite3"
            store = BattleTransportStore(database)
            store.ingest_line(make_wire(sequence="1", payload=b"old"))
            store.close()
            reopened = BattleTransportStore(database)
            self.assertTrue(reopened.ingest_line(make_wire(
                sequence="1", world_generation=OTHER_WORLD, payload=b"new"))["inserted"])
            self.assertEqual(reopened.get_record(INSTALLATION, WORLD, "1")["payload"], b"old")
            self.assertEqual(reopened.get_record(INSTALLATION, OTHER_WORLD, "1")["payload"], b"new")
            reopened.close()

    def test_list_records_is_bounded_and_cursor_ordered(self) -> None:
        with temporary_store() as (store, _database):
            for sequence in range(1, 301):
                payload = bytes((sequence % 256,))
                self.assertTrue(store.ingest_line(
                    make_wire(sequence=str(sequence), payload=payload)
                )["ack"])

            first_page = store.list_records()
            self.assertEqual(len(first_page), 256)
            self.assertEqual(first_page[0]["received_order"], 1)
            self.assertEqual(first_page[-1]["received_order"], 256)

            second_page = store.list_records(after_order=256, limit=1024)
            self.assertEqual(len(second_page), 44)
            self.assertEqual(second_page[0]["received_order"], 257)
            self.assertEqual(second_page[-1]["received_order"], 300)
            self.assertEqual(
                [item["received_order"] for item in first_page + second_page],
                list(range(1, 301)),
            )

            for kwargs in (
                {"limit": True},
                {"limit": 0},
                {"limit": -1},
                {"limit": 1025},
                {"after_order": True},
                {"after_order": -1},
            ):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(ValueError):
                        store.list_records(**kwargs)

    def test_gap_pages_are_bounded_and_report_truncation(self) -> None:
        with temporary_store() as (store, _database):
            # Every even sequence leaves one independent odd sequence gap.
            for sequence in range(2, 522, 2):
                self.assertTrue(store.ingest_line(
                    make_wire(sequence=str(sequence), payload=b"g")
                )["ack"])

            status = store.stream_status(INSTALLATION, WORLD, gap_limit=2)
            self.assertEqual(len(status["observed_gaps"]), 2)
            self.assertEqual(len(status["open_gap_ranges"]), 2)
            self.assertEqual(status["observed_gaps_total"], 260)
            self.assertEqual(status["open_gap_ranges_total"], 260)
            self.assertTrue(status["observed_gaps_truncated"])
            self.assertTrue(status["open_gap_ranges_truncated"])
            self.assertEqual(status["observed_gaps_page"]["returned"], 2)
            self.assertEqual(status["open_gap_ranges_page"]["total"], 260)
            self.assertTrue(status["consistent"])

            for gap_limit in (True, 0, -1, 1025):
                with self.subTest(gap_limit=gap_limit):
                    with self.assertRaises(ValueError):
                        store.stream_status(INSTALLATION, WORLD, gap_limit=gap_limit)

    def test_late_fill_of_uint64_gap_uses_bounded_text_ranges(self) -> None:
        with temporary_store() as (store, _database):
            maximum = str(UINT64_MAX)
            self.assertTrue(store.ingest_line(
                make_wire(sequence=maximum, payload=b"z")
            )["ack"])
            initial = store.stream_status(INSTALLATION, WORLD)
            self.assertEqual(initial["open_gap_ranges"], [{
                "gap_id": initial["open_gap_ranges"][0]["gap_id"],
                "start_sequence": "1",
                "end_sequence": str(UINT64_MAX - 1),
            }])

            self.assertTrue(store.ingest_line(
                make_wire(sequence="1", payload=b"a")
            )["ack"])
            after_first = store.stream_status(INSTALLATION, WORLD)
            self.assertEqual(after_first["open_gap_ranges"][0]["start_sequence"], "2")
            self.assertEqual(after_first["open_gap_ranges"][0]["end_sequence"], str(UINT64_MAX - 1))

            self.assertTrue(store.ingest_line(
                make_wire(sequence=str(UINT64_MAX - 1), payload=b"y")
            )["ack"])
            after_last = store.stream_status(INSTALLATION, WORLD)
            self.assertEqual(after_last["open_gap_ranges"], [{
                "gap_id": after_last["open_gap_ranges"][0]["gap_id"],
                "start_sequence": "2",
                "end_sequence": str(UINT64_MAX - 2),
            }])

    def test_status_uses_one_snapshot_across_store_connections(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-snapshot-") as directory:
            database = Path(directory) / "records.sqlite3"
            first = BattleTransportStore(database)
            second = BattleTransportStore(database)
            try:
                first.ingest_line(make_wire(sequence="3", payload=b"3"))
                before = first.stream_status(INSTALLATION, WORLD, gap_limit=4)
                self.assertTrue(before["consistent"])
                self.assertEqual(before["received_count"], 1)
                self.assertEqual(before["observed_gaps_total"], 1)

                second.ingest_line(make_wire(sequence="1", payload=b"1"))
                after = first.stream_status(INSTALLATION, WORLD, gap_limit=4)
                self.assertTrue(after["consistent"])
                self.assertEqual(after["received_count"], 2)
                self.assertEqual(after["observed_gaps_total"], 1)
                self.assertEqual(after["open_gap_ranges"][0]["start_sequence"], "2")
            finally:
                second.close()
                first.close()


class NativeVectorTests(unittest.TestCase):
    def test_recorded_native_vectors_are_accepted_and_persisted(self) -> None:
        vector_path = Path(
            "work/runtime/information-battle-message-20261025-001/native-wire-test-001/"
            "wire-vectors-001.jsonl"
        )
        if not vector_path.exists():
            self.fail(f"required native vector artifact is missing: {vector_path}")
        if vector_path.stat().st_size > 4 * 1024 * 1024:
            self.fail("native vector file exceeds bounded offline test size")
        count = 0
        with tempfile.TemporaryDirectory(prefix="information-battle-vectors-") as directory:
            store = BattleTransportStore(Path(directory) / "vectors.sqlite3")
            try:
                with vector_path.open("rb") as stream:
                    for line in stream:
                        if not line.strip():
                            continue
                        vector = json.loads(line.decode("utf-8"))
                        self.assertIsInstance(vector, dict)
                        self.assertIn("wire_hex", vector)
                        wire = bytes.fromhex(vector["wire_hex"])
                        self.assertEqual(vector["written_bytes"], len(wire))
                        frame = parse_wire_frame(wire)
                        self.assertEqual(frame.installation, vector["installation"])
                        self.assertEqual(frame.world_generation, vector["world_generation"])
                        self.assertEqual(frame.attempt_sequence, vector["attempt_sequence"])
                        self.assertEqual(frame.payload_bytes, vector["payload_bytes"])
                        self.assertEqual(frame.payload.hex(), vector["payload_hex"])
                        result = store.ingest_line(wire)
                        self.assertTrue(result["ack"], result)
                        self.assertTrue(result["inserted"], result)
                        count += 1
            finally:
                store.close()
        self.assertGreater(count, 0)
        self.assertEqual(count, 2)


class NativeHandoffTests(unittest.TestCase):
    def test_real_owned_drain_handoff_is_idempotent_and_durable(self) -> None:
        handoff_path = Path(
            "work/runtime/information-battle-message-20261025-001/native-handoff-test-001/"
            "handoff-frames-001.jsonl"
        )
        if not handoff_path.exists():
            self.fail(f"required native handoff artifact is missing: {handoff_path}")
        if handoff_path.stat().st_size > 4 * 1024 * 1024:
            self.fail("native handoff artifact exceeds bounded offline test size")

        lines = []
        with handoff_path.open("rb") as stream:
            for line in stream:
                if line.strip():
                    lines.append(bytes(line))
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], lines[1])

        frames = [parse_wire_frame(line) for line in lines]
        self.assertEqual(frames[0].identity_key(), frames[1].identity_key())
        self.assertEqual(frames[0].payload, frames[1].payload)
        self.assertEqual(frames[2].payload_bytes, MAX_PAYLOAD_BYTES)
        self.assertEqual(frames[2].payload, bytes(range(256)) * 16)

        with tempfile.TemporaryDirectory(prefix="information-battle-handoff-") as directory:
            database = Path(directory) / "handoff.sqlite3"
            store = BattleTransportStore(database)
            first = store.ingest_line(lines[0])
            retry = store.ingest_line(lines[1])
            second = store.ingest_line(lines[2])
            self.assertTrue(first["ack"])
            self.assertTrue(first["inserted"])
            self.assertTrue(retry["ack"])
            self.assertTrue(retry["idempotent"])
            self.assertEqual(retry["status"], "duplicate")
            self.assertTrue(second["ack"])
            self.assertTrue(second["inserted"])

            before_restart = store.list_records(limit=10)
            self.assertEqual(len(before_restart), 2)
            self.assertEqual(before_restart[0]["wire"], lines[0])
            self.assertEqual(before_restart[0]["payload"], frames[0].payload)
            self.assertEqual(before_restart[1]["wire"], lines[2])
            self.assertEqual(before_restart[1]["payload"], frames[2].payload)
            self.assertEqual(
                [item["received_order"] for item in before_restart], [1, 2]
            )
            store.close()

            reopened = BattleTransportStore(database)
            try:
                after_restart = reopened.list_records(limit=10)
                self.assertEqual(len(after_restart), 2)
                self.assertEqual(after_restart[0]["wire"], lines[0])
                self.assertEqual(after_restart[1]["wire"], lines[2])
                self.assertEqual(after_restart[1]["payload"], bytes(range(256)) * 16)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
