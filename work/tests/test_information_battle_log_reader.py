"""Contract tests for the checked native battle-log tailer."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from work.information_battle_log_reader import (
    FileSnapshot,
    MAX_FRAMES_PER_POLL,
    BattleLogTailer,
    FileLockBusy,
    LogBindingError,
    acquire_file_lock,
    parse_log_header,
)
from work.information_battle_transport import (
    EVENT,
    MAX_WIRE_BYTES,
    BattleTransportStore,
    FrameValidationError,
    parse_wire_frame,
)


INSTALLATION = "0123456789abcdef"
WORLD = "fedcba9876543210"
OTHER_INSTALLATION = "1111111111111111"
OTHER_WORLD = "2222222222222222"
HEADER = f"EU4_OWNED_BATTLE_WIRE_V1 {INSTALLATION} {WORLD}\n".encode("ascii")
NATIVE_LOG = Path(
    "work/runtime/information-battle-popup-20261025-001/native-log-test-001/"
    "checked-battle-001.log"
)


def make_wire(
        sequence: str = "1",
        payload: bytes = b"opaque",
        *,
        installation: str = INSTALLATION,
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
    import json
    return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


@contextmanager
def components(log: Path, root: Path, *, max_frames: int = MAX_FRAMES_PER_POLL):
    receiver = BattleTransportStore(root / "records.sqlite3")
    tailer = BattleLogTailer(
        log,
        root / "cursor.sqlite3",
        receiver=receiver,
        max_frames=max_frames,
    )
    try:
        yield tailer, receiver, root / "cursor.sqlite3", root / "records.sqlite3"
    finally:
        tailer.close()
        receiver.close()


class HeaderTests(unittest.TestCase):
    def test_exact_ascii_header_and_binding(self) -> None:
        parsed = parse_log_header(HEADER)
        self.assertEqual(parsed.installation, INSTALLATION)
        self.assertEqual(parsed.world_generation, WORLD)
        self.assertEqual(parsed.raw, HEADER)
        for invalid in (
            HEADER.replace(b"\n", b"\r\n"),
            HEADER.replace(INSTALLATION.encode(), b"0123456789ABCDEF"),
            HEADER.replace(INSTALLATION.encode(), b"0000000000000000"),
            HEADER + b"extra",
            HEADER[:-1],
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(LogBindingError):
                    parse_log_header(invalid)

    def test_budget_is_at_most_256(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-budget-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            log.write_bytes(HEADER)
            for value in (True, 0, -1, MAX_FRAMES_PER_POLL + 1):
                with self.subTest(value=value):
                    receiver = BattleTransportStore(root / f"records-{value}.sqlite3")
                    with self.assertRaises(ValueError):
                        BattleLogTailer(
                            log, root / f"cursor-{value}.sqlite3",
                            receiver=receiver, max_frames=value,
                        )
                    receiver.close()


class TailerTests(unittest.TestCase):
    def test_os_read_and_seek_failures_are_typed_without_cursor_progress(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-io-error-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            log.write_bytes(HEADER + make_wire(payload=b"io"))
            with components(log, root) as (tailer, receiver, *_):
                with mock.patch.object(
                        tailer, "_read_frame",
                        side_effect=OSError("read-fail"),
                ):
                    read_failed = tailer.poll()
                self.assertEqual(read_failed["status"], "stopped_read_error")
                self.assertIn("read_failed:OSError", read_failed["reason"])
                self.assertEqual(read_failed["offset"], len(HEADER))
                self.assertEqual(tailer.cursor()["offset"], len(HEADER))
                self.assertEqual(receiver.list_records(), [])

                class BrokenSeek:
                    closed = False

                    def seek(self, offset: int) -> None:
                        raise OSError("seek-fail")

                    def close(self) -> None:
                        self.closed = True

                class Lease:
                    released = False

                    def release(self) -> None:
                        self.released = True

                stream = BrokenSeek()
                lease = Lease()
                cursor = tailer.cursor()
                assert cursor is not None
                snapshot = FileSnapshot(cursor["file_identity"], len(HEADER))
                header = parse_log_header(HEADER)
                with mock.patch.object(
                        tailer, "_open_checked_file",
                        return_value=(stream, lease, snapshot, header),
                ):
                    seek_failed = tailer.poll()
                self.assertEqual(seek_failed["status"], "stopped_read_error")
                self.assertIn("seek_failed:OSError", seek_failed["reason"])
                self.assertEqual(seek_failed["offset"], len(HEADER))
                self.assertEqual(tailer.cursor()["offset"], len(HEADER))
                self.assertTrue(lease.released)
                self.assertTrue(stream.closed)

    def test_open_failure_closes_stream_even_when_unlock_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-cleanup-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            log.write_bytes(HEADER)
            with components(log, root) as (tailer, _receiver, *_):
                original = log.open("rb")

                class TrackingStream:
                    def __init__(self, wrapped):
                        self.wrapped = wrapped
                        self.closed = False

                    def fileno(self):
                        return self.wrapped.fileno()

                    def readline(self, limit):
                        return b"invalid-header\n"

                    def close(self):
                        self.closed = True
                        self.wrapped.close()

                class UnlockFailure:
                    def release(self):
                        raise RuntimeError("unlock-fail")

                stream = TrackingStream(original)
                with mock.patch(
                        "pathlib.Path.open", return_value=stream,
                ), mock.patch(
                        "work.information_battle_log_reader.acquire_file_lock",
                        return_value=UnlockFailure(),
                ):
                    with self.assertRaises(RuntimeError):
                        tailer._open_checked_file()
                self.assertTrue(stream.closed)

    def test_restart_cursor_resumes_and_does_not_duplicate_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-restart-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            frames = [make_wire(str(i), bytes((i,))) for i in range(1, 4)]
            log.write_bytes(HEADER + b"".join(frames))
            with components(log, root, max_frames=1) as (tailer, receiver, *_):
                first = tailer.poll()
                self.assertEqual(first["status"], "budget_exhausted")
                self.assertEqual(first["acked"], 1)
                tailer.close()
                # The context manager's close is idempotent; reopen below.
            reopened_receiver = BattleTransportStore(root / "records.sqlite3")
            reopened = BattleLogTailer(
                log, root / "cursor.sqlite3", receiver=reopened_receiver
            )
            try:
                second = reopened.poll()
                self.assertEqual(second["status"], "advanced")
                self.assertEqual(second["acked"], 2)
                records = reopened_receiver.list_records(limit=10)
                self.assertEqual(len(records), 3)
                self.assertEqual([r["attempt_sequence"] for r in records], ["1", "2", "3"])
                self.assertEqual(reopened.poll()["status"], "idle")
            finally:
                reopened.close()
                reopened_receiver.close()

    def test_partial_tail_waits_then_advances_after_lf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-partial-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            frame = make_wire(payload=b"tail")
            log.write_bytes(HEADER + frame[:-1])
            with components(log, root) as (tailer, receiver, *_):
                partial = tailer.poll()
                self.assertEqual(partial["status"], "partial")
                self.assertEqual(partial["acked"], 0)
                self.assertEqual(receiver.list_records(), [])
                with log.open("ab") as stream:
                    stream.write(b"\n")
                complete = tailer.poll()
                self.assertEqual(complete["status"], "advanced")
                self.assertEqual(complete["acked"], 1)
                self.assertEqual(len(receiver.list_records()), 1)

    def test_record_commit_then_cursor_commit_failure_replays_idempotently(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-cursor-failure-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            frame = make_wire(payload=b"commit-order")
            log.write_bytes(HEADER)
            with components(log, root) as (tailer, receiver, *_):
                self.assertEqual(tailer.poll()["status"], "idle")
                with log.open("ab") as stream:
                    stream.write(frame)
                with mock.patch.object(
                        tailer, "_cursor_commit",
                        side_effect=RuntimeError("cursor-commit-fail"),
                ):
                    failed = tailer.poll()
                self.assertEqual(failed["status"], "cursor_checkpoint_failed")
                self.assertEqual(failed["acked"], 0)
                self.assertEqual(len(receiver.list_records()), 1)
                retried = tailer.poll()
                self.assertEqual(retried["status"], "advanced")
                self.assertEqual(retried["duplicates"], 1)
                self.assertEqual(len(receiver.list_records()), 1)

    def test_invalid_frame_stops_without_skipping_and_identity_is_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-invalid-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            good = make_wire(sequence="1", payload=b"good")
            wrong_stream = make_wire(
                sequence="2", payload=b"wrong", installation=OTHER_INSTALLATION,
                world_generation=OTHER_WORLD,
            )
            log.write_bytes(HEADER + wrong_stream + good)
            with components(log, root) as (tailer, receiver, *_):
                stopped = tailer.poll()
                self.assertEqual(stopped["status"], "stopped_binding_mismatch")
                self.assertEqual(stopped["acked"], 0)
                self.assertEqual(receiver.list_records(), [])

    def test_malformed_frame_and_payload_conflict_stop_at_same_offset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-stop-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            malformed = b"not-json\n"
            log.write_bytes(HEADER + malformed)
            with components(log, root / "malformed") as (tailer, receiver, *_):
                stopped = tailer.poll()
                self.assertEqual(stopped["status"], "stopped_invalid_frame")
                self.assertEqual(stopped["offset"], len(HEADER))
                self.assertEqual(receiver.list_records(), [])

            first = make_wire(sequence="1", payload=b"first")
            conflict = make_wire(sequence="1", payload=b"second")
            log.write_bytes(HEADER + first + conflict)
            with components(log, root / "conflict") as (tailer, receiver, *_):
                stopped = tailer.poll()
                self.assertEqual(stopped["status"], "stopped_receiver_rejection")
                self.assertEqual(stopped["acked"], 1)
                self.assertEqual(len(receiver.list_records()), 1)
                conflict_offset = len(HEADER) + len(first)
                self.assertEqual(stopped["offset"], conflict_offset)
                again = tailer.poll()
                self.assertEqual(again["status"], "stopped_receiver_rejection")
                self.assertEqual(again["offset"], conflict_offset)
                self.assertEqual(len(receiver.list_records()), 1)

    def test_oversize_frame_is_bounded_and_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-oversize-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            # No LF occurs within the maximum wire budget; the one-byte peek
            # proves the frame is overlong without allocating it unboundedly.
            log.write_bytes(HEADER + b"x" * (MAX_WIRE_BYTES + 1) + b"\n")
            with components(log, root) as (tailer, receiver, *_):
                stopped = tailer.poll()
                self.assertEqual(stopped["status"], "stopped_oversize")
                self.assertEqual(stopped["offset"], len(HEADER))
                self.assertEqual(receiver.list_records(), [])

    def test_truncate_replacement_and_header_change_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-binding-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            frame = make_wire(payload=b"one")
            log.write_bytes(HEADER)
            with components(log, root / "truncate") as (tailer, receiver, *_):
                self.assertEqual(tailer.poll()["status"], "idle")
                with log.open("ab") as stream:
                    stream.write(frame)
                self.assertEqual(tailer.poll()["status"], "advanced")
                with log.open("r+b") as stream:
                    stream.truncate(len(HEADER))
                truncated = tailer.poll()
                self.assertEqual(truncated["status"], "rejected_truncation")
                self.assertEqual(len(receiver.list_records()), 1)

            log.write_bytes(HEADER)
            with components(log, root / "header") as (tailer, receiver, *_):
                self.assertEqual(tailer.poll()["status"], "idle")
                changed_header = HEADER.replace(WORLD.encode(), OTHER_WORLD.encode())
                log.write_bytes(changed_header)
                changed = tailer.poll()
                self.assertEqual(changed["status"], "rejected_binding")
                self.assertIn("header_changed", changed["reason"])

            log.write_bytes(HEADER)
            with components(log, root / "replacement") as (tailer, receiver, *_):
                self.assertEqual(tailer.poll()["status"], "idle")
                replacement = root / "replacement.log"
                replacement.write_bytes(HEADER + frame)
                os.replace(replacement, log)
                replaced = tailer.poll()
                self.assertEqual(replaced["status"], "rejected_binding")
                self.assertIn("file_identity_changed", replaced["reason"])

    def test_two_readers_use_cursor_compare_and_swap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-log-cas-") as directory:
            root = Path(directory)
            log = root / "checked.log"
            frame = make_wire(payload=b"same")
            log.write_bytes(HEADER)
            seed_receiver = BattleTransportStore(root / "records.sqlite3")
            seed = BattleLogTailer(log, root / "cursor.sqlite3", receiver=seed_receiver)
            try:
                self.assertEqual(seed.poll()["status"], "idle")
            finally:
                seed.close()
                seed_receiver.close()
            with log.open("ab") as stream:
                stream.write(frame)

            receiver1 = BattleTransportStore(root / "records.sqlite3")
            receiver2 = BattleTransportStore(root / "records.sqlite3")
            first = BattleLogTailer(log, root / "cursor.sqlite3", receiver=receiver1)
            second = BattleLogTailer(log, root / "cursor.sqlite3", receiver=receiver2)
            barrier = threading.Barrier(2)
            original_first = first._checkpoint
            original_second = second._checkpoint

            def checkpoint_first(*args, **kwargs):
                barrier.wait(timeout=5)
                return original_first(*args, **kwargs)

            def checkpoint_second(*args, **kwargs):
                barrier.wait(timeout=5)
                return original_second(*args, **kwargs)

            try:
                with mock.patch.object(first, "_checkpoint", checkpoint_first), \
                        mock.patch.object(second, "_checkpoint", checkpoint_second):
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        results = list(executor.map(lambda t: t.poll(), (first, second)))
                statuses = {result["status"] for result in results}
                self.assertIn("cursor_conflict", statuses)
                self.assertTrue(statuses.intersection({"advanced", "budget_exhausted"}))
                self.assertEqual(len(receiver1.list_records(limit=10)), 1)
                self.assertEqual(first.poll()["status"], "idle")
                self.assertEqual(second.poll()["status"], "idle")
            finally:
                first.close()
                second.close()
                receiver1.close()
                receiver2.close()


class NativeCheckedLogTests(unittest.TestCase):
    def test_native_compatible_lock_blocks_poll_and_shared_tail(self) -> None:
        """A writer's exclusive range lock is a no-progress boundary.

        The checked log is produced by the native Windows sink.  Holding an
        external exclusive lock must make the Python tailer report busy without
        creating or advancing its cursor.  Conversely, the tailer's shared
        lease must reject an append-style exclusive lock, so a writer cannot
        expose a line before its flush/rollback boundary has settled.
        """

        if not NATIVE_LOG.exists():
            self.fail(f"required native checked log is missing: {NATIVE_LOG}")
        with tempfile.TemporaryDirectory(prefix="information-battle-native-lock-") as directory:
            root = Path(directory)
            receiver = BattleTransportStore(root / "records.sqlite3")
            tailer = BattleLogTailer(
                NATIVE_LOG,
                root / "cursor.sqlite3",
                receiver=receiver,
            )
            try:
                with NATIVE_LOG.open("rb") as writer_handle:
                    writer_lease = acquire_file_lock(writer_handle, exclusive=True)
                    try:
                        blocked = tailer.poll()
                        self.assertEqual(blocked["status"], "busy_no_progress")
                        self.assertEqual(blocked["acked"], 0)
                        self.assertIsNone(tailer.cursor())
                        self.assertEqual(tailer.status()["status"], "busy_no_progress")
                    finally:
                        writer_lease.release()

                resumed = tailer.poll()
                self.assertEqual(resumed["status"], "advanced")
                self.assertEqual(resumed["acked"], 3)
                self.assertEqual(tailer.cursor()["offset"], NATIVE_LOG.stat().st_size)

                with NATIVE_LOG.open("rb") as writer_handle:
                    writer_lease = acquire_file_lock(writer_handle, exclusive=True)
                    try:
                        blocked_after_cursor = tailer.poll()
                        self.assertEqual(
                            blocked_after_cursor["status"], "busy_no_progress"
                        )
                        self.assertEqual(
                            blocked_after_cursor["offset"],
                            NATIVE_LOG.stat().st_size,
                        )
                        self.assertEqual(
                            tailer.cursor()["offset"], NATIVE_LOG.stat().st_size
                        )
                        self.assertEqual(
                            tailer.status()["status"], "busy_no_progress"
                        )
                    finally:
                        writer_lease.release()

                stream, lease, _snapshot, _header = tailer._open_checked_file()
                try:
                    with NATIVE_LOG.open("ab") as append_handle:
                        with self.assertRaises(FileLockBusy):
                            acquire_file_lock(append_handle, exclusive=True)
                finally:
                    lease.release()
                    stream.close()
            finally:
                tailer.close()
                receiver.close()

    def test_actual_native_checked_log_header_and_frames(self) -> None:
        if not NATIVE_LOG.exists():
            self.fail(f"required native checked log is missing: {NATIVE_LOG}")
        if NATIVE_LOG.stat().st_size > 4 * 1024 * 1024:
            self.fail("native checked log exceeds bounded offline test size")
        with tempfile.TemporaryDirectory(prefix="information-battle-native-log-") as directory:
            root = Path(directory)
            receiver = BattleTransportStore(root / "records.sqlite3")
            tailer = BattleLogTailer(
                NATIVE_LOG,
                root / "cursor.sqlite3",
                receiver=receiver,
            )
            try:
                result = tailer.poll()
                self.assertEqual(result["status"], "advanced")
                self.assertEqual(result["acked"], 3)
                records = receiver.list_records(limit=10)
                self.assertEqual(len(records), 2)
                cursor_offset = tailer.cursor()["offset"]
                self.assertEqual(cursor_offset, NATIVE_LOG.stat().st_size)
                self.assertEqual(tailer.poll()["status"], "idle")
                tailer.close()
                receiver.close()

                reopened_receiver = BattleTransportStore(root / "records.sqlite3")
                reopened = BattleLogTailer(
                    NATIVE_LOG,
                    root / "cursor.sqlite3",
                    receiver=reopened_receiver,
                )
                try:
                    self.assertEqual(reopened.poll()["status"], "idle")
                    self.assertEqual(len(reopened_receiver.list_records(limit=10)), 2)
                finally:
                    reopened.close()
                    reopened_receiver.close()
            finally:
                tailer.close()
                receiver.close()


if __name__ == "__main__":
    unittest.main()
