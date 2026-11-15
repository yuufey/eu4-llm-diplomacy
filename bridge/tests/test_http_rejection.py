"""Unit tests for bounded cleanup of rejected HTTP request bodies."""
from __future__ import annotations

from email.message import Message
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bridge import http_rejection


class _Connection:
    def __init__(self, timeout=7.0):
        self.timeout = timeout
        self.set_calls = []

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.set_calls.append(value)
        self.timeout = value


class _Reader:
    def __init__(self, raw: bytes, *, chunk_size: int = 3, error: Exception | None = None):
        self.raw = bytearray(raw)
        self.chunk_size = chunk_size
        self.error = error
        self.calls = []

    def read1(self, size: int) -> bytes:
        self.calls.append(size)
        if self.error is not None:
            error, self.error = self.error, None
            raise error
        count = min(size, self.chunk_size, len(self.raw))
        value = bytes(self.raw[:count])
        del self.raw[:count]
        return value


def _headers(*pairs: tuple[str, str]) -> Message:
    value = Message()
    for name, item in pairs:
        value[name] = item
    return value


def _handler(headers: Message, raw: bytes, *, chunk_size: int = 3,
             error: Exception | None = None):
    connection = _Connection()
    reader = _Reader(raw, chunk_size=chunk_size, error=error)
    return SimpleNamespace(
        headers=headers,
        connection=connection,
        rfile=reader,
    ), connection, reader


class RejectedBodyTests(unittest.TestCase):
    def test_valid_opaque_fragmented_body_is_drained_in_bounded_chunks(self):
        raw = b"not-json"
        handler, connection, reader = _handler(
            _headers(("Content-Length", str(len(raw)))), raw, chunk_size=3,
        )
        # One absolute deadline is established, followed by one timestamp per
        # read attempt. The opaque bytes are never passed to a JSON decoder.
        with patch.object(http_rejection.time, "monotonic",
                          side_effect=[100.0, 100.05, 100.10, 100.15]):
            http_rejection.discard_rejected_body(handler)
        self.assertEqual(bytes(reader.raw), b"")
        self.assertEqual(reader.calls, [8, 5, 2])
        self.assertTrue(all(size <= http_rejection.READ_CHUNK for size in reader.calls))
        self.assertEqual(connection.timeout, 7.0)
        self.assertEqual(connection.set_calls[-1], 7.0)

    def test_deadline_is_absolute_and_timeout_is_restored_after_read_error(self):
        handler, connection, reader = _handler(
            _headers(("Content-Length", "4")), b"abcd", error=TimeoutError("slow"),
        )
        with patch.object(http_rejection.time, "monotonic",
                          side_effect=[10.0, 10.19, 10.25]):
            http_rejection.discard_rejected_body(handler)
        self.assertEqual(reader.calls, [4])
        self.assertEqual(connection.timeout, 7.0)
        self.assertEqual(connection.set_calls[-1], 7.0)

    def test_deadline_stops_after_successful_first_fragment_without_resetting(self):
        handler, connection, reader = _handler(
            _headers(("Content-Length", "4")), b"abcd", chunk_size=1,
        )
        with patch.object(http_rejection.time, "monotonic",
                          side_effect=[20.0, 20.05, 20.25]):
            http_rejection.discard_rejected_body(handler)
        self.assertEqual(reader.calls, [4])
        self.assertEqual(bytes(reader.raw), b"bcd")
        self.assertEqual(connection.timeout, 7.0)
        self.assertEqual(connection.set_calls[-1], 7.0)

    def test_opaque_framing_and_invalid_lengths_are_never_read(self):
        cases = [
            (),
            (("Content-Length", "1"), ("Content-Length", "1")),
            (("Content-Length", "abc"),),
            (("Content-Length", "000000"),),
            (("Content-Length", "65537"),),
            (("Content-Length", "1"), ("Transfer-Encoding", "")),
            (("Content-Length", "1"), ("Transfer-Encoding", "chunked")),
            (("Content-Length", "1"), ("Expect", "")),
            (("Content-Length", "1"), ("Expect", "100-continue")),
            (("Content-Length", "١"),),
        ]
        for pairs in cases:
            with self.subTest(pairs=pairs):
                handler, connection, reader = _handler(_headers(*pairs), b"x")
                http_rejection.discard_rejected_body(handler)
                self.assertEqual(reader.calls, [])
                self.assertEqual(connection.timeout, 7.0)

    def test_maximum_allowed_length_is_drained_without_exceeding_read_budget(self):
        raw = b"x" * http_rejection.MAX_REJECTION_BODY
        handler, connection, reader = _handler(
            _headers(("Content-Length", str(len(raw)))), raw, chunk_size=http_rejection.READ_CHUNK,
        )
        http_rejection.discard_rejected_body(handler)
        self.assertEqual(bytes(reader.raw), b"")
        self.assertTrue(reader.calls)
        self.assertTrue(all(0 < size <= http_rejection.READ_CHUNK for size in reader.calls))
        self.assertEqual(connection.timeout, 7.0)


if __name__ == "__main__":
    unittest.main()
