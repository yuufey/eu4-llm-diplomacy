"""Bounded request-body cleanup for rejected HTTP requests.

The handlers in this repository use HTTP/1.0 and close rejected connections.
On Windows, closing a socket while a small request body is still unread can
reset the connection before the client receives the refusal.  This helper only
drains a narrowly valid, bounded Content-Length body; it never parses or
dispatches the body.
"""
from __future__ import annotations

import time


MAX_REJECTION_BODY = 64 * 1024
READ_CHUNK = 8192
REJECTION_DEADLINE_SECONDS = 0.2


def discard_rejected_body(handler) -> None:
    """Best-effort drain of one small request body before a refusal is sent.

    Only a single ASCII decimal Content-Length no larger than 64 KiB is
    eligible.  Transfer-Encoding and Expect are opaque framing signals here,
    including empty or repeated headers, so they are deliberately left unread.
    All errors are contained: the caller must still be able to send its
    original refusal.  The socket timeout is restored even after a read error
    or an expired 0.2 second absolute deadline.
    """
    try:
        headers = handler.headers
        if headers.get_all("Transfer-Encoding", []) or headers.get_all("Expect", []):
            return
        lengths = headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            return
        raw_length = lengths[0]
        # Check the bounded textual length before isdigit/int so an attacker
        # cannot force an unbounded conversion or a long digit scan.
        if not isinstance(raw_length, str) or len(raw_length) > 5:
            return
        if not raw_length.isascii() or not raw_length.isdigit():
            return
        length = int(raw_length)
        if length > MAX_REJECTION_BODY:
            return
        connection = handler.connection
        previous_timeout = connection.gettimeout()
        remaining = length
        deadline = time.monotonic() + REJECTION_DEADLINE_SECONDS
        try:
            while remaining:
                budget = deadline - time.monotonic()
                if budget <= 0:
                    break
                connection.settimeout(budget)
                chunk = handler.rfile.read1(min(READ_CHUNK, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except (OSError, TimeoutError):
            pass
        finally:
            try:
                connection.settimeout(previous_timeout)
            except (OSError, TimeoutError):
                pass
    except (AttributeError, OSError, TypeError, ValueError):
        # Rejection handling must never replace the original refusal with a
        # transport-cleanup exception.
        return


__all__ = [
    "MAX_REJECTION_BODY",
    "READ_CHUNK",
    "REJECTION_DEADLINE_SECONDS",
    "discard_rejected_body",
]
