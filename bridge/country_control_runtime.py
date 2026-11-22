"""Bind the native interception scope from trusted host configuration."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
import uuid

from .information.collection_lock import CollectionLock


CAPABILITY = "native_country_control_configuration"
REQUEST_NAME = "controlled-countries.req"
ACK_EVENT = "native_controlled_countries_set"
OBSERVATION_CAPABILITY = "native_information_observer_configuration"
MAX_MANAGED_COUNTRIES = 32


def configure_native_control(session, countries, *, timeout: float = 10.0) -> dict:
    """Publish one session-bound complete country set and wait for its ACK.

    The caller supplies operator configuration, never model tool arguments.
    The native scope persists across short-lived Python clients. A new host
    must confirm its complete managed set before submitting diplomatic work.
    """
    return _configure_countries(session, countries, timeout, capability=CAPABILITY,
                                wire="EU4CONTROL1", request_name=REQUEST_NAME, ack_event=ACK_EVENT,
                                legacy_fra=True, error_prefix="COUNTRY_CONTROL")


def configure_native_observation(session, countries, *, timeout: float = 10.0) -> dict:
    """Assign countries for observation callbacks without changing execution policy."""
    return _configure_countries(session, countries, timeout, capability=OBSERVATION_CAPABILITY,
                                wire="EU4INFO1", request_name="information-observers.req",
                                ack_event="native_information_observers_set", legacy_fra=False,
                                error_prefix="INFORMATION_OBSERVER")


def _configure_countries(session, countries, timeout, *, capability, wire, request_name,
                         ack_event, legacy_fra, error_prefix):
    if not isinstance(countries, (list, tuple)) or any(
            not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None
            for country in countries):
        raise ValueError("INVALID_MANAGED_COUNTRIES")
    countries = sorted(set(countries))
    if len(countries) > MAX_MANAGED_COUNTRIES:
        raise ValueError("MANAGED_COUNTRIES_LIMIT_EXCEEDED")
    if not isinstance(timeout, (int, float)) or not 0 <= timeout <= 60:
        raise ValueError("INVALID_COUNTRY_CONTROL_TIMEOUT")
    if session.health().get("status") != "ready":
        raise RuntimeError(f"{error_prefix}_SESSION_UNREADY")
    if capability not in session.installation_capabilities():
        if legacy_fra and countries == ["FRA"]:
            return {"mode": "legacy", "countries": countries, "session_id": session.session_id}
        raise RuntimeError(f"NATIVE_{error_prefix}_CONFIGURATION_UNAVAILABLE")

    directory = Path(session.directory)
    request = directory / request_name
    log = directory / "control-probe.jsonl"
    with CollectionLock(request.with_suffix("")).acquire():
        revision = time.time_ns()
        try:
            with request.open("rb") as stream:
                previous = stream.read(4096).decode("ascii").strip().split("\t")
            if len(previous) == 4 and previous[:2] == [wire, session.session_id]:
                revision = max(revision, int(previous[2]) + 1)
        except (OSError, UnicodeError, ValueError):
            pass
        try:
            offset = log.stat().st_size
        except FileNotFoundError:
            offset = 0
        temporary = directory / (request_name + "." + uuid.uuid4().hex + ".pending")
        line = f"{wire}\t{session.session_id}\t{revision}\t{','.join(countries) or '-'}\n"
        try:
            with temporary.open("x", encoding="ascii", newline="\n") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            replace_deadline = time.monotonic() + min(1.0, timeout)
            while True:
                try:
                    os.replace(temporary, request)
                    break
                except PermissionError:
                    # A Windows reader may briefly hold the old filename.
                    # Replacing this configuration is idempotent.
                    if time.monotonic() >= replace_deadline:
                        raise
                    time.sleep(0.01)
        finally:
            temporary.unlink(missing_ok=True)

        deadline = time.monotonic() + timeout
        pending = b""
        while True:
            try:
                with log.open("rb") as stream:
                    if os.fstat(stream.fileno()).st_size < offset:
                        offset = 0
                        pending = b""
                    stream.seek(offset)
                    data = stream.read(65536)
                    offset = stream.tell()
            except (FileNotFoundError, PermissionError):
                data = b""
            lines = (pending + data).split(b"\n")
            pending = lines.pop()
            # Keep malformed native lines bounded while waiting for a result.
            if len(pending) > 65536:
                pending = b""
            for raw in lines:
                try:
                    event = json.loads(raw)
                except (ValueError, UnicodeError):
                    continue
                if (not isinstance(event, dict) or event.get("event") != ack_event
                        or event.get("session_id") != session.session_id
                        or event.get("revision") != revision):
                    continue
                if event.get("accepted") is not True or event.get("countries") != countries:
                    reason = event.get("reason")
                    known_reasons = ("country_unavailable", "session_mismatch", "stale_revision")
                    suffix = f": {reason}" if reason in known_reasons else ""
                    raise RuntimeError(f"NATIVE_{error_prefix}_CONFIGURATION_REJECTED" + suffix)
                return {"mode": "configured", "session_id": session.session_id,
                        "revision": revision, "countries": countries}
            if time.monotonic() >= deadline:
                raise RuntimeError(f"NATIVE_{error_prefix}_CONFIGURATION_TIMEOUT")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
