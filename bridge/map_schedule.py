"""Persisted calendar-based publication of live political map bundles.

The scheduler is deliberately independent of a wall clock.  ``clock`` returns
the current EU4 calendar date, and publication is due after a configurable
number of game-calendar months.  One scheduler instance owns one map service
and one observer/session identity.  A failed publication leaves the last
successful date unchanged so the next tick retries it.
"""

from __future__ import annotations

from copy import deepcopy
import json
import hashlib
import os
from pathlib import Path
import re
from threading import RLock
from typing import Any, Callable, Mapping


SCHEMA = "eu4.map_schedule.v1"
DEFAULT_INTERVAL_MONTHS = 6
MAX_INTERVAL_MONTHS = 120
DATE_RE = re.compile(r"^(\d{1,6})\.(\d{1,2})\.(\d{1,2})$")


class MapScheduleError(ValueError):
    """Raised when a map schedule request or persisted state is invalid."""


def _parse_date(value: Any) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise MapScheduleError("MAP_SCHEDULE_DATE_INVALID")
    match = DATE_RE.fullmatch(value.strip())
    if match is None:
        raise MapScheduleError("MAP_SCHEDULE_DATE_INVALID")
    year, month, day = (int(item) for item in match.groups())
    if year < 0 or not 1 <= month <= 12 or not 1 <= day <= 31:
        raise MapScheduleError("MAP_SCHEDULE_DATE_INVALID")
    return year, month, day


def _month_index(value: str) -> int:
    year, month, _ = _parse_date(value)
    return year * 12 + month - 1


_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _add_months(value: str, months: int) -> str:
    year, month, day = _parse_date(value)
    target = _month_index(value) + months
    new_year, month_zero = divmod(target, 12)
    new_month = month_zero + 1
    new_day = min(day, _MONTH_DAYS[new_month - 1])
    return f"{new_year}.{new_month}.{new_day}"


def _date_reached(current: str, due: str) -> bool:
    return _parse_date(current) >= _parse_date(due)


def _canonical_date(value: Any) -> str:
    year, month, day = _parse_date(value)
    return f"{year}.{month}.{day}"


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def _service_identity(map_service: Any) -> dict[str, str]:
    observer = getattr(map_service, "observer", None)
    if not isinstance(observer, str) or not observer:
        raise MapScheduleError("MAP_SCHEDULE_OBSERVER_MISSING")

    session = getattr(map_service, "session_id", None)
    installation = getattr(map_service, "installation", None)
    if not isinstance(session, str) or not session:
        if installation is not None:
            try:
                document = json.loads(Path(installation).read_text(encoding="utf-8-sig"))
                session = document.get("session_id")
            except (OSError, ValueError, TypeError):
                session = None
    if not isinstance(session, str) or not session:
        session = str(getattr(map_service, "pid", "unknown"))
    return {"observer": observer, "session_id": session}


class MapSchedule:
    """A serial, persisted publisher for one live map service."""

    def __init__(self, map_service: Any, state_path: str | Path,
                 clock: Callable[[], str], export_root: str | Path):
        if not callable(clock):
            raise MapScheduleError("MAP_SCHEDULE_CLOCK_INVALID")
        self.map_service = map_service
        self.state_path = Path(state_path).expanduser().resolve()
        self.export_root = Path(export_root).expanduser().resolve()
        self.clock = clock
        self.identity = _service_identity(map_service)
        self._lock = RLock()
        self._state_mtime_ns: int | None = None
        self._state_digest: str | None = None
        self._state = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.state_path.is_file():
            self._state_mtime_ns = None
            self._state_digest = None
            return self._blank()
        try:
            stat = self.state_path.stat()
            raw = self.state_path.read_bytes()
            value = json.loads(raw.decode("utf-8-sig"))
        except (OSError, ValueError, TypeError):
            self._state_mtime_ns = None
            self._state_digest = None
            return self._blank()
        self._state_mtime_ns = stat.st_mtime_ns
        self._state_digest = hashlib.sha256(raw).hexdigest()
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            return self._blank()
        if value.get("identity") != self.identity:
            return self._blank()
        try:
            interval = int(value["interval_months"])
            if not 1 <= interval <= MAX_INTERVAL_MONTHS:
                raise ValueError
            if value.get("last_success_date") is not None:
                _canonical_date(value["last_success_date"])
            if value.get("directory") is not None:
                self._directory(value["directory"])
        except (KeyError, TypeError, ValueError, MapScheduleError):
            return self._blank()
        return value

    def _reload_if_changed(self) -> None:
        try:
            stat = self.state_path.stat()
            raw = self.state_path.read_bytes()
            mtime_ns = stat.st_mtime_ns
            digest = hashlib.sha256(raw).hexdigest()
        except OSError:
            mtime_ns = None
            digest = None
        if mtime_ns != self._state_mtime_ns or digest != self._state_digest:
            self._state = self._load()

    def _blank(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "identity": deepcopy(self.identity),
            "enabled": False,
            "interval_months": DEFAULT_INTERVAL_MONTHS,
            "directory": None,
            "view": {},
            "last_success_date": None,
            "last_attempt_date": None,
            "next_due_date": None,
            "last_result": None,
            "last_error": None,
        }

    def _directory(self, value: str | Path) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.export_root / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(self.export_root)
        except ValueError as exc:
            raise MapScheduleError("MAP_SCHEDULE_DIRECTORY_OUTSIDE_EXPORT_ROOT") from exc
        return candidate

    def _write(self) -> None:
        _atomic_json(self.state_path, self._state)
        try:
            self._state_mtime_ns = self.state_path.stat().st_mtime_ns
            self._state_digest = hashlib.sha256(self.state_path.read_bytes()).hexdigest()
        except OSError:
            self._state_mtime_ns = None
            self._state_digest = None

    def _date(self) -> str:
        return _canonical_date(self.clock())

    def _publish(self, date: str) -> dict[str, Any]:
        from bridge.map_archive import publish_map_bundle

        directory = self._directory(self._state["directory"])
        result = publish_map_bundle(self.map_service, directory, **self._state.get("view", {}))
        published_date = date
        if isinstance(result, Mapping):
            for key in ("date", "snapshot_date", "game_date"):
                candidate = result.get(key)
                if isinstance(candidate, str):
                    published_date = _canonical_date(candidate)
                    break
        self._state["last_success_date"] = published_date
        self._state["last_attempt_date"] = date
        self._state["next_due_date"] = _add_months(published_date, self._state["interval_months"])
        self._state["last_result"] = result if isinstance(result, dict) else {"value": result}
        self._state["last_error"] = None
        self._write()
        return self._state["last_result"]

    def _attempt(self, date: str, *, force: bool = False) -> dict[str, Any]:
        try:
            result = self._publish(date)
            return {"status": "published", "date": date, "result": deepcopy(result)}
        except Exception as exc:
            self._state["last_attempt_date"] = date
            self._state["last_error"] = {"type": type(exc).__name__, "message": str(exc)}
            self._write()
            return {"status": "error", "date": date, "retry": True,
                    "error": deepcopy(self._state["last_error"]), "forced": force}

    def status(self, *, read_clock: bool = True, current_date: str | None = None) -> dict[str, Any]:
        with self._lock:
            self._reload_if_changed()
            current = current_date
            if read_clock and current is None:
                try:
                    current = self._date()
                except (ValueError, OSError, RuntimeError):
                    pass
            result = deepcopy(self._state)
            result["current_date"] = current
            if result.get("enabled") and result.get("last_success_date") and current:
                due_date = result.get("next_due_date") or _add_months(
                    result["last_success_date"], result["interval_months"])
                result["due"] = _date_reached(current, due_date)
            else:
                result["due"] = False
            return result

    def manage(self, operation: str, directory: str | Path | None = None,
               interval_months: int | None = None, **view: Any) -> dict[str, Any]:
        with self._lock:
            self._reload_if_changed()
            if operation not in {"configure", "status", "refresh", "disable"}:
                raise MapScheduleError("MAP_SCHEDULE_OPERATION_INVALID")
            if operation != "configure" and (directory is not None or interval_months is not None or view):
                raise MapScheduleError("Only configure accepts export settings")
            if operation == "status":
                return self.status()
            if operation == "disable":
                self._state["enabled"] = False
                self._write()
                return self.status(read_clock=False)
            if operation == "refresh":
                if self._state["directory"] is None:
                    raise MapScheduleError("MAP_SCHEDULE_NOT_CONFIGURED")
                return self._attempt(self._date(), force=True)

            if directory is None and not self._state["directory"]:
                raise MapScheduleError("MAP_SCHEDULE_DIRECTORY_REQUIRED")
            if interval_months is not None and (
                    type(interval_months) is not int or not 1 <= interval_months <= MAX_INTERVAL_MONTHS):
                raise MapScheduleError("MAP_SCHEDULE_INTERVAL_INVALID")
            if sum(key in view for key in ("center_country", "xy", "province")) > 1:
                raise MapScheduleError("Choose only one map center")
            config = {
                "directory": str(self._directory(directory or self._state["directory"])),
                "interval_months": interval_months or self._state["interval_months"],
                "view": deepcopy(view or self._state.get("view", {})),
            }
            if (self._state["enabled"] and self._state["last_success_date"] and
                    all(self._state[k] == value for k, value in config.items())):
                return {**self.status(), "status": "already_configured"}
            self._state.update(config, enabled=True, last_success_date=None, next_due_date=None,
                               last_result=None, last_error=None)
            self._write()
            return self._attempt(self._date())

    def tick(self) -> dict[str, Any]:
        with self._lock:
            self._reload_if_changed()
            if not self._state.get("enabled"):
                return {"status": "disabled", "scheduled": False, "state": self.status(read_clock=False)}
            date = self._date()
            last = self._state.get("last_success_date")
            due_date = self._state.get("next_due_date")
            if last is not None and not isinstance(due_date, str):
                due_date = _add_months(last, self._state["interval_months"])
            due = last is None or _date_reached(date, due_date)
            if not due:
                return {"status": "waiting", "scheduled": False, "state": self.status(current_date=date)}
            result = self._attempt(date)
            result["scheduled"] = True
            result["state"] = self.status(current_date=date)
            return result


__all__ = ["DEFAULT_INTERVAL_MONTHS", "MapSchedule", "MapScheduleError"]
