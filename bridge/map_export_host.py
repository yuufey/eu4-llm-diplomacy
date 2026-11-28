"""Attach calendar-based map exports to the lifetime of a unified live service."""
import hashlib
import logging
import threading
from pathlib import Path
from urllib.parse import quote

from bridge.information.truce_date_math import decode_date
from bridge.map_schedule import MapSchedule


class MapExportWorker:
    def __init__(self, service, schedule):
        self.service = service
        self.schedule = schedule
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="political-map-export", daemon=True)

    def _run(self):
        last_error = None
        while not self.stop.wait(2):
            try:
                if not self.schedule.state_path.exists():
                    continue
                with self.service.collection_lock.acquire(blocking=False) as acquired:
                    if acquired and not self.service._closed:
                        self.schedule.tick()
                last_error = None
            except Exception as exc:
                # A paused/unavailable game can remain in this state for many polls.
                if str(exc) != last_error:
                    logging.warning("Scheduled political map export: %s", exc)
                    last_error = str(exc)

    def close(self):
        self.stop.set()
        self.thread.join()


def attach_map_exports(service, maps, session, args):
    root_option = getattr(args, "map_export_root", None)
    directory = getattr(args, "map_export_directory", None)
    months = getattr(args, "map_export_months", None)
    if months is not None and (directory is None or not 1 <= months <= 120):
        raise ValueError("--map-export-months requires --map-export-directory and a value from 1 to 120")
    if maps is None:
        if directory is not None or root_option is not None:
            raise ValueError("Map exports require a live operator session with a configured observer")
        return
    database = Path(args.database).resolve()
    identity = (args.owner, maps.observer, session.session_id)
    suffix = hashlib.sha256("\0".join(identity).encode()).hexdigest()[:24]
    state = database.with_name(f"{database.name}.map-export-{suffix}.json")
    if directory is not None:
        directory = Path(directory).resolve()
    default = database.parent / "map-exports" / quote(args.owner, safe="") / maps.observer
    root = Path(root_option or directory or default).resolve()

    def clock():
        health = session.information_health()
        raw = health.get("date_raw", health.get("game_date"))
        if health.get("status") != "ready" or type(raw) is not int:
            raise RuntimeError("Live game date unavailable")
        year, month, day, _ = decode_date(raw)
        return f"{year}.{month}.{day}"

    schedule = MapSchedule(maps, state, clock, root)
    if directory is not None:
        with service.collection_lock.acquire():
            schedule.manage("configure", directory=str(directory), interval_months=months or 6)
    service.map_schedule = schedule
    worker = MapExportWorker(service, schedule)
    worker.thread.start()
    service.map_export_worker = worker
