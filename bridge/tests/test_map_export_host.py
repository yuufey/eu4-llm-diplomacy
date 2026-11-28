from pathlib import Path
from threading import Event
from types import SimpleNamespace

from bridge.information.collection_lock import CollectionLock
from bridge.map_export_host import attach_map_exports


def test_host_publishes_while_client_is_idle(tmp_path, monkeypatch):
    # One day is 24 EU4 hours; a one-month interval from February 3 is 28 days.
    from bridge import map_archive

    clock = [56896992]
    received = []
    updated = Event()

    def publish(maps, directory, **view):
        received.append((maps.observer, Path(directory)))
        if len(received) == 2:
            updated.set()
        return {"date": "1495.2.3" if len(received) == 1 else "1495.3.3"}

    monkeypatch.setattr(map_archive, "publish_map_bundle", publish)
    session = SimpleNamespace(session_id="session", information_health=lambda: {
        "status": "ready", "date_raw": clock[0]})
    maps = SimpleNamespace(session_id=session.session_id, observer="BRG")
    directory = tmp_path / "destination"
    args = SimpleNamespace(database=tmp_path/"db", owner="llm", map_export_directory=directory,
                           map_export_months=1)
    service = SimpleNamespace(collection_lock=CollectionLock(args.database), _closed=False)
    attach_map_exports(service, maps, session, args)
    try:
        assert len(received) == 1
        clock[0] += 28 * 24
        assert updated.wait(10)
        with service.collection_lock.acquire():
            state = service.map_schedule.manage("status")
            assert state["next_due_date"] == "1495.4.3"
        assert received == [("BRG", directory)] * 2
    finally:
        service.map_export_worker.close()
    assert not service.map_export_worker.thread.is_alive()
