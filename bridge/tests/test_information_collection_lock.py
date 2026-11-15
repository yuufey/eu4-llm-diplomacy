import multiprocessing
import os
import threading
import uuid

import pytest

from bridge.information.collection_lock import CollectionLock


def _child_hold_lock_until_exit(database_path, generation, connection):
    guard = CollectionLock(database_path)
    acquisition = guard.acquire()
    acquired = acquisition.__enter__()
    connection.send((generation, acquired, os.getpid()))
    if not acquired or connection.recv() != ("exit", generation):
        os._exit(2)
    # Deliberately bypass Python cleanup: the OS must release the file lock.
    os._exit(0)


def test_same_thread_reenters_and_releases_after_exception(tmp_path):
    guard = CollectionLock(tmp_path / "state.sqlite")

    with pytest.raises(RuntimeError, match="collection failed"):
        with guard.acquire() as acquired:
            assert acquired is True
            with guard.acquire(blocking=False) as nested:
                assert nested is True
            raise RuntimeError("collection failed")

    with guard.acquire(blocking=False) as acquired_after_exception:
        assert acquired_after_exception is True


def test_nonblocking_acquire_reports_busy_for_another_thread(tmp_path):
    guard = CollectionLock(tmp_path / "state.sqlite")
    holder_entered = threading.Event()
    release_holder = threading.Event()
    nonblocking_finished = threading.Event()
    nonblocking_results = []

    def hold_lock():
        with guard.acquire() as acquired:
            assert acquired is True
            holder_entered.set()
            release_holder.wait(3)

    def try_nonblocking():
        with guard.acquire(blocking=False) as acquired:
            nonblocking_results.append(acquired)
        nonblocking_finished.set()

    holder = threading.Thread(target=hold_lock)
    contender = threading.Thread(target=try_nonblocking)
    holder.start()
    try:
        assert holder_entered.wait(3)
        contender.start()
        assert nonblocking_finished.wait(3)
        assert nonblocking_results == [False]
    finally:
        release_holder.set()
        holder.join(3)
        if contender.ident is not None:
            contender.join(3)
    assert not holder.is_alive()
    assert not contender.is_alive()


def test_blocking_acquire_waits_for_another_thread(tmp_path):
    guard = CollectionLock(tmp_path / "state.sqlite")
    holder_entered = threading.Event()
    release_holder = threading.Event()
    waiter_started = threading.Event()
    waiter_entered = threading.Event()
    waiter_results = []

    def hold_lock():
        with guard.acquire() as acquired:
            assert acquired is True
            holder_entered.set()
            release_holder.wait(3)

    def wait_for_lock():
        waiter_started.set()
        with guard.acquire(blocking=True) as acquired:
            waiter_results.append(acquired)
            waiter_entered.set()

    holder = threading.Thread(target=hold_lock)
    waiter = threading.Thread(target=wait_for_lock)
    holder.start()
    try:
        assert holder_entered.wait(3)
        waiter.start()
        assert waiter_started.wait(3)
        assert not waiter_entered.wait(0.05)
    finally:
        release_holder.set()
        holder.join(3)
        if waiter.ident is not None:
            waiter.join(3)
    assert waiter_entered.is_set()
    assert waiter_results == [True]
    assert not holder.is_alive()
    assert not waiter.is_alive()


def test_separate_instances_for_same_database_are_mutually_exclusive(tmp_path):
    database = tmp_path / "state.sqlite"
    first = CollectionLock(database)
    second = CollectionLock(database)

    with first.acquire() as acquired:
        assert acquired is True
        with second.acquire(blocking=False) as competing:
            assert competing is False


def test_different_databases_do_not_block_each_other(tmp_path):
    first = CollectionLock(tmp_path / "first.sqlite")
    second = CollectionLock(tmp_path / "second.sqlite")

    with first.acquire() as first_acquired:
        assert first_acquired is True
        with second.acquire(blocking=False) as second_acquired:
            assert second_acquired is True


def test_child_process_exit_releases_its_lock(tmp_path):
    database = tmp_path / "state.sqlite"
    generation = uuid.uuid4().hex
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=True)
    child = context.Process(
        target=_child_hold_lock_until_exit,
        args=(str(database), generation, child_connection),
    )
    child.start()
    child_connection.close()

    try:
        assert parent_connection.poll(10), "child did not report its lock generation"
        child_generation, child_acquired, child_pid = parent_connection.recv()
        assert child_generation == generation
        assert child_acquired is True
        assert child_pid != os.getpid()

        parent_guard = CollectionLock(database)
        with parent_guard.acquire(blocking=False) as while_child_holds:
            assert while_child_holds is False

        parent_connection.send(("exit", generation))
        child.join(5)
        assert not child.is_alive()
        assert child.exitcode == 0

        with parent_guard.acquire(blocking=False) as after_child_exit:
            assert after_child_exit is True
    finally:
        if child.is_alive():
            child.terminate()
            child.join(5)
        parent_connection.close()
        child_connection.close()
