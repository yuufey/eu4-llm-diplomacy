"""Narrow lifecycle tests for the information battle capture lease."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from bridge.information.battle_capture import BattleCaptureManager


GAME_SHA = "a" * 64
DLL_SHA = "b" * 64
PLAYER_REF = "1234567890abcdef"
INSTALLATION = 7
PID = 43210
CREATION = 99887766


def _hex16(value: int) -> str:
    return f"{value:016x}"


class FakeController:
    def __init__(self, *, state: str = "disabled") -> None:
        self.state = state
        self.calls: list[tuple[str, str | None]] = []
        self._nonce = 0
        self.fail_enable = False
        self.fail_disable = False
        self.observed_at_ns = time.time_ns()
        self.stale_statuses = 0
        self.stale_state: str | None = None

    def _status(self) -> dict[str, object]:
        if self.stale_statuses:
            self.stale_statuses -= 1
            reported_state = self.stale_state or self.state
        else:
            # A normal status poll observes a later file heartbeat.  The
            # small future margin makes the fake deterministic relative to
            # the journal write which follows a transition response.
            self.observed_at_ns = max(
                self.observed_at_ns + 1_000_000,
                time.time_ns() + 1_000_000,
            )
            reported_state = self.state
        native: dict[str, object] = {
            "state": reported_state,
            "pid": PID,
            "creation_filetime": str(CREATION),
            "installation": str(INSTALLATION if reported_state in {"enabled", "disabled"} else 0),
            "generation": str(CREATION if reported_state in {"enabled", "disabled"} else 0),
            "exe_sha256": GAME_SHA,
            "dll_sha256": DLL_SHA,
        }
        result: dict[str, object] = {
            "status": "observed",
            "observed_at_ns": self.observed_at_ns,
            "native": native,
        }
        if reported_state in {"enabled", "disabled"}:
            result["binding"] = {
                "installation": INSTALLATION,
                "generation": CREATION,
                "pid": PID,
                "creation_filetime": CREATION,
                "game_sha256": GAME_SHA,
                "dll_sha256": DLL_SHA,
                "player_ref": PLAYER_REF,
            }
        return result

    def __call__(self, command: str, player_ref: str | None = None) -> dict[str, object]:
        self.calls.append((command, player_ref))
        if command == "status":
            return self._status()
        self._nonce += 1
        nonce = f"nonce-{self._nonce}"
        if command == "enable":
            if self.fail_enable:
                raise RuntimeError("simulated enable timeout")
            self.state = "enabled"
            state = "enabled"
        elif command == "disable":
            if self.fail_disable:
                raise RuntimeError("simulated disable timeout")
            self.state = "disabled"
            state = "disabled"
        else:
            raise AssertionError(command)
        return {
            "status": "accepted",
            "nonce": nonce,
            "response": {
                "accepted": True,
                "state": state,
                "request_id": nonce,
                "pid": PID,
                "creation_filetime": CREATION,
                "installation": INSTALLATION,
                "generation": CREATION,
                "exe_sha256": GAME_SHA,
                "dll_sha256": DLL_SHA,
            },
        }


class CaptureFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.managers: list[BattleCaptureManager] = []
        self.installation_path = self.root / "installation.json"
        self.installation = {
            "pid": PID,
            "creation_filetime": CREATION,
            "game_sha256": GAME_SHA,
            "dll_sha256": DLL_SHA,
        }
        self.installation_path.write_text(json.dumps(self.installation), encoding="utf-8")
        self.expected_binding = {
            "installation": _hex16(INSTALLATION),
            "generation": _hex16(CREATION),
            "game_sha256": GAME_SHA,
            # Deliberately different from PLAYER_REF: the manager must use
            # status.binding.player_ref instead of an observer guess.
            "observer_ref": "FRA",
        }

    def manager(self, controller: FakeController, **kwargs: object) -> BattleCaptureManager:
        manager = BattleCaptureManager(
            self.installation_path,
            self.expected_binding,
            controller=controller,
            journal_path=self.root / "capture-journal.json",
            **kwargs,
        )
        self.managers.append(manager)
        return manager

    def close(self) -> None:
        for manager in reversed(self.managers):
            manager.close()
        self.temp.cleanup()


class InformationBattleCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CaptureFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_shared_leases_enable_once_and_disable_after_last_release(self) -> None:
        controller = FakeController()
        manager = self.fx.manager(controller)

        first = manager.reconcile({"sub-a", "sub-b"})
        self.assertEqual(first["producer_state"], "enabled")
        self.assertTrue(first["owned"])
        self.assertEqual([call[0] for call in controller.calls], ["status", "enable"])
        self.assertEqual(controller.calls[1][1], PLAYER_REF)

        second = manager.reconcile({"sub-b"})
        self.assertEqual(second["consumer_count"], 1)
        self.assertEqual([call[0] for call in controller.calls], ["status", "enable", "status"])

        third = manager.reconcile(set())
        self.assertEqual(third["producer_state"], "disabled")
        self.assertTrue(third["managed"])
        self.assertFalse(third["owned"])
        self.assertEqual([call[0] for call in controller.calls], ["status", "enable", "status", "status", "disable"])
        self.assertEqual(controller.calls[-1][1], PLAYER_REF)
        closed = manager.close()
        self.assertTrue(closed["managed"])
        self.assertEqual(closed["producer_state"], "disabled")

    def test_external_enabled_source_is_borrowed_and_never_disabled(self) -> None:
        controller = FakeController(state="enabled")
        manager = self.fx.manager(controller)

        active = manager.reconcile({"sub-a"})
        self.assertFalse(active["owned"])
        self.assertTrue(active["managed"])
        self.assertEqual(active["reason"], "external_source")
        manager.reconcile(set())
        self.assertTrue(manager.snapshot()["managed"])
        self.assertEqual([call[0] for call in controller.calls], ["status"])

    def test_borrowed_source_does_not_reenable_after_disabled_mutation(self) -> None:
        controller = FakeController(state="enabled")
        manager = self.fx.manager(controller)
        manager.reconcile({"sub-a"})
        controller.state = "disabled"
        result = manager.reconcile({"sub-a"})
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["producer_state"], "unavailable")
        self.assertEqual([call[0] for call in controller.calls].count("enable"), 0)
        manager.close()

    def test_repeated_reconcile_does_not_repeat_enable(self) -> None:
        controller = FakeController()
        manager = self.fx.manager(controller)
        manager.reconcile({"sub-a"})
        manager.reconcile({"sub-a"})
        manager.reconcile({"sub-a"})
        self.assertEqual([call[0] for call in controller.calls].count("enable"), 1)

    def test_completed_owned_journal_recovers_without_enable(self) -> None:
        controller = FakeController()
        first = self.fx.manager(controller)
        first.reconcile({"sub-a"})
        # Simulate a crashed host after the completed enable record.  The
        # native source remains enabled and the file lock is the only host
        # resource which needs to be released for recovery in this test.
        first._release_lock()  # noqa: SLF001 - deliberate crash simulation

        second = self.fx.manager(controller)
        recovered = second.reconcile({"sub-b"})
        self.assertTrue(recovered["owned"])
        self.assertEqual(recovered["reason"], "owned_source_recovered")
        self.assertEqual([call[0] for call in controller.calls].count("enable"), 1)
        second.close()

    def test_stale_heartbeat_after_owned_disable_waits_then_reenables_owned(self) -> None:
        controller = FakeController()
        first = self.fx.manager(controller)
        first.reconcile({"sub-a"})
        first.reconcile(set())
        self.assertEqual(controller.state, "disabled")
        self.assertEqual([call[0] for call in controller.calls].count("disable"), 1)

        # The old heartbeat still says enabled after the completed disable.
        # A fresh status poll then exposes the actual disabled state, allowing
        # exactly one new enable and a new owned lease.
        controller.stale_state = "enabled"
        controller.stale_statuses = 1
        controller.observed_at_ns = json.loads(
            first.journal_path.read_text(encoding="utf-8")
        )["updated_at_ns"]
        resumed = self.fx.manager(controller)
        result = resumed.reconcile({"sub-b"})
        self.assertTrue(result["owned"])
        self.assertEqual(result["producer_state"], "enabled")
        self.assertEqual([call[0] for call in controller.calls].count("enable"), 2)
        resumed.reconcile(set())
        self.assertEqual([call[0] for call in controller.calls].count("disable"), 2)
        self.assertEqual(controller.state, "disabled")

    def test_stale_heartbeat_timeout_latches_without_control_dispatch(self) -> None:
        controller = FakeController()
        manager = self.fx.manager(controller)
        try:
            manager.reconcile({"sub-a"})
            before = len(controller.calls)
            controller.stale_state = "enabled"
            controller.stale_statuses = 1000
            # A stale heartbeat must be no later than the completed journal.
            # The fake's normal +1ms margin can otherwise remain in the future
            # when a fast filesystem finishes the journal write before it.
            controller.observed_at_ns = json.loads(
                manager.journal_path.read_text(encoding="utf-8")
            )["updated_at_ns"]
            with patch("bridge.information.battle_capture._STATUS_FRESH_WAIT_SECONDS", 0.01), \
                    patch("bridge.information.battle_capture._STATUS_FRESH_WAIT_INTERVAL_SECONDS", 0.001):
                result = manager.reconcile({"sub-a"})
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["producer_state"], "unavailable")
            self.assertEqual([call[0] for call in controller.calls[before:]], ["status"] * (len(controller.calls) - before))
            self.assertEqual([call[0] for call in controller.calls].count("enable"), 1)
            self.assertEqual([call[0] for call in controller.calls].count("disable"), 0)
        finally:
            manager.close()

    def test_legacy_float_updated_at_journal_remains_recoverable(self) -> None:
        controller = FakeController()
        first = self.fx.manager(controller)
        first.reconcile({"sub-a"})
        journal = json.loads(first.journal_path.read_text(encoding="utf-8"))
        journal.pop("updated_at_ns", None)
        first.journal_path.write_text(json.dumps(journal), encoding="utf-8")
        first._release_lock()  # noqa: SLF001 - deliberate crash simulation

        recovered = self.fx.manager(controller)
        result = recovered.reconcile({"sub-b"})
        self.assertTrue(result["owned"])
        self.assertEqual([call[0] for call in controller.calls].count("enable"), 1)
        recovered.close()

    def test_pending_and_unknown_journals_never_replay_enable(self) -> None:
        for journal_state in ("pending-enable", "unknown-enable"):
            with self.subTest(journal_state=journal_state):
                controller = FakeController()
                manager = self.fx.manager(controller)
                manager.reconcile({"seed"})
                manager._write_journal(journal_state, owned=False)  # noqa: SLF001
                manager._release_lock()  # noqa: SLF001

                recovered = self.fx.manager(controller)
                result = recovered.reconcile({"sub-a"})
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual([call[0] for call in controller.calls].count("enable"), 1)
                recovered.close()

                manager.journal_path.unlink()

    def test_identity_change_foreign_lock_and_disabled_mutation_do_not_dispatch(self) -> None:
        # Installation identity changes are detected before an enable call.
        controller = FakeController()
        manager = self.fx.manager(controller)
        changed = dict(self.fx.installation)
        changed["pid"] = PID + 1
        self.fx.installation_path.write_text(json.dumps(changed), encoding="utf-8")
        result = manager.reconcile({"sub-a"})
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["producer_state"], "unavailable")
        self.assertNotIn("enable", [call[0] for call in controller.calls])
        manager.close()
        manager.journal_path.unlink(missing_ok=True)

        # A live manager owns the installation lock for another host.
        self.fx.installation_path.write_text(json.dumps(self.fx.installation), encoding="utf-8")
        owner_controller = FakeController()
        owner = self.fx.manager(owner_controller)
        owner.reconcile({"owner"})
        foreign_controller = FakeController()
        foreign = self.fx.manager(foreign_controller)
        blocked = foreign.reconcile({"sub-a"})
        self.assertEqual(blocked["reason"], "capture_lock_unavailable")
        self.assertEqual(foreign_controller.calls, [])
        owner.close()

        # Once an active source disappears, the manager latches unavailable
        # and never silently sends a second enable.
        mutating_controller = FakeController()
        mutating = self.fx.manager(mutating_controller)
        mutating.reconcile({"sub-a"})
        mutating_controller.state = "disabled"
        unavailable = mutating.reconcile({"sub-a"})
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertEqual([call[0] for call in mutating_controller.calls].count("enable"), 1)
        mutating.close()

    def test_unknown_controller_result_latches_and_uses_status_player_ref_only(self) -> None:
        controller = FakeController()
        controller.fail_enable = True
        manager = self.fx.manager(controller)
        result = manager.reconcile({"sub-a"})
        self.assertEqual(result["status"], "unavailable")
        manager.reconcile({"sub-a"})
        self.assertEqual([call[0] for call in controller.calls].count("enable"), 1)
        self.assertEqual(controller.calls[1][1], PLAYER_REF)

    def test_ready_unbound_source_is_not_blindly_enabled(self) -> None:
        controller = FakeController(state="ready")
        manager = self.fx.manager(controller)
        result = manager.reconcile({"sub-a"})
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual([call[0] for call in controller.calls], ["status"])

    def test_constructor_and_snapshot_do_not_call_controller(self) -> None:
        controller = FakeController()
        manager = self.fx.manager(controller)
        self.assertEqual(controller.calls, [])
        snapshot = manager.snapshot()
        self.assertEqual(controller.calls, [])
        self.assertEqual(snapshot["complete"], False)


if __name__ == "__main__":
    unittest.main()
