"""Offline tests for the checkpoint reservation wrapper.

The suite uses temporary installation/save trees and patches every process,
control, preflight, and save boundary.  It never opens EU4, sends a request,
or calls the real autosave tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import run_information_battle_checkpoint as subject


EXPECTED_RAW_DATE = 56_554_248
EXPECTED_PLAYER_REF = "0x10000bd00524f50"
EXPECTED_SAVE_DATE = "1455.11.13"
MANIFEST_SHA = "manifest-sha"
DLL_SHA = "dll-sha"


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CheckpointWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="information-checkpoint-wrapper-")
        self.root = Path(self.temp.name)
        self.installation_dir = self.root / "installation"
        self.installation_dir.mkdir()
        self.installation = self.installation_dir / "installation.json"
        self.installation.write_text("{}", encoding="utf-8")
        self.user_root = self.root / "user-data"
        self.saves = self.user_root / "save games"
        self.saves.mkdir(parents=True)
        self.protected = self.saves / subject.R70_NAME
        self.protected.write_bytes(b"protected-r70-fixture")
        self.protected_sha = _sha(self.protected)
        self.patchers = [
            patch.object(subject, "user_data", return_value=self.user_root),
            patch.object(subject, "R70_SHA", self.protected_sha),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp.cleanup()

    def _output(self, name: str = "operation") -> Path:
        return self.root / name

    def _snapshot(self, *, date: int = EXPECTED_RAW_DATE,
                  player_ref: str = EXPECTED_PLAYER_REF,
                  paused: bool = True, speed: int = 0,
                  status: str = "passed_read_only_installed_preflight") -> dict:
        phase = {
            "game_date": {"raw": date},
            "physical_player": {"value": player_ref},
            "control": {"paused": {"value": paused}, "speed": {"value": speed}},
        }
        return {
            "status": status,
            "before": {**phase, "phase": "before"},
            "after": {**phase, "phase": "after"},
        }

    def _preflight(self, snapshot: dict | None = None):
        value = self._snapshot() if snapshot is None else snapshot

        def fake(installation: Path, output: Path, **kwargs: object) -> dict:
            output.write_text(json.dumps(value), encoding="utf-8")
            return json.loads(json.dumps(value))

        return fake

    def _status(self) -> dict:
        return {
            "status": "observed",
            "native": {
                "state": "disabled",
                "fragment_sink_pending": False,
                "fragment_queued": "0",
            },
        }

    def _base_kwargs(self, output: Path, name: str = "llm_diplomacy_checkpoint.eu4") -> dict:
        return {
            "installation": self.installation,
            "output": output,
            "name": name,
            "manifest_sha": MANIFEST_SHA,
            "dll_sha": DLL_SHA,
            "expected_raw_date": EXPECTED_RAW_DATE,
            "expected_player_ref": EXPECTED_PLAYER_REF,
            "expected_save_date": EXPECTED_SAVE_DATE,
        }

    def _successful_save(self, name: str, calls: list[dict[str, object]] | None = None):
        target = self.saves / name
        payload = b"synthetic-checkpoint-payload"

        def fake(*args: object, **kwargs: object) -> dict:
            if calls is not None:
                calls.append({"args": list(args), "kwargs": dict(kwargs)})
            target.write_bytes(payload)
            target_sha = _sha(target)
            signature = {
                "date_raw": EXPECTED_RAW_DATE,
                "player_slot": 189,
                "paused_flag": 1,
            }
            return {
                "status": "success",
                "restore": {"errors": []},
                "probe_before": {"signature": signature},
                "probe_after": {"signature": signature},
                "save": {"path": str(target), "sha256": target_sha},
            }

        return fake, target, payload

    def test_identity_date_player_and_pause_gates_reject_without_save(self) -> None:
        cases = {
            "not_ready": self._snapshot(status="failed"),
            "wrong_date": self._snapshot(date=EXPECTED_RAW_DATE + 24),
            "wrong_player": self._snapshot(player_ref="0x10000bd00524f51"),
            "not_paused": self._snapshot(paused=False),
        }
        for label, snapshot in cases.items():
            with self.subTest(label=label):
                output = self._output(label)
                with patch.object(subject, "run_preflight", side_effect=self._preflight(snapshot)), \
                     patch.object(subject, "run_experiment") as save:
                    with self.assertRaises(RuntimeError):
                        subject.run(**self._base_kwargs(output))
                save.assert_not_called()
                self.assertTrue((output / "failure-001.json").is_file())
                failure = json.loads((output / "failure-001.json").read_text(encoding="utf-8"))
                self.assertFalse(failure["attempt_started"])
                self.assertFalse(failure["retry_authorized"])

    def test_pending_request_rejects_without_save(self) -> None:
        (self.installation_dir / "game-control.request").write_bytes(b"TEST_ONLY autosave\n")
        (self.installation_dir / "game-control.intent").write_bytes(b"TEST_ONLY intent\n")
        with patch.object(subject, "run_preflight", side_effect=self._preflight()), \
             patch.object(subject, "run_control", return_value=self._status()), \
             patch.object(subject, "run_experiment") as save:
            with self.assertRaises(RuntimeError) as raised:
                subject.run(**self._base_kwargs(self._output()))
        self.assertEqual(str(raised.exception), "PENDING_REQUEST_NO_SAVE")
        save.assert_not_called()
        failure = json.loads((self._output() / "failure-001.json").read_text(encoding="utf-8"))
        self.assertFalse(failure["attempt_started"])
        self.assertIn("game-control.request", failure["audit"]["pending_files"])
        self.assertIn("game-control.intent", failure["audit"]["pending_files"])

    def test_existing_operation_directory_blocks_rerun(self) -> None:
        output = self._output()
        output.mkdir()
        (output / "attempt-started-001.json").write_text("prior", encoding="utf-8")
        with patch.object(subject, "run_experiment") as save:
            with self.assertRaises(FileExistsError):
                subject.run(**self._base_kwargs(output))
        save.assert_not_called()
        self.assertEqual((output / "attempt-started-001.json").read_text(encoding="utf-8"), "prior")

    def test_save_exception_is_started_only_and_never_retried(self) -> None:
        save_error = RuntimeError("save outcome ambiguous")
        with patch.object(subject, "run_preflight", side_effect=self._preflight()), \
             patch.object(subject, "run_control", return_value=self._status()), \
             patch.object(subject, "run_experiment", side_effect=save_error) as save:
            with self.assertRaises(RuntimeError) as raised:
                subject.run(**self._base_kwargs(self._output()))
        self.assertIs(raised.exception, save_error)
        save.assert_called_once()
        attempt = json.loads((self._output() / "attempt-started-001.json").read_text(encoding="utf-8"))
        failure = json.loads((self._output() / "failure-001.json").read_text(encoding="utf-8"))
        self.assertEqual(attempt["state"], "attempt_reserved_no_auto_retry")
        self.assertTrue(failure["attempt_started"])
        self.assertTrue(failure["native_outcome_may_be_unknown"])
        self.assertFalse(failure["retry_authorized"])

    def test_success_calls_save_once_and_keeps_protected_r70_and_snapshot(self) -> None:
        name = "llm_diplomacy_checkpoint.eu4"
        save_calls: list[dict[str, object]] = []
        fake_save, target, payload = self._successful_save(name, save_calls)
        output = self._output()
        with patch.object(subject, "run_preflight", side_effect=self._preflight()), \
             patch.object(subject, "run_control", return_value=self._status()), \
             patch.object(subject, "run_experiment", side_effect=fake_save) as save:
            outcome = subject.run(**self._base_kwargs(output, name=name))
        save.assert_called_once()
        self.assertEqual(len(save_calls), 1)
        self.assertEqual(save_calls[0]["kwargs"].get("expected_date"), EXPECTED_SAVE_DATE)
        self.assertEqual(outcome["status"], "saved_verified")
        self.assertFalse(outcome["retry_authorized"])
        self.assertEqual(outcome["save"]["sha256"], _sha(target))
        self.assertEqual((output / "checkpoint.eu4").read_bytes(), payload)
        self.assertEqual(_sha(self.protected), self.protected_sha)
        self.assertEqual(outcome["protected_r70_after"]["sha256"], self.protected_sha)
        self.assertFalse(outcome["pending_files_after"])
        self.assertTrue((output / "outcome-001.json").is_file())

    def test_postcheck_failure_does_not_retry_save(self) -> None:
        name = "llm_diplomacy_postcheck.eu4"
        fake_save, _target, _payload = self._successful_save(name)
        snapshots = [self._snapshot(), self._snapshot(status="failed")]

        def preflight_once(installation: Path, output: Path, **kwargs: object) -> dict:
            value = snapshots.pop(0)
            output.write_text(json.dumps(value), encoding="utf-8")
            return json.loads(json.dumps(value))

        output = self._output()
        with patch.object(subject, "run_preflight", side_effect=preflight_once), \
             patch.object(subject, "run_control", return_value=self._status()), \
             patch.object(subject, "run_experiment", side_effect=fake_save) as save:
            with self.assertRaises(RuntimeError) as raised:
                subject.run(**self._base_kwargs(output, name=name))
        self.assertEqual(str(raised.exception), "POST_SAVE_WORLD_OR_ARTIFACT_CHANGED")
        save.assert_called_once()
        failure = json.loads((output / "failure-001.json").read_text(encoding="utf-8"))
        self.assertTrue(failure["attempt_started"])
        self.assertFalse(failure["retry_authorized"])
        self.assertTrue((output / "checkpoint.eu4").is_file())


def _pin(path: Path) -> dict[str, object]:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": _sha(path)}


def run_stage_tests(output: Path | None = None) -> int:
    started = time.time()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CheckpointWrapperTests)
    result = unittest.TestResult()
    suite.run(result)
    report = {
        "schema": "information_battle_checkpoint_wrapper_tests_v1",
        "status": "passed" if result.wasSuccessful() else "failed",
        "scope": {
            "game_access": False,
            "save_or_autosave_executed": False,
            "control_request_sent": False,
            "http_access": False,
            "rea_or_rpm": False,
            "synthetic_temp_and_mock_only": True,
        },
        "tests": {
            "case_count": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "failure_names": [str(item[0]) for item in result.failures],
            "error_names": [str(item[0]) for item in result.errors],
        },
        "contract_checks": {
            "identity_date_player_pause_gates": True,
            "pending_request_rejected": True,
            "pending_intent_rejected": True,
            "exclusive_operation_reservation": True,
            "started_only_no_retry": True,
            "single_save_call_success": True,
            "expected_save_date_forwarded": True,
            "protected_r70_and_target_snapshot": True,
            "postcheck_failure_no_retry": True,
        },
        "source_pins": {
            "wrapper": _pin(ROOT / "work/run_information_battle_checkpoint.py"),
            "test": _pin(Path(__file__).resolve()),
            "save_tool": _pin(ROOT / "tools/save_observer_experiment.py"),
            "installed_probe": _pin(ROOT / "work/probe_information_battle_installed.py"),
            "control_tool": _pin(ROOT / "tools/control_information_battle_observer.py"),
        },
        "expected_reference": {
            "date_raw": EXPECTED_RAW_DATE,
            "save_date": EXPECTED_SAVE_DATE,
            "player_ref": EXPECTED_PLAYER_REF,
            "slot": 189,
            "paused": True,
            "note": "synthetic values mirror the current audit contract; no live/native save claim",
        },
        "wrapper_review_findings": [
            {
                "severity": "high",
                "status": "resolved_current_source",
                "source": "work/run_information_battle_checkpoint.py:42-44",
                "finding": "live pending_files now includes *.intent in addition to *.request and *.processing",
                "impact": "the synthetic .intent gate is rejected before save execution; historical window-intent.json remains outside the live suffix contract",
            },
            {
                "severity": "medium",
                "status": "resolved_current_source",
                "source": "work/run_information_battle_checkpoint.py:50,102,150-156",
                "finding": "expected_save_date is required and validated as a calendar date, then forwarded as run_experiment(expected_date=...)",
                "impact": "the mock confirms the expected textual save date reaches the save tool while raw date and world checks remain separate",
            },
        ],
        "elapsed_seconds": time.time() - started,
    }
    report_path = (output or ROOT / "work/runtime/information-battle-context-live-20261025-001/checkpoint-tests-001/report.json").resolve()
    if report_path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("xb") as stream:
        stream.write((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"status": report["status"], "report": str(report_path), "tests": result.testsRun}, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raise SystemExit(run_stage_tests(args.output))
