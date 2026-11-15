"""Offline v24 manifest, installer selection, and controller guard tests."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


GAME_SHA = "a" * 64
PLAYER_REF = "1234567890abcdef"


class V24Fixture:
    """A self-contained build directory; no process or game is touched."""

    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v24.dll"
        self.dll.write_bytes(b"synthetic-v24-observer")
        self.sources = {}
        for name in start.INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES:
            source = self.root / name
            source.write_bytes(("synthetic-source:" + name).encode("ascii"))
            self.sources[name] = source
        source_records = [
            {"name": name, "sha256": _sha256(path)}
            for name, path in self.sources.items()
        ]
        self.dll_sha = _sha256(self.dll)
        self.manifest = {
            "version": 24,
            "experiment_id": "information-battle-context-test",
            "game_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
            "information_battle_research_lifecycle": True,
            "information_battle_context_wire": 2,
            "information_battle_owned_context": True,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
            ],
            "sources": source_records,
        }
        self.manifest_path = self.root / "build-manifest.json"
        self.write_manifest()
        self.installation = {
            "pid": 43210,
            "creation_filetime": 99887766,
            "game_sha256": GAME_SHA,
            "session_id": "43210-v24-test-session",
            "dll_sha256": self.dll_sha,
            "modules_after_install": [{
                "name": self.dll.name,
                "path": str(self.dll),
                "sha256": self.dll_sha,
            }],
        }
        self.installation_path = self.root / "installation.json"
        self.write_installation()
        self.identity = {
            "pid": self.installation["pid"],
            "creation_filetime": self.installation["creation_filetime"],
            "game_sha256": GAME_SHA,
            "session_id": self.installation["session_id"],
            "modules": [{
                "name": self.dll.name,
                "path": str(self.dll),
                "sha256": self.dll_sha,
            }],
        }

    def write_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True), encoding="utf-8"
        )

    def write_installation(self) -> None:
        self.installation_path.write_text(
            json.dumps(self.installation, sort_keys=True), encoding="utf-8"
        )

    def close(self) -> None:
        self.temp.cleanup()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InformationBattleContextInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V24Fixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_v24_complete_manifest_pins_all_sources_and_macros(self) -> None:
        start._validate_information_battle_manifest(self.fx.manifest, self.fx.root)
        self.assertEqual(
            set(record["name"] for record in self.fx.manifest["sources"]),
            set(start.INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES),
        )
        self.assertIn("-DBRIDGE_INFORMATION_BATTLE=1", self.fx.manifest["compiler_arguments"])
        self.assertIn("-DINFORMATION_BATTLE_CONTEXT=1", self.fx.manifest["compiler_arguments"])

    def test_v24_manifest_rejects_missing_capability_or_wrong_wire(self) -> None:
        cases = (
            ("information_battle_research_lifecycle", None),
            ("information_battle_owned_context", None),
            ("information_battle_context_wire", 1),
            ("information_battle_context_wire", True),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                data = json.loads(json.dumps(self.fx.manifest))
                if value is None:
                    data.pop(key, None)
                else:
                    data[key] = value
                with self.assertRaises(SystemExit) as raised:
                    start._validate_information_battle_manifest(data, self.fx.root)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v24_manifest_rejects_missing_or_duplicate_source(self) -> None:
        data = json.loads(json.dumps(self.fx.manifest))
        data["sources"] = [
            record for record in data["sources"]
            if record["name"] != "information-battle-context-wire.h"
        ]
        with self.assertRaises(SystemExit) as raised:
            start._validate_information_battle_manifest(data, self.fx.root)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

        data = json.loads(json.dumps(self.fx.manifest))
        data["sources"].append(dict(data["sources"][0]))
        with self.assertRaises(SystemExit) as raised:
            start._validate_information_battle_manifest(data, self.fx.root)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v24_manifest_rejects_tampered_source_and_missing_macro(self) -> None:
        source = self.fx.sources["information-battle-owned-context.h"]
        source.write_bytes(b"tampered")
        with self.assertRaises(SystemExit) as raised:
            start._validate_information_battle_manifest(self.fx.manifest, self.fx.root)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

        source.write_bytes(("synthetic-source:" + source.name).encode("ascii"))
        data = json.loads(json.dumps(self.fx.manifest))
        data["compiler_arguments"] = ["-DBRIDGE_INFORMATION_BATTLE=1"]
        with self.assertRaises(SystemExit) as raised:
            start._validate_information_battle_manifest(data, self.fx.root)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_start_main_selects_the_pinned_v24_dll(self) -> None:
        # The installer refuses a reused directory; this test models a fresh
        # build directory while readiness/identity are supplied by the mock.
        self.fx.installation_path.unlink()
        with patch.object(start, "_wait_until_ready", return_value=(
                self._identity(), {}, None, "ready", [])), \
             patch.object(start, "_install_once") as install, \
             patch.object(start, "get_value", return_value="python"), \
             contextlib.redirect_stdout(io.StringIO()):
            start.main(["--native-text-codec", "utf8", "--pid", "43210", "--manifest", str(self.fx.manifest_path)])
        self.assertEqual(install.call_count, 1)
        self.assertEqual(install.call_args.args[3], self.fx.dll.resolve())

    def test_controller_v24_selects_dll_and_observes_unbound_status(self) -> None:
        status = {
            "schema": "EU4-BATTLE-SOURCE/1",
            "request_id": "startup",
            "command": "startup",
            "accepted": True,
            "reason": "awaiting_process_bound_enable",
            "state": "ready",
            "pid": self.fx.installation["pid"],
            "creation_filetime": str(self.fx.installation["creation_filetime"]),
            "installation": "0",
            "generation": "0",
            "exe_sha256": GAME_SHA,
            "dll_sha256": self.fx.dll_sha,
        }
        (self.fx.root / control.STATUS_NAME).write_text(
            json.dumps(status), encoding="utf-8"
        )
        with patch.object(control, "probe_identity", return_value=self.fx.identity), \
             patch.object(control, "game_exe", return_value=self.fx.root / "eu4.exe"):
            context = control._load_context(self.fx.installation_path)
            observed = control.run_control(self.fx.installation_path, "status")
        self.assertEqual(context.dll_path, self.fx.dll.resolve())
        self.assertEqual(context.manifest["version"], 24)
        self.assertEqual(observed["status"], "observed")
        self.assertEqual(observed["native"]["state"], "ready")

    def test_controller_v24_identity_nonce_and_timeout_are_no_retry(self) -> None:
        with patch.object(control, "probe_identity", return_value=self.fx.identity), \
             patch.object(control, "game_exe", return_value=self.fx.root / "eu4.exe"), \
             patch.object(control, "RESPONSE_TIMEOUT_SECONDS", 0.02), \
             patch.object(control, "RESPONSE_POLL_SECONDS", 0.001):
            result = control.run_control(self.fx.installation_path, "enable", PLAYER_REF)
            self.assertEqual(result["status"], "unknown_no_retry")
            request = (self.fx.root / control.CONTROL_NAME).read_text(encoding="ascii")
            tokens = request.rstrip("\n").split(" ")
            self.assertEqual(len(tokens), 8)
            self.assertEqual(tokens[0], control.PROTOCOL)
            self.assertEqual(tokens[2], "enable")
            self.assertEqual(tokens[3], str(self.fx.installation["pid"]))
            self.assertEqual(tokens[4], str(self.fx.installation["creation_filetime"]))
            self.assertEqual(tokens[6], self.fx.dll_sha)
            self.assertEqual(tokens[7], PLAYER_REF)
            self.assertEqual(tokens[1], result["nonce"])
            self.assertTrue((self.fx.root / f"{control.AUDIT_PREFIX}{tokens[1]}.jsonl").is_file())

            with self.assertRaises(control.ControlError) as raised:
                control.run_control(self.fx.installation_path, "enable", PLAYER_REF)
        self.assertEqual(raised.exception.reason, "CONTROL_BUSY")

    def test_controller_v24_rejects_changed_process_identity(self) -> None:
        changed = dict(self.fx.identity)
        changed["creation_filetime"] += 1
        with patch.object(control, "probe_identity", return_value=changed), \
             patch.object(control, "game_exe", return_value=self.fx.root / "eu4.exe"):
            with self.assertRaises(control.ControlError) as raised:
                control.run_control(self.fx.installation_path, "status")
        self.assertEqual(raised.exception.reason, "PROCESS_IDENTITY_MISMATCH")

    def _identity(self) -> dict[str, object]:
        return json.loads(json.dumps(self.fx.identity))


if __name__ == "__main__":
    unittest.main()
