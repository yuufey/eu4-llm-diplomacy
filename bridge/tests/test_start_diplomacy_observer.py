from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools import start_diplomacy_observer as subject


class ObserverStartTests(unittest.TestCase):
    def test_native_text_codec_uses_local_configuration_and_explicit_override(self):
        cases = (
            (None, None, "utf8"),
            ("eu4_escape", None, "eu4_escape"),
            ("eu4_escape", "utf8", "utf8"),
            ("utf8", "eu4_escape", "eu4_escape"),
            ("invalid", "eu4_escape", "eu4_escape"),
        )
        for configured, explicit, expected in cases:
            with self.subTest(configured=configured, explicit=explicit):
                temp, directory, manifest, _dll = self._setup()
                self.addCleanup(temp.cleanup)

                def get_value(name, **kwargs):
                    if name == "EU4_PYTHON":
                        return "python"
                    self.assertEqual(name, "EU4_NATIVE_TEXT_CODEC")
                    return configured if configured is not None else kwargs["default"]

                arguments = ["--pid", "52544", "--manifest", str(manifest)]
                if explicit is not None:
                    arguments.extend(["--native-text-codec", explicit])
                with patch.object(subject, "file_hash", return_value="dll"), \
                     patch.object(subject, "_wait_until_ready", return_value=(
                         self._identity(), {}, None, "ready", [])), \
                     patch.object(subject, "_install_once") as install, \
                     patch.object(subject, "get_value", side_effect=get_value), \
                     contextlib.redirect_stdout(io.StringIO()):
                    subject.main(arguments)
                self.assertEqual(install.call_count, 1)
                self.assertEqual(install.call_args.args[-1], expected)

    def test_invalid_configured_codec_fails_before_process_access(self):
        for configured in ("", "UTF8", "invalid"):
            with self.subTest(configured=configured), \
                 patch.object(subject, "get_value", return_value=configured), \
                 patch.object(subject, "_wait_until_ready") as ready, \
                 patch.object(subject, "_install_once") as install, \
                 contextlib.redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit) as raised:
                subject.main(["--pid", "52544", "--manifest", "unused.json"])
            self.assertEqual(raised.exception.code, 2)
            ready.assert_not_called()
            install.assert_not_called()

    def _setup(self, version=10):
        temp = tempfile.TemporaryDirectory()
        directory = Path(temp.name)
        dll = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        dll.write_bytes(b"reviewed observer")
        manifest = directory / "build-manifest.json"
        manifest.write_text(json.dumps({
            "version": version,
            "experiment_id": "observer-test",
            "game_sha256": "game",
            "dll_sha256": "dll",
        }), encoding="utf-8")
        return temp, directory, manifest, dll

    def _setup_v23(self):
        temp, directory, manifest, dll = self._setup(23)
        source_records = []
        for name in subject.INFORMATION_BATTLE_REQUIRED_SOURCES:
            source = directory / name
            source.write_bytes(("source:" + name).encode("ascii"))
            source_records.append({"name": name, "sha256": subject.file_hash(source, refresh=True)})
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["information_battle_research_lifecycle"] = True
        data["sources"] = source_records
        data["dll_sha256"] = subject.file_hash(dll, refresh=True)
        manifest.write_text(json.dumps(data), encoding="utf-8")
        return temp, directory, manifest, dll

    def _setup_v28(self):
        temp, directory, manifest, dll = self._setup(28)
        source_records = []
        for name in subject.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES:
            source = directory / name
            source.write_bytes(("source:" + name).encode("ascii"))
            source_records.append({"name": name, "sha256": subject.file_hash(source, refresh=True)})
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data.update({
            "information_battle_research_lifecycle": True,
            "information_battle_context_wire": 2,
            "information_battle_owned_context": True,
            "information_battle_naval_wire": 3,
            "information_battle_owned_naval": True,
            "information_battle_template_wire": 4,
            "information_battle_owned_template": True,
            "information_battle_message_scope": True,
            "information_battle_formatter_container": True,
            "information_battle_template_extensions": [1, 2],
            "information_battle_war_identity": True,
            "information_battle_war_identity_wire": 5,
            "information_battle_war_identity_scope": "observer_session",
            "information_battle_war_identity_read_only": True,
            "information_battle_war_identity_complete": False,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
                "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
            ],
            "sources": source_records,
        })
        data["dll_sha256"] = subject.file_hash(dll, refresh=True)
        manifest.write_text(json.dumps(data), encoding="utf-8")
        return temp, directory, manifest, dll

    @staticmethod
    def _identity(installed=False):
        return {
            "pid": 52544,
            "creation_filetime": 9988,
            "session_id": "52544-2704",
            "game_sha256": "game",
            "modules": ([{"name": "observer.dll", "sha256": "dll"}] if installed else []),
        }

    @staticmethod
    def _winerror(winerror):
        error = OSError(f"synthetic WinError {winerror}")
        error.winerror = winerror
        return error

    @staticmethod
    def _shortcut_api(windows):
        def owner(hwnd, output):
            output._obj.value = windows[hwnd.value][0]
            return 1

        def window_class(hwnd, output, _size):
            output.value = windows[hwnd.value][2]
            return len(output.value)

        return SimpleNamespace(
            GetWindowThreadProcessId=Mock(side_effect=owner),
            IsWindowVisible=Mock(side_effect=lambda hwnd: windows[hwnd.value][1]),
            GetClassNameW=Mock(side_effect=window_class),
            PostMessageW=Mock(return_value=True),
        )

    def test_shortcut_targets_one_visible_game_window_and_records_before_send(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        windows = {101: (52544, True, "SDL_app"), 102: (52544, False, "SDL_app"),
                   103: (7, True, "SDL_app"), 104: (52544, True, "Other")}
        api = self._shortcut_api(windows)

        def post(hwnd, message, key, flags):
            receipt = json.loads((directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_text())
            self.assertTrue(receipt["attempted"])
            self.assertIsNone(receipt["queued"])
            self.assertIsNone(receipt["key_down_queued"])
            self.assertIsNone(receipt["key_up_queued"])
            expected = ((101, 0x100, ord("C"), 0x002e0001),
                        (101, 0x101, ord("C"), 0xc02e0001))
            self.assertEqual((hwnd.value, message, key, flags), expected[api.PostMessageW.call_count - 1])
            return True

        api.PostMessageW.side_effect = post
        with patch.object(subject.C, "WinDLL", return_value=api), \
             patch.object(subject, "_enumerate_windows_for_pid", return_value=list(windows)), \
             patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
             patch.object(subject, "probe_identity", return_value=self._identity()):
            result = subject._queue_load_warning_shortcut(
                52544, self._identity(), "llm_test.eu4", directory)

        self.assertEqual(api.PostMessageW.call_count, 2)
        self.assertTrue(result["queued"])
        self.assertTrue(result["key_down_queued"])
        self.assertTrue(result["key_up_queued"])
        self.assertEqual(result["message"], "WM_KEYDOWN/WM_KEYUP")
        self.assertFalse(result["visually_confirmed"])
        self.assertEqual(result["save_name"], "llm_test.eu4")
        self.assertEqual(result["basis"], "operator_bound_saved_test_game_startup")

    def test_shortcut_rejects_ambiguous_window_or_changed_process(self):
        for case in ("two_windows", "changed_process", "changed_window", "changed_before_key_up"):
            with self.subTest(case=case):
                temp, directory, _manifest, _dll = self._setup()
                self.addCleanup(temp.cleanup)
                windows = {101: (52544, True, "SDL_app")}
                if case == "two_windows":
                    windows[102] = windows[101]
                api = self._shortcut_api(windows)
                identity = self._identity()
                if case == "changed_process":
                    identity["creation_filetime"] += 1
                if case in ("changed_window", "changed_before_key_up"):
                    def owner(hwnd, output):
                        valid_calls = 2 if case == "changed_before_key_up" else 1
                        output._obj.value = 52544 if api.GetWindowThreadProcessId.call_count <= valid_calls else 7
                        return 1
                    api.GetWindowThreadProcessId.side_effect = owner
                with patch.object(subject.C, "WinDLL", return_value=api), \
                     patch.object(subject, "_enumerate_windows_for_pid", return_value=list(windows)), \
                     patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
                     patch.object(subject, "probe_identity", return_value=identity):
                    if case == "changed_process":
                        with self.assertRaisesRegex(RuntimeError, "PROCESS_CREATION_CHANGED_NO_RETRY"):
                            subject._queue_load_warning_shortcut(
                                52544, self._identity(), "llm_test.eu4", directory)
                    else:
                        result = subject._queue_load_warning_shortcut(
                            52544, self._identity(), "llm_test.eu4", directory)
                        self.assertEqual(result["attempted"], case in ("changed_window", "changed_before_key_up"))
                if case == "changed_before_key_up":
                    self.assertEqual(api.PostMessageW.call_count, 1)
                    self.assertTrue(result["key_down_queued"])
                    self.assertIsNone(result["key_up_queued"])
                    self.assertIsNone(result["queued"])
                else:
                    api.PostMessageW.assert_not_called()

    def test_shortcut_unknown_send_is_durable_and_never_reposted(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        api = self._shortcut_api({101: (52544, True, "SDL_app")})
        api.PostMessageW.side_effect = OSError("unknown queue result")
        with patch.object(subject.C, "WinDLL", return_value=api), \
             patch.object(subject, "_enumerate_windows_for_pid", return_value=[101]), \
             patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
             patch.object(subject, "probe_identity", return_value=self._identity()):
            result = subject._queue_load_warning_shortcut(
                52544, self._identity(), "llm_test.eu4", directory)
            with self.assertRaisesRegex(RuntimeError, "SHORTCUT_ALREADY_ATTEMPTED_NO_RETRY"):
                subject._queue_load_warning_shortcut(
                    52544, self._identity(), "llm_test.eu4", directory)
        self.assertIsNone(result["queued"])
        self.assertEqual(api.PostMessageW.call_count, 1)
        receipt = json.loads((directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_text())
        self.assertIsNone(receipt["queued"])
        self.assertEqual(receipt["queue_error"], "unknown queue result")

    def test_shortcut_partial_key_pair_is_recorded_and_never_reposted(self):
        for results in ((True, False), (False, True), (True, OSError("unknown key-up result"))):
            with self.subTest(results=results):
                temp, directory, _manifest, _dll = self._setup()
                self.addCleanup(temp.cleanup)
                api = self._shortcut_api({101: (52544, True, "SDL_app")})
                api.PostMessageW.side_effect = results
                with patch.object(subject.C, "WinDLL", return_value=api), \
                     patch.object(subject, "_enumerate_windows_for_pid", return_value=[101]), \
                     patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
                     patch.object(subject, "probe_identity", return_value=self._identity()):
                    result = subject._queue_load_warning_shortcut(
                        52544, self._identity(), "llm_test.eu4", directory)
                    receipt = (directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_bytes()
                    with self.assertRaisesRegex(RuntimeError, "SHORTCUT_ALREADY_ATTEMPTED_NO_RETRY"):
                        subject._queue_load_warning_shortcut(
                            52544, self._identity(), "llm_test.eu4", directory)
                self.assertEqual(api.PostMessageW.call_count, 2)
                self.assertIs(result["key_down_queued"], results[0])
                if isinstance(results[1], OSError):
                    self.assertIsNone(result["key_up_queued"])
                    self.assertIsNone(result["queued"])
                else:
                    self.assertIs(result["key_up_queued"], results[1])
                    self.assertFalse(result["queued"])
                self.assertEqual(json.loads(receipt), result)
                self.assertEqual((directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_bytes(), receipt)

    def test_shortcut_preserves_legacy_character_receipt_without_resending(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        receipt = directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT
        receipt.write_text(json.dumps({
            "schema": "eu4.load_warning_shortcut.v1", "identity": self._identity(),
            "attempted": True, "queued": True, "message": "WM_CHAR", "character": "c",
            "load_verified": False, "visually_confirmed": False,
        }))
        original = receipt.read_bytes()
        api = self._shortcut_api({101: (52544, True, "SDL_app")})
        with patch.object(subject.C, "WinDLL", return_value=api), \
             patch.object(subject, "_enumerate_windows_for_pid", return_value=[101]), \
             patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
             patch.object(subject, "probe_identity", return_value=self._identity()):
            with self.assertRaisesRegex(RuntimeError, "SHORTCUT_ALREADY_ATTEMPTED_NO_RETRY"):
                subject._queue_load_warning_shortcut(
                    52544, self._identity(), "llm_test.eu4", directory)
        api.PostMessageW.assert_not_called()
        self.assertEqual(receipt.read_bytes(), original)

    def test_named_save_preserves_native_priority_and_other_scan_failures(self):
        for native_result in ("TEST_ONLY native\n", "LOAD_WARNING_SCAN_TIMEOUT"):
            with self.subTest(native_result=native_result):
                temp, directory, _manifest, _dll = self._setup()
                self.addCleanup(temp.cleanup)
                clock = [0.0]
                confirmation = Mock(return_value=native_result)
                if native_result == "LOAD_WARNING_SCAN_TIMEOUT":
                    confirmation.side_effect = RuntimeError(native_result)
                with patch.object(subject, "probe_identity", return_value=self._identity()), \
                     patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
                     patch.object(subject, "get_value", return_value="python"), \
                     patch.object(subject, "_preflight_once", return_value=(
                         {"player_tag": "---"}, {"reason": "PREFLIGHT_READY"})), \
                     patch.object(subject, "confirmation_request", confirmation), \
                     patch.object(subject, "_queue_load_warning_shortcut") as shortcut, \
                     patch.object(subject.time, "monotonic", side_effect=lambda: clock[0]), \
                     patch.object(subject.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if native_result == "LOAD_WARNING_SCAN_TIMEOUT":
                        with self.assertRaisesRegex(SystemExit, "WORLD_NOT_READY_TIMEOUT"):
                            subject._wait_until_ready(52544, {"game_sha256": "game"}, directory,
                                                      True, 3, load_warning_save_name="llm_test.eu4")
                    else:
                        result = subject._wait_until_ready(52544, {"game_sha256": "game"}, directory,
                                                           True, 3, load_warning_save_name="llm_test.eu4")
                        self.assertEqual(result[2:4], (native_result, "verified_load_confirmation"))
                shortcut.assert_not_called()

    def test_named_save_shortcut_waits_for_loaded_world_date_then_installs_once(self):
        temp, directory, manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        states = iter([{"player_tag": "---"}, {"player_tag": "---"},
                       {"player_tag": "POR"},
                       {"player_tag": "POR", "fra_send_date_guard": {"current_raw_date": 56694720}}])
        clock = [0.0]
        calls = {"inject": 0}

        def preflight(*_args):
            return next(states), {"reason": "PREFLIGHT_READY"}

        def queue(_pid, identity, save_name, path):
            record = {"identity": identity, "save_name": save_name, "attempted": True,
                      "queued": True, "visually_confirmed": False}
            (path / subject.LOAD_WARNING_SHORTCUT_RECEIPT).write_text(json.dumps(record))
            return record

        def inject(command, **_kwargs):
            self.assertTrue(any("inject_probe.py" in str(part) for part in command))
            calls["inject"] += 1
            return subprocess.CompletedProcess(command, 0, "installed", "")

        with patch.object(subject, "file_hash", return_value="dll"), \
             patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
             patch.object(subject, "get_value", return_value="python"), \
             patch.object(subject, "probe_identity", return_value=self._identity()), \
             patch.object(subject, "_preflight_once", side_effect=preflight), \
             patch.object(subject, "confirmation_request", side_effect=RuntimeError(
                 "UNIQUE_VERIFIED_LOAD_CONFIRMATION_NOT_FOUND")) as native, \
             patch.object(subject, "_queue_load_warning_shortcut", side_effect=queue) as shortcut, \
             patch.object(subject.subprocess, "run", side_effect=inject), \
             patch.object(subject.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(subject.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
             contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest), "--confirm-load-warning",
                          "--load-warning-save-name", "llm_test.eu4", "--wait-ready", "20"])

        self.assertEqual((native.call_count, shortcut.call_count, calls["inject"]), (1, 1, 1))
        self.assertEqual(shortcut.call_args.args[2], "llm_test.eu4")
        receipt = json.loads((directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_text())
        self.assertTrue(receipt["load_verified"])
        self.assertEqual(receipt["loaded_game_date_raw"], 56694720)
        self.assertFalse((directory / "popup-confirm.request").exists())
        installed = json.loads((directory / "installation.json").read_text())
        self.assertEqual(installed["ready_reason"], "por_loaded_after_load_warning_shortcut")
        self.assertEqual(installed["ready_attempts"][2]["reason"], "LOAD_WARNING_SHORTCUT_AWAITING_WORLD_DATE")

    def test_existing_shortcut_receipt_waits_without_resending_even_without_confirm_flag(self):
        for queued in (True, False, None):
            with self.subTest(queued=queued):
                temp, directory, _manifest, _dll = self._setup()
                self.addCleanup(temp.cleanup)
                (directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).write_text(json.dumps({
                    "identity": self._identity(), "attempted": True, "queued": queued,
                    "message": "WM_CHAR", "character": "c"}))
                original = (directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_bytes()
                clock = [0.0]
                with patch.object(subject, "probe_identity", return_value=self._identity()), \
                     patch.object(subject, "game_exe", return_value=directory / "eu4.exe"), \
                     patch.object(subject, "get_value", return_value="python"), \
                     patch.object(subject, "_preflight_once", return_value=(
                         {"player_tag": "---"}, {"reason": "PREFLIGHT_READY"})), \
                     patch.object(subject, "confirmation_request") as native, \
                     patch.object(subject, "_queue_load_warning_shortcut") as shortcut, \
                     patch.object(subject.time, "monotonic", side_effect=lambda: clock[0]), \
                     patch.object(subject.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                     contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "WORLD_NOT_READY_TIMEOUT_NO_INSTALLATION_ATTEMPTED"):
                        subject._wait_until_ready(52544, {"game_sha256": "game"}, directory, False, 3)
                native.assert_not_called()
                shortcut.assert_not_called()
                self.assertFalse((directory / "installation.json").exists())
                self.assertEqual((directory / subject.LOAD_WARNING_SHORTCUT_RECEIPT).read_bytes(), original)

    def test_named_save_argument_requires_confirmation_and_local_filename(self):
        temp, _directory, manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        for name in ("llm_test.eu4", "Test-2026.eu4"):
            self.assertEqual(subject.load_warning_save_name(name), name)
        for name in ("../test.eu4", "C:\\test.eu4", "test file.eu4", "test"):
            with self.subTest(name=name), self.assertRaises(subject.argparse.ArgumentTypeError):
                subject.load_warning_save_name(name)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest),
                          "--load-warning-save-name", "llm_test.eu4"])
        self.assertEqual(raised.exception.code, 2)

    def test_initial_identity_probe_transient_errors_wait_inside_deadline(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        clock = [0.0]
        probe_calls = [0]

        def fake_identity(_pid, _exe):
            probe_calls[0] += 1
            if probe_calls[0] == 1:
                raise self._winerror(6)
            if probe_calls[0] == 2:
                raise self._winerror(299)
            return self._identity()

        def fake_preflight(_pid, _python, attempt_directory, _deadline):
            return {"player_tag": "---"}, {
                "reason": "PREFLIGHT_READY",
                "preflight": str(attempt_directory / "preflight.json"),
            }

        output = io.StringIO()
        with patch.object(subject, "probe_identity", fake_identity), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "get_value", lambda _name: "python"), \
             patch.object(subject, "_preflight_once", fake_preflight), \
             patch.object(subject.time, "monotonic", lambda: clock[0]), \
             patch.object(subject.time, "sleep",
                          lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
             contextlib.redirect_stdout(output):
            identity, state, confirmation, reason, attempts = subject._wait_until_ready(
                52544, {"game_sha256": "game"}, directory, False, 5)

        self.assertEqual(identity, self._identity())
        self.assertEqual(state["player_tag"], "---")
        self.assertIsNone(confirmation)
        self.assertEqual(reason, "unloaded_no_confirmation_requested")
        identity_waits = [entry for entry in attempts if entry.get("phase") == "identity_probe"]
        self.assertEqual([entry["winerror"] for entry in identity_waits], [6, 299])
        self.assertTrue(all(entry["outcome"] == "waiting" for entry in identity_waits))
        waiting_lines = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual([line["phase"] for line in waiting_lines], ["identity_probe", "identity_probe"])
        self.assertEqual(probe_calls[0], 5)

    def test_initial_identity_probe_transient_errors_obey_total_deadline(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        clock = [0.0]
        output = io.StringIO()

        def fake_identity(_pid, _exe):
            raise self._winerror(6)

        with patch.object(subject, "probe_identity", fake_identity), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject.time, "monotonic", lambda: clock[0]), \
             patch.object(subject.time, "sleep",
                          lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                subject._wait_until_ready(
                    52544, {"game_sha256": "game"}, directory, False, 3)

        self.assertEqual(str(raised.exception), "WORLD_NOT_READY_TIMEOUT_NO_INSTALLATION_ATTEMPTED")
        waiting_lines = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual(len(waiting_lines), 3)
        self.assertTrue(all(line["phase"] == "identity_probe" for line in waiting_lines))
        self.assertTrue(all(line["reason"] == "IDENTITY_PROBE_TRANSIENT_WINERROR_6"
                            for line in waiting_lines))

    def test_initial_identity_probe_nontransient_error_propagates(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        error = self._winerror(5)

        def fake_identity(_pid, _exe):
            raise error

        with patch.object(subject, "probe_identity", fake_identity), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"):
            with self.assertRaises(OSError) as raised:
                subject._wait_until_ready(
                    52544, {"game_sha256": "game"}, directory, False, 5)

        self.assertIs(raised.exception, error)

    def test_transient_identity_then_install_enters_install_once(self):
        temp, directory, manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        calls = {"probe": 0, "preflight": 0, "inject": 0}

        def fake_identity(_pid, _exe):
            calls["probe"] += 1
            if calls["probe"] == 1:
                raise self._winerror(6)
            return self._identity()

        def fake_run(command, **_kwargs):
            if any("probe_native_state.py" in str(part) for part in command):
                calls["preflight"] += 1
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps({"player_tag": "POR"}), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            if any("inject_probe.py" in str(part) for part in command):
                calls["inject"] += 1
                return subprocess.CompletedProcess(command, 0, "installed", "")
            raise AssertionError(f"unexpected child command: {command}")

        output = io.StringIO()
        with patch.object(subject, "file_hash", lambda _path: "dll"), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "get_value", lambda _name: "python"), \
             patch.object(subject, "probe_identity", fake_identity), \
             patch.object(subject.subprocess, "run", fake_run), \
             patch.object(subject.time, "sleep", lambda _seconds: None), \
             contextlib.redirect_stdout(output):
            subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest), "--wait-ready", "5"])

        self.assertEqual(calls["preflight"], 1)
        self.assertEqual(calls["inject"], 1)
        installation = json.loads((directory / "installation.json").read_text(encoding="utf-8"))
        self.assertEqual(installation["installation_returncode"], 0)
        self.assertEqual(len(installation["ready_attempts"]), 2)
        waiting_lines = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual(waiting_lines[0]["phase"], "identity_probe")

    def test_delayed_preflight_then_injection_error_is_single_attempt(self):
        temp, directory, manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        calls = {"preflight": 0, "inject": 0}

        def fake_run(command, **_kwargs):
            if any("probe_native_state.py" in str(part) for part in command):
                calls["preflight"] += 1
                output = Path(command[command.index("--output") + 1])
                if calls["preflight"] == 1:
                    return subprocess.CompletedProcess(command, 17, "countryDB only", "")
                output.write_text(json.dumps({"player_tag": "POR"}), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            if any("inject_probe.py" in str(part) for part in command):
                calls["inject"] += 1
                return subprocess.CompletedProcess(command, 9, "loader failed", "")
            raise AssertionError(f"unexpected child command: {command}")

        output = io.StringIO()
        with patch.object(subject, "file_hash", lambda _path: "dll"), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "get_value", lambda _name: "python"), \
             patch.object(subject, "probe_identity", lambda _pid, _exe: self._identity()), \
             patch.object(subject.subprocess, "run", fake_run), \
             patch.object(subject.time, "sleep", lambda _seconds: None), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest), "--wait-ready", "5"])

        self.assertEqual(str(raised.exception), "INSTALLATION_FAILED_NO_RETRY_IN_THIS_PROCESS")
        self.assertEqual(calls, {"preflight": 2, "inject": 1})
        attempts = sorted(directory.glob("ready-attempt-*") )
        self.assertEqual(len(attempts), 2)
        self.assertTrue((attempts[0] / "preflight.error.txt").is_file())
        installation = json.loads((directory / "installation.json").read_text(encoding="utf-8"))
        self.assertEqual(installation["installation_returncode"], 9)
        self.assertEqual(len(installation["ready_attempts"]), 2)
        waiting_lines = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual(waiting_lines[0]["state"], "waiting")
        self.assertEqual(waiting_lines[0]["reason"], "PREFLIGHT_RETURN_17")

    def test_startup_error_scan_is_bounded_to_one_check_per_five_seconds(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        clock = [0.0]
        preflight_calls = [0]
        scan_times: list[float] = []

        def fake_preflight(_pid, _python, attempt_directory, _deadline):
            preflight_calls[0] += 1
            if clock[0] < 7.0:
                return None, {"reason": "PREFLIGHT_RETURN_17", "preflight": str(attempt_directory / "preflight.json")}
            return {"player_tag": "---"}, {"reason": "PREFLIGHT_READY", "preflight": "ready"}

        def fake_acknowledge(_pid, _attempt_directory):
            scan_times.append(clock[0])
            return None

        with patch.object(subject, "probe_identity", lambda _pid, _exe: self._identity()), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "_preflight_once", fake_preflight), \
             patch.object(subject, "acknowledge_startup_error", fake_acknowledge), \
             patch.object(subject.time, "monotonic", lambda: clock[0]), \
             patch.object(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            _identity, state, confirmation, reason, attempts = subject._wait_until_ready(
                52544, {"game_sha256": "game"}, directory, False, 10)

        self.assertEqual(state["player_tag"], "---")
        self.assertIsNone(confirmation)
        self.assertEqual(reason, "unloaded_no_confirmation_requested")
        self.assertEqual(len(attempts), 4)
        self.assertEqual(scan_times, [0.0, 6.0])
        self.assertGreaterEqual(scan_times[1] - scan_times[0], 5.0)

    def test_delayed_load_warning_uses_independent_attempts_then_queues_once(self):
        temp, directory, manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        calls = {"preflight": 0, "inject": 0}
        installed = [False]

        def fake_identity(_pid, _exe):
            return self._identity(installed[0])

        def fake_run(command, **_kwargs):
            if any("probe_native_state.py" in str(part) for part in command):
                calls["preflight"] += 1
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps({"player_tag": "---", "module_base": "0x100000"}), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            if any("inject_probe.py" in str(part) for part in command):
                calls["inject"] += 1
                installed[0] = True
                return subprocess.CompletedProcess(command, 0, "installed", "")
            raise AssertionError(f"unexpected child command: {command}")

        confirmation_calls = []

        def fake_confirmation(_pid, _state, attempt_directory, _resume_address=0):
            confirmation_calls.append(attempt_directory)
            if len(confirmation_calls) == 1:
                raise RuntimeError("UNIQUE_VERIFIED_LOAD_CONFIRMATION_NOT_FOUND")
            return "TEST_ONLY 52544 100 200 300\n"

        output = io.StringIO()
        with patch.object(subject, "file_hash", lambda _path: "dll"), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "get_value", lambda _name: "python"), \
             patch.object(subject, "probe_identity", fake_identity), \
             patch.object(subject, "confirmation_request", fake_confirmation), \
             patch.object(subject.subprocess, "run", fake_run), \
             patch.object(subject.time, "sleep", lambda _seconds: None), \
             contextlib.redirect_stdout(output):
            subject.main(["--native-text-codec", "utf8", 
                "--pid", "52544", "--manifest", str(manifest),
                "--confirm-load-warning", "--wait-ready", "5",
            ])

        self.assertEqual(calls, {"preflight": 2, "inject": 1})
        self.assertEqual(len(confirmation_calls), 2)
        popup = directory / "popup-confirm.request"
        self.assertEqual(popup.read_text(encoding="ascii"), "TEST_ONLY 52544 100 200 300\n")
        installation = json.loads((directory / "installation.json").read_text(encoding="utf-8"))
        self.assertEqual(installation["ready_reason"], "verified_load_confirmation")
        self.assertEqual(len(installation["ready_attempts"]), 2)
        waiting_lines = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual(waiting_lines[0]["reason"], "UNIQUE_VERIFIED_LOAD_CONFIRMATION_NOT_FOUND")
        final = json.loads(output.getvalue().splitlines()[-1])
        self.assertTrue(final["installed"])
        self.assertTrue(final["confirmation_queued"])

    def test_startup_dialog_scan_contract_is_bounded_and_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = directory / "startup-dialogs.json"
            report.write_text(json.dumps({"scanned_bytes": 3 * 1024**3,
                "scan_complete": False, "next_scan_address": "0x123400000"}), encoding="utf-8")
            # Exhausting one slice preserves the cursor for the next attempt.
            self.assertEqual(subject._read_scan_cursor(directory, 0), 0x123400000)
            report.write_text(json.dumps({"scan_complete": True,
                "next_scan_address": "0x7fffffffffff"}), encoding="utf-8")
            self.assertEqual(subject._read_scan_cursor(directory, 123), 0)

    def test_hung_startup_error_stops_wait_without_install_or_restart(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        ack_calls = []

        def fake_preflight(_pid, _python, attempt_directory, _deadline):
            return None, {"reason": "PREFLIGHT_RETURN_17",
                          "preflight": str(attempt_directory / "preflight.json")}

        def fake_acknowledge(_pid, attempt_directory):
            ack_calls.append(attempt_directory)
            return {
                "attempted": True,
                "acknowledged": False,
                "terminal": True,
                "reason": "STARTUP_ERROR_DIALOG_HUNG_NO_RETRY",
            }

        with patch.object(subject, "probe_identity", lambda _pid, _exe: self._identity()), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "_preflight_once", fake_preflight), \
             patch.object(subject, "acknowledge_startup_error", fake_acknowledge), \
             patch.object(subject.time, "sleep", lambda _seconds: None):
            with self.assertRaises(SystemExit) as raised:
                subject._wait_until_ready(
                    52544, {"game_sha256": "game"}, directory, False, 10)

        self.assertEqual(str(raised.exception), "STARTUP_ERROR_DIALOG_HUNG_NO_RETRY")
        self.assertEqual(len(ack_calls), 1)
        self.assertFalse((directory / "installation.json").exists())

    def test_responsive_startup_error_is_not_reposted(self):
        temp, directory, _manifest, _dll = self._setup()
        self.addCleanup(temp.cleanup)
        preflight_calls = [0]
        ack_calls = []

        def fake_preflight(_pid, _python, attempt_directory, _deadline):
            preflight_calls[0] += 1
            if preflight_calls[0] < 3:
                return None, {"reason": "PREFLIGHT_RETURN_17",
                              "preflight": str(attempt_directory / "preflight.json")}
            return {"player_tag": "---"}, {"reason": "PREFLIGHT_READY",
                                             "preflight": "ready"}

        def fake_acknowledge(_pid, attempt_directory):
            ack_calls.append(attempt_directory)
            return {
                "attempted": True,
                "acknowledged": False,
                "terminal": False,
                "reason": "STARTUP_ERROR_DIALOG_NOT_DISMISSED",
            }

        with patch.object(subject, "probe_identity", lambda _pid, _exe: self._identity()), \
             patch.object(subject, "game_exe", lambda: directory / "eu4.exe"), \
             patch.object(subject, "_preflight_once", fake_preflight), \
             patch.object(subject, "acknowledge_startup_error", fake_acknowledge), \
             patch.object(subject.time, "sleep", lambda _seconds: None):
            _identity, state, confirmation, reason, attempts = subject._wait_until_ready(
                52544, {"game_sha256": "game"}, directory, False, 10)

        self.assertEqual(state["player_tag"], "---")
        self.assertIsNone(confirmation)
        self.assertEqual(reason, "unloaded_no_confirmation_requested")
        self.assertEqual(len(ack_calls), 1)
        self.assertEqual(len(attempts), 3)

    def test_current_build_versions_select_their_own_dll(self):
        for version in (21, 22):
            with self.subTest(version=version):
                temp, directory, manifest, dll = self._setup(version)
                self.addCleanup(temp.cleanup)
                with patch.object(subject, "file_hash", return_value="dll"), \
                        patch.object(subject, "_wait_until_ready", return_value=(
                            self._identity(), {}, None, "ready", [])), \
                        patch.object(subject, "_install_once") as install, \
                        patch.object(subject, "get_value", return_value="python"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest)])
                self.assertEqual(install.call_args.args[3], dll.resolve())
                self.assertEqual(install.call_count, 1)

    def test_v23_manifest_requires_complete_battle_source_pins(self):
        temp, directory, manifest, _dll = self._setup_v23()
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest.read_text(encoding="utf-8"))
        cases = {
            "missing_capability": lambda data: data.pop("information_battle_research_lifecycle"),
            "missing_source": lambda data: data["sources"].pop(),
            "bad_source_hash": lambda data: data["sources"][0].update({"sha256": "0" * 64}),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                manifest.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v23_main_accepts_pinned_manifest_and_selects_v23_dll(self):
        temp, directory, manifest, dll = self._setup_v23()
        self.addCleanup(temp.cleanup)
        with patch.object(subject, "_wait_until_ready", return_value=(
                self._identity(), {}, None, "ready", [])), \
             patch.object(subject, "_install_once") as install, \
             patch.object(subject, "get_value", return_value="python"), \
             contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest)])
        self.assertEqual(install.call_args.args[3], dll.resolve())
        self.assertEqual(install.call_count, 1)

    def test_v28_manifest_requires_wire5_scope_readonly_and_new_source_pins(self):
        temp, directory, manifest, _dll = self._setup_v28()
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest.read_text(encoding="utf-8"))
        subject._validate_information_battle_manifest(baseline, directory)
        cases = {
            "wrong_wire": lambda data: data.update({"information_battle_war_identity_wire": 4}),
            "wrong_scope": lambda data: data.update({"information_battle_war_identity_scope": "global"}),
            "missing_read_only": lambda data: data.pop("information_battle_war_identity_read_only"),
            "complete_must_remain_false": lambda data: data.update({"information_battle_war_identity_complete": True}),
            "missing_binding_source": lambda data: data["sources"].pop(),
            "missing_identity_switch": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_WAR_IDENTITY=1"
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v28_main_accepts_explicit_pinned_manifest_and_selects_v28_dll(self):
        temp, directory, manifest, dll = self._setup_v28()
        self.addCleanup(temp.cleanup)
        with patch.object(subject, "_wait_until_ready", return_value=(
                self._identity(), {}, None, "ready", [])), \
             patch.object(subject, "_install_once") as install, \
             patch.object(subject, "get_value", return_value="python"), \
             contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest)])
        self.assertEqual(install.call_args.args[3], dll.resolve())
        self.assertEqual(install.call_count, 1)

    def test_v23_rejects_invalid_dll_hash_before_readiness(self):
        temp, _directory, manifest, _dll = self._setup_v23()
        self.addCleanup(temp.cleanup)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["dll_sha256"] = "0" * 64
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            subject.main(["--native-text-codec", "utf8", "--pid", "52544", "--manifest", str(manifest)])
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_battle_tick_runs_after_legacy_frame_and_thread_filter(self):
        source = (Path(__file__).resolve().parents[2] /
                  "work/native/diplomacy-observer-v10.cpp").read_text(encoding="utf-8")
        frame_start = source.index('extern "C" void bridge_frame_tick')
        legacy_frame = source.index("observer_legacy_frame(context)", frame_start)
        thread_filter = source.index(
            "if (!thread_changed && frame_thread==GetCurrentThreadId())", frame_start)
        tick = source.index("information_battle_tick();", frame_start)
        branch_end = source.index(
            "    }\n#ifdef BRIDGE_INFORMATION_BATTLE\n    information_battle_tick();", thread_filter)
        self.assertLess(legacy_frame, tick)
        self.assertLess(branch_end, tick)


if __name__ == "__main__":
    unittest.main()
