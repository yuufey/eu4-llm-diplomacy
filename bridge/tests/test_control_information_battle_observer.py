"""Narrow file-protocol tests for the v23-v32 battle source controller."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


PLAYER = "1234567890abcdef"
GAME_SHA = "a" * 64


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StrictV29ManifestFixture:
    """A complete v29/native-text manifest for the real start validator."""

    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sources: dict[str, Path] = {}
        required = list(start.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES)
        names = required + [
            f"observer-build-source-{index:03d}.inc"
            for index in range(116 - len(required))
        ]
        for name in names:
            path = self.root / name
            path.write_bytes(("synthetic-v29-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest = {
            "version": 29,
            "experiment_id": "information-battle-native-text-control-test",
            "game_sha256": GAME_SHA,
            "dll_sha256": "b" * 64,
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
            "information_battle_native_text": True,
            "information_battle_native_text_wire": 6,
            "information_battle_native_text_scope": "observer_session",
            "information_battle_native_text_read_only": True,
            "information_battle_native_text_complete": False,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
                "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
                "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
            ],
            "sources": [
                {"name": name, "sha256": _sha256(path)}
                for name, path in self.sources.items()
            ],
        }

    def close(self) -> None:
        self.temp.cleanup()


class StrictV30ManifestFixture(StrictV29ManifestFixture):
    """A complete v30 manifest with title-query helper-owned output metadata."""

    def __init__(self) -> None:
        super().__init__()
        for name in start.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES[-2:]:
            path = self.root / name
            path.write_bytes(("synthetic-v30-source:" + name).encode("ascii"))
            self.sources[name] = path
            self.manifest["sources"].append({
                "name": name,
                "sha256": _sha256(path),
            })
        self.manifest.update({
            "version": 30,
            "experiment_id": "information-battle-native-title-query-control-test",
            "information_battle_native_title_query": True,
            "information_battle_native_title_query_mode": "native_helper_owned_output",
            "information_battle_native_title_query_wire": 6,
            "information_battle_native_title_query_complete": False,
            "compiler_arguments": self.manifest["compiler_arguments"] + [
                "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
            ],
        })


class StrictV32ManifestFixture(StrictV30ManifestFixture):
    """A v32 gate-trace manifest that inherits v30 without control support."""

    def __init__(self) -> None:
        super().__init__()
        for name in start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES[-3:]:
            path = self.root / name
            path.write_bytes(("synthetic-v32-source:" + name).encode("ascii"))
            self.sources[name] = path
            self.manifest["sources"].append({
                "name": name,
                "sha256": _sha256(path),
            })
        self.manifest.update({
            "version": 32,
            "experiment_id": "information-battle-gate-trace-control-test",
            "information_battle_gate_trace": True,
            "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
            "information_battle_gate_trace_runtime_verified": False,
            "compiler_arguments": self.manifest["compiler_arguments"] + [
                "-DINFORMATION_BATTLE_GATE_TRACE=1",
            ],
        })


class StrictV36ManifestFixture(StrictV32ManifestFixture):
    """A v36 manifest with end-state wire9 and only name-header dependencies."""

    def __init__(self) -> None:
        super().__init__()
        for path in self.sources.values():
            path.unlink(missing_ok=True)
        names = (set(start.INFORMATION_BATTLE_V33_SOURCE_NAMES)
                 | set(start.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
                 | set(start.INFORMATION_BATTLE_END_STATE_SOURCES)
                 | set(start.INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES))
        self.sources = {}
        records = []
        for name in sorted(names):
            path = self.root / name
            path.write_bytes(("synthetic-v36-source:" + name).encode("ascii"))
            self.sources[name] = path
            records.append({"name": name, "sha256": _sha256(path)})
        arguments = self.manifest["compiler_arguments"] + [
            "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1",
            "-DBRIDGE_DEBT_QUOTE_QUERY=1",
            "-DINFORMATION_BATTLE_END_STATE=1",
        ]
        self.manifest.update({
            "version": 36,
            "experiment_id": "information-battle-end-state-control-test",
            "native_war_participants_query": True,
            "information_battle_display_context": True,
            "information_battle_display_context_wire": 7,
            "information_battle_display_context_scope": "same_battle_event",
            "information_battle_display_context_stage": "router_scope_exit",
            "information_battle_display_context_read_only": True,
            "information_battle_display_context_complete": False,
            "information_debt_quote_query": True,
            "information_debt_quote_query_wire": 1,
            "information_debt_quote_read_only": True,
            "information_debt_quote_fp_context": True,
            "information_battle_end_state": True,
            "information_battle_end_state_wire": 9,
            "information_battle_end_state_complete": False,
            "information_battle_name_handoff": False,
            "compiler_arguments": arguments,
            "sources": records,
        })


class ControlFixture:
    def __init__(self, version: int = 23) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.installation_path = self.root / "installation.json"
        self.version = version
        self.dll = self.root / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        self.dll.write_bytes(f"synthetic-v{version}-dll".encode("ascii"))
        self.dll_sha = hashlib.sha256(self.dll.read_bytes()).hexdigest()
        self.manifest = {
            "version": version,
            "game_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
            "information_battle_research_lifecycle": True,
        }
        if version == 28:
            self.manifest.update({
                "information_battle_war_identity": True,
                "information_battle_war_identity_wire": 5,
                "information_battle_war_identity_scope": "observer_session",
                "information_battle_war_identity_read_only": True,
                "information_battle_war_identity_complete": False,
            })
        (self.root / "build-manifest.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )
        self.installation = {
            "pid": 43210,
            "creation_filetime": 99887766,
            "game_sha256": GAME_SHA,
            "session_id": "43210-test-session",
            "dll_sha256": self.dll_sha,
            "modules_after_install": [{
                "name": self.dll.name,
                "path": str(self.dll),
                "sha256": self.dll_sha,
            }],
        }
        self.installation_path.write_text(json.dumps(self.installation), encoding="utf-8")
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
        self.patches = mock.patch.multiple(
            control,
            _validate_information_battle_manifest=mock.Mock(),
            probe_identity=mock.Mock(return_value=self.identity),
            game_exe=mock.Mock(return_value=self.root / "eu4.exe"),
        )
        self.patches.start()

    def close(self) -> None:
        self.patches.stop()
        self.temp.cleanup()

    def status(self, *, state: str = "ready", installation: str = "0", generation: str = "0") -> Path:
        path = self.root / control.STATUS_NAME
        value = {
            "schema": "EU4-BATTLE-SOURCE/1",
            "request_id": "startup",
            "command": "startup",
            "accepted": True,
            "reason": "awaiting_process_bound_enable",
            "state": state,
            "pid": self.installation["pid"],
            "creation_filetime": str(self.installation["creation_filetime"]),
            "installation": installation,
            "generation": generation,
            "exe_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
        }
        path.write_text(json.dumps(value), encoding="utf-8")
        return path


class InformationBattleControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = ControlFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_request_is_exactly_eight_ascii_tokens_and_no_observer_guess(self) -> None:
        context = control._load_context(self.fx.installation_path)
        payload = control._request_line(
            nonce="ab" * 16,
            command="enable",
            context=context,
            installation=7,
            player_ref=PLAYER,
        )
        tokens = payload.decode("ascii").rstrip("\n").split(" ")
        self.assertEqual(len(tokens), 8)
        self.assertEqual(tokens[0], "EU4BATTLE1")
        self.assertEqual(tokens[2], "enable")
        self.assertEqual(tokens[7], PLAYER)
        self.assertNotIn("FRA", payload.decode("ascii"))
        for bad in (PLAYER.upper(), "123", "0" * 16, "1234567890abcde!"):
            with self.subTest(bad=bad):
                with self.assertRaises(control.ControlError) as caught:
                    control._validate_player_ref(bad)
                self.assertEqual(caught.exception.reason, "PLAYER_REF_INVALID")

    def test_v28_manifest_is_accepted_only_as_explicit_versioned_context(self) -> None:
        fx = ControlFixture(version=28)
        try:
            context = control._load_context(fx.installation_path)
            self.assertEqual(context.manifest["version"], 28)
            self.assertEqual(context.dll_path, fx.dll.resolve())
        finally:
            fx.close()

    def test_v29_manifest_uses_strict_native_text_wire6_and_116_sources(self) -> None:
        self.fx.patches.stop()
        fx = StrictV29ManifestFixture()
        try:
            start._validate_information_battle_manifest(fx.manifest, fx.root)
            control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(fx.manifest["version"], 29)
            self.assertEqual(len(fx.manifest["sources"]), 116)
            self.assertEqual(fx.manifest["information_battle_native_text_wire"], 6)
            self.assertIn("-DINFORMATION_BATTLE_NATIVE_TEXT=1",
                          fx.manifest["compiler_arguments"])
        finally:
            fx.close()

    def test_v29_native_text_metadata_and_macro_are_required(self) -> None:
        self.fx.patches.stop()
        cases = (
            ("information_battle_native_text", False),
            ("information_battle_native_text_wire", 5),
            ("information_battle_native_text_scope", "process"),
            ("information_battle_native_text_read_only", False),
            ("information_battle_native_text_complete", True),
        )
        for key, value in cases:
            fx = StrictV29ManifestFixture()
            try:
                fx.manifest[key] = value
                with self.subTest(key=key):
                    with self.assertRaises(SystemExit) as raised:
                        start._validate_information_battle_manifest(
                            fx.manifest, fx.root
                        )
                    self.assertEqual(str(raised.exception),
                                     "BUILD_MANIFEST_MISMATCH")
            finally:
                fx.close()

        fx = StrictV29ManifestFixture()
        try:
            fx.manifest["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_NATIVE_TEXT=1"
            )
            with self.assertRaises(control.ControlError) as raised:
                control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")
        finally:
            fx.close()

    def test_v29_missing_native_text_source_is_rejected_by_both_validators(self) -> None:
        self.fx.patches.stop()
        fx = StrictV29ManifestFixture()
        try:
            fx.manifest["sources"] = [
                row for row in fx.manifest["sources"]
                if row["name"] != "information-battle-native-text-wire.h"
            ]
            with self.assertRaises(SystemExit) as raised:
                start._validate_information_battle_manifest(fx.manifest, fx.root)
            self.assertEqual(str(raised.exception),
                             "BUILD_MANIFEST_MISMATCH")
            with self.assertRaises(control.ControlError) as raised:
                control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")
        finally:
            fx.close()

    def test_v30_manifest_uses_wire6_title_metadata_and_118_sources(self) -> None:
        self.fx.patches.stop()
        fx = StrictV30ManifestFixture()
        try:
            start._validate_information_battle_manifest(fx.manifest, fx.root)
            control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(fx.manifest["version"], 30)
            self.assertEqual(len(fx.manifest["sources"]), 118)
            self.assertEqual(
                fx.manifest["information_battle_native_title_query_mode"],
                "native_helper_owned_output",
            )
            self.assertEqual(fx.manifest["information_battle_native_title_query_wire"], 6)
            self.assertFalse(fx.manifest["information_battle_native_title_query_complete"])
            self.assertIn(
                "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
                fx.manifest["compiler_arguments"],
            )
        finally:
            fx.close()

    def test_v30_title_metadata_and_source_count_are_strict(self) -> None:
        self.fx.patches.stop()
        cases = (
            ("information_battle_native_title_query", False),
            ("information_battle_native_title_query_mode", "runtime"),
            ("information_battle_native_title_query_wire", 5),
            ("information_battle_native_title_query_complete", True),
        )
        for key, value in cases:
            fx = StrictV30ManifestFixture()
            try:
                fx.manifest[key] = value
                with self.subTest(key=key):
                    with self.assertRaises(SystemExit) as raised:
                        start._validate_information_battle_manifest(fx.manifest, fx.root)
                    self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")
            finally:
                fx.close()

        fx = StrictV30ManifestFixture()
        try:
            fx.manifest["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1"
            )
            with self.assertRaises(control.ControlError) as raised:
                control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")
        finally:
            fx.close()

    def test_v32_gate_trace_manifest_is_strict_and_accepted_by_start_and_control(self) -> None:
        self.fx.patches.stop()
        fx = StrictV32ManifestFixture()
        try:
            start._validate_information_battle_manifest(fx.manifest, fx.root)
            control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(fx.manifest["version"], 32)
            self.assertEqual(len(fx.manifest["sources"]), 121)
            self.assertTrue(
                set(start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES)
                <= {row["name"] for row in fx.manifest["sources"]}
            )
            self.assertFalse(fx.manifest["information_battle_gate_trace_runtime_verified"])

            for bad_define in (
                "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1",
                "-DINFORMATION_CURRENT_COUNTRY_HOST_FIXTURE=1",
            ):
                mutated = json.loads(json.dumps(fx.manifest))
                mutated["compiler_arguments"].append(bad_define)
                with self.subTest(bad_define=bad_define):
                    with self.assertRaises(control.ControlError) as raised:
                        control._validate_manifest(mutated, fx.root)
                    self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")
        finally:
            fx.close()

        fx = StrictV30ManifestFixture()
        try:
            fx.manifest["sources"] = fx.manifest["sources"][:-1]
            with self.assertRaises(SystemExit) as raised:
                start._validate_information_battle_manifest(fx.manifest, fx.root)
            self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")
        finally:
            fx.close()

    def test_v36_end_state_manifest_is_accepted_by_start_and_control(self) -> None:
        self.fx.patches.stop()
        fx = StrictV36ManifestFixture()
        try:
            start._validate_information_battle_manifest(fx.manifest, fx.root)
            control._validate_manifest(fx.manifest, fx.root)
            self.assertEqual(fx.manifest["version"], 36)
            self.assertEqual(len(fx.manifest["sources"]), 131)
            self.assertTrue(
                set(start.INFORMATION_BATTLE_END_STATE_SOURCES)
                <= {row["name"] for row in fx.manifest["sources"]}
            )
            self.assertTrue(
                set(start.INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES)
                <= {row["name"] for row in fx.manifest["sources"]}
            )
            self.assertFalse(fx.manifest["information_battle_name_handoff"])
            self.assertNotIn(
                "information-battle-name-handoff-observer-stub.S",
                fx.sources,
            )
        finally:
            fx.close()

    def test_v36_status_enable_manifest_validation_rejects_bad_end_state_or_hook_claims(self) -> None:
        self.fx.patches.stop()
        fx = StrictV36ManifestFixture()
        try:
            mutations = {
                "wrong_wire": lambda data: data.update({
                    "information_battle_end_state_wire": 8
                }),
                "boolean_wire": lambda data: data.update({
                    "information_battle_end_state_wire": True
                }),
                "complete_must_be_false": lambda data: data.update({
                    "information_battle_end_state_complete": True
                }),
                "missing_macro": lambda data: data["compiler_arguments"].remove(
                    "-DINFORMATION_BATTLE_END_STATE=1"
                ),
                "missing_source": lambda data: data["sources"].pop(),
                "hook_source_without_enable": lambda data: data["sources"].append({
                    "name": "information-battle-name-handoff-observer-stub.S",
                    "sha256": "0" * 64,
                }),
                "enable_without_full_v35_contract": lambda data: data.update({
                    "information_battle_name_handoff": True
                }),
                "current_country_control_macro_forbidden": lambda data: data[
                    "compiler_arguments"
                ].append("-DBRIDGE_CURRENT_COUNTRY_CONTROL=1"),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    manifest = json.loads(json.dumps(fx.manifest))
                    mutate(manifest)
                    with self.assertRaises(control.ControlError) as raised:
                        control._validate_manifest(manifest, fx.root)
                    self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")
        finally:
            fx.close()

    def test_information_battle_ack_conversion_produces_23_and_legacy_stays_22(self) -> None:
        native = (control.ROOT / "work" / "native" / "diplomacy-observer-v10.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("version_marker[sizeof(\"\\\"version\\\":\")]='3'", native)
        base = bytearray(b'{"event":"diplomacy_observer_installed","version":22,"pid":1}\n')
        marker = b'"version":22'
        offset = base.index(marker) + len(b'"version":') + 1
        base[offset] = ord("3")  # C sizeof(prefix) includes its NUL: the second digit.
        self.assertIn(b'"version":23', bytes(base))
        legacy = bytearray(b'{"event":"diplomacy_observer_installed","version":22,"pid":1}\n')
        self.assertIn(b'"version":22', bytes(legacy))
        self.assertNotIn(b'"version":23', bytes(legacy))

    def test_status_is_read_only_and_ready_zero_installation_is_allowed(self) -> None:
        self.fx.status()
        result = control.run_control(self.fx.installation_path, "status")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["installation"], "0")
        self.assertFalse((self.fx.root / control.BINDING_NAME).exists())
        self.assertFalse((self.fx.root / control.CONTROL_NAME).exists())

    def test_status_timestamp_does_not_advance_when_heartbeat_changes_during_read(self) -> None:
        self.fx.status()
        status_path = self.fx.root / control.STATUS_NAME
        stamp = time.time_ns() - 1_000_000_000
        os.utime(status_path, ns=(stamp, stamp))
        expected = status_path.stat().st_mtime_ns
        original_read = control._read_json

        def read_then_publish(path, **kwargs):
            result = original_read(path, **kwargs)
            if Path(path).name == control.STATUS_NAME:
                newer = time.time_ns()
                os.utime(status_path, ns=(newer, newer))
            return result

        with mock.patch.object(control, "_read_json", side_effect=read_then_publish):
            result = control.run_control(self.fx.installation_path, "status")
        self.assertEqual(result["observed_at_ns"], expected)
        self.assertGreater(status_path.stat().st_mtime_ns, result["observed_at_ns"])
        self.assertFalse((self.fx.root / control.CONTROL_NAME).exists())

    def test_unbound_restart_required_status_is_observable(self) -> None:
        self.fx.status(state="restart_required")
        result = control.run_control(self.fx.installation_path, "status")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["installation"], "0")

    def test_unbound_fault_and_source_changed_are_diagnostic_only(self) -> None:
        for state in ("fault", "source_changed"):
            with self.subTest(state=state):
                self.fx.status(state=state)
                result = control.run_control(self.fx.installation_path, "status")
                self.assertEqual(result["status"], "observed")
                self.assertEqual(result["installation"], "0")

    def test_unbound_enabled_status_is_rejected(self) -> None:
        self.fx.status(state="enabled", installation="0", generation="0")
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "status")
        self.assertEqual(caught.exception.reason, "STATUS_IDENTITY_MISMATCH")

    def test_status_stale_is_rejected(self) -> None:
        path = self.fx.status()
        old = time.time() - control.MAX_STATUS_AGE_SECONDS - 1
        os.utime(path, (old, old))
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "status")
        self.assertEqual(caught.exception.reason, "NATIVE_STATUS_STALE")

    def test_bound_status_uses_process_creation_generation(self) -> None:
        context = control._load_context(self.fx.installation_path)
        binding = control._ensure_binding(context, PLAYER)
        self.fx.status(
            state="enabled",
            installation=str(binding["installation"]),
            generation=str(self.fx.installation["creation_filetime"]),
        )
        result = control.run_control(self.fx.installation_path, "status")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["binding"]["generation"], self.fx.installation["creation_filetime"])
        self.fx.status(
            state="enabled",
            installation=str(binding["installation"]),
            generation="1",
        )
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "status")
        self.assertEqual(caught.exception.reason, "STATUS_IDENTITY_MISMATCH")

    def test_preflight_rejects_changed_process_creation(self) -> None:
        changed = dict(self.fx.identity)
        changed["creation_filetime"] += 1
        control.probe_identity.return_value = changed
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "status")
        self.assertEqual(caught.exception.reason, "PROCESS_IDENTITY_MISMATCH")

    def _response_writer(self, *, accepted: bool, installation: str | None = None, pid: int | None = None) -> threading.Thread:
        def write_response() -> None:
            deadline = time.monotonic() + 2
            request = self.fx.root / control.CONTROL_NAME
            while not request.exists() and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertTrue(request.exists())
            tokens = request.read_text(encoding="ascii").rstrip("\n").split(" ")
            nonce = tokens[1]
            binding = json.loads((self.fx.root / control.BINDING_NAME).read_text(encoding="utf-8"))
            response = {
                "request_id": nonce,
                "command": tokens[2],
                "accepted": accepted,
                "reason": "capture_enabled" if accepted else "native_rejected",
                "state": "enabled" if accepted else "ready",
                "pid": self.fx.installation["pid"] if pid is None else pid,
                "creation_filetime": str(self.fx.installation["creation_filetime"]),
                "installation": str(binding["installation"] if installation is None else installation),
                "generation": str(
                    binding["generation"] if installation is None or installation != "0" else 0
                ),
                "dll_sha256": self.fx.dll_sha,
            }
            (self.fx.root / f"{control.RESPONSE_PREFIX}{nonce}.json").write_text(
                json.dumps(response), encoding="utf-8"
            )

        worker = threading.Thread(target=write_response, daemon=True)
        worker.start()
        return worker

    def test_enable_creates_stable_binding_and_accepts_matching_response(self) -> None:
        worker = self._response_writer(accepted=True)
        result = control.run_control(self.fx.installation_path, "enable", PLAYER)
        worker.join(timeout=2)
        self.assertEqual(result["status"], "accepted")
        binding = json.loads((self.fx.root / control.BINDING_NAME).read_text(encoding="utf-8"))
        self.assertEqual(binding["player_ref"], PLAYER)
        self.assertEqual(binding["generation"], str(self.fx.installation["creation_filetime"]))
        self.assertNotEqual(int(binding["installation"]), 0)
        request = (self.fx.root / control.CONTROL_NAME).read_text(encoding="ascii")
        self.assertEqual(len(request.rstrip("\n").split(" ")), 8)
        audits = list(self.fx.root.glob(f"{control.AUDIT_PREFIX}*.jsonl"))
        self.assertEqual(len(audits), 1)
        self.assertGreaterEqual(len(audits[0].read_text(encoding="utf-8").splitlines()), 2)
        context = control._load_context(self.fx.installation_path)
        again = control._ensure_binding(context, PLAYER)
        self.assertEqual(int(again["installation"]), int(binding["installation"]))

    def test_existing_request_is_never_overwritten(self) -> None:
        request = self.fx.root / control.CONTROL_NAME
        request.write_bytes(b"old request\n")
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "enable", PLAYER)
        self.assertEqual(caught.exception.reason, "CONTROL_BUSY")
        self.assertEqual(request.read_bytes(), b"old request\n")

    def test_processing_file_also_blocks_repost(self) -> None:
        processing = self.fx.root / control.PROCESSING_NAME
        processing.write_bytes(b"native is processing")
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "enable", PLAYER)
        self.assertEqual(caught.exception.reason, "CONTROL_BUSY")
        self.assertEqual(processing.read_bytes(), b"native is processing")

    def test_timeout_is_unknown_no_retry_and_leaves_request(self) -> None:
        with mock.patch.object(control, "RESPONSE_TIMEOUT_SECONDS", 0.02), mock.patch.object(
            control, "RESPONSE_POLL_SECONDS", 0.001
        ):
            result = control.run_control(self.fx.installation_path, "enable", PLAYER)
        self.assertEqual(result["status"], "unknown_no_retry")
        self.assertTrue((self.fx.root / control.CONTROL_NAME).exists())
        audit = next(self.fx.root.glob(f"{control.AUDIT_PREFIX}*.jsonl"))
        self.assertIn("unknown_no_retry", audit.read_text(encoding="utf-8"))

    def test_response_identity_mismatch_is_not_accepted(self) -> None:
        worker = self._response_writer(accepted=True, pid=99999)
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "enable", PLAYER)
        worker.join(timeout=2)
        self.assertEqual(caught.exception.reason, "RESPONSE_IDENTITY_MISMATCH")

    def test_failed_first_enable_may_report_installation_zero_but_is_rejected(self) -> None:
        worker = self._response_writer(accepted=False, installation="0")
        result = control.run_control(self.fx.installation_path, "enable", PLAYER)
        worker.join(timeout=2)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["installation"], "0")

    def test_unbound_disable_rejection_is_known_but_wrong_generation_is_not(self) -> None:
        context = control._load_context(self.fx.installation_path)
        nonce = "cd" * 16
        response = {
            "request_id": nonce,
            "command": "disable",
            "accepted": False,
            "reason": "unbound_source",
            "pid": self.fx.installation["pid"],
            "creation_filetime": str(self.fx.installation["creation_filetime"]),
            "installation": "0",
            "generation": "0",
            "dll_sha256": self.fx.dll_sha,
        }
        result = control._validate_response(
            context, nonce=nonce, command="disable", installation=17, response=response
        )
        self.assertEqual(result["status"], "rejected")
        response["generation"] = "1"
        with self.assertRaises(control.ControlError) as caught:
            control._validate_response(
                context, nonce=nonce, command="disable", installation=17, response=response
            )
        self.assertEqual(caught.exception.reason, "RESPONSE_IDENTITY_MISMATCH")
        response["installation"] = "17"
        response["generation"] = "1"
        with self.assertRaises(control.ControlError) as caught:
            control._validate_response(
                context, nonce=nonce, command="disable", installation=17, response=response
            )
        self.assertEqual(caught.exception.reason, "RESPONSE_IDENTITY_MISMATCH")

    def test_disable_requires_existing_binding_and_uses_stored_player(self) -> None:
        with self.assertRaises(control.ControlError) as caught:
            control.run_control(self.fx.installation_path, "disable")
        self.assertEqual(caught.exception.reason, "BINDING_REQUIRED")

    def test_binding_creation_is_concurrent_stable(self) -> None:
        context = control._load_context(self.fx.installation_path)
        values: list[dict[str, object]] = []
        failures: list[BaseException] = []

        def create() -> None:
            try:
                values.append(control._ensure_binding(context, PLAYER))
            except BaseException as exc:  # test should expose a race, not hide it
                failures.append(exc)

        workers = [threading.Thread(target=create) for _ in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)
        self.assertFalse(failures)
        self.assertEqual(len(values), 4)
        self.assertEqual({int(value["installation"]) for value in values}, {int(values[0]["installation"])})


if __name__ == "__main__":
    unittest.main()
