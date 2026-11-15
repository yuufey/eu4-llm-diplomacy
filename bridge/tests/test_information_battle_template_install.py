"""Offline v26 template-capability manifest and controller guard tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


class V26Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v26.dll"
        self.dll.write_bytes(b"synthetic-v26-observer")
        self.sources: dict[str, Path] = {}
        for name in start.INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES:
            path = self.root / name
            path.write_bytes(("synthetic-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest = {
            "version": 26,
            "experiment_id": "information-battle-template-test",
            "game_sha256": "a" * 64,
            "dll_sha256": _sha256(self.dll),
            "information_battle_research_lifecycle": True,
            "information_battle_context_wire": 2,
            "information_battle_owned_context": True,
            "information_battle_naval_wire": 3,
            "information_battle_owned_naval": True,
            "information_battle_template_wire": 4,
            "information_battle_owned_template": True,
            "information_battle_message_scope": True,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
            ],
            "sources": [
                {"name": name, "sha256": _sha256(path)}
                for name, path in self.sources.items()
            ],
        }
        self.write_manifest()

    def write_manifest(self) -> None:
        (self.root / "build-manifest.json").write_text(
            json.dumps(self.manifest, sort_keys=True), encoding="utf-8"
        )

    @property
    def manifest_path(self) -> Path:
        return self.root / "build-manifest.json"

    def close(self) -> None:
        self.temp.cleanup()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InformationBattleTemplateInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V26Fixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_v26_manifest_pins_template_sources_and_capabilities(self) -> None:
        start._validate_information_battle_manifest(self.fx.manifest, self.fx.root)
        control._validate_manifest(self.fx.manifest, self.fx.root)
        self.assertEqual(len(self.fx.manifest["sources"]), 18)
        self.assertIn("information-battle-owned-template.h", {
            row["name"] for row in self.fx.manifest["sources"]
        })
        self.assertIn("-DINFORMATION_BATTLE_TEMPLATE=1", self.fx.manifest["compiler_arguments"])

    def test_v26_rejects_missing_template_header_or_macro(self) -> None:
        header = self.fx.sources["information-battle-template-wire.h"]
        header.unlink()
        with self.assertRaises(SystemExit) as raised:
            start._validate_information_battle_manifest(self.fx.manifest, self.fx.root)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

        self.fx.close()
        self.fx = V26Fixture()
        manifest = json.loads(json.dumps(self.fx.manifest))
        manifest["compiler_arguments"].remove("-DINFORMATION_BATTLE_TEMPLATE=1")
        with self.assertRaises(control.ControlError) as raised:
            control._validate_manifest(manifest, self.fx.root)
        self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")

    def test_build_script_declares_opt_in_v26_without_changing_default(self) -> None:
        script = (Path(__file__).resolve().parents[2] /
                  "work/native/build-diplomacy-observer.ps1").read_text(encoding="utf-8")
        for marker in (
            "[switch]$InformationBattleTemplate",
            "information-battle-owned-template.h",
            "information-battle-template-wire.h",
            "information-battle-message-entry-plan.h",
            "-DINFORMATION_BATTLE_TEMPLATE=1",
            "information_battle_template_wire = 4",
            "information_battle_message_scope = $true",
        ):
            self.assertIn(marker, script)
        self.assertIn("else { 22 }", script)


if __name__ == "__main__":
    unittest.main()
