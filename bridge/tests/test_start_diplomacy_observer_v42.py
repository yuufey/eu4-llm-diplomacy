"""Offline installer admission tests for the independent-line v42 manifest."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from bridge.tests import test_call_to_arms_manifest as v41
from tools import start_diplomacy_observer as start


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "work/runtime/diplomacy-observer-20261108-independent-line-v42-278-003"
INDEPENDENT_LINE_DEFINE = "-DINFORMATION_BATTLE_INDEPENDENT_LINE=1"
INDEPENDENT_LINE_KEYS = (
    "information_battle_independent_line",
    "information_battle_independent_line_wire",
    "information_battle_independent_line_native_formatter",
    "information_battle_independent_line_stage",
    "information_battle_independent_line_actual_popup",
)


def _candidate():
    manifest_path = CANDIDATE / "build-manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8")), manifest_path


def _add_v42_contract(manifest: dict, directory: Path) -> None:
    manifest["version"] = 42
    manifest["compiler_arguments"].extend(("-std=c++20", INDEPENDENT_LINE_DEFINE))
    manifest.update({
        "information_battle_independent_line": True,
        "information_battle_independent_line_wire": 14,
        "information_battle_independent_line_native_formatter": True,
        "information_battle_independent_line_stage": "router_scope_exit",
        "information_battle_independent_line_actual_popup": False,
    })
    for name in start.INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES:
        payload = ("synthetic-v42:" + name).encode("ascii")
        (directory / name).write_bytes(payload)
        manifest["sources"].append({
            "name": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
        })


def _synthetic_v42(directory: Path, *, name_handoff: bool = False):
    directory.mkdir(parents=True)
    manifest, _dll = v41._make_v41_manifest_fixture(
        directory, name_handoff=name_handoff)
    _add_v42_contract(manifest, directory)
    return manifest, directory


def test_real_v42_candidate_is_admitted_without_dispatch(tmp_path):
    manifest, manifest_path = _candidate()
    directory = manifest_path.parent
    dll = directory / "eu4_bridge_diplomacy_observer_v42.dll"

    assert manifest["version"] == 42
    assert len(manifest["sources"]) == 150
    assert manifest["dll_sha256"] == "e991b124b1d16b7458230071a1d7ef6f665156942f2b3cb9eeb7ff5feefa77e8"
    assert start.file_hash(dll, refresh=True) == manifest["dll_sha256"]
    assert set(start.INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES) <= {
        row["name"] for row in manifest["sources"]
    }
    start._validate_information_battle_manifest(manifest, directory)

    # Use an isolated copy for mocked startup. The real candidate may already
    # be installed and its no-repeat marker must remain effective.
    isolated = tmp_path / 'candidate'
    isolated.mkdir()
    for row in manifest['sources']:
        shutil.copyfile(directory / row['name'], isolated / row['name'])
    shutil.copyfile(dll, isolated / dll.name)
    manifest_path = isolated / 'build-manifest.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    dll = isolated / dll.name

    # Exercise top-level v42 selection while keeping readiness and installation offline.
    with patch.object(start, "_wait_until_ready", return_value=(
            {"pid": 123, "creation_filetime": 456, "session_id": "offline",
             "game_sha256": manifest["game_sha256"], "modules": []},
            {}, None, "offline_test", [])), \
            patch.object(start, "_install_once") as install, \
            patch.object(start, "get_value", return_value="python"):
        start.main(["--native-text-codec", "utf8", "--pid", "123", "--manifest", str(manifest_path)])

    assert install.call_count == 1
    assert install.call_args.args[3] == dll.resolve()


@pytest.mark.parametrize(("name_handoff", "expected_count"), [(False, 150), (True, 153)])
def test_v42_preserves_v41_optional_name_handoff(
    tmp_path: Path, name_handoff: bool, expected_count: int,
):
    manifest, directory = _synthetic_v42(
        tmp_path / f"name-handoff-{name_handoff}", name_handoff=name_handoff)

    assert len(manifest["sources"]) == expected_count
    start._validate_information_battle_manifest(manifest, directory)
    assert manifest.get("information_battle_name_handoff", False) is name_handoff


@pytest.mark.parametrize(("name_handoff", "expected_count"), [(False, 145), (True, 148)])
def test_v41_source_sets_remain_valid(
    tmp_path: Path, name_handoff: bool, expected_count: int,
):
    directory = tmp_path / f"v41-name-handoff-{name_handoff}"
    directory.mkdir(parents=True)
    manifest, _dll = v41._make_v41_manifest_fixture(
        directory, name_handoff=name_handoff)

    assert len(manifest["sources"]) == expected_count
    start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "missing_capability", "capability_false", "integer_capability",
    "boolean_wire", "wrong_wire",
    "native_formatter_false", "wrong_stage", "actual_popup_true",
    "missing_define", "negative_define", "duplicate_define", "bare_define",
    "missing_standard", "wrong_standard", "duplicate_standard",
    "missing_source", "altered_source_pin", "extra_source", "wrong_source_count",
])
def test_v42_rejects_incomplete_or_widened_contract(mutation: str):
    manifest, manifest_path = _candidate()
    manifest = copy.deepcopy(manifest)
    directory = manifest_path.parent
    if mutation == "missing_capability":
        manifest.pop(INDEPENDENT_LINE_KEYS[0])
    elif mutation == "capability_false":
        manifest[INDEPENDENT_LINE_KEYS[0]] = False
    elif mutation == "integer_capability":
        manifest[INDEPENDENT_LINE_KEYS[0]] = 1
    elif mutation == "boolean_wire":
        manifest[INDEPENDENT_LINE_KEYS[1]] = True
    elif mutation == "wrong_wire":
        manifest[INDEPENDENT_LINE_KEYS[1]] = 13
    elif mutation == "native_formatter_false":
        manifest[INDEPENDENT_LINE_KEYS[2]] = False
    elif mutation == "wrong_stage":
        manifest[INDEPENDENT_LINE_KEYS[3]] = "entry_before_client_gate"
    elif mutation == "actual_popup_true":
        manifest[INDEPENDENT_LINE_KEYS[4]] = True
    elif mutation == "missing_define":
        manifest["compiler_arguments"].remove(INDEPENDENT_LINE_DEFINE)
    elif mutation == "negative_define":
        index = manifest["compiler_arguments"].index(INDEPENDENT_LINE_DEFINE)
        manifest["compiler_arguments"][index] = "-DINFORMATION_BATTLE_INDEPENDENT_LINE=0"
    elif mutation == "duplicate_define":
        manifest["compiler_arguments"].append(INDEPENDENT_LINE_DEFINE)
    elif mutation == "bare_define":
        manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_INDEPENDENT_LINE")
    elif mutation == "missing_standard":
        manifest["compiler_arguments"].remove("-std=c++20")
    elif mutation == "wrong_standard":
        manifest["compiler_arguments"].remove("-std=c++20")
        manifest["compiler_arguments"].append("-std=c++17")
    elif mutation == "duplicate_standard":
        manifest["compiler_arguments"].append("-std=c++20")
    elif mutation == "missing_source":
        manifest["sources"] = [
            row for row in manifest["sources"]
            if row["name"] != start.INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES[0]
        ]
    elif mutation == "altered_source_pin":
        row = next(row for row in manifest["sources"]
                   if row["name"] == start.INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES[0])
        row["sha256"] = "0" * 64
    elif mutation == "extra_source":
        manifest["sources"].append({"name": "unowned-v42.h", "sha256": "0" * 64})
    elif mutation == "wrong_source_count":
        manifest["sources"].append(copy.deepcopy(manifest["sources"][0]))
    else:
        manifest["sources"].pop()

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("carrier", ["metadata", "macro"])
def test_v41_rejects_v42_independent_line_contract(tmp_path: Path, carrier: str):
    directory = tmp_path / carrier
    directory.mkdir(parents=True)
    manifest, _dll = v41._make_v41_manifest_fixture(directory)
    if carrier == "metadata":
        manifest[INDEPENDENT_LINE_KEYS[0]] = True
    else:
        manifest["compiler_arguments"].append(INDEPENDENT_LINE_DEFINE)

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("carrier", ["metadata", "macro"])
def test_legacy_startup_rejects_v42_contract_before_file_or_process_access(
    tmp_path: Path, carrier: str,
):
    manifest_path = tmp_path / "build-manifest.json"
    manifest = {
        "version": 22,
        "compiler_arguments": [],
    }
    if carrier == "metadata":
        manifest[INDEPENDENT_LINE_KEYS[0]] = False
    else:
        manifest["compiler_arguments"].append(INDEPENDENT_LINE_DEFINE)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start.main(["--native-text-codec", "utf8", "--pid", "123", "--manifest", str(manifest_path)])
