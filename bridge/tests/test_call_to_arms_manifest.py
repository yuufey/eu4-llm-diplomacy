"""Strict synthetic v41 admission checks for call-to-arms observation."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.tests import test_information_battle_v40_manifest as v40
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


CALL_TO_ARMS_SOURCE = "call-to-arms-observer.inc"
CALL_TO_ARMS_DEFINE = "-DBRIDGE_CALL_TO_ARMS_OBSERVATION=1"
CALL_TO_ARMS_KEYS = (
    "call_to_arms_observation",
    "call_to_arms_ai_response_held",
    "call_to_arms_execution",
)


def _make_v41_manifest_fixture(directory: Path, *, name_handoff: bool = False):
    manifest, old_dll = v40._make_v40_manifest_fixture(
        directory, name_handoff=name_handoff)
    old_dll.unlink()
    dll = directory / "eu4_bridge_diplomacy_observer_v41.dll"
    dll.write_bytes(b"synthetic-v41-call-to-arms-dll")
    manifest.update(
        version=41,
        dll=str(dll.resolve()),
        dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest(),
        call_to_arms_observation=True,
        call_to_arms_ai_response_held=False,
        call_to_arms_execution=False,
    )
    manifest["compiler_arguments"].append(CALL_TO_ARMS_DEFINE)
    source = directory / CALL_TO_ARMS_SOURCE
    payload = b"synthetic-v41-call-to-arms-observer.inc"
    source.write_bytes(payload)
    manifest["sources"].append({
        "name": CALL_TO_ARMS_SOURCE,
        "sha256": hashlib.sha256(payload).hexdigest(),
    })
    (directory / "build-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    return manifest, dll


@pytest.mark.parametrize(("name_handoff", "expected_sources"), [(False, 145), (True, 148)])
def test_v41_admits_complete_v40_source_set_plus_pinned_call_to_arms(
    tmp_path: Path, name_handoff: bool, expected_sources: int
):
    directory = tmp_path / f"v41-name-handoff-{name_handoff}"
    manifest, _dll = _make_v41_manifest_fixture(
        directory, name_handoff=name_handoff)
    names = {record["name"] for record in manifest["sources"]}

    assert len(manifest["sources"]) == expected_sources
    assert set(start.INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES) <= names
    assert CALL_TO_ARMS_SOURCE in names
    assert manifest[CALL_TO_ARMS_KEYS[0]] is True
    assert manifest[CALL_TO_ARMS_KEYS[1]] is False
    assert manifest[CALL_TO_ARMS_KEYS[2]] is False
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "missing_define", "wrong_define", "duplicate_define",
    "observation_disabled", "ai_response_held", "execution_enabled",
    "missing_source", "wrong_source_pin", "duplicate_source", "extra_source",
    "missing_v40_tail_source", "missing_v40_tail_define",
])
def test_v41_rejects_missing_wrong_or_unpinned_call_to_arms_contract(
    tmp_path: Path, mutation: str
):
    directory = tmp_path / mutation
    manifest, _dll = _make_v41_manifest_fixture(directory)
    arguments = manifest["compiler_arguments"]
    source_row = next(row for row in manifest["sources"]
                      if row["name"] == CALL_TO_ARMS_SOURCE)

    if mutation == "missing_define":
        arguments.remove(CALL_TO_ARMS_DEFINE)
    elif mutation == "wrong_define":
        arguments[arguments.index(CALL_TO_ARMS_DEFINE)] = (
            "-DBRIDGE_CALL_TO_ARMS_OBSERVATION=0")
    elif mutation == "duplicate_define":
        arguments.append(CALL_TO_ARMS_DEFINE)
    elif mutation == "observation_disabled":
        manifest[CALL_TO_ARMS_KEYS[0]] = False
    elif mutation == "ai_response_held":
        manifest[CALL_TO_ARMS_KEYS[1]] = True
    elif mutation == "execution_enabled":
        manifest[CALL_TO_ARMS_KEYS[2]] = True
    elif mutation == "missing_source":
        manifest["sources"] = [row for row in manifest["sources"]
                               if row["name"] != CALL_TO_ARMS_SOURCE]
    elif mutation == "wrong_source_pin":
        source_row["sha256"] = "0" * 64
    elif mutation == "duplicate_source":
        manifest["sources"].append(copy.deepcopy(source_row))
    elif mutation == "extra_source":
        name, payload = "unowned-call-to-arms-fixture.h", b"unowned source"
        (directory / name).write_bytes(payload)
        manifest["sources"].append({
            "name": name, "sha256": hashlib.sha256(payload).hexdigest(),
        })
    elif mutation == "missing_v40_tail_source":
        tail_source = start.INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES[0]
        manifest["sources"] = [row for row in manifest["sources"]
                               if row["name"] != tail_source]
    else:
        arguments.remove("-DINFORMATION_BATTLE_OUTCOME_TAIL=1")

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("carrier", ["define", "manifest_key"])
def test_v40_rejects_call_to_arms_contract_fields(tmp_path: Path, carrier: str):
    directory = tmp_path / carrier
    manifest, _dll = v40._make_v40_manifest_fixture(directory)
    if carrier == "define":
        manifest["compiler_arguments"].append(CALL_TO_ARMS_DEFINE)
    else:
        manifest[CALL_TO_ARMS_KEYS[0]] = True

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v22_startup_rejects_call_to_arms_macro_before_dll_or_process_access(
    tmp_path: Path,
):
    directory = tmp_path / "v22"
    directory.mkdir()
    manifest_path = directory / "build-manifest.json"
    manifest_path.write_text(json.dumps({
        "version": 22,
        "compiler_arguments": [CALL_TO_ARMS_DEFINE],
    }), encoding="utf-8")

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start.main(["--pid", "123", "--manifest", str(manifest_path)])
