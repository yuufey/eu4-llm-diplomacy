"""Offline installer admission tests for the closed v43 manifest contract."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.tests import test_start_diplomacy_observer_v42 as v42
from tools import start_diplomacy_observer as start


FLAG_INPUTS_DEFINE = "-DINFORMATION_BATTLE_FLAG_INPUTS=1"
FLAG_INPUTS_KEYS = (
    "information_battle_flag_inputs",
    "information_battle_flag_inputs_wire",
    "information_battle_flag_inputs_stage",
    "information_battle_flag_inputs_actual_widget",
)
FLAG_INPUTS_SOURCES = start.INFORMATION_BATTLE_FLAG_INPUTS_SOURCES


def _synthetic_v43(directory: Path, *, name_handoff: bool = False):
    manifest, directory = v42._synthetic_v42(
        directory, name_handoff=name_handoff)
    manifest["version"] = 43
    manifest["compiler_arguments"].append(FLAG_INPUTS_DEFINE)
    manifest.update({
        "information_battle_flag_inputs": True,
        "information_battle_flag_inputs_wire": 15,
        "information_battle_flag_inputs_stage": "formatter_container_before_cleanup",
        "information_battle_flag_inputs_actual_widget": False,
    })
    for name in FLAG_INPUTS_SOURCES:
        payload = ("synthetic-v43:" + name).encode("ascii")
        (directory / name).write_bytes(payload)
        manifest["sources"].append({
            "name": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return manifest, directory


@pytest.mark.parametrize(("name_handoff", "expected_count"), [(False, 152), (True, 155)])
def test_v43_admits_full_v42_contract_plus_two_pinned_flag_sources(
    tmp_path: Path, name_handoff: bool, expected_count: int,
):
    manifest, directory = _synthetic_v43(
        tmp_path / f"name-handoff-{name_handoff}", name_handoff=name_handoff)

    assert manifest["version"] == 43
    assert len(manifest["sources"]) == expected_count
    assert set(FLAG_INPUTS_SOURCES) <= {row["name"] for row in manifest["sources"]}
    assert "-std=c++20" in manifest["compiler_arguments"]
    assert v42.INDEPENDENT_LINE_DEFINE in manifest["compiler_arguments"]
    assert manifest["call_to_arms_observation"] is True
    start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("carrier", ["metadata", "macro"])
def test_v42_rejects_v43_flag_inputs_contract(tmp_path: Path, carrier: str):
    manifest, directory = v42._synthetic_v42(tmp_path / carrier)
    if carrier == "metadata":
        manifest[FLAG_INPUTS_KEYS[0]] = True
    else:
        manifest["compiler_arguments"].append(FLAG_INPUTS_DEFINE)

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "missing_capability", "integer_capability", "boolean_wire", "wrong_wire",
    "wrong_stage", "actual_widget_true", "missing_define", "negative_define",
    "duplicate_define", "bare_define", "missing_flag_source", "altered_flag_source_pin",
    "extra_source", "wrong_source_count", "missing_independent_line_define",
    "wrong_standard", "missing_cta_define",
])
def test_v43_rejects_incomplete_or_widened_contract(mutation: str, tmp_path: Path):
    manifest, directory = _synthetic_v43(tmp_path / mutation)
    manifest = copy.deepcopy(manifest)
    if mutation == "missing_capability":
        manifest.pop(FLAG_INPUTS_KEYS[0])
    elif mutation == "integer_capability":
        manifest[FLAG_INPUTS_KEYS[0]] = 1
    elif mutation == "boolean_wire":
        manifest[FLAG_INPUTS_KEYS[1]] = True
    elif mutation == "wrong_wire":
        manifest[FLAG_INPUTS_KEYS[1]] = 14
    elif mutation == "wrong_stage":
        manifest[FLAG_INPUTS_KEYS[2]] = "router_scope_exit"
    elif mutation == "actual_widget_true":
        manifest[FLAG_INPUTS_KEYS[3]] = True
    elif mutation == "missing_define":
        manifest["compiler_arguments"].remove(FLAG_INPUTS_DEFINE)
    elif mutation == "negative_define":
        index = manifest["compiler_arguments"].index(FLAG_INPUTS_DEFINE)
        manifest["compiler_arguments"][index] = "-DINFORMATION_BATTLE_FLAG_INPUTS=0"
    elif mutation == "duplicate_define":
        manifest["compiler_arguments"].append(FLAG_INPUTS_DEFINE)
    elif mutation == "bare_define":
        manifest["compiler_arguments"].append("-DINFORMATION_BATTLE_FLAG_INPUTS")
    elif mutation == "missing_flag_source":
        manifest["sources"] = [
            row for row in manifest["sources"] if row["name"] != FLAG_INPUTS_SOURCES[0]
        ]
    elif mutation == "altered_flag_source_pin":
        row = next(row for row in manifest["sources"]
                   if row["name"] == FLAG_INPUTS_SOURCES[0])
        row["sha256"] = "0" * 64
    elif mutation == "extra_source":
        manifest["sources"].append({"name": "unowned-v43.h", "sha256": "0" * 64})
    elif mutation == "wrong_source_count":
        manifest["sources"].append(copy.deepcopy(manifest["sources"][0]))
    elif mutation == "missing_independent_line_define":
        manifest["compiler_arguments"].remove(v42.INDEPENDENT_LINE_DEFINE)
    elif mutation == "wrong_standard":
        manifest["compiler_arguments"].remove("-std=c++20")
        manifest["compiler_arguments"].append("-std=c++17")
    else:
        manifest["compiler_arguments"].remove("-DBRIDGE_CALL_TO_ARMS_OBSERVATION=1")

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v43_admission_rejects_v45_manifest(tmp_path: Path):
    manifest, directory = _synthetic_v43(tmp_path / "v43")
    future = copy.deepcopy(manifest)
    future["version"] = 45

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(future, directory)

    manifest_path = tmp_path / "v45-manifest.json"
    manifest_path.write_text(json.dumps({"version": 45}), encoding="utf-8")
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start.main(["--pid", "123", "--manifest", str(manifest_path)])
