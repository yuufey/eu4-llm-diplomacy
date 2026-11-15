"""Offline installer admission tests for the closed v44 support-role contract."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.tests import test_start_diplomacy_observer_v42 as v42
from bridge.tests import test_start_diplomacy_observer_v43 as v43
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start


SUPPORT_ROLE_DEFINE = "-DBRIDGE_SUPPORT_ROLE_CONTEXT=1"
SUPPORT_ROLE_SOURCE = "support-role-state.h"
SUPPORT_ROLE_FIELDS = [
    "support_roles_readable",
    "support_actor_is_subject",
    "support_recipient_is_subject",
]
SUPPORT_ROLE_KEYS = (
    "native_support_role_context",
    "native_support_role_context_read_only",
    "native_support_role_context_fields",
)
SUPPORT_ROLE_PAYLOAD = b"synthetic-v44:fixed-support-role-state-header\n"


def _synthetic_v44(directory: Path, *, name_handoff: bool = False):
    manifest, directory = v43._synthetic_v43(
        directory, name_handoff=name_handoff)
    manifest["version"] = 44
    manifest[SUPPORT_ROLE_KEYS[0]] = True
    manifest[SUPPORT_ROLE_KEYS[1]] = True
    manifest[SUPPORT_ROLE_KEYS[2]] = list(SUPPORT_ROLE_FIELDS)
    manifest["compiler_arguments"].append(SUPPORT_ROLE_DEFINE)
    (directory / SUPPORT_ROLE_SOURCE).write_bytes(SUPPORT_ROLE_PAYLOAD)
    manifest["sources"].append({
        "name": SUPPORT_ROLE_SOURCE,
        "sha256": hashlib.sha256(SUPPORT_ROLE_PAYLOAD).hexdigest(),
    })
    return manifest, directory


@pytest.mark.parametrize(("name_handoff", "expected_count"), [(False, 153), (True, 156)])
def test_v44_admits_full_v43_contract_plus_read_only_support_roles(
    tmp_path: Path, name_handoff: bool, expected_count: int,
):
    manifest, directory = _synthetic_v44(
        tmp_path / f"name-handoff-{name_handoff}", name_handoff=name_handoff)

    assert start.SUPPORT_ROLE_CONTEXT_SOURCES == (SUPPORT_ROLE_SOURCE,)
    assert start.SUPPORT_ROLE_CONTEXT_FIELDS == tuple(SUPPORT_ROLE_FIELDS)
    assert start.SUPPORT_ROLE_CONTEXT_KEYS == SUPPORT_ROLE_KEYS
    assert manifest["version"] == 44
    assert len(manifest["sources"]) == expected_count
    assert manifest[SUPPORT_ROLE_KEYS[0]] is True
    assert manifest[SUPPORT_ROLE_KEYS[1]] is True
    assert manifest[SUPPORT_ROLE_KEYS[2]] == SUPPORT_ROLE_FIELDS
    assert manifest["information_battle_flag_inputs_wire"] == 15
    assert "-std=c++20" in manifest["compiler_arguments"]
    assert v42.INDEPENDENT_LINE_DEFINE in manifest["compiler_arguments"]
    assert manifest["compiler_arguments"].count(SUPPORT_ROLE_DEFINE) == 1
    assert SUPPORT_ROLE_SOURCE in {row["name"] for row in manifest["sources"]}
    source_row = next(row for row in manifest["sources"]
                      if row["name"] == SUPPORT_ROLE_SOURCE)
    source_hash = hashlib.sha256((directory / SUPPORT_ROLE_SOURCE).read_bytes()).hexdigest()
    assert source_row["sha256"] == source_hash
    assert len(source_hash) == 64

    # Both public offline admission entry points share the same strict gate.
    start._validate_information_battle_manifest(manifest, directory)
    control._validate_manifest(manifest, directory)


@pytest.mark.parametrize("mutation", [
    "missing_capability", "false_capability", "integer_capability",
    "missing_read_only", "false_read_only", "integer_read_only", "missing_fields", "reordered_fields",
    "extra_field", "fields_not_list", "missing_define", "negative_define",
    "duplicate_define", "bare_define", "split_define", "missing_source",
    "altered_source_hash", "source_bytes_changed", "extra_source", "duplicate_source",
    "wrong_source_count", "missing_v43_define", "wrong_standard",
])
def test_v44_rejects_incomplete_or_widened_contract(mutation: str, tmp_path: Path):
    manifest, directory = _synthetic_v44(tmp_path / mutation)
    manifest = copy.deepcopy(manifest)
    if mutation == "missing_capability":
        manifest.pop(SUPPORT_ROLE_KEYS[0])
    elif mutation == "false_capability":
        manifest[SUPPORT_ROLE_KEYS[0]] = False
    elif mutation == "integer_capability":
        manifest[SUPPORT_ROLE_KEYS[0]] = 1
    elif mutation == "missing_read_only":
        manifest.pop(SUPPORT_ROLE_KEYS[1])
    elif mutation == "false_read_only":
        manifest[SUPPORT_ROLE_KEYS[1]] = False
    elif mutation == "integer_read_only":
        manifest[SUPPORT_ROLE_KEYS[1]] = 1
    elif mutation == "missing_fields":
        manifest.pop(SUPPORT_ROLE_KEYS[2])
    elif mutation == "reordered_fields":
        manifest[SUPPORT_ROLE_KEYS[2]] = list(reversed(SUPPORT_ROLE_FIELDS))
    elif mutation == "extra_field":
        manifest[SUPPORT_ROLE_KEYS[2]] = SUPPORT_ROLE_FIELDS + ["support_subject"]
    elif mutation == "fields_not_list":
        manifest[SUPPORT_ROLE_KEYS[2]] = tuple(SUPPORT_ROLE_FIELDS)
    elif mutation == "missing_define":
        manifest["compiler_arguments"].remove(SUPPORT_ROLE_DEFINE)
    elif mutation == "negative_define":
        index = manifest["compiler_arguments"].index(SUPPORT_ROLE_DEFINE)
        manifest["compiler_arguments"][index] = "-DBRIDGE_SUPPORT_ROLE_CONTEXT=0"
    elif mutation == "duplicate_define":
        manifest["compiler_arguments"].append(SUPPORT_ROLE_DEFINE)
    elif mutation == "bare_define":
        manifest["compiler_arguments"].append("-DBRIDGE_SUPPORT_ROLE_CONTEXT")
    elif mutation == "split_define":
        manifest["compiler_arguments"].extend(("-D", "BRIDGE_SUPPORT_ROLE_CONTEXT=1"))
    elif mutation == "missing_source":
        manifest["sources"] = [
            row for row in manifest["sources"] if row["name"] != SUPPORT_ROLE_SOURCE
        ]
    elif mutation == "altered_source_hash":
        row = next(row for row in manifest["sources"]
                   if row["name"] == SUPPORT_ROLE_SOURCE)
        row["sha256"] = "0" * 64
    elif mutation == "source_bytes_changed":
        (directory / SUPPORT_ROLE_SOURCE).write_bytes(b"changed-after-manifest")
    elif mutation == "extra_source":
        manifest["sources"].append({"name": "unowned-v44.h", "sha256": "0" * 64})
    elif mutation == "duplicate_source":
        manifest["sources"].append(copy.deepcopy(manifest["sources"][0]))
    elif mutation == "wrong_source_count":
        manifest["sources"].pop(0)
    elif mutation == "missing_v43_define":
        manifest["compiler_arguments"].remove(v42.INDEPENDENT_LINE_DEFINE)
    else:
        manifest["compiler_arguments"].remove("-std=c++20")
        manifest["compiler_arguments"].append("-std=c++17")

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


@pytest.mark.parametrize(("base_version", "carrier"), [
    (42, "metadata"), (42, "macro"), (43, "metadata"), (43, "macro"),
])
def test_v43_and_earlier_reject_support_role_extension(
    base_version: int, carrier: str, tmp_path: Path,
):
    if base_version == 43:
        manifest, directory = v43._synthetic_v43(tmp_path / f"v43-{carrier}")
    else:
        manifest, directory = v42._synthetic_v42(tmp_path / f"v42-{carrier}")

    if carrier == "metadata":
        manifest[SUPPORT_ROLE_KEYS[0]] = True
        manifest[SUPPORT_ROLE_KEYS[1]] = True
        manifest[SUPPORT_ROLE_KEYS[2]] = list(SUPPORT_ROLE_FIELDS)
    else:
        manifest["compiler_arguments"].append(SUPPORT_ROLE_DEFINE)

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v46_remains_outside_the_admitted_manifest_versions(tmp_path: Path):
    manifest, directory = _synthetic_v44(tmp_path / "v44")
    manifest["version"] = 46

    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)

    manifest_path = tmp_path / "v46-manifest.json"
    manifest_path.write_text(json.dumps({"version": 46}), encoding="utf-8")
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start.main(["--pid", "123", "--manifest", str(manifest_path)])
