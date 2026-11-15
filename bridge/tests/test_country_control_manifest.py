"""Strict v65 country-control admission fixtures inherit the complete v64 contract."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.country_control_ack import supports_observer_version
from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_v23 as probe


ROOT = Path(__file__).resolve().parents[2]
V64_CANDIDATE = ROOT / "work/runtime/diplomacy-observer-20261115-land-promise-v64-001"
NATIVE_SOURCE = ROOT / "work/native/diplomacy-observer-v10.cpp"
POLICY_SOURCE = ROOT / "work/native/control-country-policy.h"


def _v64_manifest():
    return json.loads((V64_CANDIDATE / "build-manifest.json").read_text(encoding="utf-8-sig"))


class _SourceOverlay:
    """Reuse the bounded v64 candidate files and override only edited inputs."""

    def __init__(self, baseline: Path, overrides: dict[str, Path]):
        self.baseline = baseline
        self.overrides = overrides

    def __truediv__(self, name: str) -> Path:
        return self.overrides.get(name, self.baseline / name)


def _v65_fixture(tmp_path, *, source_transform=None):
    manifest = deepcopy(_v64_manifest())
    source_text = NATIVE_SOURCE.read_text(encoding="utf-8")
    if source_transform is not None:
        source_text = source_transform(source_text)
    policy_bytes = POLICY_SOURCE.read_bytes()
    cpp_path = tmp_path / start.MACRO_EVENT_ACK_SOURCE
    policy_path = tmp_path / start.NATIVE_COUNTRY_CONTROL_SOURCE
    cpp_path.write_bytes(source_text.encode("utf-8"))
    policy_path.write_bytes(policy_bytes)

    manifest["version"] = 65
    manifest.update({
        "native_country_control_configuration": True,
        "native_country_control_protocol": "EU4CONTROL1",
        "native_country_control_ack": "native_controlled_countries_set",
        "native_country_control_request": "controlled-countries.req",
    })
    manifest["compiler_arguments"].append("-DBRIDGE_NATIVE_COUNTRY_CONTROL=1")
    cpp_row = next(row for row in manifest["sources"]
                   if row["name"] == start.MACRO_EVENT_ACK_SOURCE)
    cpp_row["sha256"] = hashlib.sha256(cpp_path.read_bytes()).hexdigest()
    manifest["sources"].append({
        "name": start.NATIVE_COUNTRY_CONTROL_SOURCE,
        "sha256": hashlib.sha256(policy_bytes).hexdigest(),
    })
    overlay = _SourceOverlay(V64_CANDIDATE, {
        start.MACRO_EVENT_ACK_SOURCE: cpp_path,
        start.NATIVE_COUNTRY_CONTROL_SOURCE: policy_path,
    })
    return manifest, overlay, source_text


def _reject(manifest, directory=V64_CANDIDATE):
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        start._validate_information_battle_manifest(manifest, directory)


def test_v65_country_control_contract_projects_to_v64(tmp_path):
    manifest, overlay, _ = _v65_fixture(tmp_path)
    start._validate_information_battle_manifest(manifest, overlay)
    assert manifest["version"] == 65
    assert len(manifest["sources"]) == 207


@pytest.mark.parametrize("mutation", [
    "capability_missing", "capability_integer", "protocol", "ack", "request",
    "define_missing", "define_zero", "define_duplicate", "source_missing",
    "source_duplicate", "source_hash", "legacy_file_alias",
])
def test_v65_rejects_incomplete_country_control_contract(mutation, tmp_path):
    manifest, _, _ = _v65_fixture(tmp_path)
    if mutation == "capability_missing":
        manifest.pop("native_country_control_configuration")
    elif mutation == "capability_integer":
        manifest["native_country_control_configuration"] = 1
    elif mutation == "protocol":
        manifest["native_country_control_protocol"] = "EU4COUNTRY1"
    elif mutation == "ack":
        manifest["native_country_control_ack"] = "other_event"
    elif mutation == "request":
        manifest["native_country_control_request"] = "other.req"
    elif mutation == "define_missing":
        manifest["compiler_arguments"].remove("-DBRIDGE_NATIVE_COUNTRY_CONTROL=1")
    elif mutation == "define_zero":
        manifest["compiler_arguments"][-1] = "-DBRIDGE_NATIVE_COUNTRY_CONTROL=0"
    elif mutation == "define_duplicate":
        manifest["compiler_arguments"].append("-DBRIDGE_NATIVE_COUNTRY_CONTROL=1")
    elif mutation == "source_missing":
        manifest["sources"] = [row for row in manifest["sources"]
                               if row["name"] != start.NATIVE_COUNTRY_CONTROL_SOURCE]
    elif mutation == "source_duplicate":
        row = next(row for row in manifest["sources"]
                   if row["name"] == start.NATIVE_COUNTRY_CONTROL_SOURCE)
        manifest["sources"].append(deepcopy(row))
    elif mutation == "source_hash":
        next(row for row in manifest["sources"]
             if row["name"] == start.NATIVE_COUNTRY_CONTROL_SOURCE)["sha256"] = "0" * 64
    else:
        manifest["native_country_control_file"] = "controlled-countries.req"
    _reject(manifest)


@pytest.mark.parametrize("mutation", ["ack_event", "ack_fields", "selector", "selector_duplicate"])
def test_v65_rejects_changed_native_ack_or_selector(mutation, tmp_path):
    def transform(text):
        if mutation == "ack_event":
            return text.replace(
                r'\"event\":\"native_controlled_countries_set\"',
                r'\"event\":\"other_event\"', 1)
        if mutation == "ack_fields":
            return text.replace(r'\"accepted\":%s', r'\"accepted\":%d', 1)
        block = start.NATIVE_COUNTRY_CONTROL_V65_VERSION_BLOCK
        if mutation == "selector":
            return text.replace(block, start.LAND_PROMISE_V64_VERSION_BLOCK, 1)
        return text.replace(block, block + "\n" + block, 1)

    manifest, overlay, _ = _v65_fixture(tmp_path, source_transform=transform)
    _reject(manifest, overlay)


@pytest.mark.parametrize("signal", ["metadata", "define", "source"])
def test_v64_rejects_country_control_extension_signals(signal):
    manifest = _v64_manifest()
    if signal == "metadata":
        manifest["native_country_control_configuration"] = False
    elif signal == "define":
        manifest["compiler_arguments"].append("-DBRIDGE_NATIVE_COUNTRY_CONTROL=1")
    else:
        manifest["sources"].append({
            "name": start.NATIVE_COUNTRY_CONTROL_SOURCE,
            "sha256": "0" * 64,
        })
    _reject(manifest)


def test_v65_observation_ack_inherits_v64_only_with_complete_control_identity():
    ack = {
        "version": 65,
        "native_country_control_configuration": True,
        "native_country_control_protocol": "EU4CONTROL1",
        "native_country_control_ack": "native_controlled_countries_set",
        "native_country_control_request": "controlled-countries.req",
    }
    assert supports_observer_version(ack, (64,))
    assert not supports_observer_version(ack, (63,))
    assert supports_observer_version({"version": 64}, (64,))
    for key in (
        "native_country_control_configuration",
        "native_country_control_protocol",
        "native_country_control_ack",
        "native_country_control_request",
    ):
        incomplete = dict(ack)
        incomplete.pop(key)
        assert not supports_observer_version(incomplete, (64,))
    wrong_protocol = dict(ack, native_country_control_protocol="other")
    assert not supports_observer_version(wrong_protocol, (64,))
    wrong_request = dict(ack, native_country_control_request="other.req")
    assert not supports_observer_version(wrong_request, (64,))
    assert not supports_observer_version(dict(ack, version=True), (64,))


def _physical_player_state(tag="ENG", slot=189, pointer="0x1234"):
    return {
        "player_tag": tag,
        "candidate_player_slot": slot,
        "candidate_player_pointer": pointer,
    }


def _run_ready_probe(monkeypatch, tmp_path, manifest, state):
    identity = {
        "pid": 42,
        "creation_filetime": "123",
        "session_id": "42-7b",
        "game_sha256": manifest["game_sha256"],
        "modules": [],
    }
    monkeypatch.setattr(start, "game_exe", lambda: tmp_path / "eu4.exe")
    monkeypatch.setattr(start, "probe_identity", lambda pid, _game: identity)
    monkeypatch.setattr(start, "get_value", lambda _name: "fixture-python")
    monkeypatch.setattr(start, "_preflight_once", lambda *_args: (state, {"reason": "PREFLIGHT_READY"}))
    monkeypatch.setattr(start, "_waiting", lambda *_args, **_kwargs: None)

    def attempt_directory(directory, attempt):
        path = directory / f"ready-attempt-{attempt}"
        path.mkdir()
        return path

    monkeypatch.setattr(start, "_attempt_directory", attempt_directory)
    return start._wait_until_ready(42, manifest, tmp_path, False, 3)


def test_v65_accepts_verified_non_por_physical_player(monkeypatch, tmp_path):
    manifest, _, _ = _v65_fixture(tmp_path)
    identity, state, _confirmation, reason, _attempts = _run_ready_probe(
        monkeypatch, tmp_path, manifest, _physical_player_state())
    assert identity["session_id"] == "42-7b"
    assert state["player_tag"] == "ENG"
    assert reason == "physical_player_already_loaded"


@pytest.mark.parametrize("state", [
    _physical_player_state(slot=True),
    _physical_player_state(pointer="0x0"),
    _physical_player_state(tag="eng"),
])
def test_v65_rejects_incomplete_physical_player_identity(monkeypatch, tmp_path, state):
    manifest, _, _ = _v65_fixture(tmp_path)
    with pytest.raises(SystemExit, match="V65_PHYSICAL_PLAYER_IDENTITY_INVALID"):
        _run_ready_probe(monkeypatch, tmp_path, manifest, state)


def test_legacy_v64_still_rejects_non_por_player(monkeypatch, tmp_path):
    manifest = _v64_manifest()
    with pytest.raises(SystemExit, match="FIXED_CONTROL_REQUIRES_UNLOADED_OR_POR_TEST_SAVE"):
        _run_ready_probe(monkeypatch, tmp_path, manifest, _physical_player_state())


def _built_v65_candidate():
    fixed = ROOT / "work/runtime/country-control-20261115-001"
    candidates = [fixed]
    candidates.extend(path for path in (ROOT / "work/runtime").glob("*")
                      if path.is_dir() and "country-control" in path.name.lower())
    for candidate in candidates:
        manifest_path = candidate / "build-manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if manifest.get("version") == 65:
            return candidate, manifest
    return None, None


def test_built_v65_candidate_passes_all_static_entries():
    candidate, manifest = _built_v65_candidate()
    if candidate is None:
        pytest.skip("offline v65 native build is not available yet")
    start._validate_information_battle_manifest(manifest, candidate)
    control._validate_manifest(manifest, candidate)
    result = probe._manifest_static_guard(candidate)
    assert result["status"] == "observed"
    assert not result["unknown_conditions"]
    assert result["observer_version"] == 65
    assert result["source_count"] == 207
