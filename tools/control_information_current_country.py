"""Operator-only, one-shot test control for a physical EU4 country switch.

This client is deliberately separate from information queries and business
commands.  It writes one TEST_ONLY request only after validating the installed
v31 build, process identity, native readiness, battle-source state, and an
independent bounded read-only world snapshot.  A published request is never
retried, including on timeout.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "work") not in sys.path:
    sys.path.insert(0, str(ROOT / "work"))

from bridge.diplomacy_session import probe_identity  # noqa: E402
from bridge.information import country_resources_memory as _country_memory  # noqa: E402
from bridge.information import localization_memory as _localization_memory  # noqa: E402
from local_config import game_exe  # noqa: E402


PROTOCOL = "EU4COUNTRY1"
PROTOCOL_PATH = ROOT / "work/runtime/information-battle-recipient-20261028-001/control-protocol-001.json"
REQUEST_NAME = "information-country-control.request"
PROCESSING_NAME = "information-country-control.processing"
STATUS_NAME = "information-country-control-status.json"
BATTLE_STATUS_NAME = "information-battle-status.json"
BATTLE_BINDING_NAME = "information-battle-binding.json"
MAX_JSON_BYTES = 128 * 1024
MAX_RPM_BYTES = 128 * 1024
MAX_RPM_CALLS = 2048
MAX_SINGLE_RPM = 16 * 1024
STATUS_MAX_AGE_SECONDS = 5.0
PREFLIGHT_WAIT_SECONDS = 20.0
TERMINAL_WAIT_SECONDS = 30.0
POLL_SECONDS = 0.05
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
REF_RE = re.compile(r"^[0-9a-f]{16}$")
DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
VALID_PAIRS = {("POR", "FRA"), ("FRA", "POR")}
COUNTRY_STATUS_FIELDS = (
    "schema", "state", "pid", "creation_filetime", "dll_sha256", "request_id",
    "request_from", "request_to", "before_player_ref", "target_player_ref",
    "observed_player_ref", "date_before", "date_raw", "speed", "paused",
    "native_attempted", "native_return", "native_calls", "attempted_mask",
    "authorized_fra_ref", "frame_thread", "reason",
)
COUNTRY_STATES = {"ready", "attempting", "pending", "confirmed", "rejected", "failed"}
TERMINAL_STATES = {"confirmed", "rejected", "failed"}


class ControlError(RuntimeError):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(f"{code}: {self.message}")


@dataclass(frozen=True)
class InstalledContext:
    installation_path: Path
    directory: Path
    installation: dict[str, Any]
    manifest: dict[str, Any]
    manifest_path: Path
    dll_path: Path
    pid: int
    creation: int
    creation_text: str
    session_id: str
    game_sha256: str
    dll_sha256: str
    pins: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class Dependencies:
    identity_probe: Callable[[int, Path], dict[str, Any]] = probe_identity
    world_reader: Callable[[InstalledContext, str, str], dict[str, Any]] | None = None
    status_reader: Callable[[Path], tuple[dict[str, Any], bytes, float]] | None = None
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic


def _fail(condition: bool, code: str, message: str = "") -> None:
    if not condition:
        raise ControlError(code, message)


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        before = path.stat()
        if not path.is_file() or before.st_size <= 0 or before.st_size > limit:
            raise ControlError("FILE_SIZE_OUT_OF_BOUNDS", str(path))
        raw = path.read_bytes()
        after = path.stat()
    except ControlError:
        raise
    except OSError as exc:
        raise ControlError("FILE_READ_FAILED", f"{path}: {exc}") from exc
    _fail(len(raw) == before.st_size and after.st_size == before.st_size
          and after.st_mtime_ns == before.st_mtime_ns,
          "FILE_CHANGED_DURING_READ", str(path))
    return raw


def _read_json(path: Path, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, limit)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ControlError("JSON_INVALID", str(path)) from exc
    _fail(isinstance(value, dict), "JSON_SCHEMA_INVALID", str(path))
    return value, raw


def _sha256_file(path: Path) -> str:
    try:
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
    except OSError as exc:
        raise ControlError("FILE_HASH_FAILED", f"{path}: {exc}") from exc
    _fail((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
          == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
          "FILE_CHANGED_DURING_HASH", str(path))
    return digest.hexdigest()


def _strict_decimal(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool):
        raise ControlError("DECIMAL_INVALID", label)
    if isinstance(value, int):
        parsed = value
        if str(parsed) != str(value):
            raise ControlError("DECIMAL_INVALID", label)
    elif isinstance(value, str) and DECIMAL_RE.fullmatch(value):
        parsed = int(value, 10)
    else:
        raise ControlError("DECIMAL_INVALID", label)
    if parsed < 0 or (positive and parsed == 0):
        raise ControlError("DECIMAL_INVALID", label)
    return parsed


def _path_key(path: Path) -> str:
    return os.path.normcase(str(path.resolve(strict=False)))


def _source_pins() -> dict[str, dict[str, Any]]:
    paths = [
        Path(__file__).resolve(),
        PROTOCOL_PATH,
        Path(probe_identity.__code__.co_filename).resolve(),
        Path(_country_memory.__file__).resolve(),
        Path(_localization_memory.__file__).resolve(),
        Path(_country_memory._mm.__file__).resolve(),
        Path(_country_memory._monthly.__file__).resolve(),
        Path(_country_memory._loc.__file__).resolve(),
        Path(_country_memory.PROFILE_FILE).resolve(),
        Path(_country_memory._mm.PROFILE_FILE).resolve(),
        Path(_country_memory._monthly.PROFILE_FILE).resolve(),
        Path(_country_memory._loc.PROFILE_FILE).resolve(),
        Path(_localization_memory.PROFILE_FILE).resolve(),
    ]
    config_module = sys.modules.get("local_config")
    if config_module is not None and getattr(config_module, "__file__", None):
        paths.append(Path(config_module.__file__).resolve())
    pins: dict[str, dict[str, Any]] = {}
    for path in dict.fromkeys(paths):
        data = _read_bounded(path, 4 * 1024 * 1024)
        pins[str(path.relative_to(ROOT).as_posix())] = {
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        }
    return pins


def _validate_protocol_document() -> dict[str, Any]:
    protocol, raw = _read_json(PROTOCOL_PATH)
    _fail(protocol.get("schema") == "information.current_country_control.operator_protocol.v1",
          "PROTOCOL_SCHEMA_MISMATCH")
    _fail(protocol.get("status") == "implementation_contract_not_live_qualified",
          "PROTOCOL_STATUS_MISMATCH")
    _fail(protocol.get("feature_macro") == "BRIDGE_CURRENT_COUNTRY_CONTROL=1"
          and protocol.get("build_version") == 31,
          "PROTOCOL_FEATURE_MISMATCH")
    _fail(protocol.get("request_grammar") ==
          "EU4COUNTRY1 TEST_ONLY <id> <pid> <creation> <date> <dllsha64lowerhex> <POR|FRA> <FRA|POR>\n",
          "PROTOCOL_GRAMMAR_MISMATCH")
    _fail(protocol.get("paths") == {
        "request": REQUEST_NAME,
        "processing": PROCESSING_NAME,
        "status": STATUS_NAME,
        "attempt": "information-country-control-{TO}.attempt.jsonl",
    }, "PROTOCOL_PATH_MISMATCH")
    _fail(protocol.get("status_schema") == PROTOCOL
          and protocol.get("status_required_fields") == list(COUNTRY_STATUS_FIELDS),
          "PROTOCOL_STATUS_FIELDS_MISMATCH")
    _fail(protocol.get("status_states") == ["ready", "attempting", "pending", "confirmed", "rejected", "failed"],
          "PROTOCOL_STATES_MISMATCH")
    _fail(protocol.get("client_cli") == [
        "--installation", "--request-id", "--from-tag", "--to-tag",
        "--expected-date", "--output", "--test-only",
    ], "PROTOCOL_CLI_MISMATCH")
    protocol["_pin"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return protocol


def _validate_build_manifest(manifest: Mapping[str, Any]) -> None:
    _fail(type(manifest.get("version")) is int and manifest.get("version") == 31,
          "BUILD_VERSION_REQUIRES_V31")
    arguments = manifest.get("compiler_arguments")
    _fail(isinstance(arguments, list)
          and "-DBRIDGE_INFORMATION_BATTLE=1" in arguments
          and "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1" in arguments,
          "CURRENT_COUNTRY_CONTROL_FEATURE_MISSING")
    _fail(manifest.get("current_country_control_test_only") is True
          and manifest.get("current_country_control_protocol") == PROTOCOL
          and manifest.get("current_country_control_entry_rva") == "0x779360",
          "CURRENT_COUNTRY_CONTROL_MANIFEST_MISMATCH")
    sources = manifest.get("sources")
    _fail(isinstance(sources, list) and bool(sources), "BUILD_SOURCES_MISSING")
    names: set[str] = set()
    for source in sources:
        _fail(isinstance(source, dict)
              and isinstance(source.get("name"), str) and bool(source["name"])
              and isinstance(source.get("sha256"), str)
              and SHA_RE.fullmatch(source["sha256"]), "BUILD_SOURCE_PIN_INVALID")
        _fail(source["name"] not in names, "BUILD_SOURCE_PIN_DUPLICATE", source["name"])
        names.add(source["name"])


def _normalize_modules(value: Any, *, label: str) -> list[dict[str, Any]]:
    _fail(isinstance(value, list) and value, "MODULE_LIST_INVALID", label)
    result: list[dict[str, Any]] = []
    for module in value:
        _fail(isinstance(module, dict), "MODULE_LIST_INVALID", label)
        name, path, sha = module.get("name"), module.get("path"), module.get("sha256")
        _fail(isinstance(name, str) and name and isinstance(path, str) and path
              and isinstance(sha, str) and SHA_RE.fullmatch(sha),
              "MODULE_LIST_INVALID", label)
        result.append({"name": name, "path": path, "sha256": sha})
    return result


def _load_installed_context(installation_path: str | os.PathLike[str],
                            identity_probe: Callable[[int, Path], dict[str, Any]]) -> InstalledContext:
    supplied = Path(installation_path)
    try:
        path = supplied.resolve()
    except OSError as exc:
        raise ControlError("INSTALLATION_PATH_INVALID", str(supplied)) from exc
    _fail(path.name.lower() == "installation.json" and path.is_file(),
          "INSTALLATION_PATH_INVALID", "--installation must name installation.json")
    directory = path.parent
    manifest_path = directory / "build-manifest.json"
    installation, install_raw = _read_json(path)
    manifest, manifest_raw = _read_json(manifest_path)
    _validate_build_manifest(manifest)

    pid = _strict_decimal(installation.get("pid"), "installation.pid", positive=True)
    creation = _strict_decimal(installation.get("creation_filetime"),
                               "installation.creation_filetime", positive=True)
    creation_text = str(creation)
    session_id = installation.get("session_id")
    _fail(isinstance(session_id, str) and session_id == f"{pid}-{creation:x}",
          "INSTALLATION_SESSION_MISMATCH")
    game_sha = manifest.get("game_sha256")
    dll_sha = manifest.get("dll_sha256")
    _fail(isinstance(game_sha, str) and SHA_RE.fullmatch(game_sha)
          and isinstance(dll_sha, str) and SHA_RE.fullmatch(dll_sha),
          "BUILD_HASH_INVALID")
    _fail(installation.get("game_sha256") == game_sha
          and installation.get("dll_sha256") == dll_sha,
          "INSTALLATION_BUILD_PIN_MISMATCH")
    experiment = manifest.get("experiment_id")
    if experiment is not None:
        _fail(installation.get("experiment_id") == experiment,
              "INSTALLATION_EXPERIMENT_MISMATCH")
    dll_path = directory / "eu4_bridge_diplomacy_observer_v31.dll"
    _fail(dll_path.is_file(), "INSTALLED_DLL_MISSING", str(dll_path))
    manifest_dll = manifest.get("dll")
    _fail(isinstance(manifest_dll, str)
          and _path_key(Path(manifest_dll)) == _path_key(dll_path),
          "BUILD_DLL_PATH_MISMATCH")
    _fail(_sha256_file(dll_path) == dll_sha, "INSTALLED_DLL_HASH_MISMATCH")

    recorded_modules = _normalize_modules(installation.get("modules_after_install"),
                                          label="modules_after_install")
    _fail(len(recorded_modules) == 1, "MODULE_SET_NOT_UNIQUE", "installed module list")
    recorded = recorded_modules[0]
    _fail(_path_key(Path(recorded["path"])) == _path_key(dll_path)
          and recorded["name"].lower() == dll_path.name.lower()
          and recorded["sha256"] == dll_sha,
          "INSTALLATION_MODULE_MISMATCH")

    try:
        current = identity_probe(pid, Path(game_exe()))
    except Exception as exc:
        raise ControlError("IDENTITY_PROBE_FAILED", str(exc)) from exc
    _fail(isinstance(current, dict), "IDENTITY_PROBE_FAILED", "no identity record")
    _fail(_strict_decimal(current.get("pid"), "current.pid", positive=True) == pid
          and _strict_decimal(current.get("creation_filetime"),
                              "current.creation_filetime", positive=True) == creation,
          "PROCESS_IDENTITY_MISMATCH")
    _fail(current.get("session_id") == session_id
          and current.get("game_sha256") == game_sha,
          "PROCESS_BUILD_MISMATCH")
    live_modules = _normalize_modules(current.get("modules"), label="live modules")
    matches = [m for m in live_modules if _path_key(Path(m["path"])) == _path_key(dll_path)]
    _fail(len(matches) == 1 and len(live_modules) == 1,
          "LIVE_MODULE_SET_MISMATCH", "exactly the installed v31 observer must be loaded")
    _fail(matches[0]["name"].lower() == dll_path.name.lower()
          and matches[0]["sha256"] == dll_sha,
          "LIVE_DLL_IDENTITY_MISMATCH")

    pins = {
        "installation.json": {"bytes": len(install_raw), "sha256": hashlib.sha256(install_raw).hexdigest()},
        "build-manifest.json": {"bytes": len(manifest_raw), "sha256": hashlib.sha256(manifest_raw).hexdigest()},
        dll_path.name: {"bytes": dll_path.stat().st_size, "sha256": dll_sha},
    }
    return InstalledContext(path, directory, installation, manifest, manifest_path,
                            dll_path, pid, creation, creation_text, session_id,
                            game_sha, dll_sha, pins)


class _BudgetedReader:
    def __init__(self, reader: Any):
        self.reader = reader
        self.module_base = getattr(reader, "module_base", None)
        self.calls = 0
        self.bytes = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        _fail(type(address) is int and 0x10000 <= address < (1 << 47),
              "RPM_ADDRESS_INVALID", label)
        _fail(type(size) is int and 0 < size <= MAX_SINGLE_RPM
              and address + size <= (1 << 47), "RPM_SIZE_INVALID", label)
        _fail(self.calls < MAX_RPM_CALLS and self.bytes + size <= MAX_RPM_BYTES,
              "RPM_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes += size
        raw = self.reader.read(address, size, label)
        _fail(isinstance(raw, bytes) and len(raw) == size, "RPM_SHORT_READ", label)
        return raw

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def _read_world_control_unchecked(context: InstalledContext, from_tag: str,
                                  to_tag: str) -> dict[str, Any]:
    """Read current/target identities and time control through bounded VM_READ."""
    profile = _country_memory._active_profile()
    _fail(isinstance(profile, dict)
          and profile.get("profile_id") == "country-resources-memory-1374",
          "WORLD_PROFILE_UNAVAILABLE")
    _fail(_country_memory._static_contract_guard().get("status") == "observed",
          "WORLD_PROFILE_CONTRACT_MISMATCH")
    layout = _country_memory._profile_layout(profile)
    kernel = _country_memory._configure_kernel()
    handle = kernel.OpenProcess(_country_memory.PROCESS_ACCESS, False, context.pid)
    if not handle:
        raise ControlError("READ_ONLY_PROCESS_OPEN_FAILED", "PROCESS_QUERY_INFORMATION|PROCESS_VM_READ")
    reader: _BudgetedReader | None = None
    close_ok = False
    try:
        identity_report: dict[str, Any] = {"identity": {}}
        module_base = _country_memory._capture_identity(identity_report,
                                                        context.installation, kernel, handle)
        base_reader = _country_memory.AddressBoundedRPM(kernel, handle, module_base)
        reader = _BudgetedReader(base_reader)

        game, _ = reader.qword(module_base + layout["game_rva"], "globals.game")
        database, _ = reader.qword(module_base + layout["database_rva"], "globals.database")
        _fail(_country_memory._mm._valid_pointer(game)
              and _country_memory._mm._valid_pointer(database), "WORLD_ROOT_INVALID")
        current_ref, _ = reader.qword(game + 0x1E60, "game.current_player")
        date_raw = int.from_bytes(reader.read(game + layout["game_date_offset"], 4,
                                              "game.date"), "little", signed=True)
        speed = int.from_bytes(reader.read(game + 0x1E08, 4, "game.speed"),
                               "little", signed=True)
        server, _ = reader.qword(game + 0x1E00, "game.server")
        _fail(_country_memory._mm._valid_pointer(server), "SERVER_POINTER_INVALID")
        pause, _ = reader.qword(server + 0x418, "server.pause_manager")
        _fail(_country_memory._mm._valid_pointer(pause), "PAUSE_POINTER_INVALID")
        paused_byte = reader.read(pause + 0x48, 1, "pause.manual_paused")[0]
        pause_owner, _ = reader.qword(pause + 0x50, "pause.owner")
        _fail(pause_owner == server and paused_byte in (0, 1), "PAUSE_IDENTITY_INVALID")

        human_count_raw = int.from_bytes(
            reader.read(game + 0xA60, 4, "game.human_count"), "little", signed=True)
        controller_types_pointer, _ = reader.qword(
            game + 0x1D48, "game.controller_types")

        tag, slot = _localization_memory._tag_and_slot(current_ref)
        _fail(tag in {"POR", "FRA"}, "CURRENT_COUNTRY_UNSUPPORTED", tag)

        refs: dict[str, str] = {}
        ref_slots: dict[str, int] = {}
        for requested_tag in {from_tag, to_tag, "FRA"}:
            country = _country_memory._country_identity(reader, database, requested_tag)
            _fail(country.get("status") == "observed", "COUNTRY_IDENTITY_UNKNOWN", requested_tag)
            info = country.get("country_handle")
            _fail(isinstance(info, dict) and isinstance(info.get("value"), str),
                  "COUNTRY_FULLREF_MISSING", requested_tag)
            value = int(info["value"], 0)
            resolved_tag, resolved_slot = _localization_memory._tag_and_slot(value)
            _fail(resolved_tag == requested_tag and resolved_slot == country.get("country_handle", {}).get("slot"),
                  "COUNTRY_FULLREF_TAG_SLOT_MISMATCH", requested_tag)
            refs[requested_tag] = f"{value:016x}"
            ref_slots[requested_tag] = resolved_slot

        controller_types_raw: dict[str, Any] = {
            "status": "unknown", "pointer": f"0x{controller_types_pointer:x}",
            "slots": {},
        }
        if _country_memory._mm._valid_pointer(controller_types_pointer):
            slot_values: dict[str, int] = {}
            for requested_tag, requested_slot in sorted(ref_slots.items()):
                raw_type = reader.read(controller_types_pointer + requested_slot * 4,
                                       4, f"game.controller_types[{requested_tag}:{requested_slot}]")
                slot_values[f"{requested_tag}:{requested_slot}"] = int.from_bytes(
                    raw_type, "little", signed=True)
            controller_types_raw = {
                "status": "observed", "pointer": f"0x{controller_types_pointer:x}",
                "slots": slot_values,
            }
        return {
            "game_pointer": f"0x{game:x}",
            "current_player_ref": f"{current_ref:016x}",
            "current_tag": tag,
            "current_slot": slot,
            "target_player_ref": refs[to_tag],
            "fra_player_ref": refs["FRA"],
            "date_raw": date_raw,
            "speed": speed,
            "paused": bool(paused_byte),
            "human_count_raw": human_count_raw,
            "controller_types_raw": controller_types_raw,
            "rpm_budget": {"calls": reader.calls, "bytes": reader.bytes,
                           "max_calls": MAX_RPM_CALLS, "max_bytes": MAX_RPM_BYTES,
                           "native_calls": 0, "memory_written": False},
        }
    finally:
        try:
            close_ok = bool(kernel.CloseHandle(handle))
        except Exception:
            close_ok = False
        _fail(close_ok, "READ_ONLY_PROCESS_CLOSE_FAILED")


def _read_world_control(context: InstalledContext, from_tag: str,
                        to_tag: str) -> dict[str, Any]:
    try:
        return _read_world_control_unchecked(context, from_tag, to_tag)
    except ControlError:
        raise
    except Exception as exc:
        raise ControlError("WORLD_READ_FAILED", type(exc).__name__) from exc


def _read_native_status(path: Path) -> tuple[dict[str, Any], bytes, float]:
    if not path.exists():
        raise FileNotFoundError(path)
    value, raw = _read_json(path)
    age = time.time() - path.stat().st_mtime
    return value, raw, age


def _validate_country_status(value: Mapping[str, Any], context: InstalledContext) -> dict[str, Any]:
    _fail(all(field in value for field in COUNTRY_STATUS_FIELDS), "COUNTRY_STATUS_FIELDS_MISSING")
    _fail(value.get("schema") == PROTOCOL and value.get("state") in COUNTRY_STATES,
          "COUNTRY_STATUS_SCHEMA_INVALID")
    _fail(type(value.get("pid")) is int and value["pid"] == context.pid,
          "COUNTRY_STATUS_PID_MISMATCH")
    _fail(isinstance(value.get("creation_filetime"), str)
          and _strict_decimal(value.get("creation_filetime"), "status.creation_filetime",
                              positive=True) == context.creation
          and value.get("dll_sha256") == context.dll_sha256,
          "COUNTRY_STATUS_IDENTITY_MISMATCH")
    for field in ("before_player_ref", "target_player_ref", "observed_player_ref", "authorized_fra_ref"):
        ref = value.get(field)
        _fail(isinstance(ref, str) and REF_RE.fullmatch(ref),
              "COUNTRY_STATUS_REF_INVALID", field)
    for field in ("date_before", "date_raw", "speed", "native_calls", "attempted_mask", "frame_thread"):
        _fail(type(value.get(field)) is int, "COUNTRY_STATUS_INTEGER_INVALID", field)
    _fail(type(value.get("paused")) is bool and type(value.get("native_attempted")) is bool,
          "COUNTRY_STATUS_BOOLEAN_INVALID")
    native_return = value.get("native_return")
    _fail(native_return is None or (type(native_return) is int and native_return in (0, 1)),
          "COUNTRY_STATUS_RETURN_INVALID")
    _fail(isinstance(value.get("request_id"), str)
          and isinstance(value.get("request_from"), str)
          and isinstance(value.get("request_to"), str)
          and isinstance(value.get("reason"), str),
          "COUNTRY_STATUS_TEXT_INVALID")
    return dict(value)


def _validate_battle_status(directory: Path, context: InstalledContext,
                            from_ref: str) -> dict[str, Any]:
    path = directory / BATTLE_STATUS_NAME
    if not path.exists():
        raise FileNotFoundError(path)
    value, _ = _read_json(path)
    try:
        age = time.time() - path.stat().st_mtime
    except OSError as exc:
        raise ControlError("BATTLE_STATUS_UNAVAILABLE", type(exc).__name__) from exc
    _fail(-1.0 <= age <= STATUS_MAX_AGE_SECONDS, "BATTLE_STATUS_STALE")
    _fail(value.get("state") in {"ready", "disabled"}, "BATTLE_SOURCE_NOT_READY",
          str(value.get("state")))
    _fail(type(value.get("pid")) is int and value.get("pid") == context.pid
          and _strict_decimal(value.get("creation_filetime"), "battle.creation_filetime",
                              positive=True) == context.creation
          and value.get("exe_sha256") == context.game_sha256
          and value.get("dll_sha256") == context.dll_sha256,
          "BATTLE_STATUS_IDENTITY_MISMATCH")
    native_installation = _strict_decimal(value.get("installation"),
                                          "battle.installation")
    native_generation = _strict_decimal(value.get("generation"), "battle.generation")
    binding_path = directory / BATTLE_BINDING_NAME
    if binding_path.exists():
        binding, _ = _read_json(binding_path)
        _fail(binding.get("schema") == "EU4-BATTLE-CONTROL/1",
              "BATTLE_BINDING_SCHEMA_INVALID")
        _fail(binding.get("player_ref") == from_ref,
              "BATTLE_BINDING_PLAYER_MISMATCH")
        binding_installation = _strict_decimal(binding.get("installation"),
                                               "battle_binding.installation", positive=True)
        _fail(binding_installation <= 0xFFFFFFFFFFFFFFFF
              and _strict_decimal(binding.get("generation"), "battle_binding.generation",
                                  positive=True) == context.creation
              and _strict_decimal(binding.get("pid"), "battle_binding.pid",
                                  positive=True) == context.pid
              and _strict_decimal(binding.get("creation_filetime"),
                                  "battle_binding.creation_filetime", positive=True) == context.creation
              and binding.get("session_id") == context.session_id
              and binding.get("game_sha256") == context.game_sha256
              and binding.get("dll_sha256") == context.dll_sha256,
              "BATTLE_BINDING_IDENTITY_MISMATCH")
        if value.get("state") == "disabled":
            _fail(native_installation == binding_installation
                  and native_generation == context.creation,
                  "BATTLE_NATIVE_BINDING_MISMATCH")
    elif value.get("state") == "disabled":
        raise ControlError("BATTLE_BINDING_REQUIRED", "disabled source must remain bound to from-tag")
    if value.get("state") == "ready":
        _fail(native_installation == 0 and native_generation == 0,
              "BATTLE_UNBOUND_STATE_MISMATCH")
    return value


def _attempt_path(directory: Path, to_tag: str) -> Path:
    return directory / f"information-country-control-{to_tag}.attempt.jsonl"


def _reject_if_busy(directory: Path, to_tag: str) -> None:
    paths = (
        _attempt_path(directory, to_tag),
        directory / REQUEST_NAME,
        directory / PROCESSING_NAME,
        directory / "information-battle-control.request",
        directory / "information-battle-control.processing",
        directory / "game-control.request",
        directory / "game-control.processing",
    )
    existing = [str(path.name) for path in paths if path.exists()]
    _fail(not existing, "CONTROL_ALREADY_ATTEMPTED_OR_BUSY", ",".join(existing))


def _valid_previous_state(status: Mapping[str, Any], from_tag: str,
                          to_tag: str) -> bool:
    state = status["state"]
    if state == "ready":
        return (not status["native_attempted"] and status["native_calls"] == 0
                and not status["request_id"] and not status["request_from"]
                and not status["request_to"] and status["frame_thread"] > 0)
    if state == "confirmed":
        return (status["native_attempted"] and status["native_return"] == 1
                and status["native_calls"] > 0
                and status["request_from"] == to_tag
                and status["request_to"] == from_tag
                and status["frame_thread"] > 0)
    return False


def _status_matches_preflight(status: Mapping[str, Any], world: Mapping[str, Any],
                              from_tag: str, to_tag: str, expected_date: int) -> bool:
    expected_authorized_fra_ref = (
        "0000000000000000" if from_tag == "POR" else world["fra_player_ref"]
    )
    return (_valid_previous_state(status, from_tag, to_tag)
            and status["observed_player_ref"] == world["current_player_ref"]
            and status["authorized_fra_ref"] == expected_authorized_fra_ref
            and status["date_raw"] == expected_date
            and world["date_raw"] == expected_date
            and status["speed"] == world["speed"] == 0
            and status["paused"] is True and world["paused"] is True
            and world["current_tag"] == from_tag)


def _world_transition_mismatches(world: Mapping[str, Any], from_tag: str,
                                 to_tag: str, *, after: bool) -> list[str]:
    mismatches: list[str] = []
    if type(world.get("human_count_raw")) is not int or world["human_count_raw"] != 1:
        mismatches.append("human_count_not_single_player")
    controller = world.get("controller_types_raw")
    slots = controller.get("slots") if isinstance(controller, Mapping) else None
    if not isinstance(controller, Mapping) or controller.get("status") != "observed" or not isinstance(slots, Mapping):
        mismatches.append("controller_types_unavailable")
        return mismatches
    expected = ({from_tag: 0, to_tag: 1} if after
                else {from_tag: 1, to_tag: 0})
    for tag, expected_value in expected.items():
        values = [value for key, value in slots.items()
                  if isinstance(key, str) and key.startswith(f"{tag}:")]
        if len(values) != 1 or type(values[0]) is not int or values[0] != expected_value:
            phase = "postcondition" if after else "precondition"
            mismatches.append(f"controller_types_{phase}_{tag}_mismatch")
    return mismatches


def _require_world_transition_ready(world: Mapping[str, Any], from_tag: str,
                                    to_tag: str) -> None:
    mismatches = _world_transition_mismatches(world, from_tag, to_tag, after=False)
    _fail(not mismatches, "WORLD_CONTROL_PRECONDITION_MISMATCH", ",".join(mismatches))


def _stable_preflight(context: InstalledContext, from_tag: str, to_tag: str,
                      expected_date: int, deps: Dependencies,
                      timeout: float) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    status_path = context.directory / STATUS_NAME
    battle_path = context.directory / BATTLE_STATUS_NAME
    deadline = deps.monotonic() + timeout
    previous_thread: int | None = None
    last_reason = "native_status_not_ready"
    while deps.monotonic() <= deadline:
        _reject_if_busy(context.directory, to_tag)
        try:
            raw_status, raw, age = deps.status_reader(status_path) if deps.status_reader else _read_native_status(status_path)
            _fail(isinstance(raw, bytes) and bool(raw), "COUNTRY_STATUS_RAW_INVALID")
            status = _validate_country_status(raw_status, context)
            if age < -1.0 or age > STATUS_MAX_AGE_SECONDS:
                last_reason = "native_status_stale"
                deps.sleep(POLL_SECONDS)
                continue
            if status["state"] in {"attempting", "pending", "rejected", "failed"}:
                raise ControlError("COUNTRY_CONTROL_NOT_READY", status["state"])
            if not _valid_previous_state(status, from_tag, to_tag):
                last_reason = "native_status_warming_or_prior_state_not_recoverable"
                deps.sleep(POLL_SECONDS)
                continue
            if (status["observed_player_ref"] == "0000000000000000"
                    or (from_tag == "FRA"
                        and status["authorized_fra_ref"] == "0000000000000000")
                    or status["date_raw"] != expected_date
                    or status["speed"] != 0 or status["paused"] is not True):
                last_reason = "native_frame_world_not_yet_ready"
                deps.sleep(POLL_SECONDS)
                continue
            if previous_thread is not None and previous_thread != status["frame_thread"]:
                raise ControlError("FRAME_THREAD_CHANGED_DURING_PREFLIGHT")
            previous_thread = status["frame_thread"]
            battle = _validate_battle_status(context.directory, context,
                                             status["observed_player_ref"])
            world_reader = deps.world_reader or _read_world_control
            try:
                first = world_reader(context, from_tag, to_tag)
                second = world_reader(context, from_tag, to_tag)
            except ControlError as exc:
                last_reason = f"independent_world_not_yet_ready:{exc.code}"
                deps.sleep(POLL_SECONDS)
                continue
            _fail(first == second, "WORLD_CHANGED_DURING_PREFLIGHT")
            if not _status_matches_preflight(status, first, from_tag, to_tag, expected_date):
                last_reason = "native_and_independent_preflight_not_yet_aligned"
                deps.sleep(POLL_SECONDS)
                continue
            _require_world_transition_ready(first, from_tag, to_tag)
            _validate_battle_status(context.directory, context, first["current_player_ref"])
            return status, first, battle, raw
        except FileNotFoundError:
            last_reason = "native_status_not_yet_published"
        deps.sleep(POLL_SECONDS)
    raise ControlError("PREFLIGHT_WAIT_TIMEOUT", last_reason)


def _make_request(request_id: str, context: InstalledContext, from_tag: str,
                  to_tag: str, expected_date: int) -> bytes:
    _fail(ID_RE.fullmatch(request_id) is not None, "REQUEST_ID_INVALID")
    _fail((from_tag, to_tag) in VALID_PAIRS, "REQUEST_DIRECTION_INVALID")
    _fail(type(expected_date) is int and not isinstance(expected_date, bool)
          and 0 <= expected_date <= 0x7fffffff, "EXPECTED_DATE_INVALID")
    line = (f"EU4COUNTRY1 TEST_ONLY {request_id} {context.pid} {context.creation_text} "
            f"{expected_date} {context.dll_sha256} {from_tag} {to_tag}\n")
    packet = line.encode("ascii")
    _fail(len(packet) <= 320 and b"\x00" not in packet and packet.endswith(b"\n")
          and b"\r" not in packet, "REQUEST_PACKET_INVALID")
    _fail(len(packet.decode("ascii").split()) == 9, "REQUEST_TOKEN_COUNT_INVALID")
    return packet


def _write_exclusive(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ControlError("EXCLUSIVE_OUTPUT_EXISTS", str(path)) from exc
    except OSError as exc:
        raise ControlError("EXCLUSIVE_OUTPUT_WRITE_FAILED", f"{path}: {exc}") from exc


def _publish_request_once(path: Path, data: bytes) -> None:
    opened = False
    try:
        stream = path.open("xb")
        opened = True
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ControlError("REQUEST_ALREADY_EXISTS", str(path)) from exc
    except OSError as exc:
        code = "REQUEST_PUBLISH_AMBIGUOUS_NO_RETRY" if opened else "REQUEST_PUBLISH_FAILED"
        raise ControlError(code, f"{path}: {exc}") from exc


def _write_json_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    _write_exclusive(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def _read_terminal_status(context: InstalledContext, request_id: str,
                          from_tag: str, to_tag: str, deps: Dependencies,
                          timeout: float) -> tuple[dict[str, Any] | None, bytes | None]:
    status_path = context.directory / STATUS_NAME
    deadline = deps.monotonic() + timeout
    last_raw: bytes | None = None
    while deps.monotonic() <= deadline:
        try:
            raw_status, raw, age = deps.status_reader(status_path) if deps.status_reader else _read_native_status(status_path)
        except FileNotFoundError:
            deps.sleep(POLL_SECONDS)
            continue
        status = _validate_country_status(raw_status, context)
        _fail(isinstance(raw, bytes) and bool(raw), "COUNTRY_STATUS_RAW_INVALID")
        last_raw = raw
        if age < -1.0 or age > STATUS_MAX_AGE_SECONDS:
            deps.sleep(POLL_SECONDS)
            continue
        if status["request_id"] == request_id:
            _fail(status["request_from"] == from_tag and status["request_to"] == to_tag,
                  "NATIVE_STATUS_REQUEST_DIRECTION_MISMATCH")
            if status["state"] in TERMINAL_STATES:
                return status, raw
        deps.sleep(POLL_SECONDS)
    return None, last_raw


def _verify_terminal(status: Mapping[str, Any], before: Mapping[str, Any],
                     after: Mapping[str, Any], native_before: Mapping[str, Any],
                     context: InstalledContext,
                     request_id: str, from_tag: str, to_tag: str,
                     expected_date: int) -> tuple[str, list[str]]:
    mismatches: list[str] = []
    if status["state"] != "confirmed":
        return status["state"], [f"native_state_{status['state']}"]
    if status["native_return"] != 1:
        mismatches.append("native_return_not_one")
    if not status["native_attempted"] or status["native_calls"] <= 0:
        mismatches.append("native_attempt_missing")
    if status["native_calls"] != native_before["native_calls"] + 1:
        mismatches.append("native_call_count_delta_mismatch")
    attempted_bit = 1 if to_tag == "FRA" else 2
    if status["attempted_mask"] != (native_before["attempted_mask"] | attempted_bit):
        mismatches.append("native_attempt_mask_delta_mismatch")
    if status["request_id"] != request_id:
        mismatches.append("request_id_mismatch")
    if status["request_from"] != from_tag or status["request_to"] != to_tag:
        mismatches.append("native_direction_mismatch")
    if status["before_player_ref"] != before["current_player_ref"]:
        mismatches.append("native_before_ref_mismatch")
    if status["target_player_ref"] != before["target_player_ref"]:
        mismatches.append("native_target_ref_mismatch")
    if status["observed_player_ref"] != before["target_player_ref"]:
        mismatches.append("native_observed_ref_mismatch")
    if status["date_before"] != expected_date or status["date_raw"] != expected_date:
        mismatches.append("native_date_changed")
    if status["speed"] != 0 or status["paused"] is not True:
        mismatches.append("native_pause_or_speed_changed")
    expected_authorized_fra_ref = (
        before["fra_player_ref"] if to_tag == "FRA" else "0000000000000000"
    )
    if status["authorized_fra_ref"] != expected_authorized_fra_ref:
        mismatches.append("native_authorized_fra_ref_mismatch")
    if after["current_tag"] != to_tag or after["current_player_ref"] != before["target_player_ref"]:
        mismatches.append("independent_effect_mismatch")
    if after.get("game_pointer") != before.get("game_pointer"):
        mismatches.append("independent_game_pointer_changed")
    if after["date_raw"] != expected_date or after["speed"] != 0 or after["paused"] is not True:
        mismatches.append("independent_time_control_mismatch")
    if after["fra_player_ref"] != before["fra_player_ref"]:
        mismatches.append("independent_fra_fullref_changed")
    mismatches.extend(_world_transition_mismatches(after, from_tag, to_tag, after=True))
    if status["pid"] != context.pid or status["creation_filetime"] != context.creation_text:
        mismatches.append("terminal_process_identity_mismatch")
    return ("confirmed" if not mismatches else "effect_mismatch"), mismatches


def _revalidate_context(context: InstalledContext,
                        identity_probe: Callable[[int, Path], dict[str, Any]]) -> None:
    installation, install_raw = _read_json(context.installation_path)
    manifest, manifest_raw = _read_json(context.manifest_path)
    _validate_build_manifest(manifest)
    _fail(hashlib.sha256(install_raw).hexdigest() == context.pins["installation.json"]["sha256"]
          and hashlib.sha256(manifest_raw).hexdigest() == context.pins["build-manifest.json"]["sha256"],
          "INSTALLATION_PINS_CHANGED")
    _fail(_sha256_file(context.dll_path) == context.dll_sha256,
          "INSTALLED_DLL_HASH_MISMATCH")
    try:
        current = identity_probe(context.pid, Path(game_exe()))
    except Exception as exc:
        raise ControlError("IDENTITY_PROBE_FAILED", type(exc).__name__) from exc
    _fail(isinstance(current, dict)
          and _strict_decimal(current.get("pid"), "current.pid", positive=True) == context.pid
          and _strict_decimal(current.get("creation_filetime"), "current.creation_filetime", positive=True) == context.creation
          and current.get("session_id") == context.session_id
          and current.get("game_sha256") == context.game_sha256,
          "PROCESS_IDENTITY_CHANGED_BEFORE_DISPATCH")
    modules = _normalize_modules(current.get("modules"), label="live modules")
    _fail(len(modules) == 1 and _path_key(Path(modules[0]["path"])) == _path_key(context.dll_path)
          and modules[0]["sha256"] == context.dll_sha256,
          "LIVE_DLL_CHANGED_BEFORE_DISPATCH")
    _fail(installation.get("dll_sha256") == context.dll_sha256,
          "INSTALLATION_DLL_CHANGED_BEFORE_DISPATCH")


def execute(installation_path: str | os.PathLike[str], request_id: str,
            from_tag: str, to_tag: str, expected_date: int,
            output: str | os.PathLike[str], *, test_only: bool = False,
            dependencies: Dependencies | None = None,
            preflight_timeout: float = PREFLIGHT_WAIT_SECONDS,
            terminal_timeout: float = TERMINAL_WAIT_SECONDS) -> dict[str, Any]:
    deps = dependencies or Dependencies()
    _fail(isinstance(request_id, str) and ID_RE.fullmatch(request_id) is not None,
          "REQUEST_ID_INVALID")
    _fail((from_tag, to_tag) in VALID_PAIRS, "REQUEST_DIRECTION_INVALID")
    _fail(type(expected_date) is int and not isinstance(expected_date, bool)
          and 0 <= expected_date <= 0x7fffffff, "EXPECTED_DATE_INVALID")
    packet_context_hint = Path(installation_path)
    output_path = Path(output).expanduser().resolve(strict=False)
    _fail(not output_path.exists(), "OUTPUT_DIRECTORY_MUST_BE_NEW", str(output_path))
    _fail(output_path.parent.is_dir(), "OUTPUT_PARENT_MISSING", str(output_path.parent))
    protocol = _validate_protocol_document()
    pins_before = _source_pins()
    context = _load_installed_context(packet_context_hint, deps.identity_probe)
    packet = _make_request(request_id, context, from_tag, to_tag, expected_date)
    _reject_if_busy(context.directory, to_tag)

    native_before, world_before, battle_before, native_before_raw = _stable_preflight(
        context, from_tag, to_tag, expected_date, deps, preflight_timeout)
    _fail(not output_path.exists(), "OUTPUT_DIRECTORY_MUST_BE_NEW", str(output_path))
    pins_ready = _source_pins()
    _fail(pins_ready == pins_before, "CLIENT_SOURCE_PINS_CHANGED_DURING_PREFLIGHT")
    protocol_after = _validate_protocol_document()
    _fail(protocol_after["_pin"] == protocol["_pin"], "PROTOCOL_CHANGED_DURING_PREFLIGHT")
    _revalidate_context(context, deps.identity_probe)

    try:
        output_path.mkdir(parents=False, exist_ok=False)
    except OSError as exc:
        raise ControlError("OUTPUT_DIRECTORY_CREATE_FAILED", str(exc)) from exc
    request_was_published = False
    request_copy = output_path / "request.original"
    try:
        _write_exclusive(request_copy, packet)
        _write_exclusive(output_path / "native-status-before.json", native_before_raw)
        _write_json_exclusive(output_path / "preflight.json", {
            "schema": "information.current_country_control.client_preflight.v1",
            "request_id": request_id,
            "request": packet.decode("ascii"),
            "test_only": test_only,
            "process": {"pid": context.pid, "creation_filetime": context.creation_text,
                        "session_id": context.session_id, "game_sha256": context.game_sha256,
                        "dll_sha256": context.dll_sha256},
            "native_status_before": native_before,
            "world_before": world_before,
            "battle_status_before": battle_before,
            "source_pins": pins_before,
            "protocol_pin": protocol["_pin"],
            "request_published": False,
            "native_calls_by_client": 0,
            "memory_written_by_client": False,
        })
        if not test_only:
            result = {"status": "prepared_no_dispatch", "request_id": request_id,
                      "request_published": False, "output": str(output_path)}
            _write_json_exclusive(output_path / "client-result.json", result)
            return result

        # Recheck every externally mutable admission guard immediately before
        # the only request publication.  Recheck does not resend or call EU4.
        _reject_if_busy(context.directory, to_tag)
        _revalidate_context(context, deps.identity_probe)
        current_status, current_raw, current_age = (
            deps.status_reader(context.directory / STATUS_NAME)
            if deps.status_reader else _read_native_status(context.directory / STATUS_NAME)
        )
        current_status = _validate_country_status(current_status, context)
        _fail(current_age >= -1.0 and current_age <= STATUS_MAX_AGE_SECONDS,
              "NATIVE_STATUS_STALE_BEFORE_DISPATCH")
        _fail(_valid_previous_state(current_status, from_tag, to_tag)
              and current_status["frame_thread"] == native_before["frame_thread"],
              "NATIVE_STATUS_CHANGED_BEFORE_DISPATCH")
        world_reader = deps.world_reader or _read_world_control
        world_now = world_reader(context, from_tag, to_tag)
        _fail(world_now == world_before
              and _status_matches_preflight(current_status, world_now, from_tag, to_tag, expected_date),
              "WORLD_OR_NATIVE_STATE_CHANGED_BEFORE_DISPATCH")
        _require_world_transition_ready(world_now, from_tag, to_tag)
        _validate_battle_status(context.directory, context, world_now["current_player_ref"])
        _fail(_source_pins() == pins_before, "CLIENT_SOURCE_PINS_CHANGED_BEFORE_DISPATCH")
        _fail(_validate_protocol_document()["_pin"] == protocol["_pin"],
              "PROTOCOL_CHANGED_BEFORE_DISPATCH")

        # The local request is saved first. The native request is created with
        # exclusive x mode; a failed/ambiguous write is never retried.
        try:
            _publish_request_once(context.directory / REQUEST_NAME, packet)
        except ControlError as exc:
            ambiguous = exc.code == "REQUEST_PUBLISH_AMBIGUOUS_NO_RETRY"
            result = {"status": "unknown_no_retry" if ambiguous else "publish_rejected",
                      "reason": exc.code, "request_id": request_id,
                      "request_published": ambiguous or (context.directory / REQUEST_NAME).exists(),
                      "native_dispatch_count": 1 if ambiguous else 0,
                      "retry_count": 0, "output": str(output_path)}
            _write_json_exclusive(output_path / "client-result.json", result)
            return result
        request_was_published = True

        try:
            terminal, terminal_raw = _read_terminal_status(
                context, request_id, from_tag, to_tag, deps, terminal_timeout)
        except ControlError as exc:
            terminal, terminal_raw = None, None
            terminal_error = exc.code
        else:
            terminal_error = None
        if terminal_raw is not None:
            status_name = "native-status-terminal.json" if terminal is not None else "native-status-last.json"
            _write_exclusive(output_path / status_name, terminal_raw)

        if terminal is None:
            result = {"status": "unknown_no_retry", "reason": terminal_error or "terminal_status_timeout",
                      "request_id": request_id, "request_published": True,
                      "native_dispatch_count": 1, "retry_count": 0,
                      "output": str(output_path)}
            _write_json_exclusive(output_path / "client-result.json", result)
            return result

        world_reader = deps.world_reader or _read_world_control
        world_after = world_reader(context, from_tag, to_tag)
        _write_json_exclusive(output_path / "world-after.json", world_after)
        _revalidate_context(context, deps.identity_probe)
        final_state, mismatches = _verify_terminal(
            terminal, world_before, world_after, native_before, context, request_id,
            from_tag, to_tag, expected_date)
        result = {
            "status": final_state,
            "request_id": request_id,
            "request_published": True,
            "native_dispatch_count": 1,
            "retry_count": 0,
            "native_state": terminal["state"],
            "native_return": terminal["native_return"],
            "native_calls_before": native_before["native_calls"],
            "native_calls_after": terminal["native_calls"],
            "attempted_mask_before": native_before["attempted_mask"],
            "attempted_mask_after": terminal["attempted_mask"],
            "logical_observer_ref": world_after["fra_player_ref"],
            "before_player_ref": world_before["current_player_ref"],
            "target_player_ref": world_before["target_player_ref"],
            "observed_player_ref": world_after["current_player_ref"],
            "date_raw": world_after["date_raw"],
            "speed": world_after["speed"],
            "paused": world_after["paused"],
            "mismatches": mismatches,
            "output": str(output_path),
        }
        _write_json_exclusive(output_path / "client-result.json", result)
        return result
    except ControlError as exc:
        request_possible = request_was_published or (context.directory / REQUEST_NAME).exists()
        result = {"status": "unknown_no_retry" if request_possible else "failed_before_dispatch",
                  "reason": exc.code,
                  "message": exc.message, "request_id": request_id,
                  "request_published": request_possible,
                  "native_dispatch_count": 1 if request_possible else 0,
                  "retry_count": 0 if request_possible else None,
                  "output": str(output_path)}
        if not (output_path / "client-result.json").exists():
            _write_json_exclusive(output_path / "client-result.json", result)
        return result


def _date_arg(value: str) -> int:
    if not DECIMAL_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("expected-date must be a canonical nonnegative decimal")
    parsed = int(value, 10)
    if parsed > 0x7fffffff:
        raise argparse.ArgumentTypeError("expected-date exceeds int32")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--from-tag", choices=("POR", "FRA"), required=True)
    parser.add_argument("--to-tag", choices=("POR", "FRA"), required=True)
    parser.add_argument("--expected-date", type=_date_arg, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--test-only", action="store_true",
                        help="Explicitly publish the one-shot TEST_ONLY request")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = execute(args.installation, args.request_id, args.from_tag,
                         args.to_tag, args.expected_date, args.output,
                         test_only=args.test_only)
    except ControlError as exc:
        print(json.dumps({"status": "error", "reason": exc.code,
                          "message": exc.message}, ensure_ascii=True, sort_keys=True), flush=True)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)
    if result["status"] == "confirmed":
        return 0
    if result["status"] == "unknown_no_retry":
        return 3
    return 0 if result["status"] == "prepared_no_dispatch" else 2


if __name__ == "__main__":
    raise SystemExit(main())
