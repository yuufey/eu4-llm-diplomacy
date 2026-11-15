"""Control the v23-v48, v51, and v54-v58 research battle sources through its file protocol.

This module is deliberately narrower than the installer.  It verifies the
recorded process/module identity and build manifest, then publishes one
reversible capture-control request.  ``status`` is read-only: it never creates
the local binding and never writes a native request.  No game function,
network endpoint, or business action is called here.

The native side accepts exactly one ASCII line with eight tokens::

    EU4BATTLE1 nonce command pid creation installation dll_sha256 player_ref

The binding and audit files are operator-side records.  A timeout is
``unknown_no_retry``: the request is left for the native poller and this
process never retransmits it automatically.

The persisted binding generation is the verified process creation FILETIME;
the native startup state is the only unbound state and reports generation 0.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "work") not in sys.path:
    sys.path.insert(0, str(ROOT / "work"))

from bridge.diplomacy_session import file_hash, probe_identity  # noqa: E402
from local_config import game_exe  # noqa: E402
from tools.start_diplomacy_observer import (  # noqa: E402
    _validate_information_battle_manifest,
)


PROTOCOL = "EU4BATTLE1"
CONTROL_NAME = "information-battle-control.request"
PROCESSING_NAME = "information-battle-control.processing"
BINDING_NAME = "information-battle-binding.json"
STATUS_NAME = "information-battle-status.json"
RESPONSE_PREFIX = "information-battle-response-"
STARTED_PREFIX = "information-battle-started-"
AUDIT_PREFIX = "information-battle-control-audit-"
MAX_JSON_BYTES = 1024 * 1024
MAX_STATUS_AGE_SECONDS = 5.0
RESPONSE_TIMEOUT_SECONDS = 10.0
RESPONSE_POLL_SECONDS = 0.05
ZERO_PLAYER_REF = "0000000000000000"
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PLAYER_RE = re.compile(r"^[0-9a-f]{16}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_BINDING_LOCK = threading.RLock()


class ControlError(RuntimeError):
    """A typed, user-facing refusal; it never means a native request ran."""

    def __init__(self, reason: str, message: str | None = None):
        self.reason = reason
        self.message = message or reason
        super().__init__(self.message)

    def as_dict(self) -> dict[str, str]:
        return {"status": "error", "reason": self.reason, "message": self.message}


@dataclass(frozen=True)
class VerifiedContext:
    installation_path: Path
    directory: Path
    installation: dict[str, Any]
    manifest: dict[str, Any]
    current: dict[str, Any]
    dll_path: Path
    dll_sha256: str
    game_sha256: str


def _sha256(value: object, *, lower: bool = False) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ControlError("IDENTITY_SCHEMA_INVALID", "sha256 must be 64 hexadecimal characters")
    result = value.lower()
    if lower and value != result:
        raise ControlError("IDENTITY_SCHEMA_INVALID", "sha256 must be lowercase")
    return result


def _strict_decimal(value: object, name: str, *, positive: bool = False) -> int:
    if isinstance(value, bool):
        raise ControlError("IDENTITY_SCHEMA_INVALID", f"{name} must be decimal")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value and value.isascii() and value.isdecimal():
        result = int(value, 10)
    else:
        raise ControlError("IDENTITY_SCHEMA_INVALID", f"{name} must be decimal")
    if result < 0 or (positive and result == 0):
        raise ControlError("IDENTITY_SCHEMA_INVALID", f"{name} has an invalid value")
    return result


def _read_bounded(path: Path, *, limit: int = MAX_JSON_BYTES) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as exc:
        raise ControlError("FILE_READ_FAILED", str(path)) from exc
    if len(data) > limit:
        raise ControlError("FILE_TOO_LARGE", str(path))
    return data


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> dict[str, Any]:
    data = _read_bounded(path, limit=limit)
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlError("JSON_INVALID", str(path)) from exc
    if not isinstance(value, dict):
        raise ControlError("JSON_SCHEMA_INVALID", str(path))
    return value


def _norm_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ControlError("IDENTITY_SCHEMA_INVALID", "module path is missing")
    try:
        return os.path.normcase(os.path.normpath(str(Path(value).resolve())))
    except OSError as exc:
        raise ControlError("IDENTITY_SCHEMA_INVALID", "module path is invalid") from exc


def _same_path(left: object, right: Path) -> bool:
    return _norm_path(left) == _norm_path(str(right))


def _single_module(modules: object, *, source: str) -> dict[str, Any]:
    if not isinstance(modules, list) or len(modules) != 1 or not isinstance(modules[0], dict):
        raise ControlError("MODULE_SET_NOT_UNIQUE", f"{source} must contain exactly one bridge DLL")
    module = modules[0]
    _norm_path(module.get("path"))
    _sha256(module.get("sha256"), lower=True)
    return module


def _module_matches(module: dict[str, Any], dll_path: Path, dll_sha256: str) -> None:
    if not _same_path(module.get("path"), dll_path):
        raise ControlError("MODULE_PATH_MISMATCH", "loaded module path differs from the pinned DLL")
    if module.get("sha256") != dll_sha256:
        raise ControlError("MODULE_HASH_MISMATCH", "loaded module hash differs from the pinned DLL")
    name = module.get("name")
    if not isinstance(name, str) or name.lower() != dll_path.name.lower():
        raise ControlError("MODULE_NAME_MISMATCH", "loaded module name differs from the pinned DLL")


def _validate_manifest(manifest: dict[str, Any], directory: Path) -> None:
    if type(manifest.get("version")) is not int or manifest.get("version") not in (23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64):
        raise ControlError("BUILD_MANIFEST_MISMATCH", "v23-v48, v51, or v54-v64 information-battle manifest required")
    try:
        _validate_information_battle_manifest(manifest, directory)
    except SystemExit as exc:
        raise ControlError("BUILD_MANIFEST_MISMATCH", str(exc)) from exc
    except Exception as exc:
        raise ControlError("BUILD_MANIFEST_MISMATCH", str(exc)) from exc


def _load_context(installation_path: Path | str) -> VerifiedContext:
    supplied = Path(installation_path)
    try:
        path = supplied.resolve()
    except OSError as exc:
        raise ControlError("INSTALLATION_PATH_INVALID", str(supplied)) from exc
    if not path.is_file() or path.name.lower() != "installation.json":
        raise ControlError("INSTALLATION_PATH_INVALID", "--installation must name installation.json")
    directory = path.parent
    manifest_path = directory / "build-manifest.json"
    installation = _read_json(path)
    manifest = _read_json(manifest_path)
    _validate_manifest(manifest, directory)

    game_sha = _sha256(manifest.get("game_sha256"), lower=True)
    dll_sha = _sha256(manifest.get("dll_sha256"), lower=True)
    dll_path = directory / f"eu4_bridge_diplomacy_observer_v{manifest['version']}.dll"
    if not dll_path.is_file():
        raise ControlError("BUILD_MANIFEST_MISMATCH", "pinned observer DLL is missing")
    try:
        actual_dll_sha = file_hash(dll_path, refresh=True)
    except (OSError, RuntimeError) as exc:
        raise ControlError("BUILD_MANIFEST_MISMATCH", "unable to hash pinned observer DLL") from exc
    if actual_dll_sha != dll_sha:
        raise ControlError("BUILD_MANIFEST_MISMATCH", "observer DLL hash differs from manifest")

    pid = _strict_decimal(installation.get("pid"), "pid", positive=True)
    creation = _strict_decimal(installation.get("creation_filetime"), "creation_filetime", positive=True)
    session_id = installation.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise ControlError("IDENTITY_SCHEMA_INVALID", "session_id is missing")
    install_game_sha = _sha256(installation.get("game_sha256"), lower=True)
    install_dll_sha = _sha256(installation.get("dll_sha256"), lower=True)
    if install_game_sha != game_sha or install_dll_sha != dll_sha:
        raise ControlError("IDENTITY_PIN_MISMATCH", "installation and manifest hashes differ")
    recorded_module = _single_module(
        installation.get("modules_after_install"), source="modules_after_install"
    )
    _module_matches(recorded_module, dll_path, dll_sha)

    try:
        current = probe_identity(pid, game_exe())
    except Exception as exc:
        raise ControlError("IDENTITY_PROBE_FAILED", str(exc)) from exc
    if not isinstance(current, dict):
        raise ControlError("IDENTITY_PROBE_FAILED", "identity probe returned no record")
    current_pid = _strict_decimal(current.get("pid"), "current.pid", positive=True)
    current_creation = _strict_decimal(current.get("creation_filetime"), "current.creation_filetime", positive=True)
    if current_pid != pid or current_creation != creation:
        raise ControlError("PROCESS_IDENTITY_MISMATCH", "pid or creation time changed")
    if current.get("session_id") != session_id:
        raise ControlError("SESSION_ID_MISMATCH", "session_id changed")
    if _sha256(current.get("game_sha256"), lower=True) != game_sha:
        raise ControlError("GAME_HASH_MISMATCH", "running game hash differs from manifest")
    live_module = _single_module(current.get("modules"), source="live modules")
    _module_matches(live_module, dll_path, dll_sha)
    return VerifiedContext(path, directory, installation, manifest, current, dll_path, dll_sha, game_sha)


def _validate_player_ref(value: object, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _PLAYER_RE.fullmatch(value):
        raise ControlError("PLAYER_REF_INVALID", "player-ref must be exactly 16 lowercase hexadecimal characters")
    if not allow_zero and value == ZERO_PLAYER_REF:
        raise ControlError("PLAYER_REF_INVALID", "player-ref must identify a nonzero physical player")
    return value


def _binding_path(context: VerifiedContext) -> Path:
    return context.directory / BINDING_NAME


def _load_binding(context: VerifiedContext) -> dict[str, Any]:
    binding = _read_json(_binding_path(context))
    if binding.get("schema") != "EU4-BATTLE-CONTROL/1":
        raise ControlError("BINDING_INVALID", "unsupported binding schema")
    installation = _strict_decimal(binding.get("installation"), "binding.installation", positive=True)
    generation = _strict_decimal(binding.get("generation"), "binding.generation", positive=True)
    expected_generation = _strict_decimal(
        context.installation.get("creation_filetime"), "creation_filetime", positive=True
    )
    if installation > 0xFFFFFFFFFFFFFFFF or generation != expected_generation:
        raise ControlError("BINDING_INVALID", "binding generation or installation is invalid")
    if _strict_decimal(binding.get("pid"), "binding.pid", positive=True) != context.installation["pid"]:
        raise ControlError("BINDING_IDENTITY_MISMATCH", "binding pid differs from installation")
    if _strict_decimal(binding.get("creation_filetime"), "binding.creation_filetime", positive=True) != context.installation["creation_filetime"]:
        raise ControlError("BINDING_IDENTITY_MISMATCH", "binding creation differs from installation")
    if binding.get("session_id") != context.installation.get("session_id"):
        raise ControlError("BINDING_IDENTITY_MISMATCH", "binding session differs from installation")
    if binding.get("dll_sha256") != context.dll_sha256:
        raise ControlError("BINDING_IDENTITY_MISMATCH", "binding DLL hash differs from installation")
    player = binding.get("player_ref")
    if player is not None:
        _validate_player_ref(player)
    binding["installation"] = installation
    binding["generation"] = generation
    return binding


def _write_exclusive_json(path: Path, value: dict[str, Any], *, reason: str) -> None:
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ControlError(reason, str(path)) from exc
    except OSError as exc:
        raise ControlError("FILE_WRITE_FAILED", str(path)) from exc


def _write_atomic_exclusive_json(path: Path, value: dict[str, Any], *, reason: str) -> None:
    """Publish a complete binding without exposing a partially written file."""
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ControlError(reason, str(path)) from exc
        except OSError as exc:
            raise ControlError("FILE_WRITE_FAILED", str(path)) from exc
    except FileExistsError as exc:
        raise ControlError("FILE_WRITE_FAILED", str(temporary)) from exc
    except OSError as exc:
        raise ControlError("FILE_WRITE_FAILED", str(path)) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _new_binding(context: VerifiedContext, player_ref: str) -> dict[str, Any]:
    value = {
        "schema": "EU4-BATTLE-CONTROL/1",
        "installation": str(_new_installation_id()),
        # The process creation FILETIME is the stream generation.  A fixed
        # generation would allow a later process to append to an old stream.
        "generation": str(context.installation["creation_filetime"]),
        "pid": int(context.installation["pid"]),
        "creation_filetime": str(context.installation["creation_filetime"]),
        "session_id": context.installation["session_id"],
        "game_sha256": context.game_sha256,
        "dll_sha256": context.dll_sha256,
        "player_ref": player_ref,
        "created_at_ns": time.time_ns(),
    }
    _write_atomic_exclusive_json(_binding_path(context), value, reason="BINDING_ALREADY_EXISTS")
    value["installation"] = int(value["installation"])
    return value


def _new_installation_id() -> int:
    for _ in range(32):
        value = secrets.randbits(64)
        if isinstance(value, int) and 0 < value <= 0xFFFFFFFFFFFFFFFF:
            return value
    raise ControlError("INSTALLATION_ID_FAILED", "unable to generate a nonzero uint64 installation id")


def _ensure_binding(context: VerifiedContext, player_ref: str) -> dict[str, Any]:
    with _BINDING_LOCK:
        path = _binding_path(context)
        if path.exists():
            binding = _load_binding(context)
            stored = binding.get("player_ref")
            if stored != player_ref:
                raise ControlError("BINDING_PLAYER_REF_MISMATCH", "existing binding is owned by another player-ref")
            return binding
        try:
            return _new_binding(context, player_ref)
        except ControlError as exc:
            if exc.reason != "BINDING_ALREADY_EXISTS":
                raise
            binding = _load_binding(context)
            if binding.get("player_ref") != player_ref:
                raise ControlError("BINDING_PLAYER_REF_MISMATCH", "concurrent binding uses another player-ref")
            return binding


def _require_binding(context: VerifiedContext) -> dict[str, Any]:
    path = _binding_path(context)
    if not path.is_file():
        raise ControlError("BINDING_REQUIRED", "disable requires an existing binding")
    return _load_binding(context)


def _request_line(*, nonce: str, command: str, context: VerifiedContext, installation: int, player_ref: str) -> bytes:
    if not _NONCE_RE.fullmatch(nonce):
        raise ControlError("NONCE_INVALID", "nonce must be 32 lowercase hexadecimal characters")
    if command not in ("enable", "disable", "status"):
        raise ControlError("COMMAND_INVALID", command)
    if installation <= 0 or installation > 0xFFFFFFFFFFFFFFFF:
        raise ControlError("INSTALLATION_ID_INVALID", "installation must be a nonzero uint64")
    _validate_player_ref(player_ref, allow_zero=True)
    line = f"{PROTOCOL} {nonce} {command} {context.installation['pid']} {context.installation['creation_filetime']} {installation} {context.dll_sha256} {player_ref}\n"
    try:
        return line.encode("ascii")
    except UnicodeEncodeError as exc:  # defensive; all fields are constrained above
        raise ControlError("REQUEST_ENCODING_FAILED", "request is not ASCII") from exc


def _audit_path(directory: Path, nonce: str) -> Path:
    return directory / f"{AUDIT_PREFIX}{nonce}.jsonl"


def _audit_reserve(context: VerifiedContext, *, nonce: str, command: str, installation: int, player_ref: str) -> Path:
    path = _audit_path(context.directory, nonce)
    value = {
        "event": "request_prepared",
        "nonce": nonce,
        "command": command,
        "pid": int(context.installation["pid"]),
        "creation_filetime": str(context.installation["creation_filetime"]),
        "installation": str(installation),
        "dll_sha256": context.dll_sha256,
        "player_ref": player_ref,
        "created_at_ns": time.time_ns(),
    }
    _write_exclusive_json(path, value, reason="NONCE_ALREADY_AUDITED")
    return path


def _audit_append(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with path.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        # The control outcome must still be returned.  A missing audit tail is
        # an explicit local-durability caveat, not permission to retry.
        return


def _publish_request(context: VerifiedContext, *, nonce: str, payload: bytes) -> None:
    target = context.directory / CONTROL_NAME
    if target.exists() or (context.directory / PROCESSING_NAME).exists():
        raise ControlError("CONTROL_BUSY", "request or processing file already exists")
    temporary = context.directory / f".{CONTROL_NAME}.{nonce}.tmp"
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise ControlError("CONTROL_BUSY", "request appeared before atomic publish") from exc
        except OSError as exc:
            raise ControlError("CONTROL_PUBLISH_FAILED", str(exc)) from exc
    except FileExistsError as exc:
        raise ControlError("CONTROL_PUBLISH_FAILED", str(temporary)) from exc
    except OSError as exc:
        raise ControlError("CONTROL_PUBLISH_FAILED", str(exc)) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _new_nonce(directory: Path) -> str:
    for _ in range(64):
        nonce = secrets.token_hex(16)
        if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
            continue
        if (_audit_path(directory, nonce).exists()
                or (directory / f"{RESPONSE_PREFIX}{nonce}.json").exists()
                or (directory / f"{STARTED_PREFIX}{nonce}.json").exists()):
            continue
        return nonce
    raise ControlError("NONCE_GENERATION_FAILED", "unable to reserve a unique nonce")


def _response_installation(value: object) -> int:
    result = _strict_decimal(value, "response.installation")
    if result > 0xFFFFFFFFFFFFFFFF:
        raise ControlError("RESPONSE_SCHEMA_INVALID", "response installation exceeds uint64")
    return result


def _validate_response(context: VerifiedContext, *, nonce: str, command: str, installation: int, response: dict[str, Any]) -> dict[str, Any]:
    if response.get("request_id") != nonce or response.get("command") != command:
        raise ControlError("RESPONSE_IDENTITY_MISMATCH", "response request_id or command differs")
    if _strict_decimal(response.get("pid"), "response.pid", positive=True) != context.installation["pid"]:
        raise ControlError("RESPONSE_IDENTITY_MISMATCH", "response pid differs")
    if _strict_decimal(response.get("creation_filetime"), "response.creation_filetime", positive=True) != context.installation["creation_filetime"]:
        raise ControlError("RESPONSE_IDENTITY_MISMATCH", "response creation differs")
    if response.get("dll_sha256") != context.dll_sha256:
        raise ControlError("RESPONSE_IDENTITY_MISMATCH", "response DLL hash differs")
    returned_installation = _response_installation(response.get("installation"))
    returned_generation = _strict_decimal(response.get("generation"), "response.generation")
    expected_generation = _strict_decimal(
        context.installation.get("creation_filetime"), "creation_filetime", positive=True
    )
    if returned_installation == 0:
        if returned_generation != 0:
            raise ControlError("RESPONSE_IDENTITY_MISMATCH", "unbound response generation must be 0")
    elif returned_generation != expected_generation:
        raise ControlError("RESPONSE_IDENTITY_MISMATCH", "response generation differs from process creation")
    accepted = response.get("accepted")
    if type(accepted) is not bool:
        raise ControlError("RESPONSE_SCHEMA_INVALID", "response accepted must be boolean")
    if accepted and returned_installation != installation:
        raise ControlError("RESPONSE_IDENTITY_MISMATCH", "accepted response installation differs")
    if not accepted and not (command in {"enable", "disable"} and returned_installation == 0):
        if returned_installation != installation:
            raise ControlError("RESPONSE_IDENTITY_MISMATCH", "rejected response installation differs")
    return {
        "status": "accepted" if accepted else "rejected",
        "nonce": nonce,
        "command": command,
        "installation": str(returned_installation),
        "response": response,
    }


def _wait_response(context: VerifiedContext, *, nonce: str, command: str, installation: int) -> dict[str, Any]:
    response_path = context.directory / f"{RESPONSE_PREFIX}{nonce}.json"
    deadline = time.monotonic() + RESPONSE_TIMEOUT_SECONDS
    while True:
        if response_path.is_file():
            response = _read_json(response_path, limit=MAX_JSON_BYTES)
            return _validate_response(
                context, nonce=nonce, command=command, installation=installation, response=response
            )
        if time.monotonic() >= deadline:
            raise ControlError("unknown_no_retry", "native response did not arrive within 10 seconds")
        time.sleep(RESPONSE_POLL_SECONDS)


def _issue(context: VerifiedContext, *, command: str, installation: int, player_ref: str) -> dict[str, Any]:
    control = context.directory / CONTROL_NAME
    processing = context.directory / PROCESSING_NAME
    if control.exists() or processing.exists():
        raise ControlError("CONTROL_BUSY", "request or processing file already exists")
    nonce = _new_nonce(context.directory)
    payload = _request_line(
        nonce=nonce, command=command, context=context, installation=installation, player_ref=player_ref
    )
    audit = _audit_reserve(
        context, nonce=nonce, command=command, installation=installation, player_ref=player_ref
    )
    try:
        _publish_request(context, nonce=nonce, payload=payload)
        try:
            result = _wait_response(context, nonce=nonce, command=command, installation=installation)
        except ControlError as exc:
            if exc.reason != "unknown_no_retry":
                _audit_append(audit, {"event": "response_error", "reason": exc.reason, "message": exc.message})
                raise
            result = {
                "status": "unknown_no_retry",
                "nonce": nonce,
                "command": command,
                "installation": str(installation),
                "reason": exc.reason,
            }
        _audit_append(audit, {"event": "outcome", **result, "recorded_at_ns": time.time_ns()})
        return result
    except ControlError as exc:
        _audit_append(audit, {"event": "request_error", "reason": exc.reason, "message": exc.message})
        raise


def _status_result(context: VerifiedContext) -> dict[str, Any]:
    path = context.directory / STATUS_NAME
    if not path.is_file():
        raise ControlError("NATIVE_STATUS_MISSING", str(path))
    try:
        status_stat = path.stat()
        mtime = status_stat.st_mtime
    except OSError as exc:
        raise ControlError("NATIVE_STATUS_UNAVAILABLE", str(path)) from exc
    age = time.time() - mtime
    if age < -1.0 or age > MAX_STATUS_AGE_SECONDS:
        raise ControlError("NATIVE_STATUS_STALE", f"status age {age:.3f}s")
    status = _read_json(path)
    if _strict_decimal(status.get("pid"), "status.pid", positive=True) != context.installation["pid"]:
        raise ControlError("STATUS_IDENTITY_MISMATCH", "status pid differs")
    if _strict_decimal(status.get("creation_filetime"), "status.creation_filetime", positive=True) != context.installation["creation_filetime"]:
        raise ControlError("STATUS_IDENTITY_MISMATCH", "status creation differs")
    if status.get("exe_sha256") != context.game_sha256 or status.get("dll_sha256") != context.dll_sha256:
        raise ControlError("STATUS_IDENTITY_MISMATCH", "status executable or DLL hash differs")
    state = status.get("state")
    if state not in {"cold", "ready", "enabled", "disabled", "source_changed", "fault", "restart_required"}:
        raise ControlError("STATUS_SCHEMA_INVALID", "unknown native state")
    native_installation = _response_installation(status.get("installation"))
    binding_path = _binding_path(context)
    binding = None
    native_generation = _strict_decimal(status.get("generation"), "status.generation")
    # A failed first enable or a thread/source guard can leave the native
    # manager unbound while still exposing a useful diagnostic state.  The
    # only impossible unbound state is an accepted/active source.
    if native_installation == 0 and state != "enabled":
        if native_generation != 0:
            raise ControlError("STATUS_IDENTITY_MISMATCH", "unbound native status must have generation 0")
    else:
        expected_generation = _strict_decimal(
            context.installation.get("creation_filetime"), "creation_filetime", positive=True
        )
        if native_generation != expected_generation:
            raise ControlError("STATUS_IDENTITY_MISMATCH", "status generation is not process creation")
        if not binding_path.is_file():
            raise ControlError("BINDING_REQUIRED", "enabled native status requires local binding")
        binding = _load_binding(context)
        if native_installation != int(binding["installation"]):
            raise ControlError("STATUS_IDENTITY_MISMATCH", "status installation differs")
    return {
        "status": "observed",
        "fresh": True,
        "age_seconds": max(0.0, age),
        # Sample before reading: a concurrent heartbeat can make this bound
        # conservative, but cannot make an old document appear newer than a
        # completed control transition.
        "observed_at_ns": status_stat.st_mtime_ns,
        "installation": str(native_installation),
        "native": status,
        "binding": binding,
    }


def run_control(installation: Path | str, command: str, player_ref: str | None = None) -> dict[str, Any]:
    """Run one status/enable/disable operation without a retry loop."""
    if command not in {"status", "enable", "disable"}:
        raise ControlError("COMMAND_INVALID", command)
    context = _load_context(installation)
    if command == "status":
        return _status_result(context)
    if ((context.directory / CONTROL_NAME).exists()
            or (context.directory / PROCESSING_NAME).exists()):
        raise ControlError("CONTROL_BUSY", "request or processing file already exists")
    if command == "enable":
        requested_player = _validate_player_ref(player_ref)
        binding = _ensure_binding(context, requested_player)
        return _issue(
            context,
            command=command,
            installation=int(binding["installation"]),
            player_ref=requested_player,
        )
    binding = _require_binding(context)
    stored_player = binding.get("player_ref")
    player = stored_player if isinstance(stored_player, str) else ZERO_PLAYER_REF
    _validate_player_ref(player, allow_zero=True)
    return _issue(context, command=command, installation=int(binding["installation"]), player_ref=player)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--command", choices=("status", "enable", "disable"), required=True)
    parser.add_argument("--player-ref", help="exact 16 lowercase hex physical-player fullref; required for enable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "enable" and args.player_ref is None:
        print(json.dumps({"status": "error", "reason": "PLAYER_REF_REQUIRED"}, sort_keys=True), flush=True)
        return 2
    try:
        result = run_control(args.installation, args.command, args.player_ref)
    except ControlError as exc:
        print(json.dumps(exc.as_dict(), ensure_ascii=True, sort_keys=True), flush=True)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)
    return 0 if result.get("status") in {"observed", "accepted"} else 3 if result.get("status") == "unknown_no_retry" else 2


if __name__ == "__main__":
    raise SystemExit(main())
