from __future__ import annotations

import ctypes
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools import control_information_current_country as subject


PID = 41234
CREATION = 134376348223436218
SESSION = f"{PID}-{CREATION:x}"
GAME_SHA = "a" * 64
POR_REF = "000000bd00524f50"
FRA_REF = "0000005500415246"
FRA_REF_WRONG_SLOT = "0000005600415246"
DATE_RAW = 56562768


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _status(*, state: str = "ready", request_id: str = "",
            request_from: str = "", request_to: str = "",
            before_ref: str = "0000000000000000",
            target_ref: str = "0000000000000000",
            observed_ref: str = POR_REF,
            date_before: int = DATE_RAW, date_raw: int = DATE_RAW,
            speed: int = 0, paused: bool = True,
            native_attempted: bool = False,
            native_return: int | None = None,
            native_calls: int = 0, attempted_mask: int = 0,
            authorized_fra_ref: str = "0000000000000000",
            frame_thread: int = 777, reason: str = "ready") -> dict[str, Any]:
    return {
        "schema": "EU4COUNTRY1", "state": state, "pid": PID,
        "creation_filetime": str(CREATION), "dll_sha256": "c" * 64,
        "request_id": request_id, "request_from": request_from,
        "request_to": request_to, "before_player_ref": before_ref,
        "target_player_ref": target_ref, "observed_player_ref": observed_ref,
        "date_before": date_before, "date_raw": date_raw, "speed": speed,
        "paused": paused, "native_attempted": native_attempted,
        "native_return": native_return, "native_calls": native_calls,
        "attempted_mask": attempted_mask,
        "authorized_fra_ref": authorized_fra_ref,
        "frame_thread": frame_thread, "reason": reason,
    }


def _world(*, tag: str = "POR", current_ref: str | None = None,
           date: int = DATE_RAW, speed: int = 0, paused: bool = True) -> dict[str, Any]:
    current_ref = current_ref or (POR_REF if tag == "POR" else FRA_REF)
    return {
        "game_pointer": "0x7ff600001000",
        "current_player_ref": current_ref,
        "current_tag": tag,
        "current_slot": 189 if tag == "POR" else 85,
        "target_player_ref": FRA_REF if tag == "POR" else POR_REF,
        "fra_player_ref": FRA_REF,
        "date_raw": date,
        "speed": speed,
        "paused": paused,
        "human_count_raw": 1,
        "controller_types_raw": {
            "status": "observed", "pointer": "0x7ff600005000",
            "slots": {"POR:189": 1 if tag == "POR" else 0,
                      "FRA:85": 1 if tag == "FRA" else 0},
        },
        "rpm_budget": {"calls": 32, "bytes": 4096,
                        "max_calls": 2048, "max_bytes": 128 * 1024,
                        "native_calls": 0, "memory_written": False},
    }


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.now += max(duration, 0.001)


class Fixture:
    def __init__(self, tmp_path: Path, *, version: int = 31,
                 terminal: dict[str, Any] | None = None,
                 after: dict[str, Any] | None = None,
                 terminal_state: str = "confirmed") -> None:
        self.directory = tmp_path / "installed-v31"
        self.directory.mkdir()
        self.installation_path = self.directory / "installation.json"
        self.dll_path = self.directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        self.dll_path.write_bytes(b"owned offline fixture DLL bytes")
        self.dll_sha = hashlib.sha256(self.dll_path.read_bytes()).hexdigest()
        self.manifest_path = self.directory / "build-manifest.json"
        manifest = {
            "version": version,
            "experiment_id": "fixture-exp",
            "game_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
            "dll": str(self.dll_path),
            "sources": [{"name": "diplomacy-observer-v10.cpp", "sha256": "d" * 64}],
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1",
            ],
            "current_country_control_test_only": True,
            "current_country_control_protocol": "EU4COUNTRY1",
            "current_country_control_entry_rva": "0x779360",
        }
        if version != 31:
            manifest["compiler_arguments"] = ["-DBRIDGE_INFORMATION_BATTLE=1"]
            manifest.pop("current_country_control_test_only")
            manifest.pop("current_country_control_protocol")
            manifest.pop("current_country_control_entry_rva")
        _write_json(self.manifest_path, manifest)
        installation = {
            "pid": PID,
            "creation_filetime": CREATION,
            "session_id": SESSION,
            "experiment_id": "fixture-exp",
            "game_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
            "modules_after_install": [{
                "name": self.dll_path.name,
                "path": str(self.dll_path),
                "sha256": self.dll_sha,
            }],
        }
        _write_json(self.installation_path, installation)
        self.identity = {
            "pid": PID,
            "creation_filetime": CREATION,
            "session_id": SESSION,
            "game_sha256": GAME_SHA,
            "modules": [{
                "name": self.dll_path.name,
                "path": str(self.dll_path),
                "sha256": self.dll_sha,
            }],
        }
        self.battle_status = {
            "state": "ready", "pid": PID,
            "creation_filetime": str(CREATION), "installation": "0",
            "generation": "0", "exe_sha256": GAME_SHA,
            "dll_sha256": self.dll_sha,
        }
        _write_json(self.directory / subject.BATTLE_STATUS_NAME, self.battle_status)
        self.initial_status = _status()
        self.initial_status["dll_sha256"] = self.dll_sha
        self.terminal_status = terminal
        if self.terminal_status is not None:
            self.terminal_status["dll_sha256"] = self.dll_sha
        self.after = after or _world(tag="FRA", current_ref=FRA_REF)
        self.terminal_state = terminal_state
        self.status_reads = 0
        self.world_reads = 0
        self.clock = FakeClock()
        self.output = tmp_path / "operator-output-001"

    def identity_probe(self, pid: int, _exe: Path) -> dict[str, Any]:
        assert pid == PID
        return self.identity

    def status_reader(self, _path: Path) -> tuple[dict[str, Any], bytes, float]:
        self.status_reads += 1
        request_exists = (self.directory / subject.REQUEST_NAME).exists()
        if self.terminal_status is not None and request_exists:
            value = self.terminal_status
        elif self.terminal_state == "pending_forever" and request_exists:
            value = _status(state="pending", request_id="r71-001",
                            request_from="POR", request_to="FRA",
                            observed_ref=POR_REF, native_attempted=True,
                            reason="awaiting_frame")
        else:
            value = self.initial_status
        raw = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
        return value, raw, 0.0

    def world_reader(self, _context: Any, from_tag: str, to_tag: str) -> dict[str, Any]:
        self.world_reads += 1
        if self.world_reads <= 3:
            assert (from_tag, to_tag) == ("POR", "FRA")
            return _world()
        return self.after

    def dependencies(self) -> subject.Dependencies:
        return subject.Dependencies(
            identity_probe=self.identity_probe,
            world_reader=self.world_reader,
            status_reader=self.status_reader,
            sleep=self.clock.sleep,
            monotonic=self.clock.monotonic,
        )


class FakeRPMKernel:
    """Small byte-addressed process-memory stand-in for the real RPM wrapper."""

    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.read_calls: list[tuple[int, int]] = []
        self.open_calls: list[tuple[int, bool, int]] = []
        self.close_calls: list[int] = []

    def put(self, address: int, raw: bytes) -> None:
        self.bytes.update({address + offset: byte for offset, byte in enumerate(raw)})

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        self.open_calls.append((access, inherit, pid))
        return 0xCAFE

    def CloseHandle(self, handle: int) -> int:
        self.close_calls.append(handle)
        return 1

    def ReadProcessMemory(self, handle: int, address: Any, buffer: Any,
                          size: int, actual: Any) -> int:
        assert handle == 0xCAFE
        start = int(address.value)
        self.read_calls.append((start, size))
        try:
            raw = bytes(self.bytes[start + offset] for offset in range(size))
        except KeyError:
            return 0
        ctypes.memmove(buffer, raw, size)
        ctypes.cast(actual, ctypes.POINTER(ctypes.c_size_t)).contents.value = size
        return 1


def _confirmed(request_id: str = "r71-001", **overrides: Any) -> dict[str, Any]:
    value = _status(
        state="confirmed", request_id=request_id, request_from="POR", request_to="FRA",
        before_ref=POR_REF, target_ref=FRA_REF, observed_ref=FRA_REF,
        native_attempted=True, native_return=1, native_calls=1,
        attempted_mask=1, authorized_fra_ref=FRA_REF, reason="confirmed",
    )
    value.update(overrides)
    return value


def _execute(fixture: Fixture, *, request_id: str = "r71-001",
             timeout: float = 0.02) -> dict[str, Any]:
    return subject.execute(
        fixture.installation_path, request_id, "POR", "FRA", DATE_RAW,
        fixture.output, test_only=True, dependencies=fixture.dependencies(),
        preflight_timeout=1.0, terminal_timeout=timeout,
    )


def test_real_world_reader_observes_por_then_fra_from_synthetic_rpm(
        monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = FakeRPMKernel()
    module_base = 0x140000000
    game = 0x50000000
    database = 0x51000000
    server = 0x52000000
    pause_manager = 0x53000000
    controller_types = 0x54000000
    country_table = 0x55000000
    por_country = 0x56000000
    fra_country = 0x57000000
    profile = subject._country_memory._active_profile()
    layout = subject._country_memory._profile_layout(profile)
    loc = subject._localization_memory

    def put_u32(address: int, value: int) -> None:
        kernel.put(address, int(value).to_bytes(4, "little", signed=False))

    def put_i32(address: int, value: int) -> None:
        kernel.put(address, int(value).to_bytes(4, "little", signed=True))

    def put_u64(address: int, value: int) -> None:
        kernel.put(address, int(value).to_bytes(8, "little", signed=False))

    put_u64(module_base + layout["game_rva"], game)
    put_u64(module_base + layout["database_rva"], database)
    put_u64(game + layout["game_date_offset"], DATE_RAW)
    put_u32(game + 0x1E08, 0)
    put_u64(game + 0x1E00, server)
    put_u64(server + 0x418, pause_manager)
    kernel.put(pause_manager + 0x48, b"\x01")
    put_u64(pause_manager + 0x50, server)
    put_i32(game + 0xA60, 7)
    put_u64(game + 0x1D48, controller_types)
    put_i32(controller_types + 189 * 4, 0x105)
    put_i32(controller_types + 85 * 4, 0x205)

    put_u64(database + loc.COUNTRY_TABLE_OFFSET, country_table)
    table_bytes = bytearray(loc.COUNTRY_SCAN_ENTRIES * 8)
    table_bytes[189 * 8:190 * 8] = por_country.to_bytes(8, "little")
    table_bytes[85 * 8:86 * 8] = fra_country.to_bytes(8, "little")
    kernel.put(country_table, bytes(table_bytes))
    put_u64(por_country + loc.COUNTRY_HANDLE_OFFSET, int(POR_REF, 16))
    put_u64(fra_country + loc.COUNTRY_HANDLE_OFFSET, int(FRA_REF, 16))

    context = SimpleNamespace(pid=PID, installation={
        "pid": PID, "creation_filetime": CREATION,
        "session_id": SESSION, "game_sha256": GAME_SHA,
    })
    monkeypatch.setattr(subject._country_memory, "_configure_kernel", lambda: kernel)
    monkeypatch.setattr(subject._country_memory, "_capture_identity",
                        lambda _report, _installation, _kernel, _handle: module_base)

    put_u64(game + 0x1E60, int(POR_REF, 16))
    before = subject._read_world_control(context, "POR", "FRA")
    put_u64(game + 0x1E60, int(FRA_REF, 16))
    after = subject._read_world_control(context, "POR", "FRA")

    assert before["current_tag"] == "POR"
    assert before["current_player_ref"] == POR_REF
    assert before["target_player_ref"] == FRA_REF
    assert after["current_tag"] == "FRA"
    assert after["current_player_ref"] == FRA_REF
    assert after["target_player_ref"] == FRA_REF
    for world in (before, after):
        assert world["human_count_raw"] == 7
        assert world["controller_types_raw"] == {
            "status": "observed", "pointer": f"0x{controller_types:x}",
            "slots": {"FRA:85": 0x205, "POR:189": 0x105},
        }
        assert world["rpm_budget"]["native_calls"] == 0
        assert world["rpm_budget"]["memory_written"] is False
    assert len(kernel.read_calls) > 0
    assert kernel.open_calls == [
        (subject._country_memory.PROCESS_ACCESS, False, PID),
        (subject._country_memory.PROCESS_ACCESS, False, PID),
    ]
    assert kernel.close_calls == [0xCAFE, 0xCAFE]


def test_fra_to_por_preflight_requires_fra_fullref_already_authorized() -> None:
    world = _world(tag="FRA", current_ref=FRA_REF)
    status = _status(
        state="confirmed", request_id="prior-por-to-fra",
        request_from="POR", request_to="FRA", before_ref=POR_REF,
        target_ref=FRA_REF, observed_ref=FRA_REF, native_attempted=True,
        native_return=1, native_calls=1, authorized_fra_ref=FRA_REF,
    )
    assert subject._status_matches_preflight(status, world, "FRA", "POR", DATE_RAW)
    status["authorized_fra_ref"] = "0000000000000000"
    assert not subject._status_matches_preflight(status, world, "FRA", "POR", DATE_RAW)


def test_full_fra_to_por_execute_clears_authorization_and_preserves_fra_observer(
        tmp_path: Path) -> None:
    terminal = _status(
        state="confirmed", request_id="r71-reverse-001",
        request_from="FRA", request_to="POR", before_ref=FRA_REF,
        target_ref=POR_REF, observed_ref=POR_REF, native_attempted=True,
        native_return=1, native_calls=2, attempted_mask=3,
        authorized_fra_ref="0000000000000000", reason="confirmed",
    )
    fixture = Fixture(tmp_path, terminal=terminal, after=_world(tag="POR"))
    fixture.output = tmp_path / "operator-output-reverse-001"
    fixture.initial_status = _status(
        state="confirmed", request_id="r71-forward-previous",
        request_from="POR", request_to="FRA", before_ref=POR_REF,
        target_ref=FRA_REF, observed_ref=FRA_REF, native_attempted=True,
        native_return=1, native_calls=1, attempted_mask=1,
        authorized_fra_ref=FRA_REF, reason="confirmed",
    )
    fixture.initial_status["dll_sha256"] = fixture.dll_sha
    fixture.battle_status.update({
        "state": "disabled", "installation": "731", "generation": str(CREATION),
    })
    _write_json(fixture.directory / subject.BATTLE_STATUS_NAME, fixture.battle_status)
    _write_json(fixture.directory / subject.BATTLE_BINDING_NAME, {
        "schema": "EU4-BATTLE-CONTROL/1", "installation": "731",
        "generation": str(CREATION), "pid": PID,
        "creation_filetime": str(CREATION), "session_id": SESSION,
        "game_sha256": GAME_SHA, "dll_sha256": fixture.dll_sha,
        "player_ref": FRA_REF,
    })

    def reverse_world_reader(_context: Any, from_tag: str,
                             to_tag: str) -> dict[str, Any]:
        fixture.world_reads += 1
        assert (from_tag, to_tag) == ("FRA", "POR")
        return _world(tag="FRA") if fixture.world_reads <= 3 else _world(tag="POR")

    fixture.world_reader = reverse_world_reader  # type: ignore[method-assign]
    result = subject.execute(
        fixture.installation_path, "r71-reverse-001", "FRA", "POR", DATE_RAW,
        fixture.output, test_only=True, dependencies=fixture.dependencies(),
        preflight_timeout=1.0, terminal_timeout=0.02,
    )

    assert result["status"] == "confirmed"
    assert result["native_dispatch_count"] == 1
    assert result["retry_count"] == 0
    assert result["native_calls_before"] == 1
    assert result["native_calls_after"] == 2
    assert result["attempted_mask_before"] == 1
    assert result["attempted_mask_after"] == 3
    assert result["before_player_ref"] == FRA_REF
    assert result["target_player_ref"] == POR_REF
    assert result["observed_player_ref"] == POR_REF
    assert result["logical_observer_ref"] == FRA_REF
    after = json.loads((fixture.output / "world-after.json").read_text(encoding="utf-8"))
    assert after["current_player_ref"] == POR_REF
    assert after["fra_player_ref"] == FRA_REF
    terminal_status = json.loads(
        (fixture.output / "native-status-terminal.json").read_text(encoding="utf-8"))
    assert terminal_status["authorized_fra_ref"] == "0000000000000000"
    assert terminal_status["native_calls"] == 2
    assert terminal_status["attempted_mask"] == 3
    binding = json.loads((fixture.directory / subject.BATTLE_BINDING_NAME).read_text(encoding="utf-8"))
    assert binding["player_ref"] == FRA_REF
    assert fixture.status_reads >= 2
    assert (fixture.directory / subject.REQUEST_NAME).read_text(encoding="ascii").count("EU4COUNTRY1") == 1


@pytest.mark.parametrize("human_count", [0, 2])
def test_non_single_human_count_is_rejected_before_request_write(
        tmp_path: Path, human_count: int) -> None:
    fixture = Fixture(tmp_path, terminal=_confirmed())

    def wrong_human_world(_context: Any, _from_tag: str, _to_tag: str) -> dict[str, Any]:
        world = _world()
        world["human_count_raw"] = human_count
        return world

    fixture.world_reader = wrong_human_world  # type: ignore[method-assign]
    with pytest.raises(subject.ControlError, match="WORLD_CONTROL_PRECONDITION_MISMATCH"):
        _execute(fixture)
    assert not fixture.output.exists()
    assert not (fixture.directory / subject.REQUEST_NAME).exists()


@pytest.mark.parametrize(("tag", "value"), [("POR:189", 0), ("FRA:85", 1)])
def test_asymmetric_controller_inputs_are_rejected_before_request_write(
        tmp_path: Path, tag: str, value: int) -> None:
    fixture = Fixture(tmp_path, terminal=_confirmed())

    def asymmetric_world(_context: Any, _from_tag: str, _to_tag: str) -> dict[str, Any]:
        world = _world()
        world["controller_types_raw"]["slots"][tag] = value
        return world

    fixture.world_reader = asymmetric_world  # type: ignore[method-assign]
    with pytest.raises(subject.ControlError, match="WORLD_CONTROL_PRECONDITION_MISMATCH"):
        _execute(fixture)
    assert not fixture.output.exists()
    assert not (fixture.directory / subject.REQUEST_NAME).exists()


def test_post_switch_asymmetric_controller_state_is_effect_mismatch_without_retry(
        tmp_path: Path) -> None:
    after = _world(tag="FRA")
    after["controller_types_raw"]["slots"]["POR:189"] = 1
    fixture = Fixture(tmp_path, terminal=_confirmed(), after=after)
    result = _execute(fixture)
    assert result["status"] == "effect_mismatch"
    assert "controller_types_postcondition_POR_mismatch" in result["mismatches"]
    assert result["native_dispatch_count"] == 1
    assert result["retry_count"] == 0
    assert (fixture.directory / subject.REQUEST_NAME).read_text(encoding="ascii").count("EU4COUNTRY1") == 1


def test_post_switch_non_single_human_count_is_effect_mismatch_without_retry(
        tmp_path: Path) -> None:
    after = _world(tag="FRA")
    after["human_count_raw"] = 2
    fixture = Fixture(tmp_path, terminal=_confirmed(), after=after)
    result = _execute(fixture)
    assert result["status"] == "effect_mismatch"
    assert "human_count_not_single_player" in result["mismatches"]
    assert result["native_dispatch_count"] == 1
    assert result["retry_count"] == 0
    assert (fixture.directory / subject.REQUEST_NAME).read_text(encoding="ascii").count("EU4COUNTRY1") == 1


def test_v30_is_rejected_before_output_or_native_request_write(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path, version=30)

    def forbidden_probe(_pid: int, _exe: Path) -> dict[str, Any]:
        raise AssertionError("old build must fail before process probe")

    dependencies = subject.Dependencies(identity_probe=forbidden_probe)
    with pytest.raises(subject.ControlError, match="BUILD_VERSION_REQUIRES_V31"):
        subject.execute(fixture.installation_path, "old-v30", "POR", "FRA",
                        DATE_RAW, fixture.output, test_only=True,
                        dependencies=dependencies)
    assert not fixture.output.exists()
    assert not (fixture.directory / subject.REQUEST_NAME).exists()


def test_request_is_saved_before_one_exclusive_dispatch_and_fullref_is_verified(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = Fixture(tmp_path, terminal=_confirmed())
    original_publish = subject._publish_request_once
    order: list[str] = []

    def observe_publish(path: Path, packet: bytes) -> None:
        order.append("publish")
        assert (fixture.output / "request.original").read_bytes() == packet
        assert len(packet.decode("ascii").split()) == 9
        original_publish(path, packet)

    monkeypatch.setattr(subject, "_publish_request_once", observe_publish)
    result = _execute(fixture)

    assert order == ["publish"]
    assert result["status"] == "confirmed"
    assert result["native_dispatch_count"] == 1
    assert result["retry_count"] == 0
    assert result["before_player_ref"] == POR_REF
    assert result["target_player_ref"] == FRA_REF
    assert (fixture.directory / subject.REQUEST_NAME).read_text(encoding="ascii") == (
        f"EU4COUNTRY1 TEST_ONLY r71-001 {PID} {CREATION} {DATE_RAW} "
        f"{fixture.dll_sha} POR FRA\n"
    )


def test_timeout_is_unknown_and_never_republishes(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path, terminal_state="pending_forever")
    result = _execute(fixture, timeout=0.05)
    request = fixture.directory / subject.REQUEST_NAME
    assert result["status"] == "unknown_no_retry"
    assert result["retry_count"] == 0
    assert result["native_dispatch_count"] == 1
    assert request.is_file()
    assert request.read_text(encoding="ascii").count("EU4COUNTRY1") == 1
    assert fixture.status_reads >= 3


def test_native_success_with_wrong_fullref_slot_is_rejected(
        tmp_path: Path) -> None:
    fixture = Fixture(
        tmp_path,
        terminal=_confirmed(),
        after=_world(tag="FRA", current_ref=FRA_REF_WRONG_SLOT),
    )
    result = _execute(fixture)
    assert result["native_return"] == 1
    assert result["status"] == "effect_mismatch"
    assert "independent_effect_mismatch" in result["mismatches"]


def test_same_tag_but_wrong_fullref_in_native_status_is_rejected(
        tmp_path: Path) -> None:
    fixture = Fixture(
        tmp_path,
        terminal=_confirmed(observed_player_ref=FRA_REF_WRONG_SLOT),
        after=_world(tag="FRA", current_ref=FRA_REF),
    )
    result = _execute(fixture)
    assert result["status"] == "effect_mismatch"
    assert "native_observed_ref_mismatch" in result["mismatches"]


def test_duplicate_direction_attempt_is_rejected_before_request_write(tmp_path: Path) -> None:
    fixture = Fixture( tmp_path, terminal=_confirmed())
    (fixture.directory / "information-country-control-FRA.attempt.jsonl").write_text(
        "reserved\n", encoding="ascii")
    with pytest.raises(subject.ControlError, match="CONTROL_ALREADY_ATTEMPTED_OR_BUSY"):
        _execute(fixture)
    assert not fixture.output.exists()
    assert not (fixture.directory / subject.REQUEST_NAME).exists()


def test_disabled_battle_source_must_be_bound_to_exact_from_fullref(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path, terminal=_confirmed())
    fixture.battle_status.update({
        "state": "disabled", "installation": "731", "generation": str(CREATION),
    })
    _write_json(fixture.directory / subject.BATTLE_STATUS_NAME, fixture.battle_status)
    _write_json(fixture.directory / subject.BATTLE_BINDING_NAME, {
        "schema": "EU4-BATTLE-CONTROL/1", "installation": "731",
        "generation": str(CREATION), "pid": PID,
        "creation_filetime": str(CREATION), "session_id": SESSION,
        "game_sha256": GAME_SHA, "dll_sha256": fixture.dll_sha,
        "player_ref": FRA_REF,
    })

    with pytest.raises(subject.ControlError, match="BATTLE_BINDING_PLAYER_MISMATCH"):
        _execute(fixture)
    assert not fixture.output.exists()
    assert not (fixture.directory / subject.REQUEST_NAME).exists()


def test_unittest_prepare_mode_does_not_create_native_request(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path, terminal=None)
    result = subject.execute(
        fixture.installation_path, "prepare-only", "POR", "FRA", DATE_RAW,
        fixture.output, test_only=False, dependencies=fixture.dependencies(),
        preflight_timeout=1.0,
    )
    assert result["status"] == "prepared_no_dispatch"
    assert (fixture.output / "request.original").is_file()
    assert not (fixture.directory / subject.REQUEST_NAME).exists()


def test_first_ready_status_warming_is_waited_without_dispatch(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path, terminal=_confirmed())
    initial = fixture.initial_status
    fixture.initial_status = _status(
        observed_ref="0000000000000000", speed=0, paused=False,
        frame_thread=0, authorized_fra_ref="0000000000000000",
        reason="frame_not_started",
    )
    fixture.initial_status["dll_sha256"] = fixture.dll_sha
    original_reader = fixture.status_reader

    def warm_then_ready(path: Path) -> tuple[dict[str, Any], bytes, float]:
        if fixture.status_reads == 0:
            result = fixture.initial_status
            fixture.status_reads += 1
            return result, (json.dumps(result) + "\n").encode(), 0.0
        fixture.initial_status = initial
        return original_reader(path)

    fixture.status_reader = warm_then_ready  # type: ignore[method-assign]
    result = _execute(fixture)
    assert result["status"] == "confirmed"
    assert result["native_dispatch_count"] == 1

