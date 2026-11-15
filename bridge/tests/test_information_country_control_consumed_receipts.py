from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from work.prepare_information_battle_natural_window import _runtime_channel_scan
from work.probe_information_battle_installed import (
    classify_country_control_consumed_receipts,
)
from work.validate_information_battle_capture_autonomous_live import (
    _pending_channel_scan as _autonomous_pending_scan,
)
from work.validate_information_battle_capture_management_corrective import (
    _pending_channel_scan as _management_pending_scan,
)


PID = 54671
CREATION = 134376348223436218
DLL_SHA256 = "a" * 64
GAME_SHA256 = "b" * 64
DATE = 56562768
FRA_REF = "0000005500415246"


def _installation() -> dict[str, Any]:
    return {
        "pid": PID,
        "creation_filetime": CREATION,
        "session_id": f"{PID}-{CREATION:x}",
        "game_sha256": GAME_SHA256,
        "dll_sha256": DLL_SHA256,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n",
                    encoding="utf-8")


def _packet(request_id: str = "saved_001", *, pid: int = PID,
            creation: int = CREATION, dll_sha: str = DLL_SHA256,
            from_tag: str = "POR", to_tag: str = "FRA") -> bytes:
    return (f"EU4COUNTRY1 TEST_ONLY {request_id} {pid} {creation} {DATE} "
            f"{dll_sha} {from_tag} {to_tag}\n").encode("ascii")


def _status(request_id: str = "saved_001", *, state: str = "confirmed",
            from_tag: str = "POR", to_tag: str = "FRA") -> dict[str, Any]:
    return {
        "schema": "EU4COUNTRY1", "state": state, "pid": PID,
        "creation_filetime": str(CREATION), "dll_sha256": DLL_SHA256,
        "request_id": request_id, "request_from": from_tag,
        "request_to": to_tag, "before_player_ref": "000000bd00524f50",
        "target_player_ref": FRA_REF, "observed_player_ref": FRA_REF,
        "date_before": DATE, "date_raw": DATE, "speed": 0,
        "paused": True, "native_attempted": True, "native_return": 1,
        "native_calls": 1, "attempted_mask": 1,
        "authorized_fra_ref": FRA_REF, "frame_thread": 777,
        "reason": "confirmed",
    }


def _write_valid_saved_receipt(directory: Path, request_id: str = "saved_001") -> str:
    packet = _packet(request_id)
    saved_name = f"country-control-{request_id}.request.saved"
    (directory / saved_name).write_bytes(packet)
    attempt = directory / "information-country-control-FRA.attempt.jsonl"
    records = [
        {
            "event": "reserved_before_native", "request_id": request_id,
            "request_ascii": packet[:-1].decode("ascii"),
        },
        {
            "event": "terminal", "request_id": request_id,
            "state": "confirmed", "native_attempted": True,
            "native_return": 1, "observed_ref": FRA_REF, "date": DATE,
            "reason": "subsequent_frame_exact_effect",
        },
    ]
    attempt.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in records),
                       encoding="utf-8")
    _write_json(directory / "information-country-control-status.json", _status())
    return saved_name


def _all_scanners(directory: Path, installation: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return (
        _autonomous_pending_scan(directory, installation),
        _management_pending_scan(directory, installation),
    )


def test_valid_terminal_saved_receipt_is_closed_but_live_request_channels_remain_pending(
        tmp_path: Path) -> None:
    installation = _installation()
    saved_name = _write_valid_saved_receipt(tmp_path)

    classification = classify_country_control_consumed_receipts(tmp_path, installation)
    assert classification["status"] == "observed"
    assert [row["name"] for row in classification["closed"]] == [saved_name]
    assert classification["unverified"] == []

    for pending, receipt_audit in _all_scanners(tmp_path, installation):
        assert pending == []
        assert [row["name"] for row in receipt_audit["closed"]] == [saved_name]
    natural = _runtime_channel_scan(tmp_path, installation)
    assert natural["request_or_processing_files"] == []
    assert [row["name"] for row in natural["country_control_consumed_receipts"]["closed"]] == [saved_name]

    active_names = [
        "information-country-control.request",
        "information-country-control.processing",
        "country-control-live_002.request",
        "country-control-live_003.processing",
    ]
    for name in active_names:
        (tmp_path / name).write_text("active\n", encoding="ascii")
    for pending, receipt_audit in _all_scanners(tmp_path, installation):
        assert set(active_names).issubset(pending)
        assert saved_name not in pending
        assert [row["name"] for row in receipt_audit["closed"]] == [saved_name]
    natural = _runtime_channel_scan(tmp_path, installation)
    assert set(active_names).issubset(natural["request_or_processing_files"])
    assert saved_name not in natural["request_or_processing_files"]


def test_bad_lookalikes_wrong_ids_and_wrong_identity_are_never_ignored(
        tmp_path: Path) -> None:
    installation = _installation()
    # Exact filename ID but different packet ID.
    (tmp_path / "country-control-name_001.request.saved").write_bytes(
        _packet("different_001"))
    # Exact filename and ID, but the packet names another process.
    (tmp_path / "country-control-pid_001.request.saved").write_bytes(
        _packet("pid_001", pid=PID + 1))
    # Invalid ID spelling and a suffix lookalike do not qualify for the exact closed-receipt rule.
    (tmp_path / "country-control-bad!id.request.saved").write_bytes(_packet("bad_id"))
    (tmp_path / "country-control-similar.request.saved.backup").write_bytes(_packet("similar"))
    _write_json(tmp_path / "information-country-control-status.json", _status("another_terminal"))

    classification = classify_country_control_consumed_receipts(tmp_path, installation)
    assert classification["closed"] == []
    assert {item["name"] for item in classification["unverified"]} == {
        "country-control-name_001.request.saved",
        "country-control-pid_001.request.saved",
    }
    expected_pending = {
        "country-control-name_001.request.saved",
        "country-control-pid_001.request.saved",
        "country-control-bad!id.request.saved",
        "country-control-similar.request.saved.backup",
    }
    for pending, _receipt_audit in _all_scanners(tmp_path, installation):
        assert expected_pending.issubset(pending)
    natural = _runtime_channel_scan(tmp_path, installation)
    assert expected_pending.issubset(natural["request_or_processing_files"])


def test_saved_request_without_terminal_evidence_remains_pending(tmp_path: Path) -> None:
    installation = _installation()
    saved_name = "country-control-no_terminal.request.saved"
    (tmp_path / saved_name).write_bytes(_packet("no_terminal"))
    _write_json(tmp_path / "information-country-control-status.json",
                _status("different_request", state="pending"))

    classification = classify_country_control_consumed_receipts(tmp_path, installation)
    assert classification["closed"] == []
    assert classification["unverified"] == [{
        "name": saved_name,
        "reason": "InstalledProbeError:saved_request_terminal_evidence_missing",
    }]
    for pending, _receipt_audit in _all_scanners(tmp_path, installation):
        assert saved_name in pending

