"""Load a local EU4 test save, confirm its achievement warning and verify the paused world."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from bridge.diplomacy_session import file_hash
from bridge.information.truce_date_math import MONTH_DAYS, decode_date
from tools.save_observer_experiment import _inspect_save, _probe_control_state
from tools.start_diplomacy_observer import MAX_WAIT_READY, bounded_wait_ready, load_warning_save_name
from work.local_config import game_exe, user_data
from work.observer_runtime_ready import wait_runtime_ready


def _read_save(path: Path) -> tuple[dict, tuple[int, int, int]]:
    if path.suffix.casefold() != ".eu4":
        raise ValueError("expected a local .eu4 save file")
    meta = _inspect_save(path, expected_player=None)
    if not meta["valid"]:
        raise ValueError(f"cannot read the save's player and date: {meta['reason']}")
    year, month, day = map(int, str(meta["date"]).split("."))
    if not (1 <= month <= 12 and 1 <= day <= MONTH_DAYS[month - 1]):
        raise ValueError(f"invalid date in save: {meta['date']}")
    return meta, (year, month, day)


def _stage_save(path: Path, saves: Path) -> Path:
    if path.parent == saves:
        try:
            load_warning_save_name(path.name)
        except argparse.ArgumentTypeError:
            pass
        else:
            return path
    alias = saves / f"llm_load_{uuid.uuid4().hex}.eu4"
    with path.open("rb") as source, alias.open("xb") as destination:
        try:
            shutil.copyfileobj(source, destination)
        except BaseException:
            destination.close()
            alias.unlink()
            raise
    if file_hash(path) != file_hash(alias):
        alias.unlink()
        raise ValueError("source save changed during staging")
    return alias


def _verify_loaded(installation: Path, pid: int, meta: dict,
                   date: tuple[int, int, int]) -> dict:
    session = ObserverSession(installation, game_exe())
    record = session.record
    if record.get("pid") != pid or record.get("installation_returncode") != 0:
        raise ValueError("installation does not match the launched process")
    # Use the save's player as the expected heartbeat tag. Publish it to disk
    # only after the live session and the read-only pause probe both agree.
    record["verified_loaded_player_tag"] = meta["player"]
    health = wait_runtime_ready(session)
    if health.get("status") != "ready" or decode_date(health["date_raw"])[:3] != date:
        raise ValueError(f"live world did not reach {meta['player']} on {meta['date']}")
    output = installation.parent / "loaded-control-state.json"
    deadline = time.monotonic() + 30
    # The first loaded heartbeat can arrive before the native startup pause.
    while time.monotonic() < deadline:
        state = _probe_control_state(pid, output, deadline)
        if state.get("read_only") is not True or state.get("pid") != pid:
            raise ValueError("pause probe did not verify the launched process")
        if state.get("paused_flag") == 1:
            break
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    else:
        raise ValueError("timed out waiting for the startup pause")

    # Recheck the session identity, player and date after observing the pause.
    final_health = session.physical_player_health()
    if (final_health.get("status") != "ready" or final_health["date_raw"] != state.get("date_raw")
            or decode_date(final_health["date_raw"])[:3] != date):
        raise ValueError("loaded world did not verify as paused on the save's date")
    load_warning = "world_already_loaded"
    if record.get("ready_reason") == "verified_load_confirmation":
        with (installation.parent / "control-probe.jsonl").open("rb") as stream:
            startup_events = stream.read(1024 * 1024)
        if b'"event":"popup_confirmation_callbacks_returned"' not in startup_events:
            raise ValueError("native achievement confirmation did not complete")
        load_warning = "confirmed"
    record["verified_loaded_date_raw"] = final_health["date_raw"]
    record["verified_loaded_control_state"] = str(output)
    record["load_warning"] = load_warning
    pending = installation.with_name("installation.verified.tmp")
    with pending.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
    os.replace(pending, installation)
    return {"player": meta["player"], "date": meta["date"], "paused": True,
            "load_warning": load_warning}


def load_save(save: Path, manifest: Path, *, wait_ready: int = MAX_WAIT_READY,
              replace_running: bool = False) -> dict:
    save = save.resolve(strict=True)
    manifest = manifest.resolve(strict=True)
    meta, date = _read_save(save)
    saves = (user_data() / "save games").resolve(strict=True)
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell is None:
        raise ValueError("PowerShell is required to start EU4")
    experiment = f"load-observer-{uuid.uuid4().hex}"
    work_dir = manifest.parent.with_name(experiment)
    python = [sys.executable, "-B"]
    subprocess.run([*python, str(ROOT / "work/reuse_observer_build.py"),
                    "--manifest", str(manifest), "--experiment", experiment, "--hardlink"],
                   cwd=ROOT, check=True, timeout=90)
    launch_save = _stage_save(save, saves)
    reached_world = False
    launched = False
    try:
        restart = [powershell, "-NoProfile", "-File", str(ROOT / "work/native/restart-game.ps1"),
                   "-SavedTestGame", "-SaveName", launch_save.name]
        if not replace_running:
            restart.append("-RequireStopped")
        launch = subprocess.run(restart, cwd=ROOT, check=True, capture_output=True, timeout=35)
        launched = True
        match = re.search(rb"Game restarted; new PID: ([0-9]+)", launch.stdout)
        if match is None:
            raise ValueError("restart did not report the new EU4 PID")
        pid = int(match[1])
        subprocess.run([*python, str(ROOT / "tools/start_diplomacy_observer.py"),
                        "--pid", str(pid), "--manifest", str(work_dir / "build-manifest.json"),
                        "--wait-ready", str(wait_ready), "--confirm-load-warning",
                        "--load-warning-save-name", launch_save.name],
                       cwd=ROOT, env={**os.environ, "EU4_PYTHON": sys.executable},
                       check=True, timeout=wait_ready + 95)
        installation = work_dir / "installation.json"
        verification = _verify_loaded(installation, pid, meta, date)
        reached_world = True
        return {"pid": pid, "experiment": experiment, "installation": str(installation),
                "save": str(save), **verification}
    except subprocess.TimeoutExpired:
        # The game may have started even if the launcher timed out.
        launched = True
        raise
    finally:
        if launch_save != save:
            if reached_world or not launched:
                launch_save.unlink(missing_ok=True)
            else:
                print(f"Retained startup save for PID investigation: {launch_save}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--wait-ready", type=bounded_wait_ready, default=MAX_WAIT_READY,
                        help=f"seconds to wait after launch (default: {MAX_WAIT_READY})")
    parser.add_argument("--replace-running", action="store_true",
                        help="replace the running local EU4 test session")
    args = parser.parse_args()
    try:
        result = load_save(args.save, args.manifest, wait_ready=args.wait_ready,
                           replace_running=args.replace_running)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"load_observer_save: {error}", file=sys.stderr)
        if isinstance(getattr(error, "stderr", None), bytes):
            print(error.stderr.decode("utf-8", errors="replace").strip(), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
