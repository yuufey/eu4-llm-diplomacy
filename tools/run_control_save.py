"""Finish the explicit test-only 35-day advance, save, and rename experiment.

Requires control_v3 in the supplied PID and foreground game frames. Preserves
all existing local saves before the native command, verifies a complete save,
and restores a preexisting filename if the native command overwrote one.
Restart/reload is a separate stage, with independent state verification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'work'))
from local_config import user_data, get_value


def events(path):
    result = []
    for line in path.read_text(encoding='utf-8').splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # The writer may be midway through its final line.
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--save-command', choices=('savegame', 'autosave'), default='autosave')
    parser.add_argument('--new-advance', action='store_true', help='Start a new advance after an explicitly cancelled attempt.')
    parser.add_argument('--resume-save', action='store_true', help='Validate an already issued save using the existing backup.')
    parser.add_argument('--save-only', action='store_true', help='Capture the paused 1445.2.5 test state without advancing.')
    args = parser.parse_args()
    if not re.fullmatch(r'llm_control_[A-Za-z0-9_-]+\.eu4', args.name):
        raise SystemExit('Use a unique llm_control_*.eu4 test filename.')
    native = ROOT / 'work/native'
    log = native / 'control-probe.jsonl'
    saves = user_data() / 'save games'
    target = saves / args.name
    if target.exists():
        raise SystemExit('Destination already exists; nothing overwritten.')
    backup = ROOT / 'work/backup' / ('control-' + args.name[:-4])
    if backup.exists() and not args.resume_save:
        raise SystemExit('Backup already exists; use --resume-save or a new experiment name before advancing.')
    frame_deadline = time.monotonic() + args.timeout
    current = events(log)
    while not any(e.get('event') == 'control_frame' and e.get('pid') == args.pid for e in current):
        if time.monotonic() >= frame_deadline:
            raise SystemExit('No controller frame for this PID; bring the game to foreground.')
        time.sleep(1)
        current = events(log)
    request = native / 'game-control.request'
    deadline = time.monotonic() + args.timeout

    # Player and pause objects appear before the load transition finishes.
    # Allow original engine frames to settle before starting simulation.
    if not args.resume_save and not args.new_advance:
        while time.monotonic() < deadline:
            current = events(log)
            loaded = next((i for i,e in enumerate(current)
                           if e.get('event') == 'control_loaded_pause_requested'), None)
            frames = ([e['frames'] for e in current[loaded:]
                       if e.get('event') == 'control_frame'] if loaded is not None else [])
            if frames and frames[-1] - frames[0] >= 120:
                break
            time.sleep(1)
        else:
            raise SystemExit('Load has not settled on foreground frames; no advance requested.')
        deadline = time.monotonic() + args.timeout

    def queue(token):
        with request.open('x', encoding='ascii', newline='\n') as stream:
            stream.write('TEST_ONLY ' + token + '\n')

    advance_offset = len(current) if args.new_advance else 0
    if not args.save_only and (args.new_advance or not any(e.get('event') == 'control_advance_begin' for e in current)) and not request.exists():
        queue('advance_35_days')
    while time.monotonic() < deadline:
        if args.save_only:
            state_path = ROOT / 'work/runtime/control-capture-live.json'
            subprocess.run([get_value('EU4_PYTHON'), '-B', str(ROOT / 'work/probe_control_state.py'),
                            '--pid', str(args.pid), '--output', str(state_path)], check=True, timeout=30)
            state = json.loads(state_path.read_text(encoding='utf-8'))
            if state['paused_flag'] != 1 or state['player_slot'] != 189:
                raise SystemExit('Capture requires paused POR.')
            completion = {'event': 'paused_capture', 'date_raw': state['date_raw'], 'days': 0}
            break
        current = events(log)
        completed = [e for e in current[advance_offset:] if e.get('event') == 'control_advance_complete']
        if completed:
            completion = completed[-1]
            if not completion['reached'] or not completion['paused_command_success']:
                raise SystemExit('Advance failed or timed out; no save requested.')
            break
        time.sleep(1)
    else:
        raise SystemExit('Waiting for foreground frames; queued request retained.')
    print(json.dumps(completion), flush=True)
    if completion['date_raw'] != 56459040:
        raise SystemExit('Expected fixed baseline advanced to 1445.2.5; no save requested.')
    if args.resume_save:
        if not backup.is_dir():
            raise SystemExit('Existing backup required for resume.')
    else:
        backup.mkdir(parents=True, exist_ok=False)
    before = {}
    for path in (backup if args.resume_save else saves).glob('*.eu4'):
        stat = path.stat()
        before[path.name] = (stat.st_size, stat.st_mtime_ns)
        if not args.resume_save:
            shutil.copy2(path, backup / path.name)
    offset = 0 if args.resume_save else len(events(log))
    if not args.resume_save:
        queue(args.save_command)
    print('Resuming saved-file validation.' if args.resume_save else
          'Native save queued; existing saves backed up.', flush=True)
    deadline = time.monotonic() + args.timeout
    stable = None
    stable_since = 0
    while time.monotonic() < deadline:
        changed = [p for p in saves.glob('*.eu4')
                   if (p.stat().st_size, p.stat().st_mtime_ns) != before.get(p.name)]
        accepted = any(e.get('event') == 'control_console_result' and e.get('command') == args.save_command
                       and e.get('success') for e in events(log)[offset:])
        candidates = ([p for p in changed if p.name.lower() == 'autosave.eu4']
                      if args.save_command == 'autosave' else changed)
        # Autosave may rotate old_autosave and older_autosave as well.
        if accepted and len(candidates) == 1:
            path = candidates[0]
            key = (path.name, path.stat().st_size, path.stat().st_mtime_ns)
            if key != stable:
                stable, stable_since = key, time.monotonic()
            elif time.monotonic() - stable_since >= 3:
                try:
                    if zipfile.is_zipfile(path):
                        with zipfile.ZipFile(path) as archive:
                            meta = archive.read('meta').decode('utf-8', errors='replace')
                            game = archive.read('gamestate')
                    else:
                        game = path.read_bytes()
                        meta = game[:8192].decode('utf-8', errors='replace')
                    date = re.search(r'(?m)^date="?([0-9.]+)', meta)
                    player = re.search(r'(?m)^player="?([A-Z]+)', meta)
                    if not date or not player or player[1] != 'POR' or len(game) < 100000:
                        raise ValueError('Save metadata invalid')
                    if date[1] != '1445.2.5' or completion['date_raw'] != 56459040:
                        raise ValueError('Save differs from the fixed experiment target date')
                    break
                except (OSError, ValueError, KeyError, zipfile.BadZipFile):
                    pass
        time.sleep(1)
    else:
        raise SystemExit(f'Save not verified; originals retained in {backup}')
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    original_name = path.name
    path.rename(target)
    restored = []
    for changed_path in changed:
        if changed_path.name in before:
            shutil.copy2(backup / changed_path.name, saves / changed_path.name)
            if hashlib.sha256((backup / changed_path.name).read_bytes()).digest() != hashlib.sha256((saves / changed_path.name).read_bytes()).digest():
                raise SystemExit('Restoration checksum mismatch: ' + changed_path.name)
            restored.append(changed_path.name)
    probe = ROOT / 'work/runtime/control-saved-live.json'
    subprocess.run([get_value('EU4_PYTHON'), '-B', str(ROOT / 'work/probe_war_pair.py'),
                    '--pid', str(args.pid), '--output', str(probe)], check=True, timeout=30)
    report = dict(pid=args.pid, advance=completion, save=str(target), sha256=sha,
                  native_filename=original_name, saved_date=date[1], player=player[1],
                  backup=str(backup), restored_originals=restored, reloaded=False)
    output = ROOT / 'work/runtime/control-save-validation.json'
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    shutil.copy2(log, ROOT / 'work/runtime/control-save-native.jsonl')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
