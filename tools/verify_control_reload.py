"""Verify the renamed experiment save after startup native confirmation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'work'))
from local_config import get_value
from run_control_save import events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    report_path = ROOT / 'work/runtime/control-save-validation.json'
    report = json.loads(report_path.read_text(encoding='utf-8'))
    if args.pid == report['pid']:
        raise SystemExit('Reload requires a fresh process.')
    if hashlib.sha256(Path(report['save']).read_bytes()).hexdigest() != report['sha256']:
        raise SystemExit('Saved file checksum changed.')
    log = ROOT / 'work/native/control-probe.jsonl'
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        records = events(log)
        if any(e.get('event') == 'control_frame' and e.get('pid') == args.pid for e in records):
            loaded = next((i for i,e in enumerate(records)
                           if e.get('event') == 'control_loaded_pause_requested'), None)
            frames = ([e['frames'] for e in records[loaded:] if e.get('event') == 'control_frame']
                      if loaded is not None else [])
            if frames and frames[-1] - frames[0] >= 120:
                break
        time.sleep(1)
    else:
        raise SystemExit('Reload has not settled on foreground frames.')
    python = get_value('EU4_PYTHON')
    def probe(script, filename):
        out = ROOT / 'work/runtime' / filename
        subprocess.run([python, '-B', str(ROOT / 'work' / script), '--pid', str(args.pid),
                        '--output', str(out)], check=True, timeout=30)
        return json.loads(out.read_text(encoding='utf-8'))
    state = probe('probe_control_state.py', 'control-reloaded-state.json')
    wars = probe('probe_war_pair.py', 'control-reloaded-wars.json')
    before = json.loads((ROOT / 'work/runtime/control-saved-live.json').read_text(encoding='utf-8'))
    if state['player_slot'] != 189 or state['date_raw'] != report['advance']['date_raw']:
        raise SystemExit('Reloaded player or date mismatch.')
    if state.get('paused_flag') != 1 or wars['countries'] != before['countries']:
        raise SystemExit('Reloaded pause or war associations mismatch.')
    report.update(reloaded=True, reload_pid=args.pid, reload_state=state,
                  reload_war_associations_match=True)
    report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    (ROOT / 'work/runtime/control-reload-native.jsonl').write_bytes(log.read_bytes())
    print(json.dumps({'reloaded': True, 'pid': args.pid, 'date': report['saved_date'],
                      'player': report['player'], 'paused': True}), flush=True)


if __name__ == '__main__':
    main()
