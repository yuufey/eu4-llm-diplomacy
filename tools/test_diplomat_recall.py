"""Queue one fixed POR diplomat 0 recall and verify the native state transition."""
import argparse
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
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    log = ROOT / 'work/native/control-probe.jsonl'
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        records = events(log)
        if any(e.get('event') == 'control_frame' and e.get('pid') == args.pid for e in records):
            loaded = next((i for i,e in enumerate(records) if e.get('event') == 'control_loaded_pause_requested'), None)
            frames = [e['frames'] for e in records[loaded:] if e.get('event') == 'control_frame'] if loaded is not None else []
            if frames and frames[-1]-frames[0] >= 120:
                break
        time.sleep(1)
    else:
        raise SystemExit('Waiting for loaded foreground frames; no recall queued.')
    def snapshot(name):
        path = ROOT / 'work/runtime' / name
        subprocess.run([get_value('EU4_PYTHON'), '-B', str(ROOT / 'work/probe_pending_peace.py'),
                        '--pid', str(args.pid), '--output', str(path)], check=True, timeout=30,
                       stdout=subprocess.DEVNULL)
        return json.loads(path.read_text(encoding='utf-8'))
    def diplomats(state):
        por = next(c for c in state['countries'] if c['tag'] == 'POR')
        return {e['raw_id_44']: e for e in por['diplomacy_entries']}
    before = snapshot('por-recall-v5-before.json')
    entries = diplomats(before)
    if entries[0]['active_raw_18'] != 2 or entries[0].get('recipient') != '0x100007a00415246':
        raise SystemExit('POR diplomat 0 is not performing the expected FRA task.')
    if [entries[i]['active_raw_18'] for i in (1,2)] != [1,1]:
        raise SystemExit('Expected other two diplomats returning; no recall queued.')
    offset = len(events(log))
    request = ROOT / 'work/native/diplomat-recall.request'
    with request.open('x', encoding='ascii', newline='\n') as stream:
        stream.write('TEST_ONLY POR diplomat_0\n')
    print('POR diplomat 0 native recall queued for frame processing.', flush=True)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        result = [e for e in events(log)[offset:] if e.get('event','').startswith('diplomat_recall_')]
        if any(e['event'] != 'diplomat_recall_queued' for e in result):
            raise SystemExit('Native recall rejected: ' + json.dumps(result))
        if result:
            after = snapshot('por-recall-v5-after.json')
            changed = diplomats(after)
            if changed[0]['active_raw_18'] == 1:
                if before['current_raw_date'] != after['current_raw_date']:
                    raise SystemExit('Game date advanced during the paused recall experiment.')
                if any(entries[i] != changed[i] for i in (1,2)):
                    raise SystemExit('Other diplomats changed during recall verification.')
                report = {'pid': args.pid, 'actor': 'POR', 'recipient': 'FRA', 'diplomat_id': 0,
                          'recalled': True, 'returned_to_pool': False,
                          'date_raw': after['current_raw_date'], 'before': entries[0], 'after': changed[0],
                          'other_diplomats_unchanged': True}
                (ROOT / 'work/runtime/por-recall-v5-validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
                (ROOT / 'work/runtime/por-recall-v5-native.jsonl').write_bytes(log.read_bytes())
                print(json.dumps(report), flush=True)
                return
        time.sleep(1)
    raise SystemExit('Recall transition not verified before timeout; inspect native log and saved baseline.')


if __name__ == '__main__':
    main()
