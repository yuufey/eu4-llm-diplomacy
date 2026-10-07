"""Install the reviewed test-save controller, locate and queue load confirmation.

No keyboard/mouse automation. The native frame callback rechecks both button
listeners before calling them; the controller pauses after POR loads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'work'))
from local_config import get_value

EXPECTED_DLL = 'e63a56666a49040aaf0b7a8538f9ea6d89fbefd0a3579a2a44321ce7bd7b8a39'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--confirm-load-warning', action='store_true')
    parser.add_argument('--recall-candidate', action='store_true')
    args = parser.parse_args()
    python = get_value('EU4_PYTHON')
    native = ROOT / 'work/native'
    dll = native / ('eu4_bridge_control_recall_v5.dll' if args.recall_candidate else 'eu4_bridge_control_v3.dll')
    expected = 'e29e17cb419176573c4ae1e7c087d3a38e6261a75705ea028c8a619ef7b2db39' if args.recall_candidate else EXPECTED_DLL
    if hashlib.sha256(dll.read_bytes()).hexdigest() != expected:
        raise SystemExit('Controller differs from reviewed build.')
    probe = ROOT / f'work/runtime/control-preflight-{args.pid}.json'
    subprocess.run([python, '-B', str(ROOT / 'work/probe_native_state.py'), '--pid', str(args.pid),
                    '--output', str(probe)], check=True, timeout=30)
    state = json.loads(probe.read_text(encoding='utf-8'))
    if state['player_tag'] not in ('---', 'POR'):
        raise SystemExit('Expected unloaded test save or player POR.')
    confirmation = None
    if args.confirm_load_warning and state['player_tag'] == '---':
        dialogs = ROOT / f'work/runtime/control-dialogs-{args.pid}.json'
        subprocess.run([python, '-B', str(ROOT / 'work/probe_startup_dialogs.py'),
                        '--pid', str(args.pid), '--output', str(dialogs)], check=True, timeout=40,
                       stdout=subprocess.DEVNULL)
        base = int(state['module_base'], 16)
        for obj in json.loads(dialogs.read_text(encoding='utf-8'))['dialogs']:
            if obj['name'] != 'DefaultConfirm':
                continue
            result = subprocess.run([python, '-B', str(ROOT / 'work/read_popup_details.py'),
                                     '--pid', str(args.pid), '--peace-address', obj['object']],
                                    check=True, capture_output=True, text=True, encoding='utf-8', timeout=30,
                                    env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
            records = [json.loads(line) for line in result.stdout.splitlines()]
            for child in records:
                if child['name'] != 'agreebutton' or len(child.get('listeners', [])) != 2:
                    continue
                first, second = child['listeners']
                blob = bytes.fromhex(second['data'])
                owner = int.from_bytes(blob[8:16], 'little')
                callback = int.from_bytes(blob[16:24], 'little')
                if int(first['listener'], 16) == int(obj['object'], 16) + 0x18 and callback == base + 0x10ef2e0:
                    if confirmation:
                        raise SystemExit('More than one matching load confirmation.')
                    confirmation = f"TEST_ONLY {args.pid} {int(obj['object'],16):x} {int(child['child'],16):x} {owner:x}\n"
        if not confirmation:
            raise SystemExit('Verified load-warning button not found; no DLL installed.')
    subprocess.run([python, '-B', str(native / 'inject_probe.py'), '--pid', str(args.pid),
                    '--dll', str(dll), '--ack-test-save'], check=True, timeout=60)
    if confirmation:
        with (native / 'popup-confirm.request').open('x', encoding='ascii', newline='\n') as stream:
            stream.write(confirmation)
    print(json.dumps(dict(pid=args.pid, controller='recall_v5' if args.recall_candidate else 'v3', confirmation_queued=bool(confirmation))), flush=True)


if __name__ == '__main__':
    main()
