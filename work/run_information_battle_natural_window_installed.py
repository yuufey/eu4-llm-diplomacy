"""Use the installed-build probe with the existing once-only natural window."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work import run_information_battle_natural_window as window
from work.probe_information_battle_installed import run as installed_probe


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation', required=True, type=Path)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--expected-dll-sha256', required=True)
    parser.add_argument('--days', required=True, type=int, choices=(1, 5, 35))
    parser.add_argument('--expected-date', required=True, type=int)
    parser.add_argument('--expected-player-tag', choices=window.EXPECTED_PLAYER_TAGS, default='POR')
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--test-only', required=True, action='store_true')
    args = parser.parse_args()
    for value in (args.expected_manifest_sha256, args.expected_dll_sha256):
        if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            parser.error('expected hashes must be exact lowercase SHA-256')

    def probe(installation: Path, output: Path) -> dict:
        result = installed_probe(
            installation, output,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_dll_sha256=args.expected_dll_sha256,
            expect_patch='installed',
        )
        if result.get('status') != 'passed_read_only_installed_preflight':
            raise RuntimeError('INSTALLED_BUILD_PREFLIGHT_FAILED')
        return result

    original_probe = window.probe
    window.probe = probe
    try:
        result = window.execute(args.installation, args.days, args.expected_date,
                                args.output_dir, test_only=args.test_only,
                                expected_player_tag=args.expected_player_tag)
    finally:
        window.probe = original_probe
    window.write_new(args.output_dir / 'installed-probe-adapter.json', {
        'wrapper': window.pin(Path(__file__)),
        'original_window': window.pin(Path(window.__file__)),
        'installed_probe': window.pin(ROOT / 'work/probe_information_battle_installed.py'),
        'expected_manifest_sha256': args.expected_manifest_sha256,
        'expected_dll_sha256': args.expected_dll_sha256,
        'expected_physical_player_tag': args.expected_player_tag,
        'reason': 'Original window probe only accepts archived v23; dispatch logic reused unchanged.',
    })
    print(json.dumps(result))
    return 0 if result.get('status') == 'observed_target_and_paused' else 2


if __name__ == '__main__':
    raise SystemExit(main())
