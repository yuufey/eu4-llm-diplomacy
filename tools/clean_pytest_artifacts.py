"""Remove old, untracked pytest case directories within explicit scratch roots.

Defaults to a dry run. Reports beside scratch directories are retained. Never
follows reparse points or removes a tree containing a recently written file.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ('work/runtime', 'work/tmp', 'work/tmp-v38-control-223-001')
CASE = re.compile(r'test_[A-Za-z0-9_]+\d+$')


def reparse(info):
    return bool(getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def inspect_tree(path, cutoff):
    count = size = 0
    pending = [path]
    while pending:
        current = pending.pop()
        info = current.lstat()
        if reparse(info) or info.st_mtime > cutoff:
            return None
        if current.is_dir():
            with os.scandir(current) as entries:
                pending.extend(Path(entry.path) for entry in entries)
        else:
            count += 1
            size += info.st_size
    return count, size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--min-age-hours', type=int, default=24)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.min_age_hours < 24:
        parser.error('minimum age must be at least 24 hours')
    report = args.report.resolve()
    report.relative_to(ROOT)
    if report.suffix != '.json' or any(report.is_relative_to(ROOT / name) for name in SCRATCH):
        parser.error('report must be a JSON file outside the scratch roots')
    if report.exists():
        parser.error('report must be a new file')
    cutoff = time.time() - args.min_age_hours * 3600
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf-8').split('\0')
    protected = set()
    for filename in tracked:
        if filename:
            protected.update(parent.as_posix() for parent in Path(filename).parents)
    result = {'apply': args.apply, 'age_hours': args.min_age_hours, 'roots': SCRATCH,
              'directories': [], 'files': 0, 'bytes': 0, 'skipped': collections.Counter(),
              'errors': []}
    report.parent.mkdir(parents=True, exist_ok=True)
    journal = report.with_suffix('.jsonl')
    with journal.open('x', encoding='utf-8') as receipt:
        for root_name in SCRATCH:
            scratch = (ROOT / root_name).resolve()
            scratch.relative_to(ROOT / 'work')
            if not scratch.is_dir():
                continue
            pending = [scratch]
            while pending:
                parent = pending.pop()
                with os.scandir(parent) as entries:
                    children = list(entries)
                for entry in children:
                    path = Path(entry.path)
                    info = entry.stat(follow_symlinks=False)
                    if reparse(info):
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if not CASE.fullmatch(entry.name):
                        pending.append(path)
                        continue
                    relative = path.relative_to(ROOT).as_posix()
                    if relative in protected:
                        result['skipped']['tracked'] += 1
                        continue
                    measured = inspect_tree(path, cutoff)
                    if measured is None:
                        result['skipped']['recent_or_reparse'] += 1
                        continue
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(scratch)
                    if resolved != path.absolute() or resolved == scratch:
                        raise RuntimeError('unexpected cleanup target')
                    row = {'path': relative, 'files': measured[0], 'bytes': measured[1]}
                    receipt.write(json.dumps(dict(row, phase='intent')) + '\n')
                    receipt.flush()
                    if args.apply:
                        try:
                            # Revalidate age and reparse points immediately before removal.
                            if inspect_tree(path, cutoff) != measured:
                                result['skipped']['changed'] += 1
                                continue
                            shutil.rmtree(resolved)
                        except OSError as error:
                            result['errors'].append({'path': relative, 'error': str(error)})
                            continue
                    result['directories'].append(row)
                    result['files'] += measured[0]
                    result['bytes'] += measured[1]
                    receipt.write(json.dumps(dict(row, phase='removed' if args.apply else 'candidate')) + '\n')
                    receipt.flush()
                    if len(result['directories']) % 500 == 0:
                        print(json.dumps({'directories': len(result['directories']), 'files': result['files']}), flush=True)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if not result['errors']:
        journal.unlink()
    print(json.dumps({key: value for key, value in result.items() if key != 'directories'}, ensure_ascii=False))
    return bool(result['errors'])


if __name__ == '__main__':
    raise SystemExit(main())
