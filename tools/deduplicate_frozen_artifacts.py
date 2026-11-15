"""Content-verified storage deduplication of old, untracked research copies.

Paths and bytes remain available through NTFS hard links. These files are frozen
evidence: copy to a new path before editing or opening a database for writing.
The scan checkpoints hashes in the requested report directory and is resumable.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
ROOTS = ('work/runtime', 'work/backup')
CURRENT = 'diplomacy-observer-20261110-rival-record-v61-360-003'


def identity(path):
    info = path.stat()
    return [info.st_size, info.st_mtime_ns, info.st_ino, info.st_dev]


def category(path):
    if path.suffix.lower() == '.eu4':
        return 'save'
    if path.suffix.lower() == '.py':
        return 'script'
    if path.suffix.lower() in ('.db', '.sqlite', '.sqlite3'):
        # Only archived analysis copies, never live journals/ingest databases.
        if any('archiv' in part.lower() or 'cache-recovery' in part.lower()
               for part in path.parts):
            return 'archived_database'
    return None


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to(ROOT / 'logs')
    output.mkdir(parents=True, exist_ok=True)
    final = output / ('applied.json' if args.apply else 'inventory.json')
    if final.exists():
        parser.error('result already exists')
    cache_path = output / 'hashes.jsonl'
    cache = {}
    if cache_path.exists():
        with cache_path.open(encoding='utf-8') as stream:
            for line in stream:
                row = json.loads(line)
                cache[row['path']] = row
    tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf-8').split('\0'))
    cutoff = time.time() - 86400
    sizes = defaultdict(list)
    for root_name in ROOTS:
        pending = [ROOT / root_name]
        while pending:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    if getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name != CURRENT:
                            pending.append(Path(entry.path))
                        continue
                    path = Path(entry.path)
                    kind = category(path)
                    relative = path.relative_to(ROOT).as_posix()
                    if (not kind or relative in tracked or info.st_mtime > cutoff
                            or info.st_size == 0):
                        continue
                    if kind == 'archived_database' and any(Path(str(path) + suffix).exists()
                                                          for suffix in ('-wal', '-shm', '-journal', '.lock')):
                        continue
                    sizes[(kind, info.st_size)].append(path)
    groups = defaultdict(list)
    hashed = 0
    with cache_path.open('a', encoding='utf-8') as checkpoint:
        for (kind, size), paths in sizes.items():
            if len(paths) < 2:
                continue
            for path in paths:
                relative = path.relative_to(ROOT).as_posix()
                before = identity(path)
                row = cache.get(relative)
                if row is None or row['identity'] != before:
                    sha = digest(path)
                    if identity(path) != before:
                        continue
                    row = {'path': relative, 'identity': before, 'sha256': sha}
                    checkpoint.write(json.dumps(row) + '\n')
                    checkpoint.flush()
                groups[(kind, size, row['sha256'])].append(row)
                hashed += 1
                if hashed % 1000 == 0:
                    print(json.dumps({'hashes_checked': hashed}), flush=True)
    duplicates = [{'category': kind, 'bytes': size, 'sha256': sha, 'files': rows}
                  for (kind, size, sha), rows in groups.items() if len(rows) > 1]
    result = {'apply': args.apply, 'groups': duplicates, 'linked': [], 'skipped': [],
              'errors': [], 'duplicate_logical_bytes_removed': 0, 'by_category': {}}
    totals = Counter()
    for group in duplicates:
        unique = {tuple(row['identity'][2:]) for row in group['files']}
        totals[group['category']] += (len(unique) - 1) * group['bytes']
    result['by_category'] = dict(totals)
    if args.apply:
        with (output / 'operations.jsonl').open('x', encoding='utf-8') as journal:
            for group in duplicates:
                canonical = ROOT / group['files'][0]['path']
                expected = group['files'][0]['identity']
                canonical.resolve(strict=True).relative_to(ROOT / 'work')
                if identity(canonical) != expected:
                    result['skipped'].append(str(canonical.relative_to(ROOT)))
                    continue
                for row in group['files'][1:]:
                    target = ROOT / row['path']
                    resolved = target.resolve(strict=True)
                    resolved.relative_to(ROOT / 'work')
                    if resolved != target or identity(target) != row['identity']:
                        result['skipped'].append(row['path'])
                        continue
                    if os.path.samefile(canonical, target):
                        continue
                    if canonical.stat().st_nlink >= 900:
                        canonical = target
                        continue
                    before_links = target.stat().st_nlink
                    record = {'path': row['path'], 'canonical': canonical.relative_to(ROOT).as_posix(),
                              'sha256': group['sha256'], 'original_identity': row['identity']}
                    journal.write(json.dumps(dict(record, phase='intent')) + '\n')
                    journal.flush()
                    temporary = target.with_name(target.name + '.dedup-' + uuid.uuid4().hex)
                    try:
                        os.link(canonical, temporary)
                        os.replace(temporary, target)
                        assert os.path.samefile(canonical, target)
                    except OSError as error:
                        if temporary.exists():
                            temporary.unlink()
                        result['errors'].append({'path': row['path'], 'error': str(error)})
                        continue
                    result['linked'].append(record)
                    if before_links == 1:
                        result['duplicate_logical_bytes_removed'] += group['bytes']
                    journal.write(json.dumps(dict(record, phase='linked')) + '\n')
                    journal.flush()
    final.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'groups': len(duplicates), 'by_category': dict(totals),
                      'linked': len(result['linked']), 'skipped': len(result['skipped']),
                      'errors': len(result['errors']),
                      'duplicate_logical_bytes_removed': result['duplicate_logical_bytes_removed']}), flush=True)
    return bool(result['errors'])


if __name__ == '__main__':
    raise SystemExit(main())
