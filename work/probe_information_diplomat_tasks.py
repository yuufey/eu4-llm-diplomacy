"""Independent bounded diplomat-instance bytes; default/help never opens EU4."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.probe_information_current_overextension import probe


def pin(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': path.resolve().relative_to(ROOT).as_posix(),
            'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def read_inputs(reader, base, country):
    def raw(address, size, label):
        return reader.read(address, size, 'independent.diplomats.' + label)

    def qword(address, label):
        return int.from_bytes(raw(address, 8, label), 'little')

    database = qword(base + 0x233D8B0, 'database')
    table = qword(database + 0x118, 'country_table')
    count = int.from_bytes(raw(database + 0x124, 4, 'country_count'), 'little')
    if not 1 <= count <= 4096:
        raise ValueError('country_count_out_of_bound')
    actor = raw(country + 0x20, 8, 'country_fullref')

    def endpoint(encoded):
        fullref = int.from_bytes(encoded, 'little')
        slot = (fullref >> 32) & 0xffff
        result = {'raw_hex': encoded.hex(), 'slot': slot, 'status': 'unknown'}
        if slot >= count or encoded == b'---\0\0\0\0\0':
            return result
        pointer = qword(table + slot * 8, 'endpoint_pointer')
        if pointer < 0x10000 or pointer % 8:
            return result
        actual = raw(pointer + 0x20, 8, 'endpoint_actual_fullref')
        result['actual_raw_hex'] = actual.hex()
        result['pointer'] = hex(pointer)
        if actual != encoded:
            return result
        tag = encoded[:3].decode('ascii', errors='replace')
        if len(tag) == 3 and all(c.isupper() or c.isdigit() for c in tag):
            result.update(status='known', country=tag)
        return result

    holder = qword(country + 0x1480, 'holder')
    manager = qword(holder + 0x18, 'manager')
    bounds = raw(manager + 0x20, 16, 'bounds_before')
    begin, end = struct.unpack('<QQ', bounds)
    if end < begin or (end - begin) % 8 or (end - begin) // 8 > 256:
        raise ValueError('instance_vector_bounds_invalid')
    pointers = raw(begin, end - begin, 'instance_pointers') if end > begin else b''
    rows = []
    for index, (entry,) in enumerate(struct.iter_unpack('<Q', pointers)):
        record = qword(entry + 0x10, f'{index}.record')
        state = raw(entry + 0x18, 1, f'{index}.state')
        identifier = raw(entry + 0x44, 4, f'{index}.id')
        row = {'index': index, 'entry': hex(entry), 'record': hex(record),
               'state_raw_hex': state.hex(), 'id_raw_hex': identifier.hex()}
        if record:
            values = {name: raw(record + offset, size, f'{index}.{name}').hex()
                      for name, offset, size in [('actor', 0x80, 8), ('recipient', 0x88, 8),
                                               ('token', 0xA8, 4), ('date_20', 0x20, 4),
                                               ('date_24', 0x24, 4), ('unknown_2c', 0x2C, 4)]}
            row.update(record_raw=values,
                       actor=endpoint(bytes.fromhex(values['actor'])),
                       recipient=endpoint(bytes.fromhex(values['recipient'])))
        rows.append(row)
    if raw(manager + 0x20, 16, 'bounds_after') != bounds:
        raise ValueError('instance_vector_changed')
    if pointers and raw(begin, len(pointers), 'instance_pointers_after') != pointers:
        raise ValueError('instance_pointer_array_changed')
    return {'country_fullref_raw_hex': actor.hex(), 'holder': hex(holder),
            'manager': hex(manager), 'bounds_raw_hex': bounds.hex(),
            'pointer_array_raw_hex': pointers.hex(), 'instance_count_observed': len(rows),
            'instances': rows, 'date_interpretation': 'lifecycle_raw_only',
            'native_function_invoked': False}


def reference(raw, path):
    if raw.get('completed') is not True or raw.get('status') != 'observed':
        raise ValueError('capture_incomplete')
    if raw.get('cleanup', {}).get('handle_close', {}).get('closed') is not True:
        raise ValueError('handle_not_closed')
    passes = raw['diplomat_tasks_inputs']
    if len(passes) != 2 or passes[0] != passes[1] or not raw['doublepass']['consistent']:
        raise ValueError('independent_passes_differ')
    rows = []
    for item in passes[0]['instances']:
        state = int(item['state_raw_hex'], 16)
        row = {'index': item['index'],
               'id': int.from_bytes(bytes.fromhex(item['id_raw_hex']), 'little', signed=True),
               'state_raw': state, 'state': {0: 'idle', 1: 'returning', 2: 'active'}.get(state, 'unknown')}
        if 'record_raw' in item:
            record = item['record_raw']
            row.update(action_token_raw=int.from_bytes(bytes.fromhex(record['token']), 'little', signed=True),
                       actor=item['actor'], recipient=item['recipient'],
                       lifecycle_date_20_raw=int.from_bytes(bytes.fromhex(record['date_20']), 'little', signed=True),
                       lifecycle_date_24_raw=int.from_bytes(bytes.fromhex(record['date_24']), 'little', signed=True),
                       unknown_2c_raw=int.from_bytes(bytes.fromhex(record['unknown_2c']), 'little', signed=True))
        rows.append(row)
    return {'schema': 'information_diplomat_tasks_independent_reference.v1',
            'basis': 'independent_RPM_not_production_reader', 'raw_input': pin(path),
            'identity': raw['identity'], 'date': passes[0]['date'],
            'instance_count_observed': len(rows), 'available_count_observed': sum(r['state_raw'] == 0 for r in rows),
            'instances': rows, 'diplomats_total_verified': False,
            'estimated_return_dates_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--installation', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--reference-from', type=Path)
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return 0
    if args.output is None or args.output.exists():
        parser.error('a new --output is required')
    if args.reference_from:
        if args.reference_from.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('raw_json_out_of_bound')
        result = reference(json.loads(args.reference_from.read_text(encoding='utf-8')), args.reference_from)
    else:
        if args.installation is None:
            parser.error('--installation is required for RPM')
        result = probe(args.installation, field='diplomat_tasks', input_reader=read_inputs)
    write(args.output, result)
    print(json.dumps({'path': str(args.output), 'status': result.get('status', 'reference_written'),
                      'completed': result.get('completed'), 'errors': result.get('errors')}))
    return 0 if result.get('completed', True) else 1


if __name__ == '__main__':
    raise SystemExit(main())
