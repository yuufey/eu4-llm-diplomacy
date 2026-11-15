"""Independent selected-pair Curry vector reference; no game calls on import/help."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.probe_information_current_overextension import probe
from work.probe_information_diplomat_tasks import pin, write


def read_inputs(reader, base, country):
    def read(address, size, label):
        return reader.read(address, size, 'independent.curry.' + label)

    database = int.from_bytes(read(base + 0x233D8B0, 8, 'database'), 'little')
    table = int.from_bytes(read(database + 0x118, 8, 'countries'), 'little')
    count = int.from_bytes(read(database + 0x124, 4, 'country_count'), 'little')
    if not 118 <= count <= 4096:
        raise ValueError('country_count_out_of_bound')
    actor_raw = read(country + 0x20, 8, 'actor_fullref')
    target = int.from_bytes(read(table + 117 * 8, 8, 'recipient_pointer'), 'little')
    recipient_raw = read(target + 0x20, 8, 'recipient_fullref')
    if recipient_raw != bytes.fromhex('4255520075000001'):
        raise ValueError('current_BUR_fullref_mismatch')
    if actor_raw != bytes.fromhex('465241007a000001'):
        raise ValueError('current_FRA_fullref_mismatch')
    relation_table_raw = read(country + 0x1510, 8, 'relation_table')
    relation_table = int.from_bytes(relation_table_raw, 'little')
    row_address = relation_table + 117 * 0x48
    row_raw = read(row_address, 0x20, 'relation_row')
    if row_raw[0x10:0x18] != recipient_raw:
        raise ValueError('relation_recipient_mismatch')
    owner = int.from_bytes(row_raw[:8], 'little')
    begin_raw = read(owner + 0x158, 8, 'begin_before')
    count_raw = read(owner + 0x164, 4, 'count_before')
    begin = int.from_bytes(begin_raw, 'little')
    length = int.from_bytes(count_raw, 'little', signed=True)
    if not 0 <= length <= 4096:
        raise ValueError('curry_vector_count_out_of_bound')
    elements = read(begin, length * 16, 'elements') if length else b''
    if read(owner + 0x158, 8, 'begin_after') != begin_raw or read(owner + 0x164, 4, 'count_after') != count_raw:
        raise ValueError('curry_vector_changed')
    return {'actor': 'FRA', 'recipient': 'BUR', 'actor_fullref_raw_hex': actor_raw.hex(),
            'recipient_fullref_raw_hex': recipient_raw.hex(),
            'relation_table_raw_hex': relation_table_raw.hex(),
            'row_address': hex(row_address), 'row_raw_hex': row_raw.hex(),
            'owner': hex(owner), 'begin_raw_hex': begin_raw.hex(),
            'count_raw_hex': count_raw.hex(), 'elements_raw_hex': elements.hex(),
            'first_dwords': [value[0] for value in struct.iter_unpack('<I12x', elements)],
            'target_slot': 117, 'native_function_invoked': False}


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
        raw = json.loads(args.reference_from.read_text(encoding='utf-8'))
        passes = raw['favor_tasks_inputs']
        if raw.get('completed') is not True or raw.get('cleanup', {}).get('handle_close', {}).get('closed') is not True:
            raise ValueError('raw_capture_incomplete')
        if len(passes) != 2 or passes[0] != passes[1] or not raw['doublepass']['consistent']:
            raise ValueError('passes_differ')
        source = passes[0]
        result = {'schema': 'information_favor_tasks_independent_reference.v1',
                  'basis': 'independent_RPM_not_public_query', 'raw_input': pin(args.reference_from),
                  'identity': raw['identity'], 'date': source['date'],
                  'actor': source['actor'], 'recipient': source['recipient'],
                  'family': 'curry_favors', 'task_active': 117 in source['first_dwords'],
                  'vector_count': len(source['first_dwords']), 'first_dwords': source['first_dwords'],
                  'source_rva': '0x5ade90', 'static_source': 'work/runtime/r71-curry-contract-20261020-001/report.md'}
    else:
        if args.installation is None:
            parser.error('--installation is required for RPM')
        result = probe(args.installation, field='favor_tasks', input_reader=read_inputs)
    write(args.output, result)
    print(json.dumps({'status': result.get('status', 'reference_written'),
                      'completed': result.get('completed'), 'errors': result.get('errors')}))
    return 0 if result.get('completed', True) else 1


if __name__ == '__main__':
    raise SystemExit(main())
