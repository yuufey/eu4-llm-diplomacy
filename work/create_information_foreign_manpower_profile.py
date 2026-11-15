"""Create the immutable B23 foreign-manpower profile without process access."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget
from work.local_config import game_exe

STAGE = ROOT / 'work/runtime/information-foreign-military-resources-20261029-001'
OUTPUT = ROOT / 'bridge/information/profiles/foreign-manpower-memory-1374.json'
SHA = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def pin(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size,
            'sha256': sha(path)}


def load(path, limit=10 * 1024 * 1024):
    assert 0 < path.stat().st_size <= limit
    return json.loads(path.read_bytes())


def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    executable = game_exe()
    assert sha(executable) == SHA
    old_path = ROOT / 'bridge/information/profiles/foreign-technology-memory-1374-v2.json'
    assert sha(old_path) == 'fd663e01bdd46bda1c456d52cc83e579b2eb9c79d7a0b8404a98db4f1e192158'
    old = load(old_path)
    for item in old['source_evidence'] + old['layout_dependencies']:
        path = ROOT / item['path']
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256']
    evidence = []
    for name in ('rea-diplomacy-military-values-001',
                 'rea-country-military-stats-permission-001',
                 'rea-country-active-manpower-001',
                 'rea-manpower-display-formatter-001'):
        path = STAGE / name / 'evidence.json'
        document = load(path)
        assert document['subject']['digest']['sha256'] == SHA
        assert document['operation'] == 'procedure_pseudo_code'
        evidence.append({**pin(path), 'evidence_id': document['evidence_id']})
    pe = PE(executable)
    assert pe.base == 0x140000000
    guards = deepcopy(old['code_guards'])
    bounds = []
    # Independently bounded by the ordinary ABI worker's reachable CFG. These
    # leaves have no .pdata rows; the ranges are not synthetic unwind records.
    leaves = {
        0x378ff0: (0x379051, 'b811adf6e525d11e5b7d0966a1d7dce825f0b7f9e8d03c66c7eb7e865c9d0658'),
        0x34dda0: (0x34de07, '017f5755f73953e9f09c722c1a5edd9affd754fc23ddd039230d5d7657161dcf'),
    }
    for name, rva in (('diplomacy_military_values', 0xef9e70),
                      ('military_stats_permission', 0x378ff0),
                      ('active_manpower_components', 0x34dda0),
                      ('manpower_display_formatter', 0xae8fe0)):
        row = pe.function(rva)
        if rva in leaves:
            assert row is None
            begin, end, unwind = rva, leaves[rva][0], None
            boundary_source = 'ordinary_reachable_CFG_through_final_RET_not_pdata'
        else:
            assert row is not None
            begin, end, unwind = row
            boundary_source = 'PE_pdata'
        assert begin == rva and 0 < end - begin <= 16 * 1024
        raw = pe.bytes_at(begin, end - begin)
        assert len(raw) == end - begin
        if rva in leaves:
            assert hashlib.sha256(raw).hexdigest() == leaves[rva][1]
        guards.append({'name': name, 'rva': hex(begin), 'end_rva_exclusive': hex(end),
                       'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                       'aslr_invariant': True, 'relocation_sites': []})
        bounds.append({'rva_start': hex(begin), 'rva_end_exclusive': hex(end),
                       'unwind_info_rva': hex(unwind) if unwind is not None else None,
                       'boundary_source': boundary_source})
    # File-relative PE relocation metadata is bounded; this does not disassemble
    # the image. Nonzero relocation types inside any guard would need masking.
    relocations = []
    for section in pe.sections:
        if section['name'] != '.reloc':
            continue
        assert section['size'] <= 1024 * 1024
        raw = pe.bytes_at(section['rva'], section['size'])
        offset = 0
        while offset + 8 <= len(raw):
            page, size = struct.unpack_from('<II', raw, offset)
            if page == size == 0:
                break
            assert 8 <= size <= len(raw) - offset and size % 2 == 0
            for at in range(offset + 8, offset + size, 2):
                entry = struct.unpack_from('<H', raw, at)[0]
                site = page + (entry & 0xfff)
                if entry >> 12 and any(int(g['rva'], 0) <= site < int(g['end_rva_exclusive'], 0)
                                       for g in guards):
                    relocations.append({'rva': hex(site), 'type': entry >> 12})
            offset += size
    assert not relocations
    extra_dependencies = [
        'foreign_technology_capture.py', 'foreign_country_memory.py',
        'foreign_manpower_memory.py', 'foreign_military_visibility_memory.py',
        'country_reference_memory.py', 'country_view_admission_memory.py',
        'country_scale_development_memory.py', 'country_faith_memory.py',
        'province_state_memory.py',
    ]
    dependencies = {item['path']: item for item in old['layout_dependencies']}
    dependencies[old_path.relative_to(ROOT).as_posix()] = pin(old_path)
    for name in extra_dependencies:
        path = ROOT / 'bridge/information' / name
        dependencies[path.relative_to(ROOT).as_posix()] = pin(path)
    profile = {
        'profile_id': 'foreign-manpower-memory-1374', 'profile_version': 1,
        'game_version': '1.37.4', 'observer': 'FRA',
        'executable': {'sha256': SHA, 'image_base': hex(pe.base)},
        'target_scope': 'resolved_foreign_country',
        'source_evidence': [*deepcopy(old['source_evidence']), *evidence],
        'layout_dependencies': list(dependencies.values()), 'code_guards': guards,
        'permission': {'world_global_rva': '0x233fe58', 'settings_offset': '0x2150',
            'public_options_i32_offsets': ['0x5c', '0x28'],
            'timed_head_offset': '0x238', 'node_record_offset': '0x0',
            'node_next_offset': '0x10', 'record_observer_ref_offset': '0x10',
            'record_expiry_i32_offset': '0x18', 'world_date_offset': '0x1dd0',
            'match': 'first signed observer-slot match; extra fullref equality required',
            'expiry_test': 'now < expiry'},
        'manpower': {'reserve_i32_offset': '0xdb8',
            'count_u16_offsets': ['0x10b8', '0x10ba', '0x10bc'],
            'definition_pointer_offsets': ['0xd48', '0xd50', '0xd58'],
            'definition_cost_i32_offset': '0x54', 'arithmetic': 'signed low32 multiply/add',
            'unit': 'native_manpower_statistic', 'scale': 1},
        'semantics': {'actual_UI_observed': False, 'native_function_invoked': False,
            'physical_player_equals_observer_required': False,
            'basis': 'native_country_military_stats_visibility_permission',
            'limits': ['Country-view projection and FRA non-player role remain parent preconditions',
                'Field permission does not establish military quality visibility',
                'Component class names and physical manpower unit remain unresolved',
                'Formatter is guarded as evidence but never executed or emulated',
                'No claim of atomicity, cache freshness, message dispatch or rendered text']},
        'limits': {'parent_total_bytes': 524288, 'leaf_total_bytes': 16384,
                   'leaf_calls': 256, 'permission_nodes': 256},
    }
    assert len(json.dumps(profile, ensure_ascii=False).encode('utf-8')) <= 60 * 1024
    write(OUTPUT, profile)
    assert OUTPUT.stat().st_size <= 65536
    assert sha(executable) == SHA
    receipt = {'status': 'created', 'profile': pin(OUTPUT), 'builder': pin(Path(__file__).resolve()),
        'ordinary_PE_function_bounds': bounds, 'relocations_in_guards': relocations,
        'guard_bytes_per_boundary': sum(len(g['bytes']) // 2 for g in guards),
        'analysis_peak_private_bytes': check_memory_budget(), 'process_access': False,
        'native_function_invoked': False,
        'seed002_correction': 'ordinary_pdata_range item 3 is unwind-info RVA, not an end RVA'}
    write(STAGE / 'manpower-profile-build-001.json', receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
