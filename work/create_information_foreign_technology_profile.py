"""Create the fixed-build foreign technology/view-predicate contract once."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe

STAGE = ROOT / 'work/runtime/information-foreign-visibility-20261029-001'
SHA = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def pin(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def load(path):
    assert path.stat().st_size <= 10 * 1024 * 1024
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    executable = game_exe()
    assert sha(executable) == SHA
    admission_path = STAGE/'rea-diplomacy-country-select-001/evidence.json'
    admission = load(admission_path)
    assert admission['evidence_id'] == 'ev_12ff55717e16b8adfecfb7eee6c4468cfa5c314b447f63e3ef50383aa9d3b32c'
    assert admission['subject']['digest']['sha256'] == SHA and admission['operation'] == 'analyze_function'
    body = admission['raw_result']['value']['procedure']['body']
    assert body['ranges'] == [{'start': '0x140f016e0', 'end': '0x140f01c2d'}]
    assert body['total_bytes'] == 1358 and body['non_contiguous'] is False
    writer_path = STAGE/'rea-ui-efd2c0-001/evidence.json'
    writer = load(writer_path)
    assert writer['subject']['digest']['sha256'] == SHA
    assert writer['operation'] == 'procedure_pseudo_code' and '"mil_value"' in writer['raw_result']['value']
    pe = PE(executable)
    begin, end = 0xf016e0, 0xf01c2e
    guard = pe.bytes_at(begin, end-begin)
    relocations = []
    for section in pe.sections:
        if section['name'] != '.reloc':
            continue
        raw = pe.bytes_at(section['rva'], section['size'])
        assert len(raw) <= 1024 * 1024
        offset = 0
        while offset+8 <= len(raw):
            page, size = struct.unpack_from('<II', raw, offset)
            if page == size == 0:
                break
            assert 8 <= size <= len(raw)-offset and size % 2 == 0
            for at in range(offset+8, offset+size, 2):
                entry = struct.unpack_from('<H', raw, at)[0]
                if entry >> 12 and begin <= page+(entry&0xfff) < end:
                    relocations.append({'rva': hex(page+(entry&0xfff)), 'type': entry >> 12})
            offset += size
    assert relocations == [], 'Runtime guard must account for relocations before use'
    dependencies = [ROOT/'bridge/information/profiles/country-rivals-memory-1374.json',
                    ROOT/'bridge/information/profiles/military-quality-memory-1374.json',
                    ROOT/'bridge/information/profiles/relation-memory-1374.json']
    profile = {
        'profile_id': 'foreign-technology-memory-1374', 'profile_version': 1,
        'game_version': '1.37.4', 'executable': {'sha256': SHA, 'image_base': '0x140000000'},
        'observer': 'FRA', 'target_scope': 'resolved_foreign_country',
        'source_evidence': [pin(admission_path), pin(writer_path), pin(STAGE/'foreign-tech-writer-contract-001.json')],
        'layout_dependencies': [pin(path) for path in dependencies],
        'code_guards': [{'name': 'diplomacy_country_selection', 'rva': hex(begin),
            'end_rva_exclusive': hex(end), 'bytes': guard.hex(),
            'sha256': hashlib.sha256(guard).hexdigest(), 'aslr_invariant': True,
            'relocation_sites': relocations}],
        'predicate_layout': {'relation_table_offset': '0x1510', 'relation_stride': '0x48',
            'row_owner_offset': '0x0', 'row_target_ref_offset': '0x10',
            'owner_counter_vector_offset': '0x38', 'counter_stride': '0x18', 'counter_offset': '0x14',
            'capital_pointer_offset': '0x14b0', 'capital_flags_offset': '0x959', 'capital_flag_mask': '0x10',
            'capital_bitset_pointer_offset': '0x5e0',
            'special_slot_globals_rva': ['0x233d884','0x233d8b8','0x233d8bc']},
        'technology': {'definition_key': 'mil_tech', 'unit': 'technology_level', 'scale': 1,
            'value_origin': 'copied_native_country_technology_cache', 'period': 'current'},
        'semantics': {'visibility_basis': 'native_country_view_predicate_projected_to_observer',
            'actual_UI_observed': False, 'native_function_invoked': False,
            'physical_player_equals_observer_required': False,
            'limits': ['Projection substitutes the resolved FRA row for the original client-current-country input',
                'Applies only to the military technology field shown unconditionally after country selection',
                'Does not establish the visibility of armies, navies, manpower or other F02 fields',
                'No claim of an atomic main-thread snapshot or cache refresh time']},
        'limits': {'max_targets': 8, 'max_country_slots': 4096, 'max_total_rpm': 524288},
    }
    output = ROOT/'bridge/information/profiles/foreign-technology-memory-1374.json'
    write(output, profile)
    assert sha(executable) == SHA
    receipt = {'status': 'created', 'profile': pin(output), 'writer_evidence_id': writer['evidence_id'],
        'admission_evidence_id': admission['evidence_id'], 'guard_bytes': len(guard),
        'relocations_in_guard': relocations, 'game_access': False,
        'profile_builder': pin(Path(__file__).resolve())}
    write(STAGE/'foreign-profile-build-001.json', receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
