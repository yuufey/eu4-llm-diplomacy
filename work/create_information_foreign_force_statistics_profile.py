"""Pin the B23 diplomacy force-statistic reader and its observed predicates."""
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

STAGE = ROOT / 'work/runtime/information-foreign-forces-20261029-001'
BASE = ROOT / 'bridge/information/profiles/foreign-manpower-memory-1374.json'
OUTPUT = ROOT / 'bridge/information/profiles/foreign-force-statistics-memory-1374.json'
EXE = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def pin(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size,
            'sha256': sha(path)}


def load(path):
    assert 0 < path.stat().st_size <= 10 * 1024 * 1024
    return json.loads(path.read_bytes())


def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    executable = game_exe()
    assert sha(executable) == EXE
    assert sha(BASE) == '6911d974130d0f83a64ae041a5521038ef93b1128a95cc05a4f9c2dee7f608da'
    base = load(BASE)
    for row in base['source_evidence'] + base['layout_dependencies']:
        p = ROOT / row['path']
        assert p.stat().st_size == row['bytes'] and sha(p) == row['sha256']
    pe = PE(executable)
    assert pe.base == 0x140000000
    keep = {'diplomacy_country_selection', 'diplomacy_military_values', 'military_stats_permission'}
    guards = [deepcopy(g) for g in base['code_guards'] if g['name'] in keep]
    assert len(guards) == 3
    ordinary_path = STAGE / 'ordinary-force-formatters-001/ordinary-force-formatters-002.json'
    ordinary = load(ordinary_path)
    assert ordinary['status'] == 'passed_with_bounded_objdump_fallback'
    for guard in ordinary['code_guards']:
        if guard['name'] not in {'force_stat_formatter_and_chained_body', 'force_count_formatter_and_chained_body'}:
            continue
        guards.append(deepcopy(guard))
    assert len(guards) == 5
    mapping_path = STAGE / 'force-predicate-map-research-001.json'
    mapping = load(mapping_path)
    assert mapping['executable_sha256'] == EXE and mapping['method_invocation'] is False
    expected_vtables = {
        '0x1c42540': {'slot_80': '0x8f440', 'slot_88': '0x8f450'},
        '0x1cca618': {'slot_80': '0x8f450', 'slot_88': '0x8f440'},
    }
    assert mapping['vtables'] == expected_vtables
    method_guards = {}
    for rva, body, truth in ((0x8f440, 'b001c3', True), (0x8f450, '32c0c3', False)):
        item = mapping['methods'][hex(rva)]
        assert item['body_hex'] == body and item['return_bool'] is truth
        raw = pe.bytes_at(rva, 3)
        assert raw.hex() == body
        method_guards[hex(rva)] = {'body_hex': body, 'constant_boolean_return': truth}
        guards.append({'name': f'constant_predicate_{rva:x}', 'rva': hex(rva),
            'end_rva_exclusive': hex(rva + 3), 'bytes': body,
            'sha256': hashlib.sha256(raw).hexdigest(), 'aslr_invariant': True,
            'relocation_sites': [],
            'boundary_source': 'exact two-instruction constant-AL leaf through RET, not a pdata claim'})
    for guard in guards:
        start, end = int(guard['rva'], 0), int(guard['end_rva_exclusive'], 0)
        raw = bytes.fromhex(guard['bytes'])
        assert len(raw) == end - start and pe.bytes_at(start, len(raw)) == raw
        assert hashlib.sha256(raw).hexdigest() == guard['sha256']
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
    dependencies = {row['path']: deepcopy(row) for row in base['layout_dependencies']}
    dependencies[BASE.relative_to(ROOT).as_posix()] = pin(BASE)
    # Capture/public sources do not pin themselves: their immutable profile
    # digest would otherwise form a source/profile hash cycle.
    for name in ('foreign_force_statistics_memory.py', 'foreign_manpower_memory.py',
                 'foreign_military_visibility_memory.py', 'foreign_manpower_capture.py',
                 'foreign_technology_capture.py', 'foreign_country_memory.py'):
        path = ROOT / 'bridge/information' / name
        dependencies[path.relative_to(ROOT).as_posix()] = pin(path)
    proof_paths = [mapping_path, ordinary_path, STAGE / 'force-unit-label-evidence-001.json',
        STAGE / 'force-value-source-review-001.json',
        STAGE / 'research-live-001/research-receipt-001.json',
        STAGE / 'rea-force-stat-formatter-001/evidence.json',
        STAGE / 'rea-force-count-formatter-001/evidence.json']
    predicate = {
        'schema': 'information.foreign_force_statistics_predicate_profile.v1',
        'executable_sha256': EXE, 'vtable_rvas': expected_vtables,
        'method_guards': method_guards,
        'evidence_pins': [pin(mapping_path), pin(STAGE / 'force-unit-label-evidence-001.json')],
    }
    profile = {
        'profile_id': 'foreign-force-statistics-memory-1374', 'profile_version': 1,
        'game_version': '1.37.4', 'executable': {'sha256': EXE, 'image_base': hex(pe.base)},
        'observer': 'FRA', 'target_scope': 'resolved_foreign_country',
        'source_evidence': [*deepcopy(base['source_evidence']), *[pin(p) for p in proof_paths]],
        'layout_dependencies': list(dependencies.values()), 'code_guards': guards,
        'force_predicates': predicate,
        'layout': {'head': 'country+0xd18', 'node_group': '0x0', 'node_next': '0x10',
            'vector_begin': 'group+0x30', 'vector_end': 'group+0x38',
            'vector_stride': 8, 'land_strength': 'record+0x28 signed int32'},
        'fields': {
            'F02.visible_army': {'unit': 'soldiers', 'scale': 1,
                'basis': 'native_diplomacy_soldier_statistic',
                'arithmetic': 'signed low32 sum of primary-true records; formatter input low32(sum*1000)',
                'unit_evidence': 'same value control -> DIP_LAND_FORCE; tooltip says Soldiers'},
            'F02.visible_navy': {'unit': 'ships', 'scale': 1,
                'basis': 'native_diplomacy_ship_statistic',
                'arithmetic': 'signed low32 sum of secondary-true vector lengths divided by 8',
                'unit_evidence': 'same value control -> DIP_NAVAL_FORCE; tooltip says Ships'},
        },
        'semantics': {'actual_UI_observed': False, 'native_function_invoked': False,
            'physical_player_equals_observer_required': False,
            'visibility': 'country-view conservative export precondition AND native military stats permission',
            'limits': ['Observed vtable rows only; unsupported rows remain unknown',
                'No reuse of N02 kind-code classification or serialized-strength unit claims',
                'Statistic inputs are exported; formatter abbreviation and rendered text are not emulated',
                'No atomicity, cache freshness or complete battlefield visibility claim',
                'Player/nonplayer message differences are not established by these fields']},
        'limits': {'parent_total_bytes': 524288, 'field_total_bytes': 262144,
            'field_calls': 4096, 'max_nodes': 128, 'max_records': 4096},
    }
    write(OUTPUT, profile)
    assert OUTPUT.stat().st_size <= 128 * 1024
    assert sha(executable) == EXE
    receipt = {'status': 'created', 'profile': pin(OUTPUT), 'builder': pin(Path(__file__).resolve()),
        'guard_count': len(guards), 'guard_bytes_per_boundary': sum(len(g['bytes']) // 2 for g in guards),
        'relocation_sites': [], 'process_access': False, 'native_function_invoked': False,
        'analysis_peak_private_bytes': check_memory_budget(),
        'count_formatter_boundary': 'primary pdata plus adjacent CHAININFO rows; report002 supersedes primary-only guard001'}
    write(STAGE / 'force-profile-build-001.json', receipt)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == '__main__':
    main()
