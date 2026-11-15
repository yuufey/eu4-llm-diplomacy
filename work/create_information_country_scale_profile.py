"""Build an immutable B23 country-scale contract from retained narrow evidence."""
from copy import deepcopy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.create_information_country_person_plugin_profile import guard, relocations
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.verify_information_foreign_technology import pin, read_json, write_new

STAGE = ROOT / 'work/runtime/information-foreign-scale-20261029-001'
EXE = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    from hashlib import file_digest
    with game_exe().open('rb') as stream:
        assert file_digest(stream, 'sha256').hexdigest() == EXE
    pe = PE(game_exe())
    prior = ROOT / 'bridge/information/profiles/foreign-technology-memory-1374-v2.json'
    old = read_json(prior)
    specs = (
        ('rea-intervention-country-entry-001', 0xf17530),
        ('rea-great-power-membership-001', 0x7cf080),
        ('rea-great-power-feature-001', 0x1295e0),
        ('rea-great-power-entry-001', 0x1152150),
        ('rea-great-power-development-001', 0x7cf0f0),
    )
    evidence = []
    guards = deepcopy(old['code_guards'])
    sites = relocations(pe)
    for name, rva in specs:
        path = STAGE / name / 'evidence.json'
        row = read_json(path)
        assert row['subject']['digest']['sha256'] == EXE
        assert row['operation'] == 'procedure_pseudo_code'
        span = pe.function(rva)
        assert span and span[0] == rva and 0 < span[1] - rva <= 65536
        evidence.append(dict(pin(path), evidence_id=row['evidence_id'],
                             rva=hex(rva), preferred_va=hex(0x140000000+rva),
                             end_rva_exclusive=hex(span[1]), evidence_class='REA static'))
        guards.append(guard(pe, name.removeprefix('rea-').removesuffix('-001'),
                            rva, span[1], sites, 'ordinary bounded PE code; REA semantics retained separately'))
    contract = {
        'schema': 'information.country_scale.native_contract.v1',
        'binary_sha256': EXE, 'preferred_image_base': '0x140000000',
        'status': 'bounded_static_contract', 'evidence': evidence,
        'actual_UI_observed': False, 'runtime_memory_observed': False,
        'native_function_invoked': False,
        'development': {'source': '7cf0f0 OWN_DEVELOPMENT tooltip input',
                        'country_offset': '0xe1c', 'type': 'signed_i32', 'scale': 1000,
                        'scope': 'own cache, not own plus weighted subjects or great-power score'},
        'subject_scale': {
            'vector': ['country+0x1a18', 'country+0x1a20'], 'stride': 8,
            'contribution': 'wrap_i32(trunc_zero(child.e1c * signed_i32(global233f8ac) / 1000)); sum wrap_i32',
            'overlord_condition': 'highest byte of child+0x18f0 nonzero, not raw reference != 0',
            'exclusion': 'relation table1510, overlord slot*48, owner+128/+134 entries stride16; first matching recipient slot; assoc+40 type; flags11b!=0 &&14b!=0 &&121==0 &&13e==0 &&151==0 &&148!=0',
            'scope': 'counts in this native contribution vector and weighted development; not complete/direct subject count or hierarchy',
            'limits': {'reference_count': 256, 'relation_entries': 4096}},
        'major_power': {
            'source': 'f17530 InterveneDiplomacyDialogue_countryentry great_power_glow condition',
            'condition': 'feature1295e0 AND eligibility7cf080 AND country288f!=0',
            'normal_reference': 'highest byte nonzero; byte48==7 special path unsupported',
            'eligibility': 'country1344!=0 AND highest_byte(country18f0)==0',
            'feature_positive': '(global233ff00!=0 OR global233ff24!=0) AND global233feb6==0',
            'feature_other': 'unresolved target execution-thread TLS; unknown unless another conjunct proves false',
            'scope': 'native great-power glow predicate, not rank, score, or membership list'},
        'admission': 'reuse bound FRA country-view entry predicate as a conservative export boundary, with separate Human1 and FRA controller0 checks; not proof every native widget uses this gate',
        'unresolved': ['actual UI rendering and field-specific complete visibility',
                       'thread TLS for remaining feature branches', 'development cache freshness and atomicity',
                       'complete subject hierarchy', 'territory source', 'complete war enumeration'],
        'rejected_interpretations': ['government_rank is not major-power membership',
                                     'country1344 qualifier alone is not proven territory count',
                                     'country1548/1554 entries alone are not proven war count'],
    }
    contract_path = STAGE / 'native-country-scale-contract-001.json'
    write_new(contract_path, contract)
    profile = {
        'profile_id': 'country-scale-memory-1374', 'profile_version': 1,
        'game_version': '1.37.4', 'executable': deepcopy(old['executable']),
        'observer': 'FRA', 'target_scope': 'resolved_country_including_observer',
        'source_evidence': [pin(contract_path)] + [pin(STAGE/n/'evidence.json') for n, _ in specs],
        'layout_dependencies': [pin(prior)] + [pin(ROOT/'bridge/information'/n) for n in (
            'country_scale_development_memory.py', 'country_scale_flag_memory.py',
            'foreign_country_memory.py', 'foreign_technology_capture.py', 'country_view_admission_memory.py',
            'country_reference_memory.py', 'country_faith_memory.py', 'province_state_memory.py')],
        'code_guards': guards,
        'observer_role_layout': deepcopy(old['observer_role_layout']),
        'predicate_layout': deepcopy(old['predicate_layout']),
        'semantics': {'supported_fields': ['F01.development', 'F01.subject_scale', 'F01.major_power'],
                      'actual_UI_observed': False, 'native_function_invoked': False,
                      'physical_player_equals_observer_required': False, 'complete': False},
    }
    output = ROOT/'bridge/information/profiles/country-scale-memory-1374.json'
    write_new(output, profile)
    write_new(STAGE/'country-scale-profile-build-001.json', {
        'status': 'created', 'profile': pin(output), 'contract': pin(contract_path),
        'builder': pin(Path(__file__).resolve()), 'guards': len(guards),
        'guard_bytes': sum(len(bytes.fromhex(g['bytes'])) for g in guards),
        'game_access': False, 'queries_repeated': False})
    print(pin(output))


if __name__ == '__main__':
    main()
