"""Pin the native country-scope city counter without calling it territory area."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_country_person_plugin_profile import guard,relocations
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-country-territory-wars-20261029-001'
OLD=ROOT/'work/runtime/information-foreign-scale-20261029-001'
SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    with game_exe().open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==SHA
    old=ROOT/'bridge/information/profiles/country-scale-memory-1374.json'
    profile=deepcopy(read_json(old));assert profile['profile_version']==1
    pe=PE(game_exe());sites=relocations(pe)
    evidence=[]
    for source,rva,label in (
        (OLD/'rea-territory-script-seed-001/evidence.json',0x6a7b20,'country numeric registry'),
        (STAGE/'rea-country-numeric-dispatch-001/evidence.json',0x6a7140,'country/province numeric dispatcher'),
        (STAGE/'rea-country-city-count-revolt-use-001/evidence.json',0xa85fa0,'country city-count tooltip input'),
    ):
        row=read_json(source);assert row['subject']['digest']['sha256']==SHA
        assert row['operation']=='procedure_pseudo_code'
        span=pe.function(rva);assert span and span[0]==rva
        evidence.append(dict(pin(source),evidence_id=row['evidence_id'],rva=hex(rva),
                             preferred_va=hex(0x140000000+rva),end_rva_exclusive=hex(span[1])))
        profile['code_guards'].append(guard(pe,label.replace(' ','_').replace('/','_'),
            rva,span[1],sites,'ordinary PE code guard; REA semantic evidence separately retained'))
    raw=pe.bytes_at(0x6e01e0,17)
    assert raw.hex()=='416980c81f0000e80300008902488bc2c3'
    profile['code_guards'].append(guard(pe,'country_script_city_counter_getter',0x6e01e0,0x6e01f1,sites,
        'exact 17-byte getter through RET, no pdata extent fabricated'))
    ordinary=[pin(STAGE/'territory-registration-001/registration-review-001.json'),
              pin(STAGE/'city-dispatch-abi-001/ordinary-abi-check-001.json'),
              pin(OLD/'territory-getter-candidates-ordinary-001.json')]
    contract={'schema':'information.country_territory.native_contract.v1',
        'status':'bounded_static_contract','binary_sha256':SHA,'preferred_image_base':'0x140000000',
        'rea':evidence,'ordinary':ordinary,
        'chain':'6a7b20 num_of_cities -> vtable1ca0210 slot+10 -> 6e01e0; 6a7140 country branch supplies DB country pointer as R8',
        'abi':'ordinary call at6a7256: R8=R10=country table[fullref.slot]; separate province call6a7486 uses world1ca8+index*2e10',
        'cache':{'offset':'0x1fc8','type':'signed_i32','public_unit':'native_city_count','public_scale':1,
                 'supported_range':[0,65535]},
        'script_encoding':'IMUL signed-i32 cache by1000, write low32; raw/private retains wrap interpretation',
        'independent_native_consumer':'a85fa0 reads the same raw integer, formats it for CV_BREAK_COUNTRY_CITIES; it does not use script multiply for that tooltip',
        'public_shape':{'city_count':'bounded integer'},'complete':False,
        'native_function_invoked':False,'actual_UI_observed':False,
        'warnings':['6a7140 REA type propagation did not settle; exact ordinary ABI instructions independently confirm the country R8 flow',
                    '6e0200 had no cached procedure and was not retried; it is the clone slot, not the numeric slot'],
        'unresolved':['complete owned-province count/list and city-versus-colony census',
                      'cache writer and freshness','full territory labels/tooltips and field-specific visibility',
                      'actual UI rendering and atomicity']}
    target=STAGE/'native-country-territory-contract-001.json';write_new(target,contract)
    profile['profile_version']=2
    profile['source_evidence'] += [pin(old),pin(target)]+[pin(ROOT/row['path']) for row in evidence]+ordinary
    profile['layout_dependencies'].append(pin(ROOT/'bridge/information/country_territory_memory.py'))
    profile['semantics']['supported_fields'].append('F01.territory')
    profile['semantics']['territory']='native num_of_cities cache only; not complete owned province census'
    profile['semantics']['unimplemented_fields']=['F01.wars']
    output=ROOT/'bridge/information/profiles/country-scale-memory-1374-v2.json'
    write_new(output,profile)
    receipt={'status':'created','profile':pin(output),'contract':pin(target),'original_profile':pin(old),
        'builder':pin(Path(__file__).resolve()),'guards':len(profile['code_guards']),
        'guard_bytes':sum(len(bytes.fromhex(row['bytes'])) for row in profile['code_guards']),
        'game_access':False,'native_queries_repeated':False}
    write_new(STAGE/'country-territory-profile-build-001.json',receipt);print(receipt)


if __name__=='__main__':main()
