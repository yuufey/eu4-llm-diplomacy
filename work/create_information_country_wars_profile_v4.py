"""Preserve v3 and bind the corrected canonical-reference and JSON-safe leaf."""
from copy import deepcopy
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-country-wars-20261029-001'


def main():
    old=ROOT/'bridge/information/profiles/country-scale-memory-1374-v3.json'
    assert pin(old)['sha256']=='daa3f6f475569dfdf410406e0e001788ef3079b67d4960f0cfb059a43019abe1'
    profile=deepcopy(read_json(old));assert profile['profile_version']==3
    before=read_json(STAGE/'failed-private-v3-replay-before-fix-001.json')
    assert before['status']=='failed_saved_war_capture_replay'
    assert sum(x['strict_saved_capture_replay_passed'] for x in before['reports'])==1
    profile['profile_version']=4;profile['supersedes']=pin(old)
    dependencies=[pin(ROOT/row['path']) for row in profile['layout_dependencies']]
    changed=[row['path'] for row,new in zip(profile['layout_dependencies'],dependencies) if row!=new]
    assert changed==['bridge/information/country_wars_memory.py'],changed
    profile['layout_dependencies']=dependencies
    profile['source_evidence'] += [pin(old),pin(STAGE/'failed-private-v3-replay-before-fix-001.json'),
        pin(STAGE/'war-leaf-v3-before-reference-fix-001/snapshot-manifest.json')]
    profile['semantics']['corrections']=[
        'native_reference uses the helper canonical hex(pointer), independently of the creation-derived ID epoch',
        'all retained raw vector ranges are JSON lists so saved strict replay preserves types']
    output=ROOT/'bridge/information/profiles/country-scale-memory-1374-v4.json'
    write_new(output,profile)
    receipt={'status':'created','profile':pin(output),'original_profile':pin(old),
        'builder':pin(Path(__file__).resolve()),'changed_dependencies':changed,
        'native_layout_or_code_guards_changed':False,'resampled':False}
    write_new(STAGE/'country-wars-profile-build-002.json',receipt);print(receipt)


if __name__=='__main__':main()
