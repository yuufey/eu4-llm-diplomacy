"""Version the domestic profile after the two optional record children."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information import domestic_pressure_memory as memory
from work.create_information_country_modifier_contract import pin,STAGE

def write(path,value):
    with path.open('x',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')

def main():
    old=memory.PROFILE_FILE
    assert old.name=='domestic-pressure-memory-1374-v5.json'
    before=memory._static_contract_guard()
    assert before['status']=='unknown'
    d=json.loads(old.read_text(encoding='utf-8'))
    helper=ROOT/'bridge/information/country_resources_memory.py'
    entry=next(x for x in d['provenance']['dependencies'] if x['path']==helper.relative_to(ROOT).as_posix())
    previous=dict(entry)
    entry.update(pin(helper))
    d['profile_version']=6
    d.setdefault('notes',[]).append('Batch52 adds optional current loan and direct modifier record children. Only the parent source dependency is rebound; native layouts, code guards and all other dependencies are unchanged.')
    target=old.with_name('domestic-pressure-memory-1374-v6.json')
    write(target,d)
    write(STAGE/'domestic-parent-dependency-update-001.json',dict(
        schema='information_domestic_parent_dependency_update.v2',old_profile=pin(old),
        new_profile=pin(target),before_guard=before,old_dependency=previous,new_dependency=pin(helper),
        native_layout_and_guards_changed=False,new_profile_enabled_at_receipt_creation=False))
    print(json.dumps(pin(target),ensure_ascii=False))

if __name__=='__main__':main()
