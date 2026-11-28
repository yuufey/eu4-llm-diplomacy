from bridge.information import country_discovery_memory as memory
from bridge.information import country_reference_memory as countries
from bridge.information import province_reference_memory as provinces
from bridge.tests.test_information_province_discovery_memory_v2 import make_image as province_image
from bridge.tests.test_information_province_state_memory import BASES, RECORDS, WORLD, _fullref

BASE=BASES[0]


def make_image(values=(True,False,True)):
    image=province_image(values)
    scan=countries.resolve_countries(image.read,BASE,['FRA','ENG','SWE','DEN'])
    bindings=scan['requested']
    for tag,pid in [('FRA',1),('ENG',2),('SWE',3),('DEN',1)]:
        pointer=int(bindings[tag]['country_pointer'],16)
        image.put_u64(pointer+0x14b0,RECORDS+pid*provinces.RECORD_STRIDE)
    for pid in range(1,4):image.put(RECORDS+pid*provinces.RECORD_STRIDE+0x959,b'\x10')
    image.reads.clear()
    return image,bindings


def test_observer_knows_only_positive_candidates_and_context_stays_nonplayer():
    image,_=make_image()
    result=memory.read_two_pass(image,BASE)
    assert result['status']=='known' and result['value']==['DEN','FRA','SWE']
    assert result['scope']['candidate_count']==4 and result['scope']['country_table_count']==12
    assert result['scope']['country_existence_filter_applied'] is False
    assert result['domain_complete'] is False and result['complete'] is False
    assert all(row['admission']['observer_nonplayer_role']['verified'] for row in result['passes'])
    assert not any(label.startswith('country_knowledge.') and ('owner' in label or 'controller' in label)
                   for _,_,label in image.reads)


def test_known_empty_does_not_mean_unknown_or_missing_capital():
    image,_=make_image((False,False,False))
    result=memory.read_two_pass(image,BASE)
    assert result['status']=='known' and result['value']==[]
    image,bindings=make_image((False,False,False))
    image.put_u64(int(bindings['ENG']['country_pointer'],16)+0x14b0,0)
    result=memory.read_two_pass(image,BASE)
    assert result['status']=='unknown' and 'value' not in result
    assert result['reason']=='COUNTRY_KNOWLEDGE_UNKNOWN'


def test_native_shortcut_can_use_index_zero_without_claiming_map_zero_semantics():
    image,bindings=make_image()
    image.put_u64(int(bindings['DEN']['country_pointer'],16)+0x14b0,RECORDS)
    image.put_i32(RECORDS+0x20,0);image.put(RECORDS+0x959,b'\0')
    result=memory.read_two_pass(image,BASE)
    assert result['status']=='known' and 'DEN' in result['value']
    assert result['domain_complete'] is False


def test_human_count_does_not_deny_bound_observer_discovery():
    image,_=make_image();image.put_i32(WORLD+0xa60,2)
    result=memory.read_two_pass(image,BASE)
    assert result['status']=='known' and result['value']==['DEN','FRA','SWE']
    assert all(not row['admission']['observer_nonplayer_role']['verified'] for row in result['passes'])


def test_wrong_fullref_slot_in_an_unrequested_country_withdraws_the_whole_list():
    image,bindings=make_image()
    image.put_u64(int(bindings['SWE']['country_pointer'],16)+0x20,_fullref('SWE',7))
    result=memory.read_two_pass(image,BASE)
    assert result['status']=='unknown' and result['reason']=='COUNTRY_CANDIDATE_SLOT_MISMATCH'


def test_shortcut_transition_with_unchanged_boolean_is_still_evidence_drift():
    image,_=make_image();changed=False

    def read(address,size,label):
        nonlocal changed
        raw=image.read(address,size,label)
        if not changed and label=='province_bitmap.word_u32':
            image.put(RECORDS+provinces.RECORD_STRIDE+0x959,b'\0');changed=True
        return raw

    result=memory.read_two_pass(read,BASE)
    assert result['status']=='unknown' and result['reason']=='TWO_PASS_EVIDENCE_CHANGED'
    assert result['consistency']['changed_components']==['candidates']


def test_invalid_observer_or_module_is_read_free():
    image,_=make_image()
    assert memory.read_two_pass(image,BASE,observer='POR')['status']=='unknown'
    assert memory.read_two_pass(image,True)['status']=='unknown'
    assert not image.reads
