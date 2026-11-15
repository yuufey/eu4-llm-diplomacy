"""The isolated public projection must not release unadmitted private data."""
from copy import deepcopy
import pytest
from bridge.information import province_permanent_claim_capture as capture


def packet(tags):
    gate={'status':'known','admitted':True,'observer_nonplayer_role':{'verified':True}}
    discovery={'status':'known','value':True}
    target={'fields':{'G01.permanent_claims':{'status':'known','value':tags}},
        'admission_by_pass':{'pass1':deepcopy(gate),'pass2':deepcopy(gate)},
        'discovery_by_pass':{'pass1':deepcopy(discovery),'pass2':deepcopy(discovery)}}
    return {'capture':{'observation':{'backend':{'observer':{'tag':'FRA'},'targets':[target]}}}}


@pytest.mark.parametrize('tags',[[],['ORL','BUR']])
def test_project_only_the_admitted_permanent_member_list(tags):
    field=capture.project_fields(packet(tags))['permanent_claims']
    assert field['status']=='known' and field['value']==sorted(tags)
    assert field['basis']=='native_permanent_claim_predicate_after_positive_actor_discovery'
    assert field['value_origin']=='derived_from_copied_native_claim_and_history_records'
    assert field['complete'] is False and field['partial'] is True


@pytest.mark.parametrize('tags',[['BUR','BUR'],['bad'],[False]])
def test_bad_private_members_are_not_promoted(tags):
    field=capture.project_fields(packet(tags))['permanent_claims']
    assert field['status']=='unknown' and 'value' not in field


@pytest.mark.parametrize('phase',['pass1','pass2'])
@pytest.mark.parametrize('failed_gate',['role','discovery','admission'])
def test_both_passes_need_their_own_positive_gate(phase,failed_gate):
    value=packet(['BUR'])
    target=value['capture']['observation']['backend']['targets'][0]
    if failed_gate=='role':target['admission_by_pass'][phase]['observer_nonplayer_role']['verified']=False
    elif failed_gate=='discovery':target['discovery_by_pass'][phase]['value']=False
    else:target['admission_by_pass'][phase]['admitted']=False
    with pytest.raises(ValueError,match='PUBLICATION_GATE'):
        capture.project_fields(value)
