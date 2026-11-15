"""Public F02 projection against deterministic, fully replayed RPM traces."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.foreign_technology import NativeForeignTechnologySource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests.test_information_foreign_technology_capture import make_valid_capture


class Base:
    event_types=()

    def __init__(self,directory,context,creation):
        self.current=deepcopy(context)
        self.current.update(status='ready',mode='live',complete=True)
        self.session=SimpleNamespace(directory=directory,creation_filetime=creation,
            record={'session_id':context['session_id'],'creation_filetime':creation})

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self,query,context):
        return {'fields':{field:{'status':'unsupported','reason':'PRIMARY_UNUSED'} for field in query['fields']},
                'complete':False,'source':{'name':'fixture_primary','mode':'live'}}


def query(fields=None):
    return {'topic':'F02','object':{'type':'country','country':'ENG'},
            'fields':fields or ['military_technology','visibility'],'parameters':{}}


def make_source(tmp_path,*,admitted=True,physical_tag='POR',human_fra=False):
    report,context,creation,fixture=make_valid_capture(admitted=admitted,
        physical_tag=physical_tag,human_fra=human_fra)
    base=Base(tmp_path,context,creation)
    calls=[]
    def capture(installation,*,country,observer):
        calls.append((installation,country,observer))
        return deepcopy(report)
    adapter=NativeForeignTechnologySource(base,capture=capture)
    return adapter,base,report,calls,fixture


def test_foreign_target_and_observer_are_distinct_and_only_public_values_escape(tmp_path):
    adapter,base,report,calls,_=make_source(tmp_path)
    result=adapter.read(query(),base.context())
    field=result['fields']['military_technology']
    assert field['status']=='known'
    assert field['value']==report['observation']['backend']['targets'][0]['technology']['value']
    assert field['unit']=='technology_level' and field['scale']==1
    assert result['complete'] is False and field['partial'] is True
    visibility=result['fields']['visibility']['value']
    assert visibility['military_technology']=={'admitted':True,'observer':'FRA','target':'ENG',
        'actual_UI_observed':False,'projected_observer_view':True}
    assert visibility['other_F02_fields']['status']=='unknown'
    assert calls==[(tmp_path/'installation.json','ENG','FRA')]
    text=repr(result)
    for private_key in ('raw_operands','country_pointer','table_entry','raw_reads','world_pointer'):
        assert private_key not in text


def test_rejected_admission_never_exports_raw_technology_even_if_backend_has_it(tmp_path):
    adapter,base,report,_,_=make_source(tmp_path,admitted=False)
    assert type(report['observation']['backend']['targets'][0]['technology']['value']) is int
    result=adapter.read(query(),base.context())
    assert result['fields']['military_technology']['status']=='invisible'
    assert 'value' not in result['fields']['military_technology']
    assert 'raw_hex' not in result['fields']['military_technology']
    assert result['fields']['visibility']['value']['military_technology']['admitted'] is False


@pytest.mark.parametrize('physical_tag',['POR','FRA'])
def test_view_reference_does_not_replace_the_logical_nonplayer_observer(tmp_path,physical_tag):
    adapter,base,_,_,_=make_source(tmp_path,physical_tag=physical_tag)
    result=adapter.read(query(),base.context())
    assert result['fields']['military_technology']['status']=='known'
    assert result['source']['provenance']['observer']=='FRA'


def test_human_controlled_fra_is_retracted(tmp_path):
    adapter,base,_,_,_=make_source(tmp_path,human_fra=True)
    result=adapter.read(query(),base.context())
    assert all(field['status']=='unknown' and 'value' not in field for field in result['fields'].values())


def test_forged_technology_value_is_rejected_by_trace_replay(tmp_path):
    adapter,base,report,_,_=make_source(tmp_path)
    report['observation']['backend']['targets'][0]['technology']['value']+=1
    result=adapter.read(query(),base.context())
    assert result['fields']['military_technology']=={'status':'unknown','reason':'FOREIGN_TECH_CAPTURE_INVALID'}


@pytest.mark.parametrize('obj,fields',[
    ({'type':'country','country':'FRA'},['military_technology']),
    ({'type':'country','country':'bad'},['military_technology']),
    ({'type':'country','country':'ENG','address':'0x10000'},['military_technology']),
    ({'type':'country','country':'ENG'},['unrecognized_quality']),
    ({'type':'country','country':'ENG'},[{}]),
])
def test_bad_foreign_selectors_do_not_capture(tmp_path,obj,fields):
    adapter,base,_,calls,_=make_source(tmp_path)
    with pytest.raises(InformationError):
        adapter.read({'topic':'F02','object':obj,'fields':fields,'parameters':{}},base.context())
    assert calls==[]


def test_query_and_saved_report_share_partial_projection_and_foreign_schema(tmp_path):
    adapter,base,_,_,_=make_source(tmp_path)
    source=CompositeSource(base,[adapter])
    service=InformationService(source,tmp_path/'information.sqlite3')
    tools=InformationTools(service)
    try:
        catalog=next(item for item in source.catalog() if item['topic_id']=='F02')
        assert catalog['fields']['military_technology']['coverage']=='partial'
        assert catalog['fields']['visibility']['coverage']=='partial'
        assert catalog['fields']['visible_army']['coverage']=='partial'
        direct=tools.call('information_query',{"view": "full", 'request_id':'foreign-query','queries':[query()]})
        report=tools.call('information_manage_report',{'request_id':'foreign-report','operation':'create',
            'config':{'name':'foreign technology','detail':'raw','queries':[query()]}})['report']
        rendered=tools.call('information_query',{"view": "full", 'request_id':'foreign-render','report_id':report['id']})
        assert direct['items'][0]['fields']==rendered['items'][0]['fields']
        assert direct['items'][0]['fields']['military_technology']['status']=='known'
        assert direct['complete'] is False
    finally:
        service.close()
