"""Keep confirmed-load initialization outside native macro delivery."""
import json

import pytest

from bridge.diplomacy import ObserverSession
from bridge import country_modifier_observation as modifiers
from bridge.tests.test_information_country_modifier_events import make_session,SESSION_ID,native_event
from bridge.tests.test_information_alliance_record_events import record_ack,relation_record
from bridge.tests.test_information_mission_availability_events import available
from bridge.tests.test_information_mission_set_events import inserted
from bridge.tests.test_information_rival_events import rival
from bridge.tests.test_information_war_declaration_events import declaration

MARKER={'event':'control_loaded_pause_requested'}

def startup_session(directory,events=(),reason='verified_load_confirmation'):
    original=make_session(directory,events,ack=record_ack())
    installation=original.directory/'installation.json'
    record=json.loads(installation.read_text())
    record['ready_reason']=reason
    installation.write_text(json.dumps(record))
    return ObserverSession(installation,original.game_exe)

def append(session,*events):
    with (session.directory/'control-probe.jsonl').open('a') as stream:
        for event in events:
            stream.write(json.dumps(event)+'\n')

@pytest.mark.parametrize('event,method,prefix',[
    (native_event(),'read_native_country_modifier_events','COUNTRY_MODIFIER'),
    (native_event(event=modifiers.REMOVE_NATIVE_EVENT,source=modifiers.REMOVE_SOURCE),
        'read_native_country_modifier_events','COUNTRY_MODIFIER'),
    (native_event(event=modifiers.EXPIRY_NATIVE_EVENT,source=modifiers.EXPIRY_SOURCE,end_date_raw=56658312),
        'read_native_country_modifier_events','COUNTRY_MODIFIER'),
    (rival(),'read_native_rival_events','RIVAL'),
    (declaration(),'read_native_war_declaration_events','WAR_DECLARATION'),
    (relation_record(1,'alliance_record_disable',before=True,after=False),'read_native_relation_events','RELATION'),
    (inserted(1),'read_native_mission_events','MISSION'),
    (available(1),'read_native_mission_availability_events','MISSION_AVAILABILITY'),
])
def test_confirmed_load_waits_for_bound_marker_without_expiring_old_dates(tmp_path,event,method,prefix):
    session=startup_session(tmp_path,[event])
    pending=getattr(session,method)()
    assert pending['events']==[]
    assert prefix+'_STARTUP_CAPTURE_PENDING' in pending['gaps']
    # The world may keep its date during loading. The boundary is explicit,
    # independent of the event date or the delay before consuming the log.
    accepted=dict(event,sequence=2)
    append(session,MARKER,accepted)
    result=getattr(session,method)()
    assert result['complete'] and len(result['events'])==1
    assert result['events'][0]['native_sequence']==2
    assert result['events'][0]['game_date']==event['date_raw']
    fresh=ObserverSession(session.directory/'installation.json',session.game_exe)
    assert getattr(fresh,method)()==result

def test_foreign_or_modified_marker_does_not_open_capture(tmp_path):
    event=relation_record(1,'alliance_record_enable')
    session=startup_session(tmp_path,[dict(MARKER,session_id=SESSION_ID),event])
    assert session.read_native_relation_events()['events']==[]
    append(session,record_ack(session_id='foreign'),MARKER,dict(event,sequence=2))
    assert session.read_native_relation_events()['events']==[]
    append(session,record_ack(),MARKER,dict(event,sequence=3))
    batch=session.read_native_relation_events()
    assert batch['complete'] and [row['native_sequence'] for row in batch['events']]==[3]

def test_loaded_world_install_keeps_existing_delivery(tmp_path):
    event=relation_record(1,'alliance_record_enable')
    session=startup_session(tmp_path,[event],reason='loaded_world')
    assert len(session.read_native_relation_events()['events'])==1

def test_configured_modifier_startup_sequence_is_not_reported_as_a_gap(tmp_path):
    from bridge.tests.test_information_rival_record_events import record_ack as scoped_ack

    ack = scoped_ack(version=65, session_id=SESSION_ID, observer='SWE',
        native_country_control_configuration=True,
        native_country_control_protocol='EU4CONTROL1', native_country_control_ack='native_controlled_countries_set',
        native_country_control_request='controlled-countries.req', native_information_observer_configuration=True,
        native_country_modifier_scoped_schema=2)
    reference = (42 << 32) | int.from_bytes(b'SWE', 'little')
    first = native_event(schema_version=2, country='SWE', country_fullref=hex(reference))
    original = make_session(tmp_path, [first], ack=ack, observer='SWE')
    installation = original.directory / 'installation.json'
    record = json.loads(installation.read_text())
    record['ready_reason'] = 'verified_load_confirmation'
    installation.write_text(json.dumps(record))
    session = ObserverSession(installation, original.game_exe)
    assert session.read_native_country_modifier_events()['events'] == []
    append(session, MARKER, dict(first, sequence=2))
    result = session.read_native_country_modifier_events()
    assert result['complete']
    assert [event['native_sequence'] for event in result['events']] == [2]

def test_log_reset_requires_a_new_current_session_marker(tmp_path):
    event=relation_record(1,'alliance_record_enable')
    session=startup_session(tmp_path,[MARKER,event])
    assert session.read_native_relation_events()['complete']
    (session.directory/'control-probe.jsonl').write_text(json.dumps(record_ack())+'\n')
    pending=session.read_native_relation_events()
    assert 'RELATION_STARTUP_CAPTURE_PENDING' in pending['gaps']
    append(session,MARKER,dict(event,sequence=2))
    batch=session.read_native_relation_events()
    assert 'RELATION_STARTUP_CAPTURE_PENDING' not in batch['gaps']
    assert 'RELATION_LOG_RESET' in batch['gaps']
