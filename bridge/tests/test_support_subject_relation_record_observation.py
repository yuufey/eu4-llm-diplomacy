"""Wire-5 role preservation, capability isolation, and retained snapshots."""
from copy import deepcopy
from itertools import product

import pytest

from bridge import relation_observation as observation
from bridge.tests.test_directed_relation_record_observation import (
    ROYAL_SESSION, _session_with_log, directed_ack, directed_record,
)
from bridge.tests.test_royal_relation_record_observation import snapshot


def support_subject_ack(**changes):
    value = directed_ack(version=60)
    value.update({
        'native_relation_change_wire': 5,
        'native_relation_change_scope': observation.SUPPORT_SUBJECT_RECORD_SCOPE,
        observation.SUPPORT_SUBJECT_RECORD_CAPABILITY: True,
    })
    value.update(changes)
    return value


def support_subject_record(**changes):
    value = directed_record(path='support_record_enable', kind='support_independence')
    value.update(schema_version=5, source=observation.SUPPORT_SUBJECT_RECORD_SOURCE)
    value.update(changes)
    return value


@pytest.mark.parametrize('kind,path,active', [
    ('support_independence', 'support_record_enable', False),
    ('support_independence', 'support_record_disable', True),
    ('subject', 'subject_record_enable', False),
    ('subject', 'subject_record_disable', True),
])
def test_new_paths_preserve_role_snapshots(kind, path, active):
    native = directed_record(path=path, kind=kind, before=active, after=not active)
    native.update(schema_version=5, source=observation.SUPPORT_SUBJECT_RECORD_SOURCE)
    result = observation.public_observation(native, ROYAL_SESSION)
    assert result is not None
    assert result['payload']['before'] == native['before']
    assert result['payload']['after'] == native['after']
    assert result['payload']['command_state'] is None
    assert result['payload']['command_mode'] is None
    assert result['payload']['scope'] == observation.SUPPORT_SUBJECT_RECORD_SCOPE


@pytest.mark.parametrize('capability', [
    observation.CAPABILITY, observation.RECORD_CAPABILITY, observation.ROYAL_RECORD_CAPABILITY,
    observation.DIRECTED_RECORD_CAPABILITY, observation.SUPPORT_SUBJECT_RECORD_CAPABILITY,
])
@pytest.mark.parametrize('invalid', [False, 1, None])
def test_v60_requires_complete_capability_chain(capability, invalid):
    good = support_subject_ack()
    assert observation.supported_support_subject_record_ack(good, observation.GAME_SHA256)
    good[capability] = invalid
    assert not observation.supported_ack(good, observation.GAME_SHA256)


@pytest.mark.parametrize('changes', [
    {'version': 59}, {'version': 61}, {'version': True},
    {'native_relation_change_wire': 4}, {'native_relation_change_wire': True},
    {'native_relation_change_scope': observation.DIRECTED_RECORD_SCOPE},
])
def test_v60_rejects_mixed_contracts(changes):
    assert not observation.supported_ack(support_subject_ack(**changes), observation.GAME_SHA256)


@pytest.mark.parametrize('changes', [
    {'schema_version': 4}, {'schema_version': True}, {'schema_version': 5.0},
    {'source': observation.DIRECTED_RECORD_SOURCE},
    {'observation_path': 'subject_record_enable'}, {'relation_kind': 'guarantee'},
    {'command_state': 0}, {'command_mode': False}, {'extra': 1},
])
def test_wire5_rejects_malformed_events(changes):
    assert observation.public_observation(support_subject_record(**changes), ROYAL_SESSION) is None


@pytest.mark.parametrize('flags', list(product((False, True), repeat=4)))
def test_collector_requires_all_four_flags(flags):
    collector = observation.Collector(ROYAL_SESSION)
    names = ('allow_record', 'allow_royal_record', 'allow_directed_record', 'allow_support_subject_record')
    collector.observe(support_subject_record(), **dict(zip(names, flags)))
    assert bool(collector.batch(0)['events']) is all(flags)


def test_capability_scope_requires_every_parent():
    full = {observation.CAPABILITY, observation.RECORD_CAPABILITY, observation.ROYAL_RECORD_CAPABILITY,
            observation.DIRECTED_RECORD_CAPABILITY, observation.SUPPORT_SUBJECT_RECORD_CAPABILITY}
    assert observation.scope_for_capabilities(full) == observation.SUPPORT_SUBJECT_RECORD_SCOPE
    for capability in full - {observation.SUPPORT_SUBJECT_RECORD_CAPABILITY}:
        assert observation.scope_for_capabilities(full - {capability}) is None


def test_session_derives_capability_and_rejects_untrusted_caps(tmp_path):
    session = _session_with_log(tmp_path / 'good', support_subject_ack(), [support_subject_record()])
    assert observation.SUPPORT_SUBJECT_RECORD_CAPABILITY in session.installation_capabilities()
    assert len(session.read_native_relation_events()['events']) == 1
    bad = support_subject_ack(**{observation.SUPPORT_SUBJECT_RECORD_CAPABILITY: False})
    bad['caps'] = [observation.SUPPORT_SUBJECT_RECORD_CAPABILITY]
    session = _session_with_log(tmp_path / 'bad', bad, [support_subject_record()])
    assert observation.SUPPORT_SUBJECT_RECORD_CAPABILITY not in session.installation_capabilities()
    assert not session.read_native_relation_events()['events']


def test_wire5_snapshot_and_previous_wire4_keep_their_identity():
    native = support_subject_record()
    archived = snapshot(native)
    previous = snapshot(directed_record())
    context = {'session_id': ROYAL_SESSION, 'observer': 'FRA', 'game_sha256': observation.GAME_SHA256}
    assert observation.valid_event_snapshot(archived, context)
    assert observation.valid_event_snapshot(previous, context)
    assert archived['event_id'] == previous['event_id']
    changed = deepcopy(archived)
    changed['payload']['scope'] = observation.DIRECTED_RECORD_SCOPE
    assert not observation.valid_event_snapshot(changed, context)
