"""Exact current-pending to A04 lookup, with bounded log and graceful failures."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import struct

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.native_pending_links import match_current_proposals
from bridge.information import InformationService
from bridge.information import native_pending_memory as native
from bridge.information.composite import CompositeSource
from bridge.information.pending_matters import JournalPendingMattersSource
from bridge.information.presentation import present_concise, present_result
from bridge.information.tools import InformationTools
from bridge.tests.test_information_native_pending_memory import _synthetic_memory, _capture, _MODULE_BASE
from bridge.tests.test_information_native_pending_source import setup
from bridge.tests.test_information_pending_matters import _query
from bridge.tests.test_information_proposal_expiry import NOW, SESSION, offer, session
from bridge.information.sources import DiplomacySource


def current_report(count=1):
    contract = native.load_contract()
    memory = _synthetic_memory(contract, [{'token': 19}] * count)
    memory['session_id'] = SESSION
    for index in range(count):
        address = 0x300000 + index * 0x100
        header = bytearray(memory['blocks'][address])
        struct.pack_into('<iii', header, 0x28, NOW - 96, NOW - 96, 3)
        memory['blocks'][address] = bytes(header)
    captured = _capture(memory, contract)
    snapshot = {**captured, 'game_date': NOW, 'player_country': 'POR',
                'roots': {'country_scan': {'country_handle': hex(memory['recipient_ref'])}}}
    return {'schema': native.SCHEMA, 'status': 'observed', 'country': 'FRA',
            'game_sha256': native.GAME_SHA256, 'profile_sha256': native.PROFILE_SHA256,
            'read_only': True, 'consistent': True, 'native_function_invoked': False,
            'target_memory_written': False, 'cleanup': {'closed': True},
            'identity': {'binding_verified': True, 'installation_session_id': SESSION},
            'module_base': {'va': hex(_MODULE_BASE), 'rva': None, 'rva_identity': 'runtime_va_or_heap'},
            'game_date': NOW, 'player_country': 'POR',
            'value': deepcopy(captured['value']), 'before': snapshot, 'after': deepcopy(snapshot)}


def records(observed):
    observed.read_native_inbound_offers()
    return deepcopy(observed._inbound_private_proposals)


def test_exact_native_pending_identity_resolves_one_public_id_without_mutation(tmp_path):
    observed = session(tmp_path, [offer()])
    report = current_report()
    original = deepcopy(report)
    originals = records(observed)
    entry_id = report['value']['entries'][0]['entry_id']
    assert match_current_proposals(report, originals, SESSION) == {entry_id: next(iter(originals))}
    assert report == original
    assert '0x' not in json.dumps(match_current_proposals(report, originals, SESSION))


@pytest.mark.parametrize('key', ['date28', 'date2c', 'created2c', 'envoy30', 'proposal3c', 'token3c'])
def test_same_parties_with_a_different_pending_identity_do_not_link(tmp_path, key):
    observed = session(tmp_path, [offer()])
    originals = records(observed)
    next(iter(originals.values()))['payload'][key] += 1
    assert match_current_proposals(current_report(), originals, SESSION) == {}


@pytest.mark.parametrize('damage', ['actor', 'recipient', 'family', 'session'])
def test_cross_party_family_or_session_records_do_not_link(tmp_path, damage):
    observed = session(tmp_path, [offer()])
    originals = records(observed)
    record = next(iter(originals.values()))
    if damage in ('actor', 'recipient'):
        record['payload'][damage] = 'ENG'
    elif damage == 'family':
        record['public']['action_id'] = 'ask_military_access'
    else:
        record['session_id'] = 'other-session'
    assert match_current_proposals(current_report(), originals, SESSION) == {}


def test_ambiguous_originals_and_duplicate_current_entries_are_unlinked(tmp_path):
    observed = session(tmp_path, [offer()])
    originals = records(observed)
    assert match_current_proposals(current_report(2), originals, SESSION) == {}
    duplicate = deepcopy(next(iter(originals.values())))
    duplicate['public']['proposal_id'] = 'f' * 32
    originals['f' * 32] = duplicate
    assert match_current_proposals(current_report(), originals, SESSION) == {}


@pytest.mark.parametrize('damage', ['session', 'profile', 'binding', 'close', 'write', 'date', 'header', 'entry', 'base', 'token_zero'])
def test_invalid_snapshot_diagnostics_cannot_produce_a_link(tmp_path, damage):
    observed = session(tmp_path, [offer()])
    report = current_report()
    if damage == 'session':
        report['identity']['installation_session_id'] = 'other'
    elif damage == 'profile':
        report['profile_sha256'] = '0' * 64
    elif damage == 'binding':
        report['identity']['binding_verified'] = False
    elif damage == 'close':
        report['cleanup']['closed'] = False
    elif damage == 'write':
        report['target_memory_written'] = True
    elif damage == 'date':
        report['game_date'] += 24
    elif damage == 'header':
        report['before']['private']['nodes'][0]['header_hex'] = '00' * 4096
        report['after'] = deepcopy(report['before'])
    elif damage == 'entry':
        report['value']['entries'][0]['entry_id'] = 'pending-entry-' + '0' * 32
        report['before']['value'] = deepcopy(report['value'])
        report['after'] = deepcopy(report['before'])
    elif damage == 'base':
        report['module_base']['va'] = hex(_MODULE_BASE + 0x10000)
    else:
        node = report['before']['private']['nodes'][0]
        header = bytearray.fromhex(node['header_hex'])
        struct.pack_into('<i', header, 0x3c, 0)
        node['header_hex'] = header.hex()
        raw_identity = SESSION.encode() + struct.pack('<QQ', int(node['node'], 0), int(node['clone'], 0)) + header
        report['value']['entries'][0]['entry_id'] = 'pending-entry-' + hashlib.sha256(raw_identity).hexdigest()[:32]
        report['before']['value'] = deepcopy(report['value'])
        report['after'] = deepcopy(report['before'])
    with pytest.raises(ValueError):
        match_current_proposals(report, records(observed), SESSION)


def test_session_links_only_after_the_existing_reader_reaches_its_log_boundary(tmp_path, monkeypatch):
    observed = session(tmp_path, [offer()])
    with monkeypatch.context() as patch:
        patch.setattr('bridge.diplomacy._RESPONSE_LOG_SCAN_BYTES', 128)
        with pytest.raises(ValueError, match='NATIVE_PENDING_PROPOSAL_LOG_NOT_CAUGHT_UP'):
            observed.link_native_pending_proposals(current_report())
    assert len(observed.link_native_pending_proposals(current_report())) == 1


@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_current_c03_lookup_supplies_a_working_a04_query_parameter(tmp_path, detail):
    observed = session(tmp_path, [offer()])
    report = current_report()
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        primary = DiplomacySource(DiplomacyTools(journal, observed))
        pending = JournalPendingMattersSource(primary, native_pending=True, pending_capture=lambda *_args: deepcopy(report))
        source = CompositeSource(primary, [pending])
        database = tmp_path / 'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            current_query = {'topic': 'C03', 'object': {'type': 'session'},
                             'fields': ['pending_matters'], 'parameters': {}}
            configured = tools.call('information_manage_report', {
                'request_id': 'current-report', 'operation': 'create',
                'config': {'name': 'Current proposal lookup', 'detail': detail, 'queries': [current_query]},
            })['report']
            current = tools.call('information_query', {
                'request_id': 'current-query', 'report_id': configured['id']})
            current_full = service.get_result(current['result_id'])
            assert current_full['items'][0]['fields']['pending_matters']['status'] == 'known', current_full
            queue = current_full['items'][0]['fields']['pending_matters']['value']['native_inbound_pending']
            assert native.validate_value(queue['value']) == report['value']
            lookup = current_full['items'][0]['source']['proposal_lookup']
            assert lookup['status'] == 'known' and lookup['response_authority'] is False
            public_id = lookup['links'][0]['proposal_id']
            selected = tools.call('information_query', {'request_id': 'selected-query', 'queries': [{
                'topic': 'A04', 'object': {'type': 'session'}, 'fields': ['proposal_id', 'actor', 'deadline'],
                'parameters': {'proposal_id': public_id},
            }]})
            selected_full = service.get_result(selected['result_id'])
            fields = selected_full['items'][0]['fields']
            assert fields['proposal_id']['value'] == public_id
            assert fields['actor']['value'] == 'SAV'
            assert fields['deadline']['value'] == NOW - 24
        with closing(InformationService(source, database)) as reopened:
            full = InformationTools(reopened).call('information_get_result', {
                'result_id': current['result_id'], 'view': 'full'})
            report_view = present_result(full) if detail == 'brief' else full
            assert present_concise(report_view) == current


@pytest.mark.parametrize('mode', ['error', 'private_id', 'foreign_entry', 'duplicate_id'])
def test_lookup_failures_preserve_the_valid_current_inventory(setup, mode):
    source, base, state, _journal = setup
    state['count'] = 1

    def link(_report):
        if mode == 'error':
            raise OSError('private-source-path')
        if mode == 'private_id':
            return {'pending-entry-' + 'a' * 32: 'private-token'}
        if mode == 'foreign_entry':
            return {'pending-entry-' + 'b' * 32: 'c' * 32}
        return {'pending-entry-' + 'a' * 32: 'c' * 32,
                'pending-entry-' + 'b' * 32: 'c' * 32}

    base.diplomacy_tools.session.link_native_pending_proposals = link
    result = source.read(_query(), base.context())
    queue = result['fields']['pending_matters']['value']['native_inbound_pending']
    assert queue['status'] == 'known' and queue['value']['native_queue_count'] == 1
    assert result['source']['proposal_lookup']['status'] == 'unknown'
    assert 'private-' not in json.dumps(result)


def test_lookup_availability_alone_does_not_change_the_current_queue_comparison(setup):
    source, base, state, _journal = setup
    state['count'] = 1
    first = source.read(_query(), base.context())
    base.diplomacy_tools.session.link_native_pending_proposals = lambda _report: {'pending-entry-' + 'a' * 32: 'c' * 32}
    second = source.read(_query(), base.context())
    assert first['fields'] == second['fields']
    assert first['source']['proposal_lookup'] != second['source']['proposal_lookup']
    assert source.change_comparison(_query(), first, base.context()) == source.change_comparison(_query(), second, base.context())
