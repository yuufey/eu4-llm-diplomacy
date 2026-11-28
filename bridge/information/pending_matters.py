"""Read scoped journal obligations and an optional native pending-list inventory."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from bridge.diplomacy_journal import REQUEST_STATES, _TERMINAL_STATES
from .catalog import get_topic, validate_query, _validate_schema
from .model import InformationError, digest
from .observation_time import context_identity, dates_match
from .sources import _result, _source_info

MAX_PAGE = 128
MAX_PAYLOAD_BYTES = 65536
_IDENTITY = ('mode', 'observer', 'session_id', 'game_sha256', 'game_version', 'game_date')
_PARAMETERS = {'type': 'object', 'properties': {
    'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_PAGE},
    'after_request_id': {'type': 'string', 'pattern': r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'},
}, 'additionalProperties': False}
_GAPS = ['CONFIGURED_JOURNAL_ONLY', 'VALIDATED_OBSERVER_ACTOR_RECORDS_ONLY',
         'NATIVE_PENDING_OFFER_SET_NOT_VERIFIED', 'NO_EXECUTION_OR_RETRY_AUTHORIZATION']
_STATES = tuple(sorted(set(REQUEST_STATES)-set(_TERMINAL_STATES)))


def _identity(context):
    return context_identity(context, _IDENTITY) if isinstance(context, dict) else None


def _ready(context):
    return (isinstance(context, dict) and context.get('status') == 'ready'
            and context.get('mode') == 'live'
            and context.get('game_version') == '1.37.4'
            and isinstance(context.get('observer'), str)
            and re.fullmatch(r'[A-Z0-9]{3}', context['observer']) is not None
            and isinstance(context.get('session_id'), str) and bool(context['session_id'])
            and type(context.get('game_date')) is int)


def _page(journal, context, experiment, limit, after):
    """SELECT only summary columns under the journal owner's lock.

    list_requests() is intentionally not used: it loads unbounded records and
    complete result/receipt bodies. Dedicated evidence/token/receipt columns are
    not read; payload bytes are verified and reduced to a public whitelist.
    """
    if (journal.session_id != context['session_id'] or journal.experiment_id != experiment):
        raise ValueError('PENDING_JOURNAL_SCOPE_MISMATCH')
    scope = (experiment, context['session_id'], context['observer'])
    actor_clause = "CASE WHEN json_valid(payload_json) THEN json_extract(payload_json,'$.actor') ELSE NULL END = ?"
    with journal._lock:
        connection = journal._connection
        if connection is None:
            raise ValueError('PENDING_JOURNAL_CLOSED')
        anchor = None
        if after is not None:
            anchor = connection.execute(
                'SELECT created_at,request_id FROM diplomacy_requests '
                'WHERE experiment_id=? AND session_id=? AND '+actor_clause+' AND request_id=?',
                (*scope, after)).fetchone()
            if anchor is None:
                raise ValueError('PENDING_CURSOR_NOT_AVAILABLE_IN_SCOPE')
        sql = ('SELECT request_id,status,created_at,updated_at,submitted_at,claimed_at,'
               '(submission_id IS NOT NULL) AS has_submission_claim,payload_sha256,'
               'substr(CAST(payload_json AS BLOB),1,?) AS payload_bytes '
               'FROM diplomacy_requests WHERE experiment_id=? AND session_id=? AND '+actor_clause+
               ' AND status IN ('+','.join('?' for _ in _STATES)+')')
        args = [MAX_PAYLOAD_BYTES+1, *scope, *_STATES]
        if anchor is not None:
            sql += ' AND (created_at>? OR (created_at=? AND request_id>?))'
            args.extend((anchor['created_at'], anchor['created_at'], anchor['request_id']))
        rows = connection.execute(sql+' ORDER BY created_at,request_id LIMIT ?', (*args, limit+1)).fetchall()
    has_more = len(rows) > limit
    items = []
    for row in rows[:limit]:
        raw = row['payload_bytes']
        if not isinstance(raw, bytes) or len(raw) > MAX_PAYLOAD_BYTES:
            raise ValueError('PENDING_JOURNAL_PAYLOAD_TOO_LARGE')
        if hashlib.sha256(raw).hexdigest() != row['payload_sha256']:
            raise ValueError('PENDING_JOURNAL_PAYLOAD_HASH_MISMATCH')
        payload = json.loads(raw.decode('utf-8'))
        if not isinstance(payload, dict) or payload.get('actor') != context['observer']:
            raise ValueError('PENDING_JOURNAL_ACTOR_UNVERIFIED')
        action, recipient, phase = (payload.get(key) for key in ('action_id', 'recipient', 'phase'))
        if ((action is not None and (not isinstance(action, str)
                                     or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', action) is None))
                or (recipient is not None and (not isinstance(recipient, str)
                                              or re.fullmatch(r'[A-Z0-9]{3}', recipient) is None))
                or (phase is not None and (not isinstance(phase, str) or not 1 <= len(phase) <= 32))):
            raise ValueError('PENDING_JOURNAL_PUBLIC_SUMMARY_INVALID')
        state = row['status']
        claimed = bool(row['has_submission_claim'])
        review = ('recorded_waiting_response' if state == 'waiting_response' else
                  'requires_reconciliation' if claimed or state in {'submitted', 'executing', 'unknown'} else
                  'local_workflow_incomplete')
        items.append({'request_id': row['request_id'], 'status': state,
            'action_id': action, 'actor': payload['actor'],
            'recipient': recipient, 'phase': phase,
            'submitted': row['submitted_at'] is not None, 'updated_at': row['updated_at'],
            'has_submission_claim': claimed, 'claimed_at': row['claimed_at'],
            'review_kind': review, 'native_pending_confirmed': False})
    return {'scope': {'experiment_id': experiment, 'session_id': context['session_id'],
                      'observer': context['observer']},
        'journal_requests': items,
        'pagination': {'returned': len(items), 'has_more': has_more,
                       'next_after_request_id': items[-1]['request_id'] if has_more and items else None},
        'native_inbound_pending': {'status': 'unknown', 'reason': 'CURRENT_NATIVE_PENDING_SET_NOT_VERIFIED'},
        'action_authorization': 'none_from_information_query'}


class JournalPendingMattersSource:
    event_types = ()

    def __init__(self, base_source, *, native_pending=False, pending_capture=None):
        if type(native_pending) is not bool or (pending_capture is not None and not callable(pending_capture)):
            raise ValueError('Invalid native pending capture configuration')
        self.base_source = base_source
        self.native_pending = native_pending
        self.pending_capture = pending_capture

    def context(self):
        return deepcopy(self.base_source.context())

    def _gaps(self):
        if self.native_pending:
            return ['CONFIGURED_JOURNAL_ACTOR_RECORDS_ONLY', 'RECIPIENT_NATIVE_PENDING_LIST_ONLY',
                    'OTHER_NATIVE_PENDING_CHANNELS_NOT_ENUMERATED', 'NATIVE_PENDING_PAYLOADS_NOT_PROJECTED',
                    'NO_EXECUTION_OR_RETRY_AUTHORIZATION']
        return list(_GAPS)

    def catalog(self):
        topic = get_topic('C03')
        topic.update(status='available', source=type(self).__name__, object_types=['session'],
            supported_versions=['1.37.4'], visibility='country_scope', context_scope='country_scope',
            triggers=['query', 'periodic', 'change'], observer_roles=['country'],
            change_detection='sampled_configured_journal_page_comparison', parameters=deepcopy(_PARAMETERS))
        topic['fields'] = {'pending_matters': {'coverage': 'partial', 'complete': False,
            'source': type(self).__name__, 'unit': 'journal_review_request_page', 'scale': 1,
            'period': 'journal_current', 'basis': 'existing_scoped_DurableJournal_nonterminal_requests',
            'gaps': self._gaps(), 'description': '已绑定日志内本国未闭合请求及对账事项；不等同游戏当前待回应提议。'}}
        if self.native_pending:
            topic['fields']['pending_matters'].update(
                description='已绑定日志的复核事项及当前观察国收到的原生待处理队列。',
                basis='scoped_journal_page_and_recipient_owned_native_list',
                native_queue_scope='recipient_owned_native_pending_action_list',
                native_queue_deadline={
                    'scope': 'recognized_native_pending_entries',
                    'unit': 'game_date_raw', 'scale': 1,
                    'expiry_comparison': 'current_game_date > deadline.value',
                    'actual_expiry_time_inferred': False},
                native_queue_proposal_lookup={
                    'path': 'source.proposal_lookup.links',
                    'target_topic': 'A04', 'parameter': 'proposal_id',
                    'response_authority': False})
            topic['change_detection'] = 'sampled_scoped_journal_and_native_queue_comparison'
            topic['change_scope'] = {'fields': ['pending_matters'],
                'scope': 'configured_journal_page_and_observer_native_pending_list'}
        return [topic]

    def _read_native(self, context):
        from . import native_pending_memory as native
        unknown = {'status': 'unknown', 'reason': 'NATIVE_PENDING_CONTEXT_UNSUPPORTED'}
        proof = {'read_only': True, 'native_function_invoked': False, 'status': 'not_read'}
        observer = context.get('observer')
        if (not isinstance(observer, str) or re.fullmatch(r'[A-Z0-9]{3}', observer) is None
                or context.get('game_sha256') != native.GAME_SHA256):
            return unknown, proof
        try:
            session = getattr(getattr(self.base_source, 'diplomacy_tools', None), 'session', None)
            directory = getattr(session, 'directory', None)
            if directory is None:
                return dict(unknown, reason='NATIVE_PENDING_INSTALLATION_UNAVAILABLE'), proof
            capture = self.pending_capture or native.capture
            report = capture(Path(directory) / 'installation.json', observer)
            if not isinstance(report, dict):
                raise ValueError('NATIVE_PENDING_REPORT_INVALID')
            access = report.get('access', {})
            access_summary = {name: access[name] for name in ('rpm_bytes', 'rpm_calls', 'rpm_limit', 'open_process_mask')
                              if isinstance(access, dict) and type(access.get(name)) is int}
            proof.update(status=report.get('status'), profile_sha256=report.get('profile_sha256'),
                         consistent=report.get('consistent'), access=access_summary,
                         capture_report_sha256=digest(report))
            if report.get('status') != 'observed':
                reason = report.get('reason')
                if not isinstance(reason, str) or re.fullmatch(r'NATIVE_PENDING_[A-Z_]{1,100}', reason) is None:
                    reason = 'NATIVE_PENDING_CAPTURE_UNAVAILABLE'
                return dict(unknown, reason=reason), proof
            identity = report.get('identity', {})
            if (report.get('schema') != native.SCHEMA or report.get('country') != observer
                    or report.get('game_sha256') != native.GAME_SHA256
                    or report.get('profile_sha256') != native.PROFILE_SHA256
                    or report.get('read_only') is not True or report.get('native_function_invoked') is not False
                    or report.get('target_memory_written') is not False or report.get('consistent') is not True
                    or report.get('cleanup', {}).get('closed') is not True
                    or identity.get('binding_verified') is not True
                    or identity.get('installation_session_id') != context.get('session_id')
                    or not self._native_dates_match(report, context)
                    or not isinstance(report.get('player_country'), str)
                    or re.fullmatch(r'[A-Z0-9]{3}', report['player_country']) is None):
                return dict(unknown, reason='NATIVE_PENDING_REPORT_BINDING_UNVERIFIED'), proof
            value = native.validate_value(report.get('value'), observer=observer)
            proof.update(binding_verified=True, observed_game_date=report['game_date'],
                         player_country=report['player_country'])
            lookup = {'status': 'unknown', 'reason': 'NATIVE_PENDING_PROPOSAL_LOOKUP_UNAVAILABLE'}
            linker = getattr(session, 'link_native_pending_proposals', None)
            if callable(linker) and value['recognized_entry_count']:
                try:
                    links = linker(report)
                    entries = {entry['entry_id'] for entry in value['entries']
                               if entry['recognition'] == 'recognized'}
                    if (not isinstance(links, dict) or set(links) - entries
                            or any(not isinstance(item, str) or re.fullmatch(r'[0-9a-f]{32}', item) is None
                                   for item in links.values())
                            or len(set(links.values())) != len(links)):
                        raise ValueError('NATIVE_PENDING_PROPOSAL_LINKS_INVALID')
                    lookup = {'status': 'known', 'links': [
                        {'entry_id': entry_id, 'proposal_id': public_id} for entry_id, public_id in links.items()],
                        'response_authority': False}
                except Exception as exc:
                    proof['proposal_lookup_error_type'] = type(exc).__name__
            elif not value['recognized_entry_count']:
                lookup = {'status': 'known', 'links': [], 'response_authority': False}
            proof['proposal_lookup'] = lookup
            return {'status': 'known', 'value': value, 'unit': 'native_pending_list_entries',
                    'scale': 1, 'period': 'current', 'complete': False, 'partial': True,
                    'gaps': ['OTHER_PENDING_CHANNELS_NOT_ENUMERATED', 'ACTION_PAYLOADS_NOT_PROJECTED',
                             'INVENTORY_IDS_HAVE_NO_RESPONSE_AUTHORITY']}, proof
        except Exception as exc:
            proof['error_type'] = type(exc).__name__
            return dict(unknown, reason='NATIVE_PENDING_CAPTURE_OR_VALIDATION_FAILED'), proof

    @staticmethod
    def _native_dates_match(report, context):
        if type(report.get('game_date')) is not int:
            return False
        before, after = report.get('before'), report.get('after')
        if isinstance(before, dict) and isinstance(after, dict):
            before_date, after_date = before.get('game_date'), after.get('game_date')
            return (type(before_date) is int and type(after_date) is int
                    and report['game_date'] == before_date
                    and dates_match(context.get('game_date'), before_date, after_date))
        # Older injected capture seams do not expose pass snapshots. They stay
        # strict on the single date they do provide.
        return dates_match(context.get('game_date'), report['game_date'])

    def validate_query(self, query, context=None):
        if not isinstance(query, dict):
            raise InformationError('invalid_parameters', 'C03 query must be an object')
        parameters = query.get('parameters', {})
        _validate_schema(parameters, _PARAMETERS, 'parameters')
        normalized = validate_query(dict(query, parameters={}), context)
        if normalized['topic'] != 'C03' or normalized['object']['type'] != 'session':
            raise InformationError('invalid_object', 'Pending matters require a C03 session object')
        normalized['parameters'] = deepcopy(parameters)
        return normalized

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        try:
            before = self.context()
        except Exception:
            before = {}
        fields = {name: {'status': 'unsupported', 'reason': 'C03_FIELD_NOT_IMPLEMENTED'} for name in query['fields']}
        provenance = {'read_only': True, 'native_function_invoked': False,
                      'business_dispatch': False, 'journal_only': True, 'atomic_snapshot': False}
        proposal_lookup = None

        def result():
            source = _source_info(type(self).__name__, before, complete=False, provenance=provenance)
            if proposal_lookup is not None and fields.get('pending_matters', {}).get('status') == 'known':
                source['proposal_lookup'] = deepcopy(proposal_lookup)
            return _result(query, before, fields, False, source)

        if 'pending_matters' not in fields:
            return result()
        selected_session = query['object'].get('session_id', before.get('session_id'))
        if (not _ready(before) or selected_session != before.get('session_id')
                or (context is not None and _identity(context) != _identity(before))):
            fields['pending_matters'] = {'status': 'unavailable', 'reason': 'PENDING_CONTEXT_UNAVAILABLE_OR_MISMATCH'}
            return result()
        value, error = None, None
        try:
            tools = getattr(self.base_source, 'diplomacy_tools', None)
            journal = getattr(tools, 'journal', None)
            session = getattr(tools, 'session', None)
            experiment = getattr(session, 'experiment_id', None)
            if not experiment or journal is None:
                raise ValueError('PENDING_JOURNAL_BINDING_UNAVAILABLE')
            value = _page(journal, before, experiment, query['parameters'].get('limit', 64),
                          query['parameters'].get('after_request_id'))
            provenance['journal_page_sha256'] = digest(value)
            if self.native_pending:
                value['native_inbound_pending'], provenance['native_queue_capture'] = self._read_native(before)
                proposal_lookup = provenance['native_queue_capture'].pop('proposal_lookup', None)
                provenance['journal_only'] = False
        except Exception as exc:
            error = str(exc) if isinstance(exc, ValueError) else f'PENDING_JOURNAL_READ_FAILED:{type(exc).__name__}'
        try:
            after = self.context()
        except Exception:
            after = None
        anchor_date = context.get('game_date') if isinstance(context, dict) else before.get('game_date')
        if (not _ready(after) or _identity(before) != _identity(after)
                or not dates_match(anchor_date, before.get('game_date'), after.get('game_date'))):
            fields['pending_matters'] = {'status': 'unavailable', 'reason': 'PENDING_CONTEXT_CHANGED'}
        elif error is not None:
            fields['pending_matters'] = {'status': 'unknown', 'reason': error}
        else:
            fields['pending_matters'] = {'status': 'known', 'value': value, 'complete': False,
                'partial': True, 'unit': 'journal_review_request_page', 'scale': 1,
                'period': 'journal_current', 'gaps': self._gaps()}
        return result()

    def change_comparison(self, query, sample, context):
        if (not self.native_pending or query.get('topic') != 'C03'
                or query.get('fields') != ['pending_matters'] or not _ready(context)):
            return None
        fields = sample.get('fields', {})
        field = fields.get('pending_matters', {})
        value = field.get('value', {})
        native = value.get('native_inbound_pending', {})
        provenance = sample.get('source', {}).get('provenance', {})
        proof = provenance.get('native_queue_capture', {})
        scope = value.get('scope', {})
        if (set(fields) != {'pending_matters'} or field.get('status') != 'known'
                or native.get('status') != 'known' or proof.get('binding_verified') is not True
                or proof.get('consistent') is not True or provenance.get('journal_only') is not False
                or scope.get('session_id') != context.get('session_id')
                or scope.get('observer') != context.get('observer')):
            return None
        selection = {'journal_scope': scope, 'parameters': query.get('parameters', {}),
                     'native_profile': proof.get('profile_sha256')}
        return {'schema': 'information.change_comparison.v1',
                'scope': 'C03.pending_matters.v1.' + digest(selection), 'fields': deepcopy(fields)}

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
