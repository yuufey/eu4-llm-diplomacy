"""Correlate fixed-B23 pending-proposal end observations with verified offers."""
from copy import deepcopy
import hashlib
import json
import re

GAME_SHA256 = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
CAPABILITY = 'native_proposal_expiry_observation'
EXPIRY_RETURN_RVA = '0x2f04b9'
INACTIVE_RETURN_RVA = '0x3609ed'
RECHECK_RETURN_RVA = '0x36087a'
CLEAR_RETURN_RVA = '0x360940'
# These sites destroy an action held in country+0x18d8. Recheck and bulk
# clearing do not require state34==0. None identifies a sender withdrawal.
INACTIVE_RETURN_RVAS = (INACTIVE_RETURN_RVA, RECHECK_RETURN_RVA, CLEAR_RETURN_RVA)
MAX_PENDING = 128
# B23 evidence is retained in information-diplomacy-expiry-20261108-261-001.
ACTION_VTABLES = {
    'offer_alliance': (0x1c80720, 'alliance'),
    'offer_royal_marriage': (0x1c80ab0, 'royal_marriage'),
    'support_independence': (0x1c805f0, 'support_independence'),
    'ask_military_access': (0x1c7fb70, 'military_access'),
    'offer_vassalization': (0x1c7fd20, 'vassalization'),
    'trade_favors_for_gold': (0x1c80980, 'favor_trade'),
    'trade_favors_for_trust': (0x1c80c60, 'favor_trade'),
    'trade_favors_for_men': (0x1c80ff0, 'favor_trade'),
    'peace_offer': (0x1c7b840, 'peace'),
}
# These verified inbound families identify the whole proposal by action and
# country pair. Favor exchanges and peace offers carry additional terms even
# when their initiation API accepts no user-selected parameters.
PARAMETERLESS_ACTIONS = frozenset({
    'offer_alliance', 'offer_royal_marriage', 'support_independence',
    'ask_military_access', 'offer_vassalization',
})


def deadline_from_created_date(created):
    """Calculate the threshold after the caller verifies native pending ownership."""
    metadata = {'unit': 'game_date_raw', 'scale': 1, 'period': 'proposal'}
    if not _integer(created, 1, 2**31 - 73):
        return {**metadata, 'status': 'unknown',
                'reason': 'PROPOSAL_PENDING_CREATED_DATE_NOT_VERIFIED'}
    return {**metadata, 'status': 'known', 'value': created + 72,
            'pending_created_game_date': created,
            'expiry_comparison': 'current_game_date > value',
            'basis': 'native_pending_created_plus_three_days'}


def project_deadline(event, *, enabled):
    """Project the expiry threshold after admission of a native pending offer.

    The pending queue writes date2c from the game date. Its cleanup compares
    cached now strictly greater than that date plus 72 raw ticks. This does
    not establish when the sender originally initiated the proposal.
    """
    unknown = deadline_from_created_date(None)
    if enabled is not True:
        return {**unknown, 'reason': 'PROPOSAL_EXPIRY_RULE_NOT_VERIFIED'}
    if not isinstance(event, dict):
        return unknown
    expected_sources = {
        'native_alliance_inbound_offer': 'native_executor_pending_block',
        'native_alliance_inbound_pending': 'native_executor_pending_block',
        'native_diplomacy_inbound_pending_restored': 'native_saved_pending_queue',
    }
    source = expected_sources.get(event.get('event'))
    created = event.get('created2c')
    token = event.get('proposal3c')
    if (source is None or event.get('pending_source') != source
            or not _integer(created, 1, 2**31 - 73)
            or type(event.get('date2c')) is not int or event['date2c'] != created
            or not _integer(token, -(2**31), 2**31 - 1) or token == 0
            or type(event.get('token3c')) is not int
            or event['token3c'] != (token & 0xffffffff)):
        return unknown
    return deadline_from_created_date(created)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _reference(value):
    if not isinstance(value, str) or re.fullmatch(r'0x[0-9a-fA-F]{1,16}', value) is None:
        return None
    number = int(value, 16)
    try:
        tag = (number & 0xffffff).to_bytes(3, 'little').decode('ascii')
    except UnicodeError:
        return None
    if ((number >> 32) & 0xffff) >= 4096 or re.fullmatch(r'[A-Z0-9]{3}', tag) is None:
        return None
    return number, tag


def _is_end_observation(event, session_id, return_rvas, controlled_country):
    if (not isinstance(event, dict) or event.get('event') != 'native_alliance_lifecycle'
            or event.get('session_id') != session_id or event.get('kind') != 'destructor_return'
            or event.get('caller_return_rva') not in return_rvas):
        return False
    source = event.get('source')
    recipient = _reference(source.get('recipient20')) if isinstance(source, dict) else None
    return recipient is None or recipient[1] == controlled_country


def is_expiry_observation(event, session_id, *, controlled_country='FRA'):
    return _is_end_observation(event, session_id, (EXPIRY_RETURN_RVA,), controlled_country)


def is_inactivation_observation(event, session_id, *, controlled_country='FRA'):
    return _is_end_observation(event, session_id, INACTIVE_RETURN_RVAS, controlled_country)


def validate_expiry(event, session_id, *, controlled_country='FRA'):
    """Require the observed native expiry call, its return and its copied shape."""
    return _validate_end(event, session_id, (EXPIRY_RETURN_RVA,), expired=True,
                         controlled_country=controlled_country)


def validate_inactivation(event, session_id, *, controlled_country='FRA'):
    """Recognize pending token, recheck or bulk removal with an unspecified cause."""
    return _validate_end(event, session_id, INACTIVE_RETURN_RVAS, expired=False,
                         controlled_country=controlled_country)


def _validate_end(event, session_id, return_rvas, *, expired, controlled_country):
    if not isinstance(event, dict):
        return None
    source = event.get('source')
    if (event.get('event') != 'native_alliance_lifecycle'
            or event.get('session_id') != session_id or event.get('kind') != 'destructor_return'
            or event.get('caller_return_rva') not in return_rvas
            or event.get('native_return_observed') is not True
            or event.get('observed_game_date_verified') is not True
            or type(event.get('native_flags')) is not int or event['native_flags'] != 1
            or type(event.get('native_forward_count_by_hook_contract')) is not int
            or event['native_forward_count_by_hook_contract'] != 1
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or type(event.get('source_event_id')) is not int
            or event['source_event_id'] != event['sequence']
            or not _integer(event.get('observed_game_date_raw'), 1, 2**31 - 1)
            or not isinstance(source, dict)):
        return None
    if (any(source.get(key) is not True for key in ('readable', 'matched', 'handles_canonical', 'tracked'))
            or any(type(source.get(key)) is not int or source[key] != value
                   for key, value in (('discriminator', 0x165), ('variant38', 1)))
            or not _integer(source.get('state34'), -(2**31), 2**31 - 1)
            # Recheck and bulk clearing also destroy nonzero-state records.
            or (event['caller_return_rva'] not in (RECHECK_RETURN_RVA, CLEAR_RETURN_RVA)
                and source['state34'] != 0)
            or any(not _integer(source.get(key), -(2**31), 2**31 - 1)
                   for key in ('date28', 'date2c', 'envoy30', 'proposal3c'))
            or not 0 < source['date2c'] <= 2**31 - 73 or source['proposal3c'] == 0
            or event['observed_game_date_raw'] < source['date2c']
            or (expired and event['observed_game_date_raw'] <= source['date2c'] + 72)):
        return None
    actor, mirror, recipient = (_reference(source.get(key)) for key in ('actor10', 'mirror18', 'recipient20'))
    if (actor is None or mirror != actor or recipient is None
            or recipient[1] != controlled_country or actor[1] == controlled_country):
        return None
    vtable = source.get('vtable_rva')
    if (not isinstance(vtable, str) or re.fullmatch(r'0x[0-9a-f]{1,8}', vtable) is None
            or (int(vtable, 16), source.get('family')) not in ACTION_VTABLES.values()
            or (source.get('family') == 'royal_marriage'
                and (type(source.get('extra60')) is not int or source['extra60'] != 0))):
        return None
    return {'sequence': event['sequence'], 'date_raw': event['observed_game_date_raw'],
            'actor': actor[1], 'recipient': recipient[1], 'vtable_rva': int(vtable, 16),
            'family': source['family'],
            'shape': {key: source[key] for key in ('date28', 'date2c', 'envoy30', 'proposal3c')}}


def match_original_proposal(candidate, proposals, session_id):
    """Find one admitted original by its family, parties and native pending identity."""
    matches = []
    for public_id, record in proposals.items():
        payload, public = record.get('payload', {}), record.get('public', {})
        action = public.get('action_id')
        if (record.get('session_id') != session_id
                or not isinstance(public_id, str) or re.fullmatch(r'[0-9a-f]{32}', public_id) is None
                or public.get('proposal_id') != public_id
                or ACTION_VTABLES.get(action) != (candidate['vtable_rva'], candidate['family'])
                or any(payload.get(key) != candidate[key] for key in ('actor', 'recipient'))
                or any(type(payload.get(key)) is not int or payload[key] != value
                       for key, value in candidate['shape'].items())
                or type(payload.get('token3c')) is not int
                or payload['token3c'] != (candidate['shape']['proposal3c'] & 0xffffffff)
                or type(payload.get('created2c')) is not int
                or payload['created2c'] != candidate['shape']['date2c']):
            continue
        matches.append(public)
    if len(matches) != 1:
        return None
    return deepcopy(matches[0])


def project_expiry(candidate, proposals, session_id):
    """Expose an expiry only when exactly one verified original offer matches."""
    return _project_end(candidate, proposals, session_id, 'expired', 'native_pending_expiry_branch')


def project_inactivation(candidate, proposals, session_id):
    return _project_end(candidate, proposals, session_id, 'inactive', 'native_pending_queue_removal')


def ended_lifecycle(public):
    """Recognize a bounded terminal observation for a public proposal view."""
    bases = {'expired': 'native_pending_expiry_branch', 'inactive': 'native_pending_queue_removal'}
    kind = public.get('observer_status')
    lifecycle = public.get('lifecycle')
    if (kind not in bases or not isinstance(lifecycle, dict)
            or lifecycle.get('kind') != kind or lifecycle.get('basis') != bases[kind]
            or not _integer(lifecycle.get('game_date_raw'), 1, 2**31 - 1)
            or public.get('currently_pending') is not False):
        return None
    result = {key: lifecycle[key] for key in ('kind', 'game_date_raw', 'basis')}
    if _integer(lifecycle.get('created_game_date_raw'), 1, lifecycle['game_date_raw']):
        result['created_game_date_raw'] = lifecycle['created_game_date_raw']
    return result


def _project_end(candidate, proposals, session_id, kind, basis):
    public = match_original_proposal(candidate, proposals, session_id)
    if public is None:
        return None
    lifecycle = {'kind': kind, 'game_date_raw': candidate['date_raw'],
                 'created_game_date_raw': candidate['shape']['date2c'],
                 'basis': basis}
    parameters = deepcopy(public.get('parameters', {}))
    parameters['proposal_lifecycle'] = lifecycle
    terms_known = (public.get('action_id') in PARAMETERLESS_ACTIONS
                   and public.get('parameters') == {})
    if public.get('action_id') == 'peace_offer':
        context = public.get('peace_context')
        terms_known = (isinstance(context, dict) and context.get('complete') is True
                       and public.get('parameters') == {'peace_context': context})
    public.update(observer_status=kind, currently_pending=False, parameters=parameters,
                  lifecycle=lifecycle, date_raw=candidate['date_raw'], complete=False,
                  gaps=(['ORIGINAL_PROPOSAL_LEGALITY_UNKNOWN'] if terms_known
                        else ['ORIGINAL_PROPOSAL_TERMS_PARTIAL']))
    identity = json.dumps([session_id, public['proposal_id'], candidate['sequence'], candidate['date_raw']],
                          separators=(',', ':'))
    return {'event_id': 'inbound-' + kind + ':' + hashlib.sha256(identity.encode()).hexdigest()[:32],
            'date_raw': candidate['date_raw'], 'payload': public,
            'log_offset': candidate.get('log_offset', 0)}
