"""Fresh selected-proposal status through the existing read-only inspection path."""
from copy import deepcopy
import re

from bridge.diplomacy import ObserverSession, _inbound_family
from .model import digest

_SHA = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
_IDENTITY = ('mode', 'observer', 'session_id', 'game_sha256', 'game_version')
_GAPS = ['SELECTED_OBSERVED_PROPOSAL_ONLY', 'NATIVE_PENDING_SET_NOT_ENUMERATED',
         'INACTIVE_REASON_NOT_ACCEPT_REJECT_WITHDRAW_OR_EXPIRY', 'NO_RESPONSE_EXECUTED']
_FAVOR_AMOUNTS = {
    'trade_favors_for_gold': ('gold', 'ducats', 1000),
    'trade_favors_for_trust': ('trust', 'trust', 1),
    'trade_favors_for_men': ('men', 'men', 1),
}


def _identity(context):
    return tuple(context.get(key) for key in _IDENTITY) if isinstance(context, dict) else None


def _current_favor_parameters(native, action, actor, recipient):
    """Keep the bound rule quote's requested resource and favor price."""
    quote = native.get('favor_trade')
    if (not isinstance(quote, dict) or action not in _FAVOR_AMOUNTS
            or quote.get('complete') is not True or quote.get('source') != 'native_rule'):
        return None
    kind, unit, scale = _FAVOR_AMOUNTS[action]
    amount, favors = quote.get('amount'), quote.get('favors')
    if (quote.get('kind') != kind or not isinstance(amount, dict) or not isinstance(favors, dict)
            or amount.get('available') is not True or favors.get('available') is not True):
        return None
    amount_identity = {'unit': unit, 'scale': scale}
    if kind == 'trust':
        amount_identity.update(trustor=recipient, trusted=actor, direction='recipient_to_actor')
    else:
        amount_identity.update(payer=recipient, receiver=actor)
    favor_identity = {'held_by': actor, 'owed_by': recipient, 'unit': 'favors', 'scale': 1000}
    if (any(amount.get(key) != value for key, value in amount_identity.items())
            or any(favors.get(key) != value for key, value in favor_identity.items())
            or type(amount.get('scale')) is not int or type(favors.get('scale')) is not int):
        return None
    amount_raw, cost_raw = amount.get('raw'), favors.get('cost_raw')
    if (type(amount_raw) is not int or not 0 <= amount_raw < 2**31
            or type(cost_raw) is not int or not 0 <= cost_raw < 2**31
            or type(amount.get('value')) not in (int, float) or amount['value'] != amount_raw / scale
            or type(favors.get('cost')) not in (int, float) or favors['cost'] != cost_raw / 1000):
        return None
    return {'favor_trade': {
        'kind': kind,
        'amount': dict(amount_identity, available=True, raw=amount_raw, value=amount['value']),
        'favors': dict(favor_identity, available=True, cost_raw=cost_raw, cost=favors['cost']),
    }}


def project_pending_flag(status, public_id):
    """Keep the comparable boolean separate from inspection timestamps."""
    result = {'status': 'unknown', 'unit': 'boolean', 'scale': 1, 'period': 'current',
              'complete': False, 'partial': True, 'proposal_id': public_id, 'gaps': list(_GAPS)}
    pending = status.get('currently_pending', {})
    if (status.get('status') == 'known' and pending.get('status') == 'known'
            and type(pending.get('value')) is bool):
        result.update(status='known', value=pending['value'])
    else:
        result.update(status=status.get('status', 'unknown'),
                      reason=status.get('reason', 'INBOUND_CURRENT_PENDING_UNKNOWN'))
    return result


def pending_change_comparison(query, sample, context):
    """Admit only the selected live proposal's validated pending boolean."""
    params = query.get('parameters', {})
    public_id = params.get('proposal_id')
    observer = context.get('observer')
    fields = sample.get('fields', {})
    source = sample.get('source', {})
    provenance = source.get('provenance', {})
    proof = provenance.get('native_status_proof', {})
    field = fields.get('currently_pending', {})
    if (query.get('topic') != 'A04' or query.get('fields') != ['currently_pending']
            or params.get('fresh_pending') is not True
            or not isinstance(public_id, str) or re.fullmatch(r'[0-9a-f]{32}', public_id) is None
            or context.get('status') != 'ready' or context.get('mode') != 'live'
            or not isinstance(observer, str) or re.fullmatch(r'[A-Z0-9]{3}', observer) is None
            or context.get('game_sha256') != _SHA
            or context.get('game_version') != '1.37.4'
            or source.get('session_id') != context.get('session_id') or source.get('observer') != observer
            or set(fields) != {'currently_pending'} or field.get('status') != 'known'
            or type(field.get('value')) is not bool or field.get('period') != 'current'
            or field.get('proposal_id') != public_id
            or provenance.get('inspection_attempted') is not True
            or provenance.get('read_only_inspection') is not True
            or provenance.get('response_executed') is not False
            or type(proof.get('pending_active')) is not bool
            or proof['pending_active'] != field['value']):
        return None
    if ((field['value'] and proof.get('decision_country_verified') is not True)
            or (not field['value'] and proof.get('reason') != 'PENDING_NOT_ACTIVE')):
        return None
    return {'schema': 'information.change_comparison.v1',
            'scope': 'A04.currently_pending.' + public_id, 'fields': deepcopy(fields)}


def read_response_inspection(source, proposal, context, phase='accept'):
    """Read and bind one response inspection to its original observed proposal."""
    provenance = {'read_only_inspection': True, 'response_executed': False,
                  'inspection_phase': phase, 'inspection_attempted': False}

    def unknown(reason, status='unknown'):
        return {'status': status, 'reason': reason, 'complete': False, 'partial': True,
                'period': 'current', 'observed_status': ('observed_pending'
                    if proposal.get('observer_status') == 'observed_pending' else None),
                'gaps': list(_GAPS)}, provenance, None

    if phase not in ('accept', 'reject'):
        return unknown('INBOUND_CURRENT_RESPONSE_PHASE_INVALID')
    recipient = context.get('observer')
    if (context.get('status') != 'ready' or context.get('mode') != 'live'
            or not isinstance(recipient, str) or re.fullmatch(r'[A-Z0-9]{3}', recipient) is None
            or context.get('game_sha256') != _SHA
            or context.get('game_version') != '1.37.4' or type(context.get('game_date')) is not int):
        return unknown('INBOUND_CURRENT_CONTEXT_UNSUPPORTED', 'unavailable')
    public_id, actor, action = (proposal.get(key) for key in ('proposal_id', 'actor', 'action_id'))
    if (not isinstance(public_id, str) or re.fullmatch(r'[0-9a-f]{32}', public_id) is None
            or not isinstance(actor, str) or re.fullmatch(r'[A-Z0-9]{3}', actor) is None
            or actor == recipient or proposal.get('recipient') != recipient
            or proposal.get('observer_status') != 'observed_pending'
            or not isinstance(action, str) or _inbound_family(action) is None):
        return unknown('INBOUND_CURRENT_OBSERVATION_INVALID')
    try:
        before = source.context()
    except Exception:
        before = {}
    if before.get('status') != 'ready' or _identity(before) != _identity(context):
        return unknown('INBOUND_CURRENT_CONTEXT_MISMATCH', 'unavailable')
    tools, session = source.diplomacy_tools, source.session
    if session is None or getattr(session, 'session_id', None) != context.get('session_id'):
        return unknown('INBOUND_CURRENT_SESSION_MISMATCH', 'unavailable')
    inspector = getattr(tools, 'inspect_diplomatic_action', None)
    if not callable(inspector):
        return unknown('INBOUND_CURRENT_INSPECTOR_UNAVAILABLE')
    inspected, error = None, None
    try:
        provenance['inspection_attempted'] = True
        inspected = inspector(action, actor, recipient, phase, {'proposal_id': public_id})
    except Exception as exc:
        error = f'INBOUND_CURRENT_INSPECTION_FAILED:{type(exc).__name__}'
    try:
        after = source.context()
    except Exception:
        after = {}
    if after.get('status') != 'ready' or _identity(before) != _identity(after):
        return unknown('INBOUND_CURRENT_CONTEXT_CHANGED', 'unavailable')
    if error:
        return unknown(error)
    if not isinstance(inspected, dict) or inspected.get('error_code'):
        return unknown('INBOUND_CURRENT_INSPECTION_UNAVAILABLE')
    native = inspected.get('native_inbound_inspection')
    observed = inspected.get('observed_inbound_proposal')
    parameters = inspected.get('parameters')
    health = inspected.get('session')
    if not all(isinstance(value, dict) for value in (native, observed, parameters, health)):
        return unknown('INBOUND_CURRENT_NATIVE_PROOF_MISSING')
    actual, requested = parameters.get('actual'), parameters.get('requested')
    if not isinstance(actual, dict) or not isinstance(requested, dict):
        return unknown('INBOUND_CURRENT_PARAMETER_BINDING_INVALID')
    if (any(inspected.get(key) != value for key, value in (
                ('action_id', action), ('actor', actor), ('recipient', recipient), ('phase', phase)))
            or actual.get('proposal_id') != public_id or requested.get('proposal_id') != public_id
            or actual.get('decision_country') != recipient
            or any(observed.get(key) != value for key, value in (
                ('proposal_id', public_id), ('actor', actor), ('recipient', recipient), ('action_id', action)))
            or health.get('status') != 'ready' or type(health.get('date_raw')) is not int
            or health['date_raw'] <= 0
            or inspected.get('decision_country') != recipient
            or health.get('session_id', context['session_id']) != context['session_id']):
        return unknown('INBOUND_CURRENT_PROPOSAL_BINDING_INVALID')
    if (native.get('event') != 'native_alliance_inbound_inspection'
            or any(native.get(key) != value for key, value in (
                ('action_id', action), ('actor', actor), ('recipient', recipient), ('phase', phase),
                ('decision_country', recipient)))
            or type(native.get('date_raw')) is not int or native['date_raw'] <= 0
            or any(type(native.get(key)) is not bool for key in (
                'pending_active', 'decision_country_verified', 'native_validity', 'response_rules_complete'))
            or type(observed.get('currently_pending')) is not bool
            or observed['currently_pending'] != native['pending_active']
            or type(inspected.get('decision_country_verified')) is not bool
            or inspected['decision_country_verified'] != native['decision_country_verified']):
        return unknown('INBOUND_CURRENT_NATIVE_IDENTITY_OR_FLAGS_INVALID')
    reason = native.get('reason')
    if reason is not None and (not isinstance(reason, str)
            or re.fullmatch(r'[A-Za-z0-9_]{1,80}', reason) is None):
        return unknown('INBOUND_CURRENT_NATIVE_REASON_INVALID')
    active = native['pending_active']
    if active:
        if native['decision_country_verified'] is not True:
            return unknown('INBOUND_CURRENT_DECISION_COUNTRY_UNVERIFIED')
        state = 'pending'
    else:
        if native.get('reason') != 'PENDING_NOT_ACTIVE':
            return unknown('INBOUND_CURRENT_INACTIVE_REASON_UNPROVEN')
        state = 'inactive'
    provenance['inspection_result_sha256'] = digest(inspected)
    provenance['native_status_proof'] = {key: deepcopy(native.get(key)) for key in (
        'pending_active', 'decision_country_verified', 'native_validity', 'response_rules_complete', 'reason')}
    result = {'status': 'known', 'value': state, 'unit': 'proposal_state', 'scale': 1,
            'period': 'current', 'complete': False, 'partial': True,
            'proposal_id': public_id, 'observed_status': proposal.get('observer_status'),
            'currently_pending': {'status': 'known', 'value': active, 'period': 'current'},
            'observation_game_date': native['date_raw'], 'gaps': list(_GAPS)}
    return result, provenance, inspected


def read_current_status(source, proposal, context, *, include_parameters=False, include_consequences=False):
    """Read the default accept-phase proof and its requested current projections."""
    result, provenance, inspected = read_response_inspection(source, proposal, context)
    if inspected is None:
        return result, provenance
    public_id, actor, recipient, action = (proposal[key] for key in ('proposal_id', 'actor', 'recipient', 'action_id'))
    native = inspected['native_inbound_inspection']
    active = native['pending_active']
    if (include_parameters and action == 'peace_offer' and active
            and native['native_validity'] is True and native['response_rules_complete'] is True
            and native.get('peace_payload_complete') is True
            and native.get('selected_terms_complete') is True):
        terms = ObserverSession._public_inbound_peace_parameters(native.get('peace_context'), actor)
        if terms is not None:
            result['proposal_parameters'] = {
                'status': 'known', 'value': terms, 'period': 'current',
                'proposal_id': public_id, 'observation_game_date': result['observation_game_date'],
                'basis': 'selected_native_inbound_peace_inspection'}
    if ((include_parameters or include_consequences) and action in _FAVOR_AMOUNTS and active
            and native['native_validity'] is True and native['response_rules_complete'] is True):
        terms = _current_favor_parameters(native, action, actor, recipient)
        if terms is not None:
            if include_parameters:
                result['proposal_parameters'] = {
                    'status': 'known', 'value': terms, 'period': 'current',
                    'proposal_id': public_id, 'observation_game_date': result['observation_game_date'],
                    'basis': 'selected_native_inbound_favor_rule_inspection',
                    'scope': 'current_native_rule_quote'}
            if include_consequences:
                from .inbound_consequences import project_favor_consequences
                changes = project_favor_consequences(native['favor_trade'], terms, actor, recipient)
                if changes is not None:
                    result['response_consequences'] = {
                        'status': 'known', 'value': changes, 'period': 'current',
                        'proposal_id': public_id, 'observation_game_date': result['observation_game_date'],
                        'basis': 'existing_favor_settlement_contract', 'derived': True,
                        'conditional_on': 'response_completes_in_inspected_state',
                        'scope': 'resource_and_favor_changes', 'response_executed': False,
                        'response_authority': False, 'complete': False, 'partial': True,
                        'gaps': ['OTHER_RELATION_PRESTIGE_OR_SCRIPT_EFFECTS_NOT_PROJECTED',
                                 'REJECT_RULES_NOT_INSPECTED']}
    if (include_consequences and action in (
            'offer_alliance', 'offer_royal_marriage', 'ask_military_access', 'offer_vassalization',
            'support_independence')
            and active and native['native_validity'] is True and native['response_rules_complete'] is True):
        from .inbound_consequences import project_relation_consequences
        changes = project_relation_consequences(native, action, actor, recipient)
        if changes is not None:
            result['response_consequences'] = {
                'status': 'known', 'value': changes, 'period': 'current',
                'proposal_id': public_id, 'observation_game_date': result['observation_game_date'],
                'basis': 'existing_primary_relation_response_contract', 'derived': True,
                'conditional_on': 'response_completes_in_inspected_state',
                'scope': 'primary_relationship_state', 'response_executed': False,
                'response_authority': False, 'complete': False, 'partial': True,
                'gaps': ['OTHER_DIRECT_EFFECTS_NOT_PROJECTED', 'REJECT_RULES_NOT_INSPECTED']}
    return result, provenance
