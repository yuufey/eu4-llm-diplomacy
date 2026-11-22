"""Conditional changes under the existing response and settlement contracts."""
from ..favor_resources import conditional_settlement, NATIVE_ACCEPT
from ..support_roles import validate_public_roles

_RELATION_FIELDS = {
    'offer_alliance': ('alliance', 'alliance_before'),
    'offer_royal_marriage': ('royal_marriage', 'royal_marriage_before'),
    'ask_military_access': ('military_access', 'military_access_before'),
    'offer_vassalization': ('vassalization', 'vassalization_before'),
    'support_independence': ('support_independence', 'support_independence_before'),
}


def project_relation_consequences(native, action, actor, recipient):
    """Project the existing primary-relation response contract from an absent state."""
    specification = _RELATION_FIELDS.get(action)
    if specification is None:
        return None
    family, field = specification
    allowed_families = (None, family) if action == 'offer_alliance' else (family,)
    if native.get('family') not in allowed_families or native.get(field) is not False:
        return None
    change = {'relation': family, 'actor': actor, 'recipient': recipient,
              'before': False, 'after': True, 'unit': 'boolean', 'scale': 1}
    if action == 'support_independence':
        roles = validate_public_roles(native.get('support_roles'), actor, recipient)
        if (roles is None or native.get('native_current_support_independence') is not False
                or native.get('native_current_support_independence_readable') is not True):
            return None
        change.update(supporter=roles['supporter'], supported_country=roles['supported_country'])
    elif action == 'ask_military_access':
        if (native.get('military_access_active') is not False
                or native.get('military_access_state_verified') is not True):
            return None
        change.update(beneficiary=actor, grantor=recipient)
    elif action == 'offer_vassalization':
        if (native.get('native_current_vassalization') is not False
                or native.get('native_current_vassalization_readable') is not True):
            return None
        change.update(overlord=actor, subject=recipient)
    else:
        change.update(symmetric=True, countries=[actor, recipient])
    return {
        'accept': {'changes': [change], 'legality': 'checked_for_current_inspection'},
        'reject': {'changes': [dict(change, after=False)], 'legality': 'not_inspected'},
    }


def project_favor_consequences(quote, parameters, actor, recipient):
    terms = parameters['favor_trade']
    amount, price = terms['amount'], terms['favors']
    current = quote['favors'].get('current_raw')
    displayed = quote['favors'].get('current')
    if (type(current) is not int or not -(2**31) <= current < 2**31
            or type(displayed) not in (int, float) or displayed != current / 1000
            or not -(2**31) <= current - price['cost_raw'] < 2**31):
        return None
    kind = terms['kind']
    before = {'complete': True, 'favors_raw': current, 'cost_raw': price['cost_raw']}
    changes = []
    if kind == 'trust':
        trust = quote.get('trust')
        if (not isinstance(trust, dict) or trust.get('trustor') != recipient
                or trust.get('trusted') != actor or trust.get('direction') != 'recipient_to_actor'
                or trust.get('unit') != 'trust' or type(trust.get('scale')) is not int
                or trust['scale'] != 1 or type(trust.get('value')) not in (int, float)
                or trust.get('value') != trust.get('raw')):
            return None
        before['recipient_trust_raw'] = trust.get('raw')
        after = conditional_settlement(before, amount['raw'], kind, NATIVE_ACCEPT)
        if after is None:
            return None
        changes.append({'resource': 'trust', 'country': recipient, 'counterparty': actor,
                        'before_raw': before['recipient_trust_raw'], 'after_raw': after['recipient_trust_raw'],
                        'delta_raw': after['recipient_trust_raw'] - before['recipient_trust_raw'],
                        'unit': 'trust', 'scale': 1, 'direction': 'recipient_to_actor'})
    elif kind == 'men':
        manpower = quote.get('manpower')
        if (not isinstance(manpower, dict) or manpower.get('actor') != actor
                or manpower.get('recipient') != recipient or manpower.get('unit') != 'men'
                or type(manpower.get('scale')) is not int or manpower['scale'] != 1):
            return None
        before.update(actor_manpower_raw=manpower.get('actor_raw'),
                      recipient_manpower_raw=manpower.get('recipient_raw'))
        after = conditional_settlement(before, amount['raw'], kind, NATIVE_ACCEPT)
        if after is None:
            return None
        for country, key in ((actor, 'actor_manpower_raw'), (recipient, 'recipient_manpower_raw')):
            changes.append({'resource': 'manpower', 'country': country, 'unit': 'men', 'scale': 1,
                            'before_raw': before[key], 'after_raw': after[key],
                            'delta_raw': after[key] - before[key]})
    else:
        for country, sign in ((actor, 1), (recipient, -1)):
            changes.append({'resource': 'treasury', 'country': country, 'unit': 'ducats',
                            'scale': 1000, 'delta_raw': sign * amount['raw']})
    changes.append({'resource': 'favors', 'country': actor, 'counterparty': recipient,
                    'unit': 'favors', 'scale': 1000, 'before_raw': current,
                    'after_raw': current - price['cost_raw'], 'delta_raw': -price['cost_raw']})
    rejected = []
    for change in changes:
        unchanged = dict(change, delta_raw=0)
        if 'before_raw' in unchanged:
            unchanged['after_raw'] = unchanged['before_raw']
        rejected.append(unchanged)
    return {
        'accept': {'changes': changes, 'legality': 'checked_for_current_inspection'},
        'reject': {'changes': rejected, 'legality': 'not_inspected'},
    }
