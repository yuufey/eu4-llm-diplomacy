"""Typed subject-role context for a selected Support Independence action pair."""
import re

CAPABILITY = 'native_support_role_context'
GAME_SHA256 = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
FIELDS = ('support_roles_readable', 'support_actor_is_subject', 'support_recipient_is_subject')


def project_roles(event, actor, recipient):
    unknown = {'status': 'unknown', 'reason': 'SUPPORT_ROLE_CONTEXT_UNAVAILABLE'}
    if (not isinstance(actor, str) or re.fullmatch(r'[A-Z0-9]{3}', actor) is None
            or not isinstance(recipient, str) or re.fullmatch(r'[A-Z0-9]{3}', recipient) is None
            or actor == recipient or not isinstance(event, dict)
            or any(type(event.get(key)) is not bool for key in FIELDS)):
        return unknown
    if event['support_roles_readable'] is not True:
        return dict(unknown, reason='SUPPORT_ROLE_CONTEXT_UNREADABLE')
    actor_subject = event['support_actor_is_subject']
    recipient_subject = event['support_recipient_is_subject']
    if actor_subject == recipient_subject:
        return dict(unknown, reason='SUPPORT_ROLE_DIRECTION_AMBIGUOUS')
    supporter, supported = (recipient, actor) if actor_subject else (actor, recipient)
    return {'status': 'known', 'actor': actor, 'recipient': recipient,
            'actor_is_subject': actor_subject, 'recipient_is_subject': recipient_subject,
            'supporter': supporter, 'supported_country': supported,
            'basis': 'copied_overlord_reference_role_context'}


def validate_public_roles(value, actor, recipient):
    if not isinstance(value, dict) or value.get('status') != 'known':
        return None
    expected = project_roles({
        'support_roles_readable': True,
        'support_actor_is_subject': value.get('actor_is_subject'),
        'support_recipient_is_subject': value.get('recipient_is_subject'),
    }, actor, recipient)
    return expected if expected.get('status') == 'known' and value == expected else None
