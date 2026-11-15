"""Match verified current queue diagnostics to admitted public A04 observations."""
from collections import Counter
import hashlib
import re
import struct

from . import proposal_expiry
from .information import native_pending_memory as native


def match_current_proposals(report, proposals, session_id):
    """Return only opaque public identifiers, keeping the native inventory intact."""
    first = report.get('before') if isinstance(report, dict) else None
    if (not isinstance(first, dict) or first != report.get('after')
            or report.get('schema') != native.SCHEMA or report.get('status') != 'observed'
            or report.get('country') != 'FRA' or report.get('game_sha256') != native.GAME_SHA256
            or report.get('profile_sha256') != native.PROFILE_SHA256
            or report.get('read_only') is not True or report.get('consistent') is not True
            or report.get('native_function_invoked') is not False
            or report.get('target_memory_written') is not False
            or report.get('cleanup', {}).get('closed') is not True
            or report.get('identity', {}).get('binding_verified') is not True
            or report.get('identity', {}).get('installation_session_id') != session_id
            or first.get('value') != report.get('value')
            or type(report.get('game_date')) is not int or not 0 < report['game_date'] < 2**31
            or first.get('game_date') != report['game_date']
            or first.get('player_country') != report.get('player_country')
            or not isinstance(report.get('player_country'), str)
            or re.fullmatch(r'[A-Z0-9]{3}', report['player_country']) is None
            or report.get('player_country') == 'FRA'):
        raise ValueError('NATIVE_PENDING_PROPOSAL_PROOF_UNAVAILABLE')
    value = native.validate_value(report['value'])
    base = int(report['module_base']['va'], 0)
    if not 0x10000 <= base < 2**47 or base % 0x10000:
        raise ValueError('NATIVE_PENDING_PROPOSAL_BASE_INVALID')
    nodes = first['private']['nodes']
    recipient_ref = int(first['roots']['country_scan']['country_handle'], 0)
    if not isinstance(nodes, list) or len(nodes) != len(value['entries']):
        raise ValueError('NATIVE_PENDING_PROPOSAL_NODES_INVALID')
    links = {}
    for entry, node in zip(value['entries'], nodes):
        if entry['recognition'] != 'recognized':
            continue
        if (not isinstance(node.get('header_hex'), str) or len(node['header_hex']) != 128
                or not isinstance(node.get('royal_flag_hex'), str) or len(node['royal_flag_hex']) > 2):
            raise ValueError('NATIVE_PENDING_PROPOSAL_HEADER_INVALID')
        header = bytes.fromhex(node['header_hex'])
        extra = bytes.fromhex(node['royal_flag_hex'])
        identity = (session_id.encode('utf-8')
                    + struct.pack('<QQ', int(node['node'], 0), int(node['clone'], 0)) + header + extra)
        if entry['entry_id'] != 'pending-entry-' + hashlib.sha256(identity).hexdigest()[:32]:
            raise ValueError('NATIVE_PENDING_PROPOSAL_ENTRY_MISMATCH')
        family = proposal_expiry.ACTION_VTABLES.get(entry['action_id'])
        actor_ref, mirror_ref, target_ref = struct.unpack_from('<QQQ', header, 0x10)
        actor = proposal_expiry._reference(hex(actor_ref))
        recipient = proposal_expiry._reference(hex(target_ref))
        if (family is None or struct.unpack_from('<Q', header)[0] != base + family[0]
                or struct.unpack_from('<i', header, 8)[0] != 0x165
                or actor is None or recipient is None or actor_ref != mirror_ref
                or target_ref != recipient_ref
                or actor[1] != entry['actor'] or recipient[1] != entry['recipient']
                or struct.unpack_from('<i', header, 0x34)[0] != 0 or header[0x38] != 1
                or struct.unpack_from('<i', header, 0x3c)[0] == 0
                or extra != (b'\0' if entry['action_id'] == 'offer_royal_marriage' else b'')):
            raise ValueError('NATIVE_PENDING_PROPOSAL_SHAPE_MISMATCH')
        date28, date2c, envoy30 = struct.unpack_from('<iii', header, 0x28)
        shape = {'date28': date28, 'date2c': date2c, 'envoy30': envoy30,
                 'proposal3c': struct.unpack_from('<i', header, 0x3c)[0]}
        candidate = {'actor': actor[1], 'recipient': recipient[1], 'vtable_rva': family[0],
                     'family': family[1], 'shape': shape}
        public = proposal_expiry.match_original_proposal(candidate, proposals, session_id)
        if public is not None:
            links[entry['entry_id']] = public['proposal_id']
    counts = Counter(links.values())
    return {entry_id: public_id for entry_id, public_id in links.items() if counts[public_id] == 1}
