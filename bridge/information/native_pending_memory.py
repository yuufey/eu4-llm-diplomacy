"""Bounded read-only inventory of FRA's recipient-owned native pending list."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct

from . import military_resources_memory as memory
from .observation_time import dates_match, without_clock
from .. import proposal_expiry

PROFILE = Path(__file__).parent / 'profiles/native-pending-memory-1374-r3.json'
PROFILE_SHA256 = 'd081e83ebc0b6bca8f57aa5cebb55b992776e63af7ddcd896718e44e172da6b1'
GAME_SHA256 = memory.EXPECTED_EXE_SHA256
SCHEMA = 'information.native_pending_capture.v1'
SCOPE = 'recipient_owned_native_pending_action_list'
MAX_ENTRIES = 256


def load_contract():
    with PROFILE.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('NATIVE_PENDING_PROFILE_PIN_MISMATCH')
    contract = json.loads(raw)
    if (contract['schema'] != 'information.native_pending_memory.v1'
            or contract['executable_sha256'] != GAME_SHA256
            or contract['observer'] != 'FRA' or contract['max_entries'] != MAX_ENTRIES):
        raise ValueError('NATIVE_PENDING_PROFILE_INVALID')
    return contract


def read_queue(read, country_pointer, recipient_ref, module_base, session_id, resolve_country,
               contract=None, *, game_date=None):
    """Read all counted links; expose list-entry identities and recognized parties."""
    contract = load_contract() if contract is None else contract
    if memory._tag_from_fullref(recipient_ref) != 'FRA':
        raise ValueError('NATIVE_PENDING_OBSERVER_MISMATCH')
    if game_date is not None and (type(game_date) is not int or not 0 < game_date < 2**31):
        raise ValueError('NATIVE_PENDING_GAME_DATE_INVALID')

    def raw(address, size):
        if type(address) is not int or address < 0x10000 or address > memory.MAX_USER_ADDRESS - size:
            raise ValueError('NATIVE_PENDING_ADDRESS_INVALID')
        data = read(address, size)
        if not isinstance(data, bytes) or len(data) != size:
            raise ValueError('NATIVE_PENDING_READ_INVALID')
        return data

    offsets = contract['queue_offsets']
    roots = raw(country_pointer + offsets['head'], 21)
    head, tail, count, deferred_removal = struct.unpack('<QQIB', roots)
    if deferred_removal:
        raise ValueError('NATIVE_PENDING_QUEUE_MUTATING')
    if (count > MAX_ENTRIES or (count == 0 and (head or tail))
            or (count and (not head or not tail))):
        raise ValueError('NATIVE_PENDING_ROOTS_INVALID')
    actions = {rva: name for name, rva in contract['action_vtable_rvas'].items()}
    entries, nodes, seen = [], [], set()
    node, previous = head, 0
    for _index in range(count):
        if node in seen:
            raise ValueError('NATIVE_PENDING_NODE_REPEATED')
        seen.add(node)
        links = raw(node, 25)
        clone, before, following, retired = struct.unpack('<QQQB', links)
        # Deferred unlinking leaves the already-destroyed action pointer in place.
        if retired:
            raise ValueError('NATIVE_PENDING_NODE_RETIRED')
        if before != previous or not clone:
            raise ValueError('NATIVE_PENDING_LINK_INVALID')
        header = raw(clone, 16)
        vtable, discriminator = struct.unpack_from('<Qi', header)
        action = actions.get(vtable - module_base)
        extra = b''
        entry = {'recognition': 'unresolved', 'reason': 'UNSUPPORTED_NATIVE_PENDING_ACTION'}
        if action is not None and discriminator == 0x165:
            header += raw(clone + 16, 48)
            actor, mirror, recipient = struct.unpack_from('<QQQ', header, 0x10)
            state = struct.unpack_from('<i', header, 0x34)[0]
            token = struct.unpack_from('<i', header, 0x3c)[0]
            if action == 'offer_royal_marriage':
                extra = raw(clone + 0x60, 1)
            shape_known = (actor != recipient_ref and mirror == actor and recipient == recipient_ref
                           and state == 0 and header[0x38] == 1 and token != 0
                           and (not extra or extra == b'\0'))
            entry['reason'] = 'NATIVE_PENDING_ACTION_SHAPE_UNVERIFIED'
            if shape_known:
                try:
                    actor_tag = resolve_country(actor)
                    recipient_tag = resolve_country(recipient)
                    if (not isinstance(actor_tag, str) or re.fullmatch(r'[A-Z0-9]{3}', actor_tag) is None
                            or actor_tag == 'FRA' or recipient_tag != 'FRA'):
                        raise ValueError('NATIVE_PENDING_PARTY_INVALID')
                    entry = {'recognition': 'recognized', 'action_id': action,
                             'actor': actor_tag, 'recipient': recipient_tag, 'phase': 'initiate'}
                    if contract.get('pending_deadline_verified') is True:
                        created = struct.unpack_from('<i', header, 0x2c)[0]
                        if game_date is not None and created > game_date:
                            created = None
                        entry['deadline'] = proposal_expiry.deadline_from_created_date(created)
                except ValueError:
                    entry['reason'] = 'NATIVE_PENDING_PARTY_UNRESOLVED'
        identity = session_id.encode('utf-8') + struct.pack('<QQ', node, clone) + header + extra
        entry['entry_id'] = 'pending-entry-' + hashlib.sha256(identity).hexdigest()[:32]
        entries.append(entry)
        nodes.append({'node': hex(node), 'clone': hex(clone), 'links_hex': links.hex(),
                      'header_hex': header.hex(), 'royal_flag_hex': extra.hex()})
        previous, node = node, following
    if node or previous != tail:
        raise ValueError('NATIVE_PENDING_TAIL_OR_COUNT_MISMATCH')
    recognized = sum(entry['recognition'] == 'recognized' for entry in entries)
    return {'value': {'scope': SCOPE, 'native_queue_count': count, 'recognized_entry_count': recognized,
                      'unresolved_entry_count': count - recognized, 'entries': entries,
                      'identity_scope': 'native_list_entry_observation', 'list_traversal_complete': True,
                      'payload_details_complete': False, 'response_contexts_available': False},
            'private': {'country_pointer': hex(country_pointer), 'roots_hex': roots.hex(), 'nodes': nodes}}


def validate_value(value, contract=None):
    """Validate the closed public projection independently of private diagnostics."""
    contract = load_contract() if contract is None else contract
    required = {'scope', 'native_queue_count', 'recognized_entry_count', 'unresolved_entry_count',
                'entries', 'identity_scope', 'list_traversal_complete',
                'payload_details_complete', 'response_contexts_available'}
    if (not isinstance(value, dict) or set(value) != required or value['scope'] != SCOPE
            or value['identity_scope'] != 'native_list_entry_observation'
            or value['list_traversal_complete'] is not True
            or value['payload_details_complete'] is not False
            or value['response_contexts_available'] is not False):
        raise ValueError('NATIVE_PENDING_PUBLIC_VALUE_INVALID')
    counts = [value[key] for key in ('native_queue_count', 'recognized_entry_count', 'unresolved_entry_count')]
    if (any(type(count) is not int or not 0 <= count <= MAX_ENTRIES for count in counts)
            or counts[0] != counts[1] + counts[2]
            or not isinstance(value['entries'], list) or len(value['entries']) != counts[0]):
        raise ValueError('NATIVE_PENDING_PUBLIC_COUNTS_INVALID')
    identifiers, recognized = set(), 0
    for entry in value['entries']:
        if (not isinstance(entry, dict) or not isinstance(entry.get('entry_id'), str)
                or re.fullmatch(r'pending-entry-[0-9a-f]{32}', entry['entry_id']) is None
                or entry['entry_id'] in identifiers):
            raise ValueError('NATIVE_PENDING_PUBLIC_ID_INVALID')
        identifiers.add(entry['entry_id'])
        if entry.get('recognition') == 'recognized':
            expected_keys = {'entry_id', 'recognition', 'action_id', 'actor', 'recipient', 'phase'}
            if (set(entry) not in (expected_keys, expected_keys | {'deadline'})
                    or entry['action_id'] not in contract['action_vtable_rvas']
                    or not isinstance(entry['actor'], str) or re.fullmatch(r'[A-Z0-9]{3}', entry['actor']) is None
                    or entry['actor'] == 'FRA' or entry['recipient'] != 'FRA' or entry['phase'] != 'initiate'):
                raise ValueError('NATIVE_PENDING_PUBLIC_ACTION_INVALID')
            if 'deadline' in entry:
                deadline = entry['deadline']
                if (contract.get('pending_deadline_verified') is not True
                        or not isinstance(deadline, dict) or type(deadline.get('scale')) is not int
                        or deadline != proposal_expiry.deadline_from_created_date(
                            deadline.get('pending_created_game_date'))):
                    raise ValueError('NATIVE_PENDING_PUBLIC_DEADLINE_INVALID')
            recognized += 1
        elif (set(entry) != {'entry_id', 'recognition', 'reason'} or entry.get('recognition') != 'unresolved'
                or entry.get('reason') not in {'UNSUPPORTED_NATIVE_PENDING_ACTION',
                    'NATIVE_PENDING_ACTION_SHAPE_UNVERIFIED', 'NATIVE_PENDING_PARTY_UNRESOLVED'}):
            raise ValueError('NATIVE_PENDING_PUBLIC_UNKNOWN_INVALID')
    if recognized != counts[1]:
        raise ValueError('NATIVE_PENDING_PUBLIC_RECOGNIZED_COUNT_INVALID')
    return deepcopy(value)


def _snapshot(reader, base, base_profile, contract, session_id, budget):
    layout = memory._profile_layout(base_profile)

    def read(address, size):
        return memory._reader_read(reader, address, size, 'native_pending', budget, layout)

    for guard in contract['code_guards']:
        if read(base + guard['rva'], guard['size']).hex() != guard['raw_hex']:
            raise ValueError('NATIVE_PENDING_RUNTIME_CODE_MISMATCH')
    game = int.from_bytes(read(base + layout['game_global_rva'], 8), 'little')
    date = int.from_bytes(read(game + layout['game_date_offset'], 4), 'little', signed=True)
    player = int.from_bytes(read(game + 0x1e60, 8), 'little')
    country, scan = memory._find_country(reader, base, 'FRA', base_profile, budget)
    recipient = int(scan['country_handle'], 0)
    table, count = int(scan['table_pointer'], 0), scan['country_count']
    resolved = {}

    def resolve_country(reference):
        if reference not in resolved:
            tag, slot = memory._tag_from_fullref(reference), (reference >> 32) & 0xffff
            if tag is None or slot >= count:
                raise ValueError('NATIVE_PENDING_COUNTRY_REFERENCE_INVALID')
            pointer = int.from_bytes(read(table + slot * 8, 8), 'little')
            actual = int.from_bytes(read(pointer + layout['country_fullref_offset'], 8), 'little')
            if actual != reference:
                raise ValueError('NATIVE_PENDING_COUNTRY_REFERENCE_CHANGED')
            resolved[reference] = {'tag': tag, 'pointer': hex(pointer), 'fullref': hex(actual)}
        return resolved[reference]['tag']

    player_tag = resolve_country(player)
    if player == recipient:
        raise ValueError('NATIVE_PENDING_OBSERVER_IS_PLAYER')
    queue = read_queue(read, country, recipient, base, session_id, resolve_country,
                       contract, game_date=date)
    queue.update(game_date=date, player_country=player_tag,
                 roots={'game': hex(game), 'country_scan': scan, 'resolved_countries': resolved})
    return queue


def capture(installation, country='FRA'):
    report = {'schema': SCHEMA, 'status': 'unknown', 'country': country, 'game_sha256': GAME_SHA256,
              'profile_sha256': PROFILE_SHA256, 'read_only': True,
              'native_function_invoked': False, 'target_memory_written': False,
              'identity': {}, 'consistent': False, 'atomic_snapshot': False}
    kernel, handle = None, None
    budget = memory._ReadBudget()
    try:
        if country != 'FRA':
            raise ValueError('NATIVE_PENDING_OBSERVER_UNSUPPORTED')
        contract, base_profile = load_contract(), memory._load_profile()
        document = memory._load_installation(Path(installation))
        kernel = memory._configure_kernel()
        handle = kernel.OpenProcess(memory.PROCESS_ACCESS, False, int(document['pid']))
        if not handle:
            raise OSError('OpenProcess failed')
        base = memory._capture_identity(report, document, kernel, handle)
        reader = memory.AddressBoundedRPM(kernel, handle, base)
        first = _snapshot(reader, base, base_profile, contract, document['session_id'], budget)
        second = _snapshot(reader, base, base_profile, contract, document['session_id'], budget)
        report.update(before=first, after=second)
        after_base = memory._capture_identity(report, document, kernel, handle)
        snapshots_match = without_clock(first) == without_clock(second)
        dates_are_monotonic = dates_match(first.get('game_date'), second.get('game_date'))
        if not snapshots_match or not dates_are_monotonic or base != after_base:
            raise ValueError('NATIVE_PENDING_SNAPSHOT_CHANGED')
        report.update(status='observed', consistent=True, game_date=first['game_date'],
                      player_country=first['player_country'], value=validate_value(first['value'], contract))
    except Exception as exc:
        report['reason'] = (str(exc) if isinstance(exc, ValueError)
                            and re.fullmatch(r'NATIVE_PENDING_[A-Z_]{1,100}', str(exc))
                            else 'NATIVE_PENDING_CAPTURE_FAILED')
        report['error'] = type(exc).__name__ + ':' + str(exc)
    finally:
        report['access'] = {'rpm_bytes': budget.used, 'rpm_calls': len(budget.reads),
                            'rpm_limit': budget.limit, 'open_process_mask': memory.PROCESS_ACCESS}
        report['cleanup'] = memory._close_process_handle(kernel, handle)
        if report['status'] == 'observed' and report['cleanup'].get('closed') is not True:
            report.update(status='unknown', reason='NATIVE_PENDING_HANDLE_CLOSE_FAILED')
            report.pop('value', None)
    return report
