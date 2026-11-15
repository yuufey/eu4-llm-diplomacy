"""Expose copied same-event reserved slots and naval templates from wire13."""
from collections.abc import Mapping
import re
from bridge.native_text import decode_native_text_hex
from .battle_score_predicate import RESERVED_SLOT_RVAS

NAVAL_KEYS = ('COMBAT_FLEE', 'COMBAT_TRIUMPH', 'COMBAT_WINNERTYPE_OUR', 'COMBAT_WINNERTYPE_THEIR')
FIELDS = ('language', *NAVAL_KEYS)
FLAGS = {'not_raw_text': True, 'native_formatter_invoked': False,
         'native_branch_selection_verified': False, 'native_line1_verified': False,
         'runtime_popup_verified': False, 'visibility_verified': False,
         'full_display_complete': False, 'complete': False}


def _unknown(reason):
    return {**FLAGS, 'status': 'unknown', 'reason': reason}


def project_outcome_tail_sources(decoded):
    if not isinstance(decoded, Mapping):
        return _unknown('OUTCOME_TAIL_INPUT_INVALID')
    wire = decoded.get('wire13')
    if (not isinstance(wire, Mapping) or wire.get('version') != 13
            or wire.get('source') != 'owned_outcome_tail'):
        return _unknown('OUTCOME_TAIL_NOT_CAPTURED')
    try:
        source = decoded['outcome_tail']
        expected = (decoded['observation']['sequence'], decoded['observation']['result']['raw_date'],
                    decoded['context']['kind'])
        actual = tuple(source[key] for key in ('sequence', 'raw_date', 'kind'))
        if (not all(type(value) is int for value in expected + actual) or expected != actual
                or not 0 < actual[0] < 1 << 64 or not 0 <= actual[1] < 1 << 31
                or actual[2] not in (1, 2)):
            raise ValueError('identity')
        failure, slots = source['failure'], source['reserved_slots']
        if (type(failure) is not int or not 0 <= failure <= 9
                or not isinstance(slots, (list, tuple)) or len(slots) != 3
                or any(type(value) is not int or not -(1 << 31) <= value < 1 << 31 for value in slots)):
            raise ValueError('failure or slots')
        fields = source['text_fields']
        if not isinstance(fields, Mapping) or set(fields) != set(FIELDS):
            raise ValueError('fields')
        states, output = [], {}
        for name in FIELDS:
            item = fields[name]
            state, length, raw_hex = item['state'], item['length'], item['raw_hex']
            maximum = 256 if name == 'language' else 8192
            if (state not in ('known', 'unknown', 'absent') or type(length) is not int
                    or not 0 <= length <= maximum or not isinstance(raw_hex, str)
                    or len(raw_hex) != length * 2 or re.fullmatch('[0-9a-fA-F]*', raw_hex) is None):
                raise ValueError('text')
            states.append(state)
            if state != 'known':
                if length or raw_hex or (name == 'language' and state == 'absent'):
                    raise ValueError('noncanonical text')
                output[name] = {'status': state, 'reason': ('CACHE_KEY_ABSENT_NOT_UI_HIDDEN'
                    if state == 'absent' else 'OUTCOME_TAIL_GROUP_NOT_CAPTURED_OR_FAILED')}
                continue
            raw = bytes.fromhex(raw_hex)
            if b'\0' in raw or (name == 'language' and re.fullmatch(rb'l_[A-Za-z0-9_]+', raw) is None):
                raise ValueError('bytes')
            try:
                text = {'status': 'known', 'value': decode_native_text_hex(raw_hex, codec='eu4_escape',
                        max_bytes=maximum, max_bytes_limit=8192)}
            except (ValueError, UnicodeError):
                text = {'status': 'unknown', 'reason': 'OUTCOME_TAIL_CODEC_INVALID'}
            output[name] = {'status': 'known', 'length': length, 'raw_hex': raw.hex(),
                            'codec': 'eu4_escape', 'decoded': text}
        if failure == 0:
            if states[0] != 'known' or any(state not in ('known', 'absent') for state in states[1:]):
                raise ValueError('successful group')
        elif any(slots) or any(state != 'unknown' for state in states):
            raise ValueError('failed group')
    except (KeyError, TypeError, ValueError):
        return _unknown('OUTCOME_TAIL_INVALID_OR_EVENT_MISMATCH')
    return {**FLAGS, 'status': 'known' if failure == 0 else 'unknown',
        'reason': None if failure == 0 else 'OUTCOME_TAIL_CAPTURE_FAILED',
        'source': 'owned_outcome_tail', 'capture_stage': 'entry_before_client_gate',
        'sequence': actual[0], 'raw_date': actual[1], 'battle_kind': actual[2], 'failure': failure,
        'reserved_slots': ({'status': 'known', 'value': list(slots), 'source_rvas': list(RESERVED_SLOT_RVAS)}
            if failure == 0 else {'status': 'unknown', 'reason': 'OUTCOME_TAIL_CAPTURE_FAILED'}),
        'text_fields': output}
