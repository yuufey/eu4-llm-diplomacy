"""Expose same-event cached outcome inputs, without selecting WINORLOSE."""
from collections.abc import Mapping
import re

from bridge.native_text import decode_native_text_hex

KEYS = ('ALLIES_WON', 'ALLIES_LOST', 'YOU_WON', 'YOU_LOST', 'RESULT_WON',
        'RESULT_LOSS', 'OTHERRESULT', 'WARSCORE_FROM_BATTLE', 'MESSAGE_HEAD_MIL', 'MESSENGER')
FIELDS = ('language', *KEYS)
FORMAT_PARAMETER_NAMES = ('OTHERRESULT', 'MESSENGER')
LOCALIZATION_KEYS = tuple(key for key in KEYS if key not in FORMAT_PARAMETER_NAMES)
FIELD_ROLES = {name: ('language' if name == 'language' else
    'legacy_cache_probe_of_format_parameter_name' if name in FORMAT_PARAMETER_NAMES else
    'localization_template_input') for name in FIELDS}
FLAGS = {'not_raw_text': True, 'native_formatter_invoked': False,
         'native_branch_selection_verified': False, 'native_line1_verified': False,
         'runtime_popup_verified': False, 'visibility_verified': False,
         'full_display_complete': False, 'complete': False}


def _unknown(reason):
    return {**FLAGS, 'status': 'unknown', 'reason': reason}


def project_outcome_text_sources(decoded):
    if not isinstance(decoded, Mapping):
        return _unknown('OUTCOME_TEXT_INPUT_INVALID')
    wire = decoded.get('wire12')
    if (not isinstance(wire, Mapping) or wire.get('version') != 12
            or wire.get('source') != 'owned_outcome_text'):
        return _unknown('OUTCOME_TEXT_NOT_CAPTURED')
    source = decoded.get('outcome_text')
    try:
        if not isinstance(source, Mapping):
            raise ValueError('source')
        expected = (decoded['observation']['sequence'],
                    decoded['observation']['result']['raw_date'], decoded['context']['kind'])
        actual = tuple(source[key] for key in ('sequence', 'raw_date', 'kind'))
        if (not all(type(value) is int for value in expected + actual) or expected != actual
                or not 0 < actual[0] < 1 << 64 or not 0 <= actual[1] < 1 << 31
                or actual[2] not in (1, 2)):
            raise ValueError('identity')
        failure = source['failure']
        if type(failure) is not int or not 0 <= failure <= 9:
            raise ValueError('failure')
        fields = source['text_fields']
        if not isinstance(fields, Mapping) or set(fields) != set(FIELDS):
            raise ValueError('field set')
        states, output = [], {}
        for name in FIELDS:
            item = fields[name]
            if not isinstance(item, Mapping):
                raise ValueError('field')
            state, length, raw_hex = item['state'], item['length'], item['raw_hex']
            limit = 256 if name == 'language' else 8192
            if (state not in ('known', 'unknown', 'absent') or type(length) is not int
                    or not 0 <= length <= limit or not isinstance(raw_hex, str)
                    or len(raw_hex) != length * 2 or re.fullmatch('[0-9a-fA-F]*', raw_hex) is None):
                raise ValueError('field shape')
            states.append(state)
            if state != 'known':
                if length or raw_hex or (name == 'language' and state == 'absent'):
                    raise ValueError('state canonicalization')
                output[name] = {'status': state, 'reason': ('CACHE_KEY_ABSENT_NOT_UI_HIDDEN'
                               if state == 'absent' else 'OUTCOME_TEXT_GROUP_NOT_CAPTURED_OR_FAILED')}
                continue
            raw = bytes.fromhex(raw_hex)
            if b'\0' in raw or (name == 'language' and re.fullmatch(rb'l_[A-Za-z0-9_]+', raw) is None):
                raise ValueError('text bytes')
            try:
                value = {'status': 'known', 'value': decode_native_text_hex(raw_hex,
                         codec='eu4_escape', max_bytes=limit, max_bytes_limit=8192)}
            except (ValueError, UnicodeError):
                value = {'status': 'unknown', 'reason': 'OUTCOME_TEXT_CODEC_INVALID'}
            output[name] = {'status': 'known', 'length': length, 'raw_hex': raw.hex(),
                            'codec': 'eu4_escape', 'decoded': value,
                            'value_kind': 'cached_template_input_not_selected_final_text'}
        if failure == 0:
            if states[0] != 'known' or any(state not in ('known', 'absent') for state in states[1:]):
                raise ValueError('successful group')
        elif any(state != 'unknown' for state in states):
            raise ValueError('failed group')
    except (KeyError, TypeError, ValueError):
        return _unknown('OUTCOME_TEXT_INVALID_OR_EVENT_MISMATCH')
    return {**FLAGS, 'status': 'known' if failure == 0 else 'unknown',
            'reason': None if failure == 0 else 'OUTCOME_TEXT_CAPTURE_FAILED',
            'source': 'owned_outcome_text', 'capture_stage': 'entry_before_client_gate',
            'sequence': actual[0], 'raw_date': actual[1], 'battle_kind': actual[2],
            'failure': failure, 'text_fields': output,
            'field_roles': dict(FIELD_ROLES), 'localization_keys': list(LOCALIZATION_KEYS),
            'format_parameter_names': list(FORMAT_PARAMETER_NAMES),
            'selection_status': 'unresolved',
            'selection_note': 'Cached alternatives do not identify a native WINORLOSE, title, or observer branch.'}
