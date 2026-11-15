"""Project copied, pre-gate name inputs; derived names remain candidates."""
from collections.abc import Mapping
import re

from bridge.native_text import decode_native_text_hex
from .battle_body_candidate import _decode_output, _parts, _render_parts, OUTPUT_LIMIT_BYTES

FIELDS = ('owner_name', 'global_name', 'battle_of_template', 'language')
# IBOW11 mode 2 is qualified by this exact native title-plan plugin hash.
# Another plugin must receive a distinct qualification, not reuse this mode.
PINNED_PLUGIN_SHA256 = 'a73a8b6c82e620fc7d577bdb64df731b779a72bb43c2363a11ed12be23a9d819'
FLAGS = {'not_raw_text': True, 'native_helper_invoked': False,
         'native_name_handoff_verified': False, 'native_line1_verified': False,
         'full_display_complete': False, 'visibility_verified': False, 'complete': False}


def _unknown(reason):
    return {**FLAGS, 'status': 'unknown', 'reason': reason}


def project_name_sources(decoded):
    if not isinstance(decoded, Mapping):
        return _unknown('NAME_SOURCES_INPUT_INVALID')
    wire = decoded.get('wire11', {})
    source = decoded.get('name_sources')
    if (not isinstance(wire, Mapping) or wire.get('version') != 11
            or wire.get('source') != 'owned_name_sources'):
        return _unknown('NAME_SOURCES_NOT_CAPTURED')
    if not isinstance(source, Mapping):
        return _unknown('NAME_SOURCES_INVALID')
    try:
        expected = (decoded['observation']['sequence'],
                    decoded['observation']['result']['raw_date'], decoded['context']['kind'])
        actual = tuple(source[key] for key in ('sequence', 'raw_date', 'kind'))
        if (not all(type(v) is int for v in expected + actual) or actual != expected
                or not 0 < actual[0] < 1 << 64 or not 0 <= actual[1] < 1 << 31
                or actual[2] not in (1, 2)):
            raise ValueError('identity')
        raw_failure, prefix_failure = source['raw_failure'], source['prefix_failure']
        transform = source['transform_mode']
        if (type(raw_failure) is not int or not 0 <= raw_failure <= 12
                or type(prefix_failure) is not int or not 0 <= prefix_failure <= 9
                or type(transform) is not int or transform not in (0, 1, 2)):
            raise ValueError('failure or transform')
        fields = source['text_fields']
        if not isinstance(fields, Mapping) or set(fields) != set(FIELDS):
            raise ValueError('fields')
        output = {}
        for name in FIELDS:
            field = fields[name]
            if not isinstance(field, Mapping):
                raise ValueError('field')
            state, length, raw_hex = field['state'], field['length'], field['raw_hex']
            limit = 256 if name == 'language' else 8192
            if (state not in ('unknown', 'known', 'absent') or type(length) is not int
                    or not 0 <= length <= limit or not isinstance(raw_hex, str)
                    or len(raw_hex) != 2 * length or re.fullmatch('[0-9a-fA-F]*', raw_hex) is None):
                raise ValueError('field shape')
            if state != 'known':
                if length or raw_hex or (state == 'absent' and name != 'battle_of_template'):
                    raise ValueError('noncanonical unknown/absent')
                output[name] = {'status': 'unknown' if state == 'unknown' else 'absent',
                                'reason': ('NAME_SOURCE_NOT_CAPTURED_OR_READ_FAILED'
                                           if state == 'unknown' else 'BATTLE_OF_CACHE_ENTRY_ABSENT')}
                continue
            raw = bytes.fromhex(raw_hex)
            if b'\0' in raw:
                raise ValueError('NUL')
            if name == 'language' and re.fullmatch(rb'l_[A-Za-z0-9_]+', raw) is None:
                raise ValueError('language')
            try:
                text = {'status': 'known', 'value': decode_native_text_hex(
                    raw_hex, codec='eu4_escape', max_bytes=limit, max_bytes_limit=8192)}
            except (ValueError, UnicodeError):
                text = {'status': 'unknown', 'reason': 'NAME_SOURCE_TEXT_CODEC_INVALID'}
            output[name] = {'status': 'known', 'length': length, 'raw_hex': raw.hex(),
                            'codec': 'eu4_escape', 'decoded': text}
        states = [fields[name]['state'] for name in FIELDS]
        if not ((states[:2] == ['known', 'known'] and raw_failure == 0)
                or (states[:2] == ['unknown', 'unknown'] and raw_failure != 0)):
            raise ValueError('raw group')
        if not ((states[2] in ('known', 'absent') and states[3] == 'known' and prefix_failure == 0)
                or (states[2:] == ['unknown', 'unknown'] and prefix_failure != 0)):
            raise ValueError('prefix group')
    except (KeyError, TypeError, ValueError):
        return _unknown('NAME_SOURCES_INVALID_OR_EVENT_MISMATCH')
    return {**FLAGS, 'status': 'known', 'source': 'owned_name_sources',
            'capture_stage': 'entry_before_client_gate',
            'sequence': actual[0], 'raw_date': actual[1], 'battle_kind': actual[2],
            'raw_failure': raw_failure, 'prefix_failure': prefix_failure,
            'transform_mode': {0: 'unknown', 1: 'original_helper', 2: 'pinned_plugin_present'}[transform],
            'text_fields': output}


def project_name_candidate(decoded):
    source = project_name_sources(decoded)
    if source.get('status') != 'known':
        return _unknown(source['reason'])
    if source['transform_mode'] == 'unknown':
        return _unknown('NAME_SOURCE_TRANSFORM_UNQUALIFIED')
    fields = source['text_fields']
    if any(fields[name].get('status') != 'known' for name in FIELDS):
        return _unknown('NAME_SOURCE_CANDIDATE_INPUT_UNKNOWN_OR_ABSENT')
    try:
        template = bytes.fromhex(fields['battle_of_template']['raw_hex'])
        parts, count = _parts(template)
        if count:
            raise ValueError('zero-argument prefix')
        prefix = _render_parts(parts, b'')
        tail = bytes.fromhex(fields['global_name']['raw_hex']) + bytes.fromhex(fields['owner_name']['raw_hex'])
        plugin = source['transform_mode'] == 'pinned_plugin_present'
        if plugin and not tail:
            return _unknown('NAME_SOURCE_PLUGIN_TAIL_EMPTY')
        # This is the plugin's temporary string value, before its separate
        # game-String32 assignment. Do not emulate HeapAlloc or its fixed
        # 255-byte allocation; large logical values remain available here.
        output = tail[1:] + prefix if plugin else prefix + tail
        if len(output) + 1 >= OUTPUT_LIMIT_BYTES:
            raise ValueError('expansion limit')
        text = _decode_output(output)
    except (ValueError, UnicodeError):
        return _unknown('NAME_SOURCE_CANDIDATE_FORMAT_OR_CODEC_UNSUPPORTED')
    result = {**FLAGS, 'status': 'known', 'raw_hex': output.hex(), 'codec': 'eu4_escape',
            'decoded': {'status': 'known', 'value': text},
            'sequence': source['sequence'], 'raw_date': source['raw_date'],
            'battle_kind': source['battle_kind'], 'input_source': 'owned_name_sources_candidate',
            'basis': ('derived_pinned_plugin_pre_assignment_byte_order' if plugin
                      else 'derived_original_helper_zero_argument_prefix_and_raw_concat')}
    if plugin:
        result.update(plugin_sha256=PINNED_PLUGIN_SHA256, value_stage='plugin_pre_assignment_text',
                      native_assignment_verified=False,
                      native_assignment_buffer_limit_exceeded=len(output) >= 255)
    return result
