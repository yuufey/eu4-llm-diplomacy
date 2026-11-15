"""Project a separately requested native render with its owned input basis."""
from collections.abc import Mapping

from bridge.native_text import decode_native_text_hex
from .battle_body_candidate import _raw, project_body_candidate
from .battle_display_context import project_display_context

FLAGS = {'is_native_raw_text': False, 'native_line1_verified': False,
         'native_name_handoff_verified': False, 'runtime_popup_verified': False,
         'visibility_verified': False, 'complete': False, 'full_display_complete': False}


def _unknown(reason, **metadata):
    return {**FLAGS, 'status': 'unknown', 'reason': reason, **metadata}


def project_independent_line(decoded):
    wire = decoded.get('wire14', {}) if isinstance(decoded, Mapping) else {}
    if not isinstance(wire, Mapping) or wire.get('version') != 14 or wire.get('source') != 'owned_independent_line':
        return _unknown('INDEPENDENT_LINE_NOT_CAPTURED')
    source = decoded.get('independent_line')
    if not isinstance(source, Mapping):
        return _unknown('INDEPENDENT_LINE_INVALID')
    if (type(source.get('flags')) is not int or not 0 <= source['flags'] <= 15
            or type(source.get('failure')) is not int or not 0 <= source['failure'] <= 12):
        return _unknown('INDEPENDENT_LINE_INVALID')
    if source.get('state') == 'unknown':
        return _unknown('INDEPENDENT_LINE_CAPTURE_FAILED', failure=source.get('failure'),
                        native_formatter_invoked=bool(source.get('flags', 0) & 1))
    context = project_display_context(decoded)
    candidate = project_body_candidate(decoded)
    try:
        identity = tuple(source[key] for key in ('sequence', 'raw_date', 'kind'))
        expected = tuple(context[key] for key in ('sequence', 'raw_date', 'battle_kind'))
        if (source.get('state') != 'known' or source.get('failure') != 0 or source.get('flags') != 15
                or type(source['transform_mode']) is not int or source['transform_mode'] not in (1, 2)
                or not all(type(value) is int for value in identity) or identity != expected
                or context.get('status') != 'known' or candidate.get('status') != 'known'
                or source['transform_mode'] != decoded['name_sources']['transform_mode']):
            return _unknown('INDEPENDENT_LINE_SOURCE_MISMATCH')
        fields = source['text_fields']
        raw = {}
        for name in ('language', 'definition_key', 'body_template', 'name_input', 'output'):
            field = fields[name]
            value = _raw(field['raw_hex'])
            if (field.get('state') != 'known' or type(field['length']) is not int
                    or field['length'] != len(value)):
                return _unknown('INDEPENDENT_LINE_TEXT_INVALID')
            raw[name] = value
        for name in ('language', 'definition_key', 'body_template'):
            field = context['text_fields'][name]
            if field.get('status') != 'known' or raw[name] != _raw(field['raw_hex']):
                return _unknown('INDEPENDENT_LINE_TEMPLATE_MISMATCH')
        if raw['body_template'] != b'$NAME$' or raw['name_input'] != _raw(candidate['raw_hex']):
            return _unknown('INDEPENDENT_LINE_NAME_INPUT_MISMATCH')
        value = decode_native_text_hex(raw['output'].hex(), codec='eu4_escape', max_bytes=8192)
    except (KeyError, TypeError, ValueError, UnicodeError):
        return _unknown('INDEPENDENT_LINE_INVALID')
    return {**FLAGS, 'status': 'known', 'reason': None, 'text': value,
            'raw_hex': raw['output'].hex(), 'codec': 'eu4_escape',
            'sequence': identity[0], 'raw_date': identity[1], 'battle_kind': identity[2],
            'basis': 'native_formatter_on_owned_same_event_name_candidate', 'derived': True,
            'native_formatter_invoked': True, 'native_output_copied': True,
            'input_source': candidate['input_source'], 'input_basis': candidate['input_basis'],
            'input_value_stage': ('plugin_pre_assignment_text' if source['transform_mode'] == 2
                                  else 'derived_original_helper_inputs'),
            'name_input_raw_hex': raw['name_input'].hex(),
            'source_path': 'B04.details.value.independent_line'}
