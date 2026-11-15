"""Describe flag setter operands copied with a same-event formatter container."""
from copy import deepcopy

from work import information_battle_flag_inputs_wire as wire
from .battle_control_frames import _parse_native_i32
from .battle_display_bindings import PROVENANCE
from .battle_text import project_template

FLAGS = {'native_call_observed': False, 'runtime_widget_state_verified': False,
         'full_display_complete': False}
KEYS = ('OURFLAG', 'ENEMYFLAG')


def _unknown(reason, **metadata):
    return {**FLAGS, 'status': 'unknown', 'reason': reason, **metadata}


def _request(entry, pair, decoded):
    common = {**FLAGS, 'pair_index': entry['pair_index'], 'mode': wire.MODE_NAMES[entry['mode']]}
    if entry['mode'] == 2:
        side = decoded['context']['sides'][entry['side']]
        participants = side.get('participants') or {}
        ref = entry['country_ref']
        if (side.get('present') is not True or participants.get('complete') is not True
                or ref not in participants.get('full_refs', [])):
            return _unknown('FLAG_COUNTRY_OUTSIDE_VERIFIED_COMBAT_SIDE', **common)
        slot = (ref >> 32) & 0xffff
        return {**common, 'status': 'known', 'country': ref.to_bytes(8, 'little')[:3].decode('ascii'),
                'country_ref': f'{ref:016x}', 'virtual_setter_requests': [
                    {'vtable_offset': '0x218', 'arg_full_ref': f'{ref:016x}', 'by_reference': True},
                    {'vtable_offset': '0x1b0', 'arg_i32': slot if slot < 0x8000 else slot - 0x10000}]}
    if entry['mode'] == 3:
        requested = (~entry['rebel_raw']) & 0xffffffff
        values = {'rebel_flag_raw_u32': entry['rebel_raw']}
    else:
        parsed = _parse_native_i32(bytes.fromhex(pair['value_raw_hex']))
        if parsed['status'] != 'known':
            return _unknown(parsed['reason'], **common)
        number = parsed['parsed']['signed_i32']
        requested = (number if number >= 1 else number - 1) & 0xffffffff
        values = {'parsed': parsed['parsed']}
    return {**common, **values, 'status': 'known', 'helper_rva': '0x10b41c0',
            'requested_flag_id_u32': requested,
            'basis': 'copied_flag_operand_with_fixed1374_helper_argument_model'}


def project_flag_inputs(decoded):
    metadata = decoded.get('wire15', {})
    if metadata.get('version') != 15 or metadata.get('source') != wire.SOURCE:
        return _unknown('FLAG_INPUTS_NOT_CAPTURED')
    try:
        identity = wire._base_identity(decoded)
        snapshot, entries = wire._normalize_snapshot(decoded['flag_inputs'], identity)
        if snapshot['state'] == 'unknown':
            return _unknown('FLAG_INPUT_CAPTURE_FAILED', failure=snapshot['failure'])
        if snapshot['state'] == 'not_applicable':
            return {**FLAGS, 'status': 'not_applicable', 'controls': []}
        template = project_template(decoded)
        if (template.get('status') != 'known'
                or template['value'].get('source_kind') not in (None, 'formatter_container_before_cleanup')):
            return _unknown('FLAG_INPUT_TEMPLATE_NOT_CAPTURED')
        pairs = template['value']['pairs']
        expected = [(index, KEYS.index(bytes.fromhex(pair['key_raw_hex']).decode('ascii')))
                    for index, pair in enumerate(pairs)
                    if pair['key_raw_hex'] in (b'OURFLAG'.hex(), b'ENEMYFLAG'.hex())]
        if [(entry['pair_index'], entry['side']) for entry in entries] != expected:
            return _unknown('FLAG_INPUT_PAIR_CORRESPONDENCE_MISMATCH')
        controls = []
        for side, key in enumerate(KEYS):
            requests = [_request(entry, pairs[entry['pair_index']], decoded)
                        for entry in entries if entry['side'] == side]
            controls.append({**FLAGS, 'status': 'known' if all(row['status'] == 'known' for row in requests) else 'partial',
                'template_key': key, 'request_kind': 'typed_flag_inputs',
                'basis': 'copied_formatter_typed_flag_inputs_with_fixed1374_setter_model',
                'binding_provenance': deepcopy(PROVENANCE), 'requests': requests,
                'list_reset_request': {'vtable_offset': '0x278', 'arguments': []}})
        return {**FLAGS, 'status': 'known', 'sequence': snapshot['sequence'], 'raw_date': snapshot['raw_date'],
                'battle_kind': snapshot['kind'], 'capture_stage': 'formatter_container_before_cleanup',
                'controls': controls}
    except (KeyError, TypeError, ValueError, IndexError, UnicodeError):
        return _unknown('FLAG_INPUTS_INVALID')


__all__ = ['project_flag_inputs']
