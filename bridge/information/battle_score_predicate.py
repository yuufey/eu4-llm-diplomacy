"""Fixed-build 0xCFFF0 reference predicate, without reading live globals.

The native leaf checks the reference's top byte, its type byte, and its signed
slot against three i32 globals. Missing same-event slot values stay unknown.
This does not test human/AI control, country visibility, or current diplomacy.
"""
PREDICATE_RVA = '0xcfff0'
RESERVED_SLOT_RVAS = ('0x233d884', '0x233d8b8', '0x233d8bc')


def score_reference_predicate(reference, reserved_slots=None):
    common = {'basis': 'fixed1374_reference_predicate', 'predicate_rva': PREDICATE_RVA,
              'reserved_slot_rvas': list(RESERVED_SLOT_RVAS), 'native_function_invoked': False}
    if type(reference) is not int or not 0 <= reference < 1 << 64:
        return {**common, 'status': 'unknown', 'reason': 'SCORE_REFERENCE_INVALID'}
    raw = reference.to_bytes(8, 'little')
    slot = int.from_bytes(raw[4:6], 'little', signed=True)
    common.update(reference_full_ref=f'{reference:016x}', signed_slot=slot,
                  metadata_checks_passed=bool(raw[7]) and raw[6] != 7)
    if raw[7] == 0 or raw[6] == 7:
        return {**common, 'status': 'known', 'value': False,
                'reason': 'REFERENCE_METADATA_REJECTED_BEFORE_SLOT_READS'}
    if reserved_slots is None:
        return {**common, 'status': 'unknown', 'reason': 'SAME_EVENT_RESERVED_SLOTS_NOT_CAPTURED'}
    if (not isinstance(reserved_slots, (tuple, list)) or len(reserved_slots) != 3
            or any(type(value) is not int or not -(1 << 31) <= value < 1 << 31
                   for value in reserved_slots)):
        return {**common, 'status': 'unknown', 'reason': 'SCORE_RESERVED_SLOTS_INVALID'}
    return {**common, 'status': 'known', 'value': slot not in reserved_slots,
            'reason': None, 'reserved_slots': list(reserved_slots)}
