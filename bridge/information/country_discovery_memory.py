"""Private two-pass projection of knows_country over ordinary table rows.

This enumerates canonical country references, not active countries or nations
visible in a rendered UI. The leaf uses the constructor-linked native
knows_country predicate. No other country's viewpoint is exported.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib

from . import country_reference_memory as _country
from . import foreign_technology_capture as _owner
from .foreign_country_memory import _tag_ok
from . import province_discovery_memory as _shared
from .model import canonical


SCHEMA = 'information.country_discovery_memory.v1'
OBSERVER = 'FRA'
MAX_READ_CALLS = _shared.MAX_READ_CALLS
MAX_TOTAL_READ_BYTES = _shared.MAX_TOTAL_READ_BYTES


def _unknown(reason, passes, budget, observer):
    return {'schema': SCHEMA, 'status': 'unknown', 'observer': observer if _tag_ok(observer) else None,
        'reason': str(reason)[:160], 'complete': False, 'domain_complete': False,
        'passes': passes, 'budget': budget.summary(), 'consistency': {'status': 'unknown'}}


def _candidates(scan):
    candidates = []
    excluded = {'empty_rows': 0, 'unclassified_rows': 0, 'nonordinary_rows': 0}
    seen = set()
    for row in scan['rows']:
        if row['country_pointer'] is None:
            excluded['empty_rows'] += 1
            continue
        if row['tag'] is None:
            excluded['unclassified_rows'] += 1
            continue
        fullref = int(row['fullref'], 16)
        if (fullref >> 56) == 0 or ((fullref >> 48) & 255) == 7:
            excluded['nonordinary_rows'] += 1
            continue
        if type(row['slot']) is not int or row['fullref_slot'] != row['slot']:
            raise ValueError('COUNTRY_CANDIDATE_SLOT_MISMATCH')
        if row['tag'] in seen:
            raise ValueError('COUNTRY_CANDIDATE_TAG_DUPLICATE')
        seen.add(row['tag'])
        candidates.append({key: deepcopy(row[key]) for key in
            ('tag', 'slot', 'country_pointer', 'fullref', 'fullref_raw_hex')})
    return candidates, excluded


def _one_pass(reader, base, number, *, existence_reader=None, observer=OBSERVER):
    from .country_knowledge_memory import read_knowledge

    context = _owner._context(reader, base)
    physical_raw = bytes.fromhex(context['physical_client_reference_raw_hex'])
    if len(physical_raw) != 8:
        raise ValueError('PHYSICAL_CLIENT_REFERENCE_INVALID')
    physical_ref = int.from_bytes(physical_raw, 'little')
    physical_tag = _country._tag_from_fullref(physical_ref)
    if physical_tag is None:
        raise ValueError('PHYSICAL_CLIENT_TAG_INVALID')
    tags = [observer] if physical_tag == observer else [observer, physical_tag]
    scan = _country.resolve_countries(reader.read, base, tags,
        expected_refs={physical_tag: physical_ref})
    if scan.get('status') != 'observed':
        raise ValueError('COUNTRY_BINDINGS_UNAVAILABLE')
    binding = _shared._country_binding(scan, observer)
    physical = _shared._country_binding(scan, physical_tag)
    gate = _shared._admission_summary(_owner._bound_admission(reader.read, base, scan, observer, observer))
    role = gate['observer_nonplayer_role']
    result = {'pass': number, 'status': 'unknown', 'reason': None,
        'bindings': {'observer': binding, 'physical_client': physical}, 'admission': gate,
        'context': {'before': context, 'after': None}, 'header': None, 'candidates': []}
    if (binding is None or physical is None or gate.get('status') != 'known'
            or gate.get('admitted') is not True or role.get('verified') is not True
            or role.get('observer') != observer or type(role.get('slot')) is not int
            or role['slot'] != binding.get('slot')):
        result['reason'] = ('FRA_SELF_ADMISSION_OR_ROLE_NOT_VERIFIED' if observer == OBSERVER
                            else 'OBSERVER_SELF_ADMISSION_OR_ROLE_NOT_VERIFIED')
        return result
    if existence_reader is not None:
        existence = existence_reader(reader, base, binding)
        result['observer_existence'] = existence
        if existence.get('status') != 'known' or existence.get('value') is not True:
            result['reason'] = 'OBSERVER_EXISTENCE_NOT_VERIFIED'
            return result
    world = int(context['world_pointer'], 16)
    header = _shared._read_header(reader, base, world)
    result['header'] = {'before': header, 'after': None}
    candidates, excluded = _candidates(scan)
    result['excluded_rows'] = excluded
    result['country_table_count'] = scan['count']
    result['country_index_sha256'] = hashlib.sha256(canonical({key: scan[key] for key in
        ('database_global_raw_hex', 'table_pointer_raw_hex', 'count_raw_hex', 'rows')}).encode()).hexdigest()
    passes_left = 2 if number == 1 else 1
    # Five leaf reads: capital pointer, ID echo, flags, bitmap header and word.
    # Keep the full second-pass country-table reserve and the existing hard cap.
    reserve_calls = 8448 if number == 1 else 0
    reserve_bytes = 67584 if number == 1 else 0
    candidate_calls = 5 if existence_reader is None else 7
    candidate_bytes = 41 if existence_reader is None else 46
    if reader.calls + len(candidates) * candidate_calls * passes_left + reserve_calls > MAX_READ_CALLS:
        result['reason'] = 'COUNTRY_SCAN_EXCEEDS_CALL_BUDGET'
        return result
    if reader.bytes_requested + len(candidates) * candidate_bytes * passes_left + reserve_bytes > MAX_TOTAL_READ_BYTES:
        result['reason'] = 'COUNTRY_SCAN_EXCEEDS_BYTE_BUDGET'
        return result
    for candidate in candidates:
        existence = None
        if existence_reader is not None:
            existence = existence_reader(reader, base, candidate)
            if existence.get('status') != 'known' or type(existence.get('value')) is not bool:
                result['candidates'].append({'tag': candidate['tag'], 'slot': candidate['slot'],
                    'status': 'unknown', 'reason': str(existence.get('reason', 'COUNTRY_EXISTENCE_UNKNOWN'))[:160]})
                result['reason'] = 'COUNTRY_EXISTENCE_UNKNOWN'
                return result
            if existence['value'] is False:
                result['candidates'].append({'tag': candidate['tag'], 'slot': candidate['slot'],
                    'status': 'known', 'value': False, 'exists': False, 'knowledge_evaluated': False,
                    'sample_sha256': hashlib.sha256(canonical(existence).encode()).hexdigest()})
                continue
        options = {'observer_tag': observer} if observer != OBSERVER else {}
        known = read_knowledge(reader, base, binding, candidate, header, **options)
        row = {'tag': candidate['tag'], 'slot': candidate['slot'], 'status': known.get('status')}
        if known.get('status') != 'known' or type(known.get('value')) is not bool:
            row['reason'] = str(known.get('reason', 'COUNTRY_KNOWLEDGE_UNKNOWN'))[:160]
            result['candidates'].append(row)
            result['reason'] = 'COUNTRY_KNOWLEDGE_UNKNOWN'
            return result
        sample = known
        if existence is not None:
            row.update(exists=True, knowledge_evaluated=True)
            sample = {'existence': existence, 'knowledge': known}
        row.update(value=known['value'], sample_sha256=hashlib.sha256(canonical(sample).encode()).hexdigest())
        result['candidates'].append(row)
    after = _owner._context(reader, base)
    after_header = _shared._read_header(reader, base, world)
    result['context']['after'] = after
    result['header']['after'] = after_header
    if not _owner._same(context, after):
        result['reason'] = 'CONTEXT_CHANGED_DURING_PASS'
    elif not _owner._same(header, after_header):
        result['reason'] = 'PROVINCE_HEADER_CHANGED_DURING_PASS'
    else:
        result.update(status='known', reason=None)
    return result


def _read_two_pass(reader, module_base, observer=OBSERVER, *, existence_reader=None, observer_scoped=False):
    budget = _shared._BudgetReader(reader)
    passes = []
    if not _tag_ok(observer) or (not observer_scoped and observer != OBSERVER):
        return _unknown('OBSERVER_SCOPE_INVALID', passes, budget, observer)
    if (type(module_base) is not int or not _country._is_user_address(module_base)
            or module_base & 7):
        return _unknown('MODULE_BASE_INVALID', passes, budget, observer)
    try:
        for number in (1, 2):
            current = _one_pass(budget, module_base, number,
                                existence_reader=existence_reader, observer=observer)
            passes.append(current)
            if current['status'] != 'known':
                return _unknown(current['reason'], passes, budget, observer)
        keys = ('bindings', 'admission', 'context', 'header', 'candidates',
                'excluded_rows', 'country_table_count', 'country_index_sha256')
        if existence_reader is not None:
            keys += ('observer_existence',)
        changed = [key for key in keys if not _owner._same(passes[0].get(key), passes[1].get(key))]
        if changed:
            result = _unknown('TWO_PASS_EVIDENCE_CHANGED', passes, budget, observer)
            result['consistency'] = {'status': 'changed', 'changed_components': changed}
            return result
    except Exception as error:
        reason = str(error) if isinstance(error, (ValueError, _shared._ReadStop)) else type(error).__name__
        return _unknown(reason, passes, budget, observer)
    values = sorted(row['tag'] for row in passes[1]['candidates'] if row['value'])
    result = {'schema': SCHEMA, 'status': 'known', 'observer': observer, 'value': values,
        'basis': 'native_knows_country_for_ordinary_canonical_table_candidates',
        'complete': False, 'domain_complete': False,
        'scope': {'candidate_count': len(passes[1]['candidates']),
            'country_table_count': passes[1]['country_table_count'],
            'excluded_rows': deepcopy(passes[1]['excluded_rows']),
            'country_existence_filter_applied': existence_reader is not None, 'domain_complete': False},
        'consistency': {'status': 'stable', 'changed_components': []},
        'passes': passes, 'budget': budget.summary()}
    if existence_reader is not None:
        result['scope']['existing_candidate_count'] = sum(row['exists'] for row in passes[1]['candidates'])
        result['basis'] = 'native_exists_and_knows_country_for_ordinary_canonical_table_candidates'
    return result


def read_two_pass(reader, module_base, observer=OBSERVER):
    return _read_two_pass(reader, module_base, observer)


__all__ = ['SCHEMA', 'read_two_pass']
