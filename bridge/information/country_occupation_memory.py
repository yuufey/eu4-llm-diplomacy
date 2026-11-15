"""Summarize control of the selected country's discovered owned provinces."""
from collections import Counter

from . import province_discovery_bitmap_memory as _discovery
from . import province_reference_memory as _provinces


def read_occupation(read, module_base, binding, observer, rows, spec, *,
                    blockade_spec=None, include_occupation=True):
    pointer = int(binding['country_pointer'], 0)
    vector = int.from_bytes(read.read(pointer + spec['owned_vector_offset'], 8,
        'occupation.owned_vector'), 'little')
    count = int.from_bytes(read.read(pointer + spec['owned_count_offset'], 4,
        'occupation.owned_count'), 'little', signed=True)
    if not 0 <= count <= spec['max_owned_provinces']:
        raise ValueError('OCCUPATION_OWNED_COUNT_INVALID')
    raw = read.read(vector, count * 4, 'occupation.owned_ids') if count else b''
    ids = [int.from_bytes(raw[offset:offset + 4], 'little', signed=True)
           for offset in range(0, len(raw), 4)]
    if len(set(ids)) != count or any(province < 1 for province in ids):
        raise ValueError('OCCUPATION_OWNED_IDS_INVALID')
    target_ref = int(binding['fullref'], 0)
    observed = 0
    blockade_observed = blockaded = 0
    occupiers = Counter()
    for start in range(0, count, _provinces.MAX_REQUESTED_PROVINCES):
        batch = ids[start:start + _provinces.MAX_REQUESTED_PROVINCES]
        resolved = _provinces.resolve_provinces(read.read, module_base, batch)
        if resolved.get('status') != 'observed':
            raise ValueError('OCCUPATION_PROVINCE_BINDING_UNAVAILABLE')
        for province in batch:
            record = int(resolved['requested'][str(province)]['record_pointer'], 0)
            discovery = _discovery.read_discovery(read, record, observer['slot'], module_base)
            if discovery.get('status') != 'known' or discovery.get('value') is not True:
                continue
            owner = int.from_bytes(read.read(record + spec['owner_offset'], 8,
                'occupation.owner'), 'little')
            if owner != target_ref:
                raise ValueError('OCCUPATION_OWNERSHIP_CHANGED')
            if blockade_spec is not None:
                try:
                    flag = read.read(record + blockade_spec['flags_offset'], 1,
                                     'occupation.blockade_flags')[0]
                    blockade_observed += 1
                    blockaded += bool(flag & blockade_spec['mask'])
                except Exception:
                    pass
            if not include_occupation:
                continue
            controller = int.from_bytes(read.read(record + spec['controller_offset'], 8,
                'occupation.controller'), 'little')
            country = rows.get(hex(controller))
            if not country or not country.get('tag'):
                continue
            observed += 1
            if controller != owner:
                occupiers[country['tag']] += 1
    result = {'status': 'known', 'complete': observed == count, 'value': {
        'owned_provinces': count, 'observed_provinces': observed,
        'occupied_provinces': sum(occupiers.values()),
        'occupiers': dict(sorted(occupiers.items()))}}
    if blockade_spec is not None:
        result['blockades'] = {'status': 'known', 'complete': blockade_observed == count,
            'value': {'owned_provinces': count, 'observed_provinces': blockade_observed,
                      'blockaded_provinces': blockaded}}
    return result
