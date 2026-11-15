"""Extend the qualified country-input capture with native calculation gates."""
from copy import deepcopy

from . import foreign_country_memory as _shared
from . import province_trade_power_country_memory as _country
from . import province_trade_power_gates_memory as _gates

FIELDS = (*_country.FIELDS, _gates.FIELD)


def _unknown(reason):
    return {'status': 'unknown', 'complete': False, 'period': 'current',
            'basis': _gates.BASIS, 'reason': reason}


def _round(limiter, base, province_id, anchor, countries):
    result = {'shared_valid': False, 'field': _unknown('CALCULATION_GATES_UNVERIFIED')}
    try:
        province = _country._province
        require = _country._require
        scan = anchor['country_scan']
        observer = countries['bindings']['observer']
        controller = countries['bindings'].get('controller')
        require(controller is not None, 'CONTROLLER_BINDING_UNVERIFIED')
        require(_country._allowed(countries['admission_before']['controller']), 'CONTROLLER_ADMISSION_UNVERIFIED')
        record = int(anchor['province_binding']['record_pointer'], 0)
        refs = {'observer': bytes.fromhex(observer['fullref_raw_hex']),
                'controller': limiter.read(record+0x470, 8, 'province_trade_calculation.controller_ref')}
        bindings = {'observer': observer, 'controller': controller}

        def validate():
            fresh = province._province.resolve_provinces(limiter, base, [province_id])
            require(_shared._same_raw(fresh, anchor['province_scan']), 'PROVINCE_BINDING_CHANGED')
            discovery = province._read_discovery(limiter, record, observer['slot'])
            require(_shared._same_raw(discovery, anchor['discovery']), 'PROVINCE_DISCOVERY_CHANGED')
            require(discovery.get('status') == 'known' and discovery.get('value') is True, 'PROVINCE_NOT_DISCOVERED')
            gates = {}
            for role, binding in bindings.items():
                bound = _country._rebind(limiter, base, scan, refs[role], 'trade_calculation.'+role)
                require(_shared._same_raw(bound, binding), 'COUNTRY_BINDING_CHANGED')
                gate = _country._admit(limiter, base, scan, bound)
                require(_country._allowed(gate), 'COUNTRY_ADMISSION_CHANGED')
                if role == 'observer':
                    require(_shared._same_raw(gate, anchor['admission']), 'OBSERVER_ADMISSION_CHANGED')
                gates[role] = gate
            return {'province': fresh, 'discovery': discovery, 'admissions': gates}

        before = validate()
        flags = limiter.read(record+0x958, 1, 'province_trade_calculation.flags958')
        owner = None
        result['field'] = _gates.read_fields(limiter, base, anchor['province_binding'], controller)[_gates.FIELD]
        if result['field'].get('reason') == 'OWNER_ADMISSION_NOT_ESTABLISHED':
            refs['owner'] = limiter.read(record+0x468, 8, 'province_trade_calculation.owner_ref')
            owner = _country._rebind(limiter, base, scan, refs['owner'], 'trade_calculation.owner')
            owner_gate = _country._admit(limiter, base, scan, owner)
            if not _country._allowed(owner_gate):
                result['field'] = _unknown('OWNER_ADMISSION_NOT_ESTABLISHED')
                owner = None
            else:
                bindings['owner'] = owner
                before = validate()
                result['field'] = _gates.read_fields(limiter, base, anchor['province_binding'], controller, owner)[_gates.FIELD]
        after_flags = limiter.read(record+0x958, 1, 'province_trade_calculation.flags958_after')
        after_controller_ref = limiter.read(record+0x470, 8, 'province_trade_calculation.controller_ref_after')
        require(after_controller_ref == refs['controller'], 'CONTROLLER_REFERENCE_CHANGED')
        if 'owner' in refs:
            after_owner_ref = limiter.read(record+0x468, 8, 'province_trade_calculation.owner_ref_after')
            require(after_owner_ref == refs['owner'], 'OWNER_REFERENCE_CHANGED')
        after = validate()
        require(_shared._same_raw(before, after), 'CALCULATION_SHARED_EVIDENCE_CHANGED')
        if flags != after_flags:
            result['field'] = _unknown('CALCULATION_FLAGS_CHANGED')
        result.update(shared_valid=True, before=before, after=after, bindings=deepcopy(bindings))
    except _country._ObserverFailure:
        result['field'] = _unknown('OBSERVER_ROLE_NOT_VERIFIED')
    except Exception:
        result['field'] = _unknown('CALCULATION_SHARED_EVIDENCE_UNVERIFIED')
    return result


def read_two_pass(reader, base, province_id, *, observer='FRA'):
    limiter = _shared._BoundedReader(_country._province._ReaderAdapter(reader))
    result = _country.read_two_pass(limiter, base, province_id, observer=observer)
    target = result['targets'][0]
    target['fields'][_gates.FIELD] = _unknown('CALCULATION_PARENT_UNVERIFIED')
    target['field_consistency'][_gates.FIELD] = {'status': 'unknown'}
    if result.get('status') != 'observed' or result.get('consistency', {}).get('status') != 'stable':
        result['budget'] = limiter.summary()
        return result
    country_rounds = result.get('country_inputs_evidence')
    if (not country_rounds or any(not country_rounds[p].get('shared_valid') for p in ('pass1', 'pass2'))
            or target['field_consistency'][_country.CONTROLLER_FIELD].get('status') == 'changed'
            or any(not country_rounds[p].get('bindings', {}).get('controller')
                   or not _country._allowed(country_rounds[p].get('admission_before', {}).get('controller', {}))
                   for p in ('pass1', 'pass2'))):
        result['budget'] = limiter.summary()
        return result
    rounds = {p: _round(limiter, base, province_id, result['pass_evidence'][p], country_rounds[p])
              for p in ('pass1', 'pass2')}
    result['calculation_gate_evidence'] = rounds
    result['budget'] = limiter.summary()
    result['errors'].extend(limiter.errors)
    if not all(r['shared_valid'] for r in rounds.values()):
        # A denied controller is a missing calculation input. A changed shared
        # observer/province identity invalidates the full composite snapshot.
        result['status'] = 'unknown'
        result['consistency'] = {'status': 'unknown', 'shared_mismatch_paths': ['calculation_gates']}
        for field in FIELDS:
            target['fields'][field] = _unknown('CALCULATION_SHARED_EVIDENCE_UNVERIFIED')
            target['field_consistency'][field] = {'status': 'unknown'}
        return result
    first, second = (rounds[p]['field'] for p in ('pass1', 'pass2'))
    if not _shared._same_raw(first, second):
        target['fields'][_gates.FIELD] = _unknown('CALCULATION_GATES_CHANGED_BETWEEN_PASSES')
        target['field_consistency'][_gates.FIELD] = {'status': 'changed'}
    else:
        target['fields'][_gates.FIELD] = deepcopy(second)
        target['field_consistency'][_gates.FIELD] = {'status': 'stable' if second.get('status') == 'known' else 'unknown'}
    return result
