"""Compose bounded province leaves without changing archived parent readers.

An extension shares the parent's 512 KiB budget, reuses its country scans, and
rechecks canonical province/FRA/controller identities around every leaf call.
Only leaf failures are local; a failed shared identity retracts the snapshot.
"""
from copy import deepcopy

from . import foreign_country_memory as _shared
from . import province_trade_power_country_memory as _identity


def _unknown(reason):
    return {'status': 'unknown', 'complete': False, 'period': 'current', 'reason': reason}


def _round(limiter, base, province_id, anchor, countries, fields, read_fields):
    result = {'shared_valid': False, 'fields': {f: _unknown('PROVINCE_EXTENSION_UNVERIFIED') for f in fields}}
    try:
        require = _identity._require
        province = _identity._province
        scan = anchor['country_scan']
        observer, controller = (countries['bindings'][role] for role in ('observer', 'controller'))
        bindings = {'observer': observer, 'controller': controller}
        record = int(anchor['province_binding']['record_pointer'], 0)

        def validate():
            fresh = province._province.resolve_provinces(limiter, base, [province_id])
            require(_shared._same_raw(fresh, anchor['province_scan']), 'PROVINCE_BINDING_CHANGED')
            discovery = province._read_discovery(limiter, record, observer['slot'])
            require(_shared._same_raw(discovery, anchor['discovery'])
                    and discovery.get('status') == 'known' and discovery.get('value') is True,
                    'PROVINCE_DISCOVERY_CHANGED')
            reference = limiter.read(record+0x470, 8, 'province_extension.controller_ref')
            require(reference.hex() == controller['fullref_raw_hex'], 'CONTROLLER_REFERENCE_CHANGED')
            admissions = {}
            for role, binding in bindings.items():
                ref = bytes.fromhex(binding['fullref_raw_hex'])
                fresh_country = _identity._rebind(limiter, base, scan, ref, 'province_extension.'+role)
                require(_shared._same_raw(fresh_country, binding), 'COUNTRY_BINDING_CHANGED')
                gate = _identity._admit(limiter, base, scan, fresh_country)
                require(_identity._allowed(gate), 'COUNTRY_ADMISSION_CHANGED')
                if role == 'observer':
                    require(_shared._same_raw(gate, anchor['admission']), 'OBSERVER_ADMISSION_CHANGED')
                admissions[role] = gate
            return {'province': fresh, 'discovery': discovery, 'admissions': admissions,
                    'controller_ref': reference.hex()}

        before = validate()
        try:
            raw = read_fields(limiter, base, anchor['province_binding'], anchor['province_scan'],
                              observer, controller)
            result['fields'] = province._normalize_field_results(raw, fields)
        except Exception:
            result['fields'] = {f: _unknown('PROVINCE_EXTENSION_FIELD_READ_FAILED') for f in fields}
        after = validate()
        require(_shared._same_raw(before, after), 'PROVINCE_EXTENSION_SHARED_EVIDENCE_CHANGED')
        result.update(shared_valid=True, before=before, after=after)
    except Exception:
        result['fields'] = {f: _unknown('PROVINCE_EXTENSION_SHARED_EVIDENCE_UNVERIFIED') for f in fields}
    return result


def extend(reader, base, province_id, *, observer, parent_reader, fields, read_fields):
    fields = _identity._province._valid_field_ids(fields)
    if fields is None or not callable(parent_reader) or not callable(read_fields):
        raise ValueError('PROVINCE_EXTENSION_SCOPE_INVALID')
    limiter = _shared._BoundedReader(_identity._province._ReaderAdapter(reader))
    result = parent_reader(limiter, base, province_id, observer=observer)
    target = result['targets'][0]
    if any(f in target['fields'] for f in fields):
        raise ValueError('PROVINCE_EXTENSION_DUPLICATE_FIELD')
    for field in fields:
        target['fields'][field] = _unknown('PROVINCE_EXTENSION_PARENT_UNVERIFIED')
        target['field_consistency'][field] = {'status': 'unknown'}
    country_rounds = result.get('country_inputs_evidence')
    permitted = (result.get('status') == 'observed' and result.get('consistency', {}).get('status') == 'stable'
                 and country_rounds and all(country_rounds[p].get('shared_valid')
                     and country_rounds[p].get('bindings', {}).get('controller')
                     and _identity._allowed(country_rounds[p].get('admission_before', {}).get('controller', {}))
                     for p in ('pass1', 'pass2'))
                 and target['field_consistency'][_identity.CONTROLLER_FIELD].get('status') != 'changed')
    if not permitted:
        result['budget'] = limiter.summary()
        return result
    rounds = {p: _round(limiter, base, province_id, result['pass_evidence'][p], country_rounds[p], fields, read_fields)
              for p in ('pass1', 'pass2')}
    result.setdefault('province_extension_evidence', {})['|'.join(fields)] = rounds
    result['budget'] = limiter.summary()
    result['errors'].extend(limiter.errors)
    if not all(r['shared_valid'] for r in rounds.values()):
        result['status'] = 'unknown'
        result['consistency'] = {'status': 'unknown', 'shared_mismatch_paths': ['province_extension']}
        for field in target['fields']:
            target['fields'][field] = _unknown('PROVINCE_EXTENSION_SHARED_EVIDENCE_UNVERIFIED')
            target['field_consistency'][field] = {'status': 'unknown'}
        return result
    for field in fields:
        first, second = (rounds[p]['fields'][field] for p in ('pass1', 'pass2'))
        if not _shared._same_raw(first, second):
            target['fields'][field] = _unknown('PROVINCE_EXTENSION_CHANGED_BETWEEN_PASSES')
            target['field_consistency'][field] = {'status': 'changed'}
        else:
            target['fields'][field] = deepcopy(second)
            target['field_consistency'][field] = {'status': 'stable' if second.get('status') == 'known' else 'unknown'}
    return result
