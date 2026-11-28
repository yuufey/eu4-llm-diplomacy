"""Compose province inputs and admitted controller/observer country inputs.

Retain the parent's complete country scan for admission; revalidate the two
selected rows by indexed fullref lookup rather than scanning the table again.
One shared 512 KiB limiter covers the parent and both extension rounds.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from . import country_province_trade_power_memory as _country_leaf
from . import foreign_country_memory as _shared
from . import foreign_technology_capture as _owner
from . import province_state_memory as _province
from . import province_trade_power_inputs_memory as _inputs

CONTROLLER_FIELD = 'G02.controller_global_province_trade_power_modifier'
OBSERVER_FIELD = 'G02.observer_global_province_trade_power_modifier'
COUNTRY_FIELDS = (CONTROLLER_FIELD, OBSERVER_FIELD)
FIELDS = (*_inputs.SUPPORTED_FIELDS, *COUNTRY_FIELDS)
_LEAF_FIELD = 'G02.country_global_province_trade_power_modifier'
_CONTROLLER_IDENTITY = 'G02.controller'
_BASIS = 'native_country_province_trade_power_modifier_processor_absent'


class _ObserverFailure(ValueError):
    pass


def _unknown(reason):
    return {'status': 'unknown', 'complete': False, 'reason': reason,
            'basis': _BASIS, 'period': 'current'}


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _binding_from_row(row):
    return {key: row[source] for key, source in (
        ('tag', 'tag'), ('slot', 'slot'), ('country_pointer', 'country_pointer'),
        ('country_fullref_address', 'fullref_address'), ('fullref', 'fullref'),
        ('fullref_raw_hex', 'fullref_raw_hex'), ('table_entry_address', 'table_entry_address'),
        ('table_entry_raw_hex', 'table_entry_raw_hex'))}


def _rebind(limiter, base, scan, raw_ref, label):
    """Require the retained scan row to still be the indexed canonical row."""
    resolved = _province._resolve_country_reference(limiter, base, raw_ref, label)
    _require(resolved.get('status') == 'known', 'COUNTRY_BINDING_UNVERIFIED')
    raw = resolved['raw_inputs']
    _require(scan.get('status') == 'observed', 'COUNTRY_SCAN_UNVERIFIED')
    _require(all(scan.get(key) == raw.get(key) for key in ('database', 'table', 'count')),
             'COUNTRY_SCAN_METADATA_CHANGED')
    slot = raw['slot']
    rows = scan.get('rows')
    _require(isinstance(rows, list) and 0 <= slot < len(rows), 'COUNTRY_SCAN_ROW_MISSING')
    row = rows[slot]
    _require(isinstance(row, Mapping), 'COUNTRY_SCAN_ROW_MISSING')
    _require(all(row.get(key) == raw.get(key) for key in
                 ('slot', 'tag', 'country_pointer', 'fullref', 'table_entry_address',
                  'table_entry_raw_hex')), 'COUNTRY_SCAN_ROW_CHANGED')
    _require(row.get('fullref_raw_hex') == raw_ref.hex()
             and row.get('fullref_address') == raw.get('canonical_fullref_address'),
             'COUNTRY_SCAN_REFERENCE_CHANGED')
    binding = _binding_from_row(row)
    # Admission checks the full retained scan plus this exact row. A duplicate
    # tag is rejected, matching resolve_countries' requested-tag contract.
    _require(sum(isinstance(r, Mapping) and r.get('tag') == binding['tag']
                 for r in rows) == 1, 'COUNTRY_SCAN_DUPLICATE_TAG')
    return binding


def _admit(limiter, base, scan, binding):
    requested = scan['requested']
    _require(isinstance(requested, Mapping) and len(requested) == 1,
             'OBSERVER_REQUEST_BINDING_UNVERIFIED')
    observer = next(iter(requested))
    selected = dict(scan)
    selected['requested'] = {**requested, binding['tag']: binding}
    gate = _owner._bound_admission(limiter.read, base, selected, observer, binding['tag'])
    return gate


def _allowed(gate):
    return (gate.get('status') == 'known' and type(gate.get('admitted')) is bool
            and gate['admitted'] is True)


def _extension_round(limiter, base, province_id, anchor):
    evidence = {'status': 'unknown', 'shared_valid': False, 'bindings': {},
                'admission_before': {}, 'admission_after': {}, 'fields': {}}
    try:
        scan = anchor['country_scan']
        observer_binding = anchor['observer_binding']
        fresh = _province._province.resolve_provinces(limiter, base, [province_id])
        _require(_shared._same_raw(fresh, anchor['province_scan']), 'PROVINCE_BINDING_CHANGED')
        record = int(anchor['province_binding']['record_pointer'], 0)
        discovery = _province._read_discovery(limiter, record, observer_binding['slot'])
        evidence['discovery_before'] = discovery
        _require(_shared._same_raw(discovery, anchor['discovery'])
                 and discovery.get('status') == 'known' and discovery.get('value') is True,
                 'PROVINCE_DISCOVERY_CHANGED')
        observer_ref = bytes.fromhex(observer_binding['fullref_raw_hex'])
        observer = _rebind(limiter, base, scan, observer_ref, 'trade_country.observer')
        _require(_shared._same_raw(observer, observer_binding), 'OBSERVER_BINDING_CHANGED')
        observer_gate = _admit(limiter, base, scan, observer)
        _require(_allowed(observer_gate), 'OBSERVER_SELF_ADMISSION_UNVERIFIED')
        _require(_shared._same_raw(observer_gate, anchor['admission']), 'OBSERVER_ADMISSION_CHANGED')
        evidence['bindings']['observer'] = observer
        evidence['admission_before']['observer'] = observer_gate

        controller_ref = limiter.read(record + _province.CONTROLLER_FULLREF_OFFSET, 8,
                                      'province_trade_country.controller_ref')
        evidence['controller_ref_raw_hex'] = controller_ref.hex()
        try:
            parent_controller = anchor['fields_raw'][_CONTROLLER_IDENTITY]
            _require(parent_controller.get('status') == 'known'
                     and parent_controller.get('raw_inputs', {}).get('reference_raw_hex') == controller_ref.hex(),
                     'CONTROLLER_REFERENCE_CHANGED')
            controller = _rebind(limiter, base, scan, controller_ref, 'trade_country.controller')
            controller_gate = (_admit(limiter, base, scan, controller)
                               if controller['tag'] != observer['tag'] else observer_gate)
            evidence['bindings']['controller'] = controller
            evidence['admission_before']['controller'] = controller_gate
        except _ObserverFailure:
            raise
        except Exception:
            controller = None
            evidence['fields'][CONTROLLER_FIELD] = _unknown('CONTROLLER_BINDING_OR_ADMISSION_UNVERIFIED')

        cache = {}
        for role, field, binding in (('observer', OBSERVER_FIELD, observer),
                                     ('controller', CONTROLLER_FIELD, controller)):
            if binding is None:
                continue
            gate = evidence['admission_before'][role]
            if not _allowed(gate):
                evidence['fields'][field] = _unknown('COUNTRY_VIEW_ADMISSION_NOT_ESTABLISHED')
                continue
            tag = binding['tag']
            if tag not in cache:
                cache[tag] = _country_leaf.read_fields(limiter, base, binding, (_LEAF_FIELD,))[_LEAF_FIELD]
            evidence['fields'][field] = deepcopy(cache[tag])

        # Bind the extension back to the original discovered province and NPC
        # observer. Numeric failures remain local; changed shared identity does not.
        after_ref = limiter.read(record + _province.CONTROLLER_FULLREF_OFFSET, 8,
                                 'province_trade_country.controller_ref_after')
        if after_ref != controller_ref:
            evidence['fields'][CONTROLLER_FIELD] = _unknown('CONTROLLER_REFERENCE_CHANGED')
        observer_after = _rebind(limiter, base, scan, observer_ref, 'trade_country.observer_after')
        _require(_shared._same_raw(observer_after, observer), 'OBSERVER_BINDING_CHANGED')
        observer_after_gate = _admit(limiter, base, scan, observer_after)
        evidence['admission_after']['observer'] = observer_after_gate
        _require(_shared._same_raw(observer_gate, observer_after_gate)
                 and _allowed(observer_after_gate), 'OBSERVER_ADMISSION_CHANGED')
        if controller is not None and after_ref == controller_ref:
            try:
                after = _rebind(limiter, base, scan, after_ref, 'trade_country.controller_after')
                after_gate = (_admit(limiter, base, scan, after)
                              if after['tag'] != observer['tag'] else observer_after_gate)
                evidence['admission_after']['controller'] = after_gate
                _require(_shared._same_raw(controller, after)
                         and _shared._same_raw(evidence['admission_before']['controller'], after_gate),
                         'CONTROLLER_ADMISSION_CHANGED')
            except _ObserverFailure:
                raise
            except Exception:
                evidence['fields'][CONTROLLER_FIELD] = _unknown('CONTROLLER_BINDING_OR_ADMISSION_CHANGED')
        after_discovery = _province._read_discovery(limiter, record, observer['slot'])
        evidence['discovery_after'] = after_discovery
        _require(_shared._same_raw(discovery, after_discovery), 'PROVINCE_DISCOVERY_CHANGED')
        after_province = _province._province.resolve_provinces(limiter, base, [province_id])
        _require(_shared._same_raw(fresh, after_province), 'PROVINCE_BINDING_CHANGED')
        evidence.update(status='observed', shared_valid=True)
    except Exception:
        evidence['reason'] = 'COUNTRY_INPUT_SHARED_EVIDENCE_UNVERIFIED'
        evidence['fields'] = {field: _unknown(evidence['reason']) for field in COUNTRY_FIELDS}
    return evidence


def read_two_pass(reader, base, province_id, *, observer='FRA'):
    limiter = _shared._BoundedReader(_province._ReaderAdapter(reader))

    def parent_fields(read, module_base, binding, fields):
        return {**_inputs.read_fields(read, module_base, binding, _inputs.SUPPORTED_FIELDS),
                **_province._read_fields(read, module_base, binding, (_CONTROLLER_IDENTITY,))}

    result = _province.read_two_pass(limiter, base, province_id, observer=observer,
        fields=(*_inputs.SUPPORTED_FIELDS, _CONTROLLER_IDENTITY), read_fields=parent_fields,
        observer_scoped=True)
    target = result['targets'][0]
    controller_identity_stable = target['field_consistency'].pop(_CONTROLLER_IDENTITY, {}).get('status') == 'stable'
    target['fields'].pop(_CONTROLLER_IDENTITY, None)
    for field in COUNTRY_FIELDS:
        target['fields'][field] = _unknown('COUNTRY_INPUT_PARENT_UNVERIFIED')
        target['field_consistency'][field] = {'status': 'unknown'}
    if result.get('status') != 'observed' or result.get('consistency', {}).get('status') != 'stable':
        result['budget'] = limiter.summary()
        return result
    # The parent can be observed even when discovery/admission was denied;
    # never perform the extension in that case.
    anchors = result['pass_evidence']
    admitted = all(_allowed(anchors[p]['admission'])
                   and anchors[p]['discovery'].get('status') == 'known'
                   and anchors[p]['discovery'].get('value') is True for p in ('pass1', 'pass2'))
    if not admitted:
        result['budget'] = limiter.summary()
        return result
    rounds = {p: _extension_round(limiter, base, province_id, anchors[p]) for p in ('pass1', 'pass2')}
    result['country_inputs_evidence'] = rounds
    result['budget'] = limiter.summary()
    result['errors'].extend(limiter.errors)
    if not all(r['shared_valid'] for r in rounds.values()):
        result['status'] = 'unknown'
        result['consistency'] = {'status': 'unknown', 'shared_mismatch_paths': ['country_inputs']}
        for field in FIELDS:
            target['fields'][field] = _unknown('COUNTRY_INPUT_SHARED_EVIDENCE_UNVERIFIED')
            target['field_consistency'][field] = {'status': 'unknown'}
        return result
    for field in COUNTRY_FIELDS:
        first, second = (rounds[p]['fields'][field] for p in ('pass1', 'pass2'))
        role = 'observer' if field == OBSERVER_FIELD else 'controller'
        stable = (_shared._same_raw(first, second)
                  and _shared._same_raw(rounds['pass1']['bindings'].get(role), rounds['pass2']['bindings'].get(role))
                  and _shared._same_raw(rounds['pass1']['admission_before'].get(role), rounds['pass2']['admission_before'].get(role)))
        if not stable:
            target['fields'][field] = _unknown('COUNTRY_INPUT_CHANGED_BETWEEN_PASSES')
            target['field_consistency'][field] = {'status': 'changed'}
        else:
            target['fields'][field] = deepcopy(second)
            target['field_consistency'][field] = {'status': 'stable' if second.get('status') == 'known' else 'unknown'}
    if not controller_identity_stable:
        target['fields'][CONTROLLER_FIELD] = _unknown('CONTROLLER_REFERENCE_CHANGED')
        target['field_consistency'][CONTROLLER_FIELD] = {'status': 'changed'}
    return result
