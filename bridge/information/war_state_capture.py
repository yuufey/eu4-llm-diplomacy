"""Shared country bindings for the selected war's national state summaries."""
import hashlib
from collections.abc import Mapping

from . import country_occupation_memory as _occupation
from . import foreign_country_memory as _countries
from . import foreign_forces_capture as _forces
from . import foreign_technology_capture as _owner
from . import war_territory as _territory
from .war_forces import project_sizes


SCHEMA = 'information.war_state_capture.v1'
PROFILE_SHA256 = hashlib.sha256(
    (_territory.PROFILE_SHA256 + _forces.PROFILE_SHA256).encode('ascii')).hexdigest()
FIELDS = ('occupations', 'blockades', 'current_forces')


def _read_forces(read, base, binding, observer, profile):
    leaf = _forces._forces
    if binding['tag'] != observer['tag']:
        permission = _forces._visibility.read_permission(
            read, base, observer, binding, observer_tag=observer['tag'])
        return leaf.read_fields(read, base, binding, _forces.FORCE_FIELDS,
            permission=permission, predicate_profile=profile['force_predicates'],
            observer_tag=observer['tag'])
    # The logical observer's own statistics use its canonical country binding.
    # Foreign-country visibility settings belong to the branch above.
    if (binding['fullref'] != observer['fullref']
            or binding['country_pointer'] != observer['country_pointer']):
        raise ValueError('WAR_OWN_COUNTRY_BINDING_MISMATCH')
    _, pointer, retained = leaf._country_binding._parse_target(base, binding)
    limiter = leaf._BudgetReader(read)
    evidence = leaf._country_binding._validate_target_binding(limiter, base, pointer, retained)
    predicates = leaf._normalize_predicate_profile(profile['force_predicates'])
    permission = {'status': 'known', 'admitted': True, 'basis': 'logical_observer_own_country'}
    return leaf._read_group_chain(limiter, base, pointer, retained, permission,
        predicates, set(_forces.FORCE_FIELDS), evidence)


def _load_profile(fields):
    profile = _territory._load_profile()
    if 'current_forces' in fields:
        forces = _forces._load_profile()
        existing = {(guard['rva'], guard['bytes']) for guard in profile['code_guards']}
        profile['code_guards'].extend(guard for guard in forces['code_guards']
                                      if (guard['rva'], guard['bytes']) not in existing)
        profile['force_predicates'] = forces['force_predicates']
    return profile


def _observe_for(countries, fields, observer='FRA'):
    def observe(reader, base, anchor, profile):
        state = {}

        def admission(read, module_base, scan, observer_tag, target):
            state['scan'] = scan
            state['rows'] = {row['fullref']: row for row in scan['rows'] if row['fullref']}
            return _owner._bound_admission(read, module_base, scan, observer_tag, target)

        def read_fields(read, module_base, binding, selected):
            observer_binding = state['scan']['requested'][observer]
            values = {}
            terrain = [field for field in fields if field in _territory.FIELDS]
            if terrain:
                try:
                    summary = _occupation.read_occupation(read, module_base, binding, observer_binding,
                        state['rows'], profile['occupation'], include_occupation='occupations' in terrain,
                        blockade_spec=profile['blockade'] if 'blockades' in terrain else None)
                    blockades = summary.pop('blockades', None)
                    available = {'occupations': summary, 'blockades': blockades}
                    values.update({'W03.' + field: available[field] for field in terrain})
                except Exception as exc:
                    values.update({'W03.' + field: {'status': 'unknown', 'reason': str(exc)}
                                   for field in terrain})
            if 'current_forces' in fields:
                try:
                    stats = _read_forces(read, module_base, binding, observer_binding, profile)
                    values['W03.current_forces'] = project_sizes(stats,
                        _forces.ARMY_FIELD, _forces.NAVY_FIELD, 'army_soldiers')
                except Exception as exc:
                    values['W03.current_forces'] = {'status': 'unknown', 'reason': str(exc)}
            return values

        def backend(read, module_base, target):
            return _countries.read_two_pass(read, module_base, observer, countries,
                fields=['W03.' + field for field in fields], admission_reader=admission,
                read_fields=read_fields)

        return _owner._observe(reader, base, anchor, profile, backend_reader=backend)
    return observe


def capture(installation, countries, *, fields, observer='FRA'):
    countries, fields = list(countries), list(fields)
    if not countries or len(countries) > _countries.MAX_TARGETS or not fields:
        raise ValueError('WAR_STATE_CAPTURE_SCOPE')
    report = _owner._capture_common(installation, countries[0], observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=lambda: _load_profile(fields),
        observe=_observe_for(countries, fields, observer), allow_observer_target=True,
        observer_scoped=True)
    report['request'].update(countries=countries, fields=fields)
    return report


def validate_capture(report, context, creation, countries, fields):
    if (not isinstance(context, Mapping) or not isinstance(report, dict)
            or report.get('request', {}).get('countries') != countries
            or report.get('request', {}).get('fields') != fields or not countries):
        return False
    return _owner._validate_capture_common(report, context, creation, countries[0],
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=lambda: _load_profile(fields),
        observe=_observe_for(countries, fields, context.get('observer')), allow_observer_target=True,
        require_access=True, observer_scoped=True)
