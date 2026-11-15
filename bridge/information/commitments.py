"""Expose current land promises, preparation pledges and subsidy terms through R07."""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .catalog import get_topic, validate_query as _validate_catalog_query
from .model import InformationError, digest
from .observation_time import dates_match
from .sources import _result, _source_info
from .trade_income import _context_reason, _identity, _session_binding


_FIELDS = ("land_commitments", "war_commitments", "economic_support", "expiry", "source")
_SUPPORTED_FIELDS = {"economic_support", "source"}
_TAG = re.compile(r"[A-Z0-9]{3}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


class NativeCommitmentsSource:
    """Read current commitments and preserve the existing subsidy evidence view."""

    event_types: tuple[str, ...] = ()

    def __init__(self, foreign_economy_source, *, land_capture=None, war_capture=None,
                 economic_capture=None, land_promise_history_reader=None):
        self.foreign_economy_source = foreign_economy_source
        self.land_capture = land_capture
        self.war_capture = war_capture
        self.economic_capture = economic_capture
        self.land_promise_history_reader = land_promise_history_reader

    def context(self):
        return deepcopy(self.foreign_economy_source.context())

    def catalog(self):
        topic = get_topic("R07")
        topic.update(
            status="available", source=type(self).__name__,
            object_types=["country_pair", "war"], observer_roles=["actor"], observer_scope=["FRA"],
            supported_versions=["1.37.4"], visibility="visible_scope",
            context_scope="country_pair", triggers=["query", "periodic", "change"],
            change_detection="sampled_state_comparison_not_lossless_events",
            change_scope={'fields': ['land_commitments', 'war_commitments', 'economic_support', 'expiry']},
        )
        topic["fields"] = {
            "land_commitments": {"coverage": "partial", "source": type(self).__name__,
                "complete": False, "period": "current", "unit": "land_commitments", "scale": 1,
                "supported_object_types": ["country_pair", "war"],
                "description": "当前土地标记、本方战争领袖及同战争中已观察的许诺发送方，按受益国或战争筛选",
                "gaps": ["PRE_CAPTURE_PROMISE_SENDER_UNKNOWN", "PENDING_CALLS_NOT_INCLUDED"]},
            "war_commitments": {"coverage": "partial", "source": type(self).__name__,
                "complete": False, "period": "current", "unit": "war_commitments", "scale": 1,
                "supported_object_types": ["country_pair"],
                "description": "双边当前备战约定，包含备战国、请求方与截止日期",
                "scope": "bilateral_war_preparation",
                "related_queries": ["W01.participants", "A04"]},
            "economic_support": {
                "coverage": "partial", "source": type(self).__name__, "complete": False,
                "unit": "economic_support_evidence", "scale": 1, "period": "current",
                "supported_object_types": ["country_pair"], "supported_observer": "FRA",
                "basis": "native_current_bilateral_subsidy_and_reparations_records",
                "paths": ["economic_support.value.active_payment_obligations",
                          "economic_support.value.registered_subsidy_evidence"],
                "description": "双边当前有效补贴与战争赔款，含双方、月额或收入比例及期限",
                "gaps": ["OTHER_ECONOMIC_SUPPORT_NOT_IMPLEMENTED"]},
            "expiry": {"coverage": "partial", "source": type(self).__name__,
                "complete": False, "period": "current", "unit": "commitment_deadlines", "scale": 1,
                "supported_object_types": ["country_pair"],
                "description": "当前备战约定、补贴与战争赔款的截止日期"},
            "source": {
                "coverage": "partial", "source": type(self).__name__, "complete": False,
                "unit": "source_evidence", "scale": 1, "period": "current",
                "basis": "canonical_digest_of_known_F03_subsidy_pair_component",
                "paths": ["F03.subsidies.value.observer_involved_contracts"],
                "gaps": ["SOURCE_EVIDENCE_REQUIRES_KNOWN_COMPONENT"]},
        }
        return [topic]

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError("invalid_context", "R07 context must be an object")
        normalized = _validate_catalog_query(query, context)
        if normalized["topic"] != "R07":
            raise InformationError("unsupported_topic", "Commitments source supports R07 only")
        if normalized["parameters"]:
            raise InformationError("invalid_parameters", "R07 takes no parameters")
        obj = normalized["object"]
        if obj["type"] == "country_pair":
            if (not isinstance(obj.get("actor"), str) or _TAG.fullmatch(obj["actor"]) is None
                    or not isinstance(obj.get("recipient"), str)
                    or _TAG.fullmatch(obj["recipient"]) is None):
                raise InformationError("invalid_object", "R07 requires two country tags")
            if obj["actor"] != "FRA":
                raise InformationError("observer_scope_mismatch", "R07 actor must be logical observer FRA")
            if obj["recipient"] == "FRA":
                raise InformationError("invalid_object", "R07 recipient must differ from observer FRA")
        if context is not None and context.get("observer") != "FRA":
            raise InformationError("observer_scope_mismatch", "R07 requires logical observer FRA")
        if obj['type'] == 'war' and 'land_commitments' in normalized['fields']:
            if (obj.get('actor') != 'FRA' or not isinstance(obj.get('recipient'), str)
                    or not _TAG.fullmatch(obj['recipient']) or obj['recipient'] == 'FRA'):
                raise InformationError('invalid_object', 'Land commitments require FRA and a war opponent')
        return normalized

    def _read_preparation(self, query, context):
        from . import war_preparation_capture as capture_module

        base = self.foreign_economy_source.base_source
        installation, creation, reason = _session_binding(base)
        reason = reason or _context_reason(context, 'FRA')
        proof = {'reader': 'war_preparation_capture', 'read_only': True}
        if reason:
            return {'status': 'unavailable', 'reason': reason}, proof
        country = query['object']['recipient']
        try:
            report = (self.war_capture or capture_module.capture)(installation, country)
            if not capture_module.validate_capture(report, context, creation, country):
                raise ValueError('WAR_PREPARATION_CAPTURE_INVALID')
            field = deepcopy(report['observation']['backend']['targets'][0]['fields']['R07.war_commitments'])
            proof['capture_report_sha256'] = digest(report)
            field.pop('raw_inputs', None)
            return field, proof
        except Exception as exc:
            return {'status': 'unknown', 'reason': 'WAR_PREPARATION_READ_FAILED:' + type(exc).__name__}, proof

    def _read_economic(self, query, context):
        base = getattr(self.foreign_economy_source, 'base_source', None)
        installation, creation, reason = _session_binding(base)
        reason = reason or _context_reason(context, 'FRA')
        proof = {'reader': 'ongoing_economic_commitments_capture', 'read_only': True}
        report = None
        try:
            if reason:
                raise ValueError(reason)
            from . import ongoing_economic_commitments_capture as capture_module

            country = query['object']['recipient']
            report = (self.economic_capture or capture_module.capture)(installation, country)
            if not capture_module.validate_capture(report, context, creation, country):
                raise ValueError('ECONOMIC_COMMITMENTS_CAPTURE_INVALID')
            fields = capture_module.project_fields(report)
            proof['capture_report_sha256'] = digest(report)
            result = {name: deepcopy(fields[name]) for name in ('economic_support', 'expiry')}
            for field in result.values():
                field.pop('raw_inputs', None)
            return result, proof
        except Exception as exc:
            proof['error'] = {'type': type(exc).__name__, 'reason': str(exc)}
            if isinstance(report, Mapping) and report.get('errors'):
                proof['capture_errors'] = deepcopy(report['errors'])
            field = {'status': 'unknown', 'reason': 'ECONOMIC_COMMITMENTS_READ_FAILED:' + type(exc).__name__}
            return {name: deepcopy(field) for name in ('economic_support', 'expiry')}, proof

    @staticmethod
    def _expiry(preparation, economic):
        entries = []
        if preparation.get('status') == 'known':
            entries.extend({'kind': row['kind'], 'country': row['country'], 'for': row['for'],
                            'end_date': row['until']} for row in preparation['value'])
        if economic.get('status') == 'known':
            entries.extend(deepcopy(economic['value']))
        complete = (preparation.get('status') == 'known' and preparation.get('complete', True) is True
                    and economic.get('status') == 'known' and economic.get('complete', True) is True)
        if complete or entries:
            return {'status': 'known', 'value': entries, 'complete': complete,
                    'component_statuses': {'war_preparation': preparation.get('status'),
                                           'subsidies': economic.get('status')}}
        return {'status': 'unknown', 'reason': 'COMMITMENT_EXPIRY_UNAVAILABLE'}

    def _read_land(self, query, context):
        from . import war_land_commitments_capture as capture_module

        base = self.foreign_economy_source.base_source
        installation, creation, reason = _session_binding(base)
        reason = reason or _context_reason(context, 'FRA')
        if reason:
            return {'status': 'unavailable', 'reason': reason}, {}
        selected_war = None
        proof = {'reader': 'war_land_commitments_capture', 'read_only': True}
        try:
            if query['object']['type'] == 'war':
                discovery = base.read({'topic': 'W01', 'object': deepcopy(query['object']),
                                       'fields': ['war_id'], 'parameters': {}}, context)
                identity = discovery['fields']['war_id']
                if identity.get('status') != 'known':
                    return deepcopy(identity), proof
                selected_war = identity['value']
                proof['war_context_source'] = 'W01'
                proof['war_id'] = selected_war
            report = (self.land_capture or capture_module.capture)(installation)
            if not capture_module.validate_capture(report, context, creation):
                raise ValueError('LAND_COMMITMENTS_CAPTURE_INVALID')
            field = capture_module.field_from_capture(report)
            proof['capture_report_sha256'] = digest(report)
            if field.get('status') != 'known':
                return field, proof
            wars = report['observation']['backend']['targets'][0]['fields']['F01.wars']['value']['wars']
            if selected_war is not None:
                if not any(war['war_id'].get('value') == selected_war for war in wars):
                    raise ValueError('LAND_COMMITMENTS_WAR_CHANGED')
                field['value'] = [row for row in field['value'] if row['war_id'] == selected_war]
            else:
                obj = query['object']
                recipient = obj['country'] if obj['type'] == 'country' else obj['recipient']
                if recipient in field.get('raw_inputs', {}).get('unavailable_beneficiaries', []):
                    return {'status': 'unknown', 'reason': 'LAND_COMMITMENTS_BENEFICIARY_UNAVAILABLE'}, proof
                field['value'] = [row for row in field['value'] if row['beneficiary'] == recipient]
            by_id = {war['war_id']['value']: war for war in wars if war['war_id'].get('status') == 'known'}
            for row in field['value']:
                war = by_id.get(row['war_id'])
                row['war_leader'] = None
                if war is not None:
                    own = war['target_side']
                    side = own if row['side'] == 'our_side' else ('side_b' if own == 'side_a' else 'side_a')
                    leader = war[side][0]
                    row['war_leader'] = leader.get('country') if leader.get('status') == 'known' else None
            field.pop('raw_inputs', None)
            from .land_promise_history import attach_observed_promisors
            field, proof['land_promise_association'] = attach_observed_promisors(
                field, context, self.land_promise_history_reader)
            return field, proof
        except Exception as exc:
            return {'status': 'unknown', 'reason': 'LAND_COMMITMENTS_READ_FAILED:' + type(exc).__name__}, proof

    def read_land_for_country(self, country, context):
        """Share the admitted land read with country-oriented adapters, including FRA."""
        if not isinstance(country, str) or _TAG.fullmatch(country) is None:
            raise InformationError('invalid_object', 'Land commitments require a country tag')
        return self._read_land({'object': {'type': 'country', 'country': country}}, context)

    @staticmethod
    def _validated_upstream(upstream, before, recipient):
        if not isinstance(upstream, Mapping):
            return None, "R07_F03_UPSTREAM_INVALID"
        info = upstream.get("source")
        provenance = info.get("provenance") if isinstance(info, Mapping) else None
        if (not isinstance(info, Mapping) or info.get("name") != "NativeForeignEconomySource"
                or info.get("mode") != before.get("mode")
                or info.get("observer") != "FRA"
                or info.get("session_id") != before.get("session_id")
                or not dates_match(before.get("game_date"), upstream.get("game_date"))
                or upstream.get("objects") != [{"type": "country", "country": recipient}]
                or not isinstance(provenance, Mapping)):
            return None, "R07_F03_UPSTREAM_IDENTITY_INVALID"
        capture_hash = provenance.get("capture_report_sha256")
        if not isinstance(capture_hash, str) or _SHA.fullmatch(capture_hash) is None:
            return None, "R07_F03_CAPTURE_EVIDENCE_MISSING"
        try:
            result_hash = digest(upstream)
        except Exception:
            return None, "R07_F03_RESULT_DIGEST_INVALID"
        if not isinstance(result_hash, str) or _SHA.fullmatch(result_hash) is None:
            return None, "R07_F03_RESULT_DIGEST_INVALID"
        return {"capture_report_sha256": capture_hash,
                "upstream_result_sha256": result_hash}, None

    @staticmethod
    def _component(upstream):
        fields = upstream.get("fields") if isinstance(upstream, Mapping) else None
        outer = fields.get("subsidies") if isinstance(fields, Mapping) else None
        if not isinstance(outer, Mapping):
            return None, "R07_F03_SUBSIDIES_FIELD_MISSING"
        if outer.get("status") != "known":
            component_status = outer.get("component_statuses")
            child = (component_status.get("observer_involved_contracts")
                     if isinstance(component_status, Mapping) else None)
            if isinstance(child, Mapping) and child.get("status") != "known":
                reason = child.get("reason")
            else:
                reason = outer.get("reason")
            return None, reason if isinstance(reason, str) and reason else "R07_F03_SUBSIDIES_UNKNOWN"
        value = outer.get("value")
        component = value.get("observer_involved_contracts") if isinstance(value, Mapping) else None
        if not isinstance(component, Mapping):
            return None, "R07_F03_SUBSIDY_COMPONENT_MISSING"
        if component.get("status") != "known":
            reason = component.get("reason")
            return None, reason if isinstance(reason, str) and reason else "R07_F03_SUBSIDY_COMPONENT_UNKNOWN"
        if not NativeCommitmentsSource._known_pair_component(component):
            return None, "R07_F03_SUBSIDY_COMPONENT_INVALID"
        return deepcopy(dict(component)), None

    @staticmethod
    def _known_pair_component(component):
        if (component.get("scope") != "observer_target_pair_only"
                or component.get("unit") != "bilateral_subsidies_relation"
                or type(component.get("scale")) is not int or component.get("scale") != 1
                or component.get("period") != "current"
                or component.get("complete_country_contracts") is not False):
            return False
        pair = component.get("pair_relation")
        contracts = component.get("contracts")
        if (not isinstance(pair, Mapping) or pair.get("status") != "known"
                or type(pair.get("present")) is not bool or not isinstance(contracts, list)
                or len(contracts) > 1):
            return False
        present = pair["present"]
        if (present is False and contracts) or (present is True and len(contracts) != 1):
            return False
        visibility = component.get("visibility")
        if (not isinstance(visibility, Mapping)
                or visibility.get("scope") != "observer_fiscal_bilateral_subsidies"
                or not isinstance(visibility.get("basis"), str)
                or visibility.get("actual_UI_observed") is not False):
            return False
        if not present:
            return True
        contract = contracts[0]
        if not isinstance(contract, Mapping):
            return False
        payer, recipient = contract.get("payer"), contract.get("recipient")
        if (not isinstance(payer, Mapping) or set(payer) != {"tag"}
                or not isinstance(recipient, Mapping) or set(recipient) != {"tag"}):
            return False
        payer_tag, recipient_tag = payer["tag"], recipient["tag"]
        if (not isinstance(payer_tag, str) or _TAG.fullmatch(payer_tag) is None
                or not isinstance(recipient_tag, str) or _TAG.fullmatch(recipient_tag) is None
                or payer_tag == recipient_tag):
            return False
        role = contract.get("observer_role")
        if ((role == "payer" and payer_tag != "FRA")
                or (role == "recipient" and recipient_tag != "FRA")
                or role not in {"payer", "recipient"}):
            return False
        amount = contract.get("monthly_nominal_amount")
        return (isinstance(amount, Mapping) and type(amount.get("raw")) is int
                and amount.get("unit") == "ducats" and type(amount.get("scale")) is int
                and amount.get("scale") == 1000 and amount.get("period") == "month")

    @staticmethod
    def _bind_component_target(component, target):
        if not NativeCommitmentsSource._known_pair_component(component):
            return False
        if not component["pair_relation"]["present"]:
            return True
        contract = component["contracts"][0]
        return {contract["payer"]["tag"], contract["recipient"]["tag"]} == {"FRA", target}

    def _project_known(self, component, upstream, evidence_hashes, recipient, observed_at):
        if not self._bind_component_target(component, recipient):
            return None
        obligations = {"status": "unknown", "reason": "CURRENT_PAYMENT_OBLIGATIONS_NOT_CAPTURED"}
        subsidies_value = upstream.get("fields", {}).get("subsidies", {}).get("value", {})
        source_obligations = (subsidies_value.get("current_payment_obligations")
                              if isinstance(subsidies_value, Mapping) else None)
        if (isinstance(source_obligations, Mapping)
                and source_obligations.get("status") == "unknown"
                and isinstance(source_obligations.get("reason"), str)):
            obligations = deepcopy(dict(source_obligations))
        evidence = {
            "registered_subsidy_evidence": deepcopy(component),
            "active_payment_obligations": obligations,
            "other_economic_support": {
                "status": "unsupported", "reason": "OTHER_ECONOMIC_SUPPORT_NOT_IMPLEMENTED"},
        }
        basis = component["visibility"]["basis"]
        source_value = {
            "name": "NativeForeignEconomySource",
            "path": "F03.subsidies.value.observer_involved_contracts",
            "basis": basis,
            "observation_date": observed_at,
            "session_id": upstream["source"].get("session_id"),
            "component_sha256": digest(component),
            "scope": {"observer": "FRA", "actor": "FRA", "recipient": recipient,
                      "relation": "observer_target_pair_only",
                      "complete_country_contracts": False},
        }
        support = {
            "status": "known", "value": evidence,
            "unit": "economic_support_evidence", "scale": 1, "period": "current",
            "basis": "F03_observer_involved_subsidy_relation_component",
            "complete": False, "partial": True,
        }
        source_field = {
            "status": "known", "value": source_value,
            "unit": "source_evidence", "scale": 1, "period": "current",
            "complete": False, "partial": True,
        }
        return support, source_field

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        fields = {name: {"status": "unsupported", "reason": "R07_FIELD_NOT_IMPLEMENTED"}
                  for name in query["fields"]}
        provenance = {
            "shared_reader": "NativeForeignEconomySource.read(F03.subsidies)",
            "read_only": True, "native_function_invoked": False,
            "sampling": "query_periodic_change_not_lossless_events",
        }
        try:
            before = self.context()
        except Exception:
            before = {}
        current = before if isinstance(before, dict) else (deepcopy(context) if isinstance(context, dict) else {})
        needed = [name for name in query["fields"] if name in _SUPPORTED_FIELDS]
        economic_fields = {}
        captured_context = deepcopy(current)

        def result():
            if _identity(captured_context) != _identity(current):
                for name in ('land_commitments', 'war_commitments', 'economic_support', 'expiry'):
                    if name in fields:
                        fields[name] = {'status': 'unavailable', 'reason': 'R07_CONTEXT_CHANGED_DURING_READ'}
                return self._result(query, current, fields, provenance)
            current_support = economic_fields.get('economic_support', {})
            if 'economic_support' in fields and current_support.get('status') == 'known':
                prior = fields['economic_support']
                if prior.get('status') == 'known' and isinstance(prior.get('value'), dict):
                    prior['value'].update(deepcopy(current_support['value']))
                else:
                    fields['economic_support'] = deepcopy(current_support)
            return self._result(query, current, fields, provenance)

        if ({'war_commitments', 'expiry'} & fields.keys()
                and query['object']['type'] == 'country_pair'):
            if context is not None and _identity(context) != _identity(current):
                preparation = {'status': 'unavailable', 'reason': 'R07_CONTEXT_MISMATCH'}
            else:
                preparation, proof = self._read_preparation(query, current)
                provenance['war_commitments'] = proof
                if not needed:
                    provenance['shared_reader'] = 'war_preparation_capture'
            if 'war_commitments' in fields:
                fields['war_commitments'] = preparation

        if ({'economic_support', 'expiry'} & fields.keys()
                and query['object']['type'] == 'country_pair'):
            if context is not None and _identity(context) != _identity(current):
                economic_fields = {name: {'status': 'unavailable', 'reason': 'R07_CONTEXT_MISMATCH'}
                                   for name in ('economic_support', 'expiry')}
            else:
                economic_fields, proof = self._read_economic(query, current)
                provenance['current_economic_support'] = proof
                support = economic_fields['economic_support']
                if (support.get('status') == 'known'
                        and any(key.startswith('registered_') for key in support.get('value', {}))):
                    if 'economic_support' in fields:
                        fields['economic_support'] = deepcopy(support)
                    if 'economic_support' in needed:
                        needed.remove('economic_support')
                    provenance['shared_reader'] = 'ongoing_economic_commitments_capture'
            if 'expiry' in fields:
                fields['expiry'] = self._expiry(preparation, economic_fields['expiry'])

        if 'land_commitments' in fields:
            if context is not None and _identity(context) != _identity(current):
                fields['land_commitments'] = {'status': 'unavailable', 'reason': 'R07_CONTEXT_MISMATCH'}
            else:
                fields['land_commitments'], proof = self._read_land(query, current)
                provenance['land_commitments'] = proof
                if proof.get('war_id') is not None:
                    query['object']['war_id'] = proof['war_id']
                if not needed:
                    provenance['shared_reader'] = 'war_land_commitments_capture'
            if query['object']['type'] == 'war':
                provenance.pop('native_function_invoked', None)

        if query["object"]["type"] == "war":
            for name in query["fields"]:
                if name != 'land_commitments':
                    fields[name] = {"status": "unsupported", "reason": "R07_WAR_OBJECT_NOT_IMPLEMENTED"}
            return result()
        if not needed:
            return result()

        reason = _context_reason(before, "FRA") if isinstance(before, dict) else "R07_CONTEXT_UNAVAILABLE"
        if reason is not None:
            for name in needed:
                fields[name] = {"status": "unavailable", "reason": reason}
            return result()
        if context is not None and _identity(context) != _identity(before):
            for name in needed:
                fields[name] = {"status": "unavailable", "reason": "R07_CONTEXT_MISMATCH"}
            return result()

        recipient = query["object"]["recipient"]
        mapped = {"topic": "F03", "object": {"type": "country", "country": recipient},
                  "fields": ["subsidies"], "parameters": {}}
        upstream, read_failure = None, None
        try:
            upstream = self.foreign_economy_source.read(mapped, before)
        except Exception as exc:
            read_failure = f"R07_F03_UPSTREAM_FAILED:{type(exc).__name__}"

        try:
            after = self.context()
        except Exception:
            after = {}
        if (not isinstance(after, dict) or _context_reason(after, "FRA") is not None
                or _identity(before) != _identity(after)):
            for name in needed:
                fields[name] = {"status": "unavailable", "reason": "R07_CONTEXT_CHANGED_DURING_READ"}
            provenance["reason"] = "R07_CONTEXT_CHANGED_DURING_READ"
            current = after if isinstance(after, dict) else current
            return result()

        if read_failure:
            for name in needed:
                fields[name] = {"status": "unknown", "reason": read_failure}
            current = after
            return result()

        hashes, upstream_reason = self._validated_upstream(upstream, before, recipient)
        if upstream_reason is not None:
            for name in needed:
                fields[name] = {"status": "unknown", "reason": upstream_reason}
            current = after
            return result()
        provenance.update(hashes)
        component, component_reason = self._component(upstream)
        if component_reason is not None:
            for name in needed:
                fields[name] = {"status": "unknown", "reason": component_reason}
            current = after
            return result()

        projected = self._project_known(component, upstream, hashes, recipient, upstream.get("game_date"))
        if projected is None:
            for name in needed:
                fields[name] = {"status": "unknown", "reason": "R07_F03_SUBSIDY_PAIR_BINDING_INVALID"}
            current = after
            return result()
        support, source_field = projected
        if "economic_support" in fields:
            fields["economic_support"] = support
        if "source" in fields:
            fields["source"] = source_field
        current = after
        return result()

    def _result(self, query, context, fields, provenance):
        complete = all(field.get('status') == 'known' and field.get('complete') is True
                       for field in fields.values())
        source = _source_info(type(self).__name__, context, complete=complete,
                              provenance=deepcopy(provenance))
        source["context_scope"] = query['object']['type']
        return _result(query, context, fields, complete, source)

    def change_comparison(self, query, sample, context):
        """Compare known current contracts while retaining the declared partial coverage."""
        fields = sample.get('fields', {})
        selected = set(query.get('fields', []))
        if (query.get('topic') != 'R07' or selected != set(fields) or not selected
                or not selected <= {'land_commitments', 'war_commitments', 'economic_support', 'expiry'}
                or _context_reason(context, 'FRA')
                or any(field.get('status') != 'known' for field in fields.values())):
            return None
        support = fields.get('economic_support')
        if support is not None:
            active = support.get('value', {}).get('active_payment_obligations', {})
            if active.get('status') != 'known' or active.get('complete') is not True:
                return None
        if any(field.get('complete') is not True for name, field in fields.items()
               if name != 'economic_support'):
            return None
        source = sample.get('source', {})
        if (source.get('name') != type(self).__name__
                or source.get('session_id') != context.get('session_id')):
            return None
        proof = source.get('provenance', {})
        readers = {'land_commitments': 'land_commitments', 'war_commitments': 'war_commitments',
                   'economic_support': 'current_economic_support'}
        required = {readers[name] for name in selected if name in readers}
        if 'expiry' in selected:
            required.update(('war_commitments', 'current_economic_support'))
        if any(not _SHA.fullmatch(proof.get(name, {}).get('capture_report_sha256', ''))
               for name in required):
            return None
        return {'schema': 'information.change_comparison.v1',
                'scope': 'R07.current_commitments.v2.' + digest({
                    'query': query, 'economic_scope': sorted(
                        key for key in (support or {}).get('value', {}) if key.startswith('registered_'))}),
                'fields': deepcopy(fields)}

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": False,
                "gaps": ["SAMPLED_STATE_COMPARISON_NOT_LOSSLESS_EVENTS"]}


__all__ = ["NativeCommitmentsSource"]
