"""Current native governing usage/limit with separately labeled derived headroom."""
from copy import deepcopy
import re
from .scalar_capture_source import ScalarCaptureSource


class NativeGovernanceCapacitySource(ScalarCaptureSource):
    TOPIC = 'N06'
    FIELD = 'governance_capacity'
    UNIT = 'governing_capacity_summary'
    SCALE = 1
    BASIS = 'native_governing_capacity_cache_and_limit_arithmetic'
    VALUE_ORIGIN = 'derived_from_copied_native_governing_capacity_inputs'
    CAPTURE_MODULE = 'bridge.information.governance_capacity_capture'
    DESCRIPTION = '本国原生治理用量、上限和使用比例，以及明确派生的有符号容量差值；各项独立保留单位、精度与未知状态。'

    def _sanitize(self, item):
        if isinstance(item, dict) and item.get('status') in ('unknown', 'invisible', 'unavailable'):
            reason = item.get('reason')
            if (set(item) != {'status', 'reason'} or not isinstance(reason, str)
                    or re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', reason) is None):
                raise ValueError('invalid capacity state')
            return self._field(item['status'], reason)
        from .governance_capacity_values import validate_public_field
        if validate_public_field(item) is not True:
            raise ValueError('invalid governing capacity projection')
        return deepcopy(item)

    def catalog(self):
        topics = super().catalog()
        field = topics[0]['fields'][self.FIELD]
        field['raw_semantics'] = 'used/limit/fraction retain native signed32 inputs or arithmetic; headroom is a signed64 mathematical limit-minus-used difference, each raw/1000'
        field['components'] = ['used', 'limit', 'used_fraction', 'headroom']
        field['gaps'] += ['SIGNED_HEADROOM_IS_DERIVED_NOT_NATIVE_UI_REMAINING', 'NAMED_LIMIT_CONTRIBUTIONS_NOT_IMPLEMENTED', 'RENDERED_GOVERNING_TOOLTIP_NOT_OBSERVED']
        return topics
