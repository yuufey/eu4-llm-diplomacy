"""Native num_of_diplomats capacity, not observed task-vector length."""
from .scalar_capture_source import ScalarCaptureSource


class NativeDiplomatsTotalSource(ScalarCaptureSource):
    TOPIC = 'N05'
    FIELD = 'diplomats_total'
    UNIT = 'diplomats'
    SCALE = 1000
    BASIS = 'native_diplomats_total_aggregate_cache'
    VALUE_ORIGIN = 'copied_native_aggregate_modifier'
    CAPTURE_MODULE = 'bridge.information.diplomats_total_capture'
    DESCRIPTION = '原生num_of_diplomats条件对应的外交官总容量；raw/1000，保留原始精度，不以任务向量条目数或空闲数推断。'

    def catalog(self):
        topics = super().catalog()
        field = topics[0]['fields'][self.FIELD]
        field['quantity'] = 'native_num_of_diplomats_capacity'
        field['gaps'].append('CURRENT_TASK_INSTANCE_POPULATION_NOT_VERIFIED')
        return topics
