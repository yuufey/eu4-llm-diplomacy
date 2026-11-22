"""Current native diplomatic reputation of the configured observer country."""
from .scalar_capture_source import ScalarCaptureSource


class NativeDiplomaticReputationSource(ScalarCaptureSource):
    observer_scoped = True
    TOPIC = 'N06'
    FIELD = 'diplomatic_reputation'
    UNIT = 'diplomatic_reputation'
    SCALE = 1000
    BASIS = 'native_diplomatic_reputation_aggregate_cache'
    VALUE_ORIGIN = 'copied_native_aggregate_modifier'
    CAPTURE_MODULE = 'bridge.information.diplomatic_reputation_capture'
    DESCRIPTION = '本国外交声誉的原生聚合缓存值；raw/1000，不含具名贡献分解，计算态或修正处理器存在时未知。'
