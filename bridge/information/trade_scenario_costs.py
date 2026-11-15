"""Current action previews explicitly associated with caller trade scenarios."""
from copy import deepcopy

from .candidate_action_costs import inspect_plans


class TradeScenarioCostReader:
    def __init__(self, inspector):
        self.inspector = inspector

    def read(self, plans, actor, context):
        inspected = inspect_plans(self.inspector, plans, actor, context)
        return {'status': 'known', 'partial': True, 'complete': False, 'game_fact': False,
            'value': {'schema': 'information.trade_scenario_costs.v1',
                'scenarios': deepcopy(inspected['plans']), 'association': 'caller_scenario_id',
                'power_deltas_caused_by_actions': 'unknown',
                'sequencing': 'independent_previews_at_current_state',
                'submitted': False, 'complete': False, 'game_fact': False,
                'inspection_collection': {'scope': 'one_t06_read',
                    'inspector_calls': inspected['inspector_calls'],
                    'shared_result_hits': inspected['shared_result_hits'],
                    'cross_request_cache': False}}}
