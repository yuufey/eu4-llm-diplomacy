"""Keep mission candidate-cost semantics around shared action previews."""
from copy import deepcopy

from .candidate_action_costs import (
    MAX_ACTIONS,
    MAX_INPUT_BYTES,
    MAX_PLANS,
    inspect_plans,
    normalize_plans,
    project_inspection,
)


class MissionCandidateCostReader:
    def __init__(self,inspector):
        self.inspector=inspector

    def read(self,plans,actor,context,selector):
        inspection=inspect_plans(self.inspector,plans,actor,context)
        return {'status':'known','partial':True,'complete':False,
            'value':{'schema':'information.mission_candidate_costs.v1','selector':deepcopy(selector),
                'plans':inspection['plans'],'task_association':'caller_selected_task',
                'target_conditions_evaluated':False,'joint_completion_evaluated':False,
                'sequencing':'independent_previews_at_current_state','complete':False,
                'inspection_collection':{'scope':'one_m05_read',
                    'inspector_calls':inspection['inspector_calls'],
                    'shared_result_hits':inspection['shared_result_hits'],
                    'cross_request_cache':False}}}
