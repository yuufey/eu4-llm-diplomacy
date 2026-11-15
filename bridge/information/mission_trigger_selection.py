"""Select loaded mission rows before collecting their dynamic trigger inputs."""
import re

_IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')


def select_tasks(tasks, selector):
    if selector is None:
        return tasks
    if (type(selector) is not dict or not selector
            or set(selector) - {'root_id', 'task_id'}
            or any(not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None
                   for value in selector.values())):
        raise ValueError('MISSION_TRIGGER_SELECTOR_INVALID')
    return [task for task in tasks
            if all(task.get(key) == value for key, value in selector.items())]
