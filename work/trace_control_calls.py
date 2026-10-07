"""Offline confirmed direct callers of the selected load path functions."""
from pathlib import Path
source_path = Path(__file__).with_name('trace_native_peace_calls.py')
source = source_path.read_text(encoding='utf-8')
start = source.index('targets = {}')
end = source.index('for section in sections:', start)
source = source[:start] + '''targets = {rva: {'label': label, 'function_rva': hex(rva), 'direct_call_candidates': []}
    for rva,label in ((0x11bdf80,'in_game_load_confirmation_ctor'),
                      (0x1175ef0,'load_selected_ui_context'))}
''' + source[end:]
source = source.replace('if caller:\n', 'if caller and caller[1]-caller[0] <= 0x20000:\n')
source = source.replace('runtime/native-peace-callers.json', 'runtime/native-control-callers.json')
exec(compile(source, str(source_path), 'exec'), {'__file__': str(source_path), '__name__': '__main__'})
