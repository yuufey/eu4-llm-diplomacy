"""Bounded offline inventory of load and diplomat recall string references."""
from pathlib import Path
source_path = Path(__file__).with_name('map_native_peace_candidates.py')
source = source_path.read_text(encoding='utf-8')
start = source.index('labels = ')
end = source.index('targets = {}', start)
source = source[:start] + '''labels = sorted(set(m.group() for m in re.finditer(rb'[ -~]{5,160}', data)
    if re.search(rb'recall|cancel.*diplomat|diplomat.*cancel|return.*diplomat|diplomat.*return|loadgame|load_game|loadsave', m.group(), re.I)))[:200]
''' + source[end:]
source = source.replace('runtime/native-peace-candidates.json', 'runtime/native-control-candidates.json')
exec(compile(source, str(source_path), 'exec'), {'__file__': str(source_path), '__name__': '__main__'})
