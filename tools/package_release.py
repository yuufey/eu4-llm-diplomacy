"""Build an allowlisted ZIP locally. Does not launch or access the game process."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import zipfile


def assert_no_machine_paths(payload):
    """Reject accidental Windows/POSIX absolute paths in text release files."""

    absolute_path = re.compile(rb"(?i)(?:[A-Z]:[\\/]|/(?:users|home)/)")
    text_suffixes = {'.md', '.py', '.json', '.txt', '.yml', '.yaml', '.ps1'}
    for name, data in payload.items():
        if name == 'local.env.example' or Path(name).suffix.lower() not in text_suffixes:
            continue
        if absolute_path.search(data):
            raise RuntimeError(f'Absolute machine path found in release file: {name}')


def observer_payload(manifest_path):
    """Package the existing verified build independently of its build directory."""
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    version = manifest['version']
    prefix = f'diplomacy-observer-portable-v{version}'
    dll_name = f'eu4_bridge_diplomacy_observer_v{version}.dll'
    records = [{'name': dll_name, 'sha256': manifest['dll_sha256']}, *manifest['sources']]
    payload = {}
    for record in records:
        name = record['name']
        if Path(name).name != name or '\\' in name:
            raise RuntimeError(f'Build member must be a filename: {name}')
        raw = (manifest_path.parent / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != record['sha256']:
            raise RuntimeError(f'Observer build member changed: {name}')
        payload[name] = raw
    portable = deepcopy(manifest)
    portable['dll'] = dll_name
    portable['experiment_id'] = prefix
    # Compiler arguments document the original build. Installation locates
    # the verified DLL and source members beside this manifest.
    portable['compiler_arguments'] = [
        PureWindowsPath(arg).name if PureWindowsPath(arg).is_absolute() else
        Path(arg).name if Path(arg).is_absolute() else arg
        for arg in portable.get('compiler_arguments', [])
    ]
    payload['build-manifest.json'] = json.dumps(portable, ensure_ascii=False, indent=2).encode('utf-8')
    assert_no_machine_paths({'build-manifest.json': payload['build-manifest.json']})
    return prefix, payload


def package_observer(manifest_path, output):
    prefix, payload = observer_payload(manifest_path)
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as zipped:
        for name, raw in sorted(payload.items()):
            zipped.writestr(f'{prefix}/{name}', raw)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(
        f'{checksum}  {output.name}\n', encoding='utf-8')
    print(output)
    print(f'SHA256: {checksum}')


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observer-manifest', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.observer_manifest:
        package_observer(args.observer_manifest, args.output or root / 'dist/observer.zip')
        return
    if args.output:
        parser.error('--output requires --observer-manifest')
    meta = json.loads((root / 'release/release.json').read_text(encoding='utf-8'))
    if not re.fullmatch(r'[A-Za-z0-9.-]+', meta['version']):
        raise RuntimeError('Invalid release version')
    dll = root / 'work/native' / meta['dll']
    if hashlib.sha256(dll.read_bytes()).hexdigest() != meta['dll_sha256']:
        raise RuntimeError('DLL differs from the reviewed release; validate before updating metadata')
    paths = ['release/release.json', 'tools/load_release.py', 'tools/request_treaty.py',
             'local.env.example', 'work/local_config.py',
             'work/native/inject_probe.py', 'work/probe_native_state.py',
             'docs/03-开发与验收/DLL安装与更新.md', 'docs/03-开发与验收/开发与发布.md',
             'work/native/' + meta['dll']]
    payload = {name: (root / name).read_bytes() for name in paths}
    assert_no_machine_paths(payload)
    payload['SHA256SUMS.txt'] = ''.join(
        f'{hashlib.sha256(data).hexdigest()}  {name}\n'
        for name, data in sorted(payload.items())).encode('utf-8')
    out = root / 'dist'
    out.mkdir(exist_ok=True)
    archive = out / f'eu4-authorized-peace-{meta["version"]}.zip'
    if archive.exists():
        raise RuntimeError('Release ZIP already exists; use a new version or move the old ZIP first')
    prefix = archive.stem
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as zipped:
        for name, data in payload.items():
            zipped.writestr(f'{prefix}/{name}', data)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(
        f'{checksum}  {archive.name}\n', encoding='utf-8')
    print(archive)
    print(f'SHA256: {checksum}')


if __name__ == '__main__':
    main()
