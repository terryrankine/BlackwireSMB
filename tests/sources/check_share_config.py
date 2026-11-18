#!/usr/bin/env python3
"""Offline share.conf transport regression: SMB bytes unchanged, NFS keys and the reader handoff."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/build'))
from reader_patch import function


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise ValueError('Use Linux/WSL Python and clang-18')
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / 'build') or out.exists():
        raise ValueError('Use a fresh build output directory')
    out.mkdir(parents=True)
    lib, stream = ROOT / 'src/blackwire/library', ROOT / 'src/blackwire/streamreader'
    # The handoff encoder is static. Test the shipped function body, not a copy.
    handoff = (lib / 'preload_handoff.c').read_text()
    header = out / 'share-config-under-test.h'
    header.write_text('#include "native_setup.h"\n#include "../streamreader/share_config.h"\n'
                      '#include <string.h>\n' + function(handoff, 'static int ph_encode_share(') + '\n')
    sources = [Path(__file__).with_name('share_config_test.c'), lib / 'native_setup.c', stream / 'share_config.c']
    pinned = sources + [header, lib / 'preload_handoff.c', lib / 'native_setup.h', stream / 'share_config.h']

    def pins():
        return {str(path.relative_to(ROOT)): {'bytes': path.stat().st_size,
                 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in pinned}
    before = pins()
    flags = ['clang-18', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-misleading-indentation', '-Wno-unused-function', '-Wno-unused-variable',
             '-D_DEFAULT_SOURCE=1', '-DBW_NATIVE_SETUP_HOST_TEST=1',
             '-ffunction-sections', '-fdata-sections', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    for directory in (out, lib, stream, ROOT / 'vendor/libsmb2/include'):
        flags += ['-I', str(directory)]
    binary = out / 'share-config-test'
    commands = []

    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, text=True,
                                env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
                                     'UBSAN_OPTIONS': 'halt_on_error=1'}, timeout=120)
        commands.append({'label': label, 'argv': list(map(str, argv)), 'exitCode': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(label + ' failed; inspect retained commands.json')
        return result.stdout
    run('compile-share-config', [*flags, *sources, '-Wl,--gc-sections', '-pthread', '-o', binary])
    observed = json.loads(run('share-config-cases', [binary]))
    if before != pins():
        raise ValueError('Source changed during test')
    proof = {'passed': True, 'observed': observed, 'sanitizers': ['address', 'undefined'],
             'inputPins': before, 'consoleContacted': False, 'networkContacted': False,
             'scope': 'Actual share.conf parser, writer, selection and handoff encoder; NFS transport needs separate qualification'}
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({key: value for key, value in proof.items() if key != 'inputPins'}))


if __name__ == '__main__':
    main()
