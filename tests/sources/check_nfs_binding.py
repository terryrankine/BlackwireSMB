#!/usr/bin/env python3
"""NFS source binding: the C digest must equal an independent recomputation of
BWBIND02, and SMB identity is checked separately by check_identity_golden."""
from pathlib import Path
import argparse, hashlib, json, os, struct, subprocess, sys

ROOT = Path(__file__).resolve().parents[2]


def bind02(*fields):
    data = b'BWBIND02' + b''.join(struct.pack('<I', len(f.encode())) + f.encode() for f in fields)
    return hashlib.sha256(data).hexdigest()


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
    sources = [Path(__file__).with_name('nfs_binding_test.c')]
    sources += [lib / n for n in ('source_catalog.c', 'source_identity.c', 'source_binding.c',
                                  'source_profile.c', 'source_snapshot.c', 'source_plan.c')]
    sources += [stream / n for n in ('share_config.c', 'manifest.c')]
    binary = out / 'nfs-binding-test'
    flags = ['clang-18', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-misleading-indentation', '-Wno-unused-function', '-D_DEFAULT_SOURCE=1',
             '-ffunction-sections', '-fdata-sections', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
             '-I', ROOT / 'src/blackwire', '-I', ROOT / 'vendor/libsmb2/include']
    env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1', 'UBSAN_OPTIONS': 'halt_on_error=1'}
    for argv in ([*flags, *sources, '-Wl,--gc-sections', '-o', binary], [binary]):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, text=True, env=env, timeout=120)
        (out / 'log.txt').open('a').write(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('nfs binding test failed; inspect log.txt')
    observed = json.loads(result.stdout.strip().splitlines()[-1])
    expected = {'images': bind02('nfs', '192.168.11.186', '/volume1/public', 'emulation/ps5/games/images',
                                 'Alpha.ffpfsc', 'PPSA09999'),
                'root': bind02('nfs', '192.168.11.186', '/volume1/public', '', 'Alpha.ffpfsc', 'PPSA09999')}
    expected['game'] = 'PPSA09999_' + expected['images']
    differ = sorted(k for k in expected if observed.get(k) != expected[k])
    proof = {'passed': not differ and observed.get('checks', 0) > 0, 'differ': differ,
             'observed': observed, 'expected': expected, 'consoleContacted': False}
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({k: proof[k] for k in ('passed', 'differ')}))
    if not proof['passed']:
        raise ValueError('NFS binding differs: ' + ', '.join(differ))


if __name__ == '__main__':
    main()
