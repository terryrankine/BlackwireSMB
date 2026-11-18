#!/usr/bin/env python3
"""Offline transport-neutral tests: error classes, connect factory, transport
ops and the NFS source over libnfs fakes. No console or server is contacted."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SRC = ROOT / 'src/blackwire'
LIB, STREAM = SRC / 'library', SRC / 'streamreader'

# name -> (test source, sources under test, extra flags). Every unit prints one
# JSON object with its check count on its last line.
UNITS = {
    'tp_error': (HERE / 'tp_error_test.c', [], []),
    'connect': (HERE / 'connect_test.c', [], []),
    'source_ops': (HERE / 'source_ops_test.c', [], []),
    # The NFS module with its real sources, linked against the libnfs fake.
    'nfs': (HERE / 'nfs_test.c', [LIB / n for n in (
        'source_nfs.c', 'source_catalog.c', 'source_param.c', 'source_plan.c', 'source_snapshot.c', 'source_directory.c',
        'compressed_data.c', 'source_profile.c', 'source_binding.c', 'source_identity.c')] + [STREAM / n for n in (
        'bw_transport_nfs.c', 'share_config.c', 'manifest.c', 'container_source.c', 'container_manifest.c', 'container_smb.c',
        'pfs_source.c', 'pfsc_range.c', 'pfsc_inflate.c')], ['-ffunction-sections', '-Wl,--gc-sections']),
    'container': (HERE / 'container_test.c', [STREAM / n for n in (
        'container_smb.c', 'container_source.c', 'pfs_source.c', 'pfsc_range.c', 'pfsc_inflate.c', 'manifest.c')], []),
}
# Compiled only, never run: the standalone preparation copy has no host build.
# Linux names the PS5 fstatat syscall newfstatat.
SYNTAX = [(STREAM / 'prepare_copy.c', ['-DSYS_fstatat=SYS_newfstatat'])]


def fixture(root):
    """A server root shared by every unit. Images/ is the container fixture.
    volume1/public is the NFS export: an images folder, as on the NAS, with a
    sidecar hash and an in-progress copy beside the image, and a folder tree
    with links for the neutral source scenarios."""
    sys.path.insert(0, str(ROOT / 'tests/compressed'))
    from fixtures import make_pfs
    (root / 'Images').mkdir(parents=True)
    asset = bytes((i * 29 + i // 251) % 256 for i in range(128 * 1024))
    image = make_pfs({'eboot.bin': b'NFS NEUTRAL STARTUP', 'sce_sys/param.json':
                      b'{"titleId":"PPSA09999","titleName":"Neutral"}', 'asset.bin': asset,
                      'sce_sys/icon0.png': b'\x89PNG NFS NEUTRAL COVER'})[0]
    (root / 'Images/Beta.ffpfsc').write_bytes(image)
    games = root / 'volume1/public/emulation/ps5/games'
    images = games / 'images'
    images.mkdir(parents=True)
    (images / 'Beta.ffpfsc').write_bytes(image)
    (images / 'Beta.ffpfsc.sha256').write_text(hashlib.sha256(image).hexdigest() + '  Beta.ffpfsc\n')
    (images / 'Gamma.ffpfsc.partial').write_bytes(image[:4096])
    (images / 'Linked.ffpfsc').symlink_to('Beta.ffpfsc')
    (games / 'linked').symlink_to('images')
    alpha = games / 'folders/Alpha'
    (alpha / 'sce_sys').mkdir(parents=True)
    (alpha / 'data').mkdir()
    (alpha / 'eboot.bin').write_bytes(bytes(i % 256 for i in range(4096)))
    (alpha / 'sce_sys/param.json').write_bytes(b'{"titleId":"PPSA09998","contentId":"UP0000-PPSA09998_00-NFSNEUTRAL000000","titleName":"Alpha"}')
    (alpha / 'sce_sys/icon0.png').write_bytes(b'\x89PNG ALPHA')
    (alpha / 'data/a.bin').write_bytes(bytes((i * 7 + i // 253) % 256 for i in range(400000)))
    (games / 'folders/LinkedGame').symlink_to('Alpha')
    (games / 'folders/Alpha.lnk').symlink_to('Alpha/eboot.bin')

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
    pinned = sorted({Path(__file__).resolve(), *[u[0] for u in UNITS.values()], *[x[0] for x in SYNTAX],
                     *[s for u in UNITS.values() for s in u[1]], *SRC.rglob('*.h')})
    def pins():
        return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in pinned}
    before = pins()
    flags = ['clang-18', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-misleading-indentation', '-Wno-unused-function', '-D_DEFAULT_SOURCE=1',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
             '-I', SRC, '-I', LIB, '-I', STREAM, '-I', ROOT / 'vendor/libsmb2/include',
             '-I', ROOT / 'vendor/libnfs/include']
    commands, results = [], {}
    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, text=True, timeout=300,
                                env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
                                     'UBSAN_OPTIONS': 'halt_on_error=1'})
        commands.append({'label': label, 'argv': list(map(str, argv)), 'exitCode': result.returncode,
                         'stdout': result.stdout[-4000:], 'stderr': result.stderr[-4000:]})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(label + ' failed; inspect retained commands.json')
        return result.stdout
    for source, extra in SYNTAX:
        run('syntax-' + source.stem, [*flags, *extra, '-fsyntax-only', source])
    with tempfile.TemporaryDirectory(prefix='blackwire-transport-') as temp:
        fixture(Path(temp))
        for name, (test, sources, extra) in UNITS.items():
            binary = out / (name + '-test')
            run('compile-' + name, [*flags, '-I', HERE, *extra, test, *sources, '-lm', '-o', binary])
            results[name] = json.loads(run(name, [binary, temp]).strip().splitlines()[-1])
    if before != pins():
        raise ValueError('Source changed during test')
    passed = all(isinstance(v, dict) and v and all(isinstance(c, int) and c > 0 for c in v.values())
                 for v in results.values())
    proof = {'passed': passed, 'units': results, 'sanitizers': ['address', 'undefined'],
             'consoleContacted': False, 'serverContacted': False}
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'passed': passed, 'units': results}))
    if not passed:
        raise ValueError('A transport unit did not pass')


if __name__ == '__main__':
    main()
