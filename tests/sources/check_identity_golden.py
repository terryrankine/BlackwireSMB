#!/usr/bin/env python3
"""Offline golden vectors for the binding, image-generation and snapshot seals.

Default: build identity_golden_test.c against this tree and require EXPECTED.
--capture-main TREE: build the same test file against a main checkout with
-DBW_GOLDEN_MAIN_API and require EXPECTED there too. This reproduces the
capture:

    git worktree add ../bw-main 193d910
    python3 tests/sources/check_identity_golden.py --output build/golden-main --capture-main ../bw-main
"""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys

ROOT = Path(__file__).resolve().parents[2]
# Captured from origin/main 193d910, before struct bw_stat replaced
# struct smb2_stat_64 in the identity code. --capture-main reproduces them: same
# test file, same inputs, main's sources and main's API. Under BW_GOLDEN_MAIN_API the test
# passes &raw straight to the seals where this tree first converts it with
# bw_stat_from_smb2, and calls bw_provider_image_generation for the _stat form.
# A change here unbinds every installed game, so these values are never
# regenerated from new code.
# Code this branch changes: catalogImage* (bw_source_catalog_image_hash) and
# imageGeneration* (bw_provider_image_generation_stat and its SMB wrapper).
# Untouched control vectors: binding*, game* (source_binding.c,
# bw_provider_binding_init) and snapshot* (source_snapshot.c).
EXPECTED = {
    'bindingFolder': '0c2e6534e6a41039f24c8437dd26f36970caa0e3fd1700265b8af217a9c84e46',
    'bindingContainer': '32cc582f19f8615090f721dc17e784b4f515fb1e79eaf5822eeb7d8f34935d69',
    'gameFolder': 'PPSA09999_0c2e6534e6a41039f24c8437dd26f36970caa0e3fd1700265b8af217a9c84e46',
    'gameContainer': 'PPSA09999_32cc582f19f8615090f721dc17e784b4f515fb1e79eaf5822eeb7d8f34935d69',
    'catalogImage0': '305fde057daf6f22285b809ab073d1dba3fa3865ba95b5e962328a8f60a71cfc',
    'imageGenerationFolder0': 'e0fd38051031db7c5bd4665a3257dba31db8cc3f118a6c0074ff30213d54d82b',
    'imageGenerationContainer0': '7e2201841dcd4e1fe1d60f73e7a4395d899b6dd3638c3f500e808ee8d87aa57d',
    'catalogImage1': 'cf8bebcbef53e5135980fbbeee9a90ff0286c432710b9b65fee5b6b9095b1282',
    'imageGenerationFolder1': 'bd21310bbdfd17dcf266ec781cdb23960023b25e65318b9c666db199b4e87835',
    'imageGenerationContainer1': 'b8fa47369be3584e1f5724e9726f4a51b137bc4a7495b2b95b8a998e609aa8a8',
    'catalogImage2': '0cea15c5493b6494051f32cac01d8a6652464154b590983e2bddd2c55c5d4846',
    'imageGenerationFolder2': '753e9d58b02fd21236973add46d54c1b70c365d30f5bff719c5bb5e2cd4d93f1',
    'imageGenerationContainer2': '60c786492c5af41b352b692753cdcb4335fc82dbe5687070eab7ba8c3f0893aa',
    'snapshotBound': '06d261adeb1f93416a602485d9dc22d1d850e8a2566770dc3c0c620bffb318ef',
    'snapshotPlain': '0db07a4c0749ab039577098da3dc55ecc2360e64befeb27d832047555fe603f3',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--capture-main', type=Path, metavar='TREE',
                        help='build against a pre-bw_stat main checkout instead of this tree')
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise ValueError('Use Linux/WSL Python and clang-18')
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / 'build') or out.exists():
        raise ValueError('Use a fresh build output directory')
    tree = (args.capture_main or ROOT).resolve()
    if args.capture_main:
        # The main API build cannot see bw_stat. A tree that has it is not main.
        if not (tree / 'src/blackwire/library/source_identity.c').is_file():
            raise ValueError('Not a Blackwire tree: ' + str(tree))
        if (tree / 'src/blackwire/streamreader/bw_stat.h').exists():
            raise ValueError('Capture tree already has bw_stat.h; use a checkout of 193d910')
    out.mkdir(parents=True)
    lib, stream = tree / 'src/blackwire/library', tree / 'src/blackwire/streamreader'
    sources = [Path(__file__).with_name('identity_golden_test.c')]
    sources += [lib / name for name in ('source_catalog.c', 'source_identity.c', 'source_binding.c',
                                       'source_profile.c', 'source_snapshot.c', 'source_plan.c')]
    sources += [stream / name for name in ('share_config.c', 'manifest.c')]
    pinned = sources + sorted((tree / 'src/blackwire').rglob('*.h'))
    def pins():
        return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in pinned}
    before = pins()
    flags = ['clang-18', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-misleading-indentation', '-Wno-unused-function', '-D_DEFAULT_SOURCE=1',
             '-ffunction-sections', '-fdata-sections', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
             '-I', tree / 'src/blackwire', '-I', tree / 'vendor/libsmb2/include']
    if args.capture_main:
        flags.append('-DBW_GOLDEN_MAIN_API=1')
    binary = out / 'identity-golden-test'
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
    run('compile-identity-golden', [*flags, *sources, '-Wl,--gc-sections', '-o', binary])
    observed = json.loads(run('identity-golden', [binary]))
    differ = sorted(key for key in EXPECTED if observed.get(key) != EXPECTED[key])
    if before != pins():
        raise ValueError('Source changed during test')
    proof = {'passed': not differ and observed.get('checks', 0) > 0, 'vectors': len(EXPECTED),
             'mode': 'capture-main' if args.capture_main else 'tree', 'tree': str(tree),
             'differ': differ, 'observed': observed, 'expected': EXPECTED,
             'sanitizers': ['address', 'undefined'], 'consoleContacted': False, 'smbConnectionsMade': False}
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({key: proof[key] for key in ('passed', 'vectors', 'differ')}))
    if not proof['passed']:
        raise ValueError('Identity seal changed: ' + ', '.join(differ))


if __name__ == '__main__':
    main()
