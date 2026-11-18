#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Send by title ID, catalog reuse wiring and GET /api/log through the actual
backend handlers and workers. Discovery and preparation are spies; no console,
network or game data is used."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIB = ROOT / 'src/blackwire/library'
STREAM = ROOT / 'src/blackwire/streamreader'
LIFE = ROOT / 'tests/dashboard/lifecycle'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    if not out.is_relative_to(ROOT / 'build') or out.exists():
        raise ValueError('Use a fresh output below build/')
    out.mkdir(parents=True)
    sources = [HERE / 'test_scriptable_api.c', LIB / 'startup_runtime_idle.c', STREAM / 'diagnostics/game_stop_identity.c']
    sources += [LIB / n for n in ('native_job.c', 'source_catalog.c', 'source_binding.c', 'source_identity.c', 'native_request.c', 'native_removal_request.c', 'source_param.c', 'source_profile.c')]
    sources += [STREAM / 'share_config.c', STREAM / 'manifest.c']
    tracked = sources + [Path(__file__), LIB / 'native_backend.c', LIFE / 'test_play_preparation_failure.c', LIFE / 'source_ampr_admission_model.h']
    pin = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    before = {str(p): pin(p) for p in tracked}
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=180,
                           env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
                                'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
        commands.append(dict(label=label, argv=argv, exitCode=r.returncode, stdout=r.stdout[-4000:], stderr=r.stderr[-8000:]))
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if r.returncode:
            raise RuntimeError(label + ' failed; inspect commands.json')
        return r.stdout
    # The default Send is never reached: its body becomes an aborting spy,
    # exactly as in the Play fixture. Every handler under test is unchanged.
    sys.path.insert(0, str(ROOT / 'tools/build'))
    from reader_patch import function
    original = (LIB / 'native_backend.c').read_text()
    prepare = function(original, 'static int prepare(')
    spy = '{' + ''.join('(void)' + p + ';' for p in ('opaque', 'config', 'selection', 'current', 'guard', 'observe', 'observer', 'out')) + 'abort();}'
    (out / 'native_backend.c').write_text(original.replace(prepare, prepare.split('{', 1)[0] + spy))
    includes = (out, LIB, STREAM, STREAM / 'diagnostics', LIFE, ROOT / 'vendor/libsmb2/include', ROOT / 'vendor/sqlite',
                ROOT / 'src/blackwire/tools/compressed_stream_candidate')
    flags = ['clang-18', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', '-Wno-unused-function',
             '-Wno-unused-variable', '-O1', '-g', '-ffunction-sections', '-fdata-sections', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-pthread', '-DBW_COPY_HOST_TEST=1',
             '-DBW_NATIVE_SEND_HOST_TEST=1', '-DBW_NATIVE_FS_HOST_TEST=1', '-DBW_NATIVE_PRELOAD=1', '-DBW_GTA_AUDIO_BOOTSTRAP=1']
    flags += [str(v) for d in includes for v in ('-I', d)]
    binary = out / 'scriptable-api-test'
    run('compile', [*flags, *sources, '-Wl,--wrap=bw_idle_log_cache_close', '-Wl,--gc-sections', '-lm', '-o', binary])
    result = json.loads(run('scriptable-api', [binary]).strip().splitlines()[-1])
    after = {str(p): pin(p) for p in tracked}
    proof = {'passed': result.get('passed') is True and before == after, 'cases': result['cases'], 'checks': result['checks'],
             'actualBackendHandlers': True, 'consoleContacted': False, 'networkContacted': False,
             'sourcePinsUnchanged': before == after}
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof))
    if not proof['passed']:
        raise ValueError('Scriptable API check failed')


if __name__ == '__main__':
    main()
