#!/usr/bin/env python3
"""Synthetic compressed images through the reader's NFS table and a modeled libnfs."""
from pathlib import Path
import argparse
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
from fixtures import make_pfs, pfsc, wrapped
from fixtures_exfat import make_exfat


def compile_test(root, out):
    sys.path.insert(0, str(root / 'tools/build'))
    import reader
    source, _ = reader.prepare(root, out)
    exe = out / 'nfs-compressed-reader-test'
    command = ['clang-18', '-D_DEFAULT_SOURCE', '-DBW_GTA_AUDIO_BOOTSTRAP=1', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-misleading-indentation', '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
               '-I' + str(root / 'vendor/libsmb2/include'), '-I' + str(root / 'vendor/libnfs/include'), '-I' + str(root / 'src/blackwire'),
               *[str(source / 'bw' / name) for name in reader.CFILES if not name.endswith('private_smb.c') and name not in reader.HOME_CFILES],
               str(source / 'bw/reader/preload/nfs_ops.c'), str(root / 'tests/compressed/nfs_reader_test.c'), '-o', str(exe)]
    compiled = subprocess.run(command, capture_output=True, text=True)
    (out / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError('compile failed: ' + compiled.stderr)
    return exe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe = compile_test(root, out)
    # Same synthetic game as check_synthetic.py. No game material.
    rng = random.Random(84271)
    raw = rng.randbytes(65536)
    contents = {'eboot.bin': b'SYNTHETIC-BOOT' * 100, 'sce_sys/param.json': b'{"titleId":"PPSA09999"}',
                'packs/first.pak': raw * 16 + b'A' * 65536 + b'tail-one',
                'other/equal.pak': b'B' * 65536 + raw * 16 + b'tail-two', 'zero.dat': b''}
    pfs, _ = make_pfs(contents)
    packed = pfsc(pfs)
    exfat_valid, _ = make_exfat(contents)
    variants = {'bare-pfsc': packed, 'wrapped-pfsc': wrapped(pfs), 'plain-pfs': pfs, 'wrapped-plain': wrapped(pfs, encode=False),
                'pfsc-exfat': pfsc(exfat_valid), 'wrapped-exfat': wrapped(exfat_valid)}
    damaged = bytearray(packed)
    first, end = struct.unpack_from('<QQ', damaged, 0x400)
    damaged[end - 1] ^= 0x01
    mismatch, _ = make_pfs({**contents, 'packs/first.pak': contents['packs/first.pak'] + b'mismatch'})
    refused = {'manifest-mismatch': mismatch, 'checksum-failure': damaged, 'truncated-header': packed[:32]}
    reports = []
    with tempfile.TemporaryDirectory(prefix='blackwire-nfs-images-') as work:
        temp = Path(work)
        folder = temp / 'originals'
        for name, body in contents.items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        admitted = temp / 'admitted.pfs'
        admitted.write_bytes(pfs)
        for label, body in {**variants, **refused}.items():
            image = temp / (label + '.ffpfsc')
            image.write_bytes(body)
            # The real handoff is v4. v3 is the design default, so it stays covered.
            for version in ('4', '3') if label not in refused else ('4',):
                result = subprocess.run([str(exe), str(admitted), str(image), str(folder), *(['refuse'] if label in refused else [])],
                                        capture_output=True, text=True, env={**os.environ, 'BW_NFS_VERSION': version})
                if result.returncode:
                    raise RuntimeError(label + ' v' + version + ': ' + result.stdout + result.stderr)
                reports.append({'case': label, 'nfsVersion': int(version), 'result': json.loads(result.stdout)})
    proof = {'passed': True, 'transport': 'nfs', 'cases': reports, 'syntheticOnly': True, 'liveNfsServer': False, 'consoleContacted': False}
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'passed': True, 'cases': len(reports), 'checks': sum(row['result']['checks'] for row in reports),
                      'refused': len(refused)}))


if __name__ == '__main__':
    main()
