"""Actual supported-profile table and lookup refusal behaviour; no console."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cc',default='clang-18')
    a=parser.parse_args()
    root=Path(__file__).resolve().parents[2];src=root/'src/blackwire';out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    diagnostics=src/'streamreader/diagnostics';lib=src/'library';service=src/'dashboard/service'
    # frontend_identity.c is included by the test, not compiled on its own.
    linked=[diagnostics/'game_stop_identity.c',lib/'startup_runtime_idle.c',service/'game_identity.c']
    inputs=[*linked,diagnostics/'game_stop_identity.h',lib/'startup_runtime_idle.h',service/'game_identity.h',
            service/'frontend_identity.c',service/'frontend_identity.h',
            root/'tests/compressed/profile_table_test.c',Path(__file__)]
    def pin(p):
        b=p.read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
    before={str(p.relative_to(root)):pin(p) for p in inputs}
    san=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'] if 'clang' in a.cc else []
    command=[a.cc,'-D_DEFAULT_SOURCE','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',
             '-DRC_GAME_IDENTITY_HOST_TEST=1','-DBD_FRONTEND_IDENTITY_HOST_TEST=1',
             *['-I'+str(d) for d in (diagnostics,src/'streamreader',lib,service,root/'vendor/libsmb2/include')],*san,
             str(root/'tests/compressed/profile_table_test.c'),*map(str,linked),
             '-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-pthread','-o',str(out/'profile_table')]
    commands=[]
    def run(label,argv):
        env={**os.environ,'ASAN_OPTIONS':'halt_on_error=1:detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'}
        p=subprocess.run(argv,capture_output=True,text=True,timeout=180,env=env)
        commands.append({'label':label,'argv':argv,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode:raise RuntimeError(label+' failed; evidence retained')
        return p.stdout
    run('compile',command)
    result=json.loads(run('profile-table',[str(out/'profile_table')]))
    after={str(p.relative_to(root)):pin(p) for p in inputs}
    if before!=after:raise RuntimeError('Source changed during verification')
    # Only what this run measured: the host binary's result and the pinned inputs.
    proof={'passed':bool(result.get('passed')),'checks':result['checks'],'source':after}
    (out/'proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({k:proof[k] for k in ('passed','checks')}))

if __name__=='__main__':main()
