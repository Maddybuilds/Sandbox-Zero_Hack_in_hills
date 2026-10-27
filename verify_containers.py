"""Run the actual Compose deployment in a disposable, unexposed project.

Requires a running Docker Engine. Never returns a passing isolation report when
Docker is missing. The web server never invokes this CLI or receives its socket.
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent


def execute(command,*,env=None,timeout=30,input=None):
    result=subprocess.run(command,cwd=ROOT,env=env,input=input,text=True,capture_output=True,timeout=timeout,
                          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:
        detail=result.stderr[-2400:]
        for key,value in (env or {}).items():
            if key.startswith('SZ_') and value:detail=detail.replace(value,'[REDACTED]')
        raise RuntimeError('Docker command failed; no isolation result substituted. '+detail.strip())
    return result.stdout


def verify():
    if not shutil.which('docker'):return {'status':'unavailable','checks':[],'reason':'Docker CLI is not installed. No container checks executed.'}
    try:version=json.loads(execute(['docker','version','--format','json']))
    except (RuntimeError,subprocess.TimeoutExpired,ValueError):return {'status':'unavailable','checks':[],'reason':'Docker Engine is not reachable. No container checks executed.'}
    project='sz-proof-'+secrets.token_hex(6)
    environment={k:v for k,v in os.environ.items() if not k.startswith(('SZ_','COMPOSE_'))}
    environment.update({k:secrets.token_urlsafe(24) for k in ['SZ_ACCESS_CODE','SZ_RED_TOKEN','SZ_BLUE_TOKEN','SZ_TARGET_TOKEN']})
    checks=[];started=False
    def check(id,name,passed,observed):checks.append({'id':id,'name':name,'passed':bool(passed),'observed':observed})
    with tempfile.TemporaryDirectory(prefix='sz-docker-proof-') as temporary:
        base=Path(temporary);empty=base/'empty.env';empty.write_text('')
        original=['docker','compose','--env-file',str(empty),'-p',project,'-f',str(ROOT/'compose.yaml')]
        configuration=json.loads(execute([*original,'config','--format','json'],env=environment))
        # No published ports and no real .env, bind mounts or workspace data.
        configuration['services']['gateway'].pop('ports',None)
        configuration['services']['gateway']['build']['context']=str(ROOT)
        for service in configuration['services'].values():
            if 'build' in service:service['build']['context']=str(ROOT)
        config=base/'compose.json';config.write_text(json.dumps(configuration))
        compose=['docker','compose','--env-file',str(empty),'-p',project,'-f',str(config)]
        try:
            started=True
            execute([*compose,'up','--build','--wait','--wait-timeout','180','-d'],env=environment,timeout=600)
            ids={role:execute([*compose,'ps','-q',role],env=environment).strip() for role in ['gateway','red','blue','target']}
            if not all(ids.values()):raise RuntimeError('Not all disposable services started.')
            records={role:json.loads(execute(['docker','inspect',id]))[0] for role,id in ids.items()}
            # Addresses are passed explicitly so a negative DNS lookup cannot fake isolation.
            addresses={role:next(iter(row['NetworkSettings']['Networks'].values()))['IPAddress'] for role,row in records.items() if role!='gateway'}
            probe=r'''
import errno,json,os,socket,sys
from pathlib import Path
task=json.load(sys.stdin);out={}
for role,ip in task.get('peers',{}).items():
 try:
  with socket.create_connection((ip,9000),timeout=2):pass
  out[role]={'connected':True}
 except OSError as e:out[role]={'connected':False,'errno':e.errno,'type':type(e).__name__}
try:Path('/app/__readonly_probe').write_text('synthetic');out['readonly']={'denied':False}
except OSError as e:out['readonly']={'denied':e.errno==errno.EROFS,'errno':e.errno}
out['uid']=os.getuid();out['files']=sorted(p.name for p in Path('/app').iterdir())
out['no_new_privs']='NoNewPrivs:\t1' in Path('/proc/self/status').read_text()
out['namespaces']={name:os.readlink('/proc/self/ns/'+name) for name in ['mnt','pid','net']}
out['cgroup']={name:(Path('/sys/fs/cgroup')/name).read_text().strip() if (Path('/sys/fs/cgroup')/name).is_file() else None for name in ['pids.max','memory.max','cpu.max']}
print(json.dumps(out))
'''
            observations={}
            for role in ids:
                peers=addresses if role=='gateway' else {peer:ip for peer,ip in addresses.items() if peer!=role}
                observations[role]=json.loads(execute(['docker','exec','-i',ids[role],'python','-c',probe],input=json.dumps({'peers':peers})))
                observed=observations[role]
                check('READONLY-'+role,role+' root filesystem rejects writes',observed['readonly']['denied'],observed['readonly'])
                check('PRIVS-'+role,role+' runs non-root with no-new-privileges',observed['uid']!=0 and observed['no_new_privs'],{'uid':observed['uid'],'no_new_privs':observed['no_new_privs']})
                host=records[role]['HostConfig']
                check('SOCKET-'+role,role+' has no host bind mount or Docker socket',not any(m.get('Type')=='bind' or m.get('Destination')=='/var/run/docker.sock' for m in records[role]['Mounts']),{'bind_mounts':sum(m.get('Type')=='bind' for m in records[role]['Mounts'])})
                expected_memory=256*1024*1024 if role=='gateway' else 128*1024*1024
                expected_cpu='50000 100000'
                check('LIMITS-'+role,role+' kernel cgroup reports its CPU, memory and process budgets',
                      observed['cgroup']=={'pids.max':'64','memory.max':str(expected_memory),'cpu.max':expected_cpu},observed['cgroup'])
            for name in ['mnt','pid','net']:
                identities={role:r['namespaces'][name] for role,r in observations.items()}
                check('NAMESPACE-'+name,'All four services have distinct '+name+' namespaces',len(set(identities.values()))==4,identities)
            for role in ['red','blue','target']:
                check('CONTROL-'+role,'Gateway can reach healthy '+role,observations['gateway'][role]['connected'],observations['gateway'][role])
                for peer in addresses:
                    if peer==role:continue
                    result=observations[role][peer]
                    # Credit known route-denial errors/timeouts only when the same
                    # destination is actually reachable by the gateway control.
                    denied=(not result['connected'] and (result.get('type')=='TimeoutError' or result.get('errno') in {13,101,113}))
                    check(role.upper()+'-TO-'+peer.upper(),role+' cannot connect directly to '+peer,
                          denied and observations['gateway'][peer]['connected'],result)
            check('RED-SOURCE','Red image excludes Blue policy and target/coordinator code',
                  not set(observations['red']['files'])&{'policy.py','engine.py','server.py','catalog.py','scenarios.py'}, {'files':observations['red']['files']})
            check('BLUE-SOURCE','Blue image excludes Red catalog and target/coordinator code',
                  not set(observations['blue']['files'])&{'red_cases.json','engine.py','server.py','catalog.py','scenarios.py'}, {'files':observations['blue']['files']})
            check('TARGET-SOURCE','Target image excludes both participant implementations and coordinator code',
                  set(observations['target']['files'])=={'fixture_runtime.py','target_worker.py'},{'files':observations['target']['files']})
            workflow=r'''
import json,os
from urllib.request import Request,urlopen
from urllib.error import HTTPError
def call(route,body=None,token=None,base='http://127.0.0.1:8000'):
 headers={'Content-Type':'application/json'}
 if token:headers['Authorization']='Bearer '+token
 try:
  with urlopen(Request(base+route,data=None if body is None else json.dumps(body).encode(),headers=headers),timeout=30) as response:return response.status,json.load(response)
 except HTTPError as e:return e.code,json.load(e)
unauth=call('/api/state')[0];token=os.environ['SZ_ACCESS_CODE']
status,run=call('/api/run',{'profile':'hardened','suite':'quick'},token)
counts={name:sum(r['outcome']==name for r in run.get('events',[])) for name in ['allowed','blocked','held','failed']}
integrity=call('/api/integrity',token=token)[1]
req=Request('http://blue:9000/inspect',data=json.dumps({'payload':'Hello','action':'chat','profile':'hardened'}).encode(),headers={'Content-Type':'application/json','X-Participant-Token':os.environ['SZ_RED_TOKEN']})
try:
 with urlopen(req,timeout=5) as response:cross=response.status
except HTTPError as e:cross=e.code;e.close()
print(json.dumps({'unauthorized_status':unauth,'run_status':status,'counts':counts,'audit_valid':integrity.get('valid'),'audit_records':integrity.get('events'),'cross_role_credential_status':cross}))
'''
            flow=json.loads(execute(['docker','exec',ids['gateway'],'python','-c',workflow],timeout=60))
            check('GATEWAY-AUTH','Running gateway rejects unauthenticated API access',flow['unauthorized_status']==401,{'status':flow['unauthorized_status']})
            check('CROSS-TOKEN','Running Blue rejects the Red service credential',flow['cross_role_credential_status']==401,{'status':flow['cross_role_credential_status']})
            check('CORE-FLOW','Containerized gateway, Red, Blue and target complete the fixed fixture suite',flow['run_status']==200 and flow['counts']=={'allowed':1,'blocked':4,'held':1,'failed':0},flow)
            check('CORE-AUDIT','Containerized fixture decisions have a valid audit chain',flow['audit_valid'] is True,{'valid':flow['audit_valid'],'records':flow['audit_records']})
            inputs=[ROOT/name for name in ['Dockerfile','compose.yaml','.dockerignore','models.lock.json']]+list(ROOT.glob('*.py'))+list((ROOT/'web').glob('*'))
            return {'status':'measured','checks':checks,'passed':sum(c['passed'] for c in checks),'total':len(checks),
                    'engine':version.get('Server',{}).get('Version'),'project':project,
                    'image_ids':{role:r['Image'] for role,r in records.items()},
                    'source_sha256':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs if p.is_file()},
                    'scope':'Actual disposable Compose workloads: role network segmentation with live positive controls, read-only filesystem, non-root tokens, source packaging and absence of host bind mounts. Synthetic service credentials only; no ports published.',
                    'unverified':['Internet egress to an external destination','Kernel escape resistance','Live provider deployment','Local ONNX/Ollama deployment inside containers']}
        except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired) as error:
            diagnostic=''
            try:
                diagnostic=execute([*compose,'logs','--no-color','--tail','15'],env=environment,timeout=20)[-6000:]
                health=[]
                for role in ['red','blue','target','gateway']:
                    id=execute([*compose,'ps','-a','-q',role],env=environment).strip()
                    if id:
                        row=json.loads(execute(['docker','inspect',id]))[0]
                        health.append({'role':role,'state':row['State'].get('Status'),'exit':row['State'].get('ExitCode'),
                            'health':row['State'].get('Health',{}).get('Log',[])[-1:]})
                diagnostic+='\nHEALTH: '+json.dumps(health)
            except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired):pass
            for key,value in environment.items():
                if key.startswith('SZ_') and value:diagnostic=diagnostic.replace(value,'[REDACTED]')
            raise RuntimeError(str(error)+'\n'+diagnostic) from None
        finally:
            if started:
                # This random project was created by this invocation only.
                execute([*compose,'down','--volumes','--remove-orphans'],env=environment,timeout=60)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);args=parser.parse_args()
    try:report=verify()
    except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired) as error:report={'status':'failed','checks':[],'reason':str(error)}
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['status']=='measured' and report['passed']==report['total'] else 2)
