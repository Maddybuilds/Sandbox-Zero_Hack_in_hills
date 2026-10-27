"""Bounded application-contract checks against real, disposable local workers.

This checks protocol authorization and packaging. It does not establish OS isolation.
"""
import hashlib
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError,URLError
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parent


def exchange(url,route,body=None,token=None,timeout=2):
    headers={'Content-Type':'application/json'}
    if token:headers['X-Participant-Token']=token
    request=Request(url+route,headers=headers,data=json.dumps(body).encode() if body is not None else None)
    try:
        with urlopen(request,timeout=timeout) as response:return response.status,json.loads(response.read(8192))
    except HTTPError as error:
        with error:return error.code,json.loads(error.read(8192))


def run_boundary_checks():
    checks=[];children=[];workers={};tokens={role:secrets.token_urlsafe(24) for role in ['red','blue']}
    def check(id,name,role,route,body,credential,expected,predicate=lambda value:True):
        start=time.perf_counter()
        try:
            status,value=exchange(workers[role],route,body,credential)
            passed=status==expected and predicate(value)
            observed={'http_status':status,'response':value}
        except (OSError,ValueError,URLError):passed=False;observed={'error':'Local worker request failed'}
        checks.append({'id':id,'name':name,'role':role,'route':route,'expected_status':expected,'observed':observed,
                       'passed':passed,'duration_ms':round((time.perf_counter()-start)*1000,2),'scope':'Application protocol'})
    with tempfile.TemporaryDirectory(prefix='sz-contract-') as temporary:
        base=Path(temporary).resolve()
        try:
            for role in ['red','blue']:
                directory=base/role;directory.mkdir()
                shutil.copy2(ROOT/'participants.py',directory/'participants.py')
                if role=='blue':shutil.copy2(ROOT/'policy.py',directory/'policy.py')
                else:(directory/'red_cases.json').write_text(json.dumps([{'id':'contract-control','payload':'Hello from a synthetic contract test.','action':'chat'}]),encoding='utf-8')
                listener=socket.socket();listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.close()
                env={k:v for k,v in os.environ.items() if k.lower() in {'systemroot','windir','path','temp','tmp','lang','lc_all'}}
                env.update(SZ_PARTICIPANT_TOKEN=tokens[role],PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1')
                child=subprocess.Popen([sys.executable,'participants.py','--role',role,'--port',str(port)],cwd=directory,
                    env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                children.append(child);workers[role]=f'http://127.0.0.1:{port}'
                ready=False
                for _ in range(60):
                    try:
                        if exchange(workers[role],'/health',timeout=.25)[0]==200:ready=True;break
                    except (OSError,ValueError):pass
                    if child.poll() is not None:break
                    time.sleep(.05)
                if not ready:raise RuntimeError('A disposable participant did not start; contract results were not fabricated.')
            control={'payload':'How can I reset a demo account password?','action':'chat','profile':'hardened'}
            check('AUTH-RED','Red catalog requires its service token','red','/cases',None,None,401)
            check('AUTH-BLUE','Blue inspection rejects missing credentials','blue','/inspect',control,None,401)
            check('AUTH-CROSS','Red credential cannot authorize a Blue request','blue','/inspect',control,tokens['red'],401)
            check('CTRL-BLUE','Valid Blue credential permits a benign control','blue','/inspect',control,tokens['blue'],200,lambda v:v.get('allowed') is True)
            check('META-BLUE','Blue rejects coordinator-only answer labels','blue','/inspect',{**control,'expected':'allowed','fixture_behavior':'secret'},tokens['blue'],400)
            check('META-RED','Red rejects hidden fields in its prepare message','red','/prepare',{'cases':[{'payload':'Hello','action':'chat','blue_policy':'hidden'}]},tokens['red'],400)
            check('ROUTE-BLUE','Blue exposes no Red catalog route','blue','/cases',None,tokens['blue'],404)
            check('ROUTE-FILE','Blue exposes no source-file download route','blue','/policy.py',None,tokens['blue'],404)
            check('CTRL-RED','Red accepts the minimal prepare contract','red','/prepare',{'cases':[{'payload':'Hello','action':'chat'}]},tokens['red'],200,lambda v:v==[{'payload':'Hello','action':'chat'}])
            check('OUT-CANARY','Blue output guard holds a synthetic marker','blue','/inspect-output',{'text':'SZ_CANARY_contract_probe','profile':'hardened'},tokens['blue'],200,lambda v:v.get('held') is True)
            manifests={role:sorted(p.name for p in (base/role).iterdir() if p.is_file()) for role in ['red','blue']}
            packaging=manifests['red']==['participants.py','red_cases.json'] and manifests['blue']==['participants.py','policy.py']
            checks.append({'id':'SOURCE-SPLIT','name':'Temporary role source trees contain only their required files','passed':packaging,
                'scope':'Source packaging','observed':{'files':manifests},'duration_ms':0})
        finally:
            for child in children:
                if child.poll() is None:child.terminate()
            for child in children:
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
    return {'checks':checks,'passed':sum(c['passed'] for c in checks),'total':len(checks),'separate_processes':True,
            'platform':platform.system(),'python':platform.python_version(),
            'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['participants.py','policy.py']},
            'scope':'Real local subprocess and HTTP checks of authorization, message schemas, routes and temporary source packaging.',
            'unverified':['Container execution and hostile-process isolation','OS-level filesystem access denial','OS-level network egress denial'],
            'limitations':'Workers share the current user and host. TCP access to Blue succeeds; its application token rejects unauthorized requests. Missing files in a temporary role folder do not prevent access elsewhere on the host.'}
