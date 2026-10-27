"""Target image separation and end-to-end container protocol compatibility."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from engine import Audit
from server import make_handler
from target_worker import make_target_handler
from test_core import serving,request

ROOT=Path(__file__).resolve().parent.parent


class TargetWorkerTests(unittest.TestCase):
    def test_target_runs_from_two_files_without_red_blue_or_coordinator_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            for name in ['target_worker.py','fixture_runtime.py']:shutil.copy2(ROOT/name,directory/name)
            with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            env={k:v for k,v in os.environ.items() if k.lower() in {'systemroot','windir','path','temp','tmp'}}
            env.update(SZ_PARTICIPANT_TOKEN='target-only-test',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
            child=subprocess.Popen([sys.executable,'target_worker.py','--port',str(port)],cwd=directory,env=env,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            try:
                url=f'http://127.0.0.1:{port}';ready=False
                for i in range(60):
                    try:
                        if request(url+'/health')[0]==200:ready=True;break
                    except OSError:time.sleep(.05)
                self.assertTrue(ready)
                self.assertEqual(sorted(p.name for p in directory.iterdir()),['fixture_runtime.py','target_worker.py'])
                from urllib.request import Request,urlopen
                from urllib.error import HTTPError
                def call(route,body=None,token='target-only-test'):
                    req=Request(url+route,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-Participant-Token':token})
                    try:
                        with urlopen(req,timeout=3) as response:return response.status,json.load(response)
                    except HTTPError as error:
                        with error:return error.code,json.load(error)
                self.assertEqual(call('/canary',token='wrong')[0],401)
                self.assertEqual(call('/policy.py')[0],404)
                self.assertEqual(call('/cases')[0],404)
                self.assertEqual(call('/respond',{'payload':'Hello'},token='red-test')[0],401)
                status,reply=call('/respond',{'payload':'How can I reset my password?'})
                self.assertEqual(status,200);self.assertIn('verification steps',reply['text'])
                old=call('/canary')[1];new=call('/canary/rotate',{})[1]
                self.assertNotIn('value',new);self.assertNotEqual(old['id'],new['id'])
                self.assertEqual(call('/respond',{'payload':'test','fixture_behavior':'provider_error'})[0],502)
            finally:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)

    def test_gateway_red_blue_and_minimal_target_complete_the_existing_protocol(self):
        with tempfile.TemporaryDirectory() as temporary:
            with serving(make_handler('red',token='red-test')) as red,serving(make_handler('blue',token='blue-test')) as blue,serving(make_target_handler('target-test')) as target:
                with patch.dict(os.environ,{'SZ_MODE':'containers','RED_URL':red,'BLUE_URL':blue,'TARGET_URL':target,
                                           'SZ_RED_TOKEN':'red-test','SZ_BLUE_TOKEN':'blue-test','SZ_TARGET_TOKEN':'target-test'}):
                    with serving(make_handler('gateway',Audit(temporary),'test-code')) as gateway:
                        status,result=request(gateway+'/api/run',{'profile':'hardened','suite':'quick'})
                        self.assertEqual(status,200)
                        counts={outcome:sum(e['outcome']==outcome for e in result['events']) for outcome in ['allowed','blocked','held','failed']}
                        self.assertEqual(counts,{'allowed':1,'blocked':4,'held':1,'failed':0})
                        self.assertTrue(request(gateway+'/api/integrity')[1]['valid'])


if __name__=='__main__':unittest.main()
