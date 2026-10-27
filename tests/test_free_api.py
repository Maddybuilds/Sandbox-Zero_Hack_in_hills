"""Free-provider setup is tested with fake credentials and local mock endpoints."""
import io
import json
import os
import tempfile
import subprocess
import shutil
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import test_core
from test_core import request,serving
from envfile import load_env_file
from catalog import redact
from server import respond,ModelServiceError,make_handler


@contextmanager
def model_endpoint(status=200,text='Public demo status: healthy'):
    calls=[]
    class Model(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append({'body':body,'authorization':self.headers.get('Authorization')})
            self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers()
            value={'choices':[{'message':{'content':text}}]} if status==200 else {'error':{'message':'Sensitive provider diagnostic gsk_never_expose_this_test_key'}}
            self.wfile.write(json.dumps(value).encode())
    with serving(Model) as url:yield url,calls


class EnvFileTests(unittest.TestCase):
    def test_env_literals_existing_environment_and_bom(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'.env'
            path.write_text("# comment\nSZ_MODEL=from-file\nexport SZ_MODEL_API_KEY='literal$(command)`value'\nSZ_ACCESS_CODE=abc=def\n",encoding='utf-8-sig')
            env={'SZ_MODEL':''}
            keys=load_env_file(path,env)
            self.assertEqual(env['SZ_MODEL'],'')
            self.assertEqual(env['SZ_MODEL_API_KEY'],'literal$(command)`value')
            self.assertEqual(env['SZ_ACCESS_CODE'],'abc=def')
            self.assertEqual(set(keys),{'SZ_MODEL_API_KEY','SZ_ACCESS_CODE'})

    def test_invalid_env_does_not_partially_apply_or_expose_values(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'.env';path.write_text('SZ_MODEL=safe\nBAD=secret-should-not-print\n')
            env={}
            with self.assertRaises(ValueError) as result:load_env_file(path,env)
            self.assertEqual(env,{})
            self.assertNotIn('secret-should-not-print',str(result.exception))

    def test_starter_preset_keeps_fixture_until_explicit_model_selection(self):
        env={};load_env_file(Path(__file__).parents[1]/'.env.example',env)
        self.assertEqual(env['SZ_MODEL'],'');self.assertEqual(env['SZ_MODEL_API_KEY'],'')
        self.assertEqual(env['SZ_MODEL_BASE_URL'],'https://api.groq.com/openai/v1')

    def test_groq_key_redacted_before_evidence_is_hashed(self):
        self.assertEqual(redact('key=gsk_secret_demo_123456789'),'key=[REDACTED_API_KEY]')

    @unittest.skipUnless(os.name=='nt' and shutil.which('powershell'),'Windows launcher test')
    def test_container_launcher_preserves_existing_api_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            shutil.copy2(Path(__file__).parents[1]/'start.ps1',root/'start.ps1')
            (root/'.env').write_text('SZ_MODEL=mock-model\nSZ_MODEL_API_KEY=gsk_fake_keep_this_value\nSZ_ACCESS_CODE=keep-existing-access')
            command="function global:docker { $global:LASTEXITCODE=0; Write-Output 'MOCK_DOCKER' }; & '"+str(root/'start.ps1').replace("'","''")+"' -Containers"
            completed=subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',command],capture_output=True,text=True,timeout=15)
            self.assertEqual(completed.returncode,0,completed.stderr)
            values={};load_env_file(root/'.env',values)
            self.assertEqual(values['SZ_MODEL_API_KEY'],'gsk_fake_keep_this_value')
            self.assertEqual(values['SZ_ACCESS_CODE'],'keep-existing-access')
            self.assertTrue(all(values.get(key) for key in ['SZ_RED_TOKEN','SZ_BLUE_TOKEN','SZ_TARGET_TOKEN']))
            self.assertNotIn('gsk_fake_keep_this_value',completed.stdout+completed.stderr)


class FreeModelAdapterTests(unittest.TestCase):
    def test_groq_request_has_bounded_reasoning_and_key_only_in_header(self):
        captured=[]
        class Response(io.BytesIO):
            def __enter__(self):return self
            def __exit__(self,*_):self.close()
        def fake_open(req,timeout):
            captured.append(req)
            return Response(json.dumps({'choices':[{'message':{'content':'Public status healthy'}}]}).encode())
        with patch.dict(os.environ,{'SZ_MODEL':'openai/gpt-oss-20b','SZ_MODEL_BASE_URL':'https://api.groq.com/openai/v1','SZ_MODEL_API_KEY':'gsk_secret_demo_123456789'}),patch('server.urlopen',fake_open):
            reply=respond({'action':'chat','payload':'Summarize public status','fixture_reply':'MUST_NOT_REACH_MODEL','expected':'held'},'SZ_CANARY_demo')
        body=json.loads(captured[0].data)
        self.assertEqual(captured[0].full_url,'https://api.groq.com/openai/v1/chat/completions')
        self.assertEqual(body['reasoning_effort'],'low');self.assertEqual(body['max_completion_tokens'],512)
        self.assertNotIn('MUST_NOT_REACH_MODEL',json.dumps(body));self.assertNotIn('gsk_secret_demo_123456789',json.dumps(body))
        self.assertEqual(reply['text'],'Public status healthy')

    def test_missing_remote_key_never_makes_a_request(self):
        with patch.dict(os.environ,{'SZ_MODEL':'openai/gpt-oss-20b','SZ_MODEL_BASE_URL':'https://api.groq.com/openai/v1'}),patch('server.urlopen') as network:
            os.environ.pop('SZ_MODEL_API_KEY',None)
            with self.assertRaises(ModelServiceError) as result:respond({'payload':'Hi'},'SZ_CANARY_demo')
            self.assertEqual(result.exception.code,'configuration');network.assert_not_called()

    def test_empty_response_is_a_failure_not_an_allowed_answer(self):
        with model_endpoint(text='') as (url,calls),patch.dict(os.environ,{'SZ_MODEL':'mock-free','SZ_MODEL_BASE_URL':url}):
            with self.assertRaises(ModelServiceError) as result:respond({'payload':'Hi'},'SZ_CANARY_demo')
        self.assertEqual(result.exception.code,'response');self.assertEqual(len(calls),1)


class FreeModelGatewayTests(unittest.TestCase):
    setUp=test_core.GatewayTests.setUp

    def test_quota_or_bad_key_stops_whole_run_without_retries_or_fallback(self):
        for code,expected in [(429,'rate_limit'),(401,'authentication')]:
            with self.subTest(code=code),model_endpoint(status=code) as (url,calls),patch.dict(os.environ,{'SZ_MODEL':'mock-free','SZ_MODEL_BASE_URL':url,'SZ_MODEL_API_KEY':'gsk_never_expose_this_test_key'}):
                status,result=request(self.url+'/api/run',{'suite':'advanced','profile':'hardened'})
                self.assertEqual(status,200);self.assertEqual(len(calls),1);self.assertEqual(len(result['events']),1)
                event=result['events'][0]
                self.assertEqual(event['outcome'],'failed');self.assertEqual(event['failure_code'],expected)
                self.assertEqual(event['target_mode'],'live');self.assertIsNone(event['response'])
                self.assertTrue(result['stopped_reason']);self.assertNotIn('gsk_never_expose_this_test_key',json.dumps(result))
                _,state=request(self.url+'/api/state');self.assertNotIn('gsk_never_expose_this_test_key',json.dumps(state))
        self.assertTrue(self.audit.verify()['valid'])

    def test_rate_limit_survives_target_service_boundary(self):
        with model_endpoint(status=429) as (url,calls),patch.dict(os.environ,{'SZ_MODEL':'mock-free','SZ_MODEL_BASE_URL':url}):
            with serving(make_handler('red')) as red,serving(make_handler('blue')) as blue,serving(make_handler('target')) as target:
                with patch.dict(os.environ,{'SZ_MODE':'containers','RED_URL':red,'BLUE_URL':blue,'TARGET_URL':target}),serving(make_handler('gateway',self.audit,'test-code')) as gateway:
                    status,result=request(gateway+'/api/run',{'suite':'advanced','profile':'hardened'})
        self.assertEqual(status,200);self.assertEqual(len(calls),1)
        self.assertEqual(result['events'][0]['failure_code'],'rate_limit')
        self.assertEqual(len(result['events']),1)


if __name__=='__main__':unittest.main()
