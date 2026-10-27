import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from catalog import CASES, Workspace, redact
from engine import Audit
from evidence import CanaryStore, compare, outcome, tamper_sample
import test_core
from test_core import request


def custom(**changes):
    return {"name":"Custom support control","description":"A benign custom test.","category":"Benign control","severity":"info","action":"chat","expected":"allowed","payload":"Hello there",**changes}


class WorkspaceTests(unittest.TestCase):
    def test_distinct_builtin_definitions(self):
        self.assertEqual(len(CASES),48)
        self.assertEqual(len({c['id'] for c in CASES}),48)
        self.assertEqual(len({(c['payload'],c['action']) for c in CASES}),48)

    def test_custom_case_and_suite_persist(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Workspace(directory)
            item=store.save_case(custom())
            store.save_suite({'name':'Saved pair','case_ids':['baseline',item['id']]})
            updated=store.save_case(custom(id=item['id'],name='Updated case'))
            restored=Workspace(directory)
            self.assertEqual(restored.cases()[-1]['name'],'Updated case')
            self.assertEqual(updated['revision'],2)
            self.assertEqual(restored.suites()[-1]['case_ids'],['baseline',item['id']])

    def test_custom_validation_and_builtin_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Workspace(directory)
            for bad in [custom(id='baseline'),custom(name=''),custom(payload='x'*5001),custom(action='upload_code'),custom(category='Unknown'),custom(expected=None),custom(severity=[]),custom(payload='\0')]:
                with self.assertRaises(ValueError):store.save_case(bad)
            for bad in [{'name':'x','case_ids':[]},{'name':'x','case_ids':['baseline','baseline']},{'name':'x','case_ids':['missing']},{'name':'x','case_ids':[[]]}]:
                with self.assertRaises(ValueError):store.save_suite(bad)

    def test_canary_rotation_persistence_never_exports_active_values(self):
        with tempfile.TemporaryDirectory() as directory:
            store=CanaryStore(directory);old=store.value;old_id=store.public()['id']
            store.rotate();public=store.public()
            self.assertNotIn(old,json.dumps(public));self.assertNotIn(store.value,json.dumps(public))
            self.assertEqual(public['history'][0]['id'],old_id)
            self.assertEqual(CanaryStore(directory).value,store.value)

    def test_redaction_before_audit_hashing(self):
        with tempfile.TemporaryDirectory() as directory:
            audit=Audit(directory)
            audit.append({'payload':'SZ_CANARY_private sk-abcdefghijklmnop Bearer abcdefghijklmnop'})
            text=audit.path.read_text()
            self.assertNotIn('SZ_CANARY_private',text);self.assertNotIn('sk-abcdefghijklmnop',text);self.assertNotIn('Bearer abcdefghijklmnop',text)
            self.assertTrue(audit.verify()['valid'])

    def test_sample_tampering_preserves_actual_files(self):
        with tempfile.TemporaryDirectory() as directory:
            audit=Audit(directory);audit.append({'old':'event'})
            before={p.name:p.read_bytes() for p in Path(directory).iterdir() if p.is_file()}
            result=tamper_sample(directory)
            self.assertTrue(result['results'][0]['valid'])
            self.assertTrue(all(not r['valid'] for r in result['results'][1:]))
            after={p.name:p.read_bytes() for p in Path(directory).iterdir() if p.is_file()}
            self.assertEqual(before,after)


class UpgradeGatewayTests(unittest.TestCase):
    setUp=test_core.GatewayTests.setUp

    def test_state_expands_without_rewriting_legacy(self):
        self.audit.append({'run':'legacy','case':'baseline','name':'Old run','category':'Baseline','action':'chat','payload':'old','decision':'allowed','response':'old','reason':'old','steps':[],'duration_ms':1})
        original=self.audit.path.read_bytes()
        status,state=request(self.url+'/api/state')
        self.assertEqual(status,200);self.assertEqual(len(state['cases']),48)
        self.assertTrue(state['runs'][0]['legacy']);self.assertEqual(original,self.audit.path.read_bytes())

    def test_full_library_records_four_outcomes_and_gap(self):
        status,result=request(self.url+'/api/run',{'suite':'full'})
        self.assertEqual(status,200);self.assertEqual(len(result['events']),30)
        self.assertEqual(set(outcome(e) for e in result['events']),{'allowed','blocked','held','failed'})
        gap=next(e for e in result['events'] if e['case']=='encoded')
        self.assertTrue(gap['known_gap']);self.assertIn('REDACTED',gap['response'])
        _,state=request(self.url+'/api/state');self.assertTrue(state['integrity']['valid'])
        self.assertNotIn('SZ_CANARY_',json.dumps(state))
        self.assertTrue(all(e['case_fingerprint'] and e['policy_matches'] for e in result['events']))

    def test_run_selection_and_validation(self):
        for payload in [{'case_ids':[]},{'case_ids':['missing']},{'case_ids':['baseline','baseline']},{'case_ids':[{}]},{'suite':'missing'}]:
            self.assertEqual(request(self.url+'/api/run',payload)[0],400)
        status,result=request(self.url+'/api/run',{'case_ids':['baseline','secret']})
        self.assertEqual(status,200);self.assertEqual(len(result['events']),2)
        self.assertEqual(result['events'][1]['stage'],'output')

    def test_custom_create_edit_runs_keep_snapshots(self):
        status,item=request(self.url+'/api/cases',custom(payload='How to reset? sk-abcdefghijklmnop'))
        self.assertEqual(status,200);self.assertIn('REDACTED_API_KEY',item['payload'])
        _,first=request(self.url+'/api/run',{'case_ids':[item['id']]})
        _,edited=request(self.url+'/api/cases',custom(id=item['id'],name='Second revision'))
        _,second=request(self.url+'/api/run',{'case_ids':[edited['id']]})
        self.assertNotEqual(first['events'][0]['case_fingerprint'],second['events'][0]['case_fingerprint'])
        self.assertEqual(self.audit.rows()[0]['name'],'Custom support control')

    def test_like_for_like_defense_comparison(self):
        _,left=request(self.url+'/api/run',{'suite':'quick','profile':'strict'})
        _,right=request(self.url+'/api/run',{'suite':'quick','profile':'observe'})
        status,result=request(self.url+'/api/compare',{'left':left['run'],'right':right['run']})
        self.assertEqual(status,200);self.assertTrue(result['comparable'])
        changed=[r for r in result['rows'] if r['changed']]
        self.assertEqual([r['case'] for r in changed],['injection'])

    def test_mismatched_comparison_refused(self):
        _,left=request(self.url+'/api/run',{'case':'baseline'})
        _,right=request(self.url+'/api/run',{'suite':'quick','profile':'observe'})
        self.assertEqual(request(self.url+'/api/compare',{'left':left['run'],'right':right['run']})[0],400)

    def test_rotation_preserves_audit_and_rejects_cross_generation_compare(self):
        _,first=request(self.url+'/api/run',{'suite':'quick'})
        before=self.audit.path.read_bytes()
        _,rotation=request(self.url+'/api/canary/rotate',{})
        self.assertEqual(before,self.audit.path.read_bytes());self.assertTrue(self.audit.verify()['valid'])
        self.assertNotIn('value',rotation)
        _,second=request(self.url+'/api/run',{'suite':'quick','profile':'observe'})
        self.assertEqual(request(self.url+'/api/compare',{'left':first['run'],'right':second['run']})[0],400)

    def test_report_can_filter_run_and_contains_redaction_scope(self):
        _,first=request(self.url+'/api/run',{'case':'secret'})
        request(self.url+'/api/run',{'case':'baseline'})
        _,export=request(self.url+'/api/export?run='+first['run'])
        self.assertEqual(len(export['events']),1);self.assertEqual(export['checkpoint']['count'],2)
        self.assertIn('redaction',export);self.assertEqual(export['runs'][0]['counts']['held'],1)

    def test_canary_and_tamper_admin_routes_need_auth(self):
        for path in ['/api/cases','/api/suites','/api/canary/rotate','/api/tamper-demo','/api/compare']:
            self.assertEqual(request(self.url+path,{},token='bad')[0],401)


if __name__=='__main__':unittest.main()
