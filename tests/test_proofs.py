"""Proof claims, actual worker observations, signed bytes and fail-closed exports."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request,urlopen

from boundary_probe import run_boundary_checks
from engine import Audit
from proofs import ProofLab
from server import evaluate_request,make_handler
from verify_proof import verify
from test_core import request,serving

CRYPTO=importlib.util.find_spec('cryptography') is not None


class BoundaryProbeTests(unittest.TestCase):
    def test_real_local_worker_contracts_are_scoped_and_credential_free(self):
        result=run_boundary_checks()
        self.assertEqual(result['total'],11);self.assertEqual(result['passed'],11)
        self.assertTrue(result['separate_processes']);self.assertEqual(len(result['unverified']),3)
        cross=next(c for c in result['checks'] if c['id']=='AUTH-CROSS')
        self.assertEqual(cross['observed']['http_status'],401)
        self.assertIn('TCP access',result['limitations'])
        self.assertNotIn('SZ_PARTICIPANT_TOKEN',json.dumps(result))


@unittest.skipUnless(CRYPTO,'Optional cryptography evidence-signing dependency is not installed')
class SignedProofTests(unittest.TestCase):
    def make_proof(self,temp):return ProofLab(Path(temp)).run(evaluate_request)

    def test_fixed_plan_forces_fixture_even_when_a_remote_model_is_configured(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{'SZ_MODEL':'must-not-be-called'}),patch('server.respond',side_effect=AssertionError('Remote response path was called')):
            record=self.make_proof(temp);report=json.loads(record['envelope']['payload'])
        self.assertTrue(report['all_observed_checks_matched'])
        self.assertEqual(len(report['pairs']),6);self.assertEqual(report['boundary']['passed'],11)
        encoded=next(p for p in report['pairs'] if p['id']=='encoded')
        self.assertEqual(encoded['strict']['outcome'],'allowed');self.assertEqual(encoded['hardened']['outcome'],'held')
        self.assertEqual(encoded['strict']['response'],'[ENCODED_CANARY_REDACTED]')
        quoted=next(p for p in report['pairs'] if p['id']=='quote-control')
        self.assertEqual(quoted['strict']['outcome'],'blocked');self.assertEqual(quoted['hardened']['outcome'],'allowed')

    def test_signed_payload_tamper_and_wrong_trust_anchor_fail(self):
        from cryptography.exceptions import InvalidSignature
        with tempfile.TemporaryDirectory() as temp:
            record=self.make_proof(temp);envelope=record['envelope'];expected=ProofLab(Path(temp)).state()['signer_fingerprint']
            result=verify(envelope,expected);self.assertTrue(result['trusted_key_matched'])
            changed=copy.deepcopy(envelope);changed['payload']+=' '
            with self.assertRaises(InvalidSignature):verify(changed,expected)
            with self.assertRaises(ValueError):verify(envelope,'0'*64)
            self.assertTrue(verify(envelope)['signature_valid']);self.assertFalse(verify(envelope)['trusted_key_matched'])

    def test_bundle_assets_verify_and_private_keys_are_excluded(self):
        with tempfile.TemporaryDirectory() as temp,tempfile.TemporaryDirectory() as extracted:
            lab=ProofLab(Path(temp));record=lab.run(evaluate_request)
            with zipfile.ZipFile(io.BytesIO(lab.bundle())) as archive:
                self.assertEqual(set(archive.namelist()),{'proof.json','report.html','verify_proof.py'})
                for name in archive.namelist():(Path(extracted)/name).write_bytes(archive.read(name))
            envelope=json.loads((Path(extracted)/'proof.json').read_text())
            fingerprint=lab.state()['signer_fingerprint']
            self.assertTrue(verify(envelope,fingerprint,Path(extracted))['assets_verified'])
            (Path(extracted)/'report.html').write_text('forged report')
            with self.assertRaises(ValueError):verify(envelope,fingerprint,Path(extracted))
            self.assertNotIn('assets',record)

    def test_failed_checks_remain_failed_even_in_a_signed_report(self):
        failed={'checks':[{'id':'TEST','name':'Simulated failed contract','passed':False}],
                'passed':0,'total':1,'unverified':['OS isolation'],'limitations':'Test stub'}
        with tempfile.TemporaryDirectory() as temp,patch('proofs.run_boundary_checks',return_value=failed):
            record=self.make_proof(temp);report=json.loads(record['envelope']['payload'])
        self.assertFalse(report['all_observed_checks_matched']);self.assertEqual(report['boundary']['passed'],0)
        self.assertTrue(verify(record['envelope'])['signature_valid'])

    def test_proof_history_preserves_main_data_and_key_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            main=Audit(temp);main.append({'decision':'allowed','original':True})
            before={p.name:p.read_bytes() for p in Path(temp).iterdir() if p.is_file()}
            lab=ProofLab(Path(temp));lab.run(evaluate_request);fingerprint=lab.state()['signer_fingerprint']
            lab.run(evaluate_request)
            self.assertEqual(lab.state()['signer_fingerprint'],fingerprint)
            self.assertEqual(lab.state()['integrity']['events'],2)
            for name,value in before.items():self.assertEqual((Path(temp)/name).read_bytes(),value)
            rows=lab.audit.rows();rows[0]['proof_id']='forged';lab.audit.path.write_text('\n'.join(json.dumps(r) for r in rows)+'\n')
            self.assertIsNone(lab.state()['latest'])
            with self.assertRaises(ValueError):lab.bundle()

    def test_proof_routes_require_auth_and_reject_unbounded_plans(self):
        with tempfile.TemporaryDirectory() as temp:
            with serving(make_handler('gateway',Audit(temp),'test-code')) as url:
                self.assertEqual(request(url+'/api/proof/state',token='wrong')[0],401)
                self.assertEqual(request(url+'/api/proof/run',{},token='wrong')[0],401)
                self.assertEqual(request(url+'/api/proof/bundle',token='wrong')[0],401)
                self.assertEqual(request(url+'/api/proof/run',{'url':'https://example.invalid'})[0],400)
                self.assertEqual(request(url+'/api/proof/bundle')[0],400)
                self.assertEqual(request(url+'/api/proof/run',{})[0],200)
                req=Request(url+'/api/proof/bundle',headers={'Authorization':'Bearer test-code'})
                with urlopen(req,timeout=5) as response:
                    self.assertEqual(response.headers['Content-Type'],'application/zip')
                    self.assertTrue(zipfile.is_zipfile(io.BytesIO(response.read())))


if __name__=='__main__':unittest.main()
