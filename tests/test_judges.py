"""Judge launch contracts: auth, private workspace, no unintended inference."""
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

from judge_start import create_judge_server, judge_environment
from server import ROOT, judge_state
from test_core import request


class JudgeLaunchTests(unittest.TestCase):
    def test_process_environment_ignores_old_providers_and_keys(self):
        with patch.dict(os.environ, {'SZ_MODEL': 'paid-model', 'SZ_MODE': 'containers',
                                   'SZ_ACCESS_CODE': 'old-key', 'SZ_MODEL_API_KEY': 'old-secret',
                                   'RED_URL': 'http://invalid.example', 'UNRELATED_SETTING': 'keep'}):
            judge_environment(Path('judge-output'))
            self.assertEqual(os.environ['SZ_MODE'], 'local')
            self.assertEqual(os.environ['SZ_MODEL'], '')
            self.assertNotIn('SZ_MODEL_API_KEY', os.environ)
            self.assertNotIn('SZ_ACCESS_CODE', os.environ)
            self.assertNotIn('RED_URL', os.environ)
            self.assertEqual(os.environ['UNRELATED_SETTING'], 'keep')
            self.assertEqual(os.environ['SZ_JUDGE_LOCAL_MODELS'], '0')

    def session(self, directory, enabled=False, port=0):
        server, key, address, browser_url = create_judge_server(port, directory, enabled)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop():
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        self.addCleanup(stop)
        return key, address, browser_url

    def test_launch_auth_bootstrap_and_separate_workspace(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ):
            root = Path(temp); original = root / '.data'; original.mkdir()
            marker = original / 'keep.txt'; marker.write_text('untouched')
            key, address, bootstrap = self.session(root / '.judge-data')
            parsed = urlparse(bootstrap)
            self.assertEqual(parsed.query, '')
            self.assertEqual(parse_qs(parsed.fragment), {'connect': [key], 'page': ['judge']})
            self.assertEqual(urlparse(address).hostname, '127.0.0.1')
            self.assertEqual(request(address + '/api/state', token='wrong')[0], 401)
            status, state = request(address + '/api/state', token=key)
            self.assertEqual(status, 200)
            self.assertTrue(state['judge']['enabled'])
            self.assertFalse(state['judge']['local_models_enabled'])
            self.assertEqual(state['target_mode'], 'fixture')
            self.assertNotIn(key, json.dumps(state))
            self.assertEqual(marker.read_text(), 'untouched')
            self.assertTrue((root / '.judge-data').is_dir())

    def test_core_works_but_optional_inference_is_blocked_without_calls(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ):
            key, address, _ = self.session(Path(temp))
            with patch('local_target.identity', side_effect=AssertionError('Ollama must not be contacted')), \
                 patch('ml_lab.ModelLab.execute', side_effect=AssertionError('Models must not run')):
                for route, payload in [('/api/target/run', {}), ('/api/ml/duel', {}),
                                       ('/api/ml/benchmark', {}), ('/api/ml/probe', {}),
                                       ('/api/run', {'profile': 'ml'})]:
                    status, result = request(address + route, payload, token=key)
                    self.assertEqual(status, 409, route)
                    self.assertIn('disabled', result['error'])
                status, result = request(address + '/api/run', {'suite': 'quick', 'profile': 'hardened'}, token=key)
                self.assertEqual(status, 200)
                self.assertEqual(len(result['events']), 6)
                self.assertTrue(all(e['target_mode'] == 'fixture' for e in result['events']))

    def test_opt_in_does_not_automatically_run_a_model(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ), \
             patch('local_target.identity', side_effect=AssertionError('No automatic inference')):
            key, address, _ = self.session(Path(temp), enabled=True)
            self.assertTrue(request(address + '/api/state', token=key)[1]['judge']['local_models_enabled'])
            with patch('local_target.LocalTargetLab.run', return_value={'test': 'explicit model action'}) as run:
                status, _ = request(address + '/api/target/run', {}, token=key)
                self.assertEqual(status, 200)
                run.assert_called_once()

    def test_busy_port_is_skipped_without_interfering_with_listener(self):
        with socket.socket() as occupied, tempfile.TemporaryDirectory() as temp, patch.dict(os.environ):
            occupied.bind(('127.0.0.1', 0)); occupied.listen()
            port = occupied.getsockname()[1]
            server, _, _, _ = create_judge_server(port, temp)
            self.addCleanup(server.server_close)
            self.assertNotEqual(server.server_port, port)
            self.assertEqual(occupied.getsockname()[1], port)

    def test_each_launch_uses_a_new_key(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ):
            a, ka, _, _ = create_judge_server(0, Path(temp) / 'a')
            b, kb, _, _ = create_judge_server(0, Path(temp) / 'b')
            self.addCleanup(a.server_close); self.addCleanup(b.server_close)
            self.assertNotEqual(ka, kb)
            self.assertGreaterEqual(len(ka), 24)

    def test_recorded_export_contains_outcomes_not_private_or_live_state(self):
        recorded = judge_state()['recorded_target']
        self.assertEqual(recorded['kind'], 'recorded-local-target-demonstration')
        self.assertEqual(recorded['target_calls'], 5)
        self.assertEqual(recorded['requests'], 6)
        self.assertEqual(len(recorded['rows']), 6)
        self.assertNotIn('SZ_CANARY_', json.dumps(recorded))
        self.assertNotIn('response', recorded['rows'][0])
        self.assertEqual(set(recorded['rows'][0]), {'id', 'name', 'profile', 'outcome'})

    def test_missing_recording_does_not_prevent_startup(self):
        with patch('server.ROOT', Path('nonexistent-judge-recording')):
            self.assertIsNone(judge_state()['recorded_target'])


if __name__ == '__main__':
    unittest.main()
