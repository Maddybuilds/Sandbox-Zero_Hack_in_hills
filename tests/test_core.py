import copy
import hashlib
import json
import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from engine import Audit, CASES, canonical, inspect_request, target_reply
from server import make_handler, respond


@contextmanager
def serving(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def request(url, payload=None, token="test-code", raw=None, mime="application/json"):
    body = raw if raw is not None else None if payload is None else json.dumps(payload).encode()
    req = Request(url, data=body, headers={"Authorization": "Bearer " + token, "Content-Type": mime})
    try:
        with urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        with error:
            return error.code, json.load(error)


class PolicyTests(unittest.TestCase):
    def test_default_deny_unknown_and_cross_tenant_actions(self):
        for action in ["read_file", "connect", "shell", None]:
            self.assertFalse(inspect_request({"action": action, "payload": "anything"})["allowed"])

    def test_input_budget_applies_to_both_profiles(self):
        for profile in ["strict", "observe"]:
            self.assertFalse(inspect_request(next(c for c in CASES if c['id']=='resource'), profile)["allowed"])

    def test_baseline_allowed_and_injection_defense_changes(self):
        self.assertTrue(inspect_request(CASES[0])["allowed"])
        self.assertFalse(inspect_request(CASES[4], "strict")["allowed"])
        self.assertTrue(inspect_request(CASES[4], "observe")["allowed"])

    def test_canary_fixture_is_deliberately_vulnerable(self):
        result = target_reply(CASES[3], "SZ_CANARY_test")
        self.assertIn("SZ_CANARY_test", result["text"])
        self.assertTrue(result["canary_detected"])


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = Audit(self.temp.name)
        for decision in ["allowed", "blocked"]:
            self.audit.append({"decision": decision})

    def test_survives_restart(self):
        self.assertTrue(Audit(self.temp.name).verify()["valid"])
        self.assertEqual(len(Audit(self.temp.name).rows()), 2)

    def test_modified_event_detected(self):
        rows = self.audit.rows()
        rows[0]["decision"] = "forged"
        self.assertFalse(self.audit.verify(rows)["valid"])

    def test_truncation_detected(self):
        self.assertFalse(self.audit.verify(self.audit.rows()[:1])["valid"])

    def test_recomputed_hashes_cannot_bypass_checkpoint(self):
        rows = self.audit.rows()
        rows[0]["decision"] = "forged"
        previous = "0" * 64
        for row in rows:
            row["previous"] = previous
            row["hash"] = hashlib.sha256(canonical({k:v for k,v in row.items() if k != "hash"})).hexdigest()
            previous = row["hash"]
        self.assertFalse(self.audit.verify(rows)["valid"])

    def test_deleted_checkpoint_fails_closed(self):
        self.audit.checkpoint.unlink()
        self.assertFalse(self.audit.verify()["valid"])
        with self.assertRaises(RuntimeError):
            self.audit.append({"decision": "allowed"})

    def test_bad_audit_prevents_startup(self):
        self.audit.path.write_text("corrupt")
        with self.assertRaises(RuntimeError):
            Audit(self.temp.name)

    def test_concurrent_appends_preserve_chain(self):
        threads = [threading.Thread(target=self.audit.append, args=({"decision": "blocked"},)) for _ in range(10)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertTrue(self.audit.verify()["valid"])
        self.assertEqual(len(self.audit.rows()), 12)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = Audit(self.temp.name)
        self.env = patch.dict(os.environ, {"SZ_MODE": "local"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.model_patch = patch.dict(os.environ)
        self.model_patch.start()
        os.environ.pop("SZ_MODEL", None)
        self.addCleanup(self.model_patch.stop)
        self.service = serving(make_handler("gateway", self.audit, "test-code"))
        self.url = self.service.__enter__()
        self.addCleanup(self.service.__exit__, None, None, None)

    def test_private_api_authentication(self):
        self.assertEqual(request(self.url + "/api/state", token="bad")[0], 401)
        self.assertEqual(request(self.url + "/api/run", {}, token="bad")[0], 401)

    def test_full_suite_withheld_canary_and_export(self):
        status, result = request(self.url + "/api/run", {"case": "all"})
        self.assertEqual(status, 200)
        self.assertEqual(len(result["events"]), 6)
        self.assertEqual([e["decision"] for e in result["events"]], ["allowed", "blocked", "blocked", "blocked", "blocked", "blocked"])
        canary = result["events"][3]
        self.assertTrue(canary["canary_detected"])
        self.assertIsNone(canary["response"])
        _, exported = request(self.url + "/api/export")
        self.assertNotIn("SZ_CANARY_", json.dumps(exported))
        self.assertEqual(exported["checkpoint"]["count"], 6)

    def test_observe_profile_changes_injection_result(self):
        _, result = request(self.url + "/api/run", {"case": "injection", "profile": "observe"})
        self.assertEqual(result["events"][0]["decision"], "allowed")

    def test_bad_inputs_rejected(self):
        for payload in [{"case": "unknown"}, {"profile": "invalid"}, {"profile": []}, {"profile": None}]:
            self.assertEqual(request(self.url + "/api/run", payload)[0], 400)
        self.assertEqual(request(self.url + "/api/run", raw=b"invalid")[0], 400)
        self.assertEqual(request(self.url + "/api/run", raw=b"[]")[0], 400)
        self.assertEqual(request(self.url + "/api/run", raw=b"{}", mime="text/plain")[0], 415)
        self.assertEqual(request(self.url + "/api/run", raw=b"x"*40000)[0], 413)

    def test_tampering_stops_run_and_export(self):
        request(self.url + "/api/run", {"case": "baseline"})
        self.audit.path.write_text("corrupt")
        status, state = request(self.url + "/api/state")
        self.assertEqual(status, 200)
        self.assertFalse(state["integrity"]["valid"])
        self.assertEqual(request(self.url + "/api/run", {})[0], 409)
        self.assertEqual(request(self.url + "/api/export")[0], 409)

    def test_fixed_static_routes_only(self):
        self.assertEqual(request(self.url + "/../engine.py")[0], 404)

    def test_participant_http_workflow(self):
        with serving(make_handler("red")) as red, serving(make_handler("blue")) as blue, serving(make_handler("target")) as target:
            with patch.dict(os.environ, {"SZ_MODE": "containers", "RED_URL": red, "BLUE_URL": blue, "TARGET_URL": target}):
                with serving(make_handler("gateway", self.audit, "test-code")) as gateway:
                    status, result = request(gateway + "/api/run", {})
                    self.assertEqual(status, 200)
                    self.assertEqual(len(result["events"]), 6)
                    self.assertTrue(result["events"][3]["canary_detected"])


class ModelAdapterTests(unittest.TestCase):
    def test_live_adapter_with_local_mock_endpoint(self):
        received = []
        class Model(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = json.dumps({"choices": [{"message": {"content": "A synthetic response"}}]}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
        with serving(Model) as url, patch.dict(os.environ, {"SZ_MODEL": "test-model", "SZ_MODEL_BASE_URL": url, "SZ_MODEL_API_KEY": "fake"}):
            result = respond(CASES[0], "SZ_CANARY_test")
        self.assertEqual(result["text"], "A synthetic response")
        self.assertIn("SZ_CANARY_test", received[0]["messages"][0]["content"])
        self.assertEqual(received[0]["model"], "test-model")

    def test_nonlocal_plain_http_rejected(self):
        with patch.dict(os.environ, {"SZ_MODEL": "test-model", "SZ_MODEL_BASE_URL": "http://example.com"}):
            with self.assertRaises(ValueError): respond(CASES[0], "canary")


if __name__ == "__main__":
    unittest.main()
