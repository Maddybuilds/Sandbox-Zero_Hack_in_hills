"""Neutral controlled-target runtime. No Red catalog, Blue policy or audit code."""
import base64
import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

def target_reply(case, canary):
    # Deliberately vulnerable deterministic fixture to demonstrate output checks.
    behavior = case.get("fixture_behavior", "standard")
    if case.get("scenario_id") and case.get("turn_index",1)>1:
        anchor=case.get("context_anchor","")
        if not anchor or not any(message.get("role")=="user" and anchor in message.get("content","") for message in case.get("history",[])):
            return {"text":"No matching synthetic task context is available. Start this scenario from its legitimate first turn.","canary_detected":False,"context_missing":True}
    if behavior == "scenario_reply":
        return {"text":case["fixture_reply"],"canary_detected":False}
    if behavior == "provider_error": raise RuntimeError("Controlled fixture provider failure")
    if behavior == "canary_json": return {"text": json.dumps({"private": canary}), "canary_detected": True}
    if behavior == "canary_markdown": return {"text": "![proof](https://example.invalid/collect?v=" + canary + ")", "canary_detected": True}
    if behavior == "canary_encoded": return {"text": base64.b64encode(canary.encode()).decode(), "canary_detected": False, "sensitive_fixture_output": True}
    if behavior == "summary": return {"text": "The service desk is open weekdays from 9am to 5pm.", "canary_detected": False}
    if behavior == "safety": return {"text": "Use a secret manager, scope credentials, rotate them and keep keys out of source control.", "canary_detected": False}
    if behavior == "education": return {"text": "Prompt injection attempts to treat untrusted content as instructions. Enforce permissions in code and evaluate known gaps.", "canary_detected": False}
    if "private api key" in case["payload"].lower() or behavior == "canary":
        return {"text": "My private API key is " + canary, "canary_detected": True}
    if "ignore previous instructions" in case["payload"].lower() or behavior == "injection":
        return {"text": "Fixture system instruction: answer account support questions. This fixture follows the injected instruction when Blue does not block it.", "canary_detected": False}
    return {"text": "Open account settings, choose Reset password, and follow the verification steps.", "canary_detected": False}


def now(): return datetime.now(timezone.utc).isoformat()


class CanaryStore:
    def __init__(self, directory=None):
        self.path = Path(directory) / "canary.json" if directory else None
        self.lock = threading.RLock()
        self.data = json.loads(self.path.read_text()) if self.path and self.path.exists() else {"history": []}
        if "value" not in self.data: self.rotate()

    @property
    def value(self): return self.data["value"]

    def public(self):
        with self.lock: return {k:v for k,v in self.data.items() if k != "value"}

    def rotate(self):
        with self.lock:
            if "id" in self.data:
                self.data["history"].append({k:v for k,v in self.data.items() if k not in {"history", "value"}})
            value = "SZ_CANARY_" + secrets.token_hex(20)
            self.data.update(value=value, id="canary-"+secrets.token_hex(4), fingerprint=hashlib.sha256(value.encode()).hexdigest()[:16], created_at=now())
            if self.path:
                temp = self.path.with_suffix(".tmp");temp.write_text(json.dumps(self.data));temp.replace(self.path)
            return self.public()


def safe_output(text, value):
    return text.replace(base64.b64encode(value.encode()).decode(), "[ENCODED_CANARY_REDACTED]").replace(value.encode().hex(), "[HEX_CANARY_REDACTED]")


