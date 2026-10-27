"""Controlled evaluation fixtures. Never executes user code or makes user-chosen requests."""
import hashlib
import hmac
import json
import secrets
import threading
import base64
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from catalog import CASES, redact

from policy import inspect_request


from fixture_runtime import target_reply


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class Audit:
    """Hash-linked events with an HMAC checkpoint under a trusted local control plane."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "events.jsonl"
        self.checkpoint = self.directory / "checkpoint.json"
        keypath = self.directory / "audit.key"
        if not keypath.exists():
            keypath.write_bytes(secrets.token_bytes(32))
        self.key = keypath.read_bytes()
        self.lock = threading.RLock()
        report = self.verify()
        if not report["valid"]:
            raise RuntimeError("Audit integrity failed. Preserve .data for investigation; use a new SZ_DATA directory for a fresh demo.")

    def rows(self):
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]

    def verify(self, rows=None):
        try:
            previous = "0" * 64
            entries = self.rows() if rows is None else rows
            for index, row in enumerate(entries, 1):
                event = {k: v for k, v in row.items() if k != "hash"}
                digest = hashlib.sha256(canonical(event)).hexdigest()
                if row["sequence"] != index:
                    return {"valid":False,"events":len(entries),"failure_index":index,"reason":f"Sequence mismatch at record {index}. A record may have moved or been deleted."}
                if row["previous"] != previous:
                    return {"valid":False,"events":len(entries),"failure_index":index,"reason":f"Predecessor link mismatch at record {index}."}
                if not hmac.compare_digest(digest, row["hash"]):
                    return {"valid":False,"events":len(entries),"failure_index":index,"reason":f"Content hash mismatch at record {index}. Stored content differs from its digest."}
                previous = digest
            if self.checkpoint.exists():
                checkpoint = json.loads(self.checkpoint.read_text())
                expected = {"count": len(entries), "head": previous}
                signature = hmac.new(self.key, canonical(expected), hashlib.sha256).hexdigest()
                if checkpoint.get("count") != len(entries) or checkpoint.get("head") != previous or not hmac.compare_digest(checkpoint.get("signature", ""), signature):
                    return {"valid": False, "events": len(entries), "reason": "Signed checkpoint mismatch"}
            elif entries:
                return {"valid": False, "events": len(entries), "reason": "Missing checkpoint"}
            return {"valid": True, "events": len(entries), "head": previous}
        except (ValueError, KeyError, TypeError, OSError):
            return {"valid": False, "events": 0, "reason": "Malformed audit data"}

    def append(self, event):
        with self.lock:
            if not self.verify()["valid"]:
                raise RuntimeError("Audit integrity failed. New evaluations stopped.")
            rows = self.rows()
            event = {**redact(event), "sequence": len(rows) + 1, "at": datetime.now(timezone.utc).isoformat(), "previous": rows[-1]["hash"] if rows else "0" * 64}
            event["hash"] = hashlib.sha256(canonical(event)).hexdigest()
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\n")
            checkpoint = {"count": len(rows) + 1, "head": event["hash"]}
            checkpoint["signature"] = hmac.new(self.key, canonical(checkpoint), hashlib.sha256).hexdigest()
            temporary = self.checkpoint.with_suffix(".tmp")
            temporary.write_text(json.dumps(checkpoint))
            temporary.replace(self.checkpoint)
            return event
