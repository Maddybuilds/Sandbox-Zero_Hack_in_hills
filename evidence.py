"""Workspace evidence helpers. Legacy event records remain untouched."""
import base64
import copy
import hashlib
import json
import secrets
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from engine import Audit, canonical


from fixture_runtime import now, CanaryStore, safe_output


def outcome(event):
    return event.get("outcome") or ("held" if event.get("canary_detected") else event["decision"])


def summarize(events):
    grouped = {}
    for event in events: grouped.setdefault(event["run"], []).append(event)
    result = []
    for run, rows in grouped.items():
        counts = {key:sum(outcome(e) == key for e in rows) for key in ["allowed", "blocked", "held", "failed"]}
        categories = {}
        for e in rows:
            counts_by_category = categories.setdefault(e["category"], {key:0 for key in counts})
            counts_by_category[outcome(e)] += 1
        result.append({"run":run,"cases":len({e['case'] for e in rows}),"requests":len(rows),"counts":counts,"categories":categories,"profile":rows[0].get("profile","strict"),"target_mode":rows[0].get("target_mode","fixture"),"at":rows[0]["at"],"duration_ms":round(sum(e.get("duration_ms",0) for e in rows),2),"legacy":any(not e.get("case_fingerprint") for e in rows)})
    return result


def compare(events, a, b):
    left = [e for e in events if e["run"] == a]
    right = [e for e in events if e["run"] == b]
    if not left or not right or a == b: raise ValueError("Choose two different saved runs.")
    if any(not e.get("case_fingerprint") for e in left+right): raise ValueError("Legacy runs lack full case fingerprints. Create two new runs to compare safely.")
    signature = lambda rows: sorted((e["case"],e.get("turn_index",1),e["case_fingerprint"],e.get("target_mode"),e.get("model"),e.get("policy_version"),e.get("canary_id")) for e in rows)
    if signature(left) != signature(right): raise ValueError("Runs must have identical case revisions, executed turns, target, policy version and canary generation. Run the same selection under both profiles.")
    if left[0].get("profile") == right[0].get("profile"): raise ValueError("Choose runs with different defense profiles.")
    indexed = {(e["case"],e.get("turn_index",1)):e for e in right}
    return {"comparable":True,"runs":summarize(left+right),"rows":[{"case":e["case"],"turn_index":e.get("turn_index",1),"name":e["name"],"left":outcome(e),"right":outcome(indexed[(e["case"],e.get("turn_index",1))]),"changed":outcome(e)!=outcome(indexed[(e["case"],e.get("turn_index",1))])} for e in left],"scope":"Counts describe this exact controlled selection, aligned by case and turn. They are not a general model-safety score."}


def tamper_sample(directory):
    # All writes occur in a disposable, separately keyed sample. User history is read-only here.
    with tempfile.TemporaryDirectory(prefix="scratch-",dir=directory) as temporary:
        sample = Audit(temporary)
        for n in range(3): sample.append({"sample":n,"decision":"allowed"})
        rows = sample.rows()
        modified = copy.deepcopy(rows);modified[0]["decision"]="forged"
        reordered = [rows[1],rows[0],rows[2]]
        deleted = [rows[0],rows[2]]
        truncated = rows[:2]
        rehashed = copy.deepcopy(modified);previous="0"*64
        for row in rehashed:
            row["previous"]=previous
            row["hash"]=hashlib.sha256(canonical({k:v for k,v in row.items() if k!="hash"})).hexdigest();previous=row["hash"]
        samples={"Unchanged control":rows,"Changed record":modified,"Reordered records":reordered,"Deleted middle record":deleted,"Truncated tail":truncated,"Rehashed forged history":rehashed}
        return {"checked_at":now(),"scope":"Disposable three-record dataset with its own signing key. Your real audit files were not edited.","results":[{"name":name,**sample.verify(data)} for name,data in samples.items()]}
