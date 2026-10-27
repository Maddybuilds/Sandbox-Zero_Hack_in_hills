"""Blue's independent classifier. No Red bank, scoring labels, or fixture access."""
import math
import re
import time
from ml_runtime import load,ModelUnavailable

THRESHOLD=.80
POLICY_VERSION='rules-v4+blue-ml-v2'


def educational_quote(payload,history=()):
    """A deliberately small grammar, not an intent classifier or phrase allowlist.

    Only a complete explanatory request with one bounded quoted datum and an
    explicit non-execution clause qualifies. Any history, appended command,
    unmatched quote, tool action or alternative framing retains normal screening.
    """
    if history or not isinstance(payload,str):return False
    pattern=(r'\s*(?:explain|discuss|analyze) (?:the|this) '
             r'(?:quoted (?:phrase|text|instruction)|literal string) '
             r'(?P<q>[\x22\x27`])[^\x22\x27`\n]{1,300}(?P=q) '
             r'as (?:a security lesson|an example of role impersonation)\.'
             r'\s+do not (?:follow|obey|execute) it\.\s*')
    return re.fullmatch(pattern,payload,re.IGNORECASE) is not None


def assess(payload,history=()):
    learned=score(payload)
    educational=educational_quote(payload,history)
    raw_flagged=learned['score']>=learned['threshold']
    return {**learned,'raw_flagged':raw_flagged,'decision_blocked':raw_flagged and not educational,
            'educational_quote':educational,'assessment_version':2,
            'assessment_scope':'A narrow complete educational-quotation grammar can override the input classifier veto. The raw score is retained; output guards still run. Other false positives remain.'}


def score(payload):
    if not isinstance(payload,str) or not payload.strip() or len(payload)>2000:raise ValueError('Classifier input must be 1–2,000 characters.')
    start=time.perf_counter();model=load('blue')
    output,_,windows=model.inference([payload],windows=True)
    if output.ndim!=2 or output.shape[1]!=2:raise ModelUnavailable('Unexpected classifier label shape; request stopped.')
    probabilities=[]
    for logits in output:
        shifted=[float(v)-float(max(logits)) for v in logits]
        values=[math.exp(v) for v in shifted]
        probabilities.append(values[1]/sum(values))
    risk=max(probabilities)
    return {'score':round(risk,6),'label':'injection' if risk>=THRESHOLD else 'benign','threshold':THRESHOLD,'windows':windows,
            'duration_ms':round((time.perf_counter()-start)*1000,2),'model':model.provenance(),
            'scope':'English input classifier score, not a calibrated probability of safety. No target response was assessed.',
            'received':['payload'],'red_plan_received':False}
