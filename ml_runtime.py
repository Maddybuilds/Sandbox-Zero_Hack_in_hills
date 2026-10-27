"""Local ONNX CPU execution. No Hub client, remote code, or network inference."""
import hashlib
import importlib.util
import json
import threading
from pathlib import Path

ROOT=Path(__file__).resolve().parent
LOCK=threading.RLock()
SESSIONS={}


class ModelUnavailable(RuntimeError):pass


def specs():return json.loads((ROOT/'models.lock.json').read_text(encoding='utf-8'))


def model_status():
    dependencies=all(importlib.util.find_spec(m) is not None for m in ['numpy','onnxruntime','tokenizers'])
    result={}
    for role,spec in specs().items():
        installed=all((ROOT/'.models'/role/f['name']).is_file() and (ROOT/'.models'/role/f['name']).stat().st_size==f['bytes'] for f in spec['files'])
        result[role]={'repo':spec['repo'],'revision':spec['revision'],'task':spec['task'],'license':spec['license'],
                      'installed':installed,'dependencies':dependencies,'ready':installed and dependencies,
                      'loaded_and_verified':role in SESSIONS,'runtime':'ONNX Runtime / CPU',
                      'weight_sha256':next(f['sha256'] for f in spec['files'] if f['name'].endswith('.onnx'))}
    return result


class LocalModel:
    def __init__(self,role):
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError:raise ModelUnavailable('Install optional CPU dependencies: python -m pip install -r requirements-ml.txt') from None
        self.np=np;self.role=role;self.spec=specs()[role];directory=ROOT/'.models'/role
        for file in self.spec['files']:
            path=directory/file['name']
            if not path.is_file() or path.stat().st_size!=file['bytes']:raise ModelUnavailable('Local models are missing. Run python setup_models.py.')
            h=hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
            if h.hexdigest()!=file['sha256']:raise ModelUnavailable('Local model integrity check failed. Re-run python setup_models.py.')
        self.tokenizer=Tokenizer.from_file(str(directory/'tokenizer.json'))
        config=json.loads((directory/'config.json').read_text())
        self.limit=256 if role=='red' else 512
        self.tokenizer.enable_truncation(max_length=self.limit,stride=64 if role=='blue' else 0)
        self.tokenizer.enable_padding(pad_id=config.get('pad_token_id',0),pad_token='[PAD]' if role=='red' else '[PAD]')
        options=ort.SessionOptions();options.intra_op_num_threads=2;options.inter_op_num_threads=1
        options.log_severity_level=3
        name=next(f['name'] for f in self.spec['files'] if f['name'].endswith('.onnx'))
        try:self.session=ort.InferenceSession(str(directory/name),sess_options=options,providers=['CPUExecutionProvider'])
        except Exception:raise ModelUnavailable('The pinned local ONNX model could not be loaded; no fallback model was selected.') from None
        self.inputs={v.name for v in self.session.get_inputs()}
        self.lock=threading.RLock()

    def inference(self,texts,windows=False):
        np=self.np
        with self.lock:
            encoded=self.tokenizer.encode_batch(texts)
            if windows:
                encoded=[window for e in encoded for window in [e]+e.overflowing]
                if len(encoded)>16:raise ValueError('Text exceeds the bounded classifier window budget')
            length=max(len(e.ids) for e in encoded)
            pad=json.loads((ROOT/'.models'/self.role/'config.json').read_text()).get('pad_token_id',0)
            values={'input_ids':np.array([e.ids+[pad]*(length-len(e.ids)) for e in encoded],dtype=np.int64),
                    'attention_mask':np.array([e.attention_mask+[0]*(length-len(e.ids)) for e in encoded],dtype=np.int64),
                    'token_type_ids':np.array([e.type_ids+[0]*(length-len(e.ids)) for e in encoded],dtype=np.int64)}
            try:output=self.session.run(None,{k:v for k,v in values.items() if k in self.inputs})[0]
            except Exception:raise ModelUnavailable('Local model execution failed; no score was substituted.') from None
            if not np.isfinite(output).all():raise ModelUnavailable('Local model produced non-finite output; request stopped.')
            return output,values['attention_mask'],len(encoded)

    def provenance(self):
        return {'repo':self.spec['repo'],'revision':self.spec['revision'],'runtime':'ONNX Runtime CPU',
                'weight_sha256':next(f['sha256'] for f in self.spec['files'] if f['name'].endswith('.onnx'))}


def load(role):
    if role not in {'red','blue'}:raise ValueError('Unknown model role')
    with LOCK:
        if role not in SESSIONS:SESSIONS[role]=LocalModel(role)
        return SESSIONS[role]
