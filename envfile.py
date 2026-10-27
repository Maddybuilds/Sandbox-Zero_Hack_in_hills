"""Load local SZ_ settings as literal strings. Never evaluates shell expressions."""
import os
import re
from pathlib import Path


def load_env_file(path, environment=None):
    environment=os.environ if environment is None else environment
    path=Path(path)
    if not path.exists():return []
    pending={}
    for number,line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#'):continue
        if line.startswith('export '):line=line[7:].strip()
        key,separator,value=line.partition('=')
        key=key.strip();value=value.strip()
        if not separator or not re.fullmatch(r'SZ_[A-Z0-9_]+',key) or '\0' in value:
            raise ValueError(f'Invalid .env setting on line {number}. Only literal SZ_ assignments are supported.')
        if value.startswith(('"',"'")):
            if len(value)<2 or value[-1]!=value[0]:raise ValueError(f'Unclosed .env quote on line {number}.')
            value=value[1:-1]
        pending[key]=value
    loaded=[]
    for key,value in pending.items():
        if key not in environment:environment[key]=value;loaded.append(key)
    return loaded
