"""Explicit one-time model download. Inference never calls the network."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parent


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def setup(check=False):
    specs=json.loads((ROOT/'models.lock.json').read_text(encoding='utf-8'))
    for role,spec in specs.items():
        directory=ROOT/'.models'/role
        if not check:directory.mkdir(parents=True,exist_ok=True)
        for file in spec['files']:
            path=directory/file['name']
            if path.exists() and path.stat().st_size==file['bytes'] and digest(path)==file['sha256']:
                print(role,file['name'],'verified',flush=True);continue
            if check:raise RuntimeError(f"Missing or changed {role}/{file['name']}. Run python setup_models.py.")
            print('Downloading',role,file['name'],file['bytes'],'bytes',flush=True)
            url=f"https://huggingface.co/{spec['repo']}/resolve/{spec['revision']}/{file['remote']}"
            temporary=path.with_suffix(path.suffix+'.part')
            with urlopen(url,timeout=120) as response,temporary.open('wb') as stream:
                size=0
                for block in iter(lambda:response.read(1024*1024),b''):
                    size+=len(block)
                    if size>file['bytes']:raise RuntimeError('Model download exceeded pinned size')
                    stream.write(block)
            if size!=file['bytes'] or digest(temporary)!=file['sha256']:
                raise RuntimeError('Model checksum mismatch; file not activated')
            temporary.replace(path)
        print(role,'ready for local inference',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Verify installed files without downloading')
    args=parser.parse_args();setup(args.check)
