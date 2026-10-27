"""Read-only startup checks. No downloads, configuration writes or model calls."""
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from ml_runtime import model_status


def checks():
    root=Path(__file__).resolve().parent
    result=[{'name':'Python 3.11+','ready':sys.version_info>=(3,11),'detail':sys.version.split()[0]},
            {'name':'Fixture UI','ready':all((root/name).is_file() for name in ['web/index.html','web/app.js','web/style.css']),
             'detail':'Start with python server.py --no-env. The fixture needs no API key.'},
            {'name':'Proof signing','ready':importlib.util.find_spec('cryptography') is not None,
             'detail':'Optional: python -m pip install -r requirements-proof.txt'}]
    for role,status in model_status().items():result.append({'name':role.title()+' local ML','ready':status['ready'],
        'detail':'Files and dependencies present; hashes checked on load.' if status['ready'] else 'python -m pip install -r requirements-ml.txt, then python setup_models.py'})
    try:
        from local_target import identity
        model=identity();result.append({'name':'Real local target','ready':True,'detail':model['model']+' / '+model['digest'][:12]})
    except RuntimeError as error:result.append({'name':'Real local target','ready':False,'detail':str(error)})
    result.append({'name':'Container verification','ready':bool(shutil.which('docker')),'detail':'Run python verify_containers.py on a working Docker Engine. CLI presence alone is not isolation proof.'})
    return result


if __name__=='__main__':
    for row in checks():print(('READY' if row['ready'] else 'OPTIONAL SETUP')+' | '+row['name']+' | '+row['detail'])
