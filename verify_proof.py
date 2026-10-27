"""Verify a Sandbox Zero proof JSON. No network or project server is required."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def verify(envelope,expected_fingerprint=None,asset_directory=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(envelope,dict) or envelope.get('format')!='sandbox-zero-proof-v1' or envelope.get('algorithm')!='Ed25519':raise ValueError('Unsupported proof format')
    payload=envelope.get('payload')
    if not isinstance(payload,str) or len(payload)>1_000_000:raise ValueError('Invalid proof payload')
    key=base64.b64decode(envelope['public_key'],validate=True)
    signature=base64.b64decode(envelope['signature'],validate=True)
    Ed25519PublicKey.from_public_bytes(key).verify(signature,payload.encode('utf-8'))
    fingerprint=hashlib.sha256(key).hexdigest()
    report=json.loads(payload)
    if report.get('signer_fingerprint')!=fingerprint:raise ValueError('Signed signer fingerprint mismatch')
    if expected_fingerprint and fingerprint!=expected_fingerprint:raise ValueError('Signer does not match the trusted fingerprint')
    assets_verified=False
    if asset_directory is not None:
        assets=report.get('assets',{})
        if set(assets)!={'report.html','verify_proof.py'}:raise ValueError('Unexpected bundle asset manifest')
        root=Path(asset_directory).resolve()
        for name,digest in assets.items():
            path=(root/name).resolve()
            if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Bundle asset checksum mismatch: '+name)
        assets_verified=True
    return {'signature_valid':True,'fingerprint':fingerprint,'trusted_key_matched':bool(expected_fingerprint),
            'assets_verified':assets_verified,'proof_id':report['proof_id'],
            'scope':'Signature authenticates recorded bytes for this key. Trust requires a fingerprint obtained independently. It does not certify the tests, timestamp, host isolation or general model safety.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('proof',type=Path)
    parser.add_argument('--fingerprint',help='Trusted SHA-256 public-key fingerprint obtained separately')
    parser.add_argument('--assets',type=Path,help='Also check report.html and verify_proof.py in the extracted bundle')
    args=parser.parse_args()
    try:
        if args.proof.stat().st_size>2_000_000:raise ValueError('Proof file exceeds 2 MB')
        print(json.dumps(verify(json.loads(args.proof.read_text(encoding='utf-8')),args.fingerprint,args.assets),indent=2))
    except Exception as error:
        print('VERIFICATION FAILED:',type(error).__name__)
        raise SystemExit(1)
