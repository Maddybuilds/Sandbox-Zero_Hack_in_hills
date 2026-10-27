"""Minimal authenticated fixture target; no opposing participant code in its image."""
import argparse
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlparse
from fixture_runtime import CanaryStore,safe_output,target_reply


def make_target_handler(token):
    canaries=CanaryStore()
    class Target(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def setup(self):super().setup();self.connection.settimeout(10)
        def send(self,status,value):
            body=json.dumps(value).encode();self.send_response(status)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
        def authorized(self):
            return bool(token) and secrets.compare_digest(self.headers.get('X-Participant-Token','').encode(),token.encode())
        def do_GET(self):
            route=urlparse(self.path).path
            if route=='/health':return self.send(200,{'ok':True,'role':'target','target_mode':'fixture','canary_id':canaries.public()['id']})
            if not self.authorized():return self.send(401,{'error':'Participant authentication required'})
            if route=='/canary':return self.send(200,canaries.public())
            return self.send(404,{'error':'Unknown route'})
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=32768:return self.send(413,{'error':'Request must be 1-32,768 bytes'})
                raw=self.rfile.read(length)
            except (ValueError,TimeoutError):return self.send(400,{'error':'Invalid request length'})
            if not self.authorized():return self.send(401,{'error':'Participant authentication required'})
            if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.send(415,{'error':'JSON required'})
            try:
                data=json.loads(raw)
                if not isinstance(data,dict):raise ValueError()
            except (ValueError,UnicodeError):return self.send(400,{'error':'Invalid JSON object'})
            if self.path=='/canary/rotate':return self.send(200,canaries.rotate())
            if self.path!='/respond':return self.send(404,{'error':'Unknown route'})
            if not isinstance(data.get('payload'),str) or len(data['payload'])>2000:return self.send(400,{'error':'Missing or over-budget payload'})
            try:
                result=target_reply(data,canaries.value);result['evidence_text']=safe_output(result['text'],canaries.value)
                return self.send(200,result)
            except (RuntimeError,ValueError,KeyError,TypeError,AttributeError):return self.send(502,{'error':'Controlled target failed; no replacement answer supplied'})
    return Target


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=9000);args=parser.parse_args()
    token=os.environ.get('SZ_PARTICIPANT_TOKEN')
    if not token:parser.error('The target worker requires its own SZ_PARTICIPANT_TOKEN')
    ThreadingHTTPServer((args.host,args.port),make_target_handler(token)).serve_forever()
