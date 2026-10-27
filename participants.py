"""Minimal Red/Blue services. Role images contain only their own required files."""
import argparse
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def make_participant_handler(role, token=None, cases=None):
    if role not in {'red','blue'}:raise ValueError('Unsupported participant')
    if role=='blue':
        from policy import input_view, inspect_request, inspect_output, PolicyUnavailable
    else:
        cases=cases if cases is not None else json.loads(Path('red_cases.json').read_text(encoding='utf-8'))

    class Participant(BaseHTTPRequestHandler):
        def log_message(self,*_):pass

        def send(self,status,value):
            body=json.dumps(value).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
            self.end_headers();self.wfile.write(body)

        def permitted(self):
            return not token or secrets.compare_digest(self.headers.get('X-Participant-Token','').encode(),token.encode())

        def do_GET(self):
            if self.path=='/health':return self.send(200,{'ok':True,'role':role})
            if not self.permitted():return self.send(401,{'error':'Participant authentication required'})
            if role=='red' and self.path=='/cases':return self.send(200,cases)
            return self.send(404,{'error':'Unknown route'})

        def do_POST(self):
            try:
                self.connection.settimeout(10)
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=32768:return self.send(413,{'error':'Bounded JSON request required'})
                raw=self.rfile.read(size)
                if not self.permitted():return self.send(401,{'error':'Participant authentication required'})
                if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.send(415,{'error':'JSON required'})
                value=json.loads(raw)
                if not isinstance(value,dict):raise ValueError()
                if role=='red' and self.path=='/prepare':
                    if set(value)!={'cases'} or not isinstance(value['cases'],list) or len(value['cases'])>100:raise ValueError()
                    if any(not isinstance(c,dict) or set(c)!={'payload','action'} or not isinstance(c['payload'],str) or not isinstance(c['action'],str) for c in value['cases']):raise ValueError()
                    return self.send(200,value['cases'])
                if role=='blue' and self.path=='/inspect':
                    if set(value)-{'payload','action','history','profile'}:raise ValueError()
                    return self.send(200,inspect_request(input_view(value),value.get('profile','strict')))
                if role=='blue' and self.path=='/inspect-output':
                    if set(value)-{'text','profile'}:raise ValueError()
                    return self.send(200,inspect_output(value.get('text'),value.get('profile','strict')))
                return self.send(404,{'error':'Unknown route'})
            except RuntimeError:return self.send(503,{'error':'Local policy model unavailable; no decision substituted'})
            except (ValueError,TypeError,UnicodeError,TimeoutError):return self.send(400,{'error':'Invalid participant message; hidden case metadata is not accepted'})
    return Participant


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--role',choices=['red','blue'],required=True)
    parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=9000)
    args=parser.parse_args();token=os.environ.get('SZ_PARTICIPANT_TOKEN')
    if args.host not in {'127.0.0.1','localhost'} and not token:parser.error('Non-loopback participants require SZ_PARTICIPANT_TOKEN')
    ThreadingHTTPServer((args.host,args.port),make_participant_handler(args.role,token)).serve_forever()
