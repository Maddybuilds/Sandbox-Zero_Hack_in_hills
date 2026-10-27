"""Disposable Windows AppContainer probes, never a claim about the normal gateway.

No elevation, loopback exemptions, firewall changes or network capabilities.
Only a private copy of the installed Python runtime and synthetic fixtures get ACLs.
"""
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path


WORKER = r'''
import ctypes,json,socket,sys
from pathlib import Path
from ctypes import wintypes as w
task=json.loads(sys.argv[1]);result={}
adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
adv.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
kernel.GetCurrentProcess.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
token=w.HANDLE();flag=w.DWORD();size=w.DWORD()
if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
try:
 if not adv.GetTokenInformation(token,29,ctypes.byref(flag),ctypes.sizeof(flag),ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
 result['appcontainer']=bool(flag.value)
finally:kernel.CloseHandle(token)
for name,path in task['files'].items():
 try:result[name]={'read':True,'sha256':__import__('hashlib').sha256(Path(path).read_bytes()).hexdigest()}
 except OSError as error:result[name]={'read':False,'errno':error.errno,'winerror':error.winerror}
for name,address in task['sockets'].items():
 try:
  with socket.create_connection(tuple(address),timeout=2):pass
  result[name]={'connected':True}
 except OSError as error:result[name]={'connected':False,'errno':error.errno,'winerror':error.winerror,'error_type':type(error).__name__,'message':str(error)}
print(json.dumps(result),flush=True)
'''


def _api():
    from ctypes import wintypes as w
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    userenv=ctypes.WinDLL('userenv',use_last_error=True)
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    class SecurityAttributes(ctypes.Structure):
        _fields_=[('length',w.DWORD),('descriptor',w.LPVOID),('inherit',w.BOOL)]
    class Startup(ctypes.Structure):
        _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),
                  ('x',w.DWORD),('y',w.DWORD),('width',w.DWORD),('height',w.DWORD),
                  ('charsx',w.DWORD),('charsy',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),
                  ('show',w.WORD),('reserved2size',w.WORD),('reserved2',ctypes.POINTER(ctypes.c_ubyte)),
                  ('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
    class StartupEx(ctypes.Structure):_fields_=[('startup',Startup),('attributes',w.LPVOID)]
    class Process(ctypes.Structure):_fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
    class Capabilities(ctypes.Structure):_fields_=[('sid',w.LPVOID),('capabilities',w.LPVOID),('count',w.DWORD),('reserved',w.DWORD)]
    userenv.CreateAppContainerProfile.argtypes=[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)]
    userenv.CreateAppContainerProfile.restype=ctypes.c_long
    userenv.DeleteAppContainerProfile.argtypes=[w.LPCWSTR];userenv.DeleteAppContainerProfile.restype=ctypes.c_long
    adv.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)];adv.FreeSid.argtypes=[w.LPVOID]
    kernel.LocalFree.argtypes=[w.LPVOID]
    kernel.InitializeProcThreadAttributeList.argtypes=[w.LPVOID,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_size_t)]
    kernel.UpdateProcThreadAttribute.argtypes=[w.LPVOID,w.DWORD,ctypes.c_size_t,w.LPVOID,ctypes.c_size_t,w.LPVOID,w.LPVOID]
    kernel.DeleteProcThreadAttributeList.argtypes=[w.LPVOID]
    kernel.CreatePipe.argtypes=[ctypes.POINTER(w.HANDLE),ctypes.POINTER(w.HANDLE),ctypes.POINTER(SecurityAttributes),w.DWORD]
    kernel.SetHandleInformation.argtypes=[w.HANDLE,w.DWORD,w.DWORD]
    kernel.CreateProcessW.argtypes=[w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(StartupEx),ctypes.POINTER(Process)]
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.TerminateProcess.argtypes=[w.HANDLE,w.UINT]
    kernel.ReadFile.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD),w.LPVOID]
    kernel.GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)];kernel.CloseHandle.argtypes=[w.HANDLE]
    return w,kernel,userenv,adv,SecurityAttributes,StartupEx,Process,Capabilities


def _runtime(directory):
    """Copy binaries; zip only stdlib .py files. Never expose site-packages/.env."""
    home=Path(sys.base_prefix)
    for source in [home/'python.exe',*home.glob('python*.dll'),*home.glob('vcruntime*.dll'),*(home/'DLLs').glob('*.pyd'),*(home/'DLLs').glob('*.dll')]:
        shutil.copy2(source,directory/source.name)
    with zipfile.ZipFile(directory/'stdlib.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for source in (home/'Lib').rglob('*.py'):
            relative=source.relative_to(home/'Lib')
            if not set(relative.parts)&{'site-packages','test','tests','idlelib','tkinter','ensurepip','__pycache__'}:
                archive.write(source,relative.as_posix())
    (directory/f'python{sys.version_info.major}{sys.version_info.minor}._pth').write_text('stdlib.zip\n.\n',encoding='ascii')
    (directory/'worker.py').write_text(WORKER,encoding='utf-8')


def _grant(path,sid):
    subprocess.run(['icacls',str(path),'/grant',f'*{sid}:(OI)(CI)(RX)','/T','/Q'],
                   check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)


def _launch(runtime,sid,task):
    w,k,userenv,adv,SA,StartupEx,Process,Capabilities=_api()
    size=ctypes.c_size_t();k.InitializeProcThreadAttributeList(None,2,0,ctypes.byref(size))
    storage=ctypes.create_string_buffer(size.value)
    if not k.InitializeProcThreadAttributeList(storage,2,0,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
    read=w.HANDLE();write=w.HANDLE();process=Process();created=False
    try:
        sa=SA(ctypes.sizeof(SA),None,True)
        if not k.CreatePipe(ctypes.byref(read),ctypes.byref(write),ctypes.byref(sa),65536):raise ctypes.WinError(ctypes.get_last_error())
        if not k.SetHandleInformation(read,1,0):raise ctypes.WinError(ctypes.get_last_error())
        capabilities=Capabilities(sid,None,0,0)
        if not k.UpdateProcThreadAttribute(storage,0,0x20009,ctypes.byref(capabilities),ctypes.sizeof(capabilities),None,None):raise ctypes.WinError(ctypes.get_last_error())
        handles=(w.HANDLE*1)(write)
        if not k.UpdateProcThreadAttribute(storage,0,0x20002,handles,ctypes.sizeof(handles),None,None):raise ctypes.WinError(ctypes.get_last_error())
        startup=StartupEx();startup.startup.cb=ctypes.sizeof(StartupEx);startup.attributes=ctypes.cast(storage,w.LPVOID)
        startup.startup.flags=0x100;startup.startup.stdout=write;startup.startup.stderr=write
        command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(runtime/'python.exe'),'-I',str(runtime/'worker.py'),json.dumps(task)]))
        # Explicit minimal Unicode environment: no inherited API/service credentials.
        safe={name:value for name,value in os.environ.items() if name.upper() in {'SYSTEMROOT','SYSTEMDRIVE','WINDIR','USERPROFILE','LOCALAPPDATA','APPDATA','TEMP','TMP','PATH'}}
        safe['PYTHONDONTWRITEBYTECODE']='1'
        environment=ctypes.create_unicode_buffer('\0'.join(name+'='+value for name,value in sorted(safe.items(),key=lambda item:item[0].upper()))+'\0\0')
        if not k.CreateProcessW(str(runtime/'python.exe'),command,None,None,True,0x80000|0x8000000|0x400,environment,str(runtime),ctypes.byref(startup),ctypes.byref(process)):
            raise ctypes.WinError(ctypes.get_last_error())
        created=True;k.CloseHandle(write);write=w.HANDLE()
        if k.WaitForSingleObject(process.process,15000)!=0:
            k.TerminateProcess(process.process,1);k.WaitForSingleObject(process.process,5000)
            raise RuntimeError('AppContainer probe timed out; no passing result substituted.')
        buffer=ctypes.create_string_buffer(16384);count=w.DWORD()
        k.ReadFile(read,buffer,len(buffer)-1,ctypes.byref(count),None)
        code=w.DWORD();k.GetExitCodeProcess(process.process,ctypes.byref(code))
        if code.value:raise RuntimeError(f'AppContainer probe exited with code {code.value}; runtime could not execute.')
        return json.loads(buffer.raw[:count.value].decode('utf-8'))
    finally:
        for handle in [read,write,process.thread,process.process]:
            if handle:k.CloseHandle(handle)
        k.DeleteProcThreadAttributeList(storage)


def run_windows_boundary_checks():
    if sys.platform!='win32':return {'status':'unavailable','checks':[],'passed':0,'total':0,'reason':'Windows AppContainer requires Windows 10 or newer.'}
    start=time.perf_counter();profiles=[];checks=[]
    w,k,userenv,adv,*_=_api()
    try:
        with tempfile.TemporaryDirectory(prefix='sz-appcontainer-') as temporary:
            base=Path(temporary);runtime=base/'runtime';runtime.mkdir();_runtime(runtime)
            for role in ['red','blue']:
                folder=base/role;folder.mkdir();(folder/'private.txt').write_text('synthetic-'+secrets.token_hex(16))
                name='OffGrid.SandboxZero.Probe.'+secrets.token_hex(10);sid=w.LPVOID()
                result=userenv.CreateAppContainerProfile(name,name,'Disposable synthetic Sandbox Zero boundary check',None,0,ctypes.byref(sid))
                if result<0:raise RuntimeError(f'Windows refused AppContainer profile creation: HRESULT {result & 0xffffffff:08x}')
                profiles.append((name,sid));sidtext=w.LPWSTR()
                if not adv.ConvertSidToStringSidW(sid,ctypes.byref(sidtext)):raise ctypes.WinError(ctypes.get_last_error())
                try:_grant(runtime,sidtext.value);_grant(folder,sidtext.value)
                finally:k.LocalFree(sidtext)
            with socket.socket() as listener:
                listener.bind(('0.0.0.0',0));listener.listen(8);address=(socket.gethostbyname(socket.gethostname()),listener.getsockname()[1])
                with socket.create_connection(address,timeout=2):pass
                checks.append({'id':'WIN-NET-CONTROL','name':'Trusted host can reach the synthetic TCP listener','passed':True,'observed':{'connected':True}})
                for role,(_,sid) in zip(['red','blue'],profiles):
                    peer='blue' if role=='red' else 'red';own=base/role/'private.txt';other=base/peer/'private.txt'
                    expected=hashlib.sha256(own.read_bytes()).hexdigest()
                    # Host can read both files before a denied read is credited.
                    assert other.read_bytes()
                    result=_launch(runtime,sid,{'files':{'own':str(own),'peer':str(other)},'sockets':{'loopback':address}})
                    observations=[('TOKEN','Process token is an AppContainer',result['appcontainer'],{'appcontainer':result['appcontainer']}),
                        ('OWN','Own synthetic file remains readable',result['own'].get('sha256')==expected,result['own']),
                        ('PEER','Peer synthetic file read denied by Windows',result['peer'].get('read') is False and (result['peer'].get('winerror')==5 or result['peer'].get('errno')==13),result['peer']),
                        ('NET','TCP access denied by Windows socket policy',result['loopback'].get('connected') is False and (result['loopback'].get('winerror')==10013 or result['loopback'].get('errno')==10013),result['loopback'])]
                    for suffix,name,passed,observed in observations:
                        if suffix=='NET' and observed.get('error_type')=='TimeoutError':passed=None
                        checks.append({'id':f'WIN-{role.upper()}-{suffix}','name':f'{role.title()}: {name}',
                                       'passed':passed,'observed':observed,'status':'inconclusive' if passed is None else 'passed' if passed else 'failed'})
        return {'status':'measured','checks':checks,'passed':sum(c['passed'] is True for c in checks),'total':len(checks),
                'inconclusive':sum(c['passed'] is None for c in checks),'failed':sum(c['passed'] is False for c in checks),
                'duration_ms':round((time.perf_counter()-start)*1000,2),'backend':'Windows AppContainer / zero capabilities',
                'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'scope':'Disposable synthetic worker processes only. Actual OS token and cross-role file access checks plus TCP attempts to a host listener. Timeouts are inconclusive, not proven network denials. No firewall changes or loopback exemptions.',
                'limitations':'The normal gateway, ONNX models and Ollama are NOT inside these AppContainers. This does not validate the Docker deployment, internet egress or resistance to kernel exploits.'}
    finally:
        for name,sid in reversed(profiles):
            userenv.DeleteAppContainerProfile(name);adv.FreeSid(sid)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);args=parser.parse_args()
    result=run_windows_boundary_checks()
    if args.output:args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
    sys.exit(0 if result['status']=='measured' and result['passed']==result['total'] else 2)
