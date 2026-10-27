"""Optional Playwright smoke test against a disposable server from with_server.py."""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

parser=argparse.ArgumentParser();parser.add_argument('--url');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;out=root/'test-results/hardening';out.mkdir(parents=True,exist_ok=True)
if not args.url:
    # Own the Python process directly; Windows shell wrappers can leave children.
    from urllib.request import urlopen
    with tempfile.TemporaryDirectory(prefix='sz-browser-data-') as temporary:
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        env={**os.environ,'SZ_ACCESS_CODE':'hardening-browser-test','SZ_MODE':'local','SZ_MODEL':'','SZ_DATA':temporary}
        child=subprocess.Popen([sys.executable,str(root/'server.py'),'--no-env','--port',str(port)],cwd=root,env=env,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            for attempt in range(80):
                try:
                    with urlopen(f'http://127.0.0.1:{port}/health',timeout=.2) as response:
                        if response.status==200:break
                except OSError:time.sleep(.1)
            else:raise RuntimeError('Disposable browser server did not start.')
            completed=subprocess.run([sys.executable,__file__,'--url',f'http://127.0.0.1:{port}'],cwd=root,env=env)
        finally:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
    raise SystemExit(completed.returncode)
token=os.environ['SZ_ACCESS_CODE'];headers={'Authorization':'Bearer '+token}
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,channel='chrome')
    try:
        page=browser.new_page(viewport={'width':1440,'height':1050},accept_downloads=True)
        errors=[];console=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.on('console',lambda message:console.append(message.text) if message.type=='error' else None)
        page.goto(args.url+'/#ml');page.wait_for_load_state('networkidle')
        page.locator('#access-code').fill(token);page.locator('#access-form button[type=submit]').click()
        page.wait_for_function("() => document.querySelector('#connection').textContent==='Connected'")
        def state():return page.request.get(args.url+'/api/state',headers=headers).json()
        original=state()['events']
        page.get_by_role('button',name='Run real local target').click()
        page.wait_for_function('() => state.local_target?.latest && !busy',timeout=180000)
        measured=state()['local_target']['latest']['result']
        assert not measured['fixture_used'] and measured['failed_requests']==0
        assert measured['target_calls']>0 and measured['target']['options']['num_gpu']==0
        assert state()['events']==original
        page.locator('.local-target-panel [data-action=target-detail]').first.click()
        assert page.locator('#detail-dialog').is_visible();page.keyboard.press('Escape')
        with page.expect_download() as download:page.locator('[data-action=target-export]').click()
        path=out/'target-evidence.json';download.value.save_as(path)
        assert json.loads(path.read_text())['integrity']['valid']
        page.locator('[data-page=proof]').click()
        page.locator('.proof-hero [data-action=proof-run]').click()
        page.wait_for_function('() => state.proof_lab?.latest && !busy',timeout=60000)
        page.locator('[data-action=proof-step][data-step="1"]').click()
        page.locator('[data-action=proof-os]').click()
        page.wait_for_function('() => JSON.parse(state.proof_lab.latest.envelope.payload).windows_boundary && !busy',timeout=90000)
        report=json.loads(state()['proof_lab']['latest']['envelope']['payload'])
        windows=report['windows_boundary']
        assert windows['status']=='measured' and windows['failed']==0
        assert any(c['id']=='WIN-RED-PEER' and c['passed'] is True for c in windows['checks'])
        assert any(c['id']=='WIN-BLUE-PEER' and c['passed'] is True for c in windows['checks'])
        if windows['inconclusive']:assert 'Inconclusive' in page.locator('.windows-boundary-panel').inner_text()
        assert state()['events']==original
        page.locator('[data-action=proof-step][data-step="2"]').click()
        page.locator('[data-action=proof-verify]').click();page.wait_for_selector('.proof-verify-result.valid')
        for width in [375,390,768,1024,1440]:
            page.set_viewport_size({'width':width,'height':1000})
            for destination in ['ml','proof']:
                page.locator('[data-page='+destination+']').click()
                if destination=='proof':page.locator('[data-action=proof-step][data-step="1"]').click()
                assert not page.evaluate('() => document.documentElement.scrollWidth>innerWidth'),f'Overflow: {destination}/{width}'
                if width in [390,1440]:page.screenshot(path=str(out/(destination+'-'+str(width)+'.png')),full_page=True)
        page.emulate_media(reduced_motion='reduce')
        page.locator('[data-action=proof-present]').click();assert page.locator('body.presenting').count()==1
        page.keyboard.press('Escape');assert page.locator('body.presenting').count()==0
        page.locator('[data-page=ml]').click()
        page.route('**/api/target/run',lambda route:route.fulfill(status=503,content_type='application/json',body=json.dumps({'error':'Test: local target unavailable; no fixture fallback.'})))
        page.locator('[data-action=target-run]').click()
        page.wait_for_function("() => !busy && document.querySelector('#toast').textContent.includes('no fixture fallback')")
        assert not errors,errors
        assert all('503' in text for text in console),console
        summary={'passed':True,'actual_local_target':measured,'windows_boundary':windows,
                 'native_signature_verified':True,'original_main_evidence_preserved':True,
                 'viewports':[375,390,768,1024,1440],'failure_state_tested':True,'page_errors':errors}
        (out/'verification.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(json.dumps({'passed':True,'completed_local_target_calls':measured['target_calls'],
                          'os_passed':windows['passed'],'os_inconclusive':windows['inconclusive'],'main_history_preserved':True}))
    finally:browser.close()
