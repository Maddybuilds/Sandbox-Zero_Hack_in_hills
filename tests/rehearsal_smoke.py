"""Read-only rehearsal against a prepared preview. Never records video or runs probes."""
import argparse
import json
import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

parser=argparse.ArgumentParser();parser.add_argument('--url',required=True);parser.add_argument('--container-report',type=Path);args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;out=root/'test-results/rehearsal';out.mkdir(parents=True,exist_ok=True)
access=os.environ['SZ_REHEARSAL_ACCESS'];headers={'Authorization':'Bearer '+access}
with sync_playwright() as p:
    browser=p.chromium.launch(channel='chrome',headless=True)
    try:
        page=browser.new_page(viewport={'width':1440,'height':1000});errors=[];requests=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.on('request',lambda request:requests.append({'method':request.method,'url':request.url}))
        page.goto(args.url+'/#proof');page.wait_for_load_state('networkidle')
        page.locator('#access-code').fill(access);page.locator('#access-form button[type=submit]').click()
        page.wait_for_function("() => document.querySelector('#connection').textContent==='Connected'")
        def state():return page.request.get(args.url+'/api/state',headers=headers).json()
        before=state();assert before['integrity']['valid']
        started=time.monotonic()
        page.locator('[data-action=proof-case][data-id=encoded]').click()
        assert page.locator('.proof-lens.strict.allowed').count()==1
        assert page.locator('.proof-lens.hardened.held').count()==1
        page.locator('[data-action=proof-present]').click();assert page.locator('body.presenting').count()==1
        page.keyboard.press('Escape');assert page.locator('body.presenting').count()==0
        page.locator('[data-page=ml]').click()
        target=page.locator('.local-target-panel');target.scroll_into_view_if_needed()
        assert target.locator('tbody tr').count()==6
        target.locator('[data-action=target-detail]').nth(4).click()
        assert 'Output held' in page.locator('#detail-dialog').inner_text() or 'withheld' in page.locator('#detail-dialog').inner_text()
        page.keyboard.press('Escape')
        page.reload();page.wait_for_function("() => document.querySelector('#connection').textContent==='Connected'")
        assert page.locator('.local-target-panel tbody tr').count()==6
        page.locator('[data-page=proof]').click();page.locator('[data-action=proof-step][data-step="2"]').click()
        page.locator('[data-action=proof-verify]').click();page.wait_for_selector('.proof-verify-result.valid')
        page.locator('[data-action=proof-tamper]').click();page.wait_for_selector('.proof-verify-result.invalid')
        page.locator('[data-action=proof-verify]').click();page.wait_for_selector('.proof-verify-result.valid')
        for width in [390,1440]:
            page.set_viewport_size({'width':width,'height':1000})
            assert not page.evaluate('() => document.documentElement.scrollWidth>innerWidth')
        container=None
        if args.container_report:
            report_page=browser.new_page(viewport={'width':1440,'height':1000})
            report_page.goto(args.container_report.resolve().as_uri());report_page.wait_for_load_state('networkidle')
            assert 'All observed checks passed' in report_page.locator('body').inner_text()
            assert 'Internet egress' in report_page.locator('body').inner_text()
            report_page.screenshot(path=str(out/'container-report.png'),full_page=True)
            container=True;report_page.close()
        after=state();assert before['events']==after['events']
        for name in ['proof_lab','ml_lab','local_target']:assert before[name]['integrity']['head']==after[name]['integrity']['head']
        assert not [r for r in requests if r['method']=='POST' and '/api/' in r['url']],requests
        assert not errors,errors
        result={'passed':True,'read_only':True,'video_recorded':False,'saved_fixture_comparison':True,
                'saved_real_target_after_reload':True,'signature_and_tampered_copy_checked':True,
                'main_records_preserved':len(before['events']),'all_ledger_heads_preserved':True,
                'container_report_opened':container,'automation_seconds':round(time.monotonic()-started,2),
                'timing_scope':'Functional click-path timing only; not a measurement of the team speaking the 90-second script.'}
        (out/'verification.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
    finally:browser.close()
