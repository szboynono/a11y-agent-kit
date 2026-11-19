import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { AuditBrowser } from '../src/audit/browser.js';
import { auditActionSchema, parseAuditManifest } from '../src/audit/schema.js';
import { openAuditSession } from '../src/audit/live.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { collectAudit } from '../src/audit/collect.js';
import { fixture } from './helpers.js';

const html = `<!doctype html><html lang="en"><title>Readiness</title><body>
<button id="go" onclick="setTimeout(window.finishReadiness,180)">Start</button>
<script>window.finishReadiness = () => { document.querySelector('#status').textContent=' Ready \\n'; document.querySelector('#status').setAttribute('aria-busy','false'); document.querySelector('#new').hidden=false; const inserted=document.createElement('p'); inserted.id='inserted'; inserted.textContent='Inserted result'; document.body.append(inserted); document.querySelector('#gone').remove(); }; </script>
<div id="status" aria-busy="true">Loading</div><p id="new" hidden>New visible state</p><p id="gone">Temporary</p><i class="duplicate"></i><i class="duplicate"></i><input id="secret" type="password" value="private">
</body></html>`;
const wait = (selector, condition, extra = {}) => ({ action: 'wait_for', selector, condition, ...extra });
async function browser(t) {
  const site = await fixture(t, html);
  const b = new AuditBrowser(parseAuditManifest({ projectRoot: site.projectRoot, url: site.url }));
  t.after(() => b.close()); await b.start(); return b;
}

test('readiness strict variants preserve literal strings and defaults', () => {
  assert.equal(auditActionSchema.parse(wait('#x', 'text', { expected: ' a\n ' })).expected, ' a\n ');
  assert.equal(auditActionSchema.parse(wait('#x', 'attached')).timeoutMs, 3000);
  for (const bad of [wait('#x','text'), wait('#x','text',{expected:'ok',value:'ok'}), wait('#x','visible',{expected:'ok'}), wait('#x','attribute',{name:'aria-busy'}), wait('#x','attribute',{name:'bad name',value:null}), wait('#x','text',{expected:'x'.repeat(4097)}), wait('#x','attribute',{name:'x'.repeat(129),value:null}), ...[0,5001,1.5].map(timeoutMs=>wait('#x','attached',{timeoutMs})), wait('#x','javascript',{expected:'true'})]) assert.equal(auditActionSchema.safeParse(bad).success, false, JSON.stringify(bad));
});

test('real Chromium delayed predicates and snapshot share the original context', async t => {
  const b = await browser(t);
  for (const action of [wait('#status','attached'), wait('#new','hidden'), {action:'click',selector:'#go'}, wait('#status','text',{expected:' Ready \n'}), wait('#status','attribute',{name:'aria-busy',value:'false'}), wait('#new','visible'), wait('#gone','detached'), wait('#gone','hidden'), wait('#status','attribute',{name:'missing',value:null})]) {
    const r = await b.execute(auditActionSchema.parse(action)); assert.equal(r.success,true,JSON.stringify(r.error));
    if (action.action === 'wait_for') { assert.equal(r.result.matched,true); assert.equal(r.result.condition,action.condition); assert.ok(r.before && r.after); }
  }
  const snap = await b.execute({action:'snapshot'});
  assert.equal(snap.success,true); assert.ok(snap.result.visibleText.includes('New visible state')); assert.ok(!snap.result.nodes.some(n=>n.attributes.id==='gone'));
  const secret = await b.execute(auditActionSchema.parse(wait('#secret','attribute',{name:'value',value:'private'})));
  assert.equal(secret.result.actual,'[omitted]'); assert.equal(secret.result.actualOmitted,true);
  await b.page.evaluate(() => { const script=document.createElement('script'); script.type='application/json'; script.id='script-data'; script.textContent='inline private data'; document.body.append(script); });
  const script=await b.execute(auditActionSchema.parse(wait('#script-data','text',{expected:'inline private data'})));
  assert.equal(script.result.actual,'[omitted]'); assert.equal(script.result.actualOmitted,true);
});

test('new element and disappearance each poll before matching; literal text is not normalized', async t => {
  const b = await browser(t);
  for (const action of [wait('#inserted','attached'),wait('#inserted','visible'),wait('#new','visible'),wait('#gone','detached'),wait('#status','attribute',{name:'aria-busy',value:'false'})]) {
    await b.page.reload(); await b.settle();
    const evaluate = b.page.evaluate.bind(b.page);
    let polls = 0;
    // Release the fixture only after the real predicate has observed the old
    // state. Host scheduling cannot consume a timer before the action starts.
    b.page.evaluate = async (fn, arg) => {
      const result = await evaluate(fn, arg);
      if (fn.name === 'readinessObservation') {
        if (++polls === 1) {
          assert.equal(result.matched, false);
          await evaluate(() => window.finishReadiness());
        }
      }
      return result;
    };
    let r;
    try { r = await b.execute(auditActionSchema.parse(action)); }
    finally { b.page.evaluate = evaluate; }
    assert.equal(r.success,true,JSON.stringify(r)); assert.ok(polls >= 2);
  }
  const wrong = await b.execute(auditActionSchema.parse(wait('#status','text',{expected:'Ready',timeoutMs:60})));
  assert.equal(wrong.success,false); assert.equal(wrong.result.actual,' Ready \n');
});

test('timeouts, ambiguity and invalid CSS are failed bounded actions without alternate attempts', async t => {
  const b = await browser(t);
  for (const condition of ['attached','visible','text','attribute','hidden','detached']) {
    const r = await b.execute(auditActionSchema.parse(wait('.duplicate',condition, condition==='text'?{expected:''}:condition==='attribute'?{name:'x',value:null}:{})));
    assert.equal(r.success,false); assert.equal(r.error.code,'AUDIT_READINESS_AMBIGUOUS'); assert.equal(r.result.matched,false);
  }
  const start=performance.now();
  const r = await b.execute(auditActionSchema.parse(wait('#missing','text',{expected:'done',timeoutMs:5000})),100);
  assert.equal(r.success,false); assert.equal(r.error.code,'AUDIT_READINESS_TIMEOUT'); assert.equal(r.result.matched,false);
  assert.ok(r.result.effectiveTimeoutMs<=100); assert.ok(performance.now()-start<1000);
  assert.equal((await b.execute(auditActionSchema.parse(wait('xpath=//*','attached')))).success,false);
  const absent = await b.execute(auditActionSchema.parse(wait('#missing','attribute',{name:'aria-busy',value:null,timeoutMs:30})));
  assert.equal(absent.success,false); assert.equal(absent.result.count,0);
  await b.page.evaluate(() => { document.querySelector('#status').textContent='x'.repeat(1500); });
  const bounded = await b.execute(auditActionSchema.parse(wait('#status','text',{expected:'x'.repeat(1500)})));
  assert.equal(bounded.success,true); assert.equal(bounded.result.actual.length,1200); assert.equal(bounded.result.actualTruncated,true);
});

test('removed targets do not retain earlier poll visibility, text or attribute observations', async t => {
  const b = await browser(t);
  for (const condition of ['hidden', 'text', 'attribute']) {
    await b.page.evaluate(() => {
      const element = document.createElement('p'); element.id = 'transient';
      element.textContent = 'Earlier value'; element.setAttribute('data-state', 'earlier');
      document.body.append(element); setTimeout(() => element.remove(), 250);
    });
    const extra = condition === 'text' ? { expected: 'Later value' }
      : condition === 'attribute' ? { name: 'data-state', value: 'later' } : {};
    const result = await b.execute(auditActionSchema.parse(wait('#transient', condition, { ...extra, timeoutMs: 450 })));
    assert.equal(result.success, condition === 'hidden');
    assert.equal(result.result.count, 0);
    assert.equal(result.result.condition, condition);
    assert.equal(result.result.timeoutMs, 450);
    for (const key of ['visible', 'actual', 'actualOmitted', 'actualTruncated', 'ambiguous']) {
      assert.equal(Object.hasOwn(result.result, key), false, `${condition} retained stale ${key}`);
    }
  }
});

test('live invalid schema costs no action; timeout retains one failed original and collection stays incomplete', async t => {
  const site=await fixture(t,html), session=await openAuditSession({projectRoot:site.projectRoot,url:site.url,maxActions:2});
  t.after(()=>session.finish());
  await assert.rejects(session.perform(wait('#status','visible',{expected:'bad'})));
  const row=await session.perform(wait('#missing','attached',{timeoutMs:80}));
  assert.equal(row.evidenceId,'ev-0001'); assert.equal(row.success,false); assert.ok(row.before && row.after);
  const stored=JSON.parse(await fs.readFile(row.json.path)); assert.equal(stored.result.matched,false);
  const snap=await session.perform({action:'snapshot'}); assert.equal(snap.evidenceId,'ev-0002');
  const report=await session.finished; assert.equal(report.summary.executedActions,2); assert.equal(report.summary.invalidRequests,1); assert.equal(report.records.length,2); assert.equal(report.assessment.wholePage,'not_assessed');
});

test('batch collection and generic agent step execute readiness on the real path', async t => {
  const site=await fixture(t,html), actions=[{action:'click',selector:'#go'},wait('#new','visible'),{action:'snapshot'}];
  const report=await collectAudit({projectRoot:site.projectRoot,url:site.url,actions});
  assert.equal(report.status,'collected',JSON.stringify(report.errors)); assert.equal(report.records[1].result.matched,true); assert.ok(report.records[2].result.visibleText.includes('New visible state'));
  const agent=await openAuditAgent({projectRoot:site.projectRoot,url:site.url}); t.after(()=>agent.close());
  const result=await agent.request({tool:'step',actions}); assert.equal(result.success,true,JSON.stringify(result));
  assert.equal(result.budget.requestedActions,3); assert.equal(result.budget.returnedActions,3);
  const stored=JSON.parse(await fs.readFile(path.join(agent.directory,'ev-0002.json'))); assert.equal(stored.result.matched,true);
  await agent.close();
});

test('wall deadline and interrupt close cancel an in-flight readiness action', async t => {
  for (const reason of ['wall_budget_exhausted','interrupted']) {
    const site = await fixture(t, html);
    const entered = Promise.withResolvers(), closing = Promise.withResolvers();
    const start = AuditBrowser.prototype.start;
    const observer = t.mock.method(AuditBrowser.prototype, 'start', async function (...args) {
      const result = await start.apply(this, args);
      const evaluate = this.page.evaluate.bind(this.page), close = this.close.bind(this);
      this.close = (...args) => { closing.resolve(); return close(...args); };
      this.page.evaluate = async (fn, arg) => {
        const result = await evaluate(fn, arg);
        if (fn.name === 'readinessObservation') {
          assert.equal(result.matched, false);
          entered.resolve();
          // Keep a real predicate in flight until the session closes. This
          // proves cancellation without timing browser teardown or report I/O.
          await closing.promise;
        }
        return result;
      };
      return result;
    });
    let session;
    try { session = await openAuditSession({projectRoot:site.projectRoot,url:site.url,wallSeconds:reason==='interrupted'?20:2}); }
    finally { observer.mock.restore(); }
    t.after(() => session.finish());
    const pending = session.perform(wait('#never','attached',{timeoutMs:5000}));
    await Promise.race([entered.promise, pending.then(() => { throw new Error('Readiness ended before the predicate was observed'); })]);
    if (reason === 'interrupted') void session.finish({reason:'interrupted',signal:'SIGINT'});
    await Promise.race([closing.promise, pending.then(() => { throw new Error('Readiness ended before browser closure'); })]);
    const row = await pending; assert.equal(row.success,false);
    const report = await session.finished;
    assert.equal(report.records.length,1); assert.equal(report.summary.executedActions,1);
    assert.equal(report.liveSession.termination.reason,reason); assert.equal(session.status,'sealed');
  }
});
