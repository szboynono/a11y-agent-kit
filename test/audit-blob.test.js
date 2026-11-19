import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { AuditBrowser } from '../src/audit/browser.js';
import { auditActionSchema, parseAuditManifest } from '../src/audit/schema.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { fixture } from './helpers.js';
const marker = 'private-body-marker-92af';
const bytes = [0,255,128,10,...Buffer.from(marker)];
const hash = data => createHash('sha256').update(Buffer.from(data)).digest('hex');
const action = extra => auditActionSchema.parse({action:'blob_digest',selector:'#asset',attribute:'href',...extra});
export const html = `<!doctype html><html lang="en"><title>Blob</title><body><a id="asset">Download</a><i class="dup"></i><i class="dup"></i><script>document.querySelector('#asset').href=URL.createObjectURL(new Blob([new Uint8Array(${JSON.stringify(bytes)})],{type:'application/x-private'}));</script></body></html>`;
async function browser(t) {
  const site = await fixture(t,html), b = new AuditBrowser(parseAuditManifest({projectRoot:site.projectRoot,url:site.url}));
  t.after(()=>b.close()); await b.start(); return b;
}
function okay(r) { assert.equal(r.success,true,JSON.stringify(r.error)); assert.equal(r.result.complete,true); assert.ok(r.result.nodeId); assert.ok(r.before && r.after); assert.ok(!JSON.stringify(r).includes(marker)); return r.result; }

test('strict action limits and unchanged readiness recipe',()=>{
  assert.equal(action().maxBytes,1048576); assert.equal(action().timeoutMs,3000);
  for (const extra of [{attribute:'poster'},{url:'blob:https://x/a'},{js:'1'},{maxBytes:0},{maxBytes:8388609},{maxBytes:1.5},{timeoutMs:0},{timeoutMs:5001}]) assert.throws(()=>action(extra));
  assert.equal(parseAuditManifest({projectRoot:'/tmp',url:'http://localhost',actions:[{action:'wait_for',selector:'#asset',condition:'attribute',name:'ready',value:null}]}).actions[0].condition,'attribute');
});

test('two fresh Chromium contexts: differing URLs, identical full byte digest/size/MIME; byte and MIME changes and empty blobs',async t=>{
  const a=await browser(t), b=await browser(t);
  const x=okay(await a.execute(action())), y=okay(await b.execute(action()));
  assert.notEqual(x.originalBlobURL,y.originalBlobURL);
  for(const r of [x,y]) { assert.equal(r.sha256,hash(bytes)); assert.equal(r.size,bytes.length); assert.equal(r.mimeType,'application/x-private'); }
  for(const [data,type] of [[[1,2,3],'application/x-private'],[bytes,'text/plain'],[[],'']]) {
    await a.page.evaluate(({data,type})=>{document.querySelector('#asset').href=URL.createObjectURL(new Blob([new Uint8Array(data)],{type}));},{data,type});
    const r=okay(await a.execute(action())); assert.equal(r.sha256,hash(data)); assert.equal(r.size,data.length); assert.equal(r.mimeType,type);
    assert.notDeepEqual([r.sha256,r.mimeType],[x.sha256,x.mimeType]);
  }
});

test('invalid sources, revoked blobs, selectors and cap fail with no fallback HTTP requests or partial hashes',async t=>{
  const b=await browser(t); let requests=0; b.page.on('request',r=>{if(/^https?:/.test(r.url()))requests++;});
  for(const url of ['https://example.invalid/body','blob:https://example.invalid/uuid','blob:null/uuid',null]) {
    await b.page.evaluate(url=>{const a=document.querySelector('#asset'); if(url===null)a.removeAttribute('href');else a.setAttribute('href',url);},url);
    const r=await b.execute(action()); assert.equal(r.success,false); assert.equal(r.result.sha256,undefined);
  }
  for(const extra of [{selector:'.dup'},{selector:'#absent'},{selector:'xpath=//*'}]) assert.equal((await b.execute(action(extra))).success,false);
  await b.page.reload(); await b.settle(); requests=0;
  assert.equal((await b.execute(action({maxBytes:1}))).error.code,'AUDIT_BLOB_OVERSIZE');
  await b.page.evaluate(()=>URL.revokeObjectURL(document.querySelector('#asset').href));
  assert.equal((await b.execute(action())).success,false); assert.equal(requests,0);
});

test('main-world fetch/crypto/DOM prototype patches cannot forge isolated byte capture',async t=>{
  const b=await browser(t);
  await b.page.evaluate(()=>{
    window.fetch=()=>Promise.resolve(new Response('FORGED'));
    crypto.subtle.digest=()=>Promise.resolve(new Uint8Array(32).buffer);
    const original=Document.prototype.querySelectorAll;
    Document.prototype.querySelectorAll=function(s){return original.call(this,s==='#asset'?'#missing':s);};
    Element.prototype.getAttribute=new Proxy(Element.prototype.getAttribute,{apply(target,self,args){if(args[0]==='href')return 'forged';return Reflect.apply(target,self,args);}});
  });
  assert.equal(okay(await b.execute(action())).sha256,hash(bytes));
  await b.page.reload(); await b.settle();
  await b.page.evaluate(()=>{window.fetch=()=>Promise.resolve(new Response('FORGED')); crypto.subtle.digest=()=>Promise.resolve(new Uint8Array(32).buffer); const q=Document.prototype.querySelectorAll; Document.prototype.querySelectorAll=function(s){return q.call(this,s==='#asset'?'#missing':s);};});
  assert.equal(okay(await b.execute(action())).sha256,hash(bytes));
});

test('deadline includes initial capture; target replacement/source mutation/navigation and close never yield partial digests',async t=>{
  const b=await browser(t), original=b.observe.bind(b);
  b.observe=async(...args)=>{await new Promise(r=>setTimeout(r,60));return original(...args);};
  const r=await b.execute(action({timeoutMs:10})); assert.equal(r.success,false); assert.equal(r.result.sha256,undefined);
  b.observe=original;
  for(const mode of ['replace','attribute','navigate','close']) {
    if(mode!=='close'){await b.page.reload();await b.settle();}
    let calls=0;
    b.observe=async(...args)=>{
      if(++calls===2) {
        if(mode==='close')await b.close();
        else if(mode==='navigate')await b.page.reload();
        else await b.page.evaluate(mode=>{const a=document.querySelector('#asset'); if(mode==='replace')a.replaceWith(a.cloneNode(true));else {const old=a.href;a.href='blob:null/new';a.href=old;}},mode);
      }
      return original(...args);
    };
    const row=await b.execute(action());assert.equal(row.success,false,mode);assert.equal(row.result.sha256,undefined,mode);
    b.observe=original;
  }
});

test('actual generic agent step stores only metadata and retains one charged failed action',async t=>{
  const site=await fixture(t,html), agent=await openAuditAgent({projectRoot:site.projectRoot,url:site.url});t.after(()=>agent.close());
  const result=await agent.request({tool:'step',actions:[action(),action({maxBytes:1})]});
  assert.ok(!JSON.stringify(result).includes(marker));
  const stored=JSON.parse(await fs.readFile(path.join(agent.directory,'ev-0001.json')));
  assert.equal(stored.result.sha256,hash(bytes)); assert.equal(stored.result.complete,true);
  const failed=JSON.parse(await fs.readFile(path.join(agent.directory,'ev-0002.json')));assert.equal(failed.success,false);assert.equal(failed.result.sha256,undefined);
  await agent.close();
  for(const file of await fs.readdir(agent.directory))if(file.endsWith('.json'))assert.ok(!(await fs.readFile(path.join(agent.directory,file),'utf8')).includes(marker));
});

test('initial observation/setup gap cannot rebind to another already-observed node', async t => {
  const b = await browser(t);
  await b.page.evaluate(() => {
    const reserve = document.createElement('a'); reserve.id = 'reserve'; reserve.textContent = 'Reserve';
    reserve.href = document.querySelector('#asset').href; document.body.append(reserve);
  });
  const observe = b.observe.bind(b); let calls = 0;
  b.observe = async (...args) => {
    const observation = await observe(...args);
    if (++calls === 1) await b.page.evaluate(() => {
      document.querySelector('#asset').remove(); document.querySelector('#reserve').id = 'asset';
    });
    return observation;
  };
  const row = await b.execute(action());
  assert.equal(row.success, false); assert.equal(row.result.sha256, undefined);
});

test('unresponsive renderer cleanup cannot exceed the executor budget', async t => {
  const b = await browser(t), attach = b.context.newCDPSession.bind(b.context);
  let detachAttempted = false;
  b.context.newCDPSession = async page => {
    const cdp = await attach(page), send = cdp.send.bind(cdp), detach = cdp.detach.bind(cdp);
    cdp.detach = async () => { detachAttempted = true; return detach(); };
    cdp.send = (method, params) => {
      if (method === 'Runtime.callFunctionOn' && params.functionDeclaration.includes('async function readBody')) {
        params = { ...params, functionDeclaration: params.functionDeclaration.replace('const timer =',
          'const until = performance.now() + 1200; while (performance.now() < until) {} const timer =') };
      }
      return send(method, params);
    };
    return cdp;
  };
  const start = performance.now(), row = await b.execute(action({ timeoutMs: 100 }), 400);
  assert.equal(row.success, false); assert.equal(row.result.sha256, undefined);
  assert.equal(detachAttempted, true);
  assert.ok(performance.now() - start < 800, 'cleanup waited for the stalled renderer');
});

test('in-flight isolated reader timeout, executor budget, live interrupt and wall closure retain failures',async t=>{
  // Delay a real reader in the test CDP transport; no product hooks or main-world
  // fetch mocks. The response bytes still originate from the real fixture Blob.
  const { openAuditSession } = await import('../src/audit/live.js');
  for(const mode of ['timeout','budget','attribute','replace','interrupt','wall']) {
    const site=await fixture(t,html);
    let instance, onRead=()=>{}, detachCount=0;
    const start=AuditBrowser.prototype.start;
    AuditBrowser.prototype.start=async function(...args){
      instance=this;
      const result=await start.apply(this,args), attach=this.context.newCDPSession.bind(this.context);
      this.context.newCDPSession=async page=>{
        const cdp=await attach(page),send=cdp.send.bind(cdp),detach=cdp.detach.bind(cdp);
        cdp.detach=async()=>{detachCount++;return detach();};
        cdp.send=(method,params)=>{
          if(method==='Runtime.callFunctionOn'&&params.functionDeclaration.includes('async function readBody')) {
            params={...params,functionDeclaration:params.functionDeclaration.replace('await this.reader.read()', 'await new Promise(resolve => setTimeout(() => resolve(this.reader.read()), 3000))')};
            onRead();
          }
          return send(method,params);
        };
        return cdp;
      };
      return result;
    };
    let session;
    try {session=await openAuditSession({projectRoot:site.projectRoot,url:site.url,wallSeconds:mode==='wall'?2:20});}
    finally {AuditBrowser.prototype.start=start;}
    onRead=()=>{
      if(mode==='interrupt')setTimeout(()=>void session.finish({reason:'interrupted',signal:'SIGINT'}),20);
      if(['attribute','replace'].includes(mode))setTimeout(()=>void instance.page.evaluate(mode=>{
        const a=document.querySelector('#asset');if(mode==='replace')a.replaceWith(a.cloneNode(true));else a.href='blob:null/changed';
      },mode).catch(()=>{}),20);
    };
    let row;
    if(mode==='budget') {
      row=await instance.execute(action({timeoutMs:5000}),100);
      await session.finish();
    } else {
      row=await session.perform(action({timeoutMs:mode==='timeout'?100:5000}));
      if(!['wall','interrupt'].includes(mode))await session.finish();
    }
    assert.equal(row.success,false,mode);assert.equal(row.result.sha256,undefined,mode);
    assert.ok(detachCount>=1,mode);
    const report=await session.finished;
    if(mode!=='budget'){assert.equal(report.records.length,1);assert.equal(report.summary.executedActions,1);}
    if(mode==='interrupt')assert.equal(report.liveSession.termination.reason,'interrupted');
    if(mode==='wall')assert.equal(report.liveSession.termination.reason,'wall_budget_exhausted');
  }
});
