import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { openAuditAgent } from '../src/audit/agent.js';
import { registerAuditTools } from '../src/audit/mcp.js';
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return {promise,resolve}; };
async function setup(t, opening = false, action = {action:'wait',ms:1}) {
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'eof-contract-')));
 t.after(()=>fs.rm(root,{recursive:true,force:true}));
 await fs.writeFile(path.join(root,'index.html'),'<p>local</p>');
 const entered=deferred(), release=deferred(), launched=deferred(), launchRelease=deferred();
 let closed=0, dispatched=0;
 const browser={axeTags:[],start:async()=>{launched.resolve();if(opening)await launchRelease.promise;return {};},close:async()=>{closed++; release.resolve();launchRelease.resolve();return [];},execute:async()=>{dispatched++;entered.resolve();await release.promise;return {success:true,before:null,after:null,result:{}};}};
 const handlers=new Map(),server={registerTool:(n,s,h)=>handlers.set(n,h),close:async()=>{},server:{}};
 registerAuditTools(server,{openAgent:(input,opts)=>openAuditAgent(input,{...opts,liveOptions:{createBrowser:()=>browser}})});
 const start=()=>handlers.get('a11y_audit_start')({manifest:{projectRoot:root,url:'http://localhost/',startupAxe:false}});
 const request=runId=>handlers.get('a11y_audit_request')({runId,request:{tool:'step',actions:[action]}});
 return {server,start,request,entered,release,launched,closed:()=>closed,dispatched:()=>dispatched};
}
for (const action of [{action:'wait',ms:1}, {action:'hover',selector:'#target'}, {action:'focus',selector:'#target'}]) {
test(`${action.action}: default MCP EOF drains in-flight and queued requests before live finish`,async t=>{
 const f=await setup(t,false,action),start=(await f.start()).structuredContent;
 const first=f.request(start.runId);await f.entered.promise;
 const second=f.request(start.runId),closing=f.server.closeAudit({reason:'eof'});
 await new Promise(r=>setImmediate(r));assert.equal(f.closed(),0);
 f.release.resolve();
 for(const reply of await Promise.all([first,second]))assert.equal(reply.structuredContent.records[0].success,true);
 assert.equal((await closing).termination.reason,'eof');assert.equal(f.dispatched(),2);
});
test(`${action.action}: explicit MCP interrupt stops live work and prevents queued dispatch`,async t=>{
 const f=await setup(t,false,action),start=(await f.start()).structuredContent;
 const first=f.request(start.runId);await f.entered.promise;
 const second=f.request(start.runId),closing=f.server.closeAudit({reason:'interrupted'});
 await Promise.all([first,second]);assert.equal((await closing).termination.reason,'interrupted');
 assert.ok(f.closed()>0);assert.equal(f.dispatched(),1);
});
test(`${action.action}: MCP EOF while opening cancels startup with cleanup and no dispatch`,async t=>{
 const f=await setup(t,true,action),starting=f.start();await f.launched.promise;
 await f.server.closeAudit({reason:'eof'});
 assert.equal((await starting).structuredContent.success,false);assert.ok(f.closed()>0);assert.equal(f.dispatched(),0);
});

}
