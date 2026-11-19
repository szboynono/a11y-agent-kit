import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { fixture } from './helpers.js';
const marker='private-interface-body-c0fe';
const html=`<!doctype html><html lang="en"><title>Blob interface</title><body><a id="asset">Download</a><script>document.querySelector('#asset').href=URL.createObjectURL(new Blob(['${marker}'],{type:'text/plain'}));</script></body></html>`;
const action={action:'blob_digest',selector:'#asset',attribute:'href'};
const sha=createHash('sha256').update(marker).digest('hex');
const actions=[{action:'wait_for',selector:'#asset',condition:'attached'},action,{action:'inspect',selector:'#asset'},{action:'screenshot'}];

test('CLI accepts explicit readiness/digest/inspect/PNG sequence, stores metadata without body',async t=>{
  const site=await fixture(t,html), dir=path.join(site.projectRoot,'evidence');await fs.mkdir(dir);
  const manifest=path.join(dir,'manifest.json');await fs.writeFile(manifest,JSON.stringify({projectRoot:site.projectRoot,url:site.url,actions}));
  const {stdout}=await promisify(execFile)(process.execPath,['src/cli.js','audit',manifest,'--summary'],{timeout:30000});
  const report=JSON.parse(await fs.readFile(JSON.parse(stdout).reportPath));
  assert.equal(report.records.length,4);assert.equal(report.records[1].result.sha256,sha);assert.ok(report.records[3].png);
  assert.ok(!stdout.includes(marker));assert.ok(!JSON.stringify(report).includes(marker));
});

test('MCP advertises strict action, preserves original BYOA ops plus inventory, executes and safely reads it',async t=>{
  const site=await fixture(t,html), client=new Client({name:'blob-test',version:'1'},{capabilities:{}});
  const transport=mcpTransport({command:process.execPath,args:['src/cli.js','serve'],stderr:'pipe'});t.after(()=>client.close());
  await client.connect(transport,{mode:'auto'});
  const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});const text=r.content[0].text;assert.ok(!text.includes(marker));return JSON.parse(text);};
  const list=await client.listTools(), schema=list.tools.find(x=>x.name==='a11y_audit_request').inputSchema;
  const serialized=JSON.stringify(schema);assert.ok(serialized.includes('blob_digest'));
  function find(v,predicate,rows=[]) { if(v&&typeof v==='object'){if(predicate(v))rows.push(v);for(const c of Object.values(v))find(c,predicate,rows);}return rows; }
  const variants=find(schema,v=>v.properties?.action?.const==='blob_digest');assert.ok(variants.length);assert.equal(variants[0].additionalProperties,false);assert.deepEqual(variants[0].properties.attribute.enum,['href','src']);
  assert.deepEqual(find(schema,v=>v.properties?.tool?.const).map(v=>v.properties.tool.const).sort(),['checkpoint','inventory','read','step','submit','view']);
  const start=await call('a11y_audit_start',{manifest:{projectRoot:site.projectRoot,url:site.url,startupAxe:false}});assert.equal(start.success,true);
  const request=request=>call('a11y_audit_request',{runId:start.runId,request});
  const bad=await request({tool:'step',actions:[{...action,url:'https://example.invalid'}]});assert.equal(bad.success,false);
  const step=await request({tool:'step',actions});assert.equal(step.success,true,JSON.stringify(step));
  const original=JSON.parse(await fs.readFile(path.join(start.directory,'ev-0002.json')));assert.equal(original.result.sha256,sha);
  const read=await request({tool:'read',evidenceId:'ev-0002',options:{view:'field',field:'/result'}});assert.equal(read.success,true);
  assert.ok(JSON.stringify(read).includes(sha));
  await call('a11y_audit_close',{runId:start.runId});await client.close();
});
