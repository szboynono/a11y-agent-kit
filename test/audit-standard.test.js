import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { digest } from '../src/evidence.js';
import { AUDIT_STANDARD, AUDIT_CATALOG, parseAuditManifest, resolveAuditStandard, auditAxeTags } from '../src/audit/schema.js';
import { collectAudit } from '../src/audit/collect.js';
import { readAuditDocument, saveAuditDocument } from '../src/audit/store.js';
import { validateAuditProposalRecords, submitAudit, checkAudit } from '../src/audit/review.js';
import { saveAuditCheckpoint } from '../src/audit/checkpoint.js';
import { openAuditAgent } from '../src/audit/agent.js';
import { fixture } from './helpers.js';

const selections = [undefined, { version: '2.1', targetLevel: 'AA' }, { version: '2.1', targetLevel: 'A' }, { version: '2.2', targetLevel: 'A' }];
test('catalogs are pinned; parser omission stays omission; unsupported targets reject', () => {
  const manifest = parseAuditManifest({ projectRoot: '/tmp', url: 'http://localhost' });
  assert.equal(Object.hasOwn(manifest, 'standard'), false);
  assert.equal(resolveAuditStandard(), AUDIT_STANDARD);
  assert.equal(AUDIT_CATALOG.criteriaTotal, 50);
  const c22 = resolveAuditStandard({version:'2.2',targetLevel:'AA'});
  assert.deepEqual(c22.levelCounts, {A:31,AA:24});
  assert.deepEqual(c22.criteria.filter(row => !AUDIT_CATALOG.criteria.some(old => old.id === row.id)).map(row => [row.id,row.level]),
    [['2.4.11','AA'],['2.5.7','AA'],['2.5.8','AA'],['3.2.6','A'],['3.3.7','A'],['3.3.8','AA']]);
  assert.ok(['2.4.12','2.4.13','3.3.9'].every(id => !c22.criteria.some(row => row.id === id)));
  for (const [version, targetLevel, count] of [['2.1','A',30],['2.1','AA',50],['2.2','A',31],['2.2','AA',55]]) {
    const standard = resolveAuditStandard({ version, targetLevel });
    assert.equal(standard.criteria.length, count);
    const { catalogDigest, ...catalog } = standard;
    assert.equal(digest(catalog), catalogDigest);
    assert.equal(standard.criteria.some(row => row.id === '4.1.1'), version === '2.1');
    assert.ok(standard.criteria.every(row => targetLevel === 'AA' || row.level === 'A'));
  }
  for (const standard of [{version:'2.0',targetLevel:'AA'}, {version:'2.3',targetLevel:'A'}, {version:'2.2',targetLevel:'AAA'}, {}, null]) {
    assert.throws(() => parseAuditManifest({ ...manifest, standard }));
  }
});

const tiny = '<!doctype html><html lang="en"><title>Target test</title><style>button{width:10px;height:10px;padding:0;margin:0;border:0}</style><main><button aria-label="One"></button><button aria-label="Two"></button></main></html>';
test('Chromium uses selected axe tags and target-size rule; coverage and claims cannot cross catalogs', async t => {
  const site = await fixture(t, tiny);
  for (const selection of selections) {
    const manifest = { projectRoot: site.projectRoot, url: site.url, actions: [{action:'axe'}], ...(selection ? {standard: selection} : {}) };
    const report = await collectAudit(manifest);
    const selected = selection ?? {version:'2.2',targetLevel:'AA'};
    const standard = resolveAuditStandard(selected);
    assert.equal(report.status, 'collected', JSON.stringify(report.errors));
    assert.deepEqual(report.manifest.standard, selected);
    assert.deepEqual(report.standard, standard);
    assert.equal(report.coverage.length, standard.criteriaTotal);
    const record = report.records[0];
    assert.deepEqual(record.result.tags, auditAxeTags(selected));
    assert.deepEqual(report.executionPolicy.axeTags, record.result.tags);
    const rules = ['violations','passes','incomplete','inapplicable'].flatMap(key => record.result.axe[key]);
    assert.equal(rules.some(rule => rule.id === 'target-size'), selected.version === '2.2' && selected.targetLevel === 'AA');
    if (selected.version === '2.2' && selected.targetLevel === 'AA') assert.ok(record.result.axe.violations.some(rule => rule.id === 'target-size'));
    assert.ok(report.candidates.every(candidate => candidate.criterionIds.every(id => standard.criteria.some(row => row.id === id))));
    assert.equal((await checkAudit(report.reportPath)).status, 'current');
    const {reportDigest, reportPath, kind, ...body} = report;
    for (const tamper of [
      {...body, standard: AUDIT_STANDARD},
      {...body, standard: {...body.standard, catalogDigest:'sha256:' + '0'.repeat(64)}},
      {...body, coverage: body.coverage.slice(1)},
      {...body, coverage: body.coverage.map((row,i) => i ? row : {...row,level:'AAA'})},
      {...body, candidates:[{criterionIds:['9.9.9']}]},
    ]) {
      if (digest(tamper) === digest(body)) continue;
      const bad = await saveAuditDocument(site.projectRoot + '/evidence/audit-' + report.runId, 'audit', tamper);
      await assert.rejects(readAuditDocument(bad.reportPath));
    }
  }
});

test('legacy report omission retains old contract; new proposal and draft scope uses selected catalog', async t => {
  const site = await fixture(t, tiny);
  const report = await collectAudit({projectRoot:site.projectRoot,url:site.url,standard:{version:'2.1',targetLevel:'AA'},actions:[]});
  const {reportDigest,reportPath,kind,...body} = report;
  delete body.manifest.standard;
  body.manifestDigest = digest(body.manifest);
  const old = await saveAuditDocument(site.projectRoot + '/evidence/audit-' + report.runId, 'audit', body);
  assert.deepEqual((await readAuditDocument(old.reportPath)).standard, AUDIT_STANDARD);
  assert.equal((await checkAudit(old.reportPath)).status,'current');
  for (const standard of [{version:'2.2',targetLevel:'A'},{version:'2.2',targetLevel:'AA'},{version:'2.1',targetLevel:'AA'}]) {
    const agent = await openAuditAgent({projectRoot:site.projectRoot,url:site.url,standard});
    await agent.request({tool:'step',actions:[{action:'inspect',selector:'button:first-of-type'}]});
    const raw = JSON.parse(await fs.readFile(agent.directory + '/ev-0001.json'));
    const proposal = criterionId => ({auditor:{name:'Test'},findings:[{id:'F1',title:'Test claim',criterionId,target:{evidenceId:raw.evidenceId,nodeId:raw.result.element.nodeId},evidenceIds:[raw.evidenceId],observation:'Observed',reason:'Reason',applicability:'Applicable',exceptions:'None',scope:'Target',method:'dom'}]});
    const outside = standard.targetLevel === 'A' ? '1.4.3' : standard.version === '2.2' ? '4.1.1' : '2.5.8';
    assert.throws(() => validateAuditProposalRecords(proposal(outside),[raw],standard));
    assert.equal((await agent.request({tool:'checkpoint',proposal:proposal(outside)})).success,false);
    const inside = standard.version === '2.2' ? '3.2.6' : '4.1.1';
    const draft = await agent.request({tool:'checkpoint',proposal:proposal(inside)});
    assert.equal(draft.success,true,JSON.stringify(draft));
    const closed = await agent.close();
    const collectionPath = closed.sourceAudit.reportPath;
    await assert.rejects(submitAudit(collectionPath, proposal(outside)));
    if (standard.targetLevel === 'A') {
      const draftOther = await saveAuditCheckpoint({runId:agent.runId, directory:agent.directory, records:(await readAuditDocument(collectionPath)).records, proposal:proposal('4.1.2'), context:{evidencePolicy:'audit-evidence-2',standard:{version:'2.2',targetLevel:'AA'}}});
      await assert.rejects(submitAudit(collectionPath, proposal('4.1.2'), {sourceCheckpoint:{checkpointPath:draftOther.checkpointPath,checkpointDigest:draftOther.checkpointDigest}}), {code:'AUDIT_CHECKPOINT_CONTEXT_MISMATCH'});
    }
    const submitted = await submitAudit(collectionPath, proposal(inside));
    assert.equal(submitted.coverage.length, resolveAuditStandard(standard).criteriaTotal);
    assert.equal((await checkAudit(submitted.reportPath)).status, 'current');
  }
});
