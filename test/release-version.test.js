// Release version consistency: every place that names the kit's own version must agree with package.json,
// so a release cannot ship with a stale server version, plugin version or pinned npx command again.
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/client';
import { mcpTransport } from './mcp-transport.js';
import { KIT_RELEASE } from '../src/init.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const cliPath = path.join(root, 'src', 'cli.js');
const readJson = async relative => JSON.parse(await fs.readFile(path.join(root, relative), 'utf8'));
const packageVersion = (await readJson('package.json')).version;

test('release version: package.json, both package-lock.json fields and the init pin agree', async () => {
  assert.match(packageVersion, /^\d+\.\d+\.\d+$/);
  const lock = await readJson('package-lock.json');
  assert.equal(lock.version, packageVersion, 'package-lock.json root version');
  assert.equal(lock.packages[''].version, packageVersion, 'package-lock.json packages[""] version');
  assert.equal(KIT_RELEASE, packageVersion, 'src/init.js KIT_RELEASE pins the version being released');
});

test('release version: the stdio MCP handshake reports the package version as serverInfo.version', async t => {
  const transport = mcpTransport({ command: process.execPath, args: [cliPath, 'serve'], stderr: 'pipe' });
  const client = new Client({ name: 'a11y-agent-kit-version-test', version: '1.0.0' }, { capabilities: {} });
  t.after(() => client.close());
  await client.connect(transport, { mode: 'auto' });
  assert.deepEqual({ ...client.getServerVersion() }, { name: 'a11y-agent-kit', version: packageVersion });
});

test('release version: the Claude Code plugin manifest carries the package version', async () => {
  const plugin = await readJson('.claude-plugin/plugin.json');
  assert.equal(plugin.name, 'a11y-agent-kit');
  assert.equal(plugin.version, packageVersion);
});

async function markdownFiles(directory) {
  const entries = await fs.readdir(path.join(root, directory), { withFileTypes: true, recursive: true });
  return entries.filter(entry => entry.isFile() && entry.name.endsWith('.md'))
    .map(entry => path.relative(root, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'));
}

// Release records keep the version they describe. A record section names its own release, so the pin check skips
// it; everything else in the file, and every other scanned file, is current documentation and must match.
const HISTORICAL_SECTIONS = { 'docs/publication-boundary.md': '## Recorded verification' };

function currentText(file, text) {
  const heading = HISTORICAL_SECTIONS[file];
  if (!heading) return text;
  const lines = text.split('\n');
  const start = lines.indexOf(heading);
  assert.notEqual(start, -1, `${file}: historical section ${heading} exists`);
  const next = lines.findIndex((line, index) => index > start && line.startsWith('## '));
  return [...lines.slice(0, start), ...(next === -1 ? [] : lines.slice(next))].join('\n');
}

function versionPins(file, text) {
  return [...currentText(file, text).matchAll(/a11y-agent-kit@(\d+\.\d+\.\d+)/g)].map(match => ({ file, pin: match[0], version: match[1] }));
}

const stalePins = (file, text, version) => versionPins(file, text).filter(match => match.version !== version);

async function scannedFiles() {
  return ['README.md', 'llms.txt', ...await markdownFiles('examples'), ...await markdownFiles('skills'), ...await markdownFiles('commands'), ...await markdownFiles('docs')];
}

test('release version: every pinned a11y-agent-kit@X.Y.Z in user docs and skills is the package version', async () => {
  const files = await scannedFiles();
  // docs/mcp-images.md ships in the npm package, so its commands are scanned even when it pins no version.
  assert.ok(files.includes('docs/mcp-images.md'), 'the packaged docs page is scanned');
  let pins = 0;
  for (const file of files) {
    const text = await fs.readFile(path.join(root, file), 'utf8');
    for (const match of versionPins(file, text)) {
      pins++;
      assert.equal(match.version, packageVersion, `${file}: ${match.pin}`);
    }
  }
  assert.ok(pins >= 20, `expected the pinned commands to be found, saw ${pins}`);
});

test('release version: a later version bump flags stale pins in current docs but not in release records', async () => {
  const [major, minor, patch] = packageVersion.split('.').map(Number);
  const nextVersion = `${major}.${minor}.${patch + 1}`;
  const stalePin = `a11y-agent-kit@${packageVersion}`;

  // Simulate the next release against the repository as it is: every current pin is reported.
  let pins = 0;
  let stale = 0;
  for (const file of await scannedFiles()) {
    const text = await fs.readFile(path.join(root, file), 'utf8');
    pins += versionPins(file, text).length;
    stale += stalePins(file, text, nextVersion).length;
  }
  assert.ok(pins >= 20, `expected the pinned commands to be found, saw ${pins}`);
  assert.equal(stale, pins, `${nextVersion} would flag every current ${packageVersion} pin`);

  // A pin inside the release record does not fail the next release.
  const boundary = 'docs/publication-boundary.md';
  const text = await fs.readFile(path.join(root, boundary), 'utf8');
  const recordHeading = HISTORICAL_SECTIONS[boundary];
  const inRecord = text.replace(`${recordHeading}\n`, `${recordHeading}\n\nThe npm package \`${stalePin}\` was released.\n`);
  assert.ok(inRecord.includes(stalePin));
  assert.deepEqual(stalePins(boundary, inRecord, nextVersion), [], 'a release record keeps its own version');

  // The same pin outside the record, or in any other doc, is still caught.
  const inCurrentPart = text.replace('## Verify the source files\n', `## Verify the source files\n\nRun \`npx -y ${stalePin} init\`.\n`);
  assert.ok(inCurrentPart.includes(stalePin));
  assert.deepEqual(stalePins(boundary, inCurrentPart, nextVersion).map(match => match.pin), [stalePin], 'current text outside the record is still checked');
  assert.deepEqual(stalePins('README.md', `Run \`npx -y ${stalePin} init\`.`, nextVersion).map(match => match.pin), [stalePin], 'other docs are checked in full');
});
