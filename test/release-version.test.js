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

test('release version: every pinned a11y-agent-kit@X.Y.Z in user docs and skills is the package version', async () => {
  const files = ['README.md', 'llms.txt', ...await markdownFiles('examples'), ...await markdownFiles('skills'), ...await markdownFiles('commands')];
  let pins = 0;
  for (const file of files) {
    const text = await fs.readFile(path.join(root, file), 'utf8');
    for (const match of text.matchAll(/a11y-agent-kit@(\d+\.\d+\.\d+)/g)) {
      pins++;
      assert.equal(match[1], packageVersion, `${file}: ${match[0]}`);
    }
  }
  assert.ok(pins >= 20, `expected the pinned commands to be found, saw ${pins}`);
});
