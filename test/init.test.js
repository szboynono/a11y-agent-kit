import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { runInit, parseInitArgs, mcpSnippets, agentPrompt, installEnv, InitError, KIT_RELEASE, DEFAULT_URL, INSTALL_COMMAND, PLAYWRIGHT_VERSION } from '../src/init.js';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('..', import.meta.url));
const cli = path.join(root, 'src/cli.js');
const ok = async () => ({ ok: true, version: '1.0.0', executablePath: '/opt/chromium' });
const missing = async () => ({ ok: false, missing: true, executablePath: '/opt/chromium', detail: "Executable doesn't exist" });
const quiet = { out: () => {} };

async function tempDir(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'a11y-init-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}
const exists = file => fs.lstat(file).then(() => true, () => false);

test('init writes only projectRoot (real path) and the default URL, and leaves an existing manifest unchanged', async t => {
  const real = await fs.realpath(await tempDir(t));
  const linked = path.join(await tempDir(t), 'link');
  await fs.symlink(real, linked);
  const first = await runInit([], { cwd: linked, probe: ok, ...quiet });
  assert.equal(first.exitCode, 0);
  const file = path.join(real, 'evidence/audit-manifest.json');
  const written = await fs.readFile(file, 'utf8');
  assert.deepEqual(JSON.parse(written), { projectRoot: real, url: DEFAULT_URL });
  assert.equal(first.manifest.state, 'created');

  const second = await runInit(['http://localhost:5173'], { cwd: real, probe: ok, ...quiet });
  assert.equal(second.manifest.state, 'kept');
  assert.equal(await fs.readFile(file, 'utf8'), written, 'existing manifest bytes are untouched');
  assert.ok(second.lines.some(line => line.includes('already exists, left unchanged')));
  assert.ok(second.lines.some(line => line.includes('rerun with --force')));
  assert.ok(second.lines.some(line => line.includes(`app at ${DEFAULT_URL}`)), 'the prompt keeps the manifest URL');

  const forced = await runInit(['http://localhost:5173', '--force'], { cwd: real, probe: ok, ...quiet });
  assert.equal(forced.manifest.state, 'replaced');
  assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { projectRoot: real, url: 'http://localhost:5173/' });
});

test('init --force replaces only a regular file and reports unwritable paths', async t => {
  const cwd = await tempDir(t);
  await fs.mkdir(path.join(cwd, 'evidence/audit-manifest.json'), { recursive: true });
  await assert.rejects(runInit(['--force'], { cwd, probe: ok, ...quiet }), error => error instanceof InitError && /not a regular file/.test(error.message));
  await fs.writeFile(path.join(cwd, 'blocker'), '');
  await assert.rejects(runInit(['--manifest', 'blocker/m.json'], { cwd, probe: ok, ...quiet }), error => error instanceof InitError && /Could not write/.test(error.message));
  await fs.writeFile(path.join(cwd, '.cursor'), 'not a directory');
  const blocked = await runInit(['--manifest', 'other.json', '--write'], { cwd, probe: ok, ...quiet });
  assert.deepEqual(blocked.snippets.map(snippet => snippet.state), ['created', 'failed', 'created']);
  assert.equal(blocked.exitCode, 1);
  assert.equal(await fs.readFile(path.join(cwd, '.cursor'), 'utf8'), 'not a directory');
});

test('init argument parsing rejects unknown, duplicate and unsafe input', () => {
  assert.equal(parseInitArgs([]).url, DEFAULT_URL);
  assert.equal(parseInitArgs(['https://staging.example.test']).url, 'https://staging.example.test/');
  for (const args of [['--bogus'], ['--force', '--force'], ['a', 'b'], ['ftp://host/'], ['not a url'], ['http://user:pw@host/'], ['--manifest'], ['--manifest', '--force']]) {
    assert.throws(() => parseInitArgs(args), InitError, JSON.stringify(args));
  }
});

test('MCP snippets: JSON for Claude Code and Cursor, TOML for Codex, all pinned to the release', async () => {
  const snippets = mcpSnippets();
  assert.deepEqual(snippets.map(snippet => [snippet.host, snippet.file.split(path.sep).join('/'), snippet.format]),
    [['Claude Code', '.mcp.json', 'json'], ['Cursor', '.cursor/mcp.json', 'json'], ['Codex', '.codex/config.toml', 'toml']]);
  const expected = { command: 'npx', args: ['-y', `a11y-agent-kit@${KIT_RELEASE}`, 'serve'] };
  for (const snippet of snippets.slice(0, 2)) assert.deepEqual(JSON.parse(snippet.text), { mcpServers: { 'a11y-agent-kit': expected } });
  assert.equal(snippets[2].text, `[mcp_servers.a11y-agent-kit]\ncommand = "npx"\nargs = ["-y", "a11y-agent-kit@${KIT_RELEASE}", "serve"]\n`);
  assert.equal(KIT_RELEASE, '0.1.2');
  const packageVersion = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8')).version.split('.').map(Number);
  const release = KIT_RELEASE.split('.').map(Number);
  const order = release.map((part, i) => Math.sign(part - packageVersion[i])).find(sign => sign !== 0) ?? 0;
  assert.ok(order >= 0, 'snippets never pin a release older than package.json');
});

test('init prints snippets by default and --write only creates missing files', async t => {
  const cwd = await fs.realpath(await tempDir(t));
  const printed = await runInit([], { cwd, probe: ok, ...quiet });
  for (const file of ['.mcp.json', '.cursor/mcp.json', '.codex/config.toml']) assert.equal(await exists(path.join(cwd, file)), false, file);
  assert.equal(printed.snippets.filter(snippet => snippet.state === 'printed').length, 3);
  assert.ok(printed.lines.join('\n').includes('"a11y-agent-kit@0.1.2"'));

  const existing = '{"mcpServers":{"other":{"command":"x"}}}\n';
  await fs.writeFile(path.join(cwd, '.mcp.json'), existing);
  const written = await runInit(['--write'], { cwd, probe: ok, ...quiet });
  assert.equal(await fs.readFile(path.join(cwd, '.mcp.json'), 'utf8'), existing, 'existing config is never rewritten');
  assert.deepEqual(written.snippets.map(snippet => snippet.state), ['exists', 'created', 'created']);
  assert.ok(written.lines.some(line => line.includes('.mcp.json already exists, left unchanged. Add this entry')));
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(cwd, '.cursor/mcp.json'), 'utf8')).mcpServers['a11y-agent-kit'].args.at(-1), 'serve');
  const again = await runInit(['--write'], { cwd, probe: ok, ...quiet });
  assert.deepEqual(again.snippets.map(snippet => snippet.state), ['exists', 'exists', 'exists']);
});

test('Chromium: OK is reported, a missing build prints the exact install command, and --install is the only download path', async t => {
  const cwd = await tempDir(t);
  let installs = 0;
  const install = async () => { installs++; return { code: 0 }; };
  const good = await runInit([], { cwd, probe: ok, install, ...quiet });
  assert.ok(good.lines.includes('   OK: Chromium 1.0.0'));
  const absent = await runInit([], { cwd, probe: missing, install, ...quiet });
  assert.equal(absent.exitCode, 1);
  assert.equal(INSTALL_COMMAND, `npx -y playwright@${PLAYWRIGHT_VERSION} install chromium`);
  assert.equal(PLAYWRIGHT_VERSION, '1.64.1');
  assert.ok(absent.lines.includes(`     ${INSTALL_COMMAND}`));
  assert.equal(installs, 0, 'nothing is downloaded without --install');
  let probes = 0;
  const flaky = async () => (probes++ === 0 ? missing() : ok());
  const installed = await runInit(['--install'], { cwd, probe: flaky, install, ...quiet });
  assert.equal(installs, 1);
  assert.equal(installed.exitCode, 0);
  assert.ok(installed.lines.includes('   OK: Chromium 1.0.0'));
  const already = await runInit(['--install'], { cwd, probe: ok, install, ...quiet });
  assert.equal(installs, 1, '--install does not download when Chromium already starts');
  assert.equal(already.exitCode, 0);
  const env = installEnv({ PATH: '/bin', PLAYWRIGHT_DOWNLOAD_HOST: 'https://mirror.invalid', PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST: 'https://mirror.invalid',
    npm_config_playwright_download_host: 'https://mirror.invalid', npm_package_config_playwright_chromium_download_host: 'https://mirror.invalid', HTTPS_PROXY: 'http://proxy.invalid' });
  assert.deepEqual(env, { PATH: '/bin', HTTPS_PROXY: 'http://proxy.invalid' }, 'download host overrides are dropped');
});

const FORBIDDEN = ['bound axe candidates', 'acknowledged digest', 'digest', 'checkpoint', 'jsonl', 'adopt', 'proposal', 'evidenceid', 'nodeid', 'scoreable'];

test('agent prompt is three plain-language lines without internal vocabulary', () => {
  const prompt = agentPrompt();
  assert.equal(prompt.split('\n').length, 3);
  for (const term of FORBIDDEN) assert.ok(!prompt.toLowerCase().includes(term), term);
  assert.match(prompt, /http:\/\/127\.0\.0\.1:3000\//);
  assert.match(prompt, /evidence\/audit-manifest\.json/);
});

test('README first screen: value, init command, prompt, screenshot, then limits', async () => {
  const readme = await fs.readFile(path.join(root, 'README.md'), 'utf8');
  const firstScreen = readme.slice(0, readme.indexOf('\n## '));
  const order = [
    firstScreen.indexOf('Find accessibility problems'),
    firstScreen.indexOf(`npx -y a11y-agent-kit@${KIT_RELEASE} init`),
    firstScreen.indexOf(`\`\`\`text\n${agentPrompt()}\n\`\`\``),
    firstScreen.indexOf('](docs/assets/sample-report.svg)'),
  ];
  assert.ok(order.every(index => index >= 0), JSON.stringify(order));
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.ok(readme.indexOf('## Limits') > readme.indexOf('## What `init` does'));
  assert.match(firstScreen, /`init` ships in a11y-agent-kit 0\.1\.2\. Until that version is on npm/);
  for (const term of FORBIDDEN.slice(0, 2)) assert.ok(!firstScreen.includes(term));
  assert.match(readme, /Validation on real third-party sites remains open/);
});

test('sample report screenshot is a reasonably sized PNG, kept as text, without local paths', async () => {
  // The PNG sits base64-encoded in a text SVG, so the committed file is ASCII and the screenshot bytes are unchanged.
  const svg = await fs.readFile(path.join(root, 'docs/assets/sample-report.svg'), 'utf8');
  assert.ok(Buffer.byteLength(svg) < 400 * 1024, `bytes ${Buffer.byteLength(svg)}`);
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="(\d+)" height="(\d+)"[^>]* role="img"/);
  assert.match(svg, /<title id="title">[^<]+<\/title>/);
  const localPaths = ['Users', 'home', 'private'].map(directory => `/${directory}/`);
  for (const marker of [...localPaths, 'file:', '<script']) assert.equal(svg.includes(marker), false, marker);
  assert.ok(/^[\x09\x0a\x20-\x7e]*$/.test(svg), 'ASCII only');
  const [, width, height] = svg.match(/width="(\d+)" height="(\d+)"/).map(Number);
  const png = Buffer.from(svg.match(/href="data:image\/png;base64,([A-Za-z0-9+/=]+)"/)[1], 'base64');
  assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  assert.equal(png.subarray(12, 16).toString('ascii'), 'IHDR');
  assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [width, height]);
  assert.ok(width >= 1200 && width <= 1400, `width ${width}`);
  assert.ok(height >= 600 && height <= 1800, `height ${height}`);
  for (const marker of [...localPaths, 'tEXt', 'iTXt', 'zTXt', 'eXIf']) assert.equal(png.includes(Buffer.from(marker)), false, marker);
});

test('init CLI runs in a fresh directory and keeps one plain-text error line for bad input', async t => {
  const cwd = await fs.realpath(await tempDir(t));
  let response;
  try { response = { ...await execute(process.execPath, [cli, 'init', 'http://127.0.0.1:4999/'], { cwd, timeout: 90000 }), code: 0 }; }
  catch (error) { response = { code: error.code, stdout: error.stdout, stderr: error.stderr }; }
  assert.ok([0, 1].includes(response.code), response.stderr);
  assert.match(response.stdout, /Created evidence\/audit-manifest\.json/);
  assert.match(response.stdout, /Chromium for Playwright 1\.64\.1/);
  assert.ok(response.stdout.includes(agentPrompt({ url: 'http://127.0.0.1:4999/' }).split('\n')[0]));
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(cwd, 'evidence/audit-manifest.json'), 'utf8')), { projectRoot: cwd, url: 'http://127.0.0.1:4999/' });
  const bad = await execute(process.execPath, [cli, 'init', '--nope'], { cwd }).catch(error => error);
  assert.equal(bad.code, 1);
  assert.equal(bad.stdout, '');
  assert.match(bad.stderr, /^a11y-agent-kit init: Unknown option "--nope"\. Usage:/);
});
