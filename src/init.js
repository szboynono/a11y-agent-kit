// One-command onboarding: write a minimal audit manifest, check Chromium, print MCP snippets and a plain prompt.
// It never rewrites an existing file unless --force is given for the manifest; MCP files are only ever created.
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** npm release that first ships `init`. The snippets pin it so every host starts the same server version. */
export const KIT_RELEASE = '0.1.2';
export const DEFAULT_URL = 'http://127.0.0.1:3000/';
export const DEFAULT_MANIFEST = 'evidence/audit-manifest.json';
export const SKILL_URL = 'https://github.com/szboynono/a11y-agent-kit/blob/main/skills/a11y-audit/SKILL.md';
export const PLAYWRIGHT_VERSION = require('playwright/package.json').version;
export const INSTALL_COMMAND = `npx -y playwright@${PLAYWRIGHT_VERSION} install chromium`;
// Playwright reads these host overrides directly and as npm_config_/npm_package_config_ variants; any of them would
// send the browser download somewhere other than the Playwright CDN mirrors built into Playwright.
const DOWNLOAD_HOST_VARIABLES = new Set(['playwright_download_host', 'playwright_chromium_download_host']
  .flatMap(name => [name, `npm_config_${name}`, `npm_package_config_${name}`]).concat('pw_test_cdn_that_should_work'));

export const USAGE = 'Usage: a11y-agent-kit init [URL] [--manifest PATH] [--force] [--write] [--install]';

export class InitError extends Error {}

export function parseInitArgs(args) {
  const options = { url: undefined, manifest: DEFAULT_MANIFEST, force: false, write: false, install: false };
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (['--force', '--write', '--install'].includes(arg)) {
      if (seen.has(arg)) throw new InitError(`Duplicate ${arg}. ${USAGE}`);
      seen.add(arg); options[arg.slice(2)] = true;
    } else if (arg === '--manifest') {
      const value = args[++i];
      if (seen.has(arg) || !value?.trim() || value.startsWith('-')) throw new InitError(`--manifest needs one file path. ${USAGE}`);
      seen.add(arg); options.manifest = value;
    } else if (arg.startsWith('-') || !arg.trim()) throw new InitError(`Unknown option ${JSON.stringify(arg)}. ${USAGE}`);
    else if (options.url !== undefined) throw new InitError(`Give at most one URL. ${USAGE}`);
    else options.url = arg;
  }
  options.urlGiven = options.url !== undefined;
  options.url = normalizeUrl(options.url ?? DEFAULT_URL);
  return options;
}

function normalizeUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new InitError(`Not a valid URL: ${JSON.stringify(value)}. Use a full address such as ${DEFAULT_URL}`); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new InitError(`Only http and https URLs can be audited, got ${JSON.stringify(value)}.`);
  if (url.username || url.password) throw new InitError('Remove the user name and password from the URL; the kit does not sign in.');
  return url.href;
}

export function mcpServerEntry(release = KIT_RELEASE) {
  return { command: 'npx', args: ['-y', `a11y-agent-kit@${release}`, 'serve'] };
}

/** The three host snippets. Claude Code and Cursor read JSON `mcpServers`; Codex reads TOML `mcp_servers`. */
export function mcpSnippets(release = KIT_RELEASE) {
  const entry = mcpServerEntry(release);
  const json = `${JSON.stringify({ mcpServers: { 'a11y-agent-kit': entry } }, null, 2)}\n`;
  const toml = `[mcp_servers.a11y-agent-kit]\ncommand = "${entry.command}"\nargs = [${entry.args.map(arg => JSON.stringify(arg)).join(', ')}]\n`;
  return [
    { host: 'Claude Code', file: '.mcp.json', format: 'json', text: json },
    { host: 'Cursor', file: path.join('.cursor', 'mcp.json'), format: 'json', text: json },
    { host: 'Codex', file: path.join('.codex', 'config.toml'), format: 'toml', text: toml,
      note: 'Codex reads a project .codex/config.toml only in trusted projects; otherwise add it to ~/.codex/config.toml.' },
  ];
}

/** Plain-language prompt for the user's own agent. Evidence vocabulary stays in the skill document. */
export function agentPrompt({ url = DEFAULT_URL, manifest = DEFAULT_MANIFEST } = {}) {
  return [
    `Check my running app at ${url} for accessibility problems with a11y-agent-kit, using ${manifest}.`,
    `Follow ${SKILL_URL}, look at the screenshots before saying anything about how the page looks, and do not change my code.`,
    'When you finish, give me the HTML report, where the evidence is saved, and what you did not check.',
  ].join('\n');
}

async function lstatOrNull(file) {
  try { return await fs.lstat(file); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

function describeWriteError(error, file) {
  const reasons = { EACCES: 'permission denied', EPERM: 'permission denied', ENOTDIR: 'a parent path is not a directory', EROFS: 'read-only file system', EISDIR: 'it is a directory' };
  return new InitError(`Could not write ${file}: ${reasons[error.code] ?? error.message}. Choose another path with --manifest or fix the directory permissions.`);
}

/** Create the manifest; an existing one is kept unless `force`, and only a regular file may be replaced. */
export async function writeManifest({ cwd, manifest, url, force }) {
  const projectRoot = await fs.realpath(cwd);
  const file = path.resolve(projectRoot, manifest);
  const text = `${JSON.stringify({ projectRoot, url }, null, 2)}\n`;
  const existing = await lstatOrNull(file).catch(error => { throw describeWriteError(error, file); });
  if (existing && !force) {
    let current;
    try { current = JSON.parse(await fs.readFile(file, 'utf8')); } catch { current = undefined; }
    return { state: 'kept', file, projectRoot, url: typeof current?.url === 'string' ? current.url : undefined };
  }
  if (existing && !existing.isFile()) throw new InitError(`${file} exists and is not a regular file; --force only replaces a regular file.`);
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, text, { flag: existing ? 'w' : 'wx' });
  } catch (error) {
    if (error.code === 'EEXIST') return { state: 'kept', file, projectRoot };
    throw describeWriteError(error, file);
  }
  return { state: existing ? 'replaced' : 'created', file, projectRoot, url };
}

/** With `write`, create each missing config file; an existing file is never opened for writing. */
export async function writeMcpFiles({ projectRoot, snippets, write }) {
  const results = [];
  for (const snippet of snippets) {
    const file = path.join(projectRoot, snippet.file);
    if (!write) { results.push({ ...snippet, state: 'printed' }); continue; }
    try {
      if (await lstatOrNull(file)) { results.push({ ...snippet, state: 'exists' }); continue; }
      await fs.mkdir(path.dirname(file), { recursive: true });
      await fs.writeFile(file, snippet.text, { flag: 'wx' });
      results.push({ ...snippet, state: 'created' });
    } catch (error) {
      if (error.code === 'EEXIST') results.push({ ...snippet, state: 'exists' });
      else results.push({ ...snippet, state: 'failed', error: describeWriteError(error, file).message });
    }
  }
  return results;
}

/** Launch the Chromium build that this Playwright version expects, the same way an audit does. */
export async function probeChromium() {
  const { chromium } = await import('playwright');
  const executablePath = chromium.executablePath();
  let browser;
  try {
    browser = await chromium.launch({ headless: true, timeout: 60000 });
    return { ok: true, version: browser.version(), executablePath };
  } catch (error) {
    const message = String(error?.message ?? error);
    const missing = /Executable doesn't exist|browserType\.launch: .*not found|Please run the following command to download new browsers/i.test(message);
    return { ok: false, missing, executablePath, detail: message.split('\n').find(line => line.trim())?.trim() };
  } finally {
    await browser?.close().catch(() => {});
  }
}

/** Child environment for the download: host overrides are dropped so only the Playwright CDN is used. */
export function installEnv(env) {
  return Object.fromEntries(Object.entries(env).filter(([name]) => !DOWNLOAD_HOST_VARIABLES.has(name.toLowerCase())));
}

/** Download Chromium with this package's own Playwright CLI from the Playwright CDN; output streams to the user. */
export function installChromium({ env = process.env, stdio = 'inherit' } = {}) {
  const cli = path.join(path.dirname(require.resolve('playwright/package.json')), 'cli.js');
  const childEnv = installEnv(env);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, 'install', 'chromium'], { env: childEnv, stdio });
    child.on('error', reject);
    child.on('close', code => resolve({ code }));
  });
}

function indent(text, prefix = '     ') {
  return text.trimEnd().split('\n').map(line => `${prefix}${line}`).join('\n');
}

/**
 * Run `init`. Dependencies are injectable so tests never download or launch anything.
 * Returns { exitCode, lines } after writing every line to `out`.
 */
export async function runInit(args, { cwd = process.cwd(), env = process.env, out = text => process.stdout.write(text),
  probe = probeChromium, install = installChromium } = {}) {
  const options = parseInitArgs(args);
  const lines = [];
  const say = (text = '') => { lines.push(text); out(`${text}\n`); };
  let exitCode = 0;

  const manifest = await writeManifest({ cwd, manifest: options.manifest, url: options.url, force: options.force });
  const relativeManifest = path.relative(manifest.projectRoot, manifest.file) || manifest.file;
  const promptUrl = manifest.state === 'kept' && manifest.url ? manifest.url : options.url;
  say('a11y-agent-kit init');
  say();
  say('1. Audit manifest');
  if (manifest.state === 'kept') {
    say(`   ${relativeManifest} already exists, left unchanged.${manifest.url ? ` It audits ${manifest.url}.` : ''}`);
    if (options.urlGiven && manifest.url !== options.url) say(`   To audit ${options.url} instead, rerun with --force to replace it.`);
    else say('   Rerun with --force to replace it.');
  } else {
    say(`   ${manifest.state === 'created' ? 'Created' : 'Replaced'} ${relativeManifest}`);
    say(`   url: ${manifest.url}`);
    say(`   projectRoot: ${manifest.projectRoot}`);
  }

  say();
  say(`2. Chromium for Playwright ${PLAYWRIGHT_VERSION}`);
  let chromium = await probe();
  if (!chromium.ok && options.install) {
    say(`   Not usable yet. Downloading Chromium from the Playwright CDN (${INSTALL_COMMAND})...`);
    const installed = await install({ env }).catch(error => ({ code: 1, error }));
    if (installed.code !== 0) say(`   The download did not finish (${installed.error?.message ?? `exit code ${installed.code}`}).`);
    chromium = await probe();
  }
  if (chromium.ok) {
    say(`   OK: Chromium ${chromium.version}`);
    if (chromium.executablePath) say(`   ${chromium.executablePath}`);
  } else {
    exitCode = 1;
    say(chromium.missing ? '   Missing. Install it with:' : `   Could not start Chromium: ${chromium.detail ?? 'unknown error'}`);
    if (chromium.missing) say(`     ${INSTALL_COMMAND}`);
    if (!options.install) say('   or rerun init with --install to download it from the Playwright CDN.');
  }

  say();
  const snippets = await writeMcpFiles({ projectRoot: manifest.projectRoot, snippets: mcpSnippets(), write: options.write });
  say(options.write ? '3. MCP server for your agent' : '3. MCP server for your agent (printed only; rerun with --write to create missing files)');
  for (const snippet of snippets) {
    say();
    if (snippet.state === 'created') say(`   ${snippet.host}: created ${snippet.file}`);
    else if (snippet.state === 'exists') say(`   ${snippet.host}: ${snippet.file} already exists, left unchanged. Add this entry to it yourself:`);
    else if (snippet.state === 'failed') { exitCode = 1; say(`   ${snippet.host}: ${snippet.error} Add this entry yourself:`); }
    else say(`   ${snippet.host} (${snippet.file}):`);
    if (snippet.state !== 'created') say(indent(snippet.text));
    if (snippet.note) say(`   ${snippet.note}`);
  }

  say();
  say('4. Paste this into your coding agent:');
  say();
  say(indent(agentPrompt({ url: promptUrl, manifest: relativeManifest })));
  say();
  say(`Next: start your app at ${promptUrl}, restart your agent so it loads the MCP server, then paste the prompt.`);
  return { exitCode, lines, manifest, chromium, snippets };
}
