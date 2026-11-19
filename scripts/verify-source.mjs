import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const filename = 'scripts/source-sha256.json';
assert.equal(process.argv.length, 2, 'Usage: node scripts/verify-source.mjs');

async function readRegularFile(relative) {
  const parts = relative.split('/');
  assert.ok(parts.every(part => /^[\w.-]+$/.test(part) && part !== '.' && part !== '..'),
    `Invalid relative path: ${relative}`);
  let resolved = root;
  for (const directory of parts.slice(0, -1)) {
    resolved = path.join(resolved, directory);
    assert.ok((await lstat(resolved)).isDirectory(), `Expected directory: ${relative}`);
  }
  resolved = path.join(resolved, parts.at(-1));
  assert.ok((await lstat(resolved)).isFile(), `Expected regular file: ${relative}`);
  return readFile(resolved);
}

const manifestBytes = await readRegularFile(filename);
const manifest = JSON.parse(manifestBytes);
assert.equal(manifest.schema, 'source-sha256-v1');
assert.ok(Array.isArray(manifest.files) && manifest.files.length > 0);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
let previous = '';
for (const entry of manifest.files) {
  assert.ok(typeof entry.path === 'string' && entry.path > previous && entry.path !== filename);
  assert.ok(Number.isSafeInteger(entry.bytes) && entry.bytes >= 0);
  assert.match(entry.sha256, /^[0-9a-f]{64}$/);
  const bytes = await readRegularFile(entry.path);
  assert.equal(bytes.length, entry.bytes, `Size changed: ${entry.path}`);
  assert.equal(sha256(bytes), entry.sha256, `SHA-256 changed: ${entry.path}`);
  previous = entry.path;
}
console.log(JSON.stringify({
  status: 'verified',
  filesChecked: manifest.files.length,
  manifestSha256: sha256(manifestBytes),
  scope: 'listed-files',
}));
