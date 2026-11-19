import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { inflateSync } from 'node:zlib';

export const INLINE_IMAGE_LIMITS = Object.freeze({ maxBytes: 2 * 1024 * 1024, maxPixels: 16000000 });
const refuse = code => { throw Object.assign(new Error('Original PNG cannot be sent inline; no image was delivered or inspected.'), { code }); };
const stable = (a, b) => ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
function crc(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}
// Validate the exact emitted buffer, including chunk checksums and bounded raster data.
// Chromium originals use non-interlaced 8-bit RGB/RGBA; other encodings refuse safely.
function validatePNG(bytes) {
  if (!bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) refuse('INLINE_IMAGE_INVALID_PNG');
  let offset = 8, width, height, channels, ended = false, idatEnded = false, palette = false;
  const compressed = [];
  while (offset + 12 <= bytes.length) {
    const size = bytes.readUInt32BE(offset), end = offset + 12 + size;
    if (end > bytes.length) refuse('INLINE_IMAGE_INVALID_PNG');
    const type = bytes.toString('latin1', offset + 4, offset + 8);
    const data = bytes.subarray(offset + 8, end - 4);
    if (!/^[A-Za-z]{2}[A-Z][A-Za-z]$/.test(type)) refuse('INLINE_IMAGE_INVALID_PNG');
    if (crc(bytes.subarray(offset + 4, end - 4)) !== bytes.readUInt32BE(end - 4)) refuse('INLINE_IMAGE_INVALID_PNG');
    if (offset === 8) {
      if (type !== 'IHDR' || size !== 13) refuse('INLINE_IMAGE_INVALID_PNG');
      width = data.readUInt32BE(0); height = data.readUInt32BE(4);
      if (!width || !height || width > 0x7fffffff || height > 0x7fffffff) refuse('INLINE_IMAGE_INVALID_PNG');
      if (width * height > INLINE_IMAGE_LIMITS.maxPixels) refuse('INLINE_IMAGE_PIXEL_LIMIT');
      channels = { 2: 3, 6: 4 }[data[9]];
      if (data[8] !== 8 || !channels || data[10] || data[11] || data[12]) refuse('INLINE_IMAGE_UNSUPPORTED_PNG');
    } else if (type === 'IDAT') {
      if (idatEnded) refuse('INLINE_IMAGE_INVALID_PNG');
      compressed.push(data);
    } else if (type === 'IEND') {
      if (size || !compressed.length || end !== bytes.length) refuse('INLINE_IMAGE_INVALID_PNG');
      ended = true; break;
    } else {
      if (compressed.length) idatEnded = true;
      // Ancillary chunks and an optional truecolor palette are permitted.
      if (!/^[A-Za-z]{4}$/.test(type) || (type[0] === type[0].toUpperCase() && type !== 'PLTE') ||
          (type === 'PLTE' && (palette || compressed.length || !size || size > 768 || size % 3))) refuse('INLINE_IMAGE_INVALID_PNG');
      if (type === 'PLTE') palette = true;
    }
    offset = end;
  }
  if (!ended) refuse('INLINE_IMAGE_INVALID_PNG');
  const stride = width * channels + 1, expected = stride * height;
  let raster;
  try {
    const input = Buffer.concat(compressed);
    const decoded = inflateSync(input, { maxOutputLength: expected, info: true });
    if (decoded.engine.bytesWritten !== input.length) refuse('INLINE_IMAGE_INVALID_PNG');
    raster = decoded.buffer;
  }
  catch { refuse('INLINE_IMAGE_INVALID_PNG'); }
  if (raster.length !== expected) refuse('INLINE_IMAGE_INVALID_PNG');
  for (let row = 0; row < height; row++) if (raster[row * stride] > 4) refuse('INLINE_IMAGE_INVALID_PNG');
  return { width, height };
}

/** Only call with the trusted successful agent.view receipt, never caller paths. */
export async function readInlineOriginal(image, directory) {
  try {
    if (!image || path.dirname(image.path ?? '') !== directory || await fs.realpath(directory) !== directory ||
        await fs.realpath(image.path) !== image.path) refuse('INLINE_IMAGE_INVALID_ARTIFACT');
    if (!Number.isSafeInteger(image.bytes) || image.bytes < 1 || image.bytes > INLINE_IMAGE_LIMITS.maxBytes) refuse('INLINE_IMAGE_BYTE_LIMIT');
    const beforePath = await fs.lstat(image.path, { bigint: true });
    if (!beforePath.isFile()) refuse('INLINE_IMAGE_INVALID_ARTIFACT');
    const handle = await fs.open(image.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.size !== BigInt(image.bytes) || !stable(beforePath, before)) refuse('INLINE_IMAGE_CHANGED');
      const bytes = Buffer.alloc(image.bytes + 1);
      let length = 0;
      while (length < bytes.length) {
        const read = await handle.read(bytes, length, bytes.length - length, length);
        if (!read.bytesRead) break;
        length += read.bytesRead;
      }
      if (length !== image.bytes || !stable(before, await handle.stat({ bigint: true })) ||
          !stable(before, await fs.lstat(image.path, { bigint: true })) || await fs.realpath(image.path) !== image.path ||
          createHash('sha256').update(bytes.subarray(0, length)).digest('hex') !== image.sha256) refuse('INLINE_IMAGE_CHANGED');
      const original = bytes.subarray(0, length);
      return { dimensions: validatePNG(original), block: { type: 'image', mimeType: 'image/png', data: original.toString('base64') } };
    } finally { await handle.close(); }
  } catch (error) {
    if (error.code?.startsWith('INLINE_IMAGE_')) throw error;
    refuse('INLINE_IMAGE_INVALID_ARTIFACT');
  }
}
