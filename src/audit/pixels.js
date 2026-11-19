import { inflateSync } from 'node:zlib';
import { ToolError } from '../evidence.js';

const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

export function pngDimensions(bytes) {
  const input = Buffer.from(bytes);
  if (input.length < 33 || !input.subarray(0, 8).equals(signature) || input.toString('ascii', 12, 16) !== 'IHDR') {
    throw new ToolError('INVALID_PNG', 'The screenshot is not a PNG image.');
  }
  const width = input.readUInt32BE(16), height = input.readUInt32BE(20);
  if (!width || !height) throw new ToolError('INVALID_PNG', 'PNG dimensions must be nonzero.');
  return { width, height };
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Public Node APIs only. Chromium's ordinary screenshots are noninterlaced,
// eight-bit RGB/RGBA PNGs; other encodings fail explicitly rather than guessing.
export function decodePng(bytes) {
  const input = Buffer.from(bytes);
  const { width, height } = pngDimensions(input);
  if (width * height > 50000000) throw new ToolError('PNG_TOO_LARGE', 'Pixel decoding is limited to 50 million pixels.');
  const depth = input[24], colorType = input[25];
  if (depth !== 8 || ![2, 6].includes(colorType) || input[26] || input[27] || input[28]) {
    throw new ToolError('UNSUPPORTED_PNG', 'Only noninterlaced eight-bit RGB and RGBA PNGs are supported.');
  }
  const compressed = [];
  let end = false, sawData = false;
  for (let offset = 8; offset < input.length;) {
    if (offset + 12 > input.length) throw new ToolError('INVALID_PNG', 'Truncated PNG chunk.');
    const length = input.readUInt32BE(offset);
    const limit = offset + length + 12;
    if (limit > input.length) throw new ToolError('INVALID_PNG', 'Truncated PNG chunk data.');
    const type = input.toString('ascii', offset + 4, offset + 8);
    if (crc32(input.subarray(offset + 4, offset + 8 + length)) !== input.readUInt32BE(offset + 8 + length)) {
      throw new ToolError('INVALID_PNG', 'PNG chunk checksum does not match.');
    }
    if (type === 'IDAT') { compressed.push(input.subarray(offset + 8, offset + 8 + length)); sawData = true; }
    if (type === 'IEND') { end = true; if (limit !== input.length) throw new ToolError('INVALID_PNG', 'Unexpected bytes after IEND.'); break; }
    offset = limit;
  }
  if (!end || !sawData) throw new ToolError('INVALID_PNG', 'PNG has no complete image data.');
  const channels = colorType === 6 ? 4 : 3, stride = width * channels;
  let raw;
  try { raw = inflateSync(Buffer.concat(compressed), { maxOutputLength: (stride + 1) * height }); }
  catch { throw new ToolError('INVALID_PNG', 'PNG image data could not be inflated.'); }
  if (raw.length !== (stride + 1) * height) throw new ToolError('INVALID_PNG', 'Unexpected PNG image data length.');
  const data = Buffer.alloc(width * height * 4);
  let previous = Buffer.alloc(stride);
  const paeth = (a, b, c) => {
    const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
    return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
  };
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    if (filter > 4) throw new ToolError('INVALID_PNG', 'Unknown PNG scanline filter.');
    const row = Buffer.alloc(stride);
    for (let x = 0; x < stride; x++) {
      const left = x >= channels ? row[x - channels] : 0;
      const up = previous[x], upperLeft = x >= channels ? previous[x - channels] : 0;
      const predictor = [0, left, up, Math.floor((left + up) / 2), paeth(left, up, upperLeft)][filter];
      row[x] = (raw[y * (stride + 1) + 1 + x] + predictor) & 255;
    }
    for (let x = 0; x < width; x++) {
      const out = (y * width + x) * 4, at = x * channels;
      data[out] = row[at]; data[out + 1] = row[at + 1]; data[out + 2] = row[at + 2];
      data[out + 3] = channels === 4 ? row[at + 3] : 255;
    }
    previous = row;
  }
  return { width, height, channels: 4, data };
}

export function pixelAt(image, x, y) {
  if (!Number.isInteger(x) || !Number.isInteger(y) || x < 0 || y < 0 || x >= image.width || y >= image.height) {
    throw new ToolError('PIXEL_OUT_OF_BOUNDS', 'Pixel coordinates must be within the original screenshot.');
  }
  return [...image.data.subarray((y * image.width + x) * 4, (y * image.width + x) * 4 + 4)];
}

export function relativeLuminance(color) {
  if (!Array.isArray(color) || color.length < 3 || color.slice(0, 3).some(value => !Number.isFinite(value) || value < 0 || value > 255) || (color.length > 3 && color[3] !== 255)) {
    throw new ToolError('INVALID_COLOR', 'Contrast requires opaque RGB samples from 0 through 255.');
  }
  return color.slice(0, 3).map(value => {
    const channel = value / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
}

export function contrastRatio(first, second) {
  const a = relativeLuminance(first), b = relativeLuminance(second);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}
