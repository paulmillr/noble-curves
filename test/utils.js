import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { dirname, join as joinPath } from 'node:path';
import { fileURLToPath } from 'node:url';

const _dirname = dirname(fileURLToPath(import.meta.url));

export function jsonGZ(path) {
  const unz = gunzipSync(readFileSync(joinPath(_dirname, path)));
  return JSON.parse(unz.toString('utf8'));
}

export function json(path) {
  try {
    // Node.js
    return JSON.parse(readFileSync(joinPath(_dirname, path), { encoding: 'utf-8' }));
  } catch {
    // Bundler
    const file = path.replace(/^\.\//, '').replace(/\.json$/, '');
    if (path !== './' + file + '.json') throw new Error('Can not load non-json file');
    return require('./' + file + '.json'); // in this form so that bundler can glob this
  }
}


const TYPE_TEST_BASE = [
  null,
  [1, 2, 3],
  { a: 1, b: 2, c: 3 },
  NaN,
  0.1234,
  1.0000000000001,
  10e9999,
  new Uint32Array([1, 2, 3]),
  100n,
  new Set([1, 2, 3]),
  new Uint8ClampedArray([1, 2, 3]),
  new Int16Array([1, 2, 3]),
  new ArrayBuffer(100),
  new DataView(new ArrayBuffer(100)),
  { constructor: { name: 'Uint8Array' }, length: '1e30' },
  () => {},
  async () => {},
  class Test {},
];
const TYPE_TEST_NOT_STR = [
  ' 1 2 3 4 5',
  '010203040x',
  'abcdefgh',
  '1 2 3 4 5 ',
  'bee',
  new String('1234'),
];
export const TYPE_TEST = { hex: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_STR), bytes: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_STR) };
