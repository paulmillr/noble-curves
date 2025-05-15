import { readFileSync } from 'node:fs';
import { dirname, join as joinPath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

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

export const getTypeTests = () => [
  [0, '0'],
  [123, '123'],
  [123.456, '123.456'],
  [-5n, '-5n'],
  [1.0000000000001, '1.0000000000001'],
  [10e9999, '10e9999'],
  [Infinity, 'Infinity'],
  [-Infinity, '-Infinity'],
  [NaN, 'NaN'],
  [true, 'true'],
  [false, 'false'],
  [null, 'null'],
  [undefined, 'undefined'],
  ['', '""'],
  ['1', '"1"'],
  ['1 ', '"1 "'],
  [' 1', '" 1"'],
  ['0xbe', '"0xbe"'],
  ['keys', '"keys"'],
  [new String('1234'), 'String(1234)'],
  [new Uint8Array([]), 'ui8a([])'],
  [new Uint8Array([0]), 'ui8a([0])'],
  [new Uint8Array([1]), 'ui8a([1])'],
  // [new Uint8Array(32).fill(1), 'ui8a(32*[1])'],
  [new Uint8Array(4096).fill(1), 'ui8a(4096*[1])'],
  [new Uint16Array(32).fill(1), 'ui16a(32*[1])'],
  [new Uint32Array(32).fill(1), 'ui32a(32*[1])'],
  [new Float32Array(32), 'f32a(32*0)'],
  [new BigUint64Array(32).fill(1n), 'ui64a(32*[1])'],
  [new ArrayBuffer(100), 'arraybuf'],
  [new DataView(new ArrayBuffer(100)), 'dataview'],
  [{ constructor: { name: 'Uint8Array' }, length: '1e30' }, 'fake(ui8a)'],
  [Array(32).fill(1), 'array'],
  [new Set([1, 2, 3]), 'set'],
  [new Map([['aa', 'bb']]), 'map'],
  [() => {}, 'fn'],
  [async () => {}, 'fn async'],
  [class Test {}, 'class'],
  [Symbol.for('a'), 'symbol("a")'],
];
export const getTypeTestsNonUi8a = () =>
  getTypeTests()
    .filter((test) => !test[1].startsWith('ui8a'))
    .map((test) => test[0]);

export function repr(item) {
  if (item && item.isProxy) return '[proxy]';
  if (typeof item === 'symbol') return item.toString();
  return `${item}`;
}
