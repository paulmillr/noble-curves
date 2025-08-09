import { bytesToUtf8, utf8ToBytes } from '@noble/hashes/utils.js';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { invert, mod } from '../src/abstract/modular.ts';
import {
  abytes,
  asciiToBytes,
  bytesToHex,
  concatBytes,
  hexToBytes,
  numberToBytesBE,
  numberToBytesLE,
  numberToHexUnpadded,
  numberToVarBytesBE,
} from '../src/utils.ts';
import { getTypeTests } from './utils.ts';
describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) eql(hexToBytes(v.hex), v.bytes);
    for (let v of staticHexVectors) eql(hexToBytes(v.hex.toUpperCase()), v.bytes);
    for (let [v, repr] of getTypeTests()) {
      if (repr === '""') continue;
      throws(() => hexToBytes(v));
    }
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) eql(bytesToHex(v.bytes), v.hex);
    for (let [v, repr] of getTypeTests()) {
      if (repr.startsWith('ui8a')) continue;
      throws(() => bytesToHex(v));
    }
  });
  function hexa() {
    const items = '0123456789abcdef';
    return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
  }
  function hexaString(constraints = {}) {
    return fc.string({ ...constraints, unit: hexa() });
  }
  should('hexToBytes <=> bytesToHex roundtrip', () =>
    fc.assert(
      fc.property(hexaString({ minLength: 2, maxLength: 64 }), (hex) => {
        if (hex.length % 2 !== 0) return;
        eql(hex, bytesToHex(hexToBytes(hex)));
        eql(hex, bytesToHex(hexToBytes(hex.toUpperCase())));
        if (typeof Buffer !== 'undefined')
          eql(hexToBytes(hex), Uint8Array.from(Buffer.from(hex, 'hex')));
      })
    )
  );
  should('concatBytes', () => {
    const a = 1;
    const b = 2;
    const c = 0xff;
    const aa = Uint8Array.from([a]);
    const bb = Uint8Array.from([b]);
    const cc = Uint8Array.from([c]);
    eql(concatBytes(), Uint8Array.of());
    eql(concatBytes(aa, bb), Uint8Array.from([a, b]));
    eql(concatBytes(aa, bb, cc), Uint8Array.from([a, b, c]));
    for (let [v, repr] of getTypeTests()) {
      if (repr.startsWith('ui8a')) continue;
      throws(() => {
        concatBytes(v);
      });
    }
  });
  should('concatBytes random', () =>
    fc.assert(
      fc.property(fc.uint8Array(), fc.uint8Array(), fc.uint8Array(), (a, b, c) => {
        const expected = Uint8Array.from([...a, ...b, ...c]);
        eql(concatBytes(a.slice(), b.slice(), c.slice()), expected);
      })
    )
  );
  should('asciiToBytes', () => {
    const strings = [
      'H2C-OVERSIZE-DST-',
      'Seed-',
      'SigEd448',
      'SigEd25519 no Ed25519 collisions',
      'HashToGroup-',
      'DeriveKeyPair',
      'OPRFV1-',
      'SigEd448\0\0', // FROST
      '`',
    ];
    for (const s of strings) {
      eql(asciiToBytes(s), utf8ToBytes(s));
    }
    const UTF8 = [
      '┌─────',
      'some 🦁 ',
      // anything over 127 is extended ascii and depends on code-page
      '\x80',
      'e\u0301', // A "decomposed" character: 'e' followed by a combining accent '´'.
      '\uD83D', // A lone high surrogate, which is an invalid UTF-16 sequence.
      '\uDE00', // A lone low surrogate, also invalid.
    ];
    for (const s of UTF8) throws(() => asciiToBytes(s));
    const bytesOK = [
      new Uint8Array([72, 101, 108, 108, 111]),
      new Uint8Array([0]),
      new Uint8Array([]),
      new Uint8Array([127]),
    ];
    const bytesFAIL = [
      new Uint8Array([233]),
      new Uint8Array([233]),
      new Uint8Array([0xff, 0xfe]),
      new Uint8Array([128]),
      new Uint8Array([0xe9]),
      new Uint8Array([0xff, 0xfe]),
      new Uint8Array([0xc2]), // Incomplete 2-byte sequence
      new Uint8Array([0xe2, 0x82]), // Incomplete 3-byte sequence
      new Uint8Array([0xe2, 0x82, 0xac]),
    ];
    for (const b of bytesOK) {
      const s = bytesToUtf8(b);
      eql(asciiToBytes(s), utf8ToBytes(s));
    }
    for (const b of bytesFAIL) {
      const s = bytesToUtf8(b);
      throws(() => asciiToBytes(s));
    }
  });
  should('numberToHexUnpadded/numberToBytesBE/numberToVarBytesBE', () => {
    const VECTORS = [
      { value: 0n, expected: '00' },
      { value: 0, expected: '00' },
      { value: 1n, expected: '01' },
      { value: 1, expected: '01' },
      { value: 255, expected: 'ff' },
      { value: 256, expected: '0100' },
      { value: 0x123456789abcdefn, expected: '0123456789abcdef' },
      { value: Number.MAX_SAFE_INTEGER, expected: '1fffffffffffff' },
      { value: BigInt(Number.MAX_SAFE_INTEGER) + 1n, expected: '20000000000000' },
      // Errors
      { value: 0x123456789abcdef, error: 'overflow' },
      { value: -1, error: 'negative' },
      { value: NaN, error: 'NaN' },
      { value: Infinity, error: 'Infinity' },
      { value: -Infinity, error: '-Infinity' },
      { value: 1.5, error: 'float' },
      { value: -1n, error: 'negative bigint' },
    ];
    for (const { value, expected, error } of VECTORS) {
      if (error) {
        throws(() => numberToHexUnpadded(value), `numberToHexUnpadded: ${error}`);
        throws(() => numberToVarBytesBE(value), `numberToVarBytesBE: ${error}`);
        throws(() => numberToBytesBE(value, expected.length / 2), `numberToBytesBE: ${error}`);
      } else {
        eql(numberToHexUnpadded(value), expected);
        eql(numberToVarBytesBE(value), hexToBytes(expected));
        eql(numberToBytesBE(value, expected.length / 2), hexToBytes(expected));
      }
    }
  });
  should('numberToBytesBE/numberToBytesLE', () => {
    const VECTORS = [
      { value: 0n, len: 1, expectedBE: '00', expectedLE: '00' },
      { value: 1n, len: 1, expectedBE: '01', expectedLE: '01' },
      { value: 1n, len: 2, expectedBE: '0001', expectedLE: '0100' },
      { value: 0xff, len: 2, expectedBE: '00ff', expectedLE: 'ff00' },
      { value: 256, len: 2, expectedBE: '0100', expectedLE: '0001' },
      { value: 256, len: 1, error: 'overflow (len=3)' },
      { value: 0xff_ff, len: 1, error: 'overflow (len=4)' },
      // Errors
      { value: -1, len: 1, error: 'negative' },
      { value: NaN, len: 1, error: 'NaN' },
      { value: Infinity, len: 1, error: 'Infinity' },
      { value: -Infinity, len: 1, error: '-Infinity' },
      { value: 1.5, len: 1, error: 'float' },
      { value: -1n, len: 1, error: 'negative bigint' },
      { value: 0n, len: 0, error: 'zero length' },
      { value: 0n, len: -1, error: 'negative length' },
      { value: 0n, len: true, error: 'true length' },
    ];
    for (const { value, len, error, expectedBE, expectedLE } of VECTORS) {
      if (error) {
        throws(() => numberToBytesLE(value, len), `numberToBytesBE: ${error}`);
        throws(() => numberToBytesBE(value, len), `numberToBytesBE: ${error}`);
      } else {
        eql(numberToBytesLE(value, len), hexToBytes(expectedLE), `numberToBytesLE: ${expectedLE}`);
        eql(numberToBytesBE(value, len), hexToBytes(expectedBE), `numberToBytesBE: ${expectedBE}`);
      }
    }
  });
  should('abytes', () => {
    const VECTORS = [
      { b: 1, comment: 'number' },
      { b: true, comment: 'boolean' },
      { b: '00', comment: 'hex' },
      { b: NaN, comment: 'NaN' },
      { b: [], comment: 'array' },
      { b: new Uint16Array(2), comment: 'u16' },
      { b: new Uint32Array(2), comment: 'u32' },
      { b: new Uint8Array(2), len: 1, comment: 'len' },
      { b: null, comment: 'null' },
      { b: undefined, comment: 'undefined' },
      { b: new DataView(new Uint8Array(10).buffer), comment: 'dataview' },
      { b: { length: 10, constructor: { name: 'Uint8Array' } }, comment: 'obj' },
      { b: () => {}, comment: 'closure' },
      { b: function () {}, comment: 'fn' },
    ];
    for (const { b, len, comment } of VECTORS) {
      throws(() => abytes(b, len, comment), comment);
      try {
        abytes(b, len, comment);
      } catch (e) {
        // console.log('abytes', e.message);
      }
    }
  });
});

describe('utils math', () => {
  should('mod', () => {
    eql(mod(11n, 10n), 1n);
    eql(mod(-1n, 10n), 9n);
    eql(mod(0n, 10n), 0n);
  });
  should('invert', () => {
    eql(invert(512n, 1023n), 2n);
    eql(
      invert(2n ** 255n, 2n ** 255n - 19n),
      21330121701610878104342023554231983025602365596302209165163239159352418617876n
    );
    throws(() => {
      invert();
    });
    throws(() => {
      invert(1n);
    }); // no default modulus
    throws(() => {
      invert(0n, 12n);
    });
    throws(() => {
      invert(1n, -12n);
    });
    throws(() => {
      invert(512n, 1023);
    });
    throws(() => {
      invert(512, 1023n);
    });
  });
});

should.runWhen(import.meta.url);
