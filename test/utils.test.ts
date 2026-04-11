import { describe, should } from '@paulmillr/jsbt/test.js';
import * as fc from 'fast-check';
import { deepStrictEqual as eql, throws } from 'node:assert';
import {
  bytesToHex,
  concatBytes,
  ed,
  extra,
  hexToBytes,
  invert,
  mod,
  secp,
} from './utils.helpers.ts';
import { getTypeTests } from './utils.ts';

function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}

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
  should('validator constructors', () => {
    if (extra.abytes) {
      throws(() => extra.abytes!('x' as any), TypeError);
      throws(() => extra.abytes!(new Uint8Array(31), 32), RangeError);
    }
    throws(() => bytesToHex('x' as any), TypeError);
    if (secp) {
      throws(() => secp.getPublicKey(new Uint8Array(32)), RangeError);
      throws(() => secp.utils.randomSecretKey('x' as any), TypeError);
      throws(() => secp.utils.randomSecretKey(new Uint8Array(39)), RangeError);
    }
    if (ed) {
      throws(() => ed.Point.BASE.multiply('x' as any), TypeError);
      throws(() => ed.Point.BASE.multiply(0n), RangeError);
      throws(() => ed.utils.randomSecretKey('x' as any), TypeError);
      throws(() => ed.utils.randomSecretKey(new Uint8Array(31)), RangeError);
    }
  });
  should(
    'bytesToHex/concatBytes reject typed-array subclasses that spoof the Uint8Array constructor name',
    () => {
      class Uint8Array extends Uint16Array {}
      const spoof = new Uint8Array([0x12, 0x1234]);
      throws(() => bytesToHex(spoof as any), /expected Uint8Array/);
      throws(
        () =>
          concatBytes(globalThis.Uint8Array.of(0xaa), spoof as any, globalThis.Uint8Array.of(0xbb)),
        /expected Uint8Array/
      );
      if (extra.abytes) {
        throws(() => extra.abytes!(spoof as any, 2, 'spoof'), /expected Uint8Array/);
      }
      class Uint8Array2 extends DataView {}
      const spoof2 = new Uint8Array2(new ArrayBuffer(4));
      throws(() => bytesToHex(spoof2 as any), /expected Uint8Array/);
      throws(
        () =>
          concatBytes(
            globalThis.Uint8Array.of(0xaa),
            spoof2 as any,
            globalThis.Uint8Array.of(0xbb)
          ),
        /expected Uint8Array/
      );
    }
  );
  if (extra.copyBytes) {
    const copyBytes = extra.copyBytes;
    should('copyBytes', () => {
      const src = Uint8Array.of(1, 2, 3);
      const copy = copyBytes(src);
      eql(copy, src);
      copy[0] = 9;
      eql(src, Uint8Array.of(1, 2, 3));
      throws(() => copyBytes([1, 2] as any), new TypeError('expected Uint8Array, got type=object'));
      throws(
        () => copyBytes(new Uint16Array([1, 2]) as any),
        new TypeError('expected Uint8Array, got type=object')
      );
    });
  }
  if (extra.equalBytes) {
    const equalBytes = extra.equalBytes;
    should('equalBytes', () => {
      eql(equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2)), true);
      eql(equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 3)), false);
      throws(
        () => equalBytes([1, 2] as any, Uint8Array.of(1, 2)),
        new TypeError('expected Uint8Array, got type=object')
      );
      throws(
        () => equalBytes(new Uint16Array([1, 2]) as any, Uint8Array.of(1, 2)),
        new TypeError('expected Uint8Array, got type=object')
      );
    });
  }
  if (extra.asciiToBytes) {
    const asciiToBytes = extra.asciiToBytes;
    should('asciiToBytes', () => {
      const strings = [
        'H2C-OVERSIZE-DST-',
        'Seed-',
        'SigEd448',
        'SigEd25519 no Ed25519 collisions',
        'HashToGroup-',
        'DeriveKeyPair',
        'OPRFV1-',
        'SigEd448\0\0',
        '`',
      ];
      for (const s of strings) eql(asciiToBytes(s), new TextEncoder().encode(s));
      throws(() => asciiToBytes(1 as any), TypeError);
      const UTF8 = ['┌─────', 'some 🦁 ', '\x80', 'e\u0301', '\uD83D', '\uDE00'];
      for (const s of UTF8) throws(() => asciiToBytes(s), RangeError);
      const bytesOK = [
        new Uint8Array([72, 101, 108, 108, 111]),
        Uint8Array.of(0),
        Uint8Array.of(),
        new Uint8Array([127]),
      ];
      const bytesFAIL = [
        new Uint8Array([233]),
        new Uint8Array([233]),
        new Uint8Array([0xff, 0xfe]),
        new Uint8Array([128]),
        new Uint8Array([0xe9]),
        new Uint8Array([0xff, 0xfe]),
        new Uint8Array([0xc2]),
        new Uint8Array([0xe2, 0x82]),
        new Uint8Array([0xe2, 0x82, 0xac]),
      ];
      for (const b of bytesOK) {
        const s = new TextDecoder().decode(b);
        eql(asciiToBytes(s), new TextEncoder().encode(s));
      }
      for (const b of bytesFAIL) {
        const s = new TextDecoder().decode(b);
        throws(() => asciiToBytes(s), RangeError);
      }
    });
  }
  if (extra.hexToNumber) {
    const hexToNumber = extra.hexToNumber;
    should('hexToNumber', () => {
      eql(hexToNumber(''), 0n);
      eql(hexToNumber('ff'), 255n);
      throws(() => hexToNumber(1 as any), TypeError);
    });
  }
  if (extra.bitLen) {
    const bitLen = extra.bitLen;
    should('bitLen', () => {
      eql(bitLen(0n), 0);
      eql(bitLen(1n), 1);
      eql(bitLen(8n), 4);
      throws(() => bitLen(-1n), /expected non-negative bigint/);
    });
  }
  if (extra.numberToHexUnpadded && extra.numberToBytesBE && extra.numberToVarBytesBE) {
    const numberToHexUnpadded = extra.numberToHexUnpadded;
    const numberToBytesBE = extra.numberToBytesBE;
    const numberToVarBytesBE = extra.numberToVarBytesBE;
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
  }
  if (extra.numberToBytesBE && extra.numberToBytesLE) {
    const numberToBytesBE = extra.numberToBytesBE;
    const numberToBytesLE = extra.numberToBytesLE;
    should('numberToBytesBE/numberToBytesLE', () => {
      const VECTORS = [
        { value: 0n, len: 1, expectedBE: '00', expectedLE: '00' },
        { value: 1n, len: 1, expectedBE: '01', expectedLE: '01' },
        { value: 1n, len: 2, expectedBE: '0001', expectedLE: '0100' },
        { value: 0xff, len: 2, expectedBE: '00ff', expectedLE: 'ff00' },
        { value: 256, len: 2, expectedBE: '0100', expectedLE: '0001' },
        { value: 256, len: 1, error: 'overflow (len=3)' },
        { value: 0xff_ff, len: 1, error: 'overflow (len=4)' },
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
          eql(
            numberToBytesLE(value, len),
            hexToBytes(expectedLE),
            `numberToBytesLE: ${expectedLE}`
          );
          eql(
            numberToBytesBE(value, len),
            hexToBytes(expectedBE),
            `numberToBytesBE: ${expectedBE}`
          );
        }
      }
      throws(() => numberToBytesBE(256n, 1), new RangeError('number too large'));
      throws(() => numberToBytesLE(256n, 1), new RangeError('number too large'));
    });
  }
  if (extra.abytes) {
    const abytes = extra.abytes;
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
  }
  if (extra.abool && extra.asafenumber && extra.aInRange && extra.validateObject) {
    const abool = extra.abool;
    const asafenumber = extra.asafenumber;
    const aInRange = extra.aInRange;
    const validateObject = extra.validateObject;
    should('abool/asafenumber/aInRange/validateObject', () => {
      eql(abool(true), true);
      throws(() => abool('x' as any), TypeError);
      eql(asafenumber(1), undefined);
      throws(() => asafenumber('1' as any), TypeError);
      throws(() => asafenumber(1.5), RangeError);
      eql(aInRange('x', 2n, 1n, 3n), undefined);
      throws(() => aInRange('x', 3n, 1n, 3n), RangeError);
      eql(validateObject({ flag: true }, { flag: 'boolean' }), undefined);
      eql(validateObject({ flag: true, flga: false } as any, { flag: 'boolean' }), undefined);
      throws(() => validateObject(Object.create({ flag: true }), { flag: 'boolean' }), TypeError);
      eql(validateObject(Object.create({ fn() {} }), { fn: 'function' }), undefined);
      throws(() => validateObject('bad' as any, { flag: 'boolean' }), TypeError);
      throws(() => validateObject([] as any, { flag: 'boolean' }), TypeError);
      throws(() => validateObject({ flag: 1 }, { flag: 'boolean' }), TypeError);
    });
  }
  if (extra.bitSet) {
    const bitSet = extra.bitSet;
    should('bitSet', () => {
      eql(bitSet(0n, 1, true), 2n);
      eql(bitSet(5n, 2, false), 1n);
    });
  }
  if (extra.createHmacDrbg) {
    const createHmacDrbg = extra.createHmacDrbg;
    should('createHmacDrbg', () => {
      throws(() => createHmacDrbg(32, 32, 1 as any), TypeError);
      const hmacFn = (key: Uint8Array, msg: Uint8Array) =>
        Uint8Array.from({ length: key.length }, (_, i) => (msg[i % msg.length] || 0) ^ (i + 1));
      const drbg = createHmacDrbg(4, 4, hmacFn);
      let calls = 0;
      eql(
        drbg(Uint8Array.of(1, 2, 3), () => {
          calls += 1;
          return calls === 1 ? 0 : 7;
        }),
        0
      );
    });
  }
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
