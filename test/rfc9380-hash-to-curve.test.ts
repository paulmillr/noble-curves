import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { json } from './utils.ts';
// Generic tests for all curves in package
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { shake128, shake256 } from '@noble/hashes/sha3.js';
import {
  _DST_scalar,
  createHasher,
  expand_message_xmd,
  expand_message_xof,
  hash_to_field,
  isogenyMap,
} from '../src/abstract/hash-to-curve.ts';
import { Field } from '../src/abstract/modular.ts';
import { mapToCurveSimpleSWU, SWUFpSqrtRatio } from '../src/abstract/hash-to-curve.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519_hasher, ristretto255_hasher } from '../src/ed25519.ts';
import { decaf448_hasher, ed448_hasher } from '../src/ed448.ts';
import * as nist from '../src/nist.ts';
import { secp256k1_hasher } from '../src/secp256k1.ts';
import { asciiToBytes } from '../src/utils.ts';
const PREFIX = './vectors/rfc9380-hash-to-curve/';
const vector = (name) => json(PREFIX + name + '.json');

function testExpandXMD(hash, name) {
  should(name, () => {
    const vectors = vector(name);
    for (let i = 0; i < vectors.tests.length; i++) {
      const t = vectors.tests[i];
      const p = expand_message_xmd(
        asciiToBytes(t.msg),
        asciiToBytes(vectors.DST),
        Number.parseInt(t.len_in_bytes),
        hash
      );
      eql(bytesToHex(p), t.uniform_bytes);
    }
  });
}

function testExpandXOF(hash, name) {
  should(name, () => {
    const vectors = vector(name);
    for (let i = 0; i < vectors.tests.length; i++) {
      const t = vectors.tests[i];
      const p = expand_message_xof(
        asciiToBytes(t.msg),
        asciiToBytes(vectors.DST),
        Number.parseInt(t.len_in_bytes),
        vectors.k,
        hash
      );
      eql(bytesToHex(p), t.uniform_bytes, i.toString());
    }
  });
}

function stringToFp(s) {
  // bls-G2 support
  if (s.includes(',')) {
    const [c0, c1] = s.split(',').map(BigInt);
    return { c0, c1 };
  }
  return BigInt(s);
}

function testCurve(hasher, roName, nuName) {
  should(roName, () => {
    const ro = vector(roName);
    for (let i = 0; i < ro.vectors.length; i++) {
      const t = ro.vectors[i];
      const p = hasher
        .hashToCurve(asciiToBytes(t.msg), {
          DST: ro.dst,
        })
        .toAffine();
      eql(p.x, stringToFp(t.P.x), 'Px');
      eql(p.y, stringToFp(t.P.y), 'Py');
    }
  });
  should(nuName, () => {
    const nu = vector(nuName);
    for (let i = 0; i < nu.vectors.length; i++) {
      const t = nu.vectors[i];
      const p = hasher
        .encodeToCurve(asciiToBytes(t.msg), {
          DST: nu.dst,
        })
        .toAffine();
      eql(p.x, stringToFp(t.P.x), 'Px');
      eql(p.y, stringToFp(t.P.y), 'Py');
    }
  });
}

describe('RFC9380 hash-to-curve', () => {
  should('helpers and wrappers reject empty DST', () => {
    const msg = new Uint8Array([1, 2, 3]);
    const err = (fn: () => unknown) => {
      try {
        fn();
        return 'ok';
      } catch (e) {
        return String(e);
      }
    };
    eql(
      {
        decaf448: err(() => decaf448_hasher.hashToCurve(msg, { DST: '' })),
        ed448: err(() => ed448_hasher.hashToCurve(msg, { DST: '' })),
        p256: err(() => nist.p256_hasher.hashToCurve(msg, { DST: '' })),
        p384: err(() => nist.p384_hasher.hashToCurve(msg, { DST: '' })),
        p521: err(() => nist.p521_hasher.hashToCurve(msg, { DST: '' })),
        ristretto255: err(() => ristretto255_hasher.hashToCurve(msg, { DST: '' })),
        secp256k1: err(() => secp256k1_hasher.hashToCurve(msg, { DST: '' })),
        xmd: err(() => expand_message_xmd(msg, new Uint8Array([]), 32, sha256)),
        xof: err(() => expand_message_xof(msg, new Uint8Array([]), 32, 128, shake128)),
      },
      {
        decaf448: 'Error: DST must be non-empty',
        ed448: 'Error: DST must be non-empty',
        p256: 'Error: DST must be non-empty',
        p384: 'Error: DST must be non-empty',
        p521: 'Error: DST must be non-empty',
        ristretto255: 'Error: DST must be non-empty',
        secp256k1: 'Error: DST must be non-empty',
        xmd: 'Error: DST must be non-empty',
        xof: 'Error: DST must be non-empty',
      }
    );
  });

  should('createHasher default snapshots and option validation', () => {
    const msg = Uint8Array.of(7, 8, 9);
    const dst = Uint8Array.of(1, 2, 3);
    const snapshotDefaults = {
      DST: dst,
      p: nist.p256.Point.Fp.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd' as const,
      hash: sha256,
    };
    const snapshotHasher = createHasher(
      nist.p256.Point,
      () => nist.p256.Point.BASE.toAffine(),
      snapshotDefaults
    );
    const before = snapshotHasher.hashToCurve(msg).toHex();
    dst[0] = 9;
    const exported = snapshotHasher.defaults;
    exported.DST[0] = 8;
    eql(Object.isFrozen(snapshotDefaults), false, 'caller defaults stay mutable');
    eql(Object.isFrozen(exported), true, 'exported defaults freeze');
    eql(snapshotHasher.defaults.DST, Uint8Array.of(1, 2, 3), 'DST snapshot');
    eql(snapshotHasher.hashToCurve(msg).toHex(), before, 'snapshot output');

    const encodeMsg = Uint8Array.of(1, 2, 3);
    const defaults = {
      DST: 'DST',
      encodeDST: '',
      p: nist.p256.Point.Fp.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd' as const,
      hash: sha256,
    };
    const hasher = createHasher(nist.p256.Point, () => nist.p256.Point.BASE.toAffine(), defaults);
    throws(() => hasher.encodeToCurve(encodeMsg), /DST/);

    const tupleDefaults = {
      DST: 'DST',
      p: nist.p256.Point.Fp.ORDER,
      m: 2,
      k: 128,
      expand: 'xmd' as const,
      hash: sha256,
    };
    const tupleHasher = createHasher(
      nist.p256.Point,
      () => nist.p256.Point.BASE.toAffine(),
      tupleDefaults
    );
    throws(() => tupleHasher.mapToCurve([1n]), /2/);
    throws(() => tupleHasher.mapToCurve([1n, 2n, 3n]), /2/);

    const scalarMsg = Uint8Array.of(1, 2, 3, 4);
    const suites = [
      ['p256_hasher', nist.p256_hasher],
      ['ristretto255_hasher', ristretto255_hasher],
      ['decaf448_hasher', decaf448_hasher],
    ] as const;
    eql(typeof _DST_scalar, 'string');
    const baseline = suites.map(([name, item]) => [name, item.hashToScalar(scalarMsg).toString()]);
    const explicit = suites.map(([name, item]) => [
      name,
      item.hashToScalar(scalarMsg, { DST: _DST_scalar }).toString(),
    ]);
    eql(baseline, explicit, '_DST_scalar explicit matches default');
    eql(_DST_scalar, 'HashToScalar-');

    const pinMsg = Uint8Array.of(1, 2, 3);
    const expected = nist.p256_hasher.hashToScalar(pinMsg, { DST: 'DST' });
    const actual = nist.p256_hasher.hashToScalar(pinMsg, { DST: 'DST', p: 1n, m: 2 } as never);
    eql(actual, expected, 'scalar field pins');

    // Per-call options are H2CDSTOpts: off-type extra keys must not replace suite parameters.
    const offType = { DST: 'DST', p: 17n, m: 2, k: 0, hash: sha512, expand: 'xof' } as never;
    eql(
      nist.p256_hasher.hashToCurve(pinMsg, offType).toHex(),
      nist.p256_hasher.hashToCurve(pinMsg, { DST: 'DST' }).toHex(),
      'hashToCurve ignores off-type suite overrides'
    );
    eql(
      nist.p256_hasher.encodeToCurve(pinMsg, offType).toHex(),
      nist.p256_hasher.encodeToCurve(pinMsg, { DST: 'DST' }).toHex(),
      'encodeToCurve ignores off-type suite overrides'
    );
    eql(
      nist.p256_hasher.hashToScalar(pinMsg, offType),
      expected,
      'hashToScalar ignores off-type suite overrides'
    );
  });

  describe('expand_message_xmd', () => {
    testExpandXMD(sha256, 'expand_message_xmd_SHA256_38');
    testExpandXMD(sha256, 'expand_message_xmd_SHA256_256');
    testExpandXMD(sha512, 'expand_message_xmd_SHA512_38');
    should('maximum ell and invalid hash guards', () => {
      const out = expand_message_xmd(new Uint8Array([1, 2, 3]), new Uint8Array([4]), 8160, sha256);
      eql(out.length, 8160, 'maximum ell');

      const noBlockLen = Object.assign((msg: Uint8Array) => sha256(msg), {
        outputLen: sha256.outputLen,
      });
      throws(
        () => expand_message_xmd(new Uint8Array([1]), 'DST', 32, noBlockLen as never),
        /blockLen/
      );
    });
  });
  describe('expand_message_xof', () => {
    testExpandXOF(shake128, 'expand_message_xof_SHAKE128_36');
    testExpandXOF(shake128, 'expand_message_xof_SHAKE128_256');
    testExpandXOF(shake256, 'expand_message_xof_SHAKE256_36');
    should('invalid lenInBytes and k guards', () => {
      throws(() => expand_message_xof(new Uint8Array([1]), 'DST', -1, 128, shake128), /lenInBytes/);

      const dst = new Uint8Array(256).fill(1);
      throws(() => expand_message_xof(new Uint8Array([1]), dst, 32, NaN, shake128), /k/);
      throws(() => expand_message_xof(new Uint8Array([1]), dst, 32, -1, shake128), /k/);
      eql(expand_message_xof(new Uint8Array([1]), dst, 0, 0, shake128).length, 0);

      const failCreate = Object.assign(() => new Uint8Array(), {
        create() {
          throw new Error('xof create reached');
        },
      });
      throws(
        () =>
          expand_message_xof(
            new Uint8Array([1]),
            new Uint8Array(256).fill(1),
            65536,
            128,
            failCreate as never
          ),
        /lenInBytes/
      );
    });
  });
  testCurve(nist.p256_hasher, 'P256_XMD_SHA-256_SSWU_RO_', 'P256_XMD_SHA-256_SSWU_NU_');
  testCurve(nist.p384_hasher, 'P384_XMD_SHA-384_SSWU_RO_', 'P384_XMD_SHA-384_SSWU_NU_');
  testCurve(nist.p521_hasher, 'P521_XMD_SHA-512_SSWU_RO_', 'P521_XMD_SHA-512_SSWU_NU_');
  testCurve(bls12_381.G1, 'BLS12381G1_XMD_SHA-256_SSWU_RO_', 'BLS12381G1_XMD_SHA-256_SSWU_NU_');
  testCurve(bls12_381.G2, 'BLS12381G2_XMD_SHA-256_SSWU_RO_', 'BLS12381G2_XMD_SHA-256_SSWU_NU_');
  testCurve(secp256k1_hasher, 'secp256k1_XMD_SHA-256_SSWU_RO_', 'secp256k1_XMD_SHA-256_SSWU_NU_');
  testCurve(
    ed25519_hasher,
    'edwards25519_XMD_SHA-512_ELL2_RO_',
    'edwards25519_XMD_SHA-512_ELL2_NU_'
  );
  testCurve(ed448_hasher, 'edwards448_XOF_SHAKE256_ELL2_RO_', 'edwards448_XOF_SHAKE256_ELL2_NU_');

  should('hash_to_field validates count, extension degree, k, and characteristic', () => {
    const msg = new Uint8Array([1, 2, 3]);
    const opts = { DST: 'DST', p: 17n, m: 1, k: 128, expand: 'xmd' as const, hash: sha256 };
    throws(() => hash_to_field(msg, 0, opts));
    throws(() => hash_to_field(msg, 1, { ...opts, m: 0 }));

    throws(() => hash_to_field(msg, 1, { ...opts, m: NaN }), /"m" expected safe integer/);
    throws(() => hash_to_field(msg, 1, { ...opts, m: 1.5 }), /"m" expected safe integer/);
    throws(() => hash_to_field(msg, 1, { ...opts, m: Infinity }), /"m" expected safe integer/);

    throws(() => hash_to_field(msg, 1, { ...opts, k: NaN }), /"k" expected safe integer/);
    throws(() => hash_to_field(msg, 1, { ...opts, k: 1.5 }), /"k" expected safe integer/);
    throws(() => hash_to_field(msg, 1, { ...opts, k: Infinity }), /"k" expected safe integer/);
    throws(() => hash_to_field(msg, 1, { ...opts, k: -1 }), /invalid k/);
    eql(hash_to_field(msg, 1, { ...opts, k: 0 })[0].length, 1);

    throws(() => hash_to_field(msg, 1, { ...opts, p: 1n }), /characteristic/);
    throws(() => hash_to_field(msg, 1, { ...opts, p: 0n }), /characteristic/);
    throws(() => hash_to_field(msg, 1, { ...opts, p: -17n }), /characteristic/);
  });
});

should('SWU, isogenyMap, and sqrt_ratio edge cases', () => {
  const Fp = Field(13n);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 0n, B: 1n, Z: 6n }), /invalid/i);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 1n, B: 0n, Z: 6n }), /invalid/i);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 1n, B: 1n, Z: 12n }), /invalid/i);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 1n, B: 1n, Z: 4n }), /invalid/i);

  const Fp5 = Field(5n);
  // RFC 9380 Appendix H.2 criterion 4: g(B / (Z * A)) must be square in F.
  throws(() => mapToCurveSimpleSWU(Fp5, { A: 2n, B: 1n, Z: 2n }), /invalid/i);

  const Fp17 = Field(17n);
  throws(() => isogenyMap(Fp17, [[], [1n], [1n], [1n]]), /isogenyMap/);

  const xDenZero = isogenyMap(Fp17, [[3n], [0n], [5n], [1n]]);
  const yDenZero = isogenyMap(Fp17, [[3n], [1n], [5n], [0n]]);
  eql(xDenZero(7n, 11n), { x: 0n, y: 0n });
  eql(yDenZero(7n, 11n), { x: 0n, y: 0n });

  const Fp13 = Field(13n);
  eql(SWUFpSqrtRatio(Fp13, 2n)(0n, 1n), { isValid: true, value: 0n });
  eql(SWUFpSqrtRatio(Fp13, 2n)(0n, 0n), { isValid: false, value: 0n });
  const Fp11 = Field(11n);
  eql(SWUFpSqrtRatio(Fp11, 2n)(0n, 1n), { isValid: true, value: 0n });
  eql(SWUFpSqrtRatio(Fp11, 2n)(0n, 0n), { isValid: false, value: 0n });

  throws(() => SWUFpSqrtRatio({ ORDER: 11n } as any, 2n), /"BYTES" expected number/);
});

should.runWhen(import.meta.url);
