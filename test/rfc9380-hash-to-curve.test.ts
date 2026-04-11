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
} from '../src/abstract/hash-to-curve.ts';
import { Field } from '../src/abstract/modular.ts';
import { mapToCurveSimpleSWU, SWUFpSqrtRatio } from '../src/abstract/weierstrass.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519_hasher, ristretto255_hasher } from '../src/ed25519.ts';
import { decaf448_hasher, ed448_hasher } from '../src/ed448.ts';
import * as nist from '../src/nist.ts';
import { secp256k1_hasher } from '../src/secp256k1.ts';
import { asciiToBytes } from '../src/utils.ts';
const PREFIX = './vectors/rfc9380-hash-to-curve/';
// XMD
const xmd_sha256_38 = json(PREFIX + 'expand_message_xmd_SHA256_38.json');
const xmd_sha256_256 = json(PREFIX + 'expand_message_xmd_SHA256_256.json');
const xmd_sha512_38 = json(PREFIX + 'expand_message_xmd_SHA512_38.json');
// XOF
const xof_shake128_36 = json(PREFIX + 'expand_message_xof_SHAKE128_36.json');
const xof_shake128_256 = json(PREFIX + 'expand_message_xof_SHAKE128_256.json');
const xof_shake256_36 = json(PREFIX + 'expand_message_xof_SHAKE256_36.json');
// P256
const p256_ro = json(PREFIX + 'P256_XMD_SHA-256_SSWU_RO_.json');
const p256_nu = json(PREFIX + 'P256_XMD_SHA-256_SSWU_NU_.json');
// P384
const p384_ro = json(PREFIX + 'P384_XMD_SHA-384_SSWU_RO_.json');
const p384_nu = json(PREFIX + 'P384_XMD_SHA-384_SSWU_NU_.json');
// P521
const p521_ro = json(PREFIX + 'P521_XMD_SHA-512_SSWU_RO_.json');
const p521_nu = json(PREFIX + 'P521_XMD_SHA-512_SSWU_NU_.json');
// secp256k1
const secp256k1_ro = json(PREFIX + 'secp256k1_XMD_SHA-256_SSWU_RO_.json');
const secp256k1_nu = json(PREFIX + 'secp256k1_XMD_SHA-256_SSWU_NU_.json');
// bls-G1
const g1_ro = json(PREFIX + 'BLS12381G1_XMD_SHA-256_SSWU_RO_.json');
const g1_nu = json(PREFIX + 'BLS12381G1_XMD_SHA-256_SSWU_NU_.json');
// bls-G2
const g2_ro = json(PREFIX + 'BLS12381G2_XMD_SHA-256_SSWU_RO_.json');
const g2_nu = json(PREFIX + 'BLS12381G2_XMD_SHA-256_SSWU_NU_.json');
// ed25519
const ed25519_ro = json(PREFIX + 'edwards25519_XMD_SHA-512_ELL2_RO_.json');
const ed25519_nu = json(PREFIX + 'edwards25519_XMD_SHA-512_ELL2_NU_.json');
// ed448
const ed448_ro = json(PREFIX + 'edwards448_XOF_SHAKE256_ELL2_RO_.json');
const ed448_nu = json(PREFIX + 'edwards448_XOF_SHAKE256_ELL2_NU_.json');

function testExpandXMD(hash, vectors) {
  should(`${vectors.hash}/${vectors.DST.length}`, () => {
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

function testExpandXOF(hash, vectors) {
  should(`${vectors.hash}/${vectors.DST.length}`, () => {
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

function testCurve(hasher, ro, nu) {
  should(`${ro.curve}/${ro.ciphersuite}`, () => {
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
  should(`${nu.curve}/${nu.ciphersuite}`, () => {
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

  should(
    'createHasher snapshots and freezes internal defaults without freezing caller input',
    () => {
      const msg = Uint8Array.of(7, 8, 9);
      const dst = Uint8Array.of(1, 2, 3);
      const defaults = {
        DST: dst,
        p: nist.p256.Point.Fp.ORDER,
        m: 1,
        k: 128,
        expand: 'xmd' as const,
        hash: sha256,
      };
      const hasher = createHasher(nist.p256.Point, () => nist.p256.Point.BASE.toAffine(), defaults);
      const before = hasher.hashToCurve(msg).toHex();
      dst[0] = 9;
      const exported = hasher.defaults;
      exported.DST[0] = 8;
      eql(Object.isFrozen(defaults), false);
      eql(Object.isFrozen(exported), true);
      eql(hasher.defaults.DST, Uint8Array.of(1, 2, 3));
      eql(hasher.hashToCurve(msg).toHex(), before);
    }
  );
  should(
    'exports _DST_scalar as immutable string so default hash-to-scalar helpers cannot be poisoned',
    () => {
      const msg = Uint8Array.of(1, 2, 3, 4);
      const suites = [
        ['p256_hasher', nist.p256_hasher],
        ['ristretto255_hasher', ristretto255_hasher],
        ['decaf448_hasher', decaf448_hasher],
      ] as const;
      eql(typeof _DST_scalar, 'string');
      const baseline = suites.map(([name, item]) => [name, item.hashToScalar(msg).toString()]);
      const explicit = suites.map(([name, item]) => [
        name,
        item.hashToScalar(msg, { DST: _DST_scalar }).toString(),
      ]);
      eql(baseline, explicit);
      eql(_DST_scalar, 'HashToScalar-');
    }
  );

  describe('expand_message_xmd', () => {
    testExpandXMD(sha256, xmd_sha256_38);
    testExpandXMD(sha256, xmd_sha256_256);
    testExpandXMD(sha512, xmd_sha512_38);
    should('accepts the RFC 9380 maximum ell=255 case', () => {
      const out = expand_message_xmd(new Uint8Array([1, 2, 3]), new Uint8Array([4]), 8160, sha256);
      eql(out.length, 8160);
    });
  });
  describe('expand_message_xof', () => {
    testExpandXOF(shake128, xof_shake128_36);
    testExpandXOF(shake128, xof_shake128_256);
    testExpandXOF(shake256, xof_shake256_36);
  });
  testCurve(nist.p256_hasher, p256_ro, p256_nu);
  testCurve(nist.p384_hasher, p384_ro, p384_nu);
  testCurve(nist.p521_hasher, p521_ro, p521_nu);
  testCurve(bls12_381.G1, g1_ro, g1_nu);
  testCurve(bls12_381.G2, g2_ro, g2_nu);
  testCurve(secp256k1_hasher, secp256k1_ro, secp256k1_nu);
  testCurve(ed25519_hasher, ed25519_ro, ed25519_nu);
  testCurve(ed448_hasher, ed448_ro, ed448_nu);

  should('hash_to_field rejects zero count and zero extension degree', () => {
    const msg = new Uint8Array([1, 2, 3]);
    const opts = { DST: 'DST', p: 17n, m: 1, k: 128, expand: 'xmd' as const, hash: sha256 };
    throws(() => hash_to_field(msg, 0, opts));
    throws(() => hash_to_field(msg, 1, { ...opts, m: 0 }));
  });
});

should('simple SWU rejects invalid RFC 9380 parameters', () => {
  const Fp = Field(13n);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 0n, B: 1n, Z: 6n }), /invalid/i);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 1n, B: 0n, Z: 6n }), /invalid/i);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 1n, B: 1n, Z: 12n }), /invalid/i);
  throws(() => mapToCurveSimpleSWU(Fp, { A: 1n, B: 1n, Z: 4n }), /invalid/i);

  const Fp5 = Field(5n);
  // RFC 9380 Appendix H.2 criterion 4: g(B / (Z * A)) must be square in F.
  throws(() => mapToCurveSimpleSWU(Fp5, { A: 2n, B: 1n, Z: 2n }), /invalid/i);
});

should('sqrt_ratio treats zero numerator as square only for non-zero denominators', () => {
  const Fp13 = Field(13n);
  eql(SWUFpSqrtRatio(Fp13, 2n)(0n, 1n), { isValid: true, value: 0n });
  eql(SWUFpSqrtRatio(Fp13, 2n)(0n, 0n), { isValid: false, value: 0n });
  const Fp11 = Field(11n);
  eql(SWUFpSqrtRatio(Fp11, 2n)(0n, 1n), { isValid: true, value: 0n });
  eql(SWUFpSqrtRatio(Fp11, 2n)(0n, 0n), { isValid: false, value: 0n });
});
should('SWUFpSqrtRatio validates malformed field objects before using them', () => {
  throws(
    () => SWUFpSqrtRatio({ ORDER: 11n } as any, 2n),
    /param "BYTES" is invalid: expected own property/
  );
});

should.runWhen(import.meta.url);
