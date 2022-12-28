import { deepStrictEqual } from 'assert';
import { should } from 'micro-should';
import { bytesToHex } from '@noble/hashes/utils';
// Generic tests for all curves in package
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { secp256r1 } from '../lib/p256.js';
import { secp384r1 } from '../lib/p384.js';
import { secp521r1 } from '../lib/p521.js';
import { secp256k1 } from '../lib/secp256k1.js';
import { bls12_381 } from '../lib/bls12-381.js';
import { ed25519 } from '../lib/ed25519.js';
import { ed448 } from '../lib/ed448.js';
import { stringToBytes, expand_message_xmd } from '@noble/curves/hashToCurve';

import { default as xmd_sha256_38 } from './hashToCurve/expand_message_xmd_SHA256_38.json' assert { type: 'json' };
import { default as xmd_sha256_256 } from './hashToCurve/expand_message_xmd_SHA256_256.json' assert { type: 'json' };
import { default as xmd_sha512_38 } from './hashToCurve/expand_message_xmd_SHA512_38.json' assert { type: 'json' };
// P256
import { default as p256_ro } from './hashToCurve/P256_XMD:SHA-256_SSWU_RO_.json' assert { type: 'json' };
import { default as p256_nu } from './hashToCurve/P256_XMD:SHA-256_SSWU_NU_.json' assert { type: 'json' };
// P384
import { default as p384_ro } from './hashToCurve/P384_XMD:SHA-384_SSWU_RO_.json' assert { type: 'json' };
import { default as p384_nu } from './hashToCurve/P384_XMD:SHA-384_SSWU_NU_.json' assert { type: 'json' };
// P521
import { default as p521_ro } from './hashToCurve/P521_XMD:SHA-512_SSWU_RO_.json' assert { type: 'json' };
import { default as p521_nu } from './hashToCurve/P521_XMD:SHA-512_SSWU_NU_.json' assert { type: 'json' };
// secp256k1
import { default as secp256k1_ro } from './hashToCurve/secp256k1_XMD:SHA-256_SSWU_RO_.json' assert { type: 'json' };
import { default as secp256k1_nu } from './hashToCurve/secp256k1_XMD:SHA-256_SSWU_NU_.json' assert { type: 'json' };
// bls-G1
import { default as g1_ro } from './hashToCurve/BLS12381G1_XMD:SHA-256_SSWU_RO_.json' assert { type: 'json' };
import { default as g1_nu } from './hashToCurve/BLS12381G1_XMD:SHA-256_SSWU_NU_.json' assert { type: 'json' };
// bls-G2
import { default as g2_ro } from './hashToCurve/BLS12381G2_XMD:SHA-256_SSWU_RO_.json' assert { type: 'json' };
import { default as g2_nu } from './hashToCurve/BLS12381G2_XMD:SHA-256_SSWU_NU_.json' assert { type: 'json' };
// ed25519
import { default as ed25519_ro } from './hashToCurve/edwards25519_XMD:SHA-512_ELL2_RO_.json' assert { type: 'json' };
import { default as ed25519_nu } from './hashToCurve/edwards25519_XMD:SHA-512_ELL2_NU_.json' assert { type: 'json' };
// ed448
import { default as ed448_ro } from './hashToCurve/edwards448_XOF:SHAKE256_ELL2_RO_.json' assert { type: 'json' };
import { default as ed448_nu } from './hashToCurve/edwards448_XOF:SHAKE256_ELL2_NU_.json' assert { type: 'json' };

function testExpandXMD(hash, vectors) {
  for (let i = 0; i < vectors.tests.length; i++) {
    const t = vectors.tests[i];
    should(`expand_message_xmd/${vectors.hash}/${vectors.DST.length}/${i}`, () => {
      const p = expand_message_xmd(
        stringToBytes(t.msg),
        stringToBytes(vectors.DST),
        t.len_in_bytes,
        hash
      );
      deepStrictEqual(bytesToHex(p), t.uniform_bytes);
    });
  }
}

testExpandXMD(sha256, xmd_sha256_38);
testExpandXMD(sha256, xmd_sha256_256);
testExpandXMD(sha512, xmd_sha512_38);

function stringToFp(s) {
  // bls-G2 support
  if (s.includes(',')) {
    const [c0, c1] = s.split(',').map(BigInt);
    return { c0, c1 };
  }
  return BigInt(s);
}

function testCurve(curve, ro, nu) {
  for (let i = 0; i < ro.vectors.length; i++) {
    const t = ro.vectors[i];
    should(`${ro.curve}/${ro.ciphersuite}(${i})`, () => {
      const p = curve.Point.hashToCurve(stringToBytes(t.msg), {
        DST: ro.dst,
      });
      deepStrictEqual(p.x, stringToFp(t.P.x), 'Px');
      deepStrictEqual(p.y, stringToFp(t.P.y), 'Py');
    });
  }
  for (let i = 0; i < nu.vectors.length; i++) {
    const t = nu.vectors[i];
    should(`${nu.curve}/${nu.ciphersuite}(${i})`, () => {
      const p = curve.Point.encodeToCurve(stringToBytes(t.msg), {
        DST: nu.dst,
      });
      deepStrictEqual(p.x, stringToFp(t.P.x), 'Px');
      deepStrictEqual(p.y, stringToFp(t.P.y), 'Py');
    });
  }
}

testCurve(secp256r1, p256_ro, p256_nu);
testCurve(secp384r1, p384_ro, p384_nu);
testCurve(secp521r1, p521_ro, p521_nu);
// TODO: remove same tests from bls12
testCurve(bls12_381.G1, g1_ro, g1_nu);
testCurve(bls12_381.G2, g2_ro, g2_nu);
testCurve(secp256k1, secp256k1_ro, secp256k1_nu);
//testCurve(ed25519, ed25519_ro, ed25519_nu);
//testCurve(ed448, ed448_ro, ed448_nu);

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
