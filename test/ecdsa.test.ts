import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import {
  kt128,
  kt256,
  parallelhash128,
  parallelhash256,
  turboshake128,
  turboshake256,
} from '@noble/hashes/sha3-addons.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { ecdh, ecdsa } from '../src/abstract/weierstrass.ts';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '../src/misc.ts';
import { p256, p384, p521 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { p192, p224 } from './_more-curves.helpers.ts';

const ECDSA = {
  P192: p192,
  P224: p224,
  P256: p256,
  P384: p384,
  P521: p521,
  secp256k1,
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
};

const HASHES = {
  sha224,
  sha256,
  sha384,
  sha512,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
  blake2b,
  blake2s,
  blake3,
  kt128,
  kt256,
  parallelhash128,
  parallelhash256,
  turboshake128,
  turboshake256,
};

const cleanObj = (o) => {
  const res = {};
  for (const k in o) {
    if (o[k] !== undefined) res[k] = o[k];
  }
  return res;
};

const testSig = (C, opts = {}) => {
  /*
  sign: (msgHash: Uint8Array, secretKey: Uint8Array, opts?: SignOpts) => Uint8Array;
  verify: (
    signature: Uint8Array,
    msgHash: Uint8Array,
    publicKey: Uint8Array,
    opts?: VerOpts
  ) => boolean;
  recoverPublicKey(signature: Uint8Array, msgHash: Uint8Array): Uint8Array;
          */

  const alice = C.keygen();
  const bob = C.keygen();
  const msg = randomBytes(10);

  const aliceSig = C.sign(msg, alice.secretKey, opts);
  const bobSig = C.sign(msg, bob.secretKey, opts);

  eql(C.verify(aliceSig, msg, alice.publicKey, opts), true);
  eql(C.verify(bobSig, msg, alice.publicKey, opts), false);

  eql(C.verify(aliceSig, msg, bob.publicKey, opts), false);
  eql(C.verify(bobSig, msg, bob.publicKey, opts), true);
  if (opts.format === 'recovered') {
    eql(C.recoverPublicKey(aliceSig, msg, opts), alice.publicKey);
    eql(C.recoverPublicKey(bobSig, msg, opts), bob.publicKey);
  } else {
    throws(() => C.recoverPublicKey(aliceSig, msg, opts));
    throws(() => C.recoverPublicKey(bobSig, msg, opts));
  }
};

describe('ECDSA', () => {
  for (const name in ECDSA) {
    const C = ECDSA[name];
    describe(name, () => {
      should('opts', () => {
        // pretty slow, but tests if some combination don't work together.
        for (const format of ['compact', 'recovered', 'der', undefined]) {
          for (const prehash of [true, false, undefined]) {
            for (const lowS of [true, false, undefined]) {
              testSig(C, { format, prehash, lowS });
              if (format === undefined || prehash === undefined || lowS === undefined) {
                testSig(C, cleanObj({ format, prehash, lowS }));
              }
            }
          }
        }
      });
      should('extraEntropy', () => {
        // would be nice to test inside 'opts', but it is too slow :(
        for (const extraEntropy of [true, false, undefined, randomBytes(9), randomBytes(32)]) {
          testSig(C, { extraEntropy });
          if (extraEntropy === undefined) {
            testSig(C, cleanObj({ extraEntropy }));
          }
        }
      });
      should('ECDH', () => {
        const alice = C.keygen();
        const bob = C.keygen();
        const aliceShared = C.getSharedSecret(alice.secretKey, bob.publicKey);
        const bobShared = C.getSharedSecret(bob.secretKey, alice.publicKey);
        eql(aliceShared, bobShared);
        const DH = ecdh(C.Point);
        eql(aliceShared, DH.getSharedSecret(alice.secretKey, bob.publicKey));
        eql(bobShared, DH.getSharedSecret(bob.secretKey, alice.publicKey));
      });
      // Test re-definition: verify that it  works with various hashes
      should('Hashes', () => {
        for (const h in HASHES) {
          const hash = HASHES[h];
          const CH = ecdsa(C.Point, hash);
          testSig(CH);
        }
      });
      // Re-definition with different opts
      should('curve opts', () => {
        for (const lowS of [true, false, undefined]) {
          const CO = ecdsa(C.Point, C.hash, { lowS });
          testSig(CO);
        }
      });
    });
  }
});

should.runWhen(import.meta.url);
