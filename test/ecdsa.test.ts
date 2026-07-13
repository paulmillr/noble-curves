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
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { ecdh, ecdsa, weierstrass } from '../src/abstract/weierstrass.ts';
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
      should('signing options, ECDH, hashes, and curve opts', () => {
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

        // would be nice to test inside 'opts', but it is too slow :(
        for (const extraEntropy of [true, false, undefined, randomBytes(9), randomBytes(32)]) {
          testSig(C, { extraEntropy });
          if (extraEntropy === undefined) {
            testSig(C, cleanObj({ extraEntropy }));
          }
        }

        const alice = C.keygen();
        const bob = C.keygen();
        const aliceShared = C.getSharedSecret(alice.secretKey, bob.publicKey);
        const bobShared = C.getSharedSecret(bob.secretKey, alice.publicKey);
        eql(aliceShared, bobShared);
        const DH = ecdh(C.Point);
        eql(aliceShared, DH.getSharedSecret(alice.secretKey, bob.publicKey));
        eql(bobShared, DH.getSharedSecret(bob.secretKey, alice.publicKey));

        // Test re-definition: verify that it  works with various hashes
        for (const h in HASHES) {
          const hash = HASHES[h];
          const CH = ecdsa(C.Point, hash);
          testSig(CH);
        }

        // Re-definition with different opts
        for (const lowS of [true, false, undefined]) {
          const CO = ecdsa(C.Point, C.hash, { lowS });
          testSig(CO);
        }
      });
    });
  }

  should('verify() binds recovered signatures to their recovery id', () => {
    const msg = Uint8Array.from({ length: 32 }, (_, i) => i);
    const secretKey = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const publicKey = p256.getPublicKey(secretKey);
    const sig = p256.sign(msg, secretKey, { prehash: false, format: 'recovered' });
    const compact = sig.slice(1);
    const der = p256.Signature.fromBytes(sig, 'recovered').toBytes('der');

    eql(p256.verify(sig, msg, publicKey, { prehash: false, format: 'recovered' }), true);
    eql(p256.verify(compact, msg, publicKey, { prehash: false, format: 'compact' }), true);
    eql(p256.verify(der, msg, publicKey, { prehash: false, format: 'der' }), true);

    const wrongRecovery = sig.slice();
    wrongRecovery[0] ^= 1;
    eql(p256.verify(wrongRecovery, msg, publicKey, { prehash: false, format: 'recovered' }), false);
  });
});

describe('weierstrass ECDH', () => {
  const makeDh = () =>
    ecdh(weierstrass({ p: 17n, n: 257n, h: 1n, a: 2n, b: 2n, Gx: 5n, Gy: 1n }), {
      randomBytes: (len = 0) => new Uint8Array(len).fill(7),
    });

  should('argument-order guards and randomSecretKey lengths', () => {
    const alice = p521.utils.randomSecretKey();
    const bob = p521.utils.randomSecretKey();
    const alicePub = p521.getPublicKey(alice);
    const bobPub = p521.getPublicKey(bob);
    throws(() => p521.getSharedSecret(alicePub, bobPub), /first arg must be private key/);
    throws(() => p521.getSharedSecret(alicePub, bob), /first arg must be private key/);
    throws(() => p521.getSharedSecret(alice, bob), /second arg must be public key/);

    const dh = makeDh();
    const seed = new Uint8Array(dh.lengths.seed).fill(7);
    const secretKey = dh.utils.randomSecretKey(seed);
    eql(secretKey.length, dh.lengths.secretKey);
    eql(dh.utils.isValidSecretKey(secretKey), true);

    const randomSecretKey = dh.utils.randomSecretKey();
    eql(randomSecretKey.length, dh.lengths.secretKey);
    eql(dh.utils.isValidSecretKey(randomSecretKey), true);
  });
});

describe('ECDSA nonce-blinding RNG probe', () => {
  const msg = new Uint8Array(32).fill(1);

  should('RNG broken at construction downgrades to invertCt; signatures value-identical', () => {
    const keys = p256.keygen();
    const want = p256.sign(msg, keys.secretKey); // RFC 6979 deterministic, blinded path
    const throwingRng = () => {
      throw new Error('no entropy');
    };
    const nullRng = (() => null) as never as (len?: number) => Uint8Array;
    const shortRng = () => new Uint8Array(3);
    for (const rng of [throwingRng, nullRng, shortRng]) {
      // probe fails -> k2sig falls back to Fermat inversion; blinding is value-identical,
      // so the downgraded signature must match the blinded one bit-for-bit
      const C = ecdsa(p256.Point, sha256, { randomBytes: rng as never });
      eql(C.sign(msg, keys.secretKey), want, `downgraded sign matches (${rng.name})`);
      eql(C.verify(want, msg, keys.publicKey), true);
    }
  });

  should('rogue RNG misbehaving after a good probe makes sign() fail closed', () => {
    // A stateful RNG can always behave while probed and misbehave later; that case must
    // throw (per-call validation), never silently drop the nonce blinding.
    const keys = p256.keygen();
    let calls = 0;
    const rogue = ((len = 0) => {
      calls++;
      if (calls === 1) return randomBytes(len); // pass the probe
      return null; // garbage afterwards
    }) as never as (len?: number) => Uint8Array;
    const C = ecdsa(p256.Point, sha256, { randomBytes: rogue });
    throws(() => C.sign(msg, keys.secretKey));
    eql(calls >= 2, true, 'rogue RNG was actually consulted after the probe');
  });
});

should(
  'recovered-signature support is not rejected for a valid h=2 curve just because 2n < p',
  () => {
    const curve = ecdsa(
      weierstrass({
        p: 7n,
        a: 1n,
        b: 3n,
        n: 3n,
        h: 2n,
        Gx: 6n,
        Gy: 1n,
      }),
      sha256
    );
    const compact = Array.from(new curve.Signature(1n, 1n).toBytes());
    const recovered = (() => {
      try {
        return Array.from(new curve.Signature(1n, 1n).addRecoveryBit(0).toBytes('recovered'));
      } catch (error) {
        return `ERR:${(error as Error).message}`;
      }
    })();
    eql(compact, [1, 1]);
    eql(recovered, [0, 1, 1]);
  }
);

should('ECDSA option-bag APIs reject primitive opts values', () => {
  const msg = Uint8Array.from({ length: 32 }, (_, i) => i);
  for (const C of Object.values(ECDSA)) {
    const sk = C.utils.randomSecretKey();
    const pk = C.getPublicKey(sk);
    const sig = C.sign(msg, sk);
    const rec = C.sign(msg, sk, { format: 'recovered' });
    throws(() => C.sign(msg, sk, 1 as any));
    throws(() => C.verify(sig, msg, pk, 1 as any));
    throws(() => C.recoverPublicKey(rec, msg, 1 as any));
  }
});

should.runWhen(import.meta.url);
