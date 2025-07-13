import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { mod } from '../esm/abstract/modular.js';
import { ed25519, x25519 } from '../esm/ed25519.js';
import { bytesToNumberLE, concatBytes, ensureBytes, equalBytes, numberToBytesLE } from '../esm/utils.js';

/*
Half-broken implementation of Hedged EdDSA / XEdDSA.
Differences from EDDSA:
- uses curve25519 keys instead of ed25519
- additional random added to nonce on signing
- there is zero reasons to use this, if you don't want to re-use x25519 key
- nobody supports, no test vectors, a few half-broken implementations
- signal uses for signing ephemeral public for x25519, which is probably only reasonable use case for this.
*/
const XEDDSA25519_PREFIX = new Uint8Array([
  0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);
const { Fp } = ed25519.Point;
export function montgomeryToEdwards(
  mont: Uint8Array,
  sign: boolean
): typeof ed25519.Point.BASE {
  const u = Fp.fromBytes(mont);
  if (Fp.eql(u, Fp.neg(Fp.ONE))) throw new Error('u=-1');
  const y = Fp.mul(Fp.sub(u, Fp.ONE), Fp.inv(Fp.add(u, Fp.ONE)));
  const yBytes = numberToBytesLE(y, 32);
  yBytes[31] ^= (sign ? 1 : 0) << 7;
  return ed25519.Point.fromBytes(yBytes);
}

export const xeddsa25519 = {
  sign(secret: Uint8Array, message: Uint8Array, random: Uint8Array = randomBytes(64)): Uint8Array {
    secret = ensureBytes('secret', secret, 32);
    const N = ed25519.CURVE.n;
    const a = mod(bytesToNumberLE(secret), N); // Interpret secret as scalar a.
    const A = ed25519.Point.BASE.multiply(a); // Compute public key A = a·B.
    const Abytes = A.toBytes();
    const signBit = Abytes[31] & 0x80; // Extract sign bit (top bit of last byte)
    const rHash = sha512
      .create()
      .update(XEDDSA25519_PREFIX)
      .update(secret)
      .update(message)
      .update(random)
      .digest(); // r = SHA512( HASH_PREFIX || secret || ...messages || randomBytes ) mod L.
    const r = mod(bytesToNumberLE(rHash), N);
    const Rpoint = ed25519.Point.BASE.multiply(r); // R = r·B.
    const Rbytes = Rpoint.toBytes();
    const hHash = sha512.create().update(Rbytes).update(Abytes).update(message).digest(); // h = SHA512( R || A || ...messages ) mod n.
    const h = mod(bytesToNumberLE(hHash), N);
    const s = mod(h * a + r, N); // s = (h·a + r) mod n.
    const Sbytes = numberToBytesLE(s, 32);
    const sig = concatBytes(Rbytes, Sbytes);
    sig[63] = (sig[63] & 0b0111_1111) | signBit;
    return sig;
  },
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    publicKey = ensureBytes('publicKey', publicKey, 32);
    signature = ensureBytes('signature', signature, 64);
    const N = ed25519.CURVE.n;
    const signBit = (signature[63] & 0b1000_0000) >> 7 === 1; // Extract sign bit from signature last byte.
    const Aed = montgomeryToEdwards(publicKey, signBit);
    const Abytes = Aed.toBytes();
    const capR = signature.slice(0, 32);
    const sBytes = signature.slice(32, 64);
    sBytes[31] &= 0b0111_1111; // masking top bit
    if ((sBytes[31] & 0b1110_0000) !== 0) return false;
    const s = mod(bytesToNumberLE(sBytes), N);
    // h = SHA512( cap_r || A_bytes || ...messages ) mod n.
    const hash = sha512.create().update(capR).update(Abytes).update(message).digest();
    const h = mod(bytesToNumberLE(hash), N);
    // Rcheck = [s]B - [h]A.
    const Rcheck = ed25519.Point.BASE.multiply(s).add(Aed.negate().multiply(h));
    const capRcheck = Rcheck.toBytes();
    return equalBytes(capRcheck, capR);
  },
};

describe('xeddsa25519', () => {
  should('signatures', () => {
    const alicePrivate = new Uint8Array([
      0xc0, 0x97, 0x24, 0x84, 0x12, 0xe5, 0x8b, 0xf0, 0x5d, 0xf4, 0x87, 0x96, 0x82, 0x05, 0x13,
      0x27, 0x94, 0x17, 0x8e, 0x36, 0x76, 0x37, 0xf5, 0x81, 0x8f, 0x81, 0xe0, 0xe6, 0xce, 0x73,
      0xe8, 0x65,
    ]);
    const alicePublic = new Uint8Array([
      0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d, 0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9, 0xdc,
      0xf8, 0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35, 0x6b, 0xe8, 0x4d, 0x88, 0x7e, 0x32,
      0x2c, 0x64,
    ]);
    const message = new Uint8Array([
      0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7, 0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2, 0xc4,
      0xa5, 0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d, 0x50, 0x31, 0x18, 0xd1, 0xa8, 0x2d,
      0x99, 0xfb, 0x4a,
    ]);
    const aliceSignature = new Uint8Array([
      0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11, 0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c, 0x9c,
      0x74, 0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb, 0x8c, 0x63, 0xc2, 0x98, 0x4e, 0x28,
      0x6d, 0xfb, 0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae, 0x0b, 0xfb, 0xb8, 0x21, 0x56,
      0x9b, 0x3d, 0x90, 0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86, 0xce, 0xf0, 0x47, 0xbd,
      0x60, 0xb8, 0x6e, 0x88,
    ]);
    deepStrictEqual(x25519.getPublicKey(alicePrivate), alicePublic);
    deepStrictEqual(xeddsa25519.verify(alicePublic, message, aliceSignature), true);
    for (let i = 0; i < aliceSignature.length; i++) {
      const copy = aliceSignature.slice();
      copy[i] ^= 0x01;
      deepStrictEqual(xeddsa25519.verify(alicePublic, message, copy), false);
    }
    const zeroSignature = new Uint8Array([
      220, 159, 25, 158, 17, 225, 126, 58, 4, 47, 234, 191, 66, 75, 186, 23, 69, 151, 134, 166, 105,
      48, 110, 213, 45, 62, 140, 235, 200, 11, 98, 70, 114, 170, 216, 146, 18, 198, 125, 71, 136,
      129, 223, 253, 240, 235, 84, 59, 153, 38, 93, 215, 204, 89, 95, 175, 102, 11, 229, 210, 124,
      90, 72, 135,
    ]);
    deepStrictEqual(xeddsa25519.sign(alicePrivate, message, new Uint8Array(64)), zeroSignature);
    deepStrictEqual(xeddsa25519.verify(alicePublic, message, zeroSignature), true);
  });
  should('random signatures', () => {
    for (let i = 0; i < 50; i++) {
      const msg = randomBytes(64);
      // x25519 can generate invalid U
      const secret = ed25519.utils.toMontgomeryPriv(ed25519.utils.randomPrivateKey());
      const pub = x25519.getPublicKey(secret);
      const signature = xeddsa25519.sign(secret, msg);
      deepStrictEqual(xeddsa25519.verify(pub, msg, signature), true);
    }
  });
});

should.runWhen(import.meta.url);
