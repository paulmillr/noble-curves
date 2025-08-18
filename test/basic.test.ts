import { sha256 } from '@noble/hashes/sha2.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual, throws } from 'node:assert';
import { Field } from '../src/abstract/modular.ts';
import { ecdsa, weierstrass } from '../src/abstract/weierstrass.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { bn254 } from '../src/bn254.ts';
import { ed25519, x25519 } from '../src/ed25519.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { json } from './utils.ts';
const wyche_curves = json('./vectors/wycheproof/ec_prime_order_curves_test.json');

describe('edge cases', () => {
  should('bigInt private keys', () => {
    // Doesn't support bigints anymore
    throws(() => ed25519.sign(Uint8Array.of(), 123n));
    throws(() => ed25519.getPublicKey(123n));
    throws(() => x25519.getPublicKey(123n));
    // Weierstrass still supports
    throws(() => secp256k1.getPublicKey(123n));
    throws(() => secp256k1.sign(Uint8Array.of(), 123n));
  });
});

describe('createCurve', () => {
  describe('handles wycheproof vectors', () => {
    const VECTORS = wyche_curves.testGroups[0].tests;
    for (const v of VECTORS) {
      should(`${v.name}`, () => {
        const CURVE = ecdsa(
          weierstrass({
            p: BigInt(`0x${v.p}`),
            a: BigInt(`0x${v.a}`),
            b: BigInt(`0x${v.b}`),
            n: BigInt(`0x${v.n}`),
            h: BigInt(v.h),
            Gx: BigInt(`0x${v.gx}`),
            Gy: BigInt(`0x${v.gy}`),
          }),
          sha256
        );
      });
      // const CURVE = CURVES[v.name];
      // if (!CURVE) continue;
      // should(`${v.name} parms verify`, () => {
      //   eql(CURVE.CURVE.Fp.ORDER, BigInt(`0x${v.p}`));
      //   eql(CURVE.CURVE.a, BigInt(`0x${v.a}`));
      //   eql(CURVE.CURVE.b, BigInt(`0x${v.b}`));
      //   eql(CURVE.CURVE.n, BigInt(`0x${v.n}`));
      //   eql(CURVE.CURVE.Gx, BigInt(`0x${v.gx}`));
      //   eql(CURVE.CURVE.Gy, BigInt(`0x${v.gy}`));
      //   eql(CURVE.CURVE.h, BigInt(v.h));
      // });
    }
  });

  should('validates generator is on-curve', () => {
    throws(() =>
      createCurve(
        {
          Fp: Field(BigInt(`0x00c302f41d932a36cda7a3463093d18db78fce476de1a86297`)),
          a: BigInt(`0x00c302f41d932a36cda7a3463093d18db78fce476de1a86294`),
          b: BigInt(`0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79`),
          n: BigInt(`0x00c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1`),
          h: BigInt(1),
          Gx: BigInt(`0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129`),
          Gy: BigInt(`0x097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c8`), // last 9 -> 8
        },
        sha256
      )
    );
  });
});

describe('Pairings', () => {
  const pairingCurves = { bls12_381, bn254 };

  for (const [name, curve] of Object.entries(pairingCurves)) {
    describe(name, () => {
      const { pairing } = curve;
      const { Fp12 } = curve.fields;
      const G1Point = curve.G1.Point;
      const G2Point = curve.G2.Point;
      const CURVE_ORDER = curve.ORDER;
      const G1 = G1Point.BASE;
      const G2 = G2Point.BASE;

      should('creates negative G1 pairing', () => {
        const p1 = pairing(G1, G2);
        const p2 = pairing(G1.negate(), G2);
        eql(Fp12.mul(p1, p2), Fp12.ONE);
      });
      should('creates negative G2 pairing', () => {
        const p2 = pairing(G1.negate(), G2);
        const p3 = pairing(G1, G2.negate());
        eql(p2, p3);
      });
      should('creates proper pairing output order', () => {
        const p1 = pairing(G1, G2);
        const p2 = Fp12.pow(p1, CURVE_ORDER);
        eql(p2, Fp12.ONE);
      });
      should('G1 billinearity', () => {
        const p1 = pairing(G1, G2);
        const p2 = pairing(G1.multiply(2n), G2);
        eql(Fp12.mul(p1, p1), p2);
      });
      should('should not degenerate', () => {
        const p1 = pairing(G1, G2);
        const p2 = pairing(G1.multiply(2n), G2);
        const p3 = pairing(G1, G2.negate());
        notDeepStrictEqual(p1, p2);
        notDeepStrictEqual(p1, p3);
        notDeepStrictEqual(p2, p3);
      });
      should('G2 billinearity', () => {
        const p1 = pairing(G1, G2);
        const p2 = pairing(G1, G2.multiply(2n));
        eql(Fp12.mul(p1, p1), p2);
      });
      should('proper pairing composite check', () => {
        const p1 = pairing(G1.multiply(37n), G2.multiply(27n));
        const p2 = pairing(G1.multiply(999n), G2);
        eql(p1, p2);
      });
    });
  }
});

should.runWhen(import.meta.url);
