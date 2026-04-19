import { sha256 } from '@noble/hashes/sha2.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual, throws } from 'node:assert';
import { edwards } from '../src/abstract/edwards.ts';
import { montgomery } from '../src/abstract/montgomery.ts';
import { Field } from '../src/abstract/modular.ts';
import { __TEST as towerTest, tower12 } from '../src/abstract/tower.ts';
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

  should('x25519 integer range rejects unclamped values above 8*(2^251-1)+2^254', () => {
    // RFC 7748: "the resulting integer is of the form 2^254 plus eight times a value
    // between 0 and 2^251 - 1 (inclusive)."
    // Integers 2^255 - 7 .. 2^255 - 1 must be rejected by the defense-in-depth range
    // check when a (hypothetical) buggy adjustScalarBytes returns them unclamped.
    const P = 2n ** 255n - 19n;
    const passthrough = montgomery({
      P,
      type: 'x25519',
      adjustScalarBytes: (bytes: Uint8Array) => bytes,
      powPminus2: (x: bigint) => x,
    });
    // 2^255 - 1 encoded little-endian as 32 bytes: 31 * 0xff, then 0x7f.
    const scalar = new Uint8Array(32).fill(0xff);
    scalar[31] = 0x7f;
    throws(() => passthrough.getPublicKey(scalar), /scalar/);
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

  should('constructs valid tiny curve helpers without forcing W=8 precomputes', () => {
    const WPoint = weierstrass({ p: 5n, n: 19n, h: 1n, a: 0n, b: 1n, Gx: 0n, Gy: 1n });
    eql(WPoint.BASE.toHex(false), '040001');
    const EPoint = edwards({ a: 1n, d: 2n, p: 5n, n: 8n, h: 1n, Gx: 2n, Gy: 2n });
    eql(EPoint.BASE.toAffine(), { x: 2n, y: 2n });
  });

  should('keeps edwards generator subgroup validation out of the constructor surface', () => {
    const Point = edwards({ ...ed25519.Point.CURVE(), Gx: 0n, Gy: 1n });
    eql(Point.BASE.toAffine(), { x: 0n, y: 1n });
    throws(() => Point.BASE.assertValidity(), /ZERO/);
  });

  should(
    'rejects invalid generator and config inputs without breaking valid constructor smoke cases',
    () => {
      const montgomeryBase = {
        adjustScalarBytes: (bytes: Uint8Array) => bytes,
        powPminus2: (x: bigint) => x,
      };

      throws(
        () => montgomery({ ...montgomeryBase, type: 'x25519' } as any),
        /param "P" is invalid/
      );
      throws(
        () => montgomery({ ...montgomeryBase, P: 17n, type: 'x25519', randomBytes: 1 } as any),
        /param "randomBytes" is invalid/
      );

      const Point = weierstrass({ p: 17n, n: 257n, h: 1n, a: 2n, b: 2n, Gx: 5n, Gy: 1n });
      eql(Point.BASE.toHex(false), '040501');
    }
  );

  should('allowInfinityPoint still rejects non-canonical projective infinity coordinates', () => {
    const Point = weierstrass(
      { p: 5n, n: 257n, h: 1n, a: 0n, b: 1n, Gx: 0n, Gy: 1n },
      { allowInfinityPoint: true }
    );
    throws(() => new Point(1n, 1n, 0n).assertValidity(), /ZERO|infinity|point/i);
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

describe('extension fields', () => {
  should('ORDER values match the tower degrees', () => {
    const { Fp: blsFp, Fp6: blsFp6, Fp12: blsFp12 } = bls12_381.fields;
    const { Fp: bnFp, Fp6: bnFp6, Fp12: bnFp12 } = bn254.fields;
    const { Fp, Fp2, Fp6, Fp12 } = tower12({
      ORDER: 19n,
      X_LEN: 4,
      FP2_NONRESIDUE: [1n, 1n],
      Fp2mulByB: (num) => num,
      Fp12finalExponentiate: (num) => num,
    });
    eql(
      {
        bls12_381: { Fp6: blsFp6.ORDER, Fp12: blsFp12.ORDER },
        bn254: { Fp6: bnFp6.ORDER, Fp12: bnFp12.ORDER },
        tower12: { Fp: Fp.ORDER, Fp2: Fp2.ORDER, Fp6: Fp6.ORDER, Fp12: Fp12.ORDER },
      },
      {
        bls12_381: { Fp6: blsFp.ORDER ** 6n, Fp12: blsFp.ORDER ** 12n },
        bn254: { Fp6: bnFp.ORDER ** 6n, Fp12: bnFp.ORDER ** 12n },
        tower12: { Fp: 19n, Fp2: 19n ** 2n, Fp6: 19n ** 6n, Fp12: 19n ** 12n },
      }
    );
  });

  should('calcFrobeniusCoefficients rejects inexact exponent divisions', () => {
    throws(() => towerTest.calcFrobeniusCoefficients(Field(19n), 3n, 19n, 6, 1, 4));
  });
  should('calcFrobeniusCoefficients rejects non-positive or fractional row counts', () => {
    const Fp = Field(19n);
    throws(() => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19n, 6, 0, 3));
    throws(() => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19n, 6, 1.5, 3));
  });

  should('bn254 tower values stay canonical and immutable', () => {
    const { Fp, Fp2, Fp6, Fp12 } = bn254.fields;
    eql(Fp2.create({ c0: Fp.ORDER, c1: -1n }), { c0: 0n, c1: Fp.ORDER - 1n });
    eql(Fp2.isValid({ c0: Fp.ORDER, c1: 0n }), false);
    eql(Fp2.isValid({ c0: 0n, c1: Fp.ORDER }), false);
    throws(() => {
      Fp2.ZERO.c0 = 1n;
    });
    eql(Fp2.ZERO, { c0: 0n, c1: 0n });

    eql(Fp6.create({ c0: { c0: Fp.ORDER, c1: -1n }, c1: Fp2.ZERO, c2: Fp2.ZERO }), {
      c0: { c0: 0n, c1: Fp.ORDER - 1n },
      c1: Fp2.ZERO,
      c2: Fp2.ZERO,
    });
    eql(Fp6.isValid({ c0: { c0: Fp.ORDER, c1: 0n }, c1: Fp2.ZERO, c2: Fp2.ZERO }), false);
    throws(() => {
      Fp6.ZERO.c0.c0 = 1n;
    });
    eql(Fp6.ZERO, {
      c0: { c0: 0n, c1: 0n },
      c1: { c0: 0n, c1: 0n },
      c2: { c0: 0n, c1: 0n },
    });

    eql(
      Fp12.create({
        c0: { c0: { c0: Fp.ORDER, c1: -1n }, c1: Fp2.ZERO, c2: Fp2.ZERO },
        c1: Fp6.ZERO,
      }),
      { c0: { c0: { c0: 0n, c1: Fp.ORDER - 1n }, c1: Fp2.ZERO, c2: Fp2.ZERO }, c1: Fp6.ZERO }
    );
    eql(
      Fp12.isValid({
        c0: { c0: { c0: Fp.ORDER, c1: 0n }, c1: Fp2.ZERO, c2: Fp2.ZERO },
        c1: Fp6.ZERO,
      }),
      false
    );
    const x = Fp12.fromBigTwelve([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n]);
    const y = Fp12.conjugate(x);
    throws(() => {
      y.c0.c0.c0 = 999n;
    });
    eql(x.c0.c0.c0, 1n);
    throws(() => {
      Fp12.ZERO.c0.c0.c0 = 1n;
    });
    eql(Fp12.ZERO, {
      c0: {
        c0: { c0: 0n, c1: 0n },
        c1: { c0: 0n, c1: 0n },
        c2: { c0: 0n, c1: 0n },
      },
      c1: {
        c0: { c0: 0n, c1: 0n },
        c1: { c0: 0n, c1: 0n },
        c2: { c0: 0n, c1: 0n },
      },
    });
  });

  should('tower tuple constructors and config reject sparse or invalid inputs eagerly', () => {
    const bad2 = [1n];
    bad2.length = 2;
    throws(() => bn254.fields.Fp2.fromBigTuple(bad2 as bigint[]));
    const bad6 = [1n];
    bad6.length = 6;
    throws(() => bn254.fields.Fp6.fromBigSix(bad6 as bigint[]));
    const bad12 = [1n];
    bad12.length = 12;
    throws(() => bn254.fields.Fp12.fromBigTwelve(bad12 as bigint[]));

    const sparse = [1n, 1n] as [bigint, bigint];
    delete sparse[1];
    throws(
      () =>
        tower12({
          ORDER: 19n,
          X_LEN: 4,
          FP2_NONRESIDUE: sparse,
          Fp2mulByB: (num) => num,
          Fp12finalExponentiate: (num) => num,
        }),
      /FP2_NONRESIDUE/
    );
    for (const X_LEN of [0, -1, 1.5, Number.NaN]) {
      throws(
        () =>
          tower12({
            ORDER: 19n,
            X_LEN,
            FP2_NONRESIDUE: [1n, 1n],
            Fp2mulByB: (num) => num,
            Fp12finalExponentiate: (num) => num,
          }),
        /X_LEN/
      );
    }
  });
});

should.runWhen(import.meta.url);
