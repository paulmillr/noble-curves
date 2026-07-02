import { sha256 } from '@noble/hashes/sha2.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual, throws } from 'node:assert';
import { edwards } from '../src/abstract/edwards.ts';
import { montgomery } from '../src/abstract/montgomery.ts';
import { Field } from '../src/abstract/modular.ts';
import { normalizeZ, wNAF } from '../src/abstract/curve.ts';
import { __TEST as towerTest, tower12 } from '../src/abstract/tower.ts';
import { ecdsa, weierstrass } from '../src/abstract/weierstrass.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { bn254 } from '../src/bn254.ts';
import { ed25519, x25519 } from '../src/ed25519.ts';
import { p256 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { json } from './utils.ts';

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
    const vectorNames = [
      'secp224r1',
      'secp256r1',
      'secp384r1',
      'secp521r1',
      'secp256k1',
      'secp224k1',
      'brainpoolP224r1',
      'brainpoolP256r1',
      'brainpoolP320r1',
      'brainpoolP384r1',
      'brainpoolP512r1',
      'brainpoolP224t1',
      'brainpoolP256t1',
      'brainpoolP320t1',
      'brainpoolP384t1',
      'brainpoolP512t1',
      'FRP256v1',
      'secp192k1',
      'secp192r1',
      'secp160k1',
      'secp160r1',
      'secp160r2',
      'brainpoolP160r1',
      'brainpoolP160t1',
      'brainpoolP192r1',
      'brainpoolP192t1',
    ];
    for (const name of vectorNames) {
      should(name, () => {
        const wyche_curves = json('./vectors/wycheproof/ec_prime_order_curves_test.json');
        const v = wyche_curves.testGroups[0].tests.find((v) => v.name === name);
        if (!v) throw new Error('missing curve vector: ' + name);
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

  should('constructs valid tiny curve helpers without forcing default precomputes', () => {
    const WPoint = weierstrass({ p: 5n, n: 19n, h: 1n, a: 0n, b: 1n, Gx: 0n, Gy: 1n });
    eql(WPoint.BASE.toHex(false), '040001');
    const EPoint = edwards({ a: 1n, d: 2n, p: 5n, n: 8n, h: 1n, Gx: 2n, Gy: 2n });
    eql(EPoint.BASE.toAffine(), { x: 2n, y: 2n });
  });

  should('keeps public precomputed weierstrass multiplication deterministic without RNG', () => {
    const Point = weierstrass(p256.Point.CURVE(), {
      Fp: p256.Point.Fp,
      Fn: p256.Point.Fn,
      randomBytes: () => {
        throw new Error('rng used');
      },
    });
    eql(Point.BASE.multiplyUnsafe(2n).equals(Point.BASE.double()), true);
    throws(() => Point.BASE.multiply(2n), /rng used/);
  });

  should('rebuilds blinded precomputes after cross-instance window changes', () => {
    const randomBytes = (len = 0) => new Uint8Array(len).fill(7);
    const Point = weierstrass(p256.Point.CURVE(), {
      Fp: p256.Point.Fp,
      Fn: p256.Point.Fn,
      randomBytes,
    });
    const P = Point.BASE;
    const norm = (points: (typeof P)[]) => normalizeZ(Point, points);
    const a = new wNAF(Point, randomBytes);
    const b = new wNAF(Point, randomBytes);
    a.createCache(P, 8);
    const r1 = a.cachedBlinded(P, 123n, norm).p;
    b.createCache(P, 4);
    const r2 = a.cachedBlinded(P, 123n, norm).p;
    eql(r2.equals(r1), true);
  });

  should('uses W=6 wNAF precomputes for blinded multiplication', () => {
    const randomBytes = (len = 0) => new Uint8Array(len).fill(9);
    const Point = weierstrass(p256.Point.CURVE(), {
      Fp: p256.Point.Fp,
      Fn: p256.Point.Fn,
      randomBytes,
    });
    const P = Point.BASE.precompute(6, false);
    for (const scalar of [1n, 2n, 3n, 123456789n, Point.Fn.ORDER - 1n]) {
      eql(P.multiply(scalar).equals(P.multiplyUnsafe(scalar)), true);
    }
  });

  should('uses unblinded multiply for cofactored weierstrass BASE when n*BASE is nonzero', () => {
    const Point = weierstrass(
      { p: 5n, n: 19n, h: 2n, a: 0n, b: 1n, Gx: 0n, Gy: 1n },
      {
        randomBytes: () => {
          throw new Error('rng used');
        },
      }
    );
    eql(Point.BASE.multiply(2n).equals(Point.BASE.multiplyUnsafe(2n)), true);
  });

  should('mulAddUnsafe matches multiplyUnsafe composition (with and without endo)', () => {
    for (const curve of [secp256k1, p256]) {
      const { Point } = curve;
      const G = Point.BASE;
      const n = Point.Fn.ORDER;
      const Q = G.multiply(123456789n);
      const cases: [bigint, bigint][] = [
        [1n, 1n],
        [0n, 5n],
        [7n, 0n],
        [0n, 0n],
        [n - 1n, n - 1n],
        [n >> 1n, (n >> 1n) + 3n],
        [0xdeadbeefn, 0xc0ffeen],
      ];
      for (const [a, b] of cases) {
        const want = G.multiplyUnsafe(a).add(Q.multiplyUnsafe(b));
        eql(G.mulAddUnsafe(a, Q, b).equals(want), true, `a=${a} b=${b}`);
      }
      throws(() => G.mulAddUnsafe(-1n, Q, 1n));
      throws(() => G.mulAddUnsafe(n, Q, 1n));
    }
  });

  should('checks cofactored edwards BASE order before blinding', () => {
    const randomBytes = () => {
      throw new Error('rng used');
    };
    const Good = edwards(ed25519.Point.CURVE(), { randomBytes });
    throws(() => Good.BASE.multiply(2n), /rng used/);

    const curve = ed25519.Point.CURVE();
    const Bad = edwards({ ...curve, Gx: 0n, Gy: curve.p - 1n }, { randomBytes });
    eql(Bad.BASE.multiply(2n).equals(Bad.ZERO), true);
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

  should('small constructor edge cases', () => {
    const Point = weierstrass(
      { p: 5n, n: 257n, h: 1n, a: 0n, b: 1n, Gx: 0n, Gy: 1n },
      { allowInfinityPoint: true }
    );
    throws(() => new Point(1n, 1n, 0n).assertValidity(), /ZERO|infinity|point/i);

    const torsionPoint = weierstrass(
      { p: 5n, n: 65535n, h: 2n, a: 0n, b: 1n, Gx: 0n, Gy: 1n },
      { endo: { beta: 1n, basises: [[1n, 0n, 0n, 1n]] } }
    );
    eql(typeof torsionPoint.BASE.isTorsionFree(), 'boolean', 'torsion fallback');

    const endoPoint = weierstrass(
      { p: 5n, n: 257n, h: 1n, a: 0n, b: 1n, Gx: 0n, Gy: 1n },
      { endo: { beta: 1n, basises: [[1n, 0n, 0n, 1n]] } }
    );
    eql(endoPoint.BASE.toAffine(), { x: 0n, y: 1n }, 'small endo base');
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

      should('pairing algebra properties', () => {
        const p1 = pairing(G1, G2);
        const p2 = pairing(G1.negate(), G2);
        eql(Fp12.mul(p1, p2), Fp12.ONE, 'negative G1');

        const p3 = pairing(G1, G2.negate());
        eql(p2, p3, 'negative G2');

        eql(Fp12.pow(p1, CURVE_ORDER), Fp12.ONE, 'output order');

        const g1Double = pairing(G1.multiply(2n), G2);
        eql(Fp12.mul(p1, p1), g1Double, 'G1 bilinearity');

        notDeepStrictEqual(p1, p2);
        notDeepStrictEqual(p1, p3, 'nondegenerate negative');
        notDeepStrictEqual(g1Double, p3, 'nondegenerate double');

        const g2Double = pairing(G1, G2.multiply(2n));
        eql(Fp12.mul(p1, p1), g2Double, 'G2 bilinearity');

        const composite = pairing(G1.multiply(37n), G2.multiply(27n));
        const scalar = pairing(G1.multiply(999n), G2);
        eql(composite, scalar, 'composite check');
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

  should('calcFrobeniusCoefficients rejects invalid parameters', () => {
    throws(() => towerTest.calcFrobeniusCoefficients(Field(19n), 3n, 19n, 6, 1, 4));

    const Fp = Field(19n);
    throws(() => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19n, 6, 0, 3));
    throws(() => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19n, 6, 1.5, 3));
    throws(
      () => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19 as never, 6, 1, 3),
      /calcFrobeniusCoefficients:.*modulus/
    );
    throws(
      () => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19n, 0, 1, 3),
      /calcFrobeniusCoefficients:.*degree/
    );
    throws(
      () => towerTest.calcFrobeniusCoefficients(Fp, 3n, 19n, 6, 1, 0),
      /calcFrobeniusCoefficients:.*divisor/
    );
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
