import { sha256 } from '@noble/hashes/sha2.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual, throws } from 'node:assert';
import { edwards } from '../src/abstract/edwards.ts';
import { montgomery } from '../src/abstract/montgomery.ts';
import { Field } from '../src/abstract/modular.ts';
import { normalizeZ, ScalarMultiplier } from '../src/abstract/curve.ts';
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

  should('falls back to unblinded multiply when RNG is unavailable', () => {
    const Point = weierstrass(p256.Point.CURVE(), {
      Fp: p256.Point.Fp,
      Fn: p256.Point.Fn,
      randomBytes: () => {
        throw new Error('rng used');
      },
    });
    eql(Point.BASE.multiplyUnsafe(2n).equals(Point.BASE.double()), true);
    // The constructor RNG probe failed: multiply() still works, on the unblinded CT path.
    eql(Point.BASE.multiply(2n).equals(Point.BASE.double()), true);
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
    const a = new ScalarMultiplier(Point, randomBytes);
    const b = new ScalarMultiplier(Point, randomBytes);
    a.setWindowSize(P, 8);
    const r1 = a.mulCTBlinded(P, 123n, norm).p;
    b.setWindowSize(P, 4);
    const r2 = a.mulCTBlinded(P, 123n, norm).p;
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

  should('ScalarMultiplier RNG probe fails open; later misbehavior fails closed', () => {
    const Point = p256.Point;
    const G = Point.BASE;
    const want = G.multiplyUnsafe(5n);
    // The constructor probes the RNG once: an RNG that is broken at construction time —
    // throwing or returning malformed bytes — downgrades mulSecret to the unblinded
    // constant-time path instead of failing on every multiply.
    const throwingRng = (_len?: number): Uint8Array => {
      throw new Error('no entropy');
    };
    const m1 = new ScalarMultiplier(Point, throwingRng);
    eql(m1.mulSecret(G, 5n, 1n).p.equals(want), true, 'throwing RNG downgrades to mulCT');
    const nullRng = ((_len?: number) => null) as never as (len?: number) => Uint8Array;
    const m2 = new ScalarMultiplier(Point, nullRng);
    eql(m2.mulSecret(G, 5n, 1n).p.equals(want), true, 'null-returning RNG downgrades to mulCT');
    const shortRng = (_len?: number) => new Uint8Array(8);
    const m3 = new ScalarMultiplier(Point, shortRng);
    eql(m3.mulSecret(G, 5n, 1n).p.equals(want), true, 'wrong-length RNG downgrades to mulCT');
    // The downgrade decision is static. After a good probe the RNG is part of the trusted
    // contract: a rogue RNG that behaves while probed and misbehaves later must fail closed
    // (throw), never silently downgrade — a dynamic fallback would let a tampered RNG strip
    // blinding on demand.
    let garbageCalls = 0;
    const rogueGarbage = ((len = 0) =>
      ++garbageCalls === 1 ? new Uint8Array(len) : null) as never as (len?: number) => Uint8Array;
    const m4 = new ScalarMultiplier(Point, rogueGarbage);
    throws(() => m4.mulSecret(G, 5n, 1n), 'garbage after good probe fails closed');
    eql(garbageCalls >= 2, true, 'rogue RNG was actually consulted after the probe');
    let throwCalls = 0;
    const rogueThrow = (len = 0): Uint8Array => {
      if (++throwCalls === 1) return new Uint8Array(len);
      throw new Error('no entropy');
    };
    const m5 = new ScalarMultiplier(Point, rogueThrow);
    throws(() => m5.mulSecret(G, 5n, 1n), 'throw after good probe fails closed');
    // non-function RNG is a caller type error, not an availability downgrade
    throws(() => new ScalarMultiplier(Point, 123 as never), 'non-function RNG rejected');
  });

  should('setWindowSize validates W; W=1 resets to un-precomputed', () => {
    const m = new ScalarMultiplier(p256.Point);
    const Q = p256.Point.BASE.double(); // fresh instance: window sizes are tracked per point
    throws(() => m.setWindowSize(Q, 0));
    throws(() => m.setWindowSize(Q, 1.5));
    throws(() => m.setWindowSize(Q, 1000), 'W > curve bits');
    m.setWindowSize(Q, 4);
    eql(m.hasWindowSize(Q), true);
    m.setWindowSize(Q, 1);
    eql(m.hasWindowSize(Q), false, 'W=1 means no window size');
  });

  should('forced extreme blinds keep 256-bit blinded multiplication exact', () => {
    // mulCTBlinded masks the blind's top byte to 10xxxxxx: an all-zero RNG forces the minimum
    // blind 2^127, an all-ff RNG the maximum 0xbfff…ff. Both extremes must stay value-identical
    // to a naive double-and-add reference, incl. on W=6 window-boundary carry-chain scalars.
    const rngMin = (len = 16) => new Uint8Array(len);
    const rngMax = (len = 16) => new Uint8Array(len).fill(0xff);
    const naiveMul = (zero: any, p: any, s: bigint) => {
      let acc = zero;
      let base = p;
      while (s > 0n) {
        if (s & 1n) acc = acc.add(base);
        if (s > 1n) base = base.double();
        s >>= 1n;
      }
      return acc;
    };
    // secp256k1 BASE (cofactor 1) and ed25519 BASE (cofactor 8, order-L base) are both blindable.
    for (const Point of [secp256k1.Point, ed25519.Point] as any[]) {
      const n: bigint = Point.Fn.ORDER;
      const G = Point.BASE;
      const Z = Point.ZERO;
      const mulMin = new ScalarMultiplier(Point, rngMin);
      const mulMax = new ScalarMultiplier(Point, rngMax);
      const bare = new ScalarMultiplier(Point);
      const edges: bigint[] = [1n, 2n, n - 1n, n - 2n, (n - 1n) / 2n];
      for (const k of [64, 128, 192, 255]) {
        for (const d of [-1n, 0n, 1n]) {
          const v = (1n << BigInt(k)) + d;
          if (v >= 1n && v < n) edges.push(v);
        }
      }
      // every W=6 window digit at half / half±1 / max: worst-case signed-digit carry chains
      for (const dd of [31n, 32n, 33n, 63n]) {
        let s = 0n;
        for (let w = 0; w * 6 < 250; w++) s |= dd << BigInt(w * 6);
        if (s < n) edges.push(s);
      }
      const fresh = Point.fromAffine(G.toAffine()); // uncached: blinded fixed-window path
      for (const s of edges) {
        const hexs = s.toString(16).slice(0, 12);
        const want = naiveMul(Z, G, s);
        eql(mulMin.mulCTBlinded(G, s).p.equals(want), true, `blind-min cached ${hexs}`);
        eql(mulMax.mulCTBlinded(G, s).p.equals(want), true, `blind-max cached ${hexs}`);
        eql(mulMin.mulCTBlinded(fresh, s).p.equals(want), true, `blind-min fixed-window ${hexs}`);
        eql(mulMax.mulCTBlinded(fresh, s).p.equals(want), true, `blind-max fixed-window ${hexs}`);
        eql(bare.mulCT(G, s).p.equals(want), true, `unblinded cached ${hexs}`);
        eql(bare.mulUnsafe(G, s).equals(want), true, `vartime cached ${hexs}`);
      }
    }
  });

  should('uses unblinded multiply for cofactored weierstrass BASE when n*BASE is nonzero', () => {
    let calls = 0;
    const randomBytes = (len = 0) => {
      calls++;
      return new Uint8Array(len).fill(7);
    };
    const Point = weierstrass(
      { p: 5n, n: 19n, h: 2n, a: 0n, b: 1n, Gx: 0n, Gy: 1n },
      { randomBytes }
    );
    const before = calls;
    eql(Point.BASE.multiply(2n).equals(Point.BASE.multiplyUnsafe(2n)), true);
    eql(calls, before, 'no blind drawn for non-blindable BASE');
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

  should('edwards extended formulas match affine reference for generic param a', () => {
    // Tiny complete twisted Edwards curve with a ∉ {1, p-1}: a=3 is a square and d=8 a
    // non-square mod 13, subgroup order 5, cofactor 4. All shipped curves use a = ±1
    // (ed25519/jubjub: -1, ed448: 1), so this pins the generic mul-by-a code path.
    const p = 13n, a = 3n, d = 8n; // prettier-ignore
    const G = { x: 5n, y: 8n };
    const EPoint = edwards({ p, n: 5n, h: 4n, a, d, Gx: G.x, Gy: G.y });
    const F = Field(p);
    type Aff = { x: bigint; y: bigint };
    const refAdd = (P: Aff, Q: Aff): Aff => {
      const t = F.mul(F.mul(d, F.mul(P.x, Q.x)), F.mul(P.y, Q.y)); // d·x1x2y1y2
      const x = F.div(F.add(F.mul(P.x, Q.y), F.mul(Q.x, P.y)), F.add(F.ONE, t));
      const y = F.div(F.sub(F.mul(P.y, Q.y), F.mul(a, F.mul(P.x, Q.x))), F.sub(F.ONE, t));
      return { x, y };
    };
    // Walk k·G for k = 2..12: passes through the identity at k = 5 and 10, so additions
    // involving the neutral element are exercised too.
    let R = EPoint.BASE;
    let ref: Aff = G;
    for (let k = 2; k <= 12; k++) {
      R = R.add(EPoint.BASE);
      ref = refAdd(ref, G);
      eql(R.toAffine(), ref, `k=${k}`);
      if (!R.is0()) R.assertValidity();
    }
    eql(EPoint.BASE.double().toAffine(), refAdd(G, G), 'double');
    eql(EPoint.BASE.multiplyUnsafe(4n).add(EPoint.BASE).is0(), true, 'order 5');
    for (const k of [1n, 2n, 3n, 4n]) {
      eql(EPoint.BASE.multiply(k).equals(EPoint.BASE.multiplyUnsafe(k)), true, `mul ${k}`);
    }
  });

  should('toAffine accepts precomputed invertedZ and rejects wrong values', () => {
    for (const Point of [secp256k1.Point, ed25519.Point]) {
      const { Fp } = Point;
      const P = Point.BASE.double().add(Point.BASE); // non-normalized: Z != 1
      eql(Fp.eql(P.Z, Fp.ONE), false, 'test point must not be normalized');
      const iz = Fp.inv(P.Z);
      eql(P.toAffine(iz), P.toAffine());
      throws(() => P.toAffine(Fp.mul(iz, 2n)), /invZ was invalid/);
    }
    // Malformed invertedZ fails before any math.
    const W = secp256k1.Point.BASE.double();
    throws(() => W.toAffine(secp256k1.Point.Fp.ORDER), /invertedZ/);
    const E = ed25519.Point.BASE.double();
    throws(() => E.toAffine('1' as any), /invertedZ/);
  });

  should('checks cofactored edwards BASE order before blinding', () => {
    let calls = 0;
    const randomBytes = (len = 0) => {
      calls++;
      return new Uint8Array(len).fill(7);
    };
    const Good = edwards(ed25519.Point.CURVE(), { randomBytes });
    const beforeGood = calls;
    Good.BASE.multiply(2n);
    eql(calls > beforeGood, true, 'order-L BASE gets blinded (draws randomness)');

    const curve = ed25519.Point.CURVE();
    const Bad = edwards({ ...curve, Gx: 0n, Gy: curve.p - 1n }, { randomBytes });
    const beforeBad = calls;
    eql(Bad.BASE.multiply(2n).equals(Bad.ZERO), true);
    eql(calls, beforeBad, 'small-order BASE skips blinding');
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
      // Subgroup order r. (`curve.ORDER` does not exist: it made this exponent `undefined`, which
      // old FpPow silently mapped to ONE — the 'output order' check below was vacuous.)
      const CURVE_ORDER = G1Point.Fn.ORDER;
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
