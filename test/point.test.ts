import { describe, should } from '@paulmillr/jsbt/test.js';
import * as fc from 'fast-check';
import { deepStrictEqual as eql, throws } from 'node:assert';
import {
  CURVES,
  createCurveFields,
  edwards,
  getOtherCurve,
  hex,
  hexToBytes,
  invert,
  mod,
  ScalarMultiplier,
  mulAddUnsafe,
  normalizeZ,
  pippenger,
  interleavedMSMUnsafe,
  weierstrass,
} from './point.helpers.ts';
import { getTypeTests } from './utils.ts';

const NUM_RUNS = 5;
function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}
const FC_HEX = hexaString({ minLength: 64, maxLength: 64 });

// Group tests
const getXY = (p) => ({ x: p.x, y: p.y });
const validWeierstrass = { p: 17n, n: 19n, h: 1n, a: 2n, b: 2n, Gx: 5n, Gy: 1n };

function equal(a, b, comment) {
  eql(a.equals(b), true, `eq(${comment})`);
  if (a.toAffine && b.toAffine) {
    eql(getXY(a.toAffine()), getXY(b.toAffine()), `eqToAffine(${comment})`);
  } else if (!a.toAffine && !b.toAffine) {
    // Already affine
    eql(getXY(a), getXY(b), `eqAffine(${comment})`);
  } else throw new Error('Different point types');
}

describe('basic curve tests', () => {
  should('curve field constructors validate inputs', () => {
    throws(
      () => createCurveFields('weierstrass', validWeierstrass, null as never),
      /expected valid options object/,
      'curveOpts object shape'
    );
    throws(
      () => createCurveFields('montgomery' as never, validWeierstrass),
      /weierstrass.*edwards/,
      'curve family'
    );
    const Point = edwards({
      p: 257n,
      n: 251n,
      h: 1n,
      a: 1n,
      d: 2n,
      Gx: 256n,
      Gy: 0n,
    });
    eql(Point.BASE.X, 256n, 'edwards coordinate mask follows Fp byte width');
  });

  for (const name in CURVES) {
    const C = CURVES[name];
    const CURVE_ORDER = C.Point.Fn?.ORDER ?? C.Point.CURVE().n;
    const FC_BIGINT = fc.bigInt(1n + 1n, CURVE_ORDER - 1n);
    const p = C.Point;
    const o = getOtherCurve(name).Point;
    if (!p) continue;

    const G = [p.ZERO, p.BASE];
    for (let i = 2n; i < 10n; i++) G.push(G[1].multiply(i));
    const title = `basic curve ${name}`;
    describe(title, () => {
      describe('basic group laws', () => {
        // Here we check basic group laws, to verify that points works as group
        should('deterministic and random group laws', () => {
          equal(G[0].double(), G[0], '(0*G).double() = 0');
          equal(G[0].add(G[0]), G[0], '0*G + 0*G = 0');
          equal(G[0].subtract(G[0]), G[0], '0*G - 0*G = 0');
          equal(G[0].negate(), G[0], '-0 = 0');
          for (let i = 0; i < G.length; i++) {
            const p = G[i];
            equal(p, p.add(G[0]), `${i}*G + 0 = ${i}*G`);
            equal(G[0].multiply(BigInt(i + 1)), G[0], `${i + 1}*0 = 0`);
            equal(G[0].multiplyUnsafe(BigInt(i + 1)), G[0], `${i + 1}*0 = 0`);
          }

          equal(G[1].double(), G[2], '(1*G).double() = 2*G');
          equal(G[1].subtract(G[1]), G[0], '1*G - 1*G = 0');
          equal(G[1].add(G[1]), G[2], '1*G + 1*G = 2*G');
          equal(G[2].double(), G[4], '(2*G).double() = 4*G');
          equal(G[2].add(G[2]), G[4], '2*G + 2*G = 4*G');
          equal(G[7].add(G[3].negate()), G[4], '7*G - 3*G = 4*G');
          equal(G[4].add(G[3]), G[3].add(G[4]), '4*G + 3*G = 3*G + 4*G');
          equal(G[4].add(G[3]), G[3].add(G[2]).add(G[2]), '4*G + 3*G = 3*G + 2*G + 2*G');
          equal(G[3].double(), G[6], '(3*G).double() = 6*G');
          equal(G[2].multiply(3n), G[6], '(2*G).multiply(3) = 6*G');
          equal(G[2].multiplyUnsafe(3n), G[6], '(2*G).multiplyUnsafe(3) = 6*G');
          equal(G[1].multiplyUnsafe(0n), G[0], '(1*G).multiplyUnsafe(0) = 0');
          equal(G[1].multiplyUnsafe(1n), G[1], '(1*G).multiplyUnsafe(1) = 1*G');
          equal(G[0].multiplyUnsafe(5n), G[0], '(0*G).multiplyUnsafe(5) = 0');

          if (typeof ScalarMultiplier === 'function') {
            const point = G[2];
            const scalar = 5n;
            const want = point.multiplyUnsafe(scalar);
            const w = new ScalarMultiplier(p) as any;
            // mulAddUnsafe allowOversized: swaps `s < Fn.ORDER` for the ORDER^4 DoS cap
            const Point = p as any;
            eql(
              mulAddUnsafe(Point, [point], [scalar], true).equals(want),
              true,
              'mulAddUnsafe(c, [point], [scalar], oversized)'
            );
            eql(
              mulAddUnsafe(Point, [point], [0n], true).equals(G[0]),
              true,
              'mulAddUnsafe(c, [point], [0], oversized)'
            );
            throws(() => mulAddUnsafe(Point, [point], [-1n], true), /invalid scalar/);
            const order = Point.Fn.ORDER;
            // point is in the prime-order subgroup, so ORDER⋅point = O
            eql(
              mulAddUnsafe(Point, [point], [order], true).equals(G[0]),
              true,
              'mulAddUnsafe oversized accepts s = ORDER'
            );
            throws(
              () => mulAddUnsafe(Point, [point], [order ** 4n], true),
              /invalid scalar/,
              'DoS cap: rejects s >= ORDER^4'
            );
            throws(
              () => mulAddUnsafe(Point, [point], [order]),
              /invalid scalar/,
              'default: rejects s >= ORDER'
            );
            // precomputed-point path: mulUnsafe reuses the CT kernel
            w.setWindowSize(point, 2);
            eql(
              w.mulUnsafe(point, scalar).equals(want),
              true,
              'mulUnsafe(precomputed point, scalar)'
            );
            w.setWindowSize(point, 1); // reset to un-precomputed
            eql(w.mulUnsafe(point, scalar).equals(want), true, 'mulUnsafe(point, scalar)');
            eql(w.mulUnsafe(point, 0n).equals(G[0]), true, 'mulUnsafe(point, 0)');
            throws(() => w.mulUnsafe(point, -1n), /invalid scalar/);
          }

          equal(G[3].add(G[3]), G[6], '3*G + 3*G = 6*G');
          equal(G[3].add(G[3].negate()), G[0], '3*G + (- 3*G) = 0*G');
          equal(G[3].subtract(G[3]), G[0], '3*G - 3*G = 0*G');
          equal(G[1].multiply(CURVE_ORDER - 1n).add(G[1]), G[0], '(N-1)*G + G = 0');
          equal(G[1].multiply(CURVE_ORDER - 1n).add(G[2]), G[1], '(N-1)*G + 2*G = 1*G');
          equal(G[1].multiply(CURVE_ORDER - 2n).add(G[2]), G[0], '(N-2)*G + 2*G = 0');
          equal(G[1].multiplyUnsafe(CURVE_ORDER - 1n).add(G[1]), G[0], '(N-1)*G + G = 0');
          equal(G[1].multiplyUnsafe(CURVE_ORDER - 1n).add(G[2]), G[1], '(N-1)*G + 2*G = 1*G');
          equal(G[1].multiplyUnsafe(CURVE_ORDER - 2n).add(G[2]), G[0], '(N-2)*G + 2*G = 0');
          const half = CURVE_ORDER / 2n;
          const carry = CURVE_ORDER % 2n === 1n ? G[1] : G[0];
          equal(G[1].multiply(half).double().add(carry), G[0], '((N/2) * G).double() = 0');

          const a = 1234n;
          const b = 5678n;
          const c = a * b;
          equal(G[1].multiply(a).multiply(b), G[1].multiply(c), 'a*b*G = c*G');
          const inv = invert(b, CURVE_ORDER);
          equal(G[1].multiply(c).multiply(inv), G[1].multiply(a), 'c*G * (1/b)*G = a*G');

          fc.assert(
            fc.property(FC_BIGINT, FC_BIGINT, (a, b) => {
              const c = mod(a + b, CURVE_ORDER);
              if (c === CURVE_ORDER || c < 1n) return;
              const pA = G[1].multiply(a);
              const pB = G[1].multiply(b);
              const pC = G[1].multiply(c);
              equal(pA, G[1].multiplyUnsafe(a), 'multiplyUnsafe(a)');
              equal(pB, G[1].multiplyUnsafe(b), 'multiplyUnsafe(b)');
              equal(pC, G[1].multiplyUnsafe(c), 'multiplyUnsafe(c)');
              equal(pA.add(pB), pB.add(pA), 'pA + pB = pB + pA');
              equal(pA.add(pB), pC, 'pA + pB = pC');
            }),
            { numRuns: NUM_RUNS }
          );
          fc.assert(
            fc.property(FC_BIGINT, FC_BIGINT, (a, b) => {
              const c = mod(a * b, CURVE_ORDER);
              const pA = G[1].multiply(a);
              const pB = G[1].multiply(b);
              equal(pA, G[1].multiplyUnsafe(a), 'multiplyUnsafe(a)');
              equal(pB, G[1].multiplyUnsafe(b), 'multiplyUnsafe(b)');
              equal(pA.multiply(b), pB.multiply(a), 'b*pA = a*pB');
              equal(pA.multiply(b), G[1].multiply(c), 'b*pA = c*G');
            }),
            { numRuns: NUM_RUNS }
          );
        });
      });

      // special case for add, subtract, equals, multiply. NOT multiplyUnsafe
      // [0n, '0n'],

      should('add/subtract type check', () => {
        for (const op of ['add', 'subtract']) {
          for (let [item, repr_] of getTypeTests()) {
            throws(() => G[1][op](item), `${op}: ${repr_}`);
          }
          throws(() => G[1][op](0), `${op}: 0`);
          throws(() => G[1][op](0n), `${op}: 0n`);
          G[1][op](G[2]);
          throws(() => G[1][op](CURVE_ORDER), `${op}: CURVE_ORDER`);
          throws(() => G[1][op]({ x: 1n, y: 1n }), `${op}: { x: 1n, y: 1n }`);
          throws(() => G[1][op]({ x: 1n, y: 1n, z: 1n }), `${op}: { x: 1n, y: 1n, z: 1n }`);
          throws(
            () => G[1][op]({ x: 1n, y: 1n, z: 1n, t: 1n }),
            `${op}: { x: 1n, y: 1n, z: 1n, t: 1n }`
          );
          throws(() => G[1][op](o.BASE), `${op}: other curve point`);
        }
      });

      should('equals type check', () => {
        const op = 'equals';
        for (let [item, repr_] of getTypeTests()) {
          throws(() => G[1][op](item), repr_);
        }
        throws(() => G[1].equals(0), '0');
        throws(() => G[1].equals(0n), '0n');
        eql(G[1].equals(G[2]), false, '1*G != 2*G');
        eql(G[1].equals(G[1]), true, '1*G == 1*G');
        eql(G[2].equals(G[2]), true, '2*G == 2*G');
        throws(() => G[1].equals(CURVE_ORDER), 'CURVE_ORDER');
        throws(() => G[1].equals({ x: 1n, y: 1n, z: 1n, t: 1n }), '{ x: 1n, y: 1n, z: 1n, t: 1n }');
        throws(() => G[1].equals(o.BASE), 'other curve point');
      });

      should('multiply type check', () => {
        for (const op of ['multiply', 'multiplyUnsafe']) {
          if (!p.BASE[op]) continue;
          for (let [item, repr_] of getTypeTests()) {
            throws(() => G[1][op](item), `${op}: ${repr_}`);
          }
          G[1][op](1n);
          G[1][op](CURVE_ORDER - 1n);
          throws(() => G[1][op](G[2]), `${op}: G[2]`);
          throws(() => G[1][op](CURVE_ORDER), `${op}: CURVE_ORDER`);
          throws(() => G[1][op](CURVE_ORDER + 1n), `${op}: CURVE_ORDER+1`);
          throws(() => G[1][op](o.BASE), `${op}: other curve point`);
          if (op !== 'multiplyUnsafe') {
            throws(() => G[1][op](0), `${op}: 0`);
            throws(() => G[1][op](0n), `${op}: 0n`);
          }
        }
      });

      describe('multiscalar multiplication', () => {
        if (typeof pippenger !== 'function' || typeof interleavedMSMUnsafe !== 'function') return;
        should('basic, random, and precomputed MSM', () => {
          const msm = (points, scalars) => pippenger(p, points, scalars);
          equal(msm([p.BASE], [0n]), p.ZERO, '0*G');
          equal(msm([], []), p.ZERO, 'empty');
          equal(msm([p.ZERO], [123n]), p.ZERO, '123 * Infinity');
          equal(msm([p.BASE], [123n]), p.BASE.multiply(123n), '123 * G');
          const points = [p.BASE, p.BASE.multiply(2n), p.BASE.multiply(4n), p.BASE.multiply(8n)];
          // 1*3 + 5*2 + 4*7 + 11*8 = 129
          equal(msm(points, [3n, 5n, 7n, 11n]), p.BASE.multiply(129n), '129 * G');
          throws(() => normalizeZ(p, [p.BASE, {} as never]), /invalid point at index 1/);

          fc.assert(
            fc.property(fc.array(fc.tuple(FC_BIGINT, FC_BIGINT)), FC_BIGINT, (pairs) => {
              let total = 0n;
              const scalars = [];
              const points = [];
              for (const [ps, s] of pairs) {
                points.push(p.BASE.multiply(ps));
                scalars.push(s);
                total += ps * s;
              }
              total = mod(total, CURVE_ORDER);
              const exp = total ? p.BASE.multiply(total) : p.ZERO;
              equal(pippenger(p, points, scalars), exp, 'total');
            }),
            { numRuns: NUM_RUNS }
          );

          const Point = C.Point;
          if (!Point) throw new Error('Unknown point');

          const points2 = [p.BASE, p.BASE.multiply(2n), p.BASE.multiply(4n), p.BASE.multiply(8n)];
          const scalars = [3n, 5n, 7n, 11n];
          const res = p.BASE.multiply(129n);
          for (let windowSize = 2; windowSize <= 10; windowSize++) {
            const mul = interleavedMSMUnsafe(Point, points2, windowSize);
            equal(mul(scalars), res, 'windowSize=' + windowSize);
          }
          throws(() => interleavedMSMUnsafe(Point, points2, 1), /window/);

          fc.assert(
            fc.property(fc.array(fc.tuple(FC_BIGINT, FC_BIGINT)), FC_BIGINT, (pairs) => {
              const Point = C.Point;
              if (!Point) throw new Error('Unknown point');

              let total = 0n;
              const scalars = [];
              const points = [];
              for (const [ps, s] of pairs) {
                points.push(p.BASE.multiply(ps));
                scalars.push(s);
                total += ps * s;
              }
              total = mod(total, CURVE_ORDER);
              const res = total ? p.BASE.multiply(total) : p.ZERO;

              for (let windowSize = 2; windowSize <= 10; windowSize++) {
                const mul = interleavedMSMUnsafe(Point, points, windowSize);
                equal(mul(scalars), res, 'windowSize=' + windowSize);
              }
            }),
            { numRuns: NUM_RUNS }
          );
        });
      });

      should('point serialization roundtrips', () => {
        equal(p.ZERO, p.fromAffine(p.ZERO.toAffine()), '0 = 0');
        equal(p.BASE, p.fromAffine(p.BASE.toAffine()), '1 = 1');
        equal(p.BASE.multiply(2n), p.fromAffine(p.BASE.multiply(2n).toAffine()), '1 = 1');

        fc.assert(
          fc.property(FC_BIGINT, (x) => {
            const point = p.BASE.multiply(x);
            let c = false; // compressed
            const bu = point.toBytes(c);
            eql(p.fromBytes(bu).toBytes(c), bu, `${name}: fromBytes uncompressed`);

            c = true;
            const bc = point.toBytes(c);
            eql(p.fromBytes(bc).toBytes(c), bc, `${name}: fromBytes compressed`);
          })
        );
        // toHex/fromHex (if available)
        fc.assert(
          fc.property(FC_BIGINT, (x) => {
            const point = p.BASE.multiply(x);
            let c = false; // compressed
            const hu = point.toHex(c);
            eql(p.fromHex(hu).toHex(c), hu, `${name}: fromHex uncompressed`);

            c = true;
            const hc = point.toHex(c);
            eql(p.fromHex(hc).toHex(c), hc, `${name}: fromHex compressed`);
          })
        );
      });
    });

    describe(name, () => {
      // Generic complex things (getPublicKey/sign/verify/getSharedSecret)
      should('.getPublicKey() type check', () => {
        for (let [item, repr_] of getTypeTests()) {
          throws(() => C.getPublicKey(item), repr_);
        }
        throws(() => C.getPublicKey('key'), "'key'");
        throws(() => C.getPublicKey({}));
        throws(() => C.getPublicKey(Uint8Array.of()));
        throws(() => C.getPublicKey(Array(32).fill(1)));
      });

      if (C.verify) {
        should('.verify() accepts valid signatures', () => {
          fc.assert(
            fc.property(FC_HEX, (msgh) => {
              const msg = hexToBytes(msgh);
              const keys = C.keygen();
              const sig = C.sign(msg, keys.secretKey);
              eql(
                C.verify(sig, msg, keys.publicKey),
                true,
                `priv=${hex(keys.secretKey)},pub=${hex(keys.publicKey)},msg=${msg}`
              );
            }),
            { numRuns: NUM_RUNS }
          );
          const msg = Uint8Array.of();
          const k = C.keygen();
          const sig = C.sign(msg, k.secretKey);
          eql(
            C.verify(sig, msg, k.publicKey),
            true,
            `empty: priv=${hex(k.secretKey)},pub=${hex(k.publicKey)},msg=${msg}`
          );
        });
        should('.sign() type and edge cases', () => {
          const msg = Uint8Array.of();
          const k = C.keygen();
          C.sign(msg, k.secretKey);
          for (let [item, repr_] of getTypeTests()) {
            throws(() => C.sign(msg, item), repr_);
            if (!repr_.startsWith('ui8a') && repr_ !== '""') {
              throws(() => C.sign(item, k.secretKey), repr_);
            }
          }
          throws(() => C.sign(), 'sign missing args');
          throws(() => C.sign(''), 'sign missing secret');
          throws(() => C.sign('', ''), 'sign empty strings');
          throws(() => C.sign(Uint8Array.of(), Uint8Array.of()), 'sign empty bytes');
        });

        describe('verify()', () => {
          const msg = hexToBytes('01'.repeat(32));
          const msgWrong = hexToBytes('11'.repeat(32));
          should('valid, invalid, and type cases', () => {
            const k = C.keygen();
            const sig = C.sign(msg, k.secretKey);
            eql(C.verify(sig, msg, k.publicKey), true, 'proper signature');
            eql(C.verify(sig, msgWrong, k.publicKey), false, 'wrong message');
            const k2 = C.keygen();
            eql(C.verify(sig, msg, k2.publicKey), false, 'wrong key');
            const pub = k.publicKey;
            C.verify(sig, msg, pub);
            for (let [item, repr_] of getTypeTests()) {
              if (repr_.startsWith('ui8a') || repr_.startsWith('"')) continue;
              throws(() => C.verify(item, msg, pub), `verify(${repr_}, _, _)`);
              throws(() => C.verify(sig, item, pub), `verify(_, ${repr_}, _)`);
              throws(() => C.verify(sig, msg, item), `verify(_, _, ${repr_})`);
            }
          });
        });
      }
      if (C.Signature) {
        should('Signature serialization and recovery', () => {
          fc.assert(
            fc.property(FC_HEX, (msgh) => {
              const msg = hexToBytes(msgh);
              const priv = C.utils.randomSecretKey();
              const sigb = C.sign(msg, priv);
              const sig = C.Signature.fromBytes(sigb);
              const sigRS = (sig) => ({ s: sig.s, r: sig.r });
              const hasToHex = !!C.Signature.fromHex;

              let f = 'compact';
              eql(sigRS(C.Signature.fromBytes(sig.toBytes(f), f)), sigRS(sig));
              if (hasToHex) eql(sigRS(C.Signature.fromHex(sig.toHex(f), f)), sigRS(sig));

              if (C.Point.CURVE().h <= 2n) {
                f = 'recovered';
                const sigrb = C.sign(msg, priv, { format: f });
                const sigr = C.Signature.fromBytes(sigrb, f);
                eql(sigRS(C.Signature.fromBytes(sigr.toBytes(f), f)), sigRS(sigr));
                if (hasToHex) eql(sigRS(C.Signature.fromHex(sigr.toHex(f), f)), sigRS(sigr));
              }

              const isNobleCurves = !!C.Point.Fp;
              if (isNobleCurves) {
                f = 'der';
                eql(sigRS(C.Signature.fromBytes(sig.toBytes(f), f)), sigRS(sig));
                if (hasToHex) eql(sigRS(C.Signature.fromHex(sig.toHex(f), f)), sigRS(sig));
              }
            }),
            { numRuns: NUM_RUNS }
          );
          fc.assert(
            fc.property(FC_HEX, (msgh) => {
              if (C.Point.CURVE().h > 2) return; // unsupported, see k2sig
              const msg = hexToBytes(msgh);
              const keys = C.keygen();
              const sigb = C.sign(msg, keys.secretKey, { format: 'recovered' });
              const sig = C.Signature.fromBytes(sigb, 'recovered');
              let res;
              try {
                res = C.recoverPublicKey(sigb, msg);
              } catch (error) {
                // curves with cofactor>1 can't be recovered
                if (/recovery id is ambiguous/.test(error.message)) return;
              }
              eql(res, keys.publicKey);
              // Old API: by default we do same thing as sign/verify, this allows generic API even when curve prehash: true,
              // otherwise user would need to prehash manually which is weird.
              eql(res, C.recoverPublicKey(sigb, C.hash(msg), { prehash: false })); // can still provide hash manually
              // Create identical sig
              const sig2 = C.Signature.fromBytes(sig.toBytes('compact'), 'compact');
              const sig3 = sig2.addRecoveryBit(sig.recovery);
              throws(() => C.recoverPublicKey(sig3, msg));
              eql(C.recoverPublicKey(sig3.toBytes('recovered'), msg), keys.publicKey);
            }),
            { numRuns: NUM_RUNS }
          );
        });
      }

      if (C.getSharedSecret) {
        should('getSharedSecret() should be commutative', () => {
          for (let i = 0; i < NUM_RUNS; i++) {
            const a = C.keygen();
            const b = C.keygen();
            try {
              eql(
                C.getSharedSecret(a.secretKey, b.publicKey),
                C.getSharedSecret(b.secretKey, a.publicKey)
              );
            } catch (error) {
              console.error('not commutative', { a, b });
              throw error;
            }
          }
        });
      }
    });
  }
});

// Deterministic xorshift64 PRNG: reproducible complement to fast-check for the
// kernel tests below.
function makeRng(initialSeed: bigint) {
  let seed = initialSeed;
  const mask64 = (1n << 64n) - 1n;
  const rnd64 = () => {
    seed = (seed ^ (seed << 13n)) & mask64;
    seed ^= seed >> 7n;
    seed = (seed ^ (seed << 17n)) & mask64;
    return seed;
  };
  const rndBig = (bits: number) => {
    let r = 0n;
    for (let i = 0; i < bits; i += 64) r = (r << 64n) | rnd64();
    return r & ((1n << BigInt(bits)) - 1n);
  };
  const rndBelow = (n: bigint) => {
    const bits = n.toString(2).length;
    while (true) {
      const r = rndBig(bits);
      if (r < n) return r;
    }
  };
  return { rndBig, rndBelow };
}

// Naive double-and-add using only add/double: independent reference for every kernel.
function naiveMul(zero, p, s: bigint) {
  let acc = zero;
  let base = p;
  while (s > 0n) {
    if (s & 1n) acc = acc.add(base);
    if (s > 1n) base = base.double();
    s >>= 1n;
  }
  return acc;
}

describe('scalar-mult kernels: toy curve, exhaustive', () => {
  // y² = x³ + x + 6 over F_1039 has prime order 1009 (cofactor 1). Params were found once by
  // exhaustive point counting over small (a, b); hardcoded so tests skip the search. The small
  // order allows checking every kernel on EVERY scalar against a full naive multiple table.
  const toy = { p: 1039n, a: 1n, b: 6n, n: 1009n, h: 1n, Gx: 1n, Gy: 221n };
  const TPoint = weierstrass(toy);
  const TN = toy.n;
  const TG = TPoint.BASE;
  const TZ = TPoint.ZERO;
  // Full naive multiple table, exact by construction: nmul[i] = i*G via repeated add().
  const nmul = [TZ];
  for (let i = 1; i <= Number(TN); i++) nmul.push(nmul[i - 1].add(TG));
  // Forced extreme blinds: mulCTBlinded masks the top byte to 10xxxxxx, so all-zero bytes give
  // the minimum blind 0x80 00…00 = 2^127 and all-ff bytes the maximum blind 0xbf ff…ff.
  const rngMin = (l = 16) => new Uint8Array(l);
  const rngMax = (l = 16) => new Uint8Array(l).fill(0xff);

  should('N*G == O and (N-1)*G != O', () => {
    eql(nmul[Number(TN)].is0(), true);
    eql(nmul[Number(TN) - 1].is0(), false);
  });

  should('all kernels agree with the naive table on every scalar', () => {
    const freshG = TPoint.fromAffine(TG.toAffine()); // separate identity: uncached fixed-window path
    const bare = new ScalarMultiplier(TPoint); // no RNG: unblinded CT paths
    const mulMin = new ScalarMultiplier(TPoint, rngMin);
    const mulMax = new ScalarMultiplier(TPoint, rngMax);
    for (let s = 1n; s < TN; s++) {
      const want = nmul[Number(s)];
      eql(TG.multiply(s).equals(want), true, `multiply(BASE, ${s})`);
      eql(freshG.multiply(s).equals(want), true, `multiply(fresh, ${s})`);
      eql(bare.mulCT(TG, s).p.equals(want), true, `mulCT cached ${s}`);
      eql(bare.mulCT(freshG, s).p.equals(want), true, `mulCT fixed-window ${s}`);
      eql(mulMin.mulCTBlinded(TG, s).p.equals(want), true, `blind-min cached ${s}`);
      eql(mulMax.mulCTBlinded(TG, s).p.equals(want), true, `blind-max cached ${s}`);
      eql(mulMin.mulCTBlinded(freshG, s).p.equals(want), true, `blind-min fixed-window ${s}`);
      eql(mulMax.mulCTBlinded(freshG, s).p.equals(want), true, `blind-max fixed-window ${s}`);
      eql(TG.multiplyUnsafe(s).equals(want), true, `multiplyUnsafe(BASE, ${s})`);
      eql(freshG.multiplyUnsafe(s).equals(want), true, `multiplyUnsafe(fresh, ${s})`);
    }
  });

  should('cached wNAF at every window width W=1..8 on every scalar', () => {
    for (let W = 1; W <= 8; W++) {
      const Q = TPoint.fromAffine(TG.toAffine());
      Q.precompute(W, false); // eager build; W=1 resets to the un-precomputed paths
      for (let s = 1n; s < TN; s++) {
        eql(Q.multiply(s).equals(nmul[Number(s)]), true, `W=${W} multiply ${s}`);
        eql(Q.multiplyUnsafe(s).equals(nmul[Number(s)]), true, `W=${W} multiplyUnsafe ${s}`);
      }
    }
  });

  should('vartime oversized scalars: reduction mod n, ORDER^4 DoS cap, bounds', () => {
    const bare = new ScalarMultiplier(TPoint);
    const freshG = TPoint.fromAffine(TG.toAffine());
    // ScalarMultiplier.mulUnsafe routes oversized scalars through the allowOversized wNAF path
    for (const s of [TN, TN + 1n, 2n * TN + 3n, TN * TN, TN ** 3n + 17n, TN ** 4n - 1n]) {
      const want = nmul[Number(s % TN)];
      eql(bare.mulUnsafe(TG, s).equals(want), true, `mulUnsafe oversized ${s}`);
      eql(bare.mulUnsafe(freshG, s).equals(want), true, `mulUnsafe oversized fresh ${s}`);
    }
    throws(() => bare.mulUnsafe(TG, TN ** 4n), 'ORDER^4 cap');
    throws(() => bare.mulUnsafe(TG, -1n));
    eql(bare.mulUnsafe(TG, 0n).is0(), true);
    eql(bare.mulUnsafe(freshG, 0n).is0(), true);
    // multiply()/mulCT/mulCTBlinded bound checks
    throws(() => TG.multiply(0n));
    throws(() => TG.multiply(TN));
    throws(() => bare.mulCT(TG, 0n));
    throws(() => bare.mulCT(TG, TN));
    const mulMin = new ScalarMultiplier(TPoint, rngMin);
    throws(() => mulMin.mulCTBlinded(TG, TN));
  });

  should('blind determinism and ZERO handling', () => {
    const s = 777n % TN;
    const base0 = TG.multiply(s);
    // multiply() draws a fresh random blind per call; the result must not depend on it
    for (let i = 0; i < 30; i++) eql(TG.multiply(s).equals(base0), true, 'blind determinism');
    eql(TZ.multiply(5n).is0(), true);
    eql(TZ.multiplyUnsafe(5n).is0(), true);
  });

  should('mulAddUnsafe: dense grid, edges, oversized, invalid inputs', () => {
    const G2 = TG.double();
    const G3 = G2.add(TG);
    for (let s1 = 0n; s1 < TN; s1 += 5n) {
      for (let s2 = 0n; s2 < TN; s2 += 97n) {
        const want = nmul[Number((s1 + 2n * s2) % TN)];
        eql(mulAddUnsafe(TPoint, [TG, G2], [s1, s2]).equals(want), true, `grid ${s1},${s2}`);
      }
    }
    eql(mulAddUnsafe(TPoint, [], []).is0(), true, 'empty');
    eql(mulAddUnsafe(TPoint, [TG], [0n]).is0(), true, '[0]');
    eql(mulAddUnsafe(TPoint, [TG, G2], [0n, 0n]).is0(), true, 'zeros');
    eql(mulAddUnsafe(TPoint, [TG, TZ], [3n, 5n]).equals(nmul[3]), true, 'with ZERO point');
    eql(
      mulAddUnsafe(TPoint, [TG, G2, G3], [TN - 1n, TN - 1n, TN - 1n]).equals(
        nmul[Number((6n * (TN - 1n)) % TN)]
      ),
      true,
      'max scalars'
    );
    const so = TN ** 3n + 12345n;
    eql(mulAddUnsafe(TPoint, [TG], [so], true).equals(nmul[Number(so % TN)]), true, 'oversized');
    throws(() => mulAddUnsafe(TPoint, [TG], [TN]), 'scalar=N without allowOversized');
    throws(() => mulAddUnsafe(TPoint, [TG], [TN ** 4n], true), 'ORDER^4 cap');
    throws(() => mulAddUnsafe(TPoint, [TG], [-1n], true));
    throws(() => mulAddUnsafe(TPoint, [TG], [1n, 2n]), 'length mismatch');
    throws(() => mulAddUnsafe(TPoint, [{} as never], [1n]), 'foreign point');
  });

  should('pippenger and interleavedMSMUnsafe vs the naive table', () => {
    const { rndBelow } = makeRng(0xdeadbeefn);
    const G2 = TG.double();
    const G3 = G2.add(TG);
    for (const L of [1, 2, 3, 8, 33, 100]) {
      const ps = [];
      const ss = [];
      let total = 0n;
      for (let i = 0; i < L; i++) {
        const k = rndBelow(TN);
        const s = i % 4 === 0 ? 0n : rndBelow(TN); // mix in zero scalars
        ps.push(nmul[Number(k)]);
        ss.push(s);
        total = (total + k * s) % TN;
      }
      eql(pippenger(TPoint, ps, ss).equals(nmul[Number(total)]), true, `pippenger L=${L}`);
    }
    eql(pippenger(TPoint, [], []).is0(), true, 'pippenger empty');
    eql(pippenger(TPoint, [TG, G2], [0n, 0n]).is0(), true, 'pippenger all-zero');
    eql(pippenger(TPoint, [TG], [TN - 1n]).equals(nmul[Number(TN - 1n)]), true, 'pippenger n-1');
    throws(() => pippenger(TPoint, [TG], [TN]), 'pippenger scalar=N');
    throws(() => pippenger(TPoint, [TG], [1n, 2n]), 'pippenger length mismatch');

    const pts = [TG, G2, G3];
    for (const W of [2, 3, 4, 8]) {
      const msm = interleavedMSMUnsafe(TPoint, pts, W);
      for (let t = 0; t < 20; t++) {
        const ss = [rndBelow(TN), rndBelow(TN), rndBelow(TN)];
        const total = (ss[0] + 2n * ss[1] + 3n * ss[2]) % TN;
        eql(msm(ss).equals(nmul[Number(total)]), true, `interleaved W=${W} t=${t}`);
      }
      // fewer scalars than points: trailing zeros
      eql(msm([5n]).equals(nmul[5]), true, `interleaved W=${W} partial scalars`);
      eql(msm([]).is0(), true, `interleaved W=${W} no scalars`);
      throws(() => msm([1n, 2n, 3n, 4n]), 'too many scalars');
      throws(() => msm([TN]), 'scalar=N');
    }
  });

  should('normalizeZ normalizes Z without changing values', () => {
    const G2 = TG.double();
    const batch = [TG, G2, TZ, G2.double()];
    const norm = normalizeZ(TPoint, batch);
    for (let i = 0; i < batch.length; i++) {
      eql(norm[i].equals(batch[i]), true, `equality @${i}`);
      eql(norm[i].is0() || (norm[i] as never as { Z: bigint }).Z === 1n, true, `Z=1 @${i}`);
    }
  });
});

describe('scalar-mult vs naive reference: real curves', () => {
  function edgeScalars(n: bigint): bigint[] {
    const out = new Set<bigint>();
    const add = (x: bigint) => {
      if (x >= 1n && x < n) out.add(x);
    };
    [1n, 2n, 3n, 7n, n - 1n, n - 2n, (n - 1n) / 2n, (n + 1n) / 2n].forEach(add);
    // prettier-ignore
    for (const k of [8, 16, 32, 63, 64, 65, 127, 128, 129, 191, 192, 250, 251, 252, 253, 254, 255]) {
      add(1n << BigInt(k));
      add((1n << BigInt(k)) - 1n);
      add((1n << BigInt(k)) + 1n);
    }
    // W=6 window-boundary patterns: every window at half / half±1 / max digit (carry chains)
    for (const d of [31n, 32n, 33n, 63n]) {
      let s = 0n;
      for (let w = 0; w * 6 < 250; w++) s |= d << BigInt(w * 6);
      add(s);
    }
    // alternating bit patterns 0b1010… and 0b0101…
    let alt = 0n;
    for (let i = 0; i < 128; i++) alt = (alt << 2n) | 2n;
    add(alt);
    add(alt >> 1n);
    return [...out];
  }

  // secp256k1 exercises the GLV endo path; p256 the plain weierstrass path; ed25519 the
  // cofactored edwards path.
  for (const name of ['secp256k1', 'secp256r1', 'ed25519']) {
    should(`${name}: edge + random scalars across kernels`, () => {
      const Point = CURVES[name].Point;
      const n = Point.Fn.ORDER;
      const G = Point.BASE;
      const Z = Point.ZERO;
      const { rndBelow } = makeRng(0xc0ffeen);
      const scalars = edgeScalars(n).concat(
        Array.from({ length: 20 }, () => rndBelow(n - 1n) + 1n)
      );
      const freshG = Point.fromAffine(G.toAffine()); // separate identity: uncached fixed-window path
      const bare = new ScalarMultiplier(Point);
      let i = 0;
      for (const s of scalars) {
        const want = naiveMul(Z, G, s);
        eql(G.multiply(s).equals(want), true, `multiply(BASE, ${s.toString(16)})`);
        eql(G.multiplyUnsafe(s).equals(want), true, `multiplyUnsafe(BASE, ${s.toString(16)})`);
        // uncached paths are slower; run on a subset
        if (i % 3 === 0) {
          eql(freshG.multiply(s).equals(want), true, `multiply(fresh, ${s.toString(16)})`);
          eql(freshG.multiplyUnsafe(s).equals(want), true, `multiplyUnsafe(fresh)`);
          eql(bare.mulCT(G, s).p.equals(want), true, `mulCT ${s.toString(16)}`);
        }
        i++;
      }
    });
  }

  should('joint mulAddUnsafe (incl. GLV endo split) vs naive', () => {
    const { rndBelow } = makeRng(0x5eedn);
    for (const name of ['secp256k1', 'secp256r1']) {
      const Point = CURVES[name].Point;
      const n = Point.Fn.ORDER;
      const G = Point.BASE;
      const Z = Point.ZERO;
      const Q = G.multiply(rndBelow(n - 1n) + 1n);
      for (let t = 0; t < 8; t++) {
        const a = t === 0 ? 0n : t === 1 ? n - 1n : rndBelow(n);
        const b = t === 2 ? 0n : t === 3 ? n - 1n : rndBelow(n);
        const want = naiveMul(Z, G, a).add(naiveMul(Z, Q, b));
        eql(G.mulAddUnsafe(a, Q, b).equals(want), true, `${name} t=${t}`);
      }
      // curve-level joint MSM with generic points (no endo folding: direct path)
      for (let t = 0; t < 4; t++) {
        const pts = [G, Q, Q.double()];
        const ss = [rndBelow(n), rndBelow(n), rndBelow(n)];
        let want = Z;
        for (let j = 0; j < 3; j++) want = want.add(naiveMul(Z, pts[j], ss[j]));
        eql(mulAddUnsafe(Point, pts, ss).equals(want), true, `${name} L=3 t=${t}`);
      }
    }
  });

  should('pippenger/interleaved on secp256k1 + cross-curve point rejection', () => {
    const Point = CURVES.secp256k1.Point;
    const n = Point.Fn.ORDER;
    const G = Point.BASE;
    const Z = Point.ZERO;
    const { rndBelow } = makeRng(0xabcdefn);
    const pts = [];
    const ss = [];
    let want = Z;
    for (let i = 0; i < 7; i++) {
      const P = G.multiplyUnsafe(rndBelow(n - 1n) + 1n);
      const s = i === 3 ? 0n : rndBelow(n);
      pts.push(P);
      ss.push(s);
      want = want.add(naiveMul(Z, P, s));
    }
    eql(pippenger(Point, pts, ss).equals(want), true, 'pippenger L=7');
    const msm = interleavedMSMUnsafe(Point, pts.slice(0, 3), 5);
    const want3 = naiveMul(Z, pts[0], ss[0])
      .add(naiveMul(Z, pts[1], ss[1]))
      .add(naiveMul(Z, pts[2], ss[2]));
    eql(msm(ss.slice(0, 3)).equals(want3), true, 'interleaved L=3 W=5');
    const foreign = CURVES.secp256r1.Point.BASE;
    throws(() => pippenger(Point, [foreign as never], [1n]), 'pippenger foreign point');
    throws(() => mulAddUnsafe(Point, [foreign as never], [1n]), 'mulAddUnsafe foreign point');
  });
});

should.runWhen(import.meta.url);
