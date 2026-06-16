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
  normalizeZ,
  pippenger,
  precomputeMSMUnsafe,
  wNAF,
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

          if (typeof wNAF === 'function') {
            const point = G[2];
            const acc = G[7];
            const scalar = 5n;
            const want = acc.add(point.multiplyUnsafe(scalar));
            const w = new wNAF(p) as any;
            eql(
              w.ladder_nonCT(point, scalar, acc).equals(want),
              true,
              'ladder_nonCT(point, scalar, acc)'
            );
            eql(w.ladder_nonCT(point, 0n, acc).equals(acc), true, 'ladder_nonCT(point, 0, acc)');
            throws(() => w.ladder_nonCT(point, -1n, acc), /invalid scalar/);
            const precomputes = w.getPrecomputes(2, point);
            eql(
              w.wNAF_nonCT(2, precomputes, scalar, acc).equals(want),
              true,
              'wNAF_nonCT(point, scalar, acc)'
            );
            eql(
              w.wNAF_nonCT(2, precomputes, 0n, acc).equals(acc),
              true,
              'wNAF_nonCT(point, 0, acc)'
            );
            eql(
              w.unsafe(point, scalar, undefined, acc).equals(want),
              true,
              'unsafe(point, scalar, acc)'
            );
            eql(w.unsafe(point, 0n, undefined, acc).equals(acc), true, 'unsafe(point, 0, acc)');
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
        if (typeof pippenger !== 'function' || typeof precomputeMSMUnsafe !== 'function') return;
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
          for (let windowSize = 1; windowSize <= 10; windowSize++) {
            const mul = precomputeMSMUnsafe(Point, points2, windowSize);
            equal(mul(scalars), res, 'windowSize=' + windowSize);
          }

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

              for (let windowSize = 1; windowSize <= 10; windowSize++) {
                const mul = precomputeMSMUnsafe(Point, points, windowSize);
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

should.runWhen(import.meta.url);
