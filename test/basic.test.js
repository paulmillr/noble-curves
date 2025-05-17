import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, notDeepStrictEqual, throws } from 'node:assert';
import * as mod from '../esm/abstract/modular.js';
import { isBytes, bytesToHex as toHex } from '../esm/abstract/utils.js';
import { getTypeTests, json } from './utils.js';
// Generic tests for all curves in package
import { sha256, sha512 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { createCurve } from '../esm/_shortw_utils.js';
import { precomputeMSMUnsafe } from '../esm/abstract/curve.js';
import { twistedEdwards } from '../esm/abstract/edwards.js';
import { Field } from '../esm/abstract/modular.js';
import { bls12_381 } from '../esm/bls12-381.js';
import { bn254 } from '../esm/bn254.js';
import { ed25519, ed25519ctx, ed25519ph, RistrettoPoint, x25519 } from '../esm/ed25519.js';
import { DecafPoint, ed448, ed448ph } from '../esm/ed448.js';
import { jubjub } from '../esm/misc.js';
import { secp256r1, secp384r1, secp521r1 } from '../esm/nist.js';
import { secp256k1 } from '../esm/secp256k1.js';
import { miscCurves, secp192r1, secp224r1 } from './_more-curves.helpers.js';
const wyche_curves = json('./wycheproof/ec_prime_order_curves_test.json');

const NUM_RUNS = 5;

function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}
const FC_HEX = hexaString({ minLength: 64, maxLength: 64 });
// const FC_HEX = fc.stringMatching(/[0-9a-fA-F]+/, { size: 64 });

// Fields tests
const FIELDS = {
  secp192r1: { Fp: [secp192r1.CURVE.Fp] },
  secp224r1: { Fp: [secp224r1.CURVE.Fp] },
  secp256r1: { Fp: [secp256r1.CURVE.Fp] },
  secp521r1: { Fp: [secp521r1.CURVE.Fp] },
  secp256k1: { Fp: [secp256k1.CURVE.Fp] },
  jubjub: { Fp: [jubjub.CURVE.Fp] },
  ed25519: { Fp: [ed25519.CURVE.Fp] },
  ed448: { Fp: [ed448.CURVE.Fp] },
  bls12: {
    Fp: [bls12_381.fields.Fp],
    Fp2: [
      bls12_381.fields.Fp2,
      fc.array(fc.bigInt(1n, bls12_381.fields.Fp.ORDER - 1n), {
        minLength: 2,
        maxLength: 2,
      }),
      (Fp2, num) => Fp2.fromBigTuple([num[0], num[1]]),
    ],
    // Fp6: [bls12_381.fields.Fp6],
    Fp12: [
      bls12_381.fields.Fp12,
      fc.array(fc.bigInt(1n, bls12_381.fields.Fp.ORDER - 1n), {
        minLength: 12,
        maxLength: 12,
      }),
      (Fp12, num) => Fp12.fromBigTwelve(num),
    ],
  },
  bn254: {
    Fp: [bn254.fields.Fp],
    Fp2: [
      bn254.fields.Fp2,
      fc.array(fc.bigInt(1n, bn254.fields.Fp.ORDER - 1n), {
        minLength: 2,
        maxLength: 2,
      }),
      (Fp2, num) => Fp2.fromBigTuple([num[0], num[1]]),
    ],
    Fp12: [
      bn254.fields.Fp12,
      fc.array(fc.bigInt(1n, bn254.fields.Fp.ORDER - 1n), {
        minLength: 12,
        maxLength: 12,
      }),
      (Fp12, num) => Fp12.fromBigTwelve(num),
    ],
  },
};

// prettier-ignore
const CURVES = {
  secp192r1,
  secp224r1,
  secp256r1,
  secp384r1,
  secp521r1,
  secp256k1,
  ed25519,
  ed25519ctx,
  ed25519ph,
  ed448,
  ed448ph,
  jubjub,
  bls12_381_G1: bls12_381.G1,
  bls12_381_G2: bls12_381.G2,
  // Requires fromHex/toHex
  // bn254_G1: bn254.G1,
  // bn254_G2: bn254.G2,
  ristretto: { ...ed25519, Point: RistrettoPoint, ExtendedPoint: RistrettoPoint },
  decaf: { ...ed448, Point: DecafPoint, ExtendedPoint: DecafPoint },
};
Object.assign(CURVES, miscCurves);

for (const c in FIELDS) {
  const curve = FIELDS[c];
  for (const f in curve) {
    const name = `${c}/${f}:`;
    // [Fp]
    // [Fp2, [fc.bigInt, fc.bigInt], Fp2.create]
    const Fp_opts = curve[f];
    const Fp = Fp_opts[0];
    const FC_BIGINT = curve[f][1] ? Fp_opts[1] : fc.bigInt(1n, Fp.ORDER - 1n);
    const create = Fp_opts[2] ? Fp_opts[2].bind(null, Fp) : (num) => Fp.create(num);
    describe(name, () => {
      should('equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            const b = create(num);
            eql(Fp.eql(a, b), true);
            eql(Fp.eql(b, a), true);
          })
        );
      });
      should('non-equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            // TODO: num1 === num2 is FALSE for Fp2
            const a = create(num1);
            const b = create(num2);
            eql(Fp.eql(a, b), num1 === num2);
            eql(Fp.eql(b, a), num1 === num2);
          })
        );
      });
      should('add/subtract/commutativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            eql(Fp.add(a, b), Fp.add(b, a));
          })
        );
      });
      should('add/subtract/associativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            eql(Fp.add(a, Fp.add(b, c)), Fp.add(Fp.add(a, b), c));
          })
        );
      });
      should('add/subtract/x+0=x', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.add(a, Fp.ZERO), a);
          })
        );
      });
      should('add/subtract/x-0=x', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.sub(a, Fp.ZERO), a);
            eql(Fp.sub(a, a), Fp.ZERO);
          })
        );
      });
      should('add/subtract/negate equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num1) => {
            const a = create(num1);
            const b = create(num1);
            eql(Fp.sub(Fp.ZERO, a), Fp.neg(a));
            eql(Fp.sub(a, b), Fp.add(a, Fp.neg(b)));
            eql(Fp.sub(a, b), Fp.add(a, Fp.mul(b, Fp.create(-1n))));
          })
        );
      });
      should('add/subtract/negate', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.neg(a), Fp.sub(Fp.ZERO, a));
            eql(Fp.neg(a), Fp.mul(a, Fp.create(-1n)));
          })
        );
      });
      should('negate(0)', () => {
        eql(Fp.neg(Fp.ZERO), Fp.ZERO);
      });

      should('multiply/commutativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            eql(Fp.mul(a, b), Fp.mul(b, a));
          })
        );
      });
      should('multiply/associativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            eql(Fp.mul(a, Fp.mul(b, c)), Fp.mul(Fp.mul(a, b), c));
          })
        );
      });
      should('multiply/distributivity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            eql(Fp.mul(a, Fp.add(b, c)), Fp.add(Fp.mul(b, a), Fp.mul(c, a)));
          })
        );
      });
      should('multiply/add equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.mul(a, 0n), Fp.ZERO);
            eql(Fp.mul(a, Fp.ZERO), Fp.ZERO);
            eql(Fp.mul(a, 1n), a);
            eql(Fp.mul(a, Fp.ONE), a);
            eql(Fp.mul(a, 2n), Fp.add(a, a));
            eql(Fp.mul(a, 3n), Fp.add(Fp.add(a, a), a));
            eql(Fp.mul(a, 4n), Fp.add(Fp.add(Fp.add(a, a), a), a));
          })
        );
      });
      should('multiply/square equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.sqr(a), Fp.mul(a, a));
          })
        );
      });
      should('multiply/pow equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.pow(a, 0n), Fp.ONE);
            eql(Fp.pow(a, 1n), a);
            eql(Fp.pow(a, 2n), Fp.mul(a, a));
            eql(Fp.pow(a, 3n), Fp.mul(Fp.mul(a, a), a));
          })
        );
      });

      should('square(0)', () => {
        eql(Fp.sqr(Fp.ZERO), Fp.ZERO);
        eql(Fp.mul(Fp.ZERO, Fp.ZERO), Fp.ZERO);
      });

      should('square(1)', () => {
        eql(Fp.sqr(Fp.ONE), Fp.ONE);
        eql(Fp.mul(Fp.ONE, Fp.ONE), Fp.ONE);
      });

      should('square(-1)', () => {
        const minus1 = Fp.neg(Fp.ONE);
        eql(Fp.sqr(minus1), Fp.ONE);
        eql(Fp.mul(minus1, minus1), Fp.ONE);
      });

      should('FpInvertBatch0', () => {
        const inv0 = (val) => mod.FpInvertBatch(Fp, [val], true)[0];
        eql(inv0(Fp.ZERO), Fp.ZERO);
        const i16 = Fp.mul(Fp.ONE, 16n);
        const i4 = Fp.mul(Fp.ONE, 4n);
        eql(Fp.eql(Fp.mul(i16, inv0(i4)), i4), true); // 16/4 == 4
      });

      // Not implemented
      if (Fp !== bls12_381.fields.Fp12 && Fp !== bn254.fields.Fp12) {
        should('multiply/sqrt', () => {
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const a = create(num);
              let root;
              try {
                root = Fp.sqrt(a);
              } catch (e) {
                eql(mod.FpIsSquare(Fp, a), false);
                return;
              }
              eql(mod.FpIsSquare(Fp, a), true);
              eql(Fp.eql(Fp.sqr(root), a), true, 'sqrt(a)^2 == a');
              eql(Fp.eql(Fp.sqr(Fp.neg(root)), a), true, '(-sqrt(a))^2 == a');
              // Returns odd/even element
              eql(Fp.isOdd(mod.FpSqrtOdd(Fp, a)), true);
              eql(Fp.isOdd(mod.FpSqrtEven(Fp, a)), false);
              eql(Fp.eql(Fp.sqr(mod.FpSqrtOdd(Fp, a)), a), true);
              eql(Fp.eql(Fp.sqr(mod.FpSqrtEven(Fp, a)), a), true);
            })
          );
        });

        should('sqrt(0)', () => {
          eql(Fp.sqrt(Fp.ZERO), Fp.ZERO);
          const sqrt1 = Fp.sqrt(Fp.ONE);
          eql(Fp.eql(sqrt1, Fp.ONE) || Fp.eql(sqrt1, Fp.neg(Fp.ONE)), true, 'sqrt(1) = 1 or -1');
        });
      }

      should('div/division by one equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            if (Fp.eql(a, Fp.ZERO)) return; // No division by zero
            eql(Fp.div(a, Fp.ONE), a);
            eql(Fp.div(a, a), Fp.ONE);
            // FpDiv tests
            eql(mod.FpDiv(Fp, a, Fp.ONE), a);
            eql(mod.FpDiv(Fp, a, a), Fp.ONE);
          })
        );
      });
      should('zero division equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.div(Fp.ZERO, a), Fp.ZERO);
            eql(mod.FpDiv(Fp, Fp.ZERO, a), Fp.ZERO);
          })
        );
      });
      should('div/division distributivity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            eql(Fp.div(Fp.add(a, b), c), Fp.add(Fp.div(a, c), Fp.div(b, c)));
            eql(mod.FpDiv(Fp, Fp.add(a, b), c), Fp.add(mod.FpDiv(Fp, a, c), mod.FpDiv(Fp, b, c)));
          })
        );
      });
      should('div/division and multiplication equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            eql(Fp.div(a, b), Fp.mul(a, Fp.inv(b)));
          })
        );
      });
    });
  }
}

// Group tests
const getXY = (p) => ({ x: p.x, y: p.y });

function equal(a, b, comment) {
  eql(a.equals(b), true, `eq(${comment})`);
  if (a.toAffine && b.toAffine) {
    eql(getXY(a.toAffine()), getXY(b.toAffine()), `eqToAffine(${comment})`);
  } else if (!a.toAffine && !b.toAffine) {
    // Already affine
    eql(getXY(a), getXY(b), `eqAffine(${comment})`);
  } else throw new Error('Different point types');
}

for (const name in CURVES) {
  const C = CURVES[name];
  const CURVE_ORDER = C.CURVE.n;
  const FC_BIGINT = fc.bigInt(1n + 1n, CURVE_ORDER - 1n);

  // Check that curve doesn't accept points from other curves
  const O = name === 'secp256k1' ? secp256r1 : secp256k1;
  const POINTS = {};
  const OTHER_POINTS = {};
  for (const name of ['Point', 'ProjectivePoint', 'ExtendedPoint', 'ProjectivePoint']) {
    POINTS[name] = C[name];
    OTHER_POINTS[name] = O[name];
  }

  for (const pointName in POINTS) {
    const p = POINTS[pointName];
    const o = OTHER_POINTS[pointName];
    if (!p) continue;

    const G = [p.ZERO, p.BASE];
    for (let i = 2n; i < 10n; i++) G.push(G[1].multiply(i));
    const title = `${name}/${pointName}`;
    describe(title, () => {
      describe('basic group laws', () => {
        // Here we check basic group laws, to verify that points works as group
        should('zero', () => {
          equal(G[0].double(), G[0], '(0*G).double() = 0');
          equal(G[0].add(G[0]), G[0], '0*G + 0*G = 0');
          equal(G[0].subtract(G[0]), G[0], '0*G - 0*G = 0');
          equal(G[0].negate(), G[0], '-0 = 0');
          for (let i = 0; i < G.length; i++) {
            const p = G[i];
            equal(p, p.add(G[0]), `${i}*G + 0 = ${i}*G`);
            equal(G[0].multiply(BigInt(i + 1)), G[0], `${i + 1}*0 = 0`);
          }
        });
        should('one', () => {
          equal(G[1].double(), G[2], '(1*G).double() = 2*G');
          equal(G[1].subtract(G[1]), G[0], '1*G - 1*G = 0');
          equal(G[1].add(G[1]), G[2], '1*G + 1*G = 2*G');
        });
        should('sanity tests', () => {
          equal(G[2].double(), G[4], '(2*G).double() = 4*G');
          equal(G[2].add(G[2]), G[4], '2*G + 2*G = 4*G');
          equal(G[7].add(G[3].negate()), G[4], '7*G - 3*G = 4*G');
        });
        should('add commutativity', () => {
          equal(G[4].add(G[3]), G[3].add(G[4]), '4*G + 3*G = 3*G + 4*G');
          equal(G[4].add(G[3]), G[3].add(G[2]).add(G[2]), '4*G + 3*G = 3*G + 2*G + 2*G');
        });
        should('double', () => {
          equal(G[3].double(), G[6], '(3*G).double() = 6*G');
        });
        should('multiply', () => {
          equal(G[2].multiply(3n), G[6], '(2*G).multiply(3) = 6*G');
        });
        should('add same-point', () => {
          equal(G[3].add(G[3]), G[6], '3*G + 3*G = 6*G');
        });
        should('add same-point negative', () => {
          equal(G[3].add(G[3].negate()), G[0], '3*G + (- 3*G) = 0*G');
          equal(G[3].subtract(G[3]), G[0], '3*G - 3*G = 0*G');
        });
        should('mul by curve order', () => {
          equal(G[1].multiply(CURVE_ORDER - 1n).add(G[1]), G[0], '(N-1)*G + G = 0');
          equal(G[1].multiply(CURVE_ORDER - 1n).add(G[2]), G[1], '(N-1)*G + 2*G = 1*G');
          equal(G[1].multiply(CURVE_ORDER - 2n).add(G[2]), G[0], '(N-2)*G + 2*G = 0');
          const half = CURVE_ORDER / 2n;
          const carry = CURVE_ORDER % 2n === 1n ? G[1] : G[0];
          equal(G[1].multiply(half).double().add(carry), G[0], '((N/2) * G).double() = 0');
        });
        should('inversion', () => {
          const a = 1234n;
          const b = 5678n;
          const c = a * b;
          equal(G[1].multiply(a).multiply(b), G[1].multiply(c), 'a*b*G = c*G');
          const inv = mod.invert(b, CURVE_ORDER);
          equal(G[1].multiply(c).multiply(inv), G[1].multiply(a), 'c*G * (1/b)*G = a*G');
        });
        should('multiply, rand', () =>
          fc.assert(
            fc.property(FC_BIGINT, FC_BIGINT, (a, b) => {
              const c = mod.mod(a + b, CURVE_ORDER);
              if (c === CURVE_ORDER || c < 1n) return;
              const pA = G[1].multiply(a);
              const pB = G[1].multiply(b);
              const pC = G[1].multiply(c);
              equal(pA.add(pB), pB.add(pA), 'pA + pB = pB + pA');
              equal(pA.add(pB), pC, 'pA + pB = pC');
            }),
            { numRuns: NUM_RUNS }
          )
        );
        should('multiply2, rand', () =>
          fc.assert(
            fc.property(FC_BIGINT, FC_BIGINT, (a, b) => {
              const c = mod.mod(a * b, CURVE_ORDER);
              const pA = G[1].multiply(a);
              const pB = G[1].multiply(b);
              equal(pA.multiply(b), pB.multiply(a), 'b*pA = a*pB');
              equal(pA.multiply(b), G[1].multiply(c), 'b*pA = c*G');
            }),
            { numRuns: NUM_RUNS }
          )
        );
      });

      // special case for add, subtract, equals, multiply. NOT multiplyUnsafe
      // [0n, '0n'],

      for (const op of ['add', 'subtract']) {
        describe(op, () => {
          should('type check', () => {
            for (let [item, repr_] of getTypeTests()) {
              throws(() => G[1][op](item), repr_);
            }
            throws(() => G[1][op](0), '0');
            throws(() => G[1][op](0n), '0n');
            G[1][op](G[2]);
            throws(() => G[1][op](CURVE_ORDER), 'CURVE_ORDER');
            throws(() => G[1][op]({ x: 1n, y: 1n }), '{ x: 1n, y: 1n }');
            throws(() => G[1][op]({ x: 1n, y: 1n, z: 1n }), '{ x: 1n, y: 1n, z: 1n }');
            throws(
              () => G[1][op]({ x: 1n, y: 1n, z: 1n, t: 1n }),
              '{ x: 1n, y: 1n, z: 1n, t: 1n }'
            );
            // if (G[1].toAffine) throws(() => G[1][op](C.Point.BASE), `Point ${op} ${pointName}`);
            throws(() => G[1][op](o.BASE), `${op}/other curve point`);
          });
        });
      }

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
        // if (G[1].toAffine) throws(() => G[1].equals(C.Point.BASE), 'Point.equals(${pointName})');
        throws(() => G[1].equals(o.BASE), 'other curve point');
      });

      for (const op of ['multiply', 'multiplyUnsafe']) {
        if (!p.BASE[op]) continue;
        describe(op, () => {
          should('type check', () => {
            for (let [item, repr_] of getTypeTests()) {
              throws(() => G[1][op](item), repr_);
            }
            G[1][op](1n);
            G[1][op](CURVE_ORDER - 1n);
            throws(() => G[1][op](G[2]), 'G[2]');
            throws(() => G[1][op](CURVE_ORDER), 'CURVE_ORDER');
            throws(() => G[1][op](CURVE_ORDER + 1n), 'CURVE_ORDER+1');
            throws(() => G[1][op](o.BASE), 'other curve point');
            if (op !== 'multiplyUnsafe') {
              throws(() => G[1][op](0), '0');
              throws(() => G[1][op](0n), '0n');
            }
          });
        });
      }

      describe('multiscalar multiplication', () => {
        should('MSM basic', () => {
          const msm = p.msm;
          equal(msm([p.BASE], [0n]), p.ZERO, '0*G');
          equal(msm([], []), p.ZERO, 'empty');
          equal(msm([p.ZERO], [123n]), p.ZERO, '123 * Infinity');
          equal(msm([p.BASE], [123n]), p.BASE.multiply(123n), '123 * G');
          const points = [p.BASE, p.BASE.multiply(2n), p.BASE.multiply(4n), p.BASE.multiply(8n)];
          // 1*3 + 5*2 + 4*7 + 11*8 = 129
          equal(msm(points, [3n, 5n, 7n, 11n]), p.BASE.multiply(129n), '129 * G');
        });
        should('MSM random', () =>
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
              total = mod.mod(total, CURVE_ORDER);
              const exp = total ? p.BASE.multiply(total) : p.ZERO;
              equal(p.msm(points, scalars), exp, 'total');
            }),
            { numRuns: NUM_RUNS }
          )
        );
        should('precomputeMSMUnsafe basic', () => {
          return;
          const Point = C.Point || C.ExtendedPoint || C.ProjectivePoint;
          if (!Point) throw new Error('Unknown point');
          const field = Field(CURVE_ORDER);

          const points = [p.BASE, p.BASE.multiply(2n), p.BASE.multiply(4n), p.BASE.multiply(8n)];
          const scalars = [3n, 5n, 7n, 11n];
          const res = p.BASE.multiply(129n);
          for (let windowSize = 1; windowSize <= 10; windowSize++) {
            const mul = precomputeMSMUnsafe(Point, field, points, windowSize);
            equal(mul(scalars), res, 'windowSize=' + windowSize);
          }
        });
        should('precomputeMSMUnsafe random', () =>
          fc.assert(
            fc.property(fc.array(fc.tuple(FC_BIGINT, FC_BIGINT)), FC_BIGINT, (pairs) => {
              return;
              const Point = C.Point || C.ExtendedPoint || C.ProjectivePoint;
              if (!Point) throw new Error('Unknown point');
              const field = Field(CURVE_ORDER);

              let total = 0n;
              const scalars = [];
              const points = [];
              for (const [ps, s] of pairs) {
                points.push(p.BASE.multiply(ps));
                scalars.push(s);
                total += ps * s;
              }
              total = mod.mod(total, CURVE_ORDER);
              const res = total ? p.BASE.multiply(total) : p.ZERO;

              for (let windowSize = 1; windowSize <= 10; windowSize++) {
                const mul = precomputeMSMUnsafe(Point, field, points, windowSize);
                equal(mul(scalars), res, 'windowSize=' + windowSize);
              }
            }),
            { numRuns: NUM_RUNS }
          )
        );
      });

      // Complex point (Extended/Jacobian/Projective?)
      // if (p.BASE.toAffine && C.Point) {
      //   should('toAffine()', () => {
      //     equal(p.ZERO.toAffine(), C.Point.ZERO, '0 = 0');
      //     equal(p.BASE.toAffine(), C.Point.BASE, '1 = 1');
      //   });
      // }
      // if (p.fromAffine && C.Point) {
      //   should('fromAffine()', () => {
      //     equal(p.ZERO, p.fromAffine(C.Point.ZERO), '0 = 0');
      //     equal(p.BASE, p.fromAffine(C.Point.BASE), '1 = 1');
      //   });
      // }
      // toHex/fromHex (if available)
      if (p.fromHex && p.BASE.toHex) {
        should('fromHex(toHex(compressed=false)) roundtrip', () => {
          fc.assert(
            fc.property(FC_BIGINT, (x) => {
              const point = p.BASE.multiply(x);
              const isComp = false;
              const hex1 = point.toHex(isComp);
              const bytes1 = point.toBytes(isComp);
              // eql(p.fromHex(hex1).toHex(isComp), hex1);
              eql(p.fromHex(bytes1).toHex(isComp), hex1);
            })
          );
        });
        should('fromHex(toHex(compressed=true)) roundtrip', () => {
          fc.assert(
            fc.property(FC_BIGINT, (x) => {
              const point = p.BASE.multiply(x);
              const isComp = true;
              const hex1 = point.toHex(isComp);
              const bytes1 = point.toBytes(isComp);
              // eql(p.fromHex(hex1).toHex(isComp), hex1);
              eql(p.fromHex(bytes1).toHex(isComp), hex1);
            })
          );
        });
      }
    });
  }
  describe(name, () => {
    // Generic complex things (getPublicKey/sign/verify/getSharedSecret)
    should('.getPublicKey() type check', () => {
      for (let [item, repr_] of getTypeTests()) {
        throws(() => C.getPublicKey(item), repr_);
      }
      // NOTE: passes because of disabled hex padding checks for starknet, maybe enable?
      if (name !== 'starknet') {
        // throws(() => C.getPublicKey('1'), "'1'");
      }
      throws(() => C.getPublicKey('key'), "'key'");
      throws(() => C.getPublicKey({}));
      throws(() => C.getPublicKey(new Uint8Array([])));
      throws(() => C.getPublicKey(Array(32).fill(1)));
    });

    if (C.verify) {
      //if (C.verify)
      should('.verify() should verify random signatures', () =>
        fc.assert(
          fc.property(FC_HEX, (msg) => {
            const priv = C.utils.randomPrivateKey();
            const pub = C.getPublicKey(priv);
            const sig = C.sign(msg, priv);
            eql(C.verify(sig, msg, pub), true, `priv=${toHex(priv)},pub=${toHex(pub)},msg=${msg}`);
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('.verify() should verify random signatures in hex', () =>
        fc.assert(
          fc.property(FC_HEX, (msg) => {
            const priv = toHex(C.utils.randomPrivateKey());
            const pub = toHex(C.getPublicKey(priv));
            const sig = C.sign(msg, priv);
            let sighex = isBytes(sig) ? toHex(sig) : sig.toCompactHex();
            eql(C.verify(sighex, msg, pub), true, `priv=${priv},pub=${pub},msg=${msg}`);
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('.verify() should verify empty signatures', () => {
        const msg = new Uint8Array([]);
        const priv = C.utils.randomPrivateKey();
        const pub = C.getPublicKey(priv);
        const sig = C.sign(msg, priv);
        eql(C.verify(sig, msg, pub), true, 'priv=${toHex(priv)},pub=${toHex(pub)},msg=${msg}');
      });

      should('.sign() type tests', () => {
        const msg = new Uint8Array([]);
        const priv = C.utils.randomPrivateKey();
        C.sign(msg, priv);
        for (let [item, repr_] of getTypeTests()) {
          throws(() => C.sign(msg, item), repr_);
          if (!repr_.startsWith('ui8a') && repr_ !== '""') {
            throws(() => C.sign(item, priv), repr_);
          }
        }
      });
      should('.sign() edge cases', () => {
        throws(() => C.sign());
        throws(() => C.sign(''));
        throws(() => C.sign('', ''));
        throws(() => C.sign(Uint8Array.of(), Uint8Array.of()));
      });

      describe('verify()', () => {
        const msg = '01'.repeat(32);
        const msgWrong = '11'.repeat(32);
        should('true for proper signatures', () => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(msg, priv);
          const pub = C.getPublicKey(priv);
          eql(C.verify(sig, msg, pub), true);
        });
        should('false for wrong messages', () => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(msg, priv);
          const pub = C.getPublicKey(priv);
          eql(C.verify(sig, msgWrong, pub), false);
        });
        should('false for wrong keys', () => {
          const priv = C.utils.randomPrivateKey();
          const pub2 = C.getPublicKey(C.utils.randomPrivateKey());
          const sig = C.sign(msg, priv);
          eql(C.verify(sig, msg, pub2), false);
        });
        should('type tests', () => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(msg, priv);
          const pub = C.getPublicKey(priv);
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
      should('Signature serialization roundtrip', () =>
        fc.assert(
          fc.property(FC_HEX, (msg) => {
            const priv = C.utils.randomPrivateKey();
            const sig = C.sign(msg, priv);
            const sigRS = (sig) => ({ s: sig.s, r: sig.r });
            // Compact
            eql(sigRS(C.Signature.fromCompact(sig.toCompactHex())), sigRS(sig));
            eql(sigRS(C.Signature.fromCompact(sig.toCompactRawBytes())), sigRS(sig));
            // DER
            eql(sigRS(C.Signature.fromDER(sig.toDERHex())), sigRS(sig));
            eql(sigRS(C.Signature.fromDER(sig.toDERRawBytes())), sigRS(sig));
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('Signature.addRecoveryBit/Signature.recoverPublicKey', () =>
        fc.assert(
          fc.property(FC_HEX, (msg) => {
            if (C.CURVE.h >= 2n) return;
            // if (/secp128r2|secp224k1|bls|mnt/i.test(name)) return;
            const priv = C.utils.randomPrivateKey();
            const pub = C.getPublicKey(priv);
            const sig = C.sign(msg, priv);
            eql(sig.recoverPublicKey(msg).toBytes(), pub);
            const sig2 = C.Signature.fromCompact(sig.toCompactHex());
            throws(() => sig2.recoverPublicKey(msg));
            const sig3 = sig2.addRecoveryBit(sig.recovery);
            eql(sig3.recoverPublicKey(msg).toBytes(), pub);
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('Signature.normalizeS', () =>
        fc.assert(
          fc.property(FC_HEX, (msg) => {
            const priv = C.utils.randomPrivateKey();
            const pub = C.getPublicKey(priv);
            const sig = C.sign(msg, priv, { lowS: false });
            if (!sig.hasHighS()) return;
            const sigNorm = sig.normalizeS();
            eql(sigNorm.hasHighS(), false, 'a');

            eql(C.verify(sig, msg, pub, { lowS: false }), true, 'b');
            eql(C.verify(sig, msg, pub, { lowS: true }), false, 'c');
            eql(C.verify(sigNorm, msg, pub, { lowS: true }), true, 'd');
            eql(C.verify(sigNorm, msg, pub, { lowS: false }), true, 'e');
          }),
          { numRuns: NUM_RUNS }
        )
      );
    }

    // NOTE: fails for ed, because of empty message. Since we convert it to scalar,
    // need to check what other implementations do. Empty message != new Uint8Array([0]), but what scalar should be in that case?
    // should('should not verify signature with wrong message', () => {
    //   fc.assert(
    //     fc.property(
    //       fc.array(fc.integer({ min: 0x00, max: 0xff })),
    //       fc.array(fc.integer({ min: 0x00, max: 0xff })),
    //       (bytes, wrongBytes) => {
    //         const privKey = C.utils.randomPrivateKey();
    //         const message = new Uint8Array(bytes);
    //         const wrongMessage = new Uint8Array(wrongBytes);
    //         const publicKey = C.getPublicKey(privKey);
    //         const signature = C.sign(message, privKey);
    //         deepStrictEqual(
    //           C.verify(signature, wrongMessage, publicKey),
    //           bytes.toString() === wrongBytes.toString()
    //         );
    //       }
    //     ),
    //     { numRuns: NUM_RUNS }
    //   );
    // });

    if (C.getSharedSecret) {
      should('getSharedSecret() should be commutative', () => {
        for (let i = 0; i < NUM_RUNS; i++) {
          const asec = C.utils.randomPrivateKey();
          const apub = C.getPublicKey(asec);
          const bsec = C.utils.randomPrivateKey();
          const bpub = C.getPublicKey(bsec);
          try {
            eql(C.getSharedSecret(asec, bpub), C.getSharedSecret(bsec, apub));
          } catch (error) {
            console.error('not commutative', { asec, apub, bsec, bpub });
            throw error;
          }
        }
      });
    }
  });
}

describe('edge cases', () => {
  should('bigInt private keys', () => {
    // Doesn't support bigints anymore
    throws(() => ed25519.sign(Uint8Array.of(), 123n));
    throws(() => ed25519.getPublicKey(123n));
    throws(() => x25519.getPublicKey(123n));
    // Weierstrass still supports
    secp256k1.getPublicKey(123n);
    secp256k1.sign(Uint8Array.of(), 123n);
  });

  should('secp224k1 sqrt bug', () => {
    const { Fp } = secp224r1.CURVE;
    const sqrtMinus1 = Fp.sqrt(-1n);
    // Verified against sage
    eql(sqrtMinus1, 23621584063597419797792593680131996961517196803742576047493035507225n);
    eql(Fp.neg(sqrtMinus1), 3338362603553219996874421406887633712040719456283732096017030791656n);
    eql(Fp.sqr(sqrtMinus1), Fp.create(-1n));
  });

  should('Field: prohibit non-prime sqrt. gh-168', () => {
    const Fp =
      Field(21888242871839275222246405745257275088548364400416034343698204186575808495617n);
    throws(() =>
      mod.tonelliShanks(
        21888242871839275222246405745257275088614511777268538073601725287587578984328n
      )
    );
    const babyJubNoble = twistedEdwards({
      a: Fp.create(168700n),
      d: Fp.create(168696n),
      Fp: Fp,
      n: 21888242871839275222246405745257275088614511777268538073601725287587578984328n,
      h: 8n,
      Gx: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
      Gy: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
      hash: sha512,
      randomBytes,
    });
  });
});

describe('createCurve', () => {
  describe('handles wycheproof vectors', () => {
    const VECTORS = wyche_curves.testGroups[0].tests;
    for (const v of VECTORS) {
      should(`${v.name}`, () => {
        const CURVE = createCurve(
          {
            Fp: Field(BigInt(`0x${v.p}`)),
            a: BigInt(`0x${v.a}`),
            b: BigInt(`0x${v.b}`),
            n: BigInt(`0x${v.n}`),
            h: BigInt(v.h),
            Gx: BigInt(`0x${v.gx}`),
            Gy: BigInt(`0x${v.gy}`),
          },
          sha256
        );
      });
      const CURVE = CURVES[v.name];
      if (!CURVE) continue;
      should(`${v.name} parms verify`, () => {
        eql(CURVE.CURVE.Fp.ORDER, BigInt(`0x${v.p}`));
        eql(CURVE.CURVE.a, BigInt(`0x${v.a}`));
        eql(CURVE.CURVE.b, BigInt(`0x${v.b}`));
        eql(CURVE.CURVE.n, BigInt(`0x${v.n}`));
        eql(CURVE.CURVE.Gx, BigInt(`0x${v.gx}`));
        eql(CURVE.CURVE.Gy, BigInt(`0x${v.gy}`));
        eql(CURVE.CURVE.h, BigInt(v.h));
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
});

describe('Pairings', () => {
  const pairingCurves = { bls12_381, bn254 };

  for (const [name, curve] of Object.entries(pairingCurves)) {
    describe(name, () => {
      const { pairing } = curve;
      const { Fp12 } = curve.fields;
      const G1Point = curve.G1.ProjectivePoint;
      const G2Point = curve.G2.ProjectivePoint;
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
