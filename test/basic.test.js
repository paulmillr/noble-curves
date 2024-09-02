import { json } from './utils.js';
import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import { should, describe } from 'micro-should';
import * as fc from 'fast-check';
import * as mod from '../esm/abstract/modular.js';
import { bytesToHex, isBytes, bytesToHex as toHex } from '../esm/abstract/utils.js';
// Generic tests for all curves in package
import { secp192r1, secp224r1 } from './_more-curves.helpers.js';
import { secp256r1 } from '../esm/p256.js';
import { secp384r1 } from '../esm/p384.js';
import { secp521r1 } from '../esm/p521.js';
import { secp256k1 } from '../esm/secp256k1.js';
import { ed25519, ed25519ctx, ed25519ph, x25519 } from '../esm/ed25519.js';
import { ed448, ed448ph } from '../esm/ed448.js';
import { pallas, vesta } from '../esm/pasta.js';
import { bn254_weierstrass } from '../esm/bn254.js';
import { jubjub } from '../esm/jubjub.js';
import { bls12_381 } from '../esm/bls12-381.js';
import { createCurve } from '../esm/_shortw_utils.js';
import { Field } from '../esm/abstract/modular.js';
import { sha256 } from '@noble/hashes/sha256';
import { bn254 } from '../esm/bn254.js';
const wyche_curves = json('./wycheproof/ec_prime_order_curves_test.json');

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
  bn254_weierstrass: { Fp: [bn254_weierstrass.CURVE.Fp] },
  pallas: { Fp: [pallas.CURVE.Fp] },
  vesta: { Fp: [vesta.CURVE.Fp] },
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
    // Fp6: [bls12_381.fields.Fp6],
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
  secp192r1, secp224r1, secp256r1, secp384r1, secp521r1,
  secp256k1,
  ed25519, ed25519ctx, ed25519ph,
  ed448, ed448ph,
  pallas, vesta,
  bn254: bn254_weierstrass,
  jubjub,
  bls12_381_G1: bls12_381.G1, bls12_381_G2: bls12_381.G2,
  // Requires fromHex/toHex
  // alt_bn128_G1: alt_bn128.G1, alt_bn128_G2: alt_bn128.G2,
};

const PAIRINGS = { bls12_381, bn254 };

for (const c in FIELDS) {
  const curve = FIELDS[c];
  for (const f in curve) {
    const Fp = curve[f][0];
    const name = `${c}/${f}:`;
    const FC_BIGINT = curve[f][1] ? curve[f][1] : fc.bigInt(1n, Fp.ORDER - 1n);

    const create = curve[f][2] ? curve[f][2].bind(null, Fp) : (num) => Fp.create(num);
    describe(name, () => {
      should('equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            const b = create(num);
            deepStrictEqual(Fp.eql(a, b), true);
            deepStrictEqual(Fp.eql(b, a), true);
          })
        );
      });
      should('non-equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            deepStrictEqual(Fp.eql(a, b), num1 === num2);
            deepStrictEqual(Fp.eql(b, a), num1 === num2);
          })
        );
      });
      should('add/subtract/commutativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            deepStrictEqual(Fp.add(a, b), Fp.add(b, a));
          })
        );
      });
      should('add/subtract/associativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            deepStrictEqual(Fp.add(a, Fp.add(b, c)), Fp.add(Fp.add(a, b), c));
          })
        );
      });
      should('add/subtract/x+0=x', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.add(a, Fp.ZERO), a);
          })
        );
      });
      should('add/subtract/x-0=x', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.sub(a, Fp.ZERO), a);
            deepStrictEqual(Fp.sub(a, a), Fp.ZERO);
          })
        );
      });
      should('add/subtract/negate equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num1) => {
            const a = create(num1);
            const b = create(num1);
            deepStrictEqual(Fp.sub(Fp.ZERO, a), Fp.neg(a));
            deepStrictEqual(Fp.sub(a, b), Fp.add(a, Fp.neg(b)));
            deepStrictEqual(Fp.sub(a, b), Fp.add(a, Fp.mul(b, Fp.create(-1n))));
          })
        );
      });
      should('add/subtract/negate', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.neg(a), Fp.sub(Fp.ZERO, a));
            deepStrictEqual(Fp.neg(a), Fp.mul(a, Fp.create(-1n)));
          })
        );
      });
      should('negate(0)', () => {
        deepStrictEqual(Fp.neg(Fp.ZERO), Fp.ZERO);
      });

      should('multiply/commutativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            deepStrictEqual(Fp.mul(a, b), Fp.mul(b, a));
          })
        );
      });
      should('multiply/associativity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            deepStrictEqual(Fp.mul(a, Fp.mul(b, c)), Fp.mul(Fp.mul(a, b), c));
          })
        );
      });
      should('multiply/distributivity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            deepStrictEqual(Fp.mul(a, Fp.add(b, c)), Fp.add(Fp.mul(b, a), Fp.mul(c, a)));
          })
        );
      });
      should('multiply/add equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.mul(a, 0n), Fp.ZERO);
            deepStrictEqual(Fp.mul(a, Fp.ZERO), Fp.ZERO);
            deepStrictEqual(Fp.mul(a, 1n), a);
            deepStrictEqual(Fp.mul(a, Fp.ONE), a);
            deepStrictEqual(Fp.mul(a, 2n), Fp.add(a, a));
            deepStrictEqual(Fp.mul(a, 3n), Fp.add(Fp.add(a, a), a));
            deepStrictEqual(Fp.mul(a, 4n), Fp.add(Fp.add(Fp.add(a, a), a), a));
          })
        );
      });
      should('multiply/square equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.sqr(a), Fp.mul(a, a));
          })
        );
      });
      should('multiply/pow equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.pow(a, 0n), Fp.ONE);
            deepStrictEqual(Fp.pow(a, 1n), a);
            deepStrictEqual(Fp.pow(a, 2n), Fp.mul(a, a));
            deepStrictEqual(Fp.pow(a, 3n), Fp.mul(Fp.mul(a, a), a));
          })
        );
      });

      should('square(0)', () => {
        deepStrictEqual(Fp.sqr(Fp.ZERO), Fp.ZERO);
        deepStrictEqual(Fp.mul(Fp.ZERO, Fp.ZERO), Fp.ZERO);
      });

      should('square(1)', () => {
        deepStrictEqual(Fp.sqr(Fp.ONE), Fp.ONE);
        deepStrictEqual(Fp.mul(Fp.ONE, Fp.ONE), Fp.ONE);
      });

      should('square(-1)', () => {
        const minus1 = Fp.neg(Fp.ONE);
        deepStrictEqual(Fp.sqr(minus1), Fp.ONE);
        deepStrictEqual(Fp.mul(minus1, minus1), Fp.ONE);
      });

      const isSquare = mod.FpIsSquare(Fp);
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
                deepStrictEqual(isSquare(a), false);
                return;
              }
              deepStrictEqual(isSquare(a), true);
              deepStrictEqual(Fp.eql(Fp.sqr(root), a), true, 'sqrt(a)^2 == a');
              deepStrictEqual(Fp.eql(Fp.sqr(Fp.neg(root)), a), true, '(-sqrt(a))^2 == a');
              // Returns odd/even element
              deepStrictEqual(Fp.isOdd(mod.FpSqrtOdd(Fp, a)), true);
              deepStrictEqual(Fp.isOdd(mod.FpSqrtEven(Fp, a)), false);
              deepStrictEqual(Fp.eql(Fp.sqr(mod.FpSqrtOdd(Fp, a)), a), true);
              deepStrictEqual(Fp.eql(Fp.sqr(mod.FpSqrtEven(Fp, a)), a), true);
            })
          );
        });

        should('sqrt(0)', () => {
          deepStrictEqual(Fp.sqrt(Fp.ZERO), Fp.ZERO);
          const sqrt1 = Fp.sqrt(Fp.ONE);
          deepStrictEqual(
            Fp.eql(sqrt1, Fp.ONE) || Fp.eql(sqrt1, Fp.neg(Fp.ONE)),
            true,
            'sqrt(1) = 1 or -1'
          );
        });
      }

      should('div/division by one equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            if (Fp.eql(a, Fp.ZERO)) return; // No division by zero
            deepStrictEqual(Fp.div(a, Fp.ONE), a);
            deepStrictEqual(Fp.div(a, a), Fp.ONE);
            // FpDiv tests
            deepStrictEqual(mod.FpDiv(Fp, a, Fp.ONE), a);
            deepStrictEqual(mod.FpDiv(Fp, a, a), Fp.ONE);
          })
        );
      });
      should('zero division equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            deepStrictEqual(Fp.div(Fp.ZERO, a), Fp.ZERO);
            deepStrictEqual(mod.FpDiv(Fp, Fp.ZERO, a), Fp.ZERO);
          })
        );
      });
      should('div/division distributivity', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            deepStrictEqual(Fp.div(Fp.add(a, b), c), Fp.add(Fp.div(a, c), Fp.div(b, c)));
            deepStrictEqual(
              mod.FpDiv(Fp, Fp.add(a, b), c),
              Fp.add(mod.FpDiv(Fp, a, c), mod.FpDiv(Fp, b, c))
            );
          })
        );
      });
      should('div/division and multiplication equality', () => {
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
            const a = create(num1);
            const b = create(num2);
            deepStrictEqual(Fp.div(a, b), Fp.mul(a, Fp.inv(b)));
          })
        );
      });
    });
  }
}

// Group tests

const NUM_RUNS = 5;

const getXY = (p) => ({ x: p.x, y: p.y });

function equal(a, b, comment) {
  deepStrictEqual(a.equals(b), true, `eq(${comment})`);
  if (a.toAffine && b.toAffine) {
    deepStrictEqual(getXY(a.toAffine()), getXY(b.toAffine()), `eqToAffine(${comment})`);
  } else if (!a.toAffine && !b.toAffine) {
    // Already affine
    deepStrictEqual(getXY(a), getXY(b), `eqAffine(${comment})`);
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
        should('MSM (basic)', () => {
          equal(p.msm([p.BASE], [0n]), p.ZERO, '0*G');
          equal(p.msm([], []), p.ZERO, 'empty');
          equal(p.msm([p.ZERO], [123n]), p.ZERO, '123 * Infinity');
          equal(p.msm([p.BASE], [123n]), p.BASE.multiply(123n), '123 * G');
          const points = [p.BASE, p.BASE.multiply(2n), p.BASE.multiply(4n), p.BASE.multiply(8n)];
          // 1*3 + 5*2 + 4*7 + 11*8 = 129
          equal(p.msm(points, [3n, 5n, 7n, 11n]), p.BASE.multiply(129n), '129 * G');
        });
        should('MSM (rand)', () =>
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
      });

      for (const op of ['add', 'subtract']) {
        describe(op, () => {
          should('type check', () => {
            throws(() => G[1][op](0), '0');
            throws(() => G[1][op](0n), '0n');
            G[1][op](G[2]);
            throws(() => G[1][op](CURVE_ORDER), 'CURVE_ORDER');
            throws(() => G[1][op](-123n), '-123n');
            throws(() => G[1][op](123), '123');
            throws(() => G[1][op](123.456), '123.456');
            throws(() => G[1][op](true), 'true');
            throws(() => G[1][op](false), 'false');
            throws(() => G[1][op](null), 'null');
            throws(() => G[1][op](undefined), 'undefined');
            throws(() => G[1][op]('1'), "'1'");
            throws(() => G[1][op]({ x: 1n, y: 1n }), '{ x: 1n, y: 1n }');
            throws(() => G[1][op]({ x: 1n, y: 1n, z: 1n }), '{ x: 1n, y: 1n, z: 1n }');
            throws(
              () => G[1][op]({ x: 1n, y: 1n, z: 1n, t: 1n }),
              '{ x: 1n, y: 1n, z: 1n, t: 1n }'
            );
            throws(() => G[1][op](new Uint8Array([])), 'ui8a([])');
            throws(() => G[1][op](new Uint8Array([0])), 'ui8a([0])');
            throws(() => G[1][op](new Uint8Array([1])), 'ui8a([1])');
            throws(() => G[1][op](new Uint8Array(4096).fill(1)), 'ui8a(4096*[1])');
            // if (G[1].toAffine) throws(() => G[1][op](C.Point.BASE), `Point ${op} ${pointName}`);
            throws(() => G[1][op](o.BASE), `${op}/other curve point`);
          });
        });
      }

      should('equals type check', () => {
        throws(() => G[1].equals(0), '0');
        throws(() => G[1].equals(0n), '0n');
        deepStrictEqual(G[1].equals(G[2]), false, '1*G != 2*G');
        deepStrictEqual(G[1].equals(G[1]), true, '1*G == 1*G');
        deepStrictEqual(G[2].equals(G[2]), true, '2*G == 2*G');
        throws(() => G[1].equals(CURVE_ORDER), 'CURVE_ORDER');
        throws(() => G[1].equals(123.456), '123.456');
        throws(() => G[1].equals(true), 'true');
        throws(() => G[1].equals('1'), "'1'");
        throws(() => G[1].equals({ x: 1n, y: 1n, z: 1n, t: 1n }), '{ x: 1n, y: 1n, z: 1n, t: 1n }');
        throws(() => G[1].equals(new Uint8Array([])), 'ui8a([])');
        throws(() => G[1].equals(new Uint8Array([0])), 'ui8a([0])');
        throws(() => G[1].equals(new Uint8Array([1])), 'ui8a([1])');
        throws(() => G[1].equals(new Uint8Array(4096).fill(1)), 'ui8a(4096*[1])');
        // if (G[1].toAffine) throws(() => G[1].equals(C.Point.BASE), 'Point.equals(${pointName})');
        throws(() => G[1].equals(o.BASE), 'other curve point');
      });

      for (const op of ['multiply', 'multiplyUnsafe']) {
        if (!p.BASE[op]) continue;
        describe(op, () => {
          should('type check', () => {
            if (op !== 'multiplyUnsafe') {
              throws(() => G[1][op](0), '0');
              throws(() => G[1][op](0n), '0n');
            }
            G[1][op](1n);
            G[1][op](CURVE_ORDER - 1n);
            throws(() => G[1][op](G[2]), 'G[2]');
            throws(() => G[1][op](CURVE_ORDER), 'CURVE_ORDER');
            throws(() => G[1][op](CURVE_ORDER + 1n), 'CURVE_ORDER+1');
            throws(() => G[1][op](123.456), '123.456');
            throws(() => G[1][op](true), 'true');
            throws(() => G[1][op]('1'), '1');
            throws(() => G[1][op](new Uint8Array([])), 'ui8a([])');
            throws(() => G[1][op](new Uint8Array([0])), 'ui8a([0])');
            throws(() => G[1][op](new Uint8Array([1])), 'ui8a([1])');
            throws(() => G[1][op](new Uint8Array(4096).fill(1)), 'ui8a(4096*[1])');
            throws(() => G[1][op](o.BASE), 'other curve point');
          });
        });
      }
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
        should('fromHex(toHex()) roundtrip', () => {
          fc.assert(
            fc.property(FC_BIGINT, (x) => {
              const point = p.BASE.multiply(x);
              const hex = point.toHex();
              const bytes = point.toRawBytes();
              deepStrictEqual(p.fromHex(hex).toHex(), hex);
              deepStrictEqual(p.fromHex(bytes).toHex(), hex);
            })
          );
        });
        should('fromHex(toHex(compressed=true)) roundtrip', () => {
          fc.assert(
            fc.property(FC_BIGINT, (x) => {
              const point = p.BASE.multiply(x);
              const hex = point.toHex(true);
              const bytes = point.toRawBytes(true);
              deepStrictEqual(p.fromHex(hex).toHex(true), hex);
              deepStrictEqual(p.fromHex(bytes).toHex(true), hex);
            })
          );
        });
      }
    });
  }
  describe(name, () => {
    if (['bn254', 'pallas', 'vesta'].includes(name)) return;
    // Generic complex things (getPublicKey/sign/verify/getSharedSecret)
    should('.getPublicKey() type check', () => {
      throws(() => C.getPublicKey(0), '0');
      throws(() => C.getPublicKey(0n), '0n');
      throws(() => C.getPublicKey(-123n), '-123n');
      throws(() => C.getPublicKey(123), '123');
      throws(() => C.getPublicKey(123.456), '123.456');
      throws(() => C.getPublicKey(true), 'true');
      throws(() => C.getPublicKey(false), 'false');
      throws(() => C.getPublicKey(null), 'null');
      throws(() => C.getPublicKey(undefined), 'undefined');
      throws(() => C.getPublicKey(''), "''");
      // NOTE: passes because of disabled hex padding checks for starknet, maybe enable?
      // throws(() => C.getPublicKey('1'), "'1'");
      throws(() => C.getPublicKey('key'), "'key'");
      throws(() => C.getPublicKey({}));
      throws(() => C.getPublicKey(new Uint8Array([])));
      throws(() => C.getPublicKey(new Uint8Array([0])));
      throws(() => C.getPublicKey(new Uint8Array([1])));
      throws(() => C.getPublicKey(new Uint8Array(4096).fill(1)));
      throws(() => C.getPublicKey(Array(32).fill(1)));
    });

    if (C.verify) {
      //if (C.verify)
      should('.verify() should verify random signatures', () =>
        fc.assert(
          fc.property(fc.hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
            const priv = C.utils.randomPrivateKey();
            const pub = C.getPublicKey(priv);
            const sig = C.sign(msg, priv);
            deepStrictEqual(
              C.verify(sig, msg, pub),
              true,
              `priv=${toHex(priv)},pub=${toHex(pub)},msg=${msg}`
            );
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('.verify() should verify random signatures in hex', () =>
        fc.assert(
          fc.property(fc.hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
            const priv = toHex(C.utils.randomPrivateKey());
            const pub = toHex(C.getPublicKey(priv));
            const sig = C.sign(msg, priv);
            let sighex = isBytes(sig) ? toHex(sig) : sig.toCompactHex();
            deepStrictEqual(C.verify(sighex, msg, pub), true, `priv=${priv},pub=${pub},msg=${msg}`);
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('.verify() should verify empty signatures', () => {
        const msg = new Uint8Array([]);
        const priv = C.utils.randomPrivateKey();
        const pub = C.getPublicKey(priv);
        const sig = C.sign(msg, priv);
        deepStrictEqual(
          C.verify(sig, msg, pub),
          true,
          'priv=${toHex(priv)},pub=${toHex(pub)},msg=${msg}'
        );
      });

      should('.sign() edge cases', () => {
        throws(() => C.sign());
        throws(() => C.sign(''));
        throws(() => C.sign('', ''));
        throws(() => C.sign(new Uint8Array(), new Uint8Array()));
      });

      describe('verify()', () => {
        const msg = '01'.repeat(32);
        should('true for proper signatures', () => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(msg, priv);
          const pub = C.getPublicKey(priv);
          deepStrictEqual(C.verify(sig, msg, pub), true);
        });
        should('false for wrong messages', () => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(msg, priv);
          const pub = C.getPublicKey(priv);
          deepStrictEqual(C.verify(sig, '11'.repeat(32), pub), false);
        });
        should('false for wrong keys', () => {
          const priv = C.utils.randomPrivateKey();
          const sig = C.sign(msg, priv);
          deepStrictEqual(C.verify(sig, msg, C.getPublicKey(C.utils.randomPrivateKey())), false);
        });
      });
    }
    if (C.Signature) {
      should('Signature serialization roundtrip', () =>
        fc.assert(
          fc.property(fc.hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
            const priv = C.utils.randomPrivateKey();
            const sig = C.sign(msg, priv);
            const sigRS = (sig) => ({ s: sig.s, r: sig.r });
            // Compact
            deepStrictEqual(sigRS(C.Signature.fromCompact(sig.toCompactHex())), sigRS(sig));
            deepStrictEqual(sigRS(C.Signature.fromCompact(sig.toCompactRawBytes())), sigRS(sig));
            // DER
            deepStrictEqual(sigRS(C.Signature.fromDER(sig.toDERHex())), sigRS(sig));
            deepStrictEqual(sigRS(C.Signature.fromDER(sig.toDERRawBytes())), sigRS(sig));
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('Signature.addRecoveryBit/Signature.recoveryPublicKey', () =>
        fc.assert(
          fc.property(fc.hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
            const priv = C.utils.randomPrivateKey();
            const pub = C.getPublicKey(priv);
            const sig = C.sign(msg, priv);
            deepStrictEqual(sig.recoverPublicKey(msg).toRawBytes(), pub);
            const sig2 = C.Signature.fromCompact(sig.toCompactHex());
            throws(() => sig2.recoverPublicKey(msg));
            const sig3 = sig2.addRecoveryBit(sig.recovery);
            deepStrictEqual(sig3.recoverPublicKey(msg).toRawBytes(), pub);
          }),
          { numRuns: NUM_RUNS }
        )
      );
      should('Signature.normalizeS', () =>
        fc.assert(
          fc.property(fc.hexaString({ minLength: 64, maxLength: 64 }), (msg) => {
            const priv = C.utils.randomPrivateKey();
            const pub = C.getPublicKey(priv);
            const sig = C.sign(msg, priv);
            const sig2 = sig.normalizeS();
            deepStrictEqual(sig2.hasHighS(), false);
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
            deepStrictEqual(C.getSharedSecret(asec, bpub), C.getSharedSecret(bsec, apub));
          } catch (error) {
            console.error('not commutative', { asec, apub, bsec, bpub });
            throw error;
          }
        }
      });
    }
  });
}

should('secp224k1 sqrt bug', () => {
  const { Fp } = secp224r1.CURVE;
  const sqrtMinus1 = Fp.sqrt(-1n);
  // Verified against sage
  deepStrictEqual(
    sqrtMinus1,
    23621584063597419797792593680131996961517196803742576047493035507225n
  );
  deepStrictEqual(
    Fp.neg(sqrtMinus1),
    3338362603553219996874421406887633712040719456283732096017030791656n
  );
  deepStrictEqual(Fp.sqr(sqrtMinus1), Fp.create(-1n));
});

should('bigInt private keys', () => {
  // Doesn't support bigints anymore
  throws(() => ed25519.sign('', 123n));
  throws(() => ed25519.getPublicKey(123n));
  throws(() => x25519.getPublicKey(123n));
  // Weierstrass still supports
  secp256k1.getPublicKey(123n);
  secp256k1.sign('', 123n);
});

describe('wycheproof curve creation', () => {
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
      deepStrictEqual(CURVE.CURVE.Fp.ORDER, BigInt(`0x${v.p}`));
      deepStrictEqual(CURVE.CURVE.a, BigInt(`0x${v.a}`));
      deepStrictEqual(CURVE.CURVE.b, BigInt(`0x${v.b}`));
      deepStrictEqual(CURVE.CURVE.n, BigInt(`0x${v.n}`));
      deepStrictEqual(CURVE.CURVE.Gx, BigInt(`0x${v.gx}`));
      deepStrictEqual(CURVE.CURVE.Gy, BigInt(`0x${v.gy}`));
      deepStrictEqual(CURVE.CURVE.h, BigInt(v.h));
    });
  }
});

should('validate generator point is on curve', () => {
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

describe('Pairings', () => {
  for (const [name, curve] of Object.entries(PAIRINGS)) {
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
        deepStrictEqual(Fp12.mul(p1, p2), Fp12.ONE);
      });
      should('creates negative G2 pairing', () => {
        const p2 = pairing(G1.negate(), G2);
        const p3 = pairing(G1, G2.negate());
        deepStrictEqual(p2, p3);
      });
      should('creates proper pairing output order', () => {
        const p1 = pairing(G1, G2);
        const p2 = Fp12.pow(p1, CURVE_ORDER);
        deepStrictEqual(p2, Fp12.ONE);
      });
      should('G1 billinearity', () => {
        const p1 = pairing(G1, G2);
        const p2 = pairing(G1.multiply(2n), G2);
        deepStrictEqual(Fp12.mul(p1, p1), p2);
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
        deepStrictEqual(Fp12.mul(p1, p1), p2);
      });
      should('proper pairing composite check', () => {
        const p1 = pairing(G1.multiply(37n), G2.multiply(27n));
        const p2 = pairing(G1.multiply(999n), G2);
        deepStrictEqual(p1, p2);
      });
    });
  }
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
