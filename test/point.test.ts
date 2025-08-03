import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { pippenger, precomputeMSMUnsafe } from '../src/abstract/curve.ts';
import { invert, mod } from '../src/abstract/modular.ts';
import { bytesToHex as hex, hexToBytes } from '../src/utils.ts';
import { getTypeTests } from './utils.ts';

import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519, ed25519ctx, ed25519ph, ristretto255 } from '../src/ed25519.ts';
import { decaf448, ed448, ed448ph } from '../src/ed448.ts';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, jubjub } from '../src/misc.ts';
import { p256 as secp256r1, p384 as secp384r1, p521 as secp521r1 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { miscCurves, secp192r1, secp224r1 } from './_more-curves.helpers.ts';

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
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
  bls12_381_G1: bls12_381.G1,
  bls12_381_G2: bls12_381.G2,
  // Requires fromHex/toHex
  // bn254_G1: bn254.G1,
  // bn254_G2: bn254.G2,
  ristretto: { ...ed25519, Point: ristretto255.Point },
  decaf: { ...ed448, Point: decaf448.Point },
};
Object.assign(CURVES, miscCurves);

function getOtherCurve(currCurveName) {
  return currCurveName === 'secp256k1' ? secp256r1 : secp256k1;
}

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
        should('zero', () => {
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
          equal(G[2].multiplyUnsafe(3n), G[6], '(2*G).multiplyUnsafe(3) = 6*G');
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
          equal(G[1].multiplyUnsafe(CURVE_ORDER - 1n).add(G[1]), G[0], '(N-1)*G + G = 0');
          equal(G[1].multiplyUnsafe(CURVE_ORDER - 1n).add(G[2]), G[1], '(N-1)*G + 2*G = 1*G');
          equal(G[1].multiplyUnsafe(CURVE_ORDER - 2n).add(G[2]), G[0], '(N-2)*G + 2*G = 0');
          const half = CURVE_ORDER / 2n;
          const carry = CURVE_ORDER % 2n === 1n ? G[1] : G[0];
          equal(G[1].multiply(half).double().add(carry), G[0], '((N/2) * G).double() = 0');
        });
        should('inversion', () => {
          const a = 1234n;
          const b = 5678n;
          const c = a * b;
          equal(G[1].multiply(a).multiply(b), G[1].multiply(c), 'a*b*G = c*G');
          const inv = invert(b, CURVE_ORDER);
          equal(G[1].multiply(c).multiply(inv), G[1].multiply(a), 'c*G * (1/b)*G = a*G');
        });
        should('multiply, rand', () =>
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
          )
        );
        should('multiply2, rand', () =>
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
        if (typeof pippenger !== 'function' || typeof precomputeMSMUnsafe !== 'function') return;
        should('MSM basic', () => {
          const msm = (points, scalars) => pippenger(p, points, scalars);
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
              total = mod(total, CURVE_ORDER);
              const exp = total ? p.BASE.multiply(total) : p.ZERO;
              equal(pippenger(p, points, scalars), exp, 'total');
            }),
            { numRuns: NUM_RUNS }
          )
        );
        should('precomputeMSMUnsafe basic', () => {
          const Point = C.Point;
          if (!Point) throw new Error('Unknown point');

          const points = [p.BASE, p.BASE.multiply(2n), p.BASE.multiply(4n), p.BASE.multiply(8n)];
          const scalars = [3n, 5n, 7n, 11n];
          const res = p.BASE.multiply(129n);
          for (let windowSize = 1; windowSize <= 10; windowSize++) {
            const mul = precomputeMSMUnsafe(Point, points, windowSize);
            equal(mul(scalars), res, 'windowSize=' + windowSize);
          }
        });
        should('precomputeMSMUnsafe random', () =>
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
          )
        );
      });

      should('fromAffine(toAffine()) roundtrip', () => {
        equal(p.ZERO, p.fromAffine(p.ZERO.toAffine()), '0 = 0');
        equal(p.BASE, p.fromAffine(p.BASE.toAffine()), '1 = 1');
        equal(p.BASE.multiply(2n), p.fromAffine(p.BASE.multiply(2n).toAffine()), '1 = 1');
      });
      // toHex/fromHex (if available)
      should('fromBytes(toBytes()) roundtrip', () => {
        fc.assert(
          fc.property(FC_BIGINT, (x) => {
            const point = p.BASE.multiply(x);
            let c = false; // compressed
            const bu = point.toBytes(c);
            eql(p.fromBytes(bu).toBytes(c), bu);

            c = true;
            const bc = point.toBytes(c);
            eql(p.fromBytes(bc).toBytes(c), bc);
          })
        );
      });
      should('fromHex(toHex()) roundtrip', () => {
        fc.assert(
          fc.property(FC_BIGINT, (x) => {
            const point = p.BASE.multiply(x);
            let c = false; // compressed
            const hu = point.toHex(c);
            eql(p.fromHex(hu).toHex(c), hu);

            c = true;
            const hc = point.toHex(c);
            eql(p.fromHex(hc).toHex(c), hc);
          })
        );
      });
      // }
    });

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
        should('.verify() should verify random signatures', () =>
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
          )
        );
        // should('.verify() should verify random signatures in hex', () =>
        //   fc.assert(
        //     fc.property(FC_HEX, (msg) => {
        //       const priv = hex(C.utils.randomSecretKey());
        //       const pub = hex(C.getPublicKey(priv));
        //       const sig = C.sign(msg, priv);
        //       let sighex = isBytes(sig) ? hex(sig) : sig.toHex('compact');
        //       eql(C.verify(sighex, msg, pub), true, `priv=${priv},pub=${pub},msg=${msg}`);
        //     }),
        //     { numRuns: NUM_RUNS }
        //   )
        // );
        should('.verify() should verify empty signatures', () => {
          const msg = new Uint8Array([]);
          const k = C.keygen();
          const sig = C.sign(msg, k.secretKey);
          eql(
            C.verify(sig, msg, k.publicKey),
            true,
            `priv=${hex(k.secretKey)},pub=${hex(k.publicKey)},msg=${msg}`
          );
        });

        should('.sign() type tests', () => {
          const msg = new Uint8Array([]);
          const k = C.keygen();
          C.sign(msg, k.secretKey);
          for (let [item, repr_] of getTypeTests()) {
            throws(() => C.sign(msg, item), repr_);
            if (!repr_.startsWith('ui8a') && repr_ !== '""') {
              throws(() => C.sign(item, k.secretKey), repr_);
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
          const msg = hexToBytes('01'.repeat(32));
          const msgWrong = hexToBytes('11'.repeat(32));
          should('true for proper signatures', () => {
            const k = C.keygen();
            const sig = C.sign(msg, k.secretKey);
            eql(C.verify(sig, msg, k.publicKey), true);
          });
          should('false for wrong messages', () => {
            const k = C.keygen();
            const sig = C.sign(msg, k.secretKey);
            eql(C.verify(sig, msgWrong, k.publicKey), false);
          });
          should('false for wrong keys', () => {
            const k = C.keygen();
            const k2 = C.keygen();
            const sig = C.sign(msg, k.secretKey);
            eql(C.verify(sig, msg, k2.publicKey), false);
          });
          should('type tests', () => {
            const k = C.keygen();
            const sig = C.sign(msg, k.secretKey);
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
        should('Signature serialization roundtrip', () =>
          fc.assert(
            fc.property(FC_HEX, (msgh) => {
              const msg = hexToBytes(msgh);
              const priv = C.utils.randomSecretKey();
              const sigb = C.sign(msg, priv, { format: 'recovered' });
              const sig = C.Signature.fromBytes(sigb, 'recovered');
              const sigRS = (sig) => ({ s: sig.s, r: sig.r });
              const hasToHex = !!C.Signature.fromHex;
              let f = 'compact';
              if (hasToHex) eql(sigRS(C.Signature.fromHex(sig.toHex(f), f)), sigRS(sig));
              eql(sigRS(C.Signature.fromBytes(sig.toBytes(f), f)), sigRS(sig));
              f = 'recovered';
              if (hasToHex) eql(sigRS(C.Signature.fromHex(sig.toHex(f), f)), sigRS(sig));
              eql(sigRS(C.Signature.fromBytes(sig.toBytes(f), f)), sigRS(sig));
              const isNobleCurves = !!C.Point.Fp;
              if (isNobleCurves) {
                f = 'der';
                if (hasToHex) eql(sigRS(C.Signature.fromHex(sig.toHex(f), f)), sigRS(sig));
                eql(sigRS(C.Signature.fromBytes(sig.toBytes(f), f)), sigRS(sig));
              }
            }),
            { numRuns: NUM_RUNS }
          )
        );
        should('Signature.addRecoveryBit/Signature.recoverPublicKey', () =>
          fc.assert(
            fc.property(FC_HEX, (msgh) => {
              const msg = hexToBytes(msgh);
              // const priv = C.utils.randomSecretKey();
              // const pub = C.getPublicKey(priv);
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
      //         const privKey = C.utils.randomSecretKey();
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
