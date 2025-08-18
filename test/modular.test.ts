import * as fc from 'fast-check';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import * as mod from '../src/abstract/modular.ts';
import { Field } from '../src/abstract/modular.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { bn254 } from '../src/bn254.ts';
import { ed25519 } from '../src/ed25519.ts';
import { ed448 } from '../src/ed448.ts';
import {
  babyjubjub,
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
  jubjub,
} from '../src/misc.ts';
import { p256 as secp256r1, p521 as secp521r1 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { secp192r1, secp224r1 } from './_more-curves.helpers.ts';
import { json } from './utils.ts';
const wyche_curves = json('./vectors/wycheproof/ec_prime_order_curves_test.json');

// const FC_HEX = fc.stringMatching(/[0-9a-fA-F]+/, { size: 64 });

// Fields tests
const FIELDS = {
  secp192r1: { Fp: [secp192r1.Point.Fp] },
  secp224r1: { Fp: [secp224r1.Point.Fp] },
  secp256r1: { Fp: [secp256r1.Point.Fp] },
  secp521r1: { Fp: [secp521r1.Point.Fp] },
  secp256k1: { Fp: [secp256k1.Point.Fp] },
  jubjub: { Fp: [jubjub.Point.Fp] },
  babyjubjub: { Fp: [babyjubjub.Point.Fp] },
  ed25519: { Fp: [ed25519.Point.Fp] },
  ed448: { Fp: [ed448.Point.Fp] },
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
  brainpoolP256r1: { Fp: [brainpoolP256r1.Point.Fp] },
  brainpoolP384r1: { Fp: [brainpoolP384r1.Point.Fp] },
  brainpoolP512r1: { Fp: [brainpoolP512r1.Point.Fp] },
  // https://neuromancer.sk/std/other/E-382 (just to check Kong sqrt, nobody else uses it)
  e382: {
    // Prime
    Fr: [
      Field(
        2462625387274654950767440006258975862817483704404090416745738034557663054564649171262659326683244604346084081047321n
      ),
    ],
  },
};

// prettier-ignore
const SQRT_FIELDS = [];
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
    const noSqrt = [bls12_381.fields.Fp12, bn254.fields.Fp12].includes(Fp);
    const isNonPrime = noSqrt || [bls12_381.fields.Fp2, bn254.fields.Fp2].includes(Fp);

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

      const checkRoot = (n, root) => {
        const negRoot = Fp.neg(root);
        eql(mod.FpPow(Fp, root, 2n), n);
        eql(mod.FpPow(Fp, negRoot, 2n), n);
        // Cross-check with tonneli
        eql(Fp.mul(root, root), n);
        eql(Fp.mul(negRoot, negRoot), n);
        eql(Fp.eql(Fp.sqr(root), n), true, 'sqrt(a)^2 == a');
        eql(Fp.eql(Fp.sqr(Fp.neg(root)), n), true, '(-sqrt(a))^2 == a');
        // Returns odd/even element
        eql(Fp.isOdd(mod.FpSqrtOdd(Fp, n)), true);
        eql(Fp.isOdd(mod.FpSqrtEven(Fp, n)), false);
        eql(Fp.eql(Fp.sqr(mod.FpSqrtOdd(Fp, n)), n), true);
        eql(Fp.eql(Fp.sqr(mod.FpSqrtEven(Fp, n)), n), true);
      };

      // No legendre for extension fields, but we can have Fp.sqrt defined via specific algorithm
      if (!noSqrt) {
        should('sqrt(sqr)', () => {
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const x = create(num);
              const sq = Fp.mul(x, x);
              const root = Fp.sqrt(sq);
              eql(Fp.eql(root, x) || Fp.eql(root, Fp.neg(x)), true);
            })
          );
        });
        should('sqrt(field)', () => {
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const a = create(num);
              let root;
              try {
                root = Fp.sqrt(a);
              } catch (e) {
                if (!e.message.includes('Cannot find square root')) throw e;
                eql(mod.FpIsSquare(Fp, a), false);
                return;
              }
              checkRoot(a, root);
            })
          );
        });
      }
      if (!isNonPrime) {
        SQRT_FIELDS.push(Fp);
        should('sqrt(0)', () => {
          eql(Fp.sqrt(Fp.ZERO), Fp.ZERO);
          const sqrt1 = Fp.sqrt(Fp.ONE);
          eql(Fp.eql(sqrt1, Fp.ONE) || Fp.eql(sqrt1, Fp.neg(Fp.ONE)), true, 'sqrt(1) = 1 or -1');
          eql(mod.FpLegendre(Fp, Fp.ZERO), 0);
        });
        should('sqr returns square', () =>
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const x = create(num);
              eql(mod.FpIsSquare(Fp, Fp.sqr(x)), true);
            })
          )
        );
        should('FpSqrt + legendre', () =>
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const n = create(num);
              const leg = mod.FpLegendre(Fp, n);
              if (leg === 1) {
                const root = mod.FpSqrt(Fp.ORDER)(Fp, n);
                const negRoot = Fp.neg(root);
                checkRoot(n, root);
                const t = mod.tonelliShanks(Fp.ORDER)(Fp, n);
                eql(Fp.eql(t, root) || Fp.eql(t, negRoot), true);
              } else if (leg === 0) {
                eql(n, Fp.ZERO);
                eql(mod.FpIsSquare(Fp, n), false);
              } else if (leg === -1) {
                throws(() => mod.FpSqrt(Fp, n));
                eql(mod.FpIsSquare(Fp, n), false);
              } else {
                throw new Error('unexpected legendre output');
              }
            })
          )
        );
        should('legendre correctness', () =>
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const n = create(num);
              const leg = BigInt(mod.FpLegendre(Fp, n));
              eql(Fp.mul(Fp.ONE, leg), Fp.pow(n, (Fp.ORDER - 1n) / 2n));
            })
          )
        );
        should('legendre multiplicativity', () =>
          fc.assert(
            fc.property(FC_BIGINT, FC_BIGINT, (num1, num2) => {
              const a = create(num1);
              const b = create(num2);
              eql(mod.FpLegendre(Fp, a) * mod.FpLegendre(Fp, b), mod.FpLegendre(Fp, Fp.mul(a, b)));
            })
          )
        );
      } else {
        should('sqrt(fail)', () =>
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const a = create(num);
              throws(() => mod.FpSqrt(Fp.ORDER)(Fp, n));
            })
          )
        );
      }
      should('pow(x*y, e) == pow(x,e)*pow(y,e)', () =>
        fc.assert(
          fc.property(FC_BIGINT, FC_BIGINT, FC_BIGINT, (num1, num2, num3) => {
            const a = create(num1);
            const b = create(num2);
            const c = create(num3);
            eql(Fp.pow(Fp.mul(a, b), c), Fp.mul(Fp.pow(a, c), Fp.pow(b, c)));
          })
        )
      );
      should('pow(x, 0) = 1', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const x = create(num);
            if (Fp.eql(x, Fp.ZERO)) return; // Optional skip or check 0^0 edge case
            eql(Fp.eql(mod.FpPow(Fp, x, 0n), Fp.ONE), true);
          })
        );
      });
      should('pow(x, 1) = x', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const x = create(num);
            eql(Fp.eql(mod.FpPow(Fp, x, 1n), x), true);
          })
        );
      });
      if (!isNonPrime) {
        should('pow(x, p-1) = 1 (mod p) for x ≠ 0', () => {
          fc.assert(
            fc.property(FC_BIGINT, (num) => {
              const x = create(num);
              if (Fp.eql(x, Fp.ZERO)) return;
              eql(Fp.eql(mod.FpPow(Fp, x, Fp.ORDER - 1n), Fp.ONE), true);
            })
          );
        });
      }
      should('legendre(0)', () => {
        eql(mod.FpLegendre(Fp, Fp.ZERO), 0);
      });

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

describe('sqrt cases', () => {
  should('Sqrt cases', () => {
    // Verify that we checked fields for every sqrt case
    const CASES = [
      (n) => n % 4n === 3n,
      (n) => n % 8n === 5n, // atkin
      (n) => n % 16n == 9n, // kong
      (n) => true, // shanks
    ];
    const checkedCases = new Set();
    for (const f of SQRT_FIELDS) {
      for (let i = 0; i < CASES.length; i++) {
        if (CASES[i](f.ORDER)) {
          checkedCases.add(i);
          break;
        }
      }
    }
    eql(checkedCases.size, CASES.length);
  });

  should('secp224k1 sqrt bug', () => {
    const { Fp } = secp224r1.Point;
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
  });
});

should.runWhen(import.meta.url);
