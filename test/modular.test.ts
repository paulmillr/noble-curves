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
    Fp6: [
      bls12_381.fields.Fp6,
      fc.array(fc.bigInt(1n, bls12_381.fields.Fp.ORDER - 1n), {
        minLength: 6,
        maxLength: 6,
      }),
      (Fp6, num) => Fp6.fromBigSix(num),
    ],
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
    Fp6: [
      bn254.fields.Fp6,
      fc.array(fc.bigInt(1n, bn254.fields.Fp.ORDER - 1n), {
        minLength: 6,
        maxLength: 6,
      }),
      (Fp6, num) => Fp6.fromBigSix(num),
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
    const noSqrt = [
      bls12_381.fields.Fp6,
      bls12_381.fields.Fp12,
      bn254.fields.Fp6,
      bn254.fields.Fp12,
    ].includes(Fp);
    const noGenericSqrt = noSqrt || [bls12_381.fields.Fp2, bn254.fields.Fp2].includes(Fp);

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
            const minus1 = Fp.neg(Fp.ONE);
            eql(Fp.sub(Fp.ZERO, a), Fp.neg(a));
            eql(Fp.sub(a, b), Fp.add(a, Fp.neg(b)));
            eql(Fp.sub(a, b), Fp.add(a, Fp.mul(b, minus1)));
          })
        );
      });
      should('add/subtract/negate', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const a = create(num);
            eql(Fp.neg(a), Fp.sub(Fp.ZERO, a));
            eql(Fp.neg(a), Fp.mul(a, Fp.neg(Fp.ONE)));
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

      // Extension fields can still use `FpLegendre` / `FpIsSquare` when ORDER=q.
      // Only the generic `FpSqrt(P)` / Tonelli-Shanks path is prime-field-specific here.
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
      should('sqr returns square', () =>
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const x = create(num);
            eql(mod.FpIsSquare(Fp, Fp.sqr(x)), true);
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
      if (!noGenericSqrt) {
        SQRT_FIELDS.push(Fp);
        should('sqrt(0)', () => {
          eql(Fp.sqrt(Fp.ZERO), Fp.ZERO);
          const sqrt1 = Fp.sqrt(Fp.ONE);
          eql(Fp.eql(sqrt1, Fp.ONE) || Fp.eql(sqrt1, Fp.neg(Fp.ONE)), true, 'sqrt(1) = 1 or -1');
          eql(mod.FpLegendre(Fp, Fp.ZERO), 0);
        });
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
                eql(mod.FpIsSquare(Fp, n), true);
              } else if (leg === -1) {
                throws(() => mod.FpSqrt(Fp, n));
                eql(mod.FpIsSquare(Fp, n), false);
              } else {
                throw new Error('unexpected legendre output');
              }
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
      should('pow(x, q-1) = 1 for x ≠ 0', () => {
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const x = create(num);
            if (Fp.eql(x, Fp.ZERO)) return;
            eql(Fp.eql(mod.FpPow(Fp, x, Fp.ORDER - 1n), Fp.ONE), true);
          })
        );
      });
      should('legendre(0)', () => {
        eql(mod.FpLegendre(Fp, Fp.ZERO), 0);
      });
      should('isSquare(0)', () => {
        eql(mod.FpIsSquare(Fp, Fp.ZERO), true);
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
    eql(Fp.sqr(sqrtMinus1), Fp.neg(Fp.ONE));
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

describe('guard cases', () => {
  should('Field rejects empty allowed-length encodings', () => {
    const FpPad = Field(17n, { allowedLengths: [0, 1] });
    throws(() => FpPad.fromBytes(new Uint8Array([])));
  });

  should('Field runtime properties are not externally mutable', () => {
    const Fp = Field(17n);
    const before = Fp.create(20n);
    throws(() => ((Fp as any).ORDER = 19n));
    eql(Fp.create(20n), before);
  });

  should('Field shared prototype methods are not externally mutable', () => {
    const Fp = Field(17n);
    const before = Fp.create(20n);
    const proto = Object.getPrototypeOf(Fp);
    throws(() => (proto.create = () => 123n));
    eql(Fp.create(20n), before);
  });

  should('positive-order helpers reject non-positive orders and cached bit lengths', () => {
    throws(() => mod.getFieldBytesLength(0n));
    throws(() => mod.getFieldBytesLength(1n));
    throws(() => mod.getFieldBytesLength(-5n));
    throws(() => mod.getMinHashLength(0n));
    throws(() => mod.getMinHashLength(1n));
    throws(() => mod.getMinHashLength(-5n));
    throws(() => mod.nLength(0n));
    throws(() => mod.nLength(-5n));
    throws(() => mod.nLength(255n, 0));
  });

  should('mod rejects zero and negative moduli', () => {
    throws(() => mod.mod(1n, 0n));
    throws(() => mod.mod(1n, -5n));
  });

  should('pow rejects degenerate moduli of one or less', () => {
    throws(() => mod.pow(3n, 1n, 1n));
    throws(() => mod.pow(3n, 1n, 0n));
  });

  should('pow2 rejects negative exponents', () => {
    throws(() => mod.pow2(3n, -1n, 11n));
  });

  should('validateField rejects impossible field metadata', () => {
    const fn = () => 0n;
    const field = {
      ORDER: 17n,
      BYTES: 1,
      BITS: 1,
      create: fn,
      isValid: () => true,
      is0: () => false,
      isValidNot0: () => true,
      neg: fn,
      inv: fn,
      sqrt: fn,
      sqr: fn,
      eql: () => true,
      add: fn,
      sub: fn,
      mul: fn,
      pow: fn,
      div: fn,
      addN: fn,
      subN: fn,
      mulN: fn,
      sqrN: fn,
      invertBatch: () => [],
      toBytes: () => new Uint8Array([]),
      fromBytes: fn,
      cmov: fn,
    } as any;
    const cases = [
      { name: 'zero-byte-length', value: { BYTES: 0 } },
      { name: 'zero-bit-length', value: { BITS: 0 } },
      { name: 'fractional-bytes', value: { BYTES: 1.5 } },
      { name: 'nan-bytes', value: { BYTES: Number.NaN } },
      { name: 'infinite-bits', value: { BITS: Number.POSITIVE_INFINITY } },
      { name: 'zero-order', value: { ORDER: 0n } },
      { name: 'one-order', value: { ORDER: 1n } },
      { name: 'negative-order', value: { ORDER: -17n } },
    ];
    const out = cases.map(({ name, value }) => {
      try {
        mod.validateField({ ...field, ...value });
        return { name, ok: true };
      } catch {
        return { name, ok: false };
      }
    });
    eql(out, cases.map(({ name }) => ({ name, ok: false })));
  });

  should('Field returns a frozen field instance', () => {
    eql(Object.isFrozen(Field(17n)), true);
  });

  should('Field rejects cached bit lengths smaller than the order bit length', () => {
    throws(() => Field(257n, { BITS: 1 }));
  });

  should('Field rejects degenerate orders of one or less', () => {
    throws(() => Field(1n));
    throws(() => Field(0n));
  });
});

describe('field helpers', () => {
  should('tower12 keeps higher Frobenius tables lazy and cached', () => {
    const proto6 = Object.getPrototypeOf(bn254.fields.Fp6);
    const proto12 = Object.getPrototypeOf(bn254.fields.Fp12);
    eql(typeof Object.getOwnPropertyDescriptor(proto6, 'FROBENIUS_COEFFICIENTS_1')?.get, 'function');
    eql(typeof Object.getOwnPropertyDescriptor(proto6, 'FROBENIUS_COEFFICIENTS_2')?.get, 'function');
    eql(typeof Object.getOwnPropertyDescriptor(proto12, 'FROBENIUS_COEFFICIENTS')?.get, 'function');
    eql(Object.isFrozen(bn254.fields.Fp6), true);
    eql(Object.isFrozen(bn254.fields.Fp12), true);
    const frob61 = bn254.fields.Fp6.FROBENIUS_COEFFICIENTS_1;
    const frob62 = bn254.fields.Fp6.FROBENIUS_COEFFICIENTS_2;
    eql(bn254.fields.Fp6.FROBENIUS_COEFFICIENTS_1, frob61);
    eql(bn254.fields.Fp6.FROBENIUS_COEFFICIENTS_2, frob62);
    eql(Object.isFrozen(frob61), true);
    eql(Object.isFrozen(frob62), true);
    const frob12 = bn254.fields.Fp12.FROBENIUS_COEFFICIENTS;
    eql(bn254.fields.Fp12.FROBENIUS_COEFFICIENTS, frob12);
    eql(Object.isFrozen(frob12), true);
  });

  should('_Field12.cmov selects by boolean condition on valid inputs', () => {
    const suites = [
      ['bn254', bn254.fields.Fp12, bn254.fields.Fp],
      ['bls12_381', bls12_381.fields.Fp12, bls12_381.fields.Fp],
    ] as const;
    for (const [, Fp12, Fp] of suites) {
      const a = {
        c0: {
          c0: { c0: Fp.ORDER + 1n, c1: Fp.ORDER + 2n },
          c1: { c0: Fp.ORDER + 3n, c1: Fp.ORDER + 4n },
          c2: { c0: Fp.ORDER + 5n, c1: Fp.ORDER + 6n },
        },
        c1: {
          c0: { c0: Fp.ORDER + 7n, c1: Fp.ORDER + 8n },
          c1: { c0: Fp.ORDER + 9n, c1: Fp.ORDER + 10n },
          c2: { c0: Fp.ORDER + 11n, c1: Fp.ORDER + 12n },
        },
      };
      const b = {
        c0: {
          c0: { c0: 13n, c1: 14n },
          c1: { c0: 15n, c1: 16n },
          c2: { c0: 17n, c1: 18n },
        },
        c1: {
          c0: { c0: 19n, c1: 20n },
          c1: { c0: 21n, c1: 22n },
          c2: { c0: 23n, c1: 24n },
        },
      };
      eql(Fp12.cmov(a, b, false), Fp12.create(a));
      eql(Fp12.cmov(a, b, true), Fp12.create(b));
    }
  });

  should('field cmov rejects non-boolean conditions', () => {
    const suites = [
      ['Field', Field(17n), 1n, 2n],
      ['bn254.Fp2', bn254.fields.Fp2, bn254.fields.Fp2.ONE, bn254.fields.Fp2.ZERO],
      ['bls12_381.Fp2', bls12_381.fields.Fp2, bls12_381.fields.Fp2.ONE, bls12_381.fields.Fp2.ZERO],
      ['bn254.Fp6', bn254.fields.Fp6, bn254.fields.Fp6.ONE, bn254.fields.Fp6.ZERO],
      ['bls12_381.Fp6', bls12_381.fields.Fp6, bls12_381.fields.Fp6.ONE, bls12_381.fields.Fp6.ZERO],
      ['bn254.Fp12', bn254.fields.Fp12, bn254.fields.Fp12.ONE, bn254.fields.Fp12.ZERO],
      ['bls12_381.Fp12', bls12_381.fields.Fp12, bls12_381.fields.Fp12.ONE, bls12_381.fields.Fp12.ZERO],
    ] as const;
    for (const [, F, a, b] of suites) {
      throws(() => F.cmov(a, b, 0 as any));
      throws(() => F.cmov(a, b, 1 as any));
      throws(() => F.cmov(a, b, '' as any));
      throws(() => F.cmov(a, b, 'x' as any));
      throws(() => F.cmov(a, b, null as any));
      throws(() => F.cmov(a, b, undefined as any));
    }
  });

  should('_Field12._cyclotomicExp matches pow in range and rejects out-of-range exponents', () => {
    const suites = [
      ['bn254', bn254.fields.Fp12],
      ['bls12_381', bls12_381.fields.Fp12],
    ] as const;
    for (const [, Fp12] of suites) {
      const mk = (off: number) =>
        Fp12.create({
          c0: {
            c0: { c0: BigInt(off + 1), c1: BigInt(off + 2) },
            c1: { c0: BigInt(off + 3), c1: BigInt(off + 4) },
            c2: { c0: BigInt(off + 5), c1: BigInt(off + 6) },
          },
          c1: {
            c0: { c0: BigInt(off + 7), c1: BigInt(off + 8) },
            c1: { c0: BigInt(off + 9), c1: BigInt(off + 10) },
            c2: { c0: BigInt(off + 11), c1: BigInt(off + 12) },
          },
        });
      const g = Fp12.finalExponentiate(Fp12.mul(mk(0), mk(20)));
      for (const n of [0n, 1n, 2n, 5n, 17n, BigInt(Fp12.X_LEN - 1)]) eql(Fp12._cyclotomicExp(g, n), Fp12.pow(g, n));
      throws(() => Fp12._cyclotomicExp(g, -1n));
      throws(() => Fp12._cyclotomicExp(g, 1n << BigInt(Fp12.X_LEN)));
    }
  });

  should('_Field12.fromBytes rejects non-Uint8Array inputs before subarray access', () => {
    const suites = [
      ['bn254', bn254.fields.Fp12],
      ['bls12_381', bls12_381.fields.Fp12],
    ] as const;
    for (const [, Fp12] of suites)
      throws(() => Fp12.fromBytes({ length: Fp12.BYTES } as any), /expected Uint8Array, got type=object/);
  });

  should('tower isValid throws on malformed coordinate types', () => {
    const suites = [
      ['bn254.Fp2', bn254.fields.Fp2, { c0: 1n }, /expected bigint, got undefined/],
      ['bls12_381.Fp2', bls12_381.fields.Fp2, { c1: 1n }, /expected bigint, got undefined/],
      ['bn254.Fp6', bn254.fields.Fp6, { c0: bn254.fields.Fp2.ONE, c1: bn254.fields.Fp2.ZERO }, /expected object, got undefined/],
      ['bls12_381.Fp6', bls12_381.fields.Fp6, { c1: bls12_381.fields.Fp2.ONE, c2: bls12_381.fields.Fp2.ZERO }, /expected object, got undefined/],
      ['bn254.Fp12', bn254.fields.Fp12, { c0: bn254.fields.Fp6.ONE }, /expected object, got undefined/],
      ['bls12_381.Fp12', bls12_381.fields.Fp12, { c1: bls12_381.fields.Fp6.ONE }, /expected object, got undefined/],
    ] as const;
    for (const [, F, value, err] of suites) throws(() => F.isValid(value as any), err);
  });

  should('tower isValidNot0 throws on malformed coordinate types', () => {
    const suites = [
      ['bn254.Fp2', bn254.fields.Fp2, { c0: 1n }, /expected bigint, got undefined/],
      ['bls12_381.Fp2', bls12_381.fields.Fp2, { c1: 1n }, /expected bigint, got undefined/],
      ['bn254.Fp6', bn254.fields.Fp6, { c0: bn254.fields.Fp2.ONE, c1: bn254.fields.Fp2.ZERO }, /expected object, got undefined/],
      ['bls12_381.Fp6', bls12_381.fields.Fp6, { c1: bls12_381.fields.Fp2.ONE, c2: bls12_381.fields.Fp2.ZERO }, /expected object, got undefined/],
      ['bn254.Fp12', bn254.fields.Fp12, { c0: bn254.fields.Fp6.ONE }, /expected object, got undefined/],
      ['bls12_381.Fp12', bls12_381.fields.Fp12, { c1: bls12_381.fields.Fp6.ONE }, /expected object, got undefined/],
    ] as const;
    for (const [, F, value, err] of suites) throws(() => F.isValidNot0(value as any), err);
  });

  should('_Field2.cmov selects by boolean condition on valid inputs', () => {
    const suites = [
      ['bn254', bn254.fields.Fp2, bn254.fields.Fp],
      ['bls12_381', bls12_381.fields.Fp2, bls12_381.fields.Fp],
    ] as const;
    for (const [, Fp2, Fp] of suites) {
      const a = { c0: Fp.ORDER + 1n, c1: Fp.ORDER + 2n };
      const b = { c0: 3n, c1: 4n };
      eql(Fp2.cmov(a, b, false), Fp2.create(a));
      eql(Fp2.cmov(a, b, true), Fp2.create(b));
    }
  });

  should('_Field2.fromBytes rejects non-Uint8Array inputs before subarray access', () => {
    const suites = [
      ['bn254', bn254.fields.Fp2],
      ['bls12_381', bls12_381.fields.Fp2],
    ] as const;
    for (const [, Fp2] of suites)
      throws(() => Fp2.fromBytes({ length: Fp2.BYTES } as any), /expected Uint8Array, got type=object/);
  });

  should('_Field6.cmov selects by boolean condition on valid inputs', () => {
    const suites = [
      ['bn254', bn254.fields.Fp6, bn254.fields.Fp],
      ['bls12_381', bls12_381.fields.Fp6, bls12_381.fields.Fp],
    ] as const;
    for (const [, Fp6, Fp] of suites) {
      const a = {
        c0: { c0: Fp.ORDER + 1n, c1: Fp.ORDER + 2n },
        c1: { c0: Fp.ORDER + 3n, c1: Fp.ORDER + 4n },
        c2: { c0: Fp.ORDER + 5n, c1: Fp.ORDER + 6n },
      };
      const b = {
        c0: { c0: 7n, c1: 8n },
        c1: { c0: 9n, c1: 10n },
        c2: { c0: 11n, c1: 12n },
      };
      eql(Fp6.cmov(a, b, false), Fp6.create(a));
      eql(Fp6.cmov(a, b, true), Fp6.create(b));
    }
  });

  should('_Field6.fromBytes rejects non-Uint8Array inputs before subarray access', () => {
    const suites = [
      ['bn254', bn254.fields.Fp6],
      ['bls12_381', bls12_381.fields.Fp6],
    ] as const;
    for (const [, Fp6] of suites)
      throws(() => Fp6.fromBytes({ length: Fp6.BYTES } as any), /expected Uint8Array, got type=object/);
  });

  should('Field.addN keeps bigint arithmetic on valid inputs', () => {
    const F = Field(11n);
    eql(F.create(F.addN(30n, -2n)), F.add(30n, -2n));
  });

  should('Field accepts coherent cached bit lengths', () => {
    const F = Field(257n, { BITS: 9 });
    eql({ bits: F.BITS, bytes: F.BYTES }, { bits: 9, bytes: 2 });
  });

  should('Field.cmov selects by boolean condition on valid inputs', () => {
    const F = Field(17n);
    eql(F.cmov(1n, 2n, false), 1n);
    eql(F.cmov(1n, 2n, true), 2n);
  });

  should('Field.mulN keeps bigint arithmetic on valid inputs', () => {
    const F = Field(11n);
    eql(F.create(F.mulN(30n, -2n)), F.mul(30n, -2n));
  });

  should('Field.subN keeps bigint arithmetic on valid inputs', () => {
    const F = Field(11n);
    eql(F.create(F.subN(30n, -2n)), F.sub(30n, -2n));
  });

  should('getFieldBytesLength uses the element range, not the order bit length', () => {
    eql(
      [255n, 256n, 257n, 65535n, 65536n].map((fieldOrder) => ({
        fieldOrder,
        len: mod.getFieldBytesLength(fieldOrder),
      })),
      [
        { fieldOrder: 255n, len: 1 },
        { fieldOrder: 256n, len: 1 },
        { fieldOrder: 257n, len: 2 },
        { fieldOrder: 65535n, len: 2 },
        { fieldOrder: 65536n, len: 2 },
      ]
    );
  });

  should('getMinHashLength tracks the minimal byte width of the field range', () => {
    eql(
      [255n, 256n, 257n, 65535n, 65536n].map((fieldOrder) => ({
        fieldOrder,
        len: mod.getMinHashLength(fieldOrder),
      })),
      [
        { fieldOrder: 255n, len: 2 },
        { fieldOrder: 256n, len: 2 },
        { fieldOrder: 257n, len: 3 },
        { fieldOrder: 65535n, len: 3 },
        { fieldOrder: 65536n, len: 3 },
      ]
    );
  });

  const bytesToNum = (bytes: Uint8Array, isLE: boolean) => {
    let n = 0n;
    if (isLE) {
      for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    } else {
      for (const b of bytes) n = (n << 8n) | BigInt(b);
    }
    return n;
  };

  const numToBytes = (n: bigint, len: number, isLE: boolean) => {
    const out = new Uint8Array(len);
    let x = n;
    for (let i = 0; i < len; i++) {
      const b = Number(x & 0xffn);
      out[isLE ? i : len - 1 - i] = b;
      x >>= 8n;
    }
    return out;
  };

  const minBytes = (fieldOrder: bigint) => Math.ceil((fieldOrder - 1n).toString(2).length / 8);

  const ref = (key: Uint8Array, fieldOrder: bigint, isLE: boolean) => {
    const num = bytesToNum(key, isLE);
    const reduced = (num % (fieldOrder - 1n)) + 1n;
    return numToBytes(reduced, minBytes(fieldOrder), isLE);
  };

  should('mapHashToField uses the minimal encoding width of the scalar range', () => {
    const key = new Uint8Array(16).fill(1);
    const out = [
      { fieldOrder: 255n, isLE: false, got: mod.mapHashToField(key, 255n, false) },
      { fieldOrder: 255n, isLE: true, got: mod.mapHashToField(key, 255n, true) },
      { fieldOrder: 256n, isLE: false, got: mod.mapHashToField(key, 256n, false) },
      { fieldOrder: 256n, isLE: true, got: mod.mapHashToField(key, 256n, true) },
      { fieldOrder: 257n, isLE: false, got: mod.mapHashToField(key, 257n, false) },
      { fieldOrder: 257n, isLE: true, got: mod.mapHashToField(key, 257n, true) },
    ].map(({ fieldOrder, isLE, got }) => ({
      fieldOrder,
      isLE,
      hex: Buffer.from(got).toString('hex'),
      expected: Buffer.from(ref(key, fieldOrder, isLE)).toString('hex'),
    }));
    eql(out, [
      { fieldOrder: 255n, isLE: false, hex: '04', expected: '04' },
      { fieldOrder: 255n, isLE: true, hex: '04', expected: '04' },
      { fieldOrder: 256n, isLE: false, hex: '11', expected: '11' },
      { fieldOrder: 256n, isLE: true, hex: '11', expected: '11' },
      { fieldOrder: 257n, isLE: false, hex: '0002', expected: '0002' },
      { fieldOrder: 257n, isLE: true, hex: '0200', expected: '0200' },
    ]);
  });

  should('nLength rejects cached bit lengths smaller than len(n)', () => {
    const cases = [
      { n: 255n, bits: 9 },
      { n: 257n, bits: 1 },
      { n: 257n, bits: 9 },
    ];
    const out = cases.map(({ n, bits }) => {
      try {
        return { n, bits, ok: true, value: mod.nLength(n, bits) };
      } catch (err) {
        return { n, bits, ok: false, err: err instanceof Error ? err.message : String(err) };
      }
    });
    eql(out, [
      { n: 255n, bits: 9, ok: true, value: { nBitLength: 9, nByteLength: 2 } },
      { n: 257n, bits: 1, ok: false, err: 'invalid n length: expected bit length (9) >= n.length (1)' },
      { n: 257n, bits: 9, ok: true, value: { nBitLength: 9, nByteLength: 2 } },
    ]);
  });
});

should.runWhen(import.meta.url);
