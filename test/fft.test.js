import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'node:assert';
import * as fft from '../esm/abstract/fft.js';
import { bitLen } from '../esm/abstract/utils.js';
import { bls12_381 } from '../esm/bls12-381.js';
import { bn254 } from '../esm/bn254.js';

// Very useful to debug brp related stuff!
const indices = (a, b) => a.map((i) => b.indexOf(i));

describe('FFT', () => {
  describe('Utils', () => {
    should('isPowerOfTwo', () => {
      // this basically checks if integer is in form of '1 << X'
      deepStrictEqual(fft.isPowerOfTwo(0), false);
      deepStrictEqual(fft.isPowerOfTwo(1), true);
      deepStrictEqual(fft.isPowerOfTwo(2), true);
      deepStrictEqual(fft.isPowerOfTwo(3), false);
      deepStrictEqual(fft.isPowerOfTwo(2 ** 31), true);
      deepStrictEqual(fft.isPowerOfTwo(2 ** 32 - 1), false);
      throws(() => fft.isPowerOfTwo(2 ** 32));
      for (let i = 0; i < 31; i++) deepStrictEqual(fft.isPowerOfTwo(1 << i), true);
    });
    should('nextPowerOfTwo', () => {
      deepStrictEqual(fft.nextPowerOfTwo(0), 1);
      deepStrictEqual(fft.nextPowerOfTwo(1), 1);
      deepStrictEqual(fft.nextPowerOfTwo(2), 2);
      deepStrictEqual(fft.nextPowerOfTwo(3), 4);
      deepStrictEqual(fft.nextPowerOfTwo(5), 8);
      deepStrictEqual(fft.nextPowerOfTwo(15), 16);
      deepStrictEqual(fft.nextPowerOfTwo(16), 16);
      deepStrictEqual(fft.nextPowerOfTwo(17), 32);
      deepStrictEqual(fft.nextPowerOfTwo(31), 32);
      deepStrictEqual(fft.nextPowerOfTwo(32), 32);
      deepStrictEqual(fft.nextPowerOfTwo(33), 64);
      deepStrictEqual(fft.nextPowerOfTwo(2 ** 30), 2 ** 30);
      deepStrictEqual(fft.nextPowerOfTwo(2 ** 30 + 1), 2 ** 31);
      // U32 boundary
      throws(() => fft.nextPowerOfTwo(2 ** 32));
      throws(() => fft.nextPowerOfTwo(-1));
      // nextPowerOfTwo(n) is always a power of two
      for (let i = 0; i <= 2 ** 16; i++) {
        const pow = fft.nextPowerOfTwo(i);
        deepStrictEqual(fft.isPowerOfTwo(pow), true);
        deepStrictEqual(pow >= i, true);
      }
      // nextPowerOfTwo(1 << k) == 1 << k
      for (let k = 0; k < 31; k++) {
        const val = 1 << k;
        deepStrictEqual(fft.nextPowerOfTwo(val), val);
      }
    });
    should('reverseBits', () => {
      deepStrictEqual(fft.reverseBits(0b0001, 4), 0b1000);
      deepStrictEqual(fft.reverseBits(0b0010, 4), 0b0100);
      deepStrictEqual(fft.reverseBits(0b1111, 4), 0b1111);
      const x = 0b10101;
      deepStrictEqual(fft.reverseBits(fft.reverseBits(x, 5), 5), x);
    });
    should('log2', () => {
      for (let i = 0; i < 32; i++) {
        const x = (1 << i) >>> 0;
        deepStrictEqual(fft.log2(x), bitLen(BigInt(x)) - 1);
      }
      throws(() => fft.log2(2 ** 32));
    });
    describe('bitReversalPermutation', () => {
      should('basic', () => {
        // identity for two elements
        deepStrictEqual(fft.bitReversalPermutation([0, 1]), [0, 1]);
        // left part is even indices, right part is odd indices
        deepStrictEqual(fft.bitReversalPermutation([0, 1, 2, 3]), [0, 2, 1, 3]);
        // same as before, but also applied recursively for each part:
        // [0, 1, 2, 3, 4, 5, 6, 7] ->
        // [0, 2, 4, 6, 1, 3, 5, 7] ->
        // [0, 4, 2, 6, 1, 5, 3, 7]
        deepStrictEqual(
          fft.bitReversalPermutation([0, 1, 2, 3, 4, 5, 6, 7]),
          [0, 4, 2, 6, 1, 5, 3, 7]
        );

        const bitPerm = (values, bits) =>
          new Array(values.length).fill(0).map((_, i) => values[fft.reverseBits(i, bits)]);
        // same as before
        deepStrictEqual(bitPerm([0, 1, 2, 3, 4, 5, 6, 7], 3), [0, 4, 2, 6, 1, 5, 3, 7]);
        // but what happens if bitreverse is smaller?
        deepStrictEqual(bitPerm([0, 1, 2, 3, 4, 5, 6, 7], 2), [0, 2, 1, 3, 0, 2, 1, 3]);
        // which is:
        const x = [0, 1, 2, 3, 4, 5, 6, 7];
        const y = fft.bitReversalPermutation(x.slice(0, 4));
        deepStrictEqual(bitPerm([0, 1, 2, 3, 4, 5, 6, 7], 2), [...y, ...y]);
        // -> do half && dup
      });
      should('kzg table example', () => {
        deepStrictEqual(
          fft.bitReversalPermutation(Array.from({ length: 128 }, (_, j) => j)),
          [
            0x00, 0x40, 0x20, 0x60, 0x10, 0x50, 0x30, 0x70, 0x08, 0x48, 0x28, 0x68, 0x18, 0x58,
            0x38, 0x78, 0x04, 0x44, 0x24, 0x64, 0x14, 0x54, 0x34, 0x74, 0x0c, 0x4c, 0x2c, 0x6c,
            0x1c, 0x5c, 0x3c, 0x7c, 0x02, 0x42, 0x22, 0x62, 0x12, 0x52, 0x32, 0x72, 0x0a, 0x4a,
            0x2a, 0x6a, 0x1a, 0x5a, 0x3a, 0x7a, 0x06, 0x46, 0x26, 0x66, 0x16, 0x56, 0x36, 0x76,
            0x0e, 0x4e, 0x2e, 0x6e, 0x1e, 0x5e, 0x3e, 0x7e, 0x01, 0x41, 0x21, 0x61, 0x11, 0x51,
            0x31, 0x71, 0x09, 0x49, 0x29, 0x69, 0x19, 0x59, 0x39, 0x79, 0x05, 0x45, 0x25, 0x65,
            0x15, 0x55, 0x35, 0x75, 0x0d, 0x4d, 0x2d, 0x6d, 0x1d, 0x5d, 0x3d, 0x7d, 0x03, 0x43,
            0x23, 0x63, 0x13, 0x53, 0x33, 0x73, 0x0b, 0x4b, 0x2b, 0x6b, 0x1b, 0x5b, 0x3b, 0x7b,
            0x07, 0x47, 0x27, 0x67, 0x17, 0x57, 0x37, 0x77, 0x0f, 0x4f, 0x2f, 0x6f, 0x1f, 0x5f,
            0x3f, 0x7f,
          ]
        );
      });
    });
  });
  describe('rootsOfUnity', () => {
    should('bls12_381', () => {
      const roots = fft.rootsOfUnity(bls12_381.fields.Fr, 7n);
      deepStrictEqual(roots.roots(3), [
        1n,
        23674694431658770659612952115660802947967373701506253797663184111817857449850n,
        3465144826073652318776269530687742778270252468765361963008n,
        8685283084174350996472453922654922162880456818468779543064782192722679779374n,
        52435875175126190479447740508185965837690552500527637822603658699938581184512n,
        28761180743467419819834788392525162889723178799021384024940474588120723734663n,
        52435875175126190475982595682112313518914282969839895044333406231173219221505n,
        43750592090951839482975286585531043674810095682058858279538876507215901405139n,
      ]);
      deepStrictEqual(roots.brp(3), [
        1n,
        52435875175126190479447740508185965837690552500527637822603658699938581184512n,
        3465144826073652318776269530687742778270252468765361963008n,
        52435875175126190475982595682112313518914282969839895044333406231173219221505n,
        23674694431658770659612952115660802947967373701506253797663184111817857449850n,
        28761180743467419819834788392525162889723178799021384024940474588120723734663n,
        8685283084174350996472453922654922162880456818468779543064782192722679779374n,
        43750592090951839482975286585531043674810095682058858279538876507215901405139n,
      ]);
    });
    should('bn254', () => {
      const roots = fft.rootsOfUnity(bn254.fields.Fr, 7n);
      deepStrictEqual(roots.roots(3), [
        1n,
        19540430494807482326159819597004422086093766032135589407132600596362845576832n,
        21888242871839275217838484774961031246007050428528088939761107053157389710902n,
        13274704216607947843011480449124596415239537050559949017414504948711435969894n,
        21888242871839275222246405745257275088548364400416034343698204186575808495616n,
        2347812377031792896086586148252853002454598368280444936565603590212962918785n,
        4407920970296243842541313971887945403937097133418418784715n,
        8613538655231327379234925296132678673308827349856085326283699237864372525723n,
      ]);
      deepStrictEqual(roots.brp(3), [
        1n,
        21888242871839275222246405745257275088548364400416034343698204186575808495616n,
        21888242871839275217838484774961031246007050428528088939761107053157389710902n,
        4407920970296243842541313971887945403937097133418418784715n,
        19540430494807482326159819597004422086093766032135589407132600596362845576832n,
        2347812377031792896086586148252853002454598368280444936565603590212962918785n,
        13274704216607947843011480449124596415239537050559949017414504948711435969894n,
        8613538655231327379234925296132678673308827349856085326283699237864372525723n,
      ]);
    });
  });
  should('Basic FFT', () => {
    const Fr = bls12_381.fields.Fr;

    const roots = fft.rootsOfUnity(Fr, 7n);
    const fftFr = fft.FFT(roots, Fr);
    const input = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
    const exp = [
      36n,
      27867715462046084800141018067000387794575257298931808991818101006592146784607n,
      52435875175126190465587161203891356562585474377776666709522648824877133332477n,
      27867715462046084827862176675589606344785413544433751217980120756715042488671n,
      52435875175126190479447740508185965837690552500527637822603658699938581184509n,
      24568159713080105651585563832596359492905138956093886604623537943223538695834n,
      13860579304294609275105078122750971113081009875061447852028n,
      24568159713080105679306722441185578043115295201595828830785557693346434399898n,
    ];

    deepStrictEqual(fftFr.direct(input), exp);
    deepStrictEqual(fftFr.direct(fft.bitReversalPermutation(input), true), exp);
    // Fails, why? scaling?
    deepStrictEqual(fft.bitReversalPermutation(fftFr.direct(input, false, true)), exp);
    deepStrictEqual(
      fft.bitReversalPermutation(fftFr.direct(fft.bitReversalPermutation(input), true, true)),
      exp
    );
    // inverse
    deepStrictEqual(fftFr.inverse(fftFr.direct(input)), input);
    deepStrictEqual(fftFr.inverse(fftFr.direct(input, false, true), true), input);
    deepStrictEqual(
      fft.bitReversalPermutation(fftFr.inverse(fftFr.direct(input), false, true)),
      input
    );
    deepStrictEqual(
      fft.bitReversalPermutation(fftFr.inverse(fftFr.direct(input, false, true), true, true)),
      input
    );
  });
  for (const [name, curve] of Object.entries({ bls12_381, bn254 })) {
    const Fr = curve.fields.Fr;
    const G1 = curve.G1.ProjectivePoint;
    const FR_BIGINT = fc.bigInt(1n, Fr.ORDER - 1n);
    const FR_BIGINT_POLY = fc.array(FR_BIGINT, { minLength: 8, maxLength: 8 });
    const roots = fft.rootsOfUnity(Fr, 7n);
    const fftFr = fft.FFT(roots, Fr);
    const fftG1 = fft.FFT(roots, {
      add: (a, b) => a.add(b),
      sub: (a, b) => a.subtract(b),
      mul: (a, scalar) => a.multiplyUnsafe(scalar),
      inv: Fr.inv,
    });
    const P = fft.poly(Fr, roots);
    const Pf = fft.poly(Fr, roots, undefined, fftFr);

    describe(`Polynomimal/${name}`, () => {
      should('degree', () => {
        deepStrictEqual(P.degree([]), -1);
        deepStrictEqual(P.degree([0n]), -1);
        deepStrictEqual(P.degree([1n]), 0);
        deepStrictEqual(P.degree([1n, 0n]), 0);
        deepStrictEqual(P.degree([1n, 0n, 0n]), 0);
        deepStrictEqual(P.degree([1n, 1n, 0n, 0n]), 1);
        deepStrictEqual(P.degree([1n, 2n, 0n, 0n]), 1);
        deepStrictEqual(P.degree([1n, 1n]), 1);
      });
      should('a + 0 = a, a - 0 = a, a - a = 0', () => {
        deepStrictEqual(P.add([], []), []);
        deepStrictEqual(P.add([1n], [0n]), [1n]);
        deepStrictEqual(P.sub([1n], [0n]), [1n]);
        deepStrictEqual(P.sub([1n], [1n]), [0n]);
      });
      should('a + b = b + a', () => {
        const a = [1n, 2n, 3n];
        const b = [3n, 2n, 1n];
        deepStrictEqual(P.add(a, b), P.add(b, a));
      });
      should('a - b = -(b - a)', () => {
        const a = [5n, 3n, 1n];
        const b = [1n, 3n, 0n];
        const neg = P.sub(b, a).map((x) => Fr.neg(x));
        deepStrictEqual(P.sub(a, b), neg);
      });
      should('eval basis', () => {
        const a = [1n, 2n, 3n]; // assume eval using basis of monomials
        const x = 2n;
        const monomialBasis = [1n, x, x ** 2n]; // 1, x, x^2
        const expected = Fr.add(Fr.add(1n, 2n * x), 3n * x * x);
        deepStrictEqual(P.eval(a, monomialBasis), expected);
      });
      for (const p of [P, Pf]) {
        should('a * 0 = 0, a * 1 = a', () => {
          const a = [1n, 2n, 3n, 4n];
          deepStrictEqual(p.mul(a, 0n), [0n, 0n, 0n, 0n]);
          deepStrictEqual(p.mul(a, 1n), a);
          deepStrictEqual(p.mul(a, [0n, 0n, 0n, 0n]), [0n, 0n, 0n, 0n]);
          deepStrictEqual(p.mul(a, [1n, 1n, 1n, 1n]), [10n, 10n, 10n, 10n]);
          deepStrictEqual(p.convolve(a, [0n, 0n, 0n, 0n]), [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
          deepStrictEqual(p.convolve(a, [1n, 1n, 1n, 1n]), [1n, 3n, 6n, 10n, 9n, 7n, 4n, 0n]);
        });
        should('mul small', () => {
          // (1 + 2x) * (3 + 4x) = 3 + 10x + 8x^2
          deepStrictEqual(p.mul([1n, 2n], [3n, 4n]), [11n, 10n]);
          deepStrictEqual(p.convolve([1n, 2n], [3n, 4n]), [3n, 10n, 8n, 0n]);
        });
      }
      describe('monomial', () => {
        should('eval', () => {
          deepStrictEqual(P.monomial.eval([3n, 2n, 1n], 5n), 38n); // 3 + 2x + x²
        });
        should('monomialBasis(x, n) = [x^0, x^1...x^n-1]', () => {
          deepStrictEqual(P.monomial.basis(2n, 0), []);
          deepStrictEqual(P.monomial.basis(2n, 1), [1n]); // [1]
          deepStrictEqual(P.monomial.basis(2n, 3), [1n, 2n, 4n]); // [1, x, x²]
          deepStrictEqual(P.monomial.basis(3n, 4), [1n, 3n, 9n, 27n]); // 3⁰, 3¹, 3², 3³
        });
        should('eval(a, monomialBasis(x)) = evalMonomial(a, x)', () =>
          fc.assert(
            fc.property(FR_BIGINT_POLY, FR_BIGINT, (a, x) => {
              deepStrictEqual(P.eval(a, P.monomial.basis(x, a.length)), P.monomial.eval(a, x));
            })
          )
        );
      });
    });
    // Basic sanity checks
    describe(`FFT/${name}`, () => {
      should('random/Fr', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, (poly) => {
            deepStrictEqual(fftFr.inverse(fftFr.direct(poly)), poly);
            deepStrictEqual(fftFr.direct(fftFr.inverse(poly)), poly);
          })
        )
      );
      should('random/BRP', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, (poly) => {
            deepStrictEqual(fft.bitReversalPermutation(fft.bitReversalPermutation(poly)), poly);
          })
        )
      );
      should('random/G1', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, (poly) => {
            const polyG1 = poly.map((i) => G1.BASE.multiplyUnsafe(i));
            const polyG1Affine = polyG1.map((i) => i.toAffine());
            deepStrictEqual(
              fftG1.inverse(fftG1.direct(polyG1)).map((i) => i.toAffine()),
              polyG1Affine
            );
            deepStrictEqual(
              fftG1.direct(fftG1.inverse(polyG1)).map((i) => i.toAffine()),
              polyG1Affine
            );
          })
        )
      );
      should('FFT(a + b) = FFT(a) + FFT(b)', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, (a, b) => {
            deepStrictEqual(fftFr.direct(P.add(a, b)), P.add(fftFr.direct(a), fftFr.direct(b)));
          })
        )
      );
      should('FFT(c * a) = c * FFT(a)', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT, (a, c) => {
            deepStrictEqual(fftFr.direct(P.mul(a, c)), P.mul(fftFr.direct(a), c));
          })
        )
      );
      should('FFT([c, c, ..., c]) = [Nc, 0, ..., 0]', () =>
        fc.assert(
          fc.property(FR_BIGINT, (c) => {
            const N = 256;
            const poly = P.create(N, c);
            const out = fftFr.direct(poly);
            deepStrictEqual(Fr.eql(out[0], Fr.mul(c, BigInt(N))), true);
            for (let i = 1; i < out.length; i++) deepStrictEqual(Fr.is0(out[i]), true);
          })
        )
      );
      should('FFT(0) = 0', () => {
        const out = fftFr.direct(P.create(256));
        for (const x of out) deepStrictEqual(Fr.is0(x), true);
      });
      should('eval(a * b, x) = eval(a, x) * eval(b, x)', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, FR_BIGINT, (a, b, x) => {
            const ab = P.convolve(a, b);
            deepStrictEqual(ab, Pf.convolve(a, b));
            const y1 = P.monomial.eval(ab, x);
            const y2 = Fr.mul(P.monomial.eval(a, x), P.monomial.eval(b, x));
            deepStrictEqual(y1, y2);
          })
        )
      );
      should('eval(a + b, x) = eval(a, x) + eval(b, x)', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, FR_BIGINT, (a, b, x) => {
            const y1 = P.monomial.eval(P.add(a, b), x);
            const y2 = Fr.add(P.monomial.eval(a, x), P.monomial.eval(b, x));
            deepStrictEqual(y1, y2);
          })
        )
      );
      should('a * (b + c) = a * b + a * c', () =>
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, FR_BIGINT_POLY, (a, b, c) => {
            const lhs = P.convolve(a, P.add(b, c));
            deepStrictEqual(lhs, Pf.convolve(a, Pf.add(b, c)));
            const rhs = P.add(P.convolve(a, b), P.convolve(a, c));
            deepStrictEqual(rhs, Pf.add(Pf.convolve(a, b), Pf.convolve(a, c)));
            deepStrictEqual(lhs, rhs);
          })
        )
      );
    });
  }
});

should.runWhen(import.meta.url);
