import * as fc from 'fast-check';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import * as fft from '../src/abstract/fft.ts';
import { Field } from '../src/abstract/modular.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { bn254 } from '../src/bn254.ts';
import { bitLen } from '../src/utils.ts';

// Very useful to debug brp related stuff!
const indices = (a, b) => a.map((i) => b.indexOf(i));

describe('FFT', () => {
  describe('Utils', () => {
    should('integer helpers', () => {
      // this basically checks if integer is in form of '1 << X'
      eql(fft.isPowerOfTwo(0), false, 'isPowerOfTwo(0)');
      eql(fft.isPowerOfTwo(1), true, 'isPowerOfTwo(1)');
      eql(fft.isPowerOfTwo(2), true, 'isPowerOfTwo(2)');
      eql(fft.isPowerOfTwo(3), false, 'isPowerOfTwo(3)');
      eql(fft.isPowerOfTwo(2 ** 31), true, 'isPowerOfTwo(2**31)');
      eql(fft.isPowerOfTwo(2 ** 32 - 1), false, 'isPowerOfTwo(2**32-1)');
      throws(() => fft.isPowerOfTwo(2 ** 32), 'isPowerOfTwo rejects u32 overflow');
      for (let i = 0; i < 31; i++) eql(fft.isPowerOfTwo(1 << i), true, `isPowerOfTwo 1<<${i}`);

      eql(fft.nextPowerOfTwo(0), 1, 'nextPowerOfTwo(0)');
      eql(fft.nextPowerOfTwo(1), 1, 'nextPowerOfTwo(1)');
      eql(fft.nextPowerOfTwo(2), 2, 'nextPowerOfTwo(2)');
      eql(fft.nextPowerOfTwo(3), 4, 'nextPowerOfTwo(3)');
      eql(fft.nextPowerOfTwo(5), 8, 'nextPowerOfTwo(5)');
      eql(fft.nextPowerOfTwo(15), 16, 'nextPowerOfTwo(15)');
      eql(fft.nextPowerOfTwo(16), 16, 'nextPowerOfTwo(16)');
      eql(fft.nextPowerOfTwo(17), 32, 'nextPowerOfTwo(17)');
      eql(fft.nextPowerOfTwo(31), 32, 'nextPowerOfTwo(31)');
      eql(fft.nextPowerOfTwo(32), 32, 'nextPowerOfTwo(32)');
      eql(fft.nextPowerOfTwo(33), 64, 'nextPowerOfTwo(33)');
      eql(fft.nextPowerOfTwo(2 ** 30), 2 ** 30, 'nextPowerOfTwo(2**30)');
      eql(fft.nextPowerOfTwo(2 ** 30 + 1), 2 ** 31, 'nextPowerOfTwo(2**30+1)');
      // U32 boundary
      throws(() => fft.nextPowerOfTwo(0x8000_0001), 'nextPowerOfTwo rejects >2**31');
      throws(() => fft.nextPowerOfTwo(2 ** 32), 'nextPowerOfTwo rejects u32 overflow');
      throws(() => fft.nextPowerOfTwo(-1), 'nextPowerOfTwo rejects negative');
      // nextPowerOfTwo(n) is always a power of two
      for (let i = 0; i <= 2 ** 16; i++) {
        const pow = fft.nextPowerOfTwo(i);
        eql(fft.isPowerOfTwo(pow), true, `nextPowerOfTwo(${i}) is pow2`);
        eql(pow >= i, true, `nextPowerOfTwo(${i}) >= input`);
      }
      // nextPowerOfTwo(1 << k) == 1 << k
      for (let k = 0; k < 31; k++) {
        const val = 1 << k;
        eql(fft.nextPowerOfTwo(val), val, `nextPowerOfTwo preserves 1<<${k}`);
      }

      eql(fft.reverseBits(0b0001, 4), 0b1000, 'reverseBits 0001');
      eql(fft.reverseBits(0b0010, 4), 0b0100, 'reverseBits 0010');
      eql(fft.reverseBits(0b1111, 4), 0b1111, 'reverseBits 1111');
      const x = 0b10101;
      eql(fft.reverseBits(fft.reverseBits(x, 5), 5), x, 'reverseBits involution');
      eql(fft.reverseBits(1, 32), 0x8000_0000, 'reverseBits high bit');
      eql(fft.reverseBits(0x8000_0000, 32), 1, 'reverseBits low bit');
      throws(() => fft.reverseBits(1, 1.5), 'reverseBits rejects fractional bits');
      throws(() => fft.reverseBits(1, -1), 'reverseBits rejects negative bits');
      throws(() => fft.reverseBits(1, 33), 'reverseBits rejects over 32 bits');

      for (let i = 0; i < 32; i++) {
        const x = (1 << i) >>> 0;
        eql(fft.log2(x), bitLen(BigInt(x)) - 1, `log2 1<<${i}`);
      }
      throws(() => fft.log2(2 ** 32), 'log2 rejects u32 overflow');
    });
    describe('bitReversalPermutation', () => {
      should('basic and kzg table', () => {
        eql(fft.bitReversalPermutation([0]), [0], 'single element');
        // identity for two elements
        eql(fft.bitReversalPermutation([0, 1]), [0, 1], 'two elements');
        // left part is even indices, right part is odd indices
        eql(fft.bitReversalPermutation([0, 1, 2, 3]), [0, 2, 1, 3], 'four elements');
        // same as before, but also applied recursively for each part:
        // [0, 1, 2, 3, 4, 5, 6, 7] ->
        // [0, 2, 4, 6, 1, 3, 5, 7] ->
        // [0, 4, 2, 6, 1, 5, 3, 7]
        eql(
          fft.bitReversalPermutation([0, 1, 2, 3, 4, 5, 6, 7]),
          [0, 4, 2, 6, 1, 5, 3, 7],
          'eight elements'
        );

        const bitPerm = (values, bits) =>
          new Array(values.length).fill(0).map((_, i) => values[fft.reverseBits(i, bits)]);
        // same as before
        eql(bitPerm([0, 1, 2, 3, 4, 5, 6, 7], 3), [0, 4, 2, 6, 1, 5, 3, 7], 'bits=3');
        // but what happens if bitreverse is smaller?
        eql(bitPerm([0, 1, 2, 3, 4, 5, 6, 7], 2), [0, 2, 1, 3, 0, 2, 1, 3], 'bits=2');
        // which is:
        const x = [0, 1, 2, 3, 4, 5, 6, 7];
        const y = fft.bitReversalPermutation(x.slice(0, 4));
        eql(bitPerm([0, 1, 2, 3, 4, 5, 6, 7], 2), [...y, ...y], 'bits=2 duplicates half');
        // -> do half && dup
        eql(
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
          ],
          'kzg table example'
        );
      });
    });
  });
  describe('rootsOfUnity', () => {
    should('cache and fixed vectors', () => {
      let roots = fft.rootsOfUnity(Field(17n));
      const before = roots.inverse(2);
      roots.clear();
      const after = roots.inverse(2);
      eql(after === before, false, 'clear drops inverse cache');

      roots = fft.rootsOfUnity(bls12_381.fields.Fr, 7n);
      eql(
        roots.roots(3),
        [
          1n,
          23674694431658770659612952115660802947967373701506253797663184111817857449850n,
          3465144826073652318776269530687742778270252468765361963008n,
          8685283084174350996472453922654922162880456818468779543064782192722679779374n,
          52435875175126190479447740508185965837690552500527637822603658699938581184512n,
          28761180743467419819834788392525162889723178799021384024940474588120723734663n,
          52435875175126190475982595682112313518914282969839895044333406231173219221505n,
          43750592090951839482975286585531043674810095682058858279538876507215901405139n,
        ],
        'bls12_381 roots'
      );
      eql(
        roots.brp(3),
        [
          1n,
          52435875175126190479447740508185965837690552500527637822603658699938581184512n,
          3465144826073652318776269530687742778270252468765361963008n,
          52435875175126190475982595682112313518914282969839895044333406231173219221505n,
          23674694431658770659612952115660802947967373701506253797663184111817857449850n,
          28761180743467419819834788392525162889723178799021384024940474588120723734663n,
          8685283084174350996472453922654922162880456818468779543064782192722679779374n,
          43750592090951839482975286585531043674810095682058858279538876507215901405139n,
        ],
        'bls12_381 brp'
      );

      roots = fft.rootsOfUnity(bn254.fields.Fr, 7n);
      eql(
        roots.roots(3),
        [
          1n,
          19540430494807482326159819597004422086093766032135589407132600596362845576832n,
          21888242871839275217838484774961031246007050428528088939761107053157389710902n,
          13274704216607947843011480449124596415239537050559949017414504948711435969894n,
          21888242871839275222246405745257275088548364400416034343698204186575808495616n,
          2347812377031792896086586148252853002454598368280444936565603590212962918785n,
          4407920970296243842541313971887945403937097133418418784715n,
          8613538655231327379234925296132678673308827349856085326283699237864372525723n,
        ],
        'bn254 roots'
      );
      eql(
        roots.brp(3),
        [
          1n,
          21888242871839275222246405745257275088548364400416034343698204186575808495616n,
          21888242871839275217838484774961031246007050428528088939761107053157389710902n,
          4407920970296243842541313971887945403937097133418418784715n,
          19540430494807482326159819597004422086093766032135589407132600596362845576832n,
          2347812377031792896086586148252853002454598368280444936565603590212962918785n,
          13274704216607947843011480449124596415239537050559949017414504948711435969894n,
          8613538655231327379234925296132678673308827349856085326283699237864372525723n,
        ],
        'bn254 brp'
      );
    });
  });
  should('poly extend truncates shorter target length', () => {
    const F = Field(17n);
    const P = fft.poly(F, fft.rootsOfUnity(F));
    eql(P.extend([1n, 2n, 3n], 2), [1n, 2n]);
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

    eql(fftFr.direct(input), exp);
    eql(fftFr.direct(fft.bitReversalPermutation(input), true), exp);
    // Fails, why? scaling?
    eql(fft.bitReversalPermutation(fftFr.direct(input, false, true)), exp);
    eql(
      fft.bitReversalPermutation(fftFr.direct(fft.bitReversalPermutation(input), true, true)),
      exp
    );
    // inverse
    eql(fftFr.inverse(fftFr.direct(input)), input);
    eql(fftFr.inverse(fftFr.direct(input, false, true), true), input);
    eql(fft.bitReversalPermutation(fftFr.inverse(fftFr.direct(input), false, true)), input);
    eql(
      fft.bitReversalPermutation(fftFr.inverse(fftFr.direct(input, false, true), true, true)),
      input
    );
  });
  should('size-1 FFT is identity', () => {
    const F = Field(17n);
    const roots = fft.rootsOfUnity(F, 3n);
    const fftF = fft.FFT(roots, F);
    eql(roots.brp(0), [1n]);
    eql(fftF.direct([5n]), [5n]);
    eql(fftF.inverse([5n]), [5n]);
    throws(() => fftF.inverse([]), /FFT: Polynomial size should be power of two/);
  });
  should('FFTCore rejects mismatched root tables', () => {
    const F = Field(17n);
    const roots = fft.rootsOfUnity(F, 3n).roots(2);
    throws(
      () => fft.FFTCore(F, { N: 8, roots, dit: true }),
      /wrong roots length: expected 8, got 4/
    );
  });
  should('FFTCore validates skipStages', () => {
    const F = Field(17n);
    const roots = fft.rootsOfUnity(F, 3n).roots(2);
    throws(() => fft.FFTCore(F, { N: 4, roots, dit: true, skipStages: -1 }), /wrong u32/);
    throws(() => fft.FFTCore(F, { N: 4, roots, dit: true, skipStages: 1.5 }), /wrong u32/);
    throws(() => fft.FFTCore(F, { N: 4, roots, dit: true, skipStages: 2 }), /skipStages/);
  });
  should('poly.eval rejects mismatched basis vector lengths', () => {
    const F = Field(17n);
    const P = fft.poly(F, fft.rootsOfUnity(F, 3n));
    throws(() => P.eval([1n, 2n, 3n], [1n, 2n]), /poly: mismatched lengths 3 vs 2/);
    throws(() => P.eval([1n, 2n, 3n], [1n, 2n, 3n, 4n]), /poly: mismatched lengths 3 vs 4/);
  });
  should('poly.lagrange handles the size-1 identity case and explicit weights', () => {
    const F = Field(17n);
    const P = fft.poly(F, fft.rootsOfUnity(F, 3n));
    const coeffs = [42n];
    const before = [...coeffs];
    eql(P.lagrange.basis(1n, 1, true), [1n]);
    eql(P.lagrange.eval(coeffs, 1n, true), 42n);
    eql(coeffs, before);
    const weights = [1n, 3n, 9n, 10n];
    const weights0 = [...weights];
    const x = 5n;
    const n = 4;
    const got = P.lagrange.basis(x, n, false, weights as never);
    const expected = (() => {
      const out = Array(n).fill(0n);
      const c = F.mul(F.sub(F.pow(x, BigInt(n)), F.ONE), F.inv(BigInt(n)));
      const denom = Array(n).fill(0n);
      for (let i = 0; i < n; i++) denom[i] = F.sub(x, weights[i]);
      const inv = F.invertBatch(denom);
      for (let i = 0; i < n; i++) out[i] = F.mul(c, F.mul(weights[i], inv[i]));
      return out;
    })();
    eql(got, expected);
    eql(weights, weights0);
  });
  should('poly.lagrange uses explicit weights for its fast path', () => {
    const F = Field(17n);
    const P = fft.poly(F, fft.rootsOfUnity(F, 3n));
    const weights = [2n, 3n, 5n, 8n];
    // x=1 is a standard omega root, but it is not in the explicit weights domain.
    eql(P.lagrange.basis(1n, 4, false, weights as never), [0n, 0n, 0n, 0n]);
    eql(P.lagrange.basis(2n, 4, false, weights as never), [1n, 0n, 0n, 0n]);
  });
  should('poly.lagrange rejects non-power-of-two lengths', () => {
    const F = Field(17n);
    const P = fft.poly(F, fft.rootsOfUnity(F, 3n));
    throws(() => P.lagrange.basis(5n, 3), /power of two/i);
    throws(() => P.lagrange.eval([1n, 2n, 3n], 5n), /power of two/i);
  });
  should('poly.shift preserves empty polynomial shape', () => {
    const F = Field(17n);
    const P = fft.poly(F, fft.rootsOfUnity(F, 3n));
    eql(P.shift([], 2n), []);
  });
  for (const [name, curve] of Object.entries({ bls12_381, bn254 })) {
    const Fr = curve.fields.Fr;
    const G1 = curve.G1.Point;
    const FR_BIGINT = fc.bigInt(1n, Fr.ORDER - 1n);
    const FR_BIGINT_POLY = fc.array(FR_BIGINT, { minLength: 8, maxLength: 8 });
    const roots = fft.rootsOfUnity(Fr, 7n);
    const fftFr = fft.FFT(roots, Fr);
    const fftG1 = fft.FFT(roots, {
      add: (a, b) => a.add(b),
      sub: (a, b) => a.subtract(b),
      mul: (a, scalar) => a.multiplyUnsafe(scalar),
      inv: (a) => Fr.inv(a),
    });
    const P = fft.poly(Fr, roots);
    const Pf = fft.poly(Fr, roots, undefined, fftFr);

    describe(`Polynomimal/${name}`, () => {
      should('degree/arithmetic/eval', () => {
        const l = (msg) => `${name}: ${msg}`;
        eql(P.degree([]), -1, l('degree []'));
        eql(P.degree([0n]), -1, l('degree zero'));
        eql(P.degree([1n]), 0, l('degree const'));
        eql(P.degree([1n, 0n]), 0, l('degree trailing zero 1'));
        eql(P.degree([1n, 0n, 0n]), 0, l('degree trailing zero 2'));
        eql(P.degree([1n, 1n, 0n, 0n]), 1, l('degree linear 1'));
        eql(P.degree([1n, 2n, 0n, 0n]), 1, l('degree linear 2'));
        eql(P.degree([1n, 1n]), 1, l('degree linear no trailing'));

        eql(P.add([], []), [], l('add empty'));
        eql(P.add([1n], [0n]), [1n], l('a + 0 = a'));
        eql(P.sub([1n], [0n]), [1n], l('a - 0 = a'));
        eql(P.sub([1n], [1n]), [0n], l('a - a = 0'));

        const a = [1n, 2n, 3n];
        const b = [3n, 2n, 1n];
        eql(P.add(a, b), P.add(b, a), l('a + b = b + a'));

        const c = [5n, 3n, 1n];
        const d = [1n, 3n, 0n];
        const neg = P.sub(d, c).map((x) => Fr.neg(x));
        eql(P.sub(c, d), neg, l('a - b = -(b - a)'));

        // assume eval using basis of monomials
        const x = 2n;
        const monomialBasis = [1n, x, x ** 2n]; // 1, x, x^2
        const expected = Fr.add(Fr.add(1n, 2n * x), 3n * x * x);
        eql(P.eval(a, monomialBasis), expected, l('eval basis'));
        throws(() => P.eval(a, [1n, x]), /poly: mismatched lengths 3 vs 2/, l('eval short basis'));
        throws(
          () => P.eval(a, [1n, x, x ** 2n, x ** 3n]),
          /poly: mismatched lengths 3 vs 4/,
          l('eval long basis')
        );
      });
      for (const p of [P, Pf]) {
        should('mul/convolve small cases', () => {
          const l = (msg) => `${name}: ${p === P ? 'poly' : 'poly+fft'}: ${msg}`;
          const a = [1n, 2n, 3n, 4n];
          eql(p.mul(a, 0n), [0n, 0n, 0n, 0n], l('a * 0 = 0'));
          eql(p.mul(a, 1n), a, l('a * 1 = a'));
          eql(p.mul(a, [0n, 0n, 0n, 0n]), [0n, 0n, 0n, 0n], l('a * zero poly = 0'));
          eql(p.mul(a, [1n, 1n, 1n, 1n]), [10n, 10n, 10n, 10n], l('a * ones poly'));
          eql(
            p.convolve(a, [0n, 0n, 0n, 0n]),
            [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
            l('convolve zero')
          );
          eql(
            p.convolve(a, [1n, 1n, 1n, 1n]),
            [1n, 3n, 6n, 10n, 9n, 7n, 4n, 0n],
            l('convolve ones')
          );
          // (1 + 2x) * (3 + 4x) = 3 + 10x + 8x^2
          eql(p.mul([1n, 2n], [3n, 4n]), [11n, 10n], l('mul small'));
          eql(p.convolve([1n, 2n], [3n, 4n]), [3n, 10n, 8n, 0n], l('convolve small'));
        });
      }
      describe('monomial', () => {
        should('eval/basis properties', () => {
          const l = (msg) => `${name}: monomial ${msg}`;
          eql(P.monomial.eval([3n, 2n, 1n], 5n), 38n, l('eval')); // 3 + 2x + x²
          eql(P.monomial.basis(2n, 0), [], l('basis zero'));
          eql(P.monomial.basis(2n, 1), [1n], l('basis one')); // [1]
          eql(P.monomial.basis(2n, 3), [1n, 2n, 4n], l('basis x=2')); // [1, x, x²]
          eql(P.monomial.basis(3n, 4), [1n, 3n, 9n, 27n], l('basis x=3')); // 3⁰, 3¹, 3², 3³
          fc.assert(
            fc.property(FR_BIGINT_POLY, FR_BIGINT, (a, x) => {
              eql(
                P.eval(a, P.monomial.basis(x, a.length)),
                P.monomial.eval(a, x),
                l('eval roundtrip')
              );
            })
          );
        });
      });
    });
    // Basic sanity checks
    describe(`FFT/${name}`, () => {
      should('random and algebra properties', () => {
        const l = (msg) => `${name}: ${msg}`;
        fc.assert(
          fc.property(FR_BIGINT_POLY, (poly) => {
            eql(fftFr.inverse(fftFr.direct(poly)), poly, l('Fr inverse(direct(poly))'));
            eql(fftFr.direct(fftFr.inverse(poly)), poly, l('Fr direct(inverse(poly))'));
          })
        );
        fc.assert(
          fc.property(FR_BIGINT_POLY, (poly) => {
            eql(
              fft.bitReversalPermutation(fft.bitReversalPermutation(poly)),
              poly,
              l('BRP roundtrip')
            );
          })
        );
        fc.assert(
          fc.property(FR_BIGINT_POLY, (poly) => {
            const polyG1 = poly.map((i) => G1.BASE.multiplyUnsafe(i));
            const polyG1Affine = polyG1.map((i) => i.toAffine());
            eql(
              fftG1.inverse(fftG1.direct(polyG1)).map((i) => i.toAffine()),
              polyG1Affine,
              l('G1 inverse(direct(poly))')
            );
            eql(
              fftG1.direct(fftG1.inverse(polyG1)).map((i) => i.toAffine()),
              polyG1Affine,
              l('G1 direct(inverse(poly))')
            );
          })
        );
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, (a, b) => {
            eql(
              fftFr.direct(P.add(a, b)),
              P.add(fftFr.direct(a), fftFr.direct(b)),
              l('FFT additivity')
            );
          })
        );
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT, (a, c) => {
            eql(fftFr.direct(P.mul(a, c)), P.mul(fftFr.direct(a), c), l('FFT scalar mul'));
          })
        );
        fc.assert(
          fc.property(FR_BIGINT, (c) => {
            const N = 256;
            const poly = P.create(N, c);
            const out = fftFr.direct(poly);
            eql(Fr.eql(out[0], Fr.mul(c, BigInt(N))), true, l('FFT const first coefficient'));
            for (let i = 1; i < out.length; i++)
              eql(Fr.is0(out[i]), true, l(`FFT const zero ${i}`));
          })
        );
        const out = fftFr.direct(P.create(256));
        for (const x of out) eql(Fr.is0(x), true, l('FFT zero'));
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, FR_BIGINT, (a, b, x) => {
            const ab = P.convolve(a, b);
            eql(ab, Pf.convolve(a, b), l('convolve matches fast path'));
            const y1 = P.monomial.eval(ab, x);
            const y2 = Fr.mul(P.monomial.eval(a, x), P.monomial.eval(b, x));
            eql(y1, y2, l('eval(a*b) = eval(a)*eval(b)'));
          })
        );
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, FR_BIGINT, (a, b, x) => {
            const y1 = P.monomial.eval(P.add(a, b), x);
            const y2 = Fr.add(P.monomial.eval(a, x), P.monomial.eval(b, x));
            eql(y1, y2, l('eval(a+b) = eval(a)+eval(b)'));
          })
        );
        fc.assert(
          fc.property(FR_BIGINT_POLY, FR_BIGINT_POLY, FR_BIGINT_POLY, (a, b, c) => {
            const lhs = P.convolve(a, P.add(b, c));
            eql(lhs, Pf.convolve(a, Pf.add(b, c)), l('left distributivity fast path'));
            const rhs = P.add(P.convolve(a, b), P.convolve(a, c));
            eql(
              rhs,
              Pf.add(Pf.convolve(a, b), Pf.convolve(a, c)),
              l('right distributivity fast path')
            );
            eql(lhs, rhs, l('convolve distributivity'));
          })
        );
      });
    });
  }
});

should.runWhen(import.meta.url);
