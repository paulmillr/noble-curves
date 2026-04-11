import compare_ from '@paulmillr/jsbt/bench-compare.js';
import { pippenger } from '../../src/abstract/curve.ts';
import { bls12_381 } from '../../src/bls12-381.ts';
import { title } from './_shared.ts';

(async () => {
  title('MSM timings');
  const g1 = bls12_381.G1.Point;
  const N = g1.Fn.ORDER;
  // Keep the bit patterns below Fn.ORDER; the old 255-bit literals made MSM reject the inputs.
  const bits = g1.Fn.BITS - 1;
  const ones = BigInt(`0b${'1'.repeat(bits)}`);
  function msm(p, s) {
    return pippenger(bls12_381.G1.Point, p, s)
  }
  function compare(title, samples, libs) {
    return compare_(title, {}, libs, { samples });
  }
  function sum(points, scalars) {
    let res = g1.ZERO;
    for (let i = 0; i < points.length; i++) res = res.add(points[i].multiplyUnsafe(scalars[i]));
    return res;
  }
  function check(title, cases) {
    // Validate once up front so we don't print timings for broken benchmark variants.
    for (const [name, c] of Object.entries(cases)) {
      if (!c.got().equals(c.want())) throw new Error(`${title}/${name}: invalid result`);
    }
  }

  const onezero = BigInt(`0b${'10'.repeat(Math.floor(bits / 2))}`);
  const one8zero = BigInt(`0b${'10000000'.repeat(Math.floor(bits / 8))}`);
  const single = {
    zero: { got: () => msm([g1.BASE], [0n]), want: () => sum([g1.BASE], [0n]) },
    one: { got: () => msm([g1.BASE], [1n]), want: () => sum([g1.BASE], [1n]) },
    one0: { got: () => msm([g1.ZERO], [1n]), want: () => sum([g1.ZERO], [1n]) },
    small: { got: () => msm([g1.BASE], [123n]), want: () => sum([g1.BASE], [123n]) },
    big: { got: () => msm([g1.BASE], [N - 1n]), want: () => sum([g1.BASE], [N - 1n]) },
  };
  // Single scalar
  check('single point', single);
  await compare('single point', 5000, Object.fromEntries(Object.entries(single).map(([k, v]) => [k, v.got])));
  // Multiple
  const points = [3n, 5n, 7n, 11n, 13n].map((i) => g1.BASE.multiply(i));
  const zeroes = [0n, 0n, 0n, 0n, 0n];
  const bigs = [N - 1n, N - 100n, N - 200n, N - 300n, N - 400n];
  const ones5 = [ones, ones, ones, ones, ones];
  const onezero5 = [onezero, onezero, onezero, onezero, onezero];
  const plain1 = [1n, 1n, 1n, 1n, 1n];
  const one8zero5 = [one8zero, one8zero, one8zero, one8zero, one8zero];
  const multi = {
    zero: { got: () => msm([g1.BASE, g1.BASE, g1.BASE, g1.BASE, g1.BASE], zeroes), want: () => sum([g1.BASE, g1.BASE, g1.BASE, g1.BASE, g1.BASE], zeroes) },
    zero2: { got: () => msm([g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO], zeroes), want: () => sum([g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO], zeroes) },
    big: { got: () => msm(points, bigs), want: () => sum(points, bigs) },
    same_scalar: { got: () => msm(points, ones5), want: () => sum(points, ones5) },
    same_scalar2: { got: () => msm(points, onezero5), want: () => sum(points, onezero5) },
    same_scalar3: { got: () => msm(points, plain1), want: () => sum(points, plain1) },
    same_scalar4: { got: () => msm(points, one8zero5), want: () => sum(points, one8zero5) },
  };
  check('multi point', multi);
  await compare('multi point', 500, Object.fromEntries(Object.entries(multi).map(([k, v]) => [k, v.got])));
  // Ok, and what about multiply itself?
  const mul = {
    '1*G1': { got: () => g1.BASE.multiply(1n), want: () => g1.BASE },
    '(n-1)*G1': { got: () => g1.BASE.multiply(N - 1n), want: () => g1.BASE.negate() },
    'ones*G1': { got: () => g1.BASE.multiply(ones), want: () => g1.BASE.multiplyUnsafe(ones) },
    'onezero*G1': { got: () => g1.BASE.multiply(onezero), want: () => g1.BASE.multiplyUnsafe(onezero) },
    'one8zero*G1': { got: () => g1.BASE.multiply(one8zero), want: () => g1.BASE.multiplyUnsafe(one8zero) },
    '1*Inf': { got: () => g1.ZERO.multiply(1n), want: () => g1.ZERO },
    '(n-1)*Inf': { got: () => g1.ZERO.multiply(N - 1n), want: () => g1.ZERO },
    'ones*Inf': { got: () => g1.ZERO.multiply(ones), want: () => g1.ZERO },
    'onezero*Inf': { got: () => g1.ZERO.multiply(onezero), want: () => g1.ZERO },
    'one8zero*Inf': { got: () => g1.ZERO.multiply(one8zero), want: () => g1.ZERO },
  };
  check('basic multiply', mul);
  await compare('basic multiply', 5000, Object.fromEntries(Object.entries(mul).map(([k, v]) => [k, v.got])));
})();
