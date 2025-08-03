import { pippenger } from '@noble/curves/abstract/curve.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { title } from './_shared.ts';

(async () => {
  title('MSM timings');
  const g1 = bls12_381.G1.Point;
  const N = g1.Fn.ORDER;
  const bits = 255;
  const ones = BigInt(`0b${'1'.repeat(bits)}`);
  function msm(p, s) {
    return pippenger(bls12_381.G1.Point, p, s)
  }
  // todo
  function compare() {}

  const onezero = BigInt(`0b${'10'.repeat(bits / 2)}`);
  const one8zero = BigInt(`0b${'10000000'.repeat(bits / 8)}`);
  // Single scalar
  await compare('single point', 5000, {
    zero: () => msm([g1.BASE], [0n]),
    one: () => msm([g1.BASE], [1n]),
    one0: () => msm([g1.ZERO], [1n]),
    small: () => msm([g1.BASE], [123n]),
    big: () => msm([g1.BASE], [N - 1n]),
  });
  // Multiple
  const points = [3n, 5n, 7n, 11n, 13n].map((i) => g1.BASE.multiply(i));
  await compare('single point', 500, {
    zero: () => msm([g1.BASE, g1.BASE, g1.BASE, g1.BASE, g1.BASE], [0n, 0n, 0n, 0n, 0n]),
    zero2: () => msm([g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO], [0n, 0n, 0n, 0n, 0n]),
    big: () =>
      msm(points, [
        N - 1n,
        N - 100n,
        N - 200n,
        N - 300n,
        N - 400n,
      ]),
    same_scalar: () => msm(points, [ones, ones, ones, ones, ones]),
    same_scalar2: () => msm(points, [onezero, onezero, onezero, onezero, onezero]),
    same_scalar3: () => msm(points, [1n, 1n, 1n, 1n, 1n]),
    same_scalar4: () => msm(points, [one8zero, one8zero, one8zero, one8zero, one8zero]),
  });
  // Ok, and what about multiply itself?
  await compare('basic multiply', 5000, {
    '1*G1': () => g1.BASE.multiply(1n),
    '(n-1)*G1': () => g1.BASE.multiply(N - 1n),
    'ones*G1': () => g1.BASE.multiply(ones),
    'onezero*G1': () => g1.BASE.multiply(onezero),
    'one8zero*G1': () => g1.BASE.multiply(one8zero),
    // Infinity
    '1*Inf': () => g1.ZERO.multiply(1n),
    '(n-1)*Inf': () => g1.ZERO.multiply(N - 1n),
    'ones*Inf': () => g1.ZERO.multiply(ones),
    'onezero*Inf': () => g1.ZERO.multiply(onezero),
    'one8zero*Inf': () => g1.ZERO.multiply(one8zero),
  });
})();
