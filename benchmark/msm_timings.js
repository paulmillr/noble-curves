import { run, mark, compare, utils } from 'micro-bmark';
import { bls12_381 } from '../bls12-381.js';

run(async () => {
  const g1 = bls12_381.G1.ProjectivePoint;
  const bits = bls12_381.G1.CURVE.nBitLength - 1;
  const ones = BigInt(`0b${'1'.repeat(bits)}`);

  const onezero = BigInt(`0b${'10'.repeat(bits / 2)}`);
  const one8zero = BigInt(`0b${'10000000'.repeat(bits / 8)}`);
  // Single scalar
  await compare('single point', 5000, {
    zero: () => g1.msm([g1.BASE], [0n]),
    one: () => g1.msm([g1.BASE], [1n]),
    one0: () => g1.msm([g1.ZERO], [1n]),
    small: () => g1.msm([g1.BASE], [123n]),
    big: () => g1.msm([g1.BASE], [bls12_381.G1.CURVE.n - 1n]),
  });
  // Multiple
  const points = [3n, 5n, 7n, 11n, 13n].map((i) => g1.BASE.multiply(i));
  await compare('single point', 500, {
    zero: () => g1.msm([g1.BASE, g1.BASE, g1.BASE, g1.BASE, g1.BASE], [0n, 0n, 0n, 0n, 0n]),
    zero2: () => g1.msm([g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO, g1.ZERO], [0n, 0n, 0n, 0n, 0n]),
    big: () =>
      g1.msm(points, [
        bls12_381.G1.CURVE.n - 1n,
        bls12_381.G1.CURVE.n - 100n,
        bls12_381.G1.CURVE.n - 200n,
        bls12_381.G1.CURVE.n - 300n,
        bls12_381.G1.CURVE.n - 400n,
      ]),
    same_scalar: () => g1.msm(points, [ones, ones, ones, ones, ones]),
    same_scalar2: () => g1.msm(points, [onezero, onezero, onezero, onezero, onezero]),
    same_scalar3: () => g1.msm(points, [1n, 1n, 1n, 1n, 1n]),
    same_scalar4: () => g1.msm(points, [one8zero, one8zero, one8zero, one8zero, one8zero]),
  });
  // Ok, and what about multiply itself?
  await compare('basic multiply', 5000, {
    '1*G1': () => g1.BASE.multiply(1n),
    '(n-1)*G1': () => g1.BASE.multiply(bls12_381.G1.CURVE.n - 1n),
    'ones*G1': () => g1.BASE.multiply(ones),
    'onezero*G1': () => g1.BASE.multiply(onezero),
    'one8zero*G1': () => g1.BASE.multiply(one8zero),
    // Infinity
    '1*Inf': () => g1.ZERO.multiply(1n),
    '(n-1)*Inf': () => g1.ZERO.multiply(bls12_381.G1.CURVE.n - 1n),
    'ones*Inf': () => g1.ZERO.multiply(ones),
    'onezero*Inf': () => g1.ZERO.multiply(onezero),
    'one8zero*Inf': () => g1.ZERO.multiply(one8zero),
  });

  utils.logMem();
});
