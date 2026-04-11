/**
 * Experimental implementation of NTT / FFT (Fast Fourier Transform) over finite fields.
 * API may change at any time. The code has not been audited. Feature requests are welcome.
 * @module
 */
import type { TArg } from '../utils.ts';
import type { IField } from './modular.ts';

/** Array-like coefficient storage that can be mutated in place. */
export interface MutableArrayLike<T> {
  /** Element access by numeric index. */
  [index: number]: T;
  /** Current amount of stored coefficients. */
  length: number;
  /**
   * Return a sliced copy using the same storage shape.
   * @param start - Inclusive start index.
   * @param end - Exclusive end index.
   * @returns Sliced copy.
   */
  slice(start?: number, end?: number): this;
  /**
   * Iterate over stored coefficients in order.
   * @returns Coefficient iterator.
   */
  [Symbol.iterator](): Iterator<T>;
}

/**
 * Concrete polynomial containers accepted by the high-level `poly(...)` helpers.
 * Lower-level FFT helpers can work with structural `MutableArrayLike`, but `poly(...)`
 * intentionally keeps runtime dispatch on plain arrays and typed-array views.
 */
export type PolyStorage<T> = T[] | (MutableArrayLike<T> & ArrayBufferView);

function checkU32(n: number) {
  // 0xff_ff_ff_ff
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff)
    throw new Error('wrong u32 integer:' + n);
  return n;
}

/**
 * Checks if integer is in form of `1 << X`.
 * @param x - Integer to inspect.
 * @returns `true` when the value is a power of two.
 * @throws If `x` is not a valid unsigned 32-bit integer. {@link Error}
 * @example
 * Validate that an FFT size is a power of two.
 *
 * ```ts
 * isPowerOfTwo(8);
 * ```
 */
export function isPowerOfTwo(x: number): boolean {
  checkU32(x);
  return (x & (x - 1)) === 0 && x !== 0;
}

/**
 * @param n - Input value.
 * @returns Next power of two within the u32/array-length domain.
 * @throws If `n` is not a valid unsigned 32-bit integer. {@link Error}
 * @example
 * Round an integer up to the FFT size it needs.
 *
 * ```ts
 * nextPowerOfTwo(9);
 * ```
 */
export function nextPowerOfTwo(n: number): number {
  checkU32(n);
  if (n <= 1) return 1;
  // FFT sizes here are used as JS array lengths, so `2^32` is not a meaningful result:
  // keep the fast u32 bit-twiddling path and fail explicitly instead of wrapping to 1.
  if (n > 0x8000_0000) throw new Error('nextPowerOfTwo overflow: result does not fit u32');
  return (1 << (log2(n - 1) + 1)) >>> 0;
}

/**
 * @param n - Value to reverse.
 * @param bits - Number of bits to use.
 * @returns Bit-reversed integer.
 * @throws If `n` is not a valid unsigned 32-bit integer. {@link Error}
 * @example
 * Reverse the low `bits` bits of one index.
 *
 * ```ts
 * reverseBits(3, 3);
 * ```
 */
export function reverseBits(n: number, bits: number): number {
  checkU32(n);
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
  let reversed = 0;
  for (let i = 0; i < bits; i++, n >>>= 1) reversed = (reversed << 1) | (n & 1);
  // JS bitwise ops are signed i32; cast back so 32-bit reversals stay in the unsigned u32 domain.
  return reversed >>> 0;
}

/**
 * Similar to `bitLen(x)-1` but much faster for small integers, like indices.
 * @param n - Input value.
 * @returns Base-2 logarithm. For `n = 0`, the current implementation returns `-1`.
 * @throws If `n` is not a valid unsigned 32-bit integer. {@link Error}
 * @example
 * Compute the radix-2 stage count for one transform size.
 *
 * ```ts
 * log2(8);
 * ```
 */
export function log2(n: number): number {
  checkU32(n);
  return 31 - Math.clz32(n);
}

/**
 * Moves lowest bit to highest position, which at first step splits
 * array on even and odd indices, then it applied again to each part,
 * which is core of fft
 * @param values - Mutable coefficient array.
 * @returns Mutated input array.
 * @throws If the array length is not a positive power of two. {@link Error}
 * @example
 * Reorder coefficients into bit-reversed order in place.
 *
 * ```ts
 * const values = Uint8Array.from([0, 1, 2, 3]);
 * bitReversalInplace(values);
 * ```
 */
export function bitReversalInplace<T extends MutableArrayLike<any>>(values: T): T {
  const n = values.length;
  // Size-1 FFT is the identity, so bit-reversal must stay a no-op there instead of rejecting it.
  if (!isPowerOfTwo(n)) throw new Error('expected positive power-of-two length, got ' + n);
  const bits = log2(n);
  for (let i = 0; i < n; i++) {
    const j = reverseBits(i, bits);
    if (i < j) {
      const tmp = values[i];
      values[i] = values[j];
      values[j] = tmp;
    }
  }
  return values;
}

/**
 * @param values - Input values.
 * @returns Reordered copy.
 * @throws If the array length is not a positive power of two. {@link Error}
 * @example
 * Return a reordered copy instead of mutating the input in place.
 *
 * ```ts
 * const reordered = bitReversalPermutation([0, 1, 2, 3]);
 * ```
 */
export function bitReversalPermutation<T>(values: T[]): T[] {
  return bitReversalInplace(values.slice()) as T[];
}

const _1n = /** @__PURE__ */ BigInt(1);
function findGenerator(field: TArg<IField<bigint>>) {
  let G = BigInt(2);
  for (; field.eql(field.pow(G, field.ORDER >> _1n), field.ONE); G++);
  return G;
}

/** Cached roots-of-unity tables derived from one finite field. */
export type RootsOfUnity = {
  /** Generator and 2-adicity metadata for the cached field. */
  info: { G: bigint; oddFactor: bigint; powerOfTwo: number };
  /**
   * Return the natural-order roots of unity for one radix-2 size.
   * @param bits - Transform size as `log2(N)`.
   * @returns Natural-order roots for that size.
   */
  roots: (bits: number) => bigint[];
  /**
   * Return the bit-reversal permutation of the roots for one radix-2 size.
   * @param bits - Transform size as `log2(N)`.
   * @returns Bit-reversed roots.
   */
  brp(bits: number): bigint[];
  /**
   * Return the inverse roots of unity for one radix-2 size.
   * @param bits - Transform size as `log2(N)`.
   * @returns Inverse roots.
   */
  inverse(bits: number): bigint[];
  /**
   * Return one primitive root used by a radix-2 stage.
   * @param bits - Transform size as `log2(N)`.
   * @returns Primitive root for that stage.
   */
  omega: (bits: number) => bigint;
  /**
   * Drop all cached root tables.
   * @returns Nothing.
   */
  clear: () => void;
};
/**
 * We limit roots up to 2**31, which is a lot: 2-billion polynomimal should be rare.
 * @param field - Field implementation.
 * @param generator - Optional generator override.
 * @returns Roots-of-unity cache.
 * @example
 * Cache roots once, then ask for the omega table of one FFT size.
 *
 * ```ts
 * import { rootsOfUnity } from '@noble/curves/abstract/fft.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const roots = rootsOfUnity(Field(17n));
 * const omega = roots.omega(4);
 * ```
 */
export function rootsOfUnity(field: TArg<IField<bigint>>, generator?: bigint): RootsOfUnity {
  // Factor field.ORDER-1 as oddFactor * 2^powerOfTwo
  let oddFactor = field.ORDER - _1n;
  let powerOfTwo = 0;
  for (; (oddFactor & _1n) !== _1n; powerOfTwo++, oddFactor >>= _1n);

  // Find non quadratic residue
  let G = generator !== undefined ? BigInt(generator) : findGenerator(field);
  // Powers of generator
  const omegas: bigint[] = new Array(powerOfTwo + 1);
  omegas[powerOfTwo] = field.pow(G, oddFactor);
  for (let i = powerOfTwo; i > 0; i--) omegas[i - 1] = field.sqr(omegas[i]);
  // Compute all roots of unity for powers up to maxPower
  const rootsCache: bigint[][] = [];
  const checkBits = (bits: number) => {
    checkU32(bits);
    if (bits > 31 || bits > powerOfTwo)
      throw new Error('rootsOfUnity: wrong bits ' + bits + ' powerOfTwo=' + powerOfTwo);
    return bits;
  };
  const precomputeRoots = (maxPower: number) => {
    checkBits(maxPower);
    for (let power = maxPower; power >= 0; power--) {
      if (rootsCache[power]) continue; // Skip if we've already computed roots for this power
      const rootsAtPower: bigint[] = [];
      for (let j = 0, cur = field.ONE; j < 2 ** power; j++, cur = field.mul(cur, omegas[power]))
        rootsAtPower.push(cur);
      rootsCache[power] = rootsAtPower;
    }
    return rootsCache[maxPower];
  };
  const brpCache = new Map<number, bigint[]>();
  const inverseCache = new Map<number, bigint[]>();
  // roots()/brp()/inverse() expose shared cached arrays by reference for speed; callers must treat them as read-only.

  // NOTE: we use bits instead of power, because power = 2**bits,
  // but power is not neccesary isPowerOfTwo(power)!
  return {
    info: { G, powerOfTwo, oddFactor },
    roots: (bits: number): bigint[] => {
      const b = checkBits(bits);
      return precomputeRoots(b);
    },
    brp(bits: number): bigint[] {
      const b = checkBits(bits);
      if (brpCache.has(b)) return brpCache.get(b)!;
      else {
        const res = bitReversalPermutation(this.roots(b));
        brpCache.set(b, res);
        return res;
      }
    },
    inverse(bits: number): bigint[] {
      const b = checkBits(bits);
      if (inverseCache.has(b)) return inverseCache.get(b)!;
      else {
        const res = field.invertBatch(this.roots(b));
        inverseCache.set(b, res);
        return res;
      }
    },
    omega: (bits: number): bigint => omegas[checkBits(bits)],
    clear: (): void => {
      rootsCache.splice(0, rootsCache.length);
      brpCache.clear();
      inverseCache.clear();
    },
  };
}

/** Polynomial coefficient container used by the FFT helpers. */
export type Polynomial<T> = MutableArrayLike<T>;

/**
 * Arithmetic operations used by the generic FFT implementation.
 *
 * Maps great to Field<bigint>, but not to Group (EC points):
 * - inv from scalar field
 * - we need multiplyUnsafe here, instead of multiply for speed
 * - multiplyUnsafe is safe in the context: we do mul(rootsOfUnity), which are public and sparse
 */
export type FFTOpts<T, R> = {
  /**
   * Add two coefficients.
   * @param a - Left coefficient.
   * @param b - Right coefficient.
   * @returns Sum coefficient.
   */
  add: (a: T, b: T) => T;
  /**
   * Subtract two coefficients.
   * @param a - Left coefficient.
   * @param b - Right coefficient.
   * @returns Difference coefficient.
   */
  sub: (a: T, b: T) => T;
  /**
   * Multiply one coefficient by a scalar/root factor.
   * @param a - Coefficient value.
   * @param scalar - Scalar/root factor.
   * @returns Scaled coefficient.
   */
  mul: (a: T, scalar: R) => T;
  /**
   * Invert one scalar/root factor.
   * @param a - Scalar/root factor.
   * @returns Inverse factor.
   */
  inv: (a: R) => R;
};

/** Configuration for one low-level FFT loop. */
export type FFTCoreOpts<R> = {
  /** Transform size. Must be a power of two. */
  N: number;
  /** Stage roots for the selected transform size. */
  roots: Polynomial<R>;
  /** Whether to run the DIT variant instead of DIF. */
  dit: boolean;
  /** Whether to invert butterfly placement for decode-oriented layouts. */
  invertButterflies?: boolean;
  /** Number of initial stages to skip. */
  skipStages?: number;
  /** Whether to apply bit-reversal permutation at the boundary. */
  brp?: boolean;
};

/**
 * Callable low-level FFT loop over one polynomial storage shape.
 * @param values - Polynomial coefficients to transform in place.
 * @returns The mutated input polynomial.
 */
export type FFTCoreLoop<T> = <P extends Polynomial<T>>(values: P) => P;

/**
 * Constructs different flavors of FFT. radix2 implementation of low level mutating API. Flavors:
 *
 * - DIT (Decimation-in-Time): Bottom-Up (leaves to root), Cool-Turkey
 * - DIF (Decimation-in-Frequency): Top-Down (root to leaves), Gentleman-Sande
 *
 * DIT takes brp input, returns natural output.
 * DIF takes natural input, returns brp output.
 *
 * The output is actually identical. Time / frequence distinction is not meaningful
 * for Polynomial multiplication in fields.
 * Which means if protocol supports/needs brp output/inputs, then we can skip this step.
 *
 * Cyclic NTT: Rq = Zq[x]/(x^n-1). butterfly_DIT+loop_DIT OR butterfly_DIF+loop_DIT, roots are omega
 * Negacyclic NTT: Rq = Zq[x]/(x^n+1). butterfly_DIT+loop_DIF, at least for mlkem / mldsa
 * @param F - Field operations.
 * @param coreOpts - FFT configuration:
 *   - `N`: Transform size. Must be a power of two.
 *   - `roots`: Stage roots for the selected transform size.
 *   - `dit`: Whether to run the DIT variant instead of DIF.
 *   - `invertButterflies` (optional): Whether to invert butterfly placement.
 *   - `skipStages` (optional): Number of initial stages to skip.
 *   - `brp` (optional): Whether to apply bit-reversal permutation at the boundary.
 * @returns Low-level FFT loop.
 * @throws If the FFT options or cached roots are invalid for the requested size. {@link Error}
 * @example
 * Constructs different flavors of FFT.
 *
 * ```ts
 * import { FFTCore, rootsOfUnity } from '@noble/curves/abstract/fft.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const roots = rootsOfUnity(Fp).roots(2);
 * const loop = FFTCore(Fp, { N: 4, roots, dit: true });
 * const values = loop([1n, 2n, 3n, 4n]);
 * ```
 */
export const FFTCore = <T, R>(F: FFTOpts<T, R>, coreOpts: FFTCoreOpts<R>): FFTCoreLoop<T> => {
  const { N, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
  const bits = log2(N);
  if (!isPowerOfTwo(N)) throw new Error('FFT: Polynomial size should be power of two');
  // Wrong-sized root tables can stay in-bounds for some loop shapes and silently compute nonsense.
  if (roots.length !== N)
    throw new Error(`FFT: wrong roots length: expected ${N}, got ${roots.length}`);
  const isDit = dit !== invertButterflies;
  isDit;
  return <P extends Polynomial<T>>(values: P): P => {
    if (values.length !== N) throw new Error('FFT: wrong Polynomial length');
    if (dit && brp) bitReversalInplace(values);
    for (let i = 0, g = 1; i < bits - skipStages; i++) {
      // For each stage s (sub-FFT length m = 2^s)
      const s = dit ? i + 1 + skipStages : bits - i;
      const m = 1 << s;
      const m2 = m >> 1;
      const stride = N >> s;
      // Loop over each subarray of length m
      for (let k = 0; k < N; k += m) {
        // Loop over each butterfly within the subarray
        for (let j = 0, grp = g++; j < m2; j++) {
          const rootPos = invertButterflies ? (dit ? N - grp : grp) : j * stride;
          const i0 = k + j;
          const i1 = k + j + m2;
          const omega = roots[rootPos];
          const b = values[i1];
          const a = values[i0];
          // Inlining gives us 10% perf in kyber vs functions
          if (isDit) {
            const t = F.mul(b, omega); // Standard DIT butterfly
            values[i0] = F.add(a, t);
            values[i1] = F.sub(a, t);
          } else if (invertButterflies) {
            values[i0] = F.add(b, a); // DIT loop + inverted butterflies (Kyber decode)
            values[i1] = F.mul(F.sub(b, a), omega);
          } else {
            values[i0] = F.add(a, b); // Standard DIF butterfly
            values[i1] = F.mul(F.sub(a, b), omega);
          }
        }
      }
    }
    if (!dit && brp) bitReversalInplace(values);
    return values;
  };
};

/** Forward and inverse FFT helpers for one coefficient domain. */
export type FFTMethods<T> = {
  /**
   * Apply the forward transform.
   * @param values - Polynomial coefficients to transform.
   * @param brpInput - Whether the input is already bit-reversed.
   * @param brpOutput - Whether to keep the output bit-reversed.
   * @returns Transformed copy.
   */
  direct<P extends Polynomial<T>>(values: P, brpInput?: boolean, brpOutput?: boolean): P;
  /**
   * Apply the inverse transform.
   * @param values - Polynomial coefficients to transform.
   * @param brpInput - Whether the input is already bit-reversed.
   * @param brpOutput - Whether to keep the output bit-reversed.
   * @returns Inverse-transformed copy.
   */
  inverse<P extends Polynomial<T>>(values: P, brpInput?: boolean, brpOutput?: boolean): P;
};

/**
 * NTT aka FFT over finite field (NOT over complex numbers).
 * Naming mirrors other libraries.
 * @param roots - Roots-of-unity cache.
 * @param opts - Field operations. See {@link FFTOpts}.
 * @returns Forward and inverse FFT helpers.
 * @example
 * NTT aka FFT over finite field (NOT over complex numbers).
 *
 * ```ts
 * import { FFT, rootsOfUnity } from '@noble/curves/abstract/fft.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const fft = FFT(rootsOfUnity(Fp), Fp);
 * const values = fft.direct([1n, 2n, 3n, 4n]);
 * ```
 */
export function FFT<T>(roots: RootsOfUnity, opts: FFTOpts<T, bigint>): FFTMethods<T> {
  const getLoop = (
    N: number,
    roots: Polynomial<bigint>,
    brpInput = false,
    brpOutput = false
  ): (<P extends Polynomial<T>>(values: P) => P) => {
    if (brpInput && brpOutput) {
      // we cannot optimize this case, but lets support it anyway
      return (values) =>
        FFTCore(opts, { N, roots, dit: false, brp: false })(bitReversalInplace(values));
    }
    if (brpInput) return FFTCore(opts, { N, roots, dit: true, brp: false });
    if (brpOutput) return FFTCore(opts, { N, roots, dit: false, brp: false });
    return FFTCore(opts, { N, roots, dit: true, brp: true }); // all natural
  };
  return {
    direct<P extends Polynomial<T>>(values: P, brpInput = false, brpOutput = false): P {
      const N = values.length;
      if (!isPowerOfTwo(N)) throw new Error('FFT: Polynomial size should be power of two');
      const bits = log2(N);
      return getLoop(N, roots.roots(bits), brpInput, brpOutput)<P>(values.slice());
    },
    inverse<P extends Polynomial<T>>(values: P, brpInput = false, brpOutput = false): P {
      const N = values.length;
      if (!isPowerOfTwo(N)) throw new Error('FFT: Polynomial size should be power of two');
      const bits = log2(N);
      const res = getLoop(N, roots.inverse(bits), brpInput, brpOutput)(values.slice());
      const ivm = opts.inv(BigInt(values.length)); // scale
      // we can get brp output if we use dif instead of dit!
      for (let i = 0; i < res.length; i++) res[i] = opts.mul(res[i], ivm);
      // Allows to re-use non-inverted roots, but is VERY fragile
      // return [res[0]].concat(res.slice(1).reverse());
      // inverse calculated as pow(-1), which transforms into ω^{-kn} (-> reverses indices)
      return res;
    },
  };
}

/**
 * Factory that allocates one polynomial storage container.
 * Callers must ensure `_create(len)` returns field-zero-filled storage when `elm` is omitted,
 * because the quadratic `mul()` / `convolve()` paths and the Kronecker-δ shortcut in
 * `lagrange.basis()` rely on that default instead of always passing `field.ZERO` explicitly.
 * @param len - Requested amount of coefficients.
 * @param elm - Optional fill value.
 * @returns Newly allocated polynomial container.
 */
export type CreatePolyFn<P extends PolyStorage<T>, T> = (len: number, elm?: T) => P;

/** High-level polynomial helpers layered on top of FFT and field arithmetic. */
export type PolyFn<P extends PolyStorage<T>, T> = {
  /** Roots-of-unity cache used by the helper namespace. */
  roots: RootsOfUnity;
  /** Factory used to allocate new polynomial containers. */
  create: CreatePolyFn<P, T>;
  /** Optional enforced polynomial length. */
  length?: number;

  /**
   * Compute the polynomial degree.
   * @param a - Polynomial coefficients.
   * @returns Polynomial degree.
   */
  degree: (a: P) => number;
  /**
   * Extend or truncate one polynomial to a requested length.
   * @param a - Polynomial coefficients.
   * @param len - Target length.
   * @returns Resized polynomial.
   */
  extend: (a: P, len: number) => P;
  /**
   * Add two polynomials coefficient-wise.
   * @param a - Left polynomial.
   * @param b - Right polynomial.
   * @returns Sum polynomial.
   */
  add: (a: P, b: P) => P;
  /**
   * Subtract two polynomials coefficient-wise.
   * @param a - Left polynomial.
   * @param b - Right polynomial.
   * @returns Difference polynomial.
   */
  sub: (a: P, b: P) => P;
  /**
   * Multiply by another polynomial or by one scalar.
   * @param a - Left polynomial.
   * @param b - Right polynomial or scalar.
   * @returns Product polynomial.
   */
  mul: (a: P, b: P | T) => P;
  /**
   * Multiply coefficients point-wise.
   * @param a - Left polynomial.
   * @param b - Right polynomial.
   * @returns Point-wise product polynomial.
   */
  dot: (a: P, b: P) => P;
  /**
   * Multiply two polynomials with convolution.
   * @param a - Left polynomial.
   * @param b - Right polynomial.
   * @returns Convolution product.
   */
  convolve: (a: P, b: P) => P;
  /**
   * Apply a point-wise coefficient shift by powers of one factor.
   * @param p - Polynomial coefficients.
   * @param factor - Shift factor.
   * @returns Shifted polynomial.
   */
  shift: (p: P, factor: bigint) => P;
  /**
   * Clone one polynomial container.
   * @param a - Polynomial coefficients.
   * @returns Cloned polynomial.
   */
  clone: (a: P) => P;
  /**
   * Evaluate one polynomial on a basis vector.
   * @param a - Polynomial coefficients.
   * @param basis - Basis vector.
   * @returns Evaluated field element.
   */
  eval: (a: P, basis: P) => T;
  /** Helpers for monomial-basis polynomials. */
  monomial: {
    /** Build the monomial basis vector for one evaluation point. */
    basis: (x: T, n: number) => P;
    /** Evaluate a polynomial in the monomial basis. */
    eval: (a: P, x: T) => T;
  };
  /** Helpers for Lagrange-basis polynomials. */
  lagrange: {
    /** Build the Lagrange basis vector for one evaluation point. */
    basis: (x: T, n: number, brp?: boolean) => P;
    /** Evaluate a polynomial in the Lagrange basis. */
    eval: (a: P, x: T, brp?: boolean) => T;
  };
  /**
   * Build the vanishing polynomial for a root set.
   * @param roots - Root set.
   * @returns Vanishing polynomial.
   */
  vanishing: (roots: P) => P;
};

/**
 * Poly wants a cracker.
 *
 * Polynomials are functions like `y=f(x)`, which means when we multiply two polynomials, result is
 * function `f3(x) = f1(x) * f2(x)`, we don't multiply values. Key takeaways:
 *
 * - **Polynomial** is an array of coefficients: `f(x) = sum(coeff[i] * basis[i](x))`
 * - **Basis** is array of functions
 * - **Monominal** is Polynomial where `basis[i](x) == x**i` (powers)
 * - **Array size** is domain size
 * - **Lattice** is matrix (Polynomial of Polynomials)
 * @param field - Field implementation.
 * @param roots - Roots-of-unity cache.
 * @param create - Optional polynomial factory. Runtime input validation accepts only plain `Array`
 *   and typed-array polynomial containers; arbitrary structural wrappers are intentionally rejected.
 * @param fft - Optional FFT implementation.
 * @param length - Optional fixed polynomial length.
 * @returns Polynomial helper namespace.
 * @example
 * Build polynomial helpers, then convolve two coefficient arrays.
 *
 * ```ts
 * import { poly, rootsOfUnity } from '@noble/curves/abstract/fft.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const poly17 = poly(Fp, rootsOfUnity(Fp));
 * const product = poly17.convolve([1n, 2n], [3n, 4n]);
 * ```
 */
export function poly<T>(
  field: TArg<IField<T>>,
  roots: RootsOfUnity,
  create?: undefined,
  fft?: FFTMethods<T>,
  length?: number
): PolyFn<T[], T>;
export function poly<T, P extends PolyStorage<T>>(
  field: TArg<IField<T>>,
  roots: RootsOfUnity,
  create: CreatePolyFn<P, T>,
  fft?: FFTMethods<T>,
  length?: number
): PolyFn<P, T>;
export function poly<T, P extends PolyStorage<T>>(
  field: TArg<IField<T>>,
  roots: RootsOfUnity,
  create?: CreatePolyFn<P, T>,
  fft?: FFTMethods<T>,
  length?: number
): PolyFn<any, T> {
  const F = field as IField<T>;
  const _create =
    create ||
    (((len: number, elm?: T): T[] => new Array(len).fill(elm ?? F.ZERO)) as CreatePolyFn<P, T>);

  // `poly.mul(a, b)` distinguishes polynomial-vs-scalar at runtime, so keep accepted
  // polynomial containers concrete instead of trying to support arbitrary wrappers.
  const isPoly = (x: any): x is P => {
    if (Array.isArray(x)) return true;
    if (!ArrayBuffer.isView(x)) return false;
    const v = x as unknown as ArrayLike<unknown> & { slice?: unknown; [Symbol.iterator]?: unknown };
    return (
      typeof v.length === 'number' &&
      typeof v.slice === 'function' &&
      typeof v[Symbol.iterator] === 'function'
    );
  };
  const checkLength = (...lst: P[]): number => {
    if (!lst.length) return 0;
    for (const i of lst) if (!isPoly(i)) throw new Error('poly: not polynomial: ' + i);
    const L = lst[0].length;
    for (let i = 1; i < lst.length; i++)
      if (lst[i].length !== L) throw new Error(`poly: mismatched lengths ${L} vs ${lst[i].length}`);
    if (length !== undefined && L !== length)
      throw new Error(`poly: expected fixed length ${length}, got ${L}`);
    return L;
  };
  function findOmegaIndex(x: T, n: number, brp = false): number {
    const bits = log2(n);
    const omega = brp ? roots.brp(bits) : roots.roots(bits);
    for (let i = 0; i < n; i++) if (F.eql(x, omega[i] as T)) return i;
    return -1;
  }
  // TODO: mutating versions for mlkem/mldsa
  return {
    roots,
    create: _create,
    length,
    extend: (a: P, len: number): P => {
      checkLength(a);
      const out = _create(len, F.ZERO);
      // Plain arrays grow when writing past `out.length`, so cap the copy explicitly to keep
      // `extend()` consistent with typed arrays and with its documented truncate behavior.
      for (let i = 0; i < Math.min(a.length, len); i++) out[i] = a[i];
      return out;
    },
    degree: (a: P): number => {
      checkLength(a);
      for (let i = a.length - 1; i >= 0; i--) if (!F.is0(a[i])) return i;
      return -1;
    },
    add: (a: P, b: P): P => {
      const len = checkLength(a, b);
      const out = _create(len);
      for (let i = 0; i < len; i++) out[i] = F.add(a[i], b[i]);
      return out;
    },
    sub: (a: P, b: P): P => {
      const len = checkLength(a, b);
      const out = _create(len);
      for (let i = 0; i < len; i++) out[i] = F.sub(a[i], b[i]);
      return out;
    },
    dot: (a: P, b: P): P => {
      const len = checkLength(a, b);
      const out = _create(len);
      for (let i = 0; i < len; i++) out[i] = F.mul(a[i], b[i]);
      return out;
    },
    mul: (a: P, b: P | T): P => {
      if (isPoly(b)) {
        const len = checkLength(a, b);
        if (fft) {
          const A = fft.direct(a, false, true);
          const B = fft.direct(b, false, true);
          for (let i = 0; i < A.length; i++) A[i] = F.mul(A[i], B[i]);
          return fft.inverse(A, true, false) as P;
        } else {
          // NOTE: this is quadratic and mostly for compat tests with FFT
          const res = _create(len);
          for (let i = 0; i < len; i++) {
            for (let j = 0; j < len; j++) {
              const k = (i + j) % len; // wrap mod length
              res[k] = F.add(res[k], F.mul(a[i], b[j]));
            }
          }
          return res;
        }
      } else {
        const out = _create(checkLength(a));
        for (let i = 0; i < out.length; i++) out[i] = F.mul(a[i], b);
        return out;
      }
    },
    convolve(a: P, b: P): P {
      const len = nextPowerOfTwo(a.length + b.length - 1);
      return this.mul(this.extend(a, len), this.extend(b, len));
    },
    shift(p: P, factor: bigint): P {
      const out = _create(checkLength(p));
      out[0] = p[0];
      for (let i = 1, power = F.ONE; i < p.length; i++) {
        power = F.mul(power, factor);
        out[i] = F.mul(p[i], power);
      }
      return out;
    },
    clone: (a: P): P => {
      checkLength(a);
      const out = _create(a.length);
      for (let i = 0; i < a.length; i++) out[i] = a[i];
      return out;
    },
    eval: (a: P, basis: P): T => {
      checkLength(a, basis);
      let acc = F.ZERO;
      for (let i = 0; i < a.length; i++) acc = F.add(acc, F.mul(a[i], basis[i]));
      return acc;
    },
    monomial: {
      basis: (x: T, n: number): P => {
        const out = _create(n);
        let pow = F.ONE;
        for (let i = 0; i < n; i++) {
          out[i] = pow;
          pow = F.mul(pow, x);
        }
        return out;
      },
      eval: (a: P, x: T): T => {
        checkLength(a);
        // Same as eval(a, monomialBasis(x, a.length)), but it is faster this way
        let acc = F.ZERO;
        for (let i = a.length - 1; i >= 0; i--) acc = F.add(F.mul(acc, x), a[i]);
        return acc;
      },
    },
    lagrange: {
      basis: (x: T, n: number, brp = false, weights?: P): P => {
        const bits = log2(n);
        const cache = weights || (brp ? roots.brp(bits) : roots.roots(bits)); // [ω⁰, ω¹, ..., ωⁿ⁻¹]
        const out = _create(n);
        // Fast Kronecker-δ shortcut
        const idx = findOmegaIndex(x, n, brp);
        if (idx !== -1) {
          out[idx] = F.ONE;
          return out;
        }
        const tm = F.pow(x, BigInt(n));
        const c = F.mul(F.sub(tm, F.ONE), F.inv(BigInt(n) as T)); // c = (xⁿ - 1)/n
        const denom = _create(n);
        for (let i = 0; i < n; i++) denom[i] = F.sub(x, cache[i] as T);
        const inv = F.invertBatch(denom as any as T[]);
        for (let i = 0; i < n; i++) out[i] = F.mul(c, F.mul(cache[i] as T, inv[i]));
        return out;
      },
      eval(a: P, x: T, brp = false): T {
        checkLength(a);
        const idx = findOmegaIndex(x, a.length, brp);
        if (idx !== -1) return a[idx]; // fast path
        const L = this.basis(x, a.length, brp); // Lᵢ(x)
        let acc = F.ZERO;
        for (let i = 0; i < a.length; i++) if (!F.is0(a[i])) acc = F.add(acc, F.mul(a[i], L[i]));
        return acc;
      },
    },
    vanishing(roots: P): P {
      checkLength(roots);
      const out = _create(roots.length + 1, F.ZERO);
      out[0] = F.ONE;
      for (const r of roots) {
        const neg = F.neg(r);
        for (let j = out.length - 1; j > 0; j--) out[j] = F.add(F.mul(out[j], neg), out[j - 1]);
        out[0] = F.mul(out[0], neg);
      }
      return out;
    },
  };
}
