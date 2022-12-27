/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Abelian group utilities
const _0n = BigInt(0);
const _1n = BigInt(1);

export interface Group<T extends Group<T>> {
  double(): T;
  negate(): T;
  add(other: T): T;
  subtract(other: T): T;
  equals(other: T): boolean;
  multiply(scalar: number | bigint): T;
}

export type GroupConstructor<T> = {
  BASE: T;
  ZERO: T;
};
// Not big, but pretty complex and it is easy to break stuff. To avoid too much copy paste
export function wNAF<T extends Group<T>>(c: GroupConstructor<T>, bits: number) {
  const constTimeNegate = (condition: boolean, item: T): T => {
    const neg = item.negate();
    return condition ? neg : item;
  };
  const opts = (W: number) => {
    const windows = Math.ceil(bits / W) + 1; // +1, because
    const windowSize = 2 ** (W - 1); // -1 because we skip zero
    return { windows, windowSize };
  };
  return {
    constTimeNegate,
    // non-const time multiplication ladder
    unsafeLadder(elm: T, n: bigint) {
      let p = c.ZERO;
      let d: T = elm;
      while (n > _0n) {
        if (n & _1n) p = p.add(d);
        d = d.double();
        n >>= _1n;
      }
      return p;
    },

    /**
     * Creates a wNAF precomputation window. Used for caching.
     * Default window size is set by `utils.precompute()` and is equal to 8.
     * Which means we are caching 65536 points: 256 points for every bit from 0 to 256.
     * @returns 65K precomputed points, depending on W
     */
    precomputeWindow(elm: T, W: number): Group<T>[] {
      const { windows, windowSize } = opts(W);
      const points: T[] = [];
      let p: T = elm;
      let base = p;
      for (let window = 0; window < windows; window++) {
        base = p;
        points.push(base);
        // =1, because we skip zero
        for (let i = 1; i < windowSize; i++) {
          base = base.add(p);
          points.push(base);
        }
        p = base.double();
      }
      return points;
    },

    /**
     * Implements w-ary non-adjacent form for calculating ec multiplication.
     * @param W window size
     * @param affinePoint optional 2d point to save cached precompute windows on it.
     * @param n bits
     * @returns real and fake (for const-time) points
     */
    wNAF(W: number, precomputes: T[], n: bigint): { p: T; f: T } {
      // TODO: maybe check that scalar is less than group order? wNAF will fail otherwise
      // But need to carefully remove other checks before wNAF. ORDER == bits here
      const { windows, windowSize } = opts(W);

      let p = c.ZERO;
      let f = c.BASE;

      const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
      const maxNumber = 2 ** W;
      const shiftBy = BigInt(W);

      for (let window = 0; window < windows; window++) {
        const offset = window * windowSize;
        // Extract W bits.
        let wbits = Number(n & mask);

        // Shift number by W bits.
        n >>= shiftBy;

        // If the bits are bigger than max size, we'll split those.
        // +224 => 256 - 32
        if (wbits > windowSize) {
          wbits -= maxNumber;
          n += _1n;
        }

        // This code was first written with assumption that 'f' and 'p' will never be infinity point:
        // since each addition is multiplied by 2 ** W, it cannot cancel each other. However,
        // there is negate now: it is possible that negated element from low value
        // would be the same as high element, which will create carry into next window.
        // It's not obvious how this can fail, but still worth investigating later.

        // Check if we're onto Zero point.
        // Add random point inside current window to f.
        const offset1 = offset;
        const offset2 = offset + Math.abs(wbits) - 1; // -1 because we skip zero
        const cond1 = window % 2 !== 0;
        const cond2 = wbits < 0;
        if (wbits === 0) {
          // The most important part for const-time getPublicKey
          f = f.add(constTimeNegate(cond1, precomputes[offset1]));
        } else {
          p = p.add(constTimeNegate(cond2, precomputes[offset2]));
        }
      }
      // JIT-compiler should not eliminate f here, since it will later be used in normalizeZ()
      // Even if the variable is still unused, there are some checks which will
      // throw an exception, so compiler needs to prove they won't happen, which is hard.
      // At this point there is a way to F be infinity-point even if p is not,
      // which makes it less const-time: around 1 bigint multiply.
      return { p, f };
    },
  };
}
