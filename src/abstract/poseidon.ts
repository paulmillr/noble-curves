/**
 * Implements [Poseidon](https://www.poseidon-hash.info) ZK-friendly hash.
 *
 * There are many poseidon variants with different constants.
 * We don't provide them: you should construct them manually.
 * Check out [micro-starknet](https://github.com/paulmillr/micro-starknet) package for a proper example.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { asafenumber, bitGet, validateObject, type TArg, type TRet } from '../utils.ts';
import { FpInvertBatch, FpPow, type IField, validateField } from './modular.ts';

// Grain LFSR (Linear-Feedback Shift Register): https://eprint.iacr.org/2009/109.pdf
function grainLFSR(state: number[]): () => boolean {
  // Advances the caller-provided 80-entry state array in place; only the length
  // is checked here, so entries are assumed to already be bits.
  let pos = 0;
  if (state.length !== 80) throw new Error('grainLFRS: wrong state length, should be 80 bits');
  const getBit = (): boolean => {
    const r = (offset: number) => state[(pos + offset) % 80];
    const bit = r(62) ^ r(51) ^ r(38) ^ r(23) ^ r(13) ^ r(0);
    state[pos] = bit;
    pos = ++pos % 80;
    return !!bit;
  };
  for (let i = 0; i < 160; i++) getBit();
  return () => {
    // https://en.wikipedia.org/wiki/Shrinking_generator
    while (true) {
      const b1 = getBit();
      const b2 = getBit();
      if (!b1) continue;
      return b2;
    }
  };
}

/** Core Poseidon permutation parameters shared by all variants. */
export type PoseidonBasicOpts = {
  /** Prime field used by the permutation. */
  Fp: IField<bigint>;
  /** Poseidon width `t = rate + capacity`. */
  t: number;
  /** Number of full S-box rounds. */
  roundsFull: number;
  /** Number of partial S-box rounds. */
  roundsPartial: number;
  /** Whether to use the inverse S-box variant. */
  isSboxInverse?: boolean;
};

function assertValidPosOpts(opts: TArg<PoseidonBasicOpts>) {
  const { Fp, roundsFull } = opts;
  validateField(Fp);
  validateObject(
    opts,
    {
      t: 'number',
      roundsFull: 'number',
      roundsPartial: 'number',
    },
    {
      isSboxInverse: 'boolean',
    }
  );
  for (const k of ['t', 'roundsFull', 'roundsPartial'] as const) {
    asafenumber(opts[k], k);
    if (opts[k] < 1) throw new Error('invalid number ' + k);
  }
  // Poseidon splits full rounds as `R_F / 2`, then partial rounds, then `R_F / 2` again.
  if (roundsFull & 1) throw new Error('roundsFull is not even' + roundsFull);
}

function poseidonGrain(opts: TArg<PoseidonBasicOpts>) {
  assertValidPosOpts(opts);
  const { Fp } = opts;
  const state = Array(80).fill(1);
  let pos = 0;
  const writeBits = (value: bigint, bitCount: number) => {
    for (let i = bitCount - 1; i >= 0; i--) state[pos++] = Number(bitGet(value, i));
  };
  const _0n = BigInt(0);
  const _1n = BigInt(1);
  // The Grain seed layout is fixed-width: `Fp.BITS` and `t` use 12 bits,
  // `roundsFull` and `roundsPartial` use 10, so larger values are truncated here.
  // This is intentional for compatibility with snarkVM / arkworks PoseidonGrainLFSR:
  // they write the same fixed-width seed fields without range checks, then still consume
  // the LFSR using the caller-provided round count for ARK/MDS generation.
  // Normalizing or rejecting here would diverge from those implementations.
  writeBits(_1n, 2); // prime field
  writeBits(opts.isSboxInverse ? _1n : _0n, 4); // b2..b5
  writeBits(BigInt(Fp.BITS), 12); // b6..b17
  writeBits(BigInt(opts.t), 12); // b18..b29
  writeBits(BigInt(opts.roundsFull), 10); // b30..b39
  writeBits(BigInt(opts.roundsPartial), 10); // b40..b49

  const getBit = grainLFSR(state);
  return (count: number, reject: boolean): bigint[] => {
    const res: bigint[] = [];
    for (let i = 0; i < count; i++) {
      while (true) {
        let num = _0n;
        for (let i = 0; i < Fp.BITS; i++) {
          num <<= _1n;
          if (getBit()) num |= _1n;
        }
        if (reject && num >= Fp.ORDER) continue; // rejection sampling
        res.push(Fp.create(num));
        break;
      }
    }
    return res;
  };
}

/** Poseidon settings used by the Grain-LFSR constant generator. */
export type PoseidonGrainOpts = PoseidonBasicOpts & {
  /** S-box power used while generating constants. */
  sboxPower?: number;
};

type PoseidonConstants = { mds: bigint[][]; roundConstants: bigint[][] };

// NOTE: this is not standard but used often for constant generation for poseidon
// (grain LFRS-like structure)
/**
 * @param opts - Poseidon grain options. See {@link PoseidonGrainOpts}.
 * @param skipMDS - Number of MDS samples to skip.
 * @returns Generated constants.
 * @throws If the generated MDS matrix contains a zero denominator. {@link Error}
 * @example
 * Generate Poseidon round constants and an MDS matrix from the Grain LFSR.
 *
 * ```ts
 * import { grainGenConstants } from '@noble/curves/abstract/poseidon.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const constants = grainGenConstants({ Fp, t: 2, roundsFull: 8, roundsPartial: 8 });
 * ```
 */
export function grainGenConstants(
  opts: TArg<PoseidonGrainOpts>,
  skipMDS: number = 0
): PoseidonConstants {
  const { Fp, t, roundsFull, roundsPartial } = opts;
  // `skipMDS` counts how many candidate matrices to discard before taking one.
  asafenumber(skipMDS, 'skipMDS');
  if (skipMDS < 0) throw new Error('invalid number skipMDS');
  const rounds = roundsFull + roundsPartial;
  // `sboxPower` is carried in the opts shape for Poseidon compatibility, but
  // Grain constant generation here only depends on field/size/round counts/inverse flag.
  const sample = poseidonGrain(opts);
  const roundConstants: bigint[][] = [];
  for (let r = 0; r < rounds; r++) roundConstants.push(sample(t, true));
  if (skipMDS > 0) for (let i = 0; i < skipMDS; i++) sample(2 * t, false);
  const xs = sample(t, false);
  const ys = sample(t, false);
  // Construct MDS Matrix M[i][j] = 1 / (xs[i] + ys[j])
  const mds: bigint[][] = [];
  for (let i = 0; i < t; i++) {
    const row: bigint[] = [];
    for (let j = 0; j < t; j++) {
      const xy = Fp.add(xs[i], ys[j]);
      if (Fp.is0(xy))
        throw new Error(`Error generating MDS matrix: xs[${i}] + ys[${j}] resulted in zero.`);
      row.push(xy);
    }
    mds.push(FpInvertBatch(Fp, row));
  }

  return { roundConstants, mds };
}

/** Fully specified Poseidon permutation options with explicit constants. */
export type PoseidonOpts = PoseidonBasicOpts &
  PoseidonConstants & {
    /** S-box power used by the permutation. */
    sboxPower?: number;
    /** Whether to reverse the partial-round S-box index. */
    reversePartialPowIdx?: boolean; // Hack for stark
  };

/**
 * @param opts - Poseidon options. See {@link PoseidonOpts}.
 * @returns Normalized poseidon options.
 * @throws If the Poseidon options, constants, or MDS matrix are invalid. {@link Error}
 * @example
 * Validate generated constants before constructing a permutation.
 *
 * ```ts
 * import { grainGenConstants, validateOpts } from '@noble/curves/abstract/poseidon.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const constants = grainGenConstants({ Fp, t: 2, roundsFull: 8, roundsPartial: 8 });
 * const opts = validateOpts({ ...constants, Fp, t: 2, roundsFull: 8, roundsPartial: 8, sboxPower: 3 });
 * ```
 */
export function validateOpts(opts: TArg<PoseidonOpts>): TRet<
  Readonly<{
    rounds: number;
    sboxFn: (n: bigint) => bigint;
    roundConstants: bigint[][];
    mds: bigint[][];
    Fp: IField<bigint>;
    t: number;
    roundsFull: number;
    roundsPartial: number;
    sboxPower?: number;
    reversePartialPowIdx?: boolean; // Hack for stark
  }>
> {
  // This only normalizes shapes and field membership for the provided constants;
  // it does not prove the stronger MDS/security criteria discussed in the specs.
  assertValidPosOpts(opts);
  const { Fp, mds, reversePartialPowIdx: rev, roundConstants: rc } = opts;
  const { roundsFull, roundsPartial, sboxPower, t } = opts;

  // MDS is TxT matrix
  if (!Array.isArray(mds) || mds.length !== t) throw new Error('Poseidon: invalid MDS matrix');
  const _mds = mds.map((mdsRow) => {
    if (!Array.isArray(mdsRow) || mdsRow.length !== t)
      throw new Error('invalid MDS matrix row: ' + mdsRow);
    return mdsRow.map((i) => {
      if (typeof i !== 'bigint') throw new Error('invalid MDS matrix bigint: ' + i);
      // Hardcoded Poseidon MDS matrices often use signed entries like `-1`;
      // accept bigint representatives here and reduce them into the field.
      return Fp.create(i);
    });
  });

  if (rev !== undefined && typeof rev !== 'boolean')
    throw new Error('invalid param reversePartialPowIdx=' + rev);

  if (roundsFull & 1) throw new Error('roundsFull is not even' + roundsFull);
  const rounds = roundsFull + roundsPartial;

  if (!Array.isArray(rc) || rc.length !== rounds)
    throw new Error('Poseidon: invalid round constants');
  const roundConstants = rc.map((rc) => {
    if (!Array.isArray(rc) || rc.length !== t) throw new Error('invalid round constants');
    return rc.map((i) => {
      if (typeof i !== 'bigint' || !Fp.isValid(i)) throw new Error('invalid round constant');
      return Fp.create(i);
    });
  });
  // Freeze nested constants so exported handles cannot retune a live permutation instance.
  const freezeRows = (rows: bigint[][]) =>
    Object.freeze(rows.map((row) => Object.freeze(row))) as unknown as bigint[][];

  if (!sboxPower || ![3, 5, 7, 17].includes(sboxPower)) throw new Error('invalid sboxPower');
  const _sboxPower = BigInt(sboxPower);
  let sboxFn = (n: bigint) => FpPow(Fp, n, _sboxPower);
  // Unwrapped sbox power for common cases (195->142μs)
  if (sboxPower === 3) sboxFn = (n: bigint) => Fp.mul(Fp.sqrN(n), n);
  else if (sboxPower === 5) sboxFn = (n: bigint) => Fp.mul(Fp.sqrN(Fp.sqrN(n)), n);

  return Object.freeze({
    ...opts,
    rounds,
    sboxFn,
    roundConstants: freezeRows(roundConstants),
    mds: freezeRows(_mds),
  }) as TRet<
    Readonly<{
      rounds: number;
      sboxFn: (n: bigint) => bigint;
      roundConstants: bigint[][];
      mds: bigint[][];
      Fp: IField<bigint>;
      t: number;
      roundsFull: number;
      roundsPartial: number;
      sboxPower?: number;
      reversePartialPowIdx?: boolean;
    }>
  >;
}

/**
 * @param rc - Flattened round constants.
 * @param t - Poseidon width.
 * @returns Constants grouped by round.
 * @throws If the width or flattened constant array is invalid. {@link Error}
 * @example
 * Regroup a flat constant list into per-round chunks.
 *
 * ```ts
 * const rounds = splitConstants([1n, 2n, 3n, 4n], 2);
 * ```
 */
export function splitConstants(rc: bigint[], t: number): bigint[][] {
  asafenumber(t, 't');
  if (t < 1) throw new Error('poseidonSplitConstants: invalid t');
  if (!Array.isArray(rc) || rc.length % t) throw new Error('poseidonSplitConstants: invalid rc');
  const res = [];
  let tmp = [];
  for (let i = 0; i < rc.length; i++) {
    const c = rc[i];
    if (typeof c !== 'bigint') throw new Error('invalid bigint=' + c);
    tmp.push(c);
    if (tmp.length === t) {
      res.push(tmp);
      tmp = [];
    }
  }
  return res;
}

/**
 * Poseidon permutation callable.
 * @param values - Poseidon state vector. Non-canonical bigints are normalized with `Fp.create(...)`.
 * @returns Permuted state vector.
 */
export type PoseidonFn = {
  (values: bigint[]): bigint[];
  /** Round constants captured by the permutation instance. */
  roundConstants: bigint[][];
};
/** Poseidon NTT-friendly hash. */
/**
 * @param opts - Poseidon options. See {@link PoseidonOpts}.
 * @returns Poseidon permutation.
 * @throws If the Poseidon options or state vector are invalid. {@link Error}
 * @example
 * Build a Poseidon permutation from validated parameters and constants.
 *
 * ```ts
 * import { grainGenConstants, poseidon } from '@noble/curves/abstract/poseidon.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const constants = grainGenConstants({ Fp, t: 2, roundsFull: 8, roundsPartial: 8 });
 * const hash = poseidon({ ...constants, Fp, t: 2, roundsFull: 8, roundsPartial: 8, sboxPower: 3 });
 * const state = hash([1n, 2n]);
 * ```
 */
export function poseidon(opts: TArg<PoseidonOpts>): PoseidonFn {
  const _opts = validateOpts(opts);
  const { Fp, mds, roundConstants, rounds: totalRounds, roundsPartial, sboxFn, t } = _opts;
  const halfRoundsFull = _opts.roundsFull / 2;
  const partialIdx = _opts.reversePartialPowIdx ? t - 1 : 0;
  const poseidonRound = (values: bigint[], isFull: boolean, idx: number) => {
    values = values.map((i, j) => Fp.add(i, roundConstants[idx][j]));

    if (isFull) values = values.map((i) => sboxFn(i));
    else values[partialIdx] = sboxFn(values[partialIdx]);
    // Matrix multiplication
    values = mds.map((i) => i.reduce((acc, i, j) => Fp.add(acc, Fp.mulN(i, values[j])), Fp.ZERO));
    return values;
  };
  const poseidonHash = function poseidonHash(values: bigint[]) {
    if (!Array.isArray(values) || values.length !== t)
      throw new Error('invalid values, expected array of bigints with length ' + t);
    // `.map()` skips sparse holes, which would leak `undefined` into round math below.
    values = values.slice();
    for (let j = 0; j < values.length; j++) {
      const i = values[j];
      if (typeof i !== 'bigint') throw new Error('invalid bigint=' + i);
      values[j] = Fp.create(i);
    }
    let lastRound = 0;
    // Apply r_f/2 full rounds.
    for (let i = 0; i < halfRoundsFull; i++) values = poseidonRound(values, true, lastRound++);
    // Apply r_p partial rounds.
    for (let i = 0; i < roundsPartial; i++) values = poseidonRound(values, false, lastRound++);
    // Apply r_f/2 full rounds.
    for (let i = 0; i < halfRoundsFull; i++) values = poseidonRound(values, true, lastRound++);

    if (lastRound !== totalRounds) throw new Error('invalid number of rounds');
    return values;
  } as PoseidonFn;
  // For verification in tests
  Object.defineProperty(poseidonHash, 'roundConstants', {
    value: roundConstants,
    enumerable: true,
  });
  return poseidonHash;
}

/**
 * @param Fp - Field implementation.
 * @param rate - Sponge rate.
 * @param capacity - Sponge capacity.
 * @param hash - Poseidon permutation.
 * @example
 * Wrap one Poseidon permutation in a sponge interface.
 *
 * ```ts
 * import { PoseidonSponge, grainGenConstants, poseidon } from '@noble/curves/abstract/poseidon.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const constants = grainGenConstants({ Fp, t: 2, roundsFull: 8, roundsPartial: 8 });
 * const hash = poseidon({ ...constants, Fp, t: 2, roundsFull: 8, roundsPartial: 8, sboxPower: 3 });
 * const sponge = new PoseidonSponge(Fp, 1, 1, hash);
 * sponge.absorb([1n]);
 * const out = sponge.squeeze(1);
 * ```
 */
export class PoseidonSponge {
  private Fp: IField<bigint>;
  readonly rate: number;
  readonly capacity: number;
  readonly hash: PoseidonFn;
  private state: bigint[]; // [...capacity, ...rate]
  private pos = 0;
  private isAbsorbing = true;

  constructor(Fp: IField<bigint>, rate: number, capacity: number, hash: PoseidonFn) {
    const width = spongeShape(rate, capacity);
    // The direct constructor accepts an arbitrary permutation hook, but callers still
    // need to preserve the `PoseidonFn.roundConstants` width metadata. Reject width
    // mismatches here instead of deferring them until the first `process()` call.
    if (width !== hash.roundConstants[0]?.length)
      throw new Error(
        `invalid sponge width: expected ${hash.roundConstants[0]?.length}, got ${width}`
      );
    this.Fp = Fp;
    this.hash = hash;
    this.rate = rate;
    this.capacity = capacity;
    this.state = new Array(width);
    this.clean();
  }
  private process(): void {
    // The permutation is expected to return an owned state array. If callers inject a custom
    // hook that reuses external storage, `clean()` will zero that shared buffer too.
    this.state = this.hash(this.state);
  }
  absorb(input: bigint[]): void {
    for (const i of input)
      if (typeof i !== 'bigint' || !this.Fp.isValid(i)) throw new Error('invalid input: ' + i);
    for (let i = 0; i < input.length; ) {
      if (!this.isAbsorbing || this.pos === this.rate) {
        this.process();
        this.pos = 0;
        this.isAbsorbing = true;
      }
      const chunk = Math.min(this.rate - this.pos, input.length - i);
      for (let j = 0; j < chunk; j++) {
        const idx = this.capacity + this.pos++;
        this.state[idx] = this.Fp.add(this.state[idx], input[i++]);
      }
    }
  }
  squeeze(count: number): bigint[] {
    // Rust oracles use unsigned counts. In JS we keep `squeeze(0) => []` for
    // compatibility, but still reject negative/fractional counts explicitly.
    asafenumber(count, 'count');
    if (count < 0) throw new Error('invalid number count');
    const res: bigint[] = [];
    while (res.length < count) {
      if (this.isAbsorbing || this.pos === this.rate) {
        this.process();
        this.pos = 0;
        this.isAbsorbing = false;
      }
      const chunk = Math.min(this.rate - this.pos, count - res.length);
      for (let i = 0; i < chunk; i++) res.push(this.state[this.capacity + this.pos++]);
    }
    return res;
  }
  clean(): void {
    this.state.fill(this.Fp.ZERO);
    this.isAbsorbing = true;
    this.pos = 0;
  }
  clone(): PoseidonSponge {
    const c = new PoseidonSponge(this.Fp, this.rate, this.capacity, this.hash);
    c.pos = this.pos;
    c.isAbsorbing = this.isAbsorbing;
    c.state = [...this.state];
    return c;
  }
}

/** Options for the non-standard but commonly used Poseidon sponge wrapper. */
export type PoseidonSpongeOpts = Omit<PoseidonOpts, 't'> & {
  /** Sponge rate. */
  rate: number;
  /** Sponge capacity. */
  capacity: number;
};

const spongeShape = (rate: number, capacity: number) => {
  asafenumber(rate, 'rate');
  asafenumber(capacity, 'capacity');
  // A sponge with zero rate cannot absorb or squeeze any field elements.
  if (rate < 1) throw new Error('invalid number rate');
  // Negative capacity can accidentally keep `rate + capacity` coherent while still
  // producing a nonsensical sponge shape.
  if (capacity < 0) throw new Error('invalid number capacity');
  return rate + capacity;
};

/**
 * The method is not defined in spec, but nevertheless used often.
 * Check carefully for compatibility: there are many edge cases, like absorbing an empty array.
 * We cross-test against:
 * - {@link https://github.com/ProvableHQ/snarkVM/tree/staging/algorithms | snarkVM algorithms}
 * - {@link https://github.com/arkworks-rs/crypto-primitives/tree/main | arkworks crypto-primitives}
 * @param opts - Sponge options. See {@link PoseidonSpongeOpts}.
 * @returns Factory for sponge instances.
 * @throws If the sponge dimensions or backing permutation options are invalid. {@link Error}
 * @example
 * Use the sponge helper to absorb several field elements and squeeze one digest.
 *
 * ```ts
 * import { grainGenConstants, poseidonSponge } from '@noble/curves/abstract/poseidon.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const constants = grainGenConstants({ Fp, t: 2, roundsFull: 8, roundsPartial: 8 });
 * const makeSponge = poseidonSponge({
 *   ...constants,
 *   Fp,
 *   rate: 1,
 *   capacity: 1,
 *   roundsFull: 8,
 *   roundsPartial: 8,
 *   sboxPower: 3,
 * });
 * const sponge = makeSponge();
 * sponge.absorb([1n]);
 * const out = sponge.squeeze(1);
 * ```
 */
export function poseidonSponge(opts: TArg<PoseidonSpongeOpts>): TRet<() => PoseidonSponge> {
  const { rate, capacity } = opts;
  const t = spongeShape(rate, capacity);
  // Re-use one hash instance between sponge instances; isolation depends on
  // poseidon(...) itself staying immutable and not carrying mutable call state.
  const hash = poseidon({ ...opts, t });
  const { Fp } = opts;
  return (() => new PoseidonSponge(Fp, rate, capacity, hash)) as TRet<() => PoseidonSponge>;
}
