/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { Field as Fp, validateField } from '../abstract/modular.js';
import { poseidon } from '../abstract/poseidon.js';
import * as u from '../abstract/utils.js';

// Poseidon hash https://docs.starkware.co/starkex/stark-curve.html
export const Fp253 = Fp(
  BigInt('14474011154664525231415395255581126252639794253786371766033694892385558855681')
); // 2^253 + 2^199 + 1
export const Fp251 = Fp(
  BigInt('3618502788666131213697322783095070105623107215331596699973092056135872020481')
); // 2^251 + 17 * 2^192 + 1

function poseidonRoundConstant(Fp, name, idx) {
  const val = Fp.fromBytes(sha256(utf8ToBytes(`${name}${idx}`)));
  return Fp.create(val);
}

// NOTE: doesn't check eiginvalues and possible can create unsafe matrix. But any filtration here will break compatibility with starknet
// Please use only if you really know what you doing.
// https://eprint.iacr.org/2019/458.pdf Section 2.3 (Avoiding Insecure Matrices)
export function _poseidonMDS(Fp, name, m, attempt = 0) {
  const x_values = [];
  const y_values = [];
  for (let i = 0; i < m; i++) {
    x_values.push(poseidonRoundConstant(Fp, `${name}x`, attempt * m + i));
    y_values.push(poseidonRoundConstant(Fp, `${name}y`, attempt * m + i));
  }
  if (new Set([...x_values, ...y_values]).size !== 2 * m)
    throw new Error('X and Y values are not distinct');
  return x_values.map((x) => y_values.map((y) => Fp.inv(Fp.sub(x, y))));
}

const MDS_SMALL = [
  [3, 1, 1],
  [1, -1, 1],
  [1, 1, -2],
].map((i) => i.map(BigInt));

export function poseidonBasic(opts, mds) {
  validateField(opts.Fp);
  if (!Number.isSafeInteger(opts.rate) || !Number.isSafeInteger(opts.capacity))
    throw new Error(`Wrong poseidon opts: ${opts}`);
  const m = opts.rate + opts.capacity;
  const rounds = opts.roundsFull + opts.roundsPartial;
  const roundConstants = [];
  for (let i = 0; i < rounds; i++) {
    const row = [];
    for (let j = 0; j < m; j++) row.push(poseidonRoundConstant(opts.Fp, 'Hades', m * i + j));
    roundConstants.push(row);
  }
  const res = poseidon({
    ...opts,
    t: m,
    sboxPower: 3,
    reversePartialPowIdx: true, // Why?!
    mds,
    roundConstants,
  });
  res.m = m;
  res.rate = opts.rate;
  res.capacity = opts.capacity;
  return res;
}

export function poseidonCreate(opts, mdsAttempt = 0) {
  const m = opts.rate + opts.capacity;
  if (!Number.isSafeInteger(mdsAttempt)) throw new Error(`Wrong mdsAttempt=${mdsAttempt}`);
  return poseidonBasic(opts, _poseidonMDS(opts.Fp, 'HadesMDS', m, mdsAttempt));
}

export const poseidonSmall = poseidonBasic(
  { Fp: Fp251, rate: 2, capacity: 1, roundsFull: 8, roundsPartial: 83 },
  MDS_SMALL
);

export function poseidonHash(x, y, fn = poseidonSmall) {
  return fn([x, y, 2n])[0];
}

export function poseidonHashFunc(x, y, fn = poseidonSmall) {
  return u.numberToVarBytesBE(poseidonHash(u.bytesToNumberBE(x), u.bytesToNumberBE(y), fn));
}

export function poseidonHashSingle(x, fn = poseidonSmall) {
  return fn([x, 0n, 1n])[0];
}

export function poseidonHashMany(values, fn = poseidonSmall) {
  const { m, rate } = fn;
  if (!Array.isArray(values)) throw new Error('bigint array expected in values');
  const padded = Array.from(values); // copy
  padded.push(1n);
  while (padded.length % rate !== 0) padded.push(0n);
  let state = new Array(m).fill(0n);
  for (let i = 0; i < padded.length; i += rate) {
    for (let j = 0; j < rate; j++) state[j] += padded[i + j];
    state = fn(state);
  }
  return state[0];
}
