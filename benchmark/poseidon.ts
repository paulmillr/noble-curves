import mark from '@paulmillr/jsbt/bench.js';
import { Field } from '../src/abstract/modular.ts';
import { grainGenConstants, poseidon, validateOpts } from '../src/abstract/poseidon.ts';
import type { PoseidonFn, PoseidonOpts } from '../src/abstract/poseidon.ts';

// Dense per-round baseline (poseidon() before the sparse partial-round decomposition),
// kept for comparison. Uses the same accumulate-then-reduce trick as production code.
function poseidonDense(opts: PoseidonOpts): PoseidonFn {
  const _opts = validateOpts(opts);
  const { Fp, mds, roundConstants, roundsPartial, sboxFn, t } = _opts;
  const halfRoundsFull = _opts.roundsFull / 2;
  const partialIdx = _opts.reversePartialPowIdx ? t - 1 : 0;
  const round = (values: bigint[], isFull: boolean, idx: number) => {
    const rc = roundConstants[idx];
    if (isFull) values = values.map((i, j) => sboxFn(Fp.add(i, rc[j])));
    else {
      values = values.map((i, j) => Fp.add(i, rc[j]));
      values[partialIdx] = sboxFn(values[partialIdx]);
    }
    return mds.map((row) =>
      Fp.create(row.reduce((acc, m, j) => Fp.addN(acc, Fp.mulN(m, values[j])), Fp.ZERO))
    );
  };
  return ((values: bigint[]) => {
    values = values.map((i) => Fp.create(i));
    let r = 0;
    for (let i = 0; i < halfRoundsFull; i++) values = round(values, true, r++);
    for (let i = 0; i < roundsPartial; i++) values = round(values, false, r++);
    for (let i = 0; i < halfRoundsFull; i++) values = round(values, true, r++);
    return values;
  }) as PoseidonFn;
}

(async () => {
  console.log('# poseidon');
  const bn254Fr = Field(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n);
  const stark251 =
    Field(3618502788666131213697322783095070105623107215331596699973092056135872020481n);
  // Round numbers follow the circomlib/hadeshash schedules for x^5,
  // and the Starknet schedule for x^3.
  const configs = [
    {
      name: 'bn254 t=3 (rf=8, rp=57, x^5)',
      Fp: bn254Fr,
      t: 3,
      roundsFull: 8,
      roundsPartial: 57,
      sboxPower: 5,
    },
    {
      name: 'bn254 t=5 (rf=8, rp=60, x^5)',
      Fp: bn254Fr,
      t: 5,
      roundsFull: 8,
      roundsPartial: 60,
      sboxPower: 5,
    },
    {
      name: 'bn254 t=9 (rf=8, rp=63, x^5)',
      Fp: bn254Fr,
      t: 9,
      roundsFull: 8,
      roundsPartial: 63,
      sboxPower: 5,
    },
    {
      name: 'stark t=3 (rf=8, rp=83, x^3)',
      Fp: stark251,
      t: 3,
      roundsFull: 8,
      roundsPartial: 83,
      sboxPower: 3,
      reversePartialPowIdx: true,
    },
  ] as const;
  for (const { name, ...c } of configs) {
    const opts = { ...c, ...grainGenConstants(c) };
    const dense = poseidonDense(opts);
    const hash = poseidon(opts);
    const input = Array.from({ length: c.t }, (_, i) => c.Fp.create(BigInt(i) * 12345n + 7n));
    if (dense(input).join() !== hash(input).join()) throw new Error('mismatch: ' + name);
    console.log(`## ${name}`);
    await mark('dense (old)', () => dense(input));
    await mark('poseidon', () => hash(input));
  }
})();
