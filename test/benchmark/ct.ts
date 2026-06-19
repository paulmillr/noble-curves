import { Field } from '../../src/abstract/modular.ts';
import { FieldCt } from '../../src/abstract/field-ct.ts';
import { secp256k1 } from '../../src/secp256k1.ts';
import { bytesToNumberBE, numberToBytesBE } from '../../src/utils.ts';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SAMPLES = Number(process.env.CT_SAMPLES || 400);
const INPUTS = Number(process.env.CT_INPUTS || 1024);

type Stats = {
  n: number;
  mean: number;
  variance: number;
};
type Probe = {
  label: string;
  batch: number;
  fixed: unknown[];
  random: unknown[];
  run: (input: unknown) => unknown;
};

let sink = 0;

function consume(value: unknown): void {
  if (typeof value === 'bigint') {
    sink ^= Number(value & 0xffn);
  } else if (value instanceof Uint8Array) {
    sink ^= value[0];
  } else if (value && typeof value === 'object' && 'X' in value) {
    const x = (value as { X: unknown }).X;
    sink ^= typeof x === 'bigint' ? Number(x & 0xffn) : x instanceof Uint8Array ? x[0] : 0;
  } else if (typeof value === 'boolean') {
    sink ^= Number(value);
  }
}

function xorshift32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return s >>> 0;
  };
}

function randomScalar(rng: () => number, order: bigint): bigint {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i++) bytes[i] = rng() & 0xff;
  return (bytesToNumberBE(bytes) % (order - 1n)) + 1n;
}

function makeSchedule(samples: number, rng: () => number): number[] {
  const out = Array.from({ length: samples }, (_, i) => i & 1);
  for (let i = out.length - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    const tmp = out[i];
    out[i] = out[j];
    out[j] = tmp;
  }
  return out;
}

function stats(samples: number[]): Stats {
  const n = samples.length;
  const mean = samples.reduce((sum, v) => sum + v, 0) / n;
  const variance = samples.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (n - 1);
  return { n, mean, variance };
}

function welchT(a: Stats, b: Stats): number {
  return (a.mean - b.mean) / Math.sqrt(a.variance / a.n + b.variance / b.n);
}

function verdict(t: number): string {
  const abs = Math.abs(t);
  if (abs >= 10) return 'strong signal';
  if (abs >= 4.5) return 'signal';
  return 'no signal';
}

function fmtNs(ns: number): string {
  if (ns >= 1_000_000) return (ns / 1_000_000).toFixed(3) + 'ms';
  if (ns >= 1_000) return (ns / 1_000).toFixed(3) + 'us';
  return ns.toFixed(1) + 'ns';
}

function runProbe(probe: Probe, samples = SAMPLES): void {
  const rng = xorshift32(0xdecafbad);
  const schedule = makeSchedule(samples, rng);
  const mask = INPUTS - 1;
  const byClass = [[], []] as [number[], number[]];

  for (let i = 0; i < Math.min(64, samples); i++) {
    const input = probe.random[i & mask];
    for (let j = 0; j < probe.batch; j++) consume(probe.run(input));
  }

  for (let sample = 0; sample < schedule.length; sample++) {
    const cls = schedule[sample];
    const inputs = cls === 0 ? probe.fixed : probe.random;
    const offset = rng() & mask;
    const start = process.hrtime.bigint();
    for (let j = 0; j < probe.batch; j++) consume(probe.run(inputs[(offset + j) & mask]));
    const elapsed = Number(process.hrtime.bigint() - start) / probe.batch;
    byClass[cls].push(elapsed);
  }
  const fixed = stats(byClass[0]);
  const random = stats(byClass[1]);
  const t = welchT(fixed, random);
  const delta = ((random.mean - fixed.mean) / fixed.mean) * 100;
  console.log(
    `${probe.label.padEnd(32)} fixed=${fmtNs(fixed.mean).padStart(9)} random=${fmtNs(
      random.mean
    ).padStart(9)} delta=${delta.toFixed(2).padStart(8)}% t=${t
      .toFixed(2)
      .padStart(8)} ${verdict(t)}`
  );
}

function assertPowerOfTwo(n: number): void {
  if (n < 2 || (n & (n - 1)) !== 0) throw new Error('CT_INPUTS must be a power of two >= 2');
}

function makeFieldProbes(name: string, order: bigint): Probe[] {
  const rng = xorshift32(name === 'Fp' ? 1 : 2);
  const bigint = Field(order);
  const ct = FieldCt(order);
  const fixedA = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fn % order;
  const fixedB = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201n % order;
  const randA = Array.from({ length: INPUTS }, () => randomScalar(rng, order));
  const randB = Array.from({ length: INPUTS }, () => randomScalar(rng, order));

  const bigFixed = Array.from({ length: INPUTS }, () => ({ a: bigint.create(fixedA), b: bigint.create(fixedB) }));
  const bigRandom = Array.from({ length: INPUTS }, (_, i) => ({
    a: bigint.create(randA[i]),
    b: bigint.create(randB[i]),
  }));
  const bigSqrtFixed = Array.from({ length: INPUTS }, () => bigint.sqr(bigint.create(fixedA)));
  const bigSqrtRandom = randA.map((a) => bigint.sqr(bigint.create(a)));
  const bigBytesFixed = Array.from({ length: INPUTS }, () => numberToBytesBE(fixedA, 32));
  const bigBytesRandom = randA.map((a) => numberToBytesBE(a, 32));

  const ctFixed = Array.from({ length: INPUTS }, () => ({ a: ct.fromBigint(fixedA), b: ct.fromBigint(fixedB) }));
  const ctRandom = Array.from({ length: INPUTS }, (_, i) => ({
    a: ct.fromBigint(randA[i]),
    b: ct.fromBigint(randB[i]),
  }));
  const ctSqrtFixed = Array.from({ length: INPUTS }, () => ct.sqr(ct.fromBigint(fixedA)));
  const ctSqrtRandom = randA.map((a) => ct.sqr(ct.fromBigint(a)));
  const ctBytesFixed = Array.from({ length: INPUTS }, () => ct.toBytes(ct.fromBigint(fixedA)));
  const ctBytesRandom = randA.map((a) => ct.toBytes(ct.fromBigint(a)));

  return [
    {
      label: `${name} bigint add`,
      batch: 256,
      fixed: bigFixed,
      random: bigRandom,
      run: (v) => {
        const { a, b } = v as { a: bigint; b: bigint };
        return bigint.add(a, b);
      },
    },
    {
      label: `${name} ct add`,
      batch: 256,
      fixed: ctFixed,
      random: ctRandom,
      run: (v) => {
        const { a, b } = v as { a: Uint8Array; b: Uint8Array };
        return ct.add(a, b);
      },
    },
    {
      label: `${name} bigint mul`,
      batch: 128,
      fixed: bigFixed,
      random: bigRandom,
      run: (v) => {
        const { a, b } = v as { a: bigint; b: bigint };
        return bigint.mul(a, b);
      },
    },
    {
      label: `${name} ct mul`,
      batch: 128,
      fixed: ctFixed,
      random: ctRandom,
      run: (v) => {
        const { a, b } = v as { a: Uint8Array; b: Uint8Array };
        return ct.mul(a, b);
      },
    },
    {
      label: `${name} bigint inv`,
      batch: 4,
      fixed: bigFixed,
      random: bigRandom,
      run: (v) => bigint.inv((v as { a: bigint }).a),
    },
    {
      label: `${name} ct inv`,
      batch: 1,
      fixed: ctFixed,
      random: ctRandom,
      run: (v) => ct.inv((v as { a: Uint8Array }).a),
    },
    {
      label: `${name} bigint sqrt(square)`,
      batch: 2,
      fixed: bigSqrtFixed,
      random: bigSqrtRandom,
      run: (v) => bigint.sqrt(v as bigint),
    },
    {
      label: `${name} ct sqrt(square)`,
      batch: 1,
      fixed: ctSqrtFixed,
      random: ctSqrtRandom,
      run: (v) => ct.sqrt(v as Uint8Array),
    },
    {
      label: `${name} bigint toBytes`,
      batch: 256,
      fixed: bigFixed,
      random: bigRandom,
      run: (v) => bigint.toBytes((v as { a: bigint }).a),
    },
    {
      label: `${name} ct toBytes`,
      batch: 128,
      fixed: ctFixed,
      random: ctRandom,
      run: (v) => ct.toBytes((v as { a: Uint8Array }).a),
    },
    {
      label: `${name} bigint fromBytes`,
      batch: 128,
      fixed: bigBytesFixed,
      random: bigBytesRandom,
      run: (v) => bigint.fromBytes(v as Uint8Array),
    },
    {
      label: `${name} ct fromBytes`,
      batch: 128,
      fixed: ctBytesFixed,
      random: ctBytesRandom,
      run: (v) => ct.fromBytes(v as Uint8Array),
    },
  ];
}

function makeMultiplyProbes(): Probe[] {
  const rng = xorshift32(3);
  const fixedScalar = 0x5555555555555555555555555555555555555555555555555555555555555555n % N;
  const fixed = Array.from({ length: INPUTS }, () => fixedScalar);
  const random = Array.from({ length: INPUTS }, () => randomScalar(rng, N));
  const Point = secp256k1.Point;
  const cachedBase = Point.BASE;
  const freshBase = Point.fromAffine(Point.BASE.toAffine());
  const randomPoint = Point.BASE.multiplyUnsafe(randomScalar(rng, N));
  const freshRandomPoint = Point.fromAffine(randomPoint.toAffine());
  const cachedRandomPoint = Point.fromAffine(randomPoint.toAffine()).precompute(8, false);
  return [
    {
      label: 'BASE.multiplyUnsafe cached',
      batch: 1,
      fixed,
      random,
      run: (v) => cachedBase.multiplyUnsafe(v as bigint),
    },
    {
      label: 'BASE.multiplyUnsafe fresh',
      batch: 1,
      fixed,
      random,
      run: (v) => freshBase.multiplyUnsafe(v as bigint),
    },
    {
      label: 'random.multiplyUnsafe fresh',
      batch: 1,
      fixed,
      random,
      run: (v) => freshRandomPoint.multiplyUnsafe(v as bigint),
    },
    {
      label: 'random.multiplyUnsafe cached',
      batch: 1,
      fixed,
      random,
      run: (v) => cachedRandomPoint.multiplyUnsafe(v as bigint),
    },
  ];
}

assertPowerOfTwo(INPUTS);
console.log(`# constant-timeness timing probe`);
console.log(`# samples/class=${SAMPLES / 2}, inputs/class=${INPUTS}, node=${process.version}`);
console.log(`# class 0 = fixed non-edge input, class 1 = random non-zero input`);
console.log(`# Welch |t| >= 4.5 is a timing signal; this is a JS timing smoke test, not a proof.\n`);

for (const probe of [...makeFieldProbes('Fp', P), ...makeFieldProbes('Fn', N), ...makeMultiplyProbes()]) {
  runProbe(probe);
}

if (sink === 256) console.log('sink', sink);
