#!/usr/bin/env node
import { pathToFileURL } from 'node:url';

type Secp256k1Module = {
  secp256k1: {
    Point: {
      BASE: {
        multiply: (scalar: bigint) => { X: bigint };
        multiplyUnsafe: (scalar: bigint) => { X: bigint };
        precompute: (windowSize?: number, isLazy?: boolean) => unknown;
      };
      Fn: { ORDER: bigint };
    };
  };
};

type Sample = {
  name: string;
  scalar: bigint;
  ns: number;
};

const DEFAULT_MODULE = './src/secp256k1.ts';
const DEFAULT_ROUNDS = 80;
const DEFAULT_BATCH = 4;

function parseArgs() {
  const opts = {
    module: DEFAULT_MODULE,
    method: 'multiply',
    rounds: DEFAULT_ROUNDS,
    batch: DEFAULT_BATCH,
    csv: false,
  };
  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    const next = () => {
      const v = process.argv[++i];
      if (!v) throw new Error(`missing value for ${arg}`);
      return v;
    };
    if (arg === '--module') opts.module = next();
    else if (arg === '--method') opts.method = next();
    else if (arg === '--rounds') opts.rounds = Number(next());
    else if (arg === '--batch') opts.batch = Number(next());
    else if (arg === '--csv') opts.csv = true;
    else if (arg === '--help' || arg === '-h') {
      console.log(`Usage: node scripts/ct/secp256k1-multiply.ts [options]

Options:
  --module PATH_OR_URL    secp256k1 module to import (${DEFAULT_MODULE})
  --method NAME           multiply or multiplyUnsafe (multiply)
  --rounds N              interleaved timing rounds (${DEFAULT_ROUNDS})
  --batch N               multiplies per timing sample (${DEFAULT_BATCH})
  --csv                   emit CSV rows instead of a table
`);
      process.exit(0);
    } else throw new Error(`unknown argument: ${arg}`);
  }
  if (!Number.isSafeInteger(opts.rounds) || opts.rounds < 2) throw new Error('--rounds must be >= 2');
  if (!Number.isSafeInteger(opts.batch) || opts.batch < 1) throw new Error('--batch must be >= 1');
  if (opts.method !== 'multiply' && opts.method !== 'multiplyUnsafe')
    throw new Error('--method must be multiply or multiplyUnsafe');
  return opts;
}

function moduleUrl(pathOrUrl: string) {
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(pathOrUrl)) return pathOrUrl;
  return pathToFileURL(pathOrUrl).href;
}

function median(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function mean(values: number[]) {
  return values.reduce((acc, v) => acc + v, 0) / values.length;
}

function stdev(values: number[]) {
  const m = mean(values);
  return Math.sqrt(values.reduce((acc, v) => acc + (v - m) ** 2, 0) / (values.length - 1));
}

function percentile(values: number[], p: number) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor((sorted.length - 1) * p)))];
}

function fmtNs(ns: number) {
  if (ns >= 1_000_000) return `${(ns / 1_000_000).toFixed(3)}ms`;
  if (ns >= 1_000) return `${(ns / 1_000).toFixed(1)}us`;
  return `${ns.toFixed(0)}ns`;
}

function xorshift32(seed: number) {
  let x = seed | 0;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return x >>> 0;
  };
}

function shuffle<T>(arr: T[], seed: number) {
  const rand = xorshift32(seed);
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = rand() % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function scalarSet(n: bigint) {
  const mask256 = (1n << 256n) - 1n;
  const scalars: [string, bigint][] = [
    ['one', 1n],
    ['low-bit', 1n << 5n],
    ['mid-bit', 1n << 127n],
    ['high-bit', 1n << 255n],
    ['alternating-a', BigInt('0x' + 'aa'.repeat(32)) % n],
    ['alternating-5', BigInt('0x' + '55'.repeat(32)) % n],
    ['dense', n - 1n],
    ['randomish', BigInt('0xf1d2c3b4a5968778695a4b3c2d1e0f123456789abcdef123456789abcdef123') % n],
  ];
  return scalars.map(([name, scalar]) => {
    scalar &= mask256;
    scalar %= n;
    if (scalar === 0n) scalar = 1n;
    return { name, scalar };
  });
}

function groupedStats(samples: Sample[]) {
  const byName = new Map<string, number[]>();
  for (const s of samples) {
    const list = byName.get(s.name) || [];
    list.push(s.ns);
    byName.set(s.name, list);
  }
  return [...byName].map(([name, values]) => ({
    name,
    samples: values.length,
    mean: mean(values),
    median: median(values),
    p05: percentile(values, 0.05),
    p95: percentile(values, 0.95),
    sd: stdev(values),
  }));
}

function printTable(rows: ReturnType<typeof groupedStats>) {
  const means = rows.map((r) => r.mean);
  const minMean = Math.min(...means);
  const maxMean = Math.max(...means);
  console.log('scalar class    samples   mean/op   median   p05      p95      rel');
  for (const r of rows) {
    console.log(
      `${r.name.padEnd(14)} ${String(r.samples).padStart(7)} ${fmtNs(r.mean).padStart(9)} ${fmtNs(
        r.median
      ).padStart(8)} ${fmtNs(r.p05).padStart(8)} ${fmtNs(r.p95).padStart(8)} ${(
        r.mean / minMean
      ).toFixed(3)}x`
    );
  }
  console.log(`max/min mean ratio: ${(maxMean / minMean).toFixed(3)}x`);
}

const opts = parseArgs();
const mod = (await import(moduleUrl(opts.module))) as Secp256k1Module;
const { Point } = mod.secp256k1;
const base = Point.BASE;
base.precompute(8, false);

const scalars = scalarSet(Point.Fn.ORDER);
const order = Array.from({ length: opts.rounds }, (_, round) => shuffle(scalars, 0x9e3779b9 ^ round)).flat();
let sink = 0;

// Warm up the selected method and WebAssembly instantiation if present.
for (let i = 0; i < 64; i++) {
  const p = base[opts.method as 'multiply'](scalars[i % scalars.length].scalar);
  sink ^= Number(p.X & 0xffn);
}

const samples: Sample[] = [];
for (const s of order) {
  const start = process.hrtime.bigint();
  for (let i = 0; i < opts.batch; i++) {
    const p = base[opts.method as 'multiply'](s.scalar);
    sink ^= Number(p.X & 0xffn);
  }
  const elapsed = Number(process.hrtime.bigint() - start) / opts.batch;
  samples.push({ name: s.name, scalar: s.scalar, ns: elapsed });
}

const rows = groupedStats(samples);
console.log(`# secp256k1 ${opts.method} timing by scalar class`);
console.log(`# module=${opts.module} rounds=${opts.rounds} batch=${opts.batch} sink=${sink}`);
if (opts.csv) {
  console.log('name,samples,mean_ns,median_ns,p05_ns,p95_ns,sd_ns,rel_to_min');
  const minMean = Math.min(...rows.map((r) => r.mean));
  for (const r of rows) {
    console.log(
      `${r.name},${r.samples},${r.mean.toFixed(1)},${r.median.toFixed(1)},${r.p05.toFixed(
        1
      )},${r.p95.toFixed(1)},${r.sd.toFixed(1)},${(r.mean / minMean).toFixed(4)}`
    );
  }
} else printTable(rows);
