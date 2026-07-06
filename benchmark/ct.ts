import { ed25519 } from '../src/ed25519.ts';
import { ed448 } from '../src/ed448.ts';
import { p256, p384, p521 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { pathToFileURL } from 'node:url';

type Bytes = Uint8Array<ArrayBuffer>;
type SecretKeyOperationFn = (secretKey: Bytes) => Bytes;
export type ScalarFieldLike = {
  ORDER: bigint;
  BITS: number;
  BYTES: number;
  toBytes: (num: bigint) => Uint8Array;
  fromBytes: (bytes: Uint8Array) => bigint;
};
type Summary = {
  curve: string;
  point: string;
  samples: number;
  meanNs: number;
  maxT: number;
  failed: boolean;
};
type PointLike = {
  multiply: (scalar: bigint) => PointLike;
  toBytes: () => Uint8Array;
  equals: (other: any) => boolean;
};
type Curve = {
  name: string;
  curve: {
    getPublicKey: (secretKey: Uint8Array, isCompressed?: boolean) => Uint8Array;
    Point: {
      BASE: PointLike;
      Fn: ScalarFieldLike;
      fromBytes: (bytes: Uint8Array) => PointLike;
    };
    utils: { randomSecretKey: () => Uint8Array };
  };
};
type OutputFormat = 'table' | 'csv';
export type CtOptions = {
  batch?: number;
  maxT?: number;
  minNs?: number;
  log?: (message: string) => void;
  onTest?: (result: CtTestResult) => void;
  progress?: {
    step: number;
    start: (test: string) => void;
    tick: () => void;
    end: () => void;
  };
  throwOnFailure?: boolean;
};
export type CtTestResult = {
  name: string;
  a: string;
  b: string;
  aMean: number;
  bMean: number;
  delta: number;
  t: number;
  failed: boolean;
};
export type CtResult = {
  samples: number;
  batch: number;
  maxT: number;
  minNs: number;
  sink: number;
  failed: boolean;
  tests: CtTestResult[];
};
type Source = {
  name: string;
  keys: Bytes[];
};
type Test = {
  name: string;
  a: Source;
  b: Source;
};
type Stats = {
  n: number;
  mean: number;
  m2: number;
};

const DEFAULT_SAMPLES = 100;
const DEFAULT_BATCH = 4;
const DEFAULT_MAX_T = 4.5;
const DEFAULT_MIN_NS = 1_000;
const PROGRESS_ESTIMATE_INTERVAL = 20;
const PROGRESS_MIN_ESTIMATE_MS = 20_000;
const CURVES: Curve[] = [
  { name: 'p256', curve: p256 },
  { name: 'p384', curve: p384 },
  { name: 'p521', curve: p521 },
  { name: 'secp256k1', curve: secp256k1 },
  { name: 'ed25519', curve: ed25519 },
  { name: 'ed448', curve: ed448 },
];
const summary: Summary[] = [];

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();

function main() {
  const samples = sampleCount();
  const format = outputFormat();
  if (format === 'csv') printCtCsvHeader();
  for (const { name, curve } of selectedCurves()) {
    const peerSecret = curve.utils.randomSecretKey();
    const randomPoint = curve.Point.fromBytes(curve.getPublicKey(peerSecret, true));
    if (randomPoint.equals(curve.Point.BASE)) throw new Error(`${name}: random point equals BASE`);
    const points = [
      { name: 'BASE*scalar', point: curve.Point.BASE },
      { name: 'RANDOM_POINT*scalar', point: randomPoint },
    ];
    for (const { name: pointName, point } of points) {
      const result = runSecretKeyOperationCt(
        (scalarBytes) => point.multiply(curve.Point.Fn.fromBytes(scalarBytes)).toBytes() as Bytes,
        curve.Point.Fn,
        samples,
        {
          name: `${name} ${pointName}`,
          log: format === 'csv' ? () => {} : console.log,
          onTest: format === 'csv' ? (test) => printCtCsvRow(name, pointName, test) : undefined,
          progress: progressEnabled() ? ctProgress(name, pointName, format) : undefined,
          throwOnFailure: false,
        }
      );
      summary.push({
        curve: name,
        point: pointName,
        samples,
        meanNs: meanNs(result),
        maxT: maxObservedT(result),
        failed: result.failed,
      });
    }
  }

  if (format === 'csv') {
    if (summary.some((row) => row.failed)) process.exitCode = 1;
    return;
  }
  console.log('\n# summary');
  console.log(
    `${pad('', 2)} ${pad('curve', 10)} ${pad('point', 20)} ${pad('samples', 8)} ${pad('mean/op', 9)} ${pad('max |t|', 8)}`
  );
  for (const row of summary) {
    console.log(
      `${fmtStatus(row.failed)} ${pad(row.curve, 10)} ${pad(row.point, 20)} ${pad(String(row.samples), 8)} ` +
        `${pad(fmtNs(row.meanNs), 9)} ${fmtSummaryT(row.maxT, row.failed)}`
    );
  }
  if (summary.some((row) => row.failed)) process.exitCode = 1;
}

function meanNs(result: CtResult): number {
  let sum = 0;
  let count = 0;
  for (const test of result.tests) {
    sum += test.aMean + test.bMean;
    count += 2;
  }
  return sum / count;
}

function maxObservedT(result: CtResult): number {
  let max = 0;
  for (const test of result.tests) {
    if (test.t > max) max = test.t;
  }
  return max;
}

function fmtNs(ns: number): string {
  return `${fmtFixed(ns / 1000, 0)}us`;
}

function pad(value: string, length: number): string {
  return value.padEnd(length);
}

function fmtStatus(failed: boolean): string {
  const status = failed ? '✕' : '✓';
  if (!supportsColor()) return status;
  return failed ? `\x1b[31m${status}\x1b[0m` : `\x1b[32m${status}\x1b[0m`;
}

function fmtSummaryT(t: number, failed: boolean): string {
  const value = pad(fmtFixed(t, 1), 8);
  return fmtTColor(t, value);
}

function fmtT(t: number, failed: boolean): string {
  const value = `t=${fmtFixed(t, 1).padEnd(13)}`;
  return fmtTColor(t, value);
}

function fmtTColor(t: number, value: string): string {
  if (!supportsColor()) return value;
  if (t >= 10) return `\x1b[31m${value}\x1b[0m`;
  if (t >= DEFAULT_MAX_T) return `\x1b[33m${value}\x1b[0m`;
  return value;
}

function fmtFixed(num: number, digits: number): string {
  const value = num.toFixed(digits);
  return Object.is(Number(value), -0) ? (0).toFixed(digits) : value;
}

function fmtNum(num: number): string {
  return String(cleanZero(num));
}

function cleanZero(num: number): number {
  return Object.is(num, -0) ? 0 : num;
}

function csvCell(value: unknown): string {
  const cell = String(value ?? '');
  return /[",\r\n]/.test(cell) ? `"${cell.replaceAll('"', '""')}"` : cell;
}

function printCsvRow(values: unknown[]) {
  console.log(values.map(csvCell).join(','));
}

function printCtCsvHeader() {
  printCsvRow(['status', 't', 'curve', 'point', 'test', 'timings_ns']);
}

function printCtCsvRow(curve: string, point: string, test: CtTestResult) {
  const timings = test.t < DEFAULT_MAX_T ? '' : fmtTimingRange(test.aMean, test.bMean, fmtNsRaw);
  printCsvRow([
    test.failed ? 'fail' : 'pass',
    fmtFixed(test.t, 1),
    curve,
    csvPointName(point),
    test.name,
    timings,
  ]);
}

function ctProgress(
  curve: string,
  point: string,
  format: OutputFormat
): NonNullable<CtOptions['progress']> {
  const prefix = `${curve},${csvPointName(point)}`;
  return {
    step: format === 'csv' ? 1 : 5,
    start: (test) => {
      process.stderr.write(`# ${prefix},${test} running: [`);
    },
    tick: () => {
      process.stderr.write('.');
    },
    end: () => {
      process.stderr.write(']\n');
    },
  };
}

function csvPointName(point: string): string {
  if (point === 'BASE*scalar') return 'base_mul';
  if (point === 'RANDOM_POINT*scalar') return 'rand_mul';
  return point;
}

function fmtTimingRange(a: number, b: number, fmt: (value: number) => string): string {
  return `${fmt(Math.min(a, b))}...${fmt(Math.max(a, b))}`;
}

function fmtNsRaw(ns: number): string {
  return fmtFixed(ns, 0);
}

function supportsColor(): boolean {
  if (process.env.CLICOLOR_FORCE !== undefined && process.env.CLICOLOR_FORCE !== '0') return true;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR === '0') return false;
  if (process.env.CLICOLOR === '0') return false;
  return process.stdout.isTTY === true && process.env.TERM !== 'dumb';
}

function outputFormat(): OutputFormat {
  if (process.env.CT_CSV !== undefined && process.env.CT_CSV !== '0') return 'csv';
  return supportsColor() ? 'table' : 'csv';
}

function envDisabled(name: string): boolean {
  const value = process.env[name];
  return value !== undefined && value !== '0' && value.toLowerCase() !== 'false';
}

function progressEnabled(): boolean {
  if (envDisabled('NO_PROGRESS')) return false;
  return true;
}

function sampleCount(): number {
  const value = process.env.SAMPLES;
  if (value === undefined) return DEFAULT_SAMPLES;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count <= 0) throw new Error('invalid SAMPLES');
  return count;
}

function selectedCurves(): Curve[] {
  const value = process.env.CURVES;
  if (value === undefined) return CURVES;
  const names = new Set(
    value.split(',').map((part) => {
      const name = part.trim();
      if (name.length === 0) throw new Error('invalid CURVES');
      return name;
    })
  );
  const selected = CURVES.filter((curve) => names.has(curve.name));
  if (selected.length !== names.size) {
    const known = new Set(CURVES.map((curve) => curve.name));
    const unknown = Array.from(names).filter((name) => !known.has(name));
    throw new Error(`unknown CURVES: ${unknown.join(', ')}`);
  }
  return selected;
}

export function runSecretKeyOperationCt(
  operation: SecretKeyOperationFn,
  field: ScalarFieldLike,
  samples: number,
  opts: CtOptions & { name?: string } = {}
): CtResult {
  const batch = opts.batch ?? DEFAULT_BATCH;
  const maxT = opts.maxT ?? DEFAULT_MAX_T;
  const minNs = opts.minNs ?? DEFAULT_MIN_NS;
  const name = opts.name ?? 'secret-key operation';
  const log = opts.log ?? console.log;
  const order = field.ORDER;
  const mask = (1n << BigInt(field.BITS)) - 1n;
  let sink = 0;

  function randBit(): number {
    return randomBytes(1)[0] & 1;
  }
  function scalarToBytes(scalar: bigint): Bytes {
    if (!(scalar > 0n && scalar < order)) throw new Error('invalid scalar');
    return new Uint8Array(field.toBytes(scalar)) as Bytes;
  }
  function patternScalar(byte: string): bigint {
    const patterned = bytesToNumberBE(hexToBytes(repeated(byte, field.BYTES))) & mask;
    return (patterned % (order - 1n)) + 1n;
  }
  function randomSecretKey(): Bytes {
    const scalar = (bytesToNumberBE(randomBytes(field.BYTES)) % (order - 1n)) + 1n;
    return scalarToBytes(scalar);
  }
  function fixed(name: string, scalar: bigint): Source {
    const key = scalarToBytes(scalar);
    const keys: Bytes[] = [];
    for (let i = 0; i < samples; i++) keys.push(key.slice());
    return { name, keys };
  }
  function randomSource(name: string): Source {
    const keys: Bytes[] = [];
    for (let i = 0; i < samples; i++) keys.push(randomSecretKey());
    return { name, keys };
  }
  function timeOperation(key: Bytes): number {
    const start = process.hrtime.bigint();
    for (let i = 0; i < batch; i++) sink ^= operation(key)[0];
    return Number(process.hrtime.bigint() - start) / batch;
  }
  function measure(source: Source, index: number): number {
    let best = Number.POSITIVE_INFINITY;
    const key = source.keys[index % source.keys.length];
    for (let attempt = 0; attempt < 16; attempt++) {
      const elapsed = timeOperation(key);
      if (elapsed < best) best = elapsed;
      if (elapsed >= minNs) break;
    }
    return best;
  }

  const one = fixed('one', 1n);
  const two = fixed('two', 2n);
  const three = fixed('three', 3n);
  const topBit = fixed('top-bit', highestPowerOf2Below(order));
  const midBit = fixed('mid-bit', highestPowerOf2Below(order) >> 1n);
  const lowBit = fixed('low-bit', 1n << 7n);
  const nHalf = fixed('n-half', order >> 1n);
  const nMinus2 = fixed('n-minus-2', order - 2n);
  const nMinus1 = fixed('n-minus-1', order - 1n);
  const randomValid = randomSource('random-valid');
  const tests: Test[] = [
    { name: 'fixed-vs-random', a: two, b: randomValid },
    { name: 'small-scalars', a: one, b: three },
    { name: 'low-vs-mid-bit', a: lowBit, b: midBit },
    { name: 'mid-vs-top-bit', a: midBit, b: topBit },
    { name: 'sparse-vs-dense', a: two, b: nMinus1 },
    { name: 'near-order-pair', a: nMinus2, b: nMinus1 },
    { name: 'half-vs-near-order', a: nHalf, b: nMinus1 },
    {
      name: 'alternating-complement',
      a: fixed('alternating-55', patternScalar('55')),
      b: fixed('alternating-aa', patternScalar('aa')),
    },
    {
      name: 'nibble-complement',
      a: fixed('nibble-0f', patternScalar('0f')),
      b: fixed('nibble-f0', patternScalar('f0')),
    },
    {
      name: 'byte-pattern-complement',
      a: fixed('pattern-33', patternScalar('33')),
      b: fixed('pattern-cc', patternScalar('cc')),
    },
    { name: 'near-order-vs-random', a: nMinus1, b: randomValid },
  ];

  for (const test of tests) {
    operation(test.a.keys[0]);
    operation(test.b.keys[0]);
  }
  for (let i = 0; i < 24; i++) {
    const test = tests[i % tests.length];
    const source = i & 1 ? test.a : test.b;
    timeOperation(source.keys[i % source.keys.length]);
  }

  log(`# ${name} samples=${samples} batch=${batch} max_t=${fmtNum(maxT)} min_ns=${fmtNum(minNs)}`);

  const results: CtTestResult[] = [];
  for (const test of tests) {
    const a = initStats();
    const b = initStats();
    const progress = opts.progress;
    const progressStartedAt = Date.now();
    let progressShown = false;
    let nextProgress = progress?.step ?? 1;
    const updateProgress = (done: number) => {
      if (!progress) return;
      if (!progressShown) {
        if (done % PROGRESS_ESTIMATE_INTERVAL !== 0) return;
        const elapsed = Date.now() - progressStartedAt;
        const estimated = (elapsed * samples) / done;
        if (estimated <= PROGRESS_MIN_ESTIMATE_MS) return;
        progress.start(test.name);
        progressShown = true;
      }
      while (nextProgress <= 100 && done * 100 >= nextProgress * samples) {
        progress.tick();
        nextProgress += progress.step;
      }
    };
    try {
      for (let i = 0; i < samples; i++) {
        if (randBit()) {
          addSample(a, measure(test.a, i));
          addSample(b, measure(test.b, i));
        } else {
          addSample(b, measure(test.b, i));
          addSample(a, measure(test.a, i));
        }
        updateProgress(i + 1);
      }
    } finally {
      if (progressShown) progress?.end();
    }
    const t = cleanZero(welchT(a, b));
    const delta = cleanZero(a.mean - b.mean);
    const failed = t > maxT;
    const result = {
      name: test.name,
      a: test.a.name,
      b: test.b.name,
      aMean: a.mean,
      bMean: b.mean,
      delta,
      t,
      failed,
    };
    results.push(result);
    opts.onTest?.(result);
    const timings = t < DEFAULT_MAX_T ? '' : fmtTimingRange(a.mean, b.mean, fmtNs);
    const tText = timings ? fmtT(t, failed) : `t=${fmtFixed(t, 1)}`;
    const extra = timings ? ` ${timings}` : '';
    log(`${fmtStatus(failed)} ${test.name.padEnd(24)} ${tText}${extra}`);
  }

  const failed = results.some((result) => result.failed);
  const res = { samples, batch, maxT, minNs, sink, failed, tests: results };
  log(`sink=${sink}`);
  if (failed && opts.throwOnFailure !== false) {
    throw new Error(`${name} timing differs by secret input class`);
  }
  return res;
}

function randomBytes(length: number): Bytes {
  const crypto = globalThis.crypto;
  if (crypto === undefined || typeof crypto.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required');
  }
  const out = new Uint8Array(length);
  for (let offset = 0; offset < out.length; offset += 65_536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65_536, out.length)));
  }
  return out as Bytes;
}

function hexToBytes(hex: string): Bytes {
  if (hex.length % 2 !== 0) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isSafeInteger(byte)) throw new Error('invalid hex');
    out[i] = byte;
  }
  return out as Bytes;
}

function bytesToNumberBE(bytes: Bytes): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function repeated(byte: string, length: number): string {
  let out = '';
  for (let i = 0; i < length; i++) out += byte;
  return out;
}

function highestPowerOf2Below(num: bigint): bigint {
  let bits = 0n;
  for (let value = num - 1n; value > 0n; value >>= 1n) bits++;
  return 1n << (bits - 1n);
}

function initStats(): Stats {
  return { n: 0, mean: 0, m2: 0 };
}

function addSample(stats: Stats, value: number) {
  stats.n++;
  const delta = value - stats.mean;
  stats.mean += delta / stats.n;
  stats.m2 += delta * (value - stats.mean);
}

function variance(stats: Stats): number {
  return stats.n > 1 ? stats.m2 / (stats.n - 1) : 0;
}

function welchT(a: Stats, b: Stats): number {
  const va = variance(a) / a.n;
  const vb = variance(b) / b.n;
  const denom = Math.sqrt(va + vb);
  return denom === 0 ? 0 : Math.abs(a.mean - b.mean) / denom;
}
