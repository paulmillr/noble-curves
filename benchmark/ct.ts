/**
 * Constant-time leakage harness for secret-scalar operations (dudect-style Welch t-test).
 *
 * For every curve it times secret-scalar multiplication (base point ≈ `getPublicKey`, random
 * point ≈ ECDH `getSharedSecret` core; X25519/X448 time the actual `getSharedSecret` ladder)
 * across classes of adversarial secret inputs and compares class timings with Welch's t.
 *
 * Metric taxonomy — which |t| matters, most-to-least meaningful:
 *   - lz@Z (VERDICT)   : leading-zero scan. Populations of scalars with 0..Z forced leading zero
 *                        bits; how timing scales with the zero count is the exact quantity an
 *                        HNP/lattice (Minerva-style) attack consumes. For X25519/X448 the scan
 *                        should read flat BECAUSE clamping fixes the top bit — this verifies it.
 *   - struct (VERDICT) : max |t| over full-size, structurally-varied (nonce-like) classes
 *                        (mid/top bit, alternating/nibble/byte patterns).
 *   - degen            : classes involving degenerate scalars (1, 2, 3, n−1, n−2) that a uniform
 *                        secret hits with probability ~2^-BITS. Reported, but QUARANTINED from
 *                        the verdict — they detect shortcuts, not exploitable leaks.
 *   - controls         : fixed-vs-fixed (same scalar both classes — nonzero |t| means the rig
 *                        itself is biased) and random-vs-random (noise floor; mean-insensitive).
 *
 * Verdict per path: leak = (lz fails) OR (any struct class fails), where "fails" requires BOTH
 * |t| > 4.5 AND |δ| above a small effect floor (0.1% of op time) — so huge-n runs don't flag
 * irrelevant sub-noise deltas. Second-order |t| (on squared residuals, TVLA-style) is reported to
 * surface secret-dependent VARIANCE, advisory only.
 *
 * Positive control: each curve also runs its *variable-time* `multiplyUnsafe` through the
 * leading-zero probe and REQUIRES it to leak — a harness that has never demonstrated it can catch
 * a leak proves nothing by passing. Exception: secp256k1, whose multiplyUnsafe GLV-splits the
 * scalar into two ~128-bit halves, decorrelating leading zeros from wNAF cost (measured |t|≈0);
 * it is skipped with a note, and the other curves establish this rig's detection power.
 *
 * Power statement: every battery prints its median minimum-detectable effect
 * (MDE = 4.5·se(δ)). A pass means "no mean timing leak larger than the MDE was observed for the
 * tested classes on this machine", nothing stronger. Raise SAMPLES to shrink the MDE
 * (README numbers are quoted at SAMPLES=1000).
 *
 * Scope / limitations:
 *   - Wall-clock only. Cache-timing and branch-predictor channels (e.g. secret-indexed table
 *     lookups) are invisible to this harness by construction.
 *   - Algorithmic constant-timeness only — JS JIT/GC preclude true constant time (see README).
 *   - Known limitation (documented in README): on cofactored Edwards curves (ed25519, ed448),
 *     non-base-point multiplication is not blinded; its RANDOM_POINT row is expected to leak and
 *     is marked `known` instead of failing the run. It doubles as a second positive control.
 *
 * Run:  node benchmark/ct.ts
 * Env:  SAMPLES, CURVES (e.g. p256,x25519), MAXZ, CT_CSV, NO_PROGRESS
 */
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { ed25519, x25519 } from '../src/ed25519.ts';
import { ed448, x448 } from '../src/ed448.ts';
import { p256, p384, p521 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';

type Bytes = Uint8Array<ArrayBuffer>;
export type SecretKeyOperationFn = (secretKey: Bytes) => Bytes;
export type ScalarFieldLike = {
  ORDER: bigint;
  BITS: number;
  BYTES: number;
  toBytes: (num: bigint) => Uint8Array;
  fromBytes: (bytes: Uint8Array) => bigint;
};
export type TestKind = 'control' | 'degen' | 'struct';
export type Progress = {
  step: number;
  start: (test: string) => void;
  tick: () => void;
  end: () => void;
};
export type CtOptions = {
  batch?: number;
  maxT?: number;
  minNs?: number;
  minDeltaNs?: number;
  log?: (message: string) => void;
  onTest?: (result: CtTestResult) => void;
  progress?: Progress;
  throwOnFailure?: boolean;
};
export type CtTestResult = {
  name: string;
  kind: TestKind;
  a: string;
  b: string;
  aMean: number;
  bMean: number;
  delta: number;
  t: number;
  t2: number;
  mdeNs: number;
  deltaFloorNs: number;
  failed: boolean;
};
export type CtResult = {
  samples: number;
  batch: number;
  maxT: number;
  minNs: number;
  sink: number;
  failed: boolean; // struct verdict only; degens and controls are quarantined
  biased: boolean; // a control class tripped — the measurement rig itself is suspect
  structT: number;
  structT2: number;
  degenT: number;
  controlT: number;
  mdeNs: number; // median per-test minimum detectable effect
  tests: CtTestResult[];
};
export type LzPoint = { z: number; mean: number; t: number; delta: number };
type Source = {
  name: string;
  keys: Bytes[];
};
type Test = {
  name: string;
  kind: TestKind;
  a: Source;
  b: Source;
};
type ArrStats = { n: number; mean: number; varc: number };
type PointLike = {
  multiply: (scalar: bigint) => PointLike;
  multiplyUnsafe: (scalar: bigint) => PointLike;
  toBytes: () => Uint8Array;
  equals: (other: any) => boolean;
};
type FieldCurve = {
  getPublicKey: (secretKey: Uint8Array, isCompressed?: boolean) => Uint8Array;
  Point: {
    BASE: PointLike;
    Fn: ScalarFieldLike;
    fromBytes: (bytes: Uint8Array) => PointLike;
  };
  utils: { randomSecretKey: () => Uint8Array };
};
type MontgomeryLike = {
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
  getSharedSecret: (secretKeyA: Uint8Array, publicKeyB: Uint8Array) => Uint8Array;
  utils: { randomSecretKey: () => Uint8Array };
};
type PathSpec = {
  label: string; // human name in table output
  csv: string; // short csv id
  op: SecretKeyOperationFn;
  knownLeak?: string; // documented, expected leak: reported but not a failure
};
type CurveSpec = {
  name: string;
  field: ScalarFieldLike;
  paths: PathSpec[];
  positiveControl?: SecretKeyOperationFn;
  positiveControlNote?: string; // reason when positive control is skipped
};
type SummaryRow = {
  curve: string;
  path: string;
  lzT: number;
  lzDelta: number;
  lzFail: boolean;
  structT: number;
  structT2: number;
  degenT: number;
  controlT: number;
  biased: boolean;
  mdeNs: number;
  meanNs: number;
  knownLeak?: string;
  leak: boolean;
};
type PcRow = {
  curve: string;
  t: number;
  delta: number;
  detected: boolean;
  skipped?: string;
};
export type OutputFormat = 'table' | 'csv';

const DEFAULT_SAMPLES = 100;
const DEFAULT_BATCH = 1; // single-shot for slow point ops; micro-ops (ct-inv) pass batch>1
export const DEFAULT_MAX_T = 4.5;
const DEFAULT_MIN_NS = 1_000;
const DEFAULT_MAXZ = 8;
// Effect floor: a class only "fails" if |δ| also exceeds this fraction of the op time, so a huge-n
// run cannot flag deltas far below anything measurable by an attacker.
export const REL_DELTA_FLOOR = 0.001;
// Positive control compares z=0 vs z=PC_MAXZ leading zeros: the wide gap makes the wNAF leak
// unmissable (|t| ≫ 4.5) even at small SAMPLES.
const PC_MAXZ = 16;
const PC_MIN_SAMPLES = 150;
const PROGRESS_ESTIMATE_INTERVAL = 20;
const PROGRESS_MIN_ESTIMATE_MS = 20_000;
let LZ_SINK = 0; // declared before main() runs; prevents dead-code elimination of the timed op

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();

function fieldCurveSpec(name: string, curve: FieldCurve, edwards: boolean): CurveSpec {
  const Fn = curve.Point.Fn;
  const peerSecret = curve.utils.randomSecretKey();
  const randomPoint = curve.Point.fromBytes(curve.getPublicKey(peerSecret, true));
  if (randomPoint.equals(curve.Point.BASE)) throw new Error(`${name}: random point equals BASE`);
  const mulOp =
    (point: PointLike): SecretKeyOperationFn =>
    (scalarBytes) =>
      point.multiply(Fn.fromBytes(scalarBytes)).toBytes() as Bytes;
  const paths: PathSpec[] = [
    { label: 'BASE*scalar', csv: 'base_mul', op: mulOp(curve.Point.BASE) },
    {
      label: 'RANDOM_POINT*scalar',
      csv: 'rand_mul',
      op: mulOp(randomPoint),
      knownLeak: edwards
        ? 'unblinded non-base Edwards multiply (README known limitation)'
        : undefined,
    },
  ];
  const spec: CurveSpec = { name, field: Fn, paths };
  if (name === 'secp256k1') {
    spec.positiveControlNote =
      'skipped: GLV endomorphism decorrelates scalar bit-length from wNAF cost (measured |t|~0)';
  } else {
    spec.positiveControl = (scalarBytes) =>
      randomPoint.multiplyUnsafe(Fn.fromBytes(scalarBytes)).toBytes() as Bytes;
  }
  return spec;
}

// X25519/X448 secret keys are raw bytes (clamped internally), not field elements. Model the
// scalar domain as [1, 2^BITS-1] with little-endian encoding so the harness can build classes.
function montgomeryFieldLike(bits: number, bytes: number): ScalarFieldLike {
  return {
    ORDER: (1n << BigInt(bits)) - 1n,
    BITS: bits,
    BYTES: bytes,
    toBytes: (num: bigint): Bytes => {
      const out = new Uint8Array(bytes);
      let value = num;
      for (let i = 0; i < bytes; i++) {
        out[i] = Number(value & 0xffn);
        value >>= 8n;
      }
      return out as Bytes;
    },
    fromBytes: (b: Uint8Array): bigint => {
      let value = 0n;
      for (let i = b.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(b[i]);
      return value;
    },
  };
}

function montgomerySpec(name: string, dh: MontgomeryLike, bits: number, bytes: number): CurveSpec {
  const peerPublic = dh.getPublicKey(dh.utils.randomSecretKey());
  return {
    name,
    field: montgomeryFieldLike(bits, bytes),
    paths: [
      {
        label: 'LADDER*scalar',
        csv: 'ladder_mul',
        op: (secretKey) => dh.getSharedSecret(secretKey, peerPublic) as Bytes,
      },
    ],
    positiveControlNote: 'skipped: no variable-time ladder variant exists to probe',
  };
}

function buildSpecs(): CurveSpec[] {
  return [
    fieldCurveSpec('p256', p256 as FieldCurve, false),
    fieldCurveSpec('p384', p384 as FieldCurve, false),
    fieldCurveSpec('p521', p521 as FieldCurve, false),
    fieldCurveSpec('secp256k1', secp256k1 as FieldCurve, false),
    fieldCurveSpec('ed25519', ed25519 as unknown as FieldCurve, true),
    fieldCurveSpec('ed448', ed448 as unknown as FieldCurve, true),
    montgomerySpec('x25519', x25519 as MontgomeryLike, 255, 32),
    montgomerySpec('x448', x448 as MontgomeryLike, 448, 56),
  ];
}

function main() {
  const samples = sampleCount();
  const maxZ = maxZCount();
  const format = outputFormat();
  const sysInfo =
    `node=${process.version} ${os.platform()}/${os.arch()} ` +
    `cpu="${os.cpus()[0]?.model ?? 'unknown'}" samples=${samples}`;
  if (format === 'csv') {
    process.stderr.write(`# ${sysInfo}\n`);
    printCtCsvHeader();
  } else {
    console.log(`# ${sysInfo}`);
  }
  const rows: SummaryRow[] = [];
  const pcs: PcRow[] = [];
  for (const spec of selectByEnv(buildSpecs())) {
    for (const path of spec.paths) {
      const progress = progressEnabled() ? ctProgress(spec.name, path.csv, format) : undefined;
      const result = runSecretKeyOperationCt(path.op, spec.field, samples, {
        name: `${spec.name} ${path.label}`,
        log: format === 'csv' ? () => {} : console.log,
        onTest: format === 'csv' ? (test) => printCtCsvRow(spec.name, path.csv, test) : undefined,
        progress,
        throwOnFailure: false,
      });
      const lz = leadingZeroScan(path.op, spec.field, samples, DEFAULT_BATCH, maxZ, progress);
      printLzRows(lz, format, spec.name, path.csv);
      const lzFail = lzScanFailed(lz, DEFAULT_MAX_T);
      const lzTop = lz[lz.length - 1];
      rows.push({
        curve: spec.name,
        path: path.csv,
        lzT: lzTop.t,
        lzDelta: lzTop.delta,
        lzFail,
        structT: result.structT,
        structT2: result.structT2,
        degenT: result.degenT,
        controlT: result.controlT,
        biased: result.biased,
        mdeNs: result.mdeNs,
        meanNs: meanNs(result),
        knownLeak: path.knownLeak,
        leak: lzFail || result.failed,
      });
    }
    if (spec.positiveControl) {
      const pcSamples = Math.max(PC_MIN_SAMPLES, samples);
      const progress = progressEnabled() ? ctProgress(spec.name, 'unsafe', format) : undefined;
      const lz = leadingZeroScan(
        spec.positiveControl,
        spec.field,
        pcSamples,
        DEFAULT_BATCH,
        PC_MAXZ,
        progress,
        [0, PC_MAXZ]
      );
      const top = lz[lz.length - 1];
      const detected = top.t > DEFAULT_MAX_T;
      pcs.push({ curve: spec.name, t: top.t, delta: top.delta, detected });
      if (format === 'csv') {
        printCsvRow([
          detected ? 'pass' : 'fail',
          'positive-control',
          fmtFixed(top.t, 1),
          '',
          fmtFixed(top.delta, 0),
          '',
          spec.name,
          'unsafe',
          `unsafe-lz@${PC_MAXZ}`,
          '',
        ]);
      } else {
        console.log(
          `${fmtStatus(!detected)} ${`unsafe-lz@${PC_MAXZ}`.padEnd(24)} ${pad('[pctrl]', 10)}` +
            `t=${fmtFixed(top.t, 1).padEnd(7)} δ=${fmtNsSigned(top.delta)} ` +
            (detected
              ? 'leak detected (harness has power)'
              : 'NO LEAK DETECTED — harness power lost')
        );
      }
    } else {
      pcs.push({
        curve: spec.name,
        t: 0,
        delta: 0,
        detected: false,
        skipped: spec.positiveControlNote,
      });
    }
  }

  const badLeak = rows.some((r) => r.leak && r.knownLeak === undefined);
  const bias = rows.some((r) => r.biased);
  const pcMiss = pcs.some((pc) => pc.skipped === undefined && !pc.detected);
  if (badLeak || bias || pcMiss) process.exitCode = 1;
  if (format === 'csv') return;

  console.log('\n# summary — verdict = lz + struct (δ-floored); degen/ctrl are informational');
  console.log(
    `${pad('', 2)} ${pad('curve', 10)} ${pad('path', 11)} ${pad(`lz@${maxZ}`, 8)} ${pad('lz-δ', 9)} ` +
      `${pad('struct', 7)} ${pad('t2', 6)} ${pad('degen', 6)} ${pad('ctrl', 5)} ${pad('mde', 8)} mean/op`
  );
  for (const row of rows) {
    const known = row.knownLeak !== undefined;
    const status = row.leak
      ? known
        ? fmtMark('!', 'yellow')
        : fmtMark('✕', 'red')
      : fmtMark('✓', 'green');
    console.log(
      `${status}  ${pad(row.curve, 10)} ${pad(row.path, 11)} ${pad(fmtFixed(row.lzT, 1), 8)} ${pad(fmtNsSigned(row.lzDelta), 9)} ` +
        `${pad(fmtFixed(row.structT, 1), 7)} ${pad(fmtFixed(row.structT2, 1), 6)} ${pad(fmtFixed(row.degenT, 1), 6)} ` +
        `${pad(fmtFixed(row.controlT, 1), 5)} ${pad(fmtNs2(row.mdeNs), 8)} ${fmtNs(row.meanNs)}` +
        (known && row.leak ? '  known-leak (see docheader)' : '') +
        (row.biased ? '  RIG-BIASED (fixed-vs-fixed tripped)' : '')
    );
  }
  console.log('\n# positive control — variable-time multiplyUnsafe MUST leak on the lz probe');
  for (const pc of pcs) {
    if (pc.skipped !== undefined) {
      console.log(`${fmtMark('-', 'yellow')}  ${pad(pc.curve, 10)} ${pc.skipped}`);
    } else {
      console.log(
        `${fmtStatus(!pc.detected)}  ${pad(pc.curve, 10)} unsafe-lz@${PC_MAXZ} t=${fmtFixed(pc.t, 1)} ` +
          `δ=${fmtNsSigned(pc.delta)} ${pc.detected ? 'detected' : 'MISSED — negative results above are not trustworthy'}`
      );
    }
  }
  const medianMde = median(rows.map((r) => r.mdeNs));
  console.log(
    `\n# power: median MDE ≈ ${fmtNs2(medianMde)} at n=${samples} — this run cannot rule out ` +
      `mean leaks smaller than that; raise SAMPLES to shrink it (README quotes SAMPLES=1000).`
  );
}

/** Print one row per z class of a leading-zero scan (table or csv). */
export function printLzRows(lz: LzPoint[], format: OutputFormat, curve: string, pathCsv: string) {
  const floor = lzDeltaFloorNs(lz);
  for (const p of lz) {
    const failed = p.t > DEFAULT_MAX_T && Math.abs(p.delta) >= floor;
    if (format === 'csv') {
      printCsvRow([
        failed ? 'fail' : 'pass',
        'lz',
        fmtFixed(p.t, 1),
        '',
        fmtFixed(p.delta, 0),
        '',
        curve,
        pathCsv,
        `lz@${p.z}`,
        '',
      ]);
    } else {
      console.log(
        `${fmtStatus(failed)} ${`lz@${p.z}`.padEnd(24)} ${pad('[lz]', 10)}` +
          `${fmtT(p.t)} δ=${fmtNsSigned(p.delta)}`
      );
    }
  }
}

export function meanNs(result: CtResult): number {
  let sum = 0;
  let count = 0;
  for (const test of result.tests) {
    sum += test.aMean + test.bMean;
    count += 2;
  }
  return count ? sum / count : 0;
}

// ---------------------------------------------------------------------------
// Core battery: adversarial secret-input classes, Welch t per class pair.
// ---------------------------------------------------------------------------
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
    // 8 extra random bytes make the modulo bias negligible (< 2^-64)
    return scalarToBytes(randBig(order - 1n) + 1n);
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
    for (let i = 0; i < batch; i++) sink ^= foldBytes(operation(key));
    return Number(process.hrtime.bigint() - start) / batch;
  }
  function measure(key: Bytes): number {
    let best = Number.POSITIVE_INFINITY;
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
    // controls: calibrate the rig itself, expected |t|≈0
    {
      name: 'fixed-vs-fixed',
      kind: 'control',
      a: fixed('n-half-a', order >> 1n),
      b: fixed('n-half-b', order >> 1n),
    },
    {
      name: 'random-vs-random',
      kind: 'control',
      a: randomSource('random-a'),
      b: randomSource('random-b'),
    },
    // degenerate scalars: shortcut detectors, quarantined from the verdict
    { name: 'fixed-vs-random', kind: 'degen', a: two, b: randomValid },
    { name: 'small-scalars', kind: 'degen', a: one, b: three },
    { name: 'low-vs-mid-bit', kind: 'degen', a: lowBit, b: midBit },
    { name: 'sparse-vs-dense', kind: 'degen', a: two, b: nMinus1 },
    { name: 'near-order-pair', kind: 'degen', a: nMinus2, b: nMinus1 },
    { name: 'half-vs-near-order', kind: 'degen', a: nHalf, b: nMinus1 },
    { name: 'near-order-vs-random', kind: 'degen', a: nMinus1, b: randomValid },
    // structural: full-size, nonce-like inputs — leaks here are the exploitable kind
    { name: 'mid-vs-top-bit', kind: 'struct', a: midBit, b: topBit },
    {
      name: 'alternating-complement',
      kind: 'struct',
      a: fixed('alternating-55', patternScalar('55')),
      b: fixed('alternating-aa', patternScalar('aa')),
    },
    {
      name: 'nibble-complement',
      kind: 'struct',
      a: fixed('nibble-0f', patternScalar('0f')),
      b: fixed('nibble-f0', patternScalar('f0')),
    },
    {
      name: 'byte-pattern-complement',
      kind: 'struct',
      a: fixed('pattern-33', patternScalar('33')),
      b: fixed('pattern-cc', patternScalar('cc')),
    },
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

  log(
    `# ${name} samples=${samples} batch=${batch} max_t=${fmtNum(maxT)} min_ns=${fmtNum(minNs)} ` +
      `delta_floor=${opts.minDeltaNs !== undefined ? `${fmtNum(opts.minDeltaNs)}ns` : `${REL_DELTA_FLOOR * 100}%`}`
  );

  const results: CtTestResult[] = [];
  for (const test of tests) {
    // Classes a/b are interleaved pairwise in random order per round, so slow drift
    // (CPU frequency, GC pressure) hits both classes of a comparison equally.
    const aTimings: number[] = [];
    const bTimings: number[] = [];
    const tracker = progressTracker(opts.progress, test.name, samples);
    try {
      for (let i = 0; i < samples; i++) {
        const keyA = test.a.keys[i % test.a.keys.length];
        const keyB = test.b.keys[i % test.b.keys.length];
        if (randBit()) {
          aTimings.push(measure(keyA));
          bTimings.push(measure(keyB));
        } else {
          bTimings.push(measure(keyB));
          aTimings.push(measure(keyA));
        }
        tracker.update(i + 1);
      }
    } finally {
      tracker.end();
    }
    const a = arrStats(aTimings);
    const b = arrStats(bTimings);
    const t = cleanZero(welchT(a, b));
    const t2 = cleanZero(secondOrderT(aTimings, bTimings, a, b));
    const delta = cleanZero(a.mean - b.mean);
    const deltaFloorNs = Math.max(opts.minDeltaNs ?? 0, (REL_DELTA_FLOOR * (a.mean + b.mean)) / 2);
    const mdeNs = maxT * Math.sqrt(a.varc / a.n + b.varc / b.n);
    const failed = t > maxT && Math.abs(delta) >= deltaFloorNs;
    const result: CtTestResult = {
      name: test.name,
      kind: test.kind,
      a: test.a.name,
      b: test.b.name,
      aMean: a.mean,
      bMean: b.mean,
      delta,
      t,
      t2,
      mdeNs,
      deltaFloorNs,
      failed,
    };
    results.push(result);
    opts.onTest?.(result);
    log(
      `${fmtStatus(failed)} ${test.name.padEnd(24)} ${pad(`[${test.kind}]`, 10)}` +
        `${fmtT(t)} t2=${fmtFixed(t2, 1).padEnd(6)} δ=${fmtNsSigned(delta)}`
    );
  }

  const maxTOf = (kind: TestKind, second = false) =>
    results.reduce((max, r) => (r.kind === kind ? Math.max(max, second ? r.t2 : r.t) : max), 0);
  const structT = maxTOf('struct');
  const structT2 = maxTOf('struct', true);
  const degenT = maxTOf('degen');
  const controlT = maxTOf('control');
  const biased = results.some((r) => r.kind === 'control' && r.failed);
  const failed = results.some((r) => r.kind === 'struct' && r.failed);
  const mdeNs = median(results.map((r) => r.mdeNs));
  const res: CtResult = {
    samples,
    batch,
    maxT,
    minNs,
    sink,
    failed,
    biased,
    structT,
    structT2,
    degenT,
    controlT,
    mdeNs,
    tests: results,
  };
  log(`# mde≈${fmtNs2(mdeNs)} (median; smaller mean leaks are invisible at this n) sink=${sink}`);
  if (biased) log(`${fmtMark('✕', 'red')} controls tripped: rig is biased, all verdicts suspect`);
  if (structT2 > maxT)
    log(
      `${fmtMark('!', 'yellow')} second-order |t|=${fmtFixed(structT2, 1)} — possible variance leak (advisory)`
    );
  if (failed && opts.throwOnFailure !== false) {
    throw new Error(`${name} timing differs by secret input class`);
  }
  return res;
}

/**
 * Leading-zero scan: the most direct measure of the exploitable (HNP / Minerva) quantity.
 * Builds one population per z (default 0..maxZ) where every scalar has EXACTLY z leading zero
 * bits (bit-length = bitLen(n) - z), and measures how timing scales with z. All z classes are
 * timed interleaved (order reshuffled each round, Fisher-Yates) to cancel CPU-frequency drift,
 * then each is compared to the z=0 baseline via Welch's t. A δ growing with z is the exact
 * quantity a lattice attack consumes; a flat δ leaks nothing about the scalar's top bits.
 * Pass `zs` to probe specific zero-counts only (element 0 must be the 0 baseline).
 */
export function leadingZeroScan(
  op: SecretKeyOperationFn,
  Fn: ScalarFieldLike,
  samples: number,
  batch: number,
  maxZ: number,
  progress?: Progress,
  zs?: number[]
): LzPoint[] {
  // exact bit length of the order (do not trust a possibly-padded Fn.BITS)
  let nb = 0n;
  for (let v = Fn.ORDER; v > 0n; v >>= 1n) nb++;
  const keyFor = (z: number): Bytes => {
    let val: bigint;
    if (z === 0) {
      const lo = 1n << (nb - 1n); // [2^(nb-1), n): top bit set => 0 leading zeros
      val = lo + randBig(Fn.ORDER - lo);
    } else {
      const base = 1n << (nb - 1n - BigInt(z)); // [2^(nb-1-z), 2^(nb-z)): exactly z leading zeros
      val = base + randBig(base);
    }
    return Fn.toBytes(val) as Bytes;
  };
  const zList = zs ?? Array.from({ length: maxZ + 1 }, (_, z) => z);
  if (zList[0] !== 0) throw new Error('leadingZeroScan: zs[0] must be the 0 baseline');
  const classes: { z: number; keys: Bytes[] }[] = zList.map((z) => {
    const keys: Bytes[] = [];
    for (let i = 0; i < samples; i++) keys.push(keyFor(z));
    return { z, keys };
  });
  for (let i = 0; i < 50; i++) timeOp(op, classes[0].keys[i % samples], batch); // warmup
  const timings: number[][] = classes.map(() => []);
  const order = classes.map((_, i) => i);
  const tracker = progressTracker(progress, 'leading-zero-scan', samples);
  try {
    for (let i = 0; i < samples; i++) {
      for (let j = order.length - 1; j > 0; j--) {
        // reshuffle class order each round (Fisher-Yates) to avoid systematic ordering bias
        const r = randomBytes(1)[0] % (j + 1);
        [order[j], order[r]] = [order[r], order[j]];
      }
      for (const idx of order) timings[idx].push(timeOp(op, classes[idx].keys[i], batch));
      tracker.update(i + 1);
    }
  } finally {
    tracker.end();
  }
  const stats = timings.map(arrStats);
  return classes.map((c, idx) => ({
    z: c.z,
    mean: stats[idx].mean,
    t: cleanZero(welchT(stats[idx], stats[0])),
    delta: cleanZero(stats[idx].mean - stats[0].mean),
  }));
}

export function lzDeltaFloorNs(lz: LzPoint[], minDeltaNs?: number): number {
  return Math.max(minDeltaNs ?? 0, REL_DELTA_FLOOR * lz[0].mean);
}

/**
 * Verdict for a leading-zero scan. Fails when the top-z class leaks (a monotone bit-length leak
 * is maximal there), or when >= 2 z classes leak (persistent mid-scan signal) — one noisy class
 * alone never fails. Each class must clear both |t| > maxT and the |δ| effect floor.
 */
export function lzScanFailed(lz: LzPoint[], maxT: number, minDeltaNs?: number): boolean {
  const floor = lzDeltaFloorNs(lz, minDeltaNs);
  const leaks = lz.filter((p) => p.z > 0 && p.t > maxT && Math.abs(p.delta) >= floor);
  return leaks.some((p) => p.z === lz[lz.length - 1].z) || leaks.length >= 2;
}

// best-of timing of one operation over `batch` repeats of the same key
export function timeOp(op: SecretKeyOperationFn, key: Bytes, batch: number): number {
  let best = Number.POSITIVE_INFINITY;
  for (let attempt = 0; attempt < 8; attempt++) {
    const t0 = process.hrtime.bigint();
    for (let j = 0; j < batch; j++) LZ_SINK ^= foldBytes(op(key));
    const elapsed = Number(process.hrtime.bigint() - t0) / batch;
    if (elapsed < best) best = elapsed;
    if (elapsed >= 1000) break;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------
function arrStats(xs: number[]): ArrStats {
  let mean = 0;
  for (const x of xs) mean += x;
  mean /= xs.length;
  let m2 = 0;
  for (const x of xs) m2 += (x - mean) ** 2;
  return { n: xs.length, mean, varc: xs.length > 1 ? m2 / (xs.length - 1) : 0 };
}

export function welchT(a: ArrStats, b: ArrStats): number {
  const denom = Math.sqrt(a.varc / a.n + b.varc / b.n);
  return denom === 0 ? 0 : Math.abs(a.mean - b.mean) / denom;
}

// Welch t over squared residuals: catches secret-dependent VARIANCE (second-order, TVLA-style),
// which a means-only test reads as ~0.
function secondOrderT(a: number[], b: number[], sa: ArrStats, sb: ArrStats): number {
  const ra = a.map((x) => (x - sa.mean) ** 2);
  const rb = b.map((x) => (x - sb.mean) ** 2);
  return welchT(arrStats(ra), arrStats(rb));
}

function median(xs: number[]): number {
  const sorted = [...xs].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

// ---------------------------------------------------------------------------
// Randomness / bytes
// ---------------------------------------------------------------------------
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

/** Uniform random bigint in [0, m); 8 extra random bytes make the modulo bias negligible. */
export function randBig(m: bigint): bigint {
  let bits = 0n;
  for (let v = m; v > 0n; v >>= 1n) bits++;
  const bytes = randomBytes(Number((bits + 7n) / 8n) + 8);
  return bytesToNumberBE(bytes) % m;
}

function foldBytes(bytes: Uint8Array): number {
  let folded = 0;
  for (let i = 0; i < bytes.length; i++) folded ^= bytes[i];
  return folded;
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

// ---------------------------------------------------------------------------
// Formatting / env plumbing (shared with ct-inv.ts)
// ---------------------------------------------------------------------------
export function fmtNs(ns: number): string {
  return `${fmtFixed(ns / 1000, 0)}us`;
}

/** µs with 2 decimals — MDE and lz-δ are often sub-µs */
export function fmtNs2(ns: number): string {
  return `${fmtFixed(cleanZero(ns) / 1000, 2)}us`;
}

export function fmtNsSigned(ns: number): string {
  const clean = cleanZero(ns);
  return `${clean >= 0 ? '+' : '-'}${fmtFixed(Math.abs(clean) / 1000, 2)}us`;
}

export function pad(value: string, length: number): string {
  return value.padEnd(length);
}

export function fmtMark(status: string, color: 'red' | 'green' | 'yellow'): string {
  if (!supportsColor()) return status;
  const code = color === 'red' ? 31 : color === 'green' ? 32 : 33;
  return `\x1b[${code}m${status}\x1b[0m`;
}

export function fmtStatus(failed: boolean): string {
  return fmtMark(failed ? '✕' : '✓', failed ? 'red' : 'green');
}

export function fmtT(t: number): string {
  return fmtTColor(t, `t=${fmtFixed(t, 1).padEnd(7)}`);
}

export function fmtTColor(t: number, value: string): string {
  if (!supportsColor()) return value;
  if (t >= 10) return `\x1b[31m${value}\x1b[0m`;
  if (t >= DEFAULT_MAX_T) return `\x1b[33m${value}\x1b[0m`;
  return value;
}

export function fmtFixed(num: number, digits: number): string {
  const value = num.toFixed(digits);
  return Object.is(Number(value), -0) ? (0).toFixed(digits) : value;
}

export function fmtNum(num: number): string {
  return String(cleanZero(num));
}

export function fmtNsRaw(ns: number): string {
  return fmtFixed(ns, 0);
}

export function cleanZero(num: number): number {
  return Object.is(num, -0) ? 0 : num;
}

export function fmtTimingRange(a: number, b: number, fmt: (value: number) => string): string {
  return `${fmt(Math.min(a, b))}...${fmt(Math.max(a, b))}`;
}

function csvCell(value: unknown): string {
  const cell = String(value ?? '');
  return /[",\r\n]/.test(cell) ? `"${cell.replaceAll('"', '""')}"` : cell;
}

export function printCsvRow(values: unknown[]) {
  console.log(values.map(csvCell).join(','));
}

function printCtCsvHeader() {
  printCsvRow([
    'status',
    'kind',
    't',
    't2',
    'delta_ns',
    'mde_ns',
    'curve',
    'point',
    'test',
    'timings_ns',
  ]);
}

function printCtCsvRow(curve: string, point: string, test: CtTestResult) {
  const timings = test.t < DEFAULT_MAX_T ? '' : fmtTimingRange(test.aMean, test.bMean, fmtNsRaw);
  printCsvRow([
    test.failed ? 'fail' : 'pass',
    test.kind,
    fmtFixed(test.t, 1),
    fmtFixed(test.t2, 1),
    fmtFixed(test.delta, 0),
    fmtFixed(test.mdeNs, 0),
    curve,
    point,
    test.name,
    timings,
  ]);
}

export function supportsColor(): boolean {
  if (process.env.CLICOLOR_FORCE !== undefined && process.env.CLICOLOR_FORCE !== '0') return true;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR === '0') return false;
  if (process.env.CLICOLOR === '0') return false;
  return process.stdout.isTTY === true && process.env.TERM !== 'dumb';
}

export function outputFormat(): OutputFormat {
  if (process.env.CT_CSV !== undefined && process.env.CT_CSV !== '0') return 'csv';
  return supportsColor() ? 'table' : 'csv';
}

function envDisabled(name: string): boolean {
  const value = process.env[name];
  return value !== undefined && value !== '0' && value.toLowerCase() !== 'false';
}

export function progressEnabled(): boolean {
  if (envDisabled('NO_PROGRESS')) return false;
  return true;
}

export function ctProgress(prefix1: string, prefix2: string, format: OutputFormat): Progress {
  const prefix = `${prefix1},${prefix2}`;
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

export function progressTracker(progress: Progress | undefined, test: string, samples: number) {
  const progressStartedAt = Date.now();
  let progressShown = false;
  let nextProgress = progress?.step ?? 1;
  return {
    update(done: number) {
      if (!progress) return;
      if (!progressShown) {
        if (done % PROGRESS_ESTIMATE_INTERVAL !== 0) return;
        const elapsed = Date.now() - progressStartedAt;
        const estimated = (elapsed * samples) / done;
        if (estimated <= PROGRESS_MIN_ESTIMATE_MS) return;
        progress.start(test);
        progressShown = true;
      }
      while (nextProgress <= 100 && done * 100 >= nextProgress * samples) {
        progress.tick();
        nextProgress += progress.step;
      }
    },
    end() {
      if (progressShown) progress?.end();
    },
  };
}

export function sampleCount(defaultSamples = DEFAULT_SAMPLES): number {
  const value = process.env.SAMPLES;
  if (value === undefined) return defaultSamples;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count <= 0) throw new Error('invalid SAMPLES');
  return count;
}

export function maxZCount(): number {
  const value = process.env.MAXZ;
  if (value === undefined) return DEFAULT_MAXZ;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('invalid MAXZ');
  return count;
}

export function selectByEnv<T extends { name: string }>(all: T[]): T[] {
  const value = process.env.CURVES;
  if (value === undefined) return all;
  const names = new Set(
    value.split(',').map((part) => {
      const name = part.trim();
      if (name.length === 0) throw new Error('invalid CURVES');
      return name;
    })
  );
  const selected = all.filter((item) => names.has(item.name));
  if (selected.length !== names.size) {
    const known = new Set(all.map((item) => item.name));
    const unknown = Array.from(names).filter((name) => !known.has(name));
    throw new Error(`unknown CURVES: ${unknown.join(', ')}`);
  }
  return selected;
}
