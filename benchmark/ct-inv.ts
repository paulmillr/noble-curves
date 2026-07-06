/**
 * Constant-time leakage test for the ECDSA nonce inversion `k⁻¹ mod n`.
 *
 * Reuses the dudect-style Welch t-test harness from ./ct.ts, but the measured secret-key
 * operation is the modular inverse instead of scalar multiplication. For each curve it runs the
 * same battery of secret-input classes and reports |t| (leak if > 4.5).
 *
 * Compares the two inverse implementations used for the secret nonce:
 *   - euclid  invert()   : extended Euclidean; loop count depends on k
 *   - fermat  invertCt() : a^(n-2), control flow fixed by public exponent
 *
 * Which |t| matters (most-to-least meaningful):
 *   - lz@Z (VERDICT) : leading-zero scan. Populations of nonces with 0..Z forced leading zero
 *                  bits; reports how k^-1 timing scales with the zero count. This is the exact
 *                  quantity a Hidden-Number-Problem lattice attack (Minerva) consumes, so it is
 *                  the sharpest, most directly exploitable probe.
 *   - structural : max |t| over full-size, structurally-varied (nonce-like) inputs. Also
 *                  Minerva-relevant, but the harness classes are coarser than the lz scan.
 *   - harness-max: worst of ALL classes; inflated by degenerate inputs (1, n-1) that a uniform
 *                  nonce never hits — so both methods "fail" it, which is misleading.
 *   - rand-rand  : two random populations; only detects a MEAN shift, so it is insensitive to
 *                  per-sample leaks and reads ~0 even for the leaky Euclidean method. Context only.
 *
 * This quantifies the impact of switching `k2sig`'s `Fn.inv(k)` to `invertCt(k, n)`.
 *
 * Run:  npx tsx benchmark/ct-inv.ts
 * Env:  SAMPLES, CURVES, MAXZ, CT_CSV, NO_PROGRESS
 */
import { pathToFileURL } from 'node:url';
import { invert, invertCt } from '../src/abstract/modular.ts';
import { ed25519 } from '../src/ed25519.ts';
import { ed448 } from '../src/ed448.ts';
import { p256, p384, p521 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { runSecretKeyOperationCt, type CtResult, type ScalarFieldLike } from './ct.ts';

type Bytes = Uint8Array<ArrayBuffer>;
type InvFn = (a: bigint, prime: bigint) => bigint;
type OutputFormat = 'table' | 'csv';
type Progress = {
  step: number;
  start: (test: string) => void;
  tick: () => void;
  end: () => void;
};
type Row = {
  curve: string;
  method: string;
  maxT: number; // harness max |t| (includes degenerate 1/n-1 inputs)
  structT: number; // max |t| over full-size structural classes = the Minerva-relevant leak
  rrT: number; // random-vs-random |t| (insensitive to per-sample leaks; context only)
  lzT: number; // leading-zero scan |t| at z=maxZ vs z=0 (the sharpest exploitable-leak probe)
  lzDeltaNs: number; // timing δ (ns) between maxZ-leading-zero nonces and full nonces
  meanNs: number;
  failed: boolean;
};

// Full-size, structurally-varied input classes from the harness. These vary bit-length / value
// structure while staying representative of a uniform nonce, so a timing difference here is the
// exploitable (Minerva-style) per-sample leak. The other harness classes involve degenerate inputs
// (1, 2, 3, n-1, n-2) that a uniform 256-bit nonce hits with probability ~2^-BITS.
const STRUCTURAL_TESTS = new Set([
  'mid-vs-top-bit',
  'alternating-complement',
  'nibble-complement',
  'byte-pattern-complement',
]);

const DEFAULT_SAMPLES = 200;
const DEFAULT_BATCH = 16; // inversion is fast; batch to clear timer noise
const DEFAULT_MAX_T = 4.5;
const DEFAULT_MIN_NS = 1_000;
const DEFAULT_MAXZ = 8; // leading-zero scan: nonces with 0..maxZ forced leading zero bits
const PROGRESS_ESTIMATE_INTERVAL = 20;
const PROGRESS_MIN_ESTIMATE_MS = 20_000;
let SINK = 0; // declared before main() runs; prevents dead-code elimination of the timed op
const CURVES: { name: string; Fn: ScalarFieldLike }[] = [
  { name: 'p256', Fn: p256.Point.Fn },
  { name: 'p384', Fn: p384.Point.Fn },
  { name: 'p521', Fn: p521.Point.Fn },
  { name: 'secp256k1', Fn: secp256k1.Point.Fn },
  { name: 'ed25519', Fn: ed25519.Point.Fn },
  { name: 'ed448', Fn: ed448.Point.Fn },
];
const METHODS: { id: string; fn: InvFn }[] = [
  { id: 'euclid_inv', fn: invert },
  { id: 'fermat_inv', fn: invertCt },
];

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();

function main() {
  const samples = sampleCount();
  const maxZ = maxZCount();
  const format = outputFormat();
  const rows: Row[] = [];
  if (format === 'csv') printInvCsvHeader();
  for (const { name, Fn } of selectedCurves()) {
    for (const method of METHODS) {
      const progress = progressEnabled() ? ctProgress(name, method.id, format) : undefined;
      if (format === 'table')
        console.log(
          `# ${name} ${method.id} samples=${samples} batch=${DEFAULT_BATCH} ` +
            `max_t=${fmtNum(DEFAULT_MAX_T)} min_ns=${fmtNum(DEFAULT_MIN_NS)} max_z=${maxZ}`
        );
      // operation: bytes(scalar) -> bytes(scalar^-1 mod n)
      const op = (scalarBytes: Bytes): Bytes =>
        Fn.toBytes(method.fn(Fn.fromBytes(scalarBytes), Fn.ORDER)) as Bytes;
      const batch = DEFAULT_BATCH;
      const result = runSecretKeyOperationCt(op, Fn, samples, {
        name: `${name} ${method.id}`,
        batch,
        log: () => {},
        onTest: (test) =>
          printInvRow(
            format,
            name,
            method.id,
            test.name,
            !test.failed,
            test.t,
            test.aMean,
            test.bMean
          ),
        progress,
        throwOnFailure: false,
      });
      const rr = randomVsRandomT(op, Fn, samples, batch, progress);
      printInvRow(
        format,
        name,
        method.id,
        'random-vs-random',
        rr.t <= DEFAULT_MAX_T,
        rr.t,
        rr.aMean,
        rr.bMean
      );
      const lz = leadingZeroScan(op, Fn, samples, batch, maxZ, progress);
      const baseline = lz[0].mean;
      for (const p of lz)
        printInvRow(
          format,
          name,
          method.id,
          `lz@${p.z}`,
          p.t <= DEFAULT_MAX_T,
          p.t,
          baseline,
          p.mean
        );
      const lzTop = lz[lz.length - 1];
      rows.push({
        curve: name,
        method: method.id,
        maxT: maxObservedT(result),
        structT: structuralMaxT(result),
        rrT: rr.t,
        lzT: lzTop.t,
        lzDeltaNs: lzTop.delta,
        meanNs: meanNs(result),
        failed: result.failed,
      });
    }
  }
  if (format === 'csv') {
    if (rows.some((r) => r.method === 'fermat_inv' && r.lzT > DEFAULT_MAX_T)) process.exitCode = 1;
    return;
  }
  printSummary(rows, maxZ);
  // Euclidean is EXPECTED to leak; only fail the run if the constant-time method (fermat) leaks
  // on the leading-zero probe (the sharpest exploitable metric).
  if (rows.some((r) => r.method === 'fermat_inv' && r.lzT > DEFAULT_MAX_T)) process.exitCode = 1;
}

function printInvCsvHeader() {
  printCsvRow(['status', 't', 'curve', 'method', 'test', 'timings_ns']);
}

function printInvRow(
  format: OutputFormat,
  curve: string,
  method: string,
  test: string,
  passed: boolean,
  t: number,
  aMean: number,
  bMean: number
) {
  const timings = t < DEFAULT_MAX_T ? '' : fmtTimingRange(aMean, bMean, fmtNsRaw);
  if (format === 'csv') {
    printCsvRow([passed ? 'pass' : 'fail', fmtFixed(t, 1), curve, method, test, timings]);
    return;
  }
  const tText = timings ? fmtT(t, !passed) : `t=${fmtFixed(t, 1)}`;
  console.log(`${fmtStatus(!passed)} ${test.padEnd(24)} ${tText}${timings ? ` ${timings}` : ''}`);
}

function printSummary(rows: Row[], maxZ: number) {
  console.log('\n# summary');
  console.log(
    `${pad('', 2)} ${pad('curve', 10)} ${pad('method', 11)} ${pad(`lz@${maxZ}`, 9)} ${pad('lz delta', 9)} ${pad('struct', 8)} ${pad('h-max', 8)} ${pad('rand', 7)} mean/op`
  );
  for (const r of rows) {
    // The sharpest exploitable verdict is the leading-zero probe |t|.
    const leak = r.lzT > DEFAULT_MAX_T;
    console.log(
      `${fmtStatus(leak)} ${pad(r.curve, 10)} ${pad(r.method, 11)} ` +
        `${pad(`${fmtFixed(r.lzT, 1)} ${leak ? 'LEAK' : 'ok'}`, 9)} ${pad(fmtNsSigned(r.lzDeltaNs), 9)} ` +
        `${pad(fmtFixed(r.structT, 1), 8)} ${pad(fmtFixed(r.maxT, 0), 8)} ${pad(fmtFixed(r.rrT, 1), 7)} ${fmtNs(r.meanNs)}`
    );
  }
  console.log(`\n# impact`);
  const byCurve = new Map<string, Row[]>();
  for (const r of rows) (byCurve.get(r.curve) ?? byCurve.set(r.curve, []).get(r.curve)!).push(r);
  for (const [curve, pair] of byCurve) {
    const eu = pair.find((r) => r.method.startsWith('euclid'));
    const fe = pair.find((r) => r.method.startsWith('fermat'));
    if (!eu || !fe) continue;
    console.log(
      `  ${pad(curve, 10)} lz@${maxZ} |t| ${fmtFixed(eu.lzT, 1)} ${eu.lzT > DEFAULT_MAX_T ? 'LEAK' : 'ok'} (δ ${fmtNsSigned(eu.lzDeltaNs)}) -> ` +
        `${fmtFixed(fe.lzT, 1)} ${fe.lzT > DEFAULT_MAX_T ? 'LEAK' : 'ok'} (δ ${fmtNsSigned(fe.lzDeltaNs)})   ` +
        `speed ${fmtNs(eu.meanNs)} -> ${fmtNs(fe.meanNs)} (${fmtFixed(fe.meanNs / eu.meanNs, 1)}x)`
    );
  }
}

function structuralMaxT(result: CtResult): number {
  let max = 0;
  for (const test of result.tests)
    if (STRUCTURAL_TESTS.has(test.name) && test.t > max) max = test.t;
  return max;
}

// --- shared timing + statistics primitives ---
type Stats = { n: number; mean: number; m2: number };

function initStats(): Stats {
  return { n: 0, mean: 0, m2: 0 };
}
function addSample(s: Stats, v: number): void {
  s.n++;
  const d = v - s.mean;
  s.mean += d / s.n;
  s.m2 += d * (v - s.mean);
}
function welch(a: Stats, b: Stats): number {
  const va = (a.n > 1 ? a.m2 / (a.n - 1) : 0) / a.n;
  const vb = (b.n > 1 ? b.m2 / (b.n - 1) : 0) / b.n;
  const denom = Math.sqrt(va + vb);
  return denom === 0 ? 0 : Math.abs(a.mean - b.mean) / denom;
}
// best-of timing of one operation over `batch` repeats of the same key
function timeOp(op: (k: Bytes) => Bytes, k: Bytes, batch: number): number {
  let best = Infinity;
  for (let attempt = 0; attempt < 8; attempt++) {
    const t0 = process.hrtime.bigint();
    for (let j = 0; j < batch; j++) SINK ^= op(k)[0];
    const el = Number(process.hrtime.bigint() - t0) / batch;
    if (el < best) best = el;
    if (el >= 1000) break;
  }
  return best;
}
function randBig(m: bigint): bigint {
  let bits = 0n;
  for (let v = m; v > 0n; v >>= 1n) bits++;
  const nbytes = Number((bits + 7n) / 8n) + 8; // extra bytes -> negligible modulo bias
  const b = new Uint8Array(nbytes);
  globalThis.crypto.getRandomValues(b);
  let x = 0n;
  for (const y of b) x = (x << 8n) | BigInt(y);
  return x % m;
}
function randomBytes1(): number {
  const b = new Uint8Array(1);
  globalThis.crypto.getRandomValues(b);
  return b[0];
}

/**
 * Welch t-test between two independent populations of uniform random nonces. NOTE: this only
 * compares population MEANS, so it is insensitive to per-sample leaks (a bit-length-dependent
 * timing does not shift the mean) — it reads ~0 even for the leaky Euclidean inverse. It is a
 * sanity check for mean stability, not the leakage verdict; see the STRUCTURAL / lz-scan classes.
 */
function randomVsRandomT(
  op: (k: Bytes) => Bytes,
  Fn: ScalarFieldLike,
  samples: number,
  batch: number,
  progress?: Progress
): { t: number; aMean: number; bMean: number } {
  const rnd = (): Bytes => Fn.toBytes(randBig(Fn.ORDER - 1n) + 1n) as Bytes; // [1, n-1]
  const A: Bytes[] = [];
  const B: Bytes[] = [];
  for (let i = 0; i < samples; i++) {
    A.push(rnd());
    B.push(rnd());
  }
  for (let i = 0; i < 50; i++) timeOp(op, A[i % samples], batch); // warmup
  const a = initStats();
  const b = initStats();
  const tracker = progressTracker(progress, 'random-vs-random', samples);
  try {
    for (let i = 0; i < samples; i++) {
      if (randomBytes1() & 1) {
        addSample(a, timeOp(op, A[i], batch));
        addSample(b, timeOp(op, B[i], batch));
      } else {
        addSample(b, timeOp(op, B[i], batch));
        addSample(a, timeOp(op, A[i], batch));
      }
      tracker.update(i + 1);
    }
  } finally {
    tracker.end();
  }
  return { t: cleanZero(welch(a, b)), aMean: a.mean, bMean: b.mean };
}

/**
 * Leading-zero scan: the most direct measure of the exploitable (HNP / Minerva) quantity.
 * Builds one population per z in [0, maxZ] where every nonce has EXACTLY z leading zero bits
 * (bit-length = bitLen(n) - z), and measures how inversion time scales with z. All z classes are
 * timed interleaved (order reshuffled each round) to cancel CPU-frequency drift, then each is
 * compared to the z=0 baseline via Welch's t. A δ growing monotonically with z (Euclidean) is the
 * exact quantity a lattice attack consumes; a flat δ leaks nothing about the nonce's top bits.
 */
function leadingZeroScan(
  op: (k: Bytes) => Bytes,
  Fn: ScalarFieldLike,
  samples: number,
  batch: number,
  maxZ: number,
  progress?: Progress
): { z: number; mean: number; t: number; delta: number }[] {
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
  const classes: { z: number; keys: Bytes[] }[] = [];
  for (let z = 0; z <= maxZ; z++) {
    const keys: Bytes[] = [];
    for (let i = 0; i < samples; i++) keys.push(keyFor(z));
    classes.push({ z, keys });
  }
  for (let i = 0; i < 50; i++) timeOp(op, classes[0].keys[i % samples], batch); // warmup
  const stats = classes.map(() => initStats());
  const order = classes.map((_, i) => i);
  const tracker = progressTracker(progress, 'leading-zero-scan', samples);
  try {
    for (let i = 0; i < samples; i++) {
      for (let j = order.length - 1; j > 0; j--) {
        // reshuffle class order each round (Fisher-Yates) to avoid systematic ordering bias
        const r = randomBytes1() % (j + 1);
        [order[j], order[r]] = [order[r], order[j]];
      }
      for (const idx of order) addSample(stats[idx], timeOp(op, classes[idx].keys[i], batch));
      tracker.update(i + 1);
    }
  } finally {
    tracker.end();
  }
  return classes.map((c, idx) => ({
    z: c.z,
    mean: stats[idx].mean,
    t: cleanZero(welch(stats[idx], stats[0])),
    delta: cleanZero(stats[idx].mean - stats[0].mean),
  }));
}

// --- small local helpers (mirroring ct.ts; its versions are module-private) ---
function meanNs(result: CtResult): number {
  let sum = 0;
  let count = 0;
  for (const test of result.tests) {
    sum += test.aMean + test.bMean;
    count += 2;
  }
  return count ? sum / count : 0;
}
function maxObservedT(result: CtResult): number {
  let max = 0;
  for (const test of result.tests) if (test.t > max) max = test.t;
  return max;
}
function fmtNs(ns: number): string {
  return `${fmtFixed(ns / 1000, 0)}us`;
}
function fmtNsSigned(ns: number): string {
  // signed µs with 2 decimals: leading-zero δ is often sub-µs
  const clean = cleanZero(ns);
  return `${clean >= 0 ? '+' : '-'}${fmtFixed(Math.abs(clean) / 1000, 2)}us`;
}
function pad(value: string, length: number): string {
  return value.padEnd(length);
}
function fmtStatus(failed: boolean): string {
  const status = failed ? '✕' : '✓';
  if (!supportsColor()) return status;
  return failed ? `\x1b[31m${status}\x1b[0m` : `\x1b[32m${status}\x1b[0m`;
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
function fmtNsRaw(ns: number): string {
  return fmtFixed(ns, 0);
}
function cleanZero(num: number): number {
  return Object.is(num, -0) ? 0 : num;
}
function fmtTimingRange(a: number, b: number, fmt: (value: number) => string): string {
  return `${fmt(Math.min(a, b))}...${fmt(Math.max(a, b))}`;
}
function csvCell(value: unknown): string {
  const cell = String(value ?? '');
  return /[",\r\n]/.test(cell) ? `"${cell.replaceAll('"', '""')}"` : cell;
}
function printCsvRow(values: unknown[]) {
  console.log(values.map(csvCell).join(','));
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
function ctProgress(curve: string, method: string, format: OutputFormat): Progress {
  const prefix = `${curve},${method}`;
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
function progressTracker(progress: Progress | undefined, test: string, samples: number) {
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
function sampleCount(): number {
  const value = process.env.SAMPLES;
  if (value === undefined) return DEFAULT_SAMPLES;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count <= 0) throw new Error('invalid SAMPLES');
  return count;
}
function maxZCount(): number {
  const value = process.env.MAXZ;
  if (value === undefined) return DEFAULT_MAXZ;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('invalid MAXZ');
  return count;
}
function selectedCurves(): { name: string; Fn: ScalarFieldLike }[] {
  const value = process.env.CURVES;
  if (value === undefined) return CURVES;
  const names = new Set(
    value
      .split(',')
      .map((p) => p.trim())
      .filter((p) => p.length)
  );
  const selected = CURVES.filter((c) => names.has(c.name));
  if (selected.length !== names.size) {
    const known = new Set(CURVES.map((c) => c.name));
    const unknown = [...names].filter((n) => !known.has(n));
    throw new Error(`unknown CURVES: ${unknown.join(', ')}`);
  }
  return selected;
}
