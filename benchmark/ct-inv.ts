/**
 * Constant-time leakage test for the ECDSA nonce inversion `k⁻¹ mod n`.
 *
 * Reuses the dudect-style Welch t-test harness from ./ct.ts, but the measured secret-key
 * operation is the modular inverse instead of scalar multiplication. For each curve it runs the
 * same battery of secret-input classes and reports |t| (leak if > CT_MAX_T, default 4.5).
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
 * Env:  CT_SAMPLES, CT_CURVES, CT_MAXZ, CT_BATCH, CT_MAX_T, CT_MIN_NS (see ct.ts)
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
const DEFAULT_MAXZ = 8; // leading-zero scan: nonces with 0..maxZ forced leading zero bits
let SINK = 0; // declared before main() runs; prevents dead-code elimination of the timed op
const CURVES: { name: string; Fn: ScalarFieldLike }[] = [
  { name: 'p256', Fn: p256.Point.Fn },
  { name: 'p384', Fn: p384.Point.Fn },
  { name: 'p521', Fn: p521.Point.Fn },
  { name: 'secp256k1', Fn: secp256k1.Point.Fn },
  { name: 'ed25519', Fn: ed25519.Point.Fn },
  { name: 'ed448', Fn: ed448.Point.Fn },
];
const METHODS: { name: string; fn: InvFn }[] = [
  { name: 'euclid(invert)', fn: invert },
  { name: 'fermat(invertCt)', fn: invertCt },
];

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();

function main() {
  const samples = sampleCount();
  const maxZ = Math.floor(envNum('CT_MAXZ', DEFAULT_MAXZ));
  const rows: Row[] = [];
  for (const { name, Fn } of selectedCurves()) {
    for (const method of METHODS) {
      console.log(`\n# ${name} ${method.name} k^-1 mod n  samples=${samples}`);
      // operation: bytes(scalar) -> bytes(scalar^-1 mod n)
      const op = (scalarBytes: Bytes): Bytes =>
        Fn.toBytes(method.fn(Fn.fromBytes(scalarBytes), Fn.ORDER)) as Bytes;
      const batch = envNum('CT_BATCH', DEFAULT_BATCH);
      const result = runSecretKeyOperationCt(op, Fn, samples, {
        name: `${name}.${method.name}`,
        batch,
        throwOnFailure: false,
      });
      // random-vs-random measures population-MEAN stability. It is INSENSITIVE to per-sample leaks
      // (both random populations share the same mean), so it cannot see the Minerva-style leak on
      // its own — it is reported only for context / as a sanity check.
      const rr = randomVsRandomT(op, Fn, samples, batch);
      console.log(`  random-vs-random |t|=${rr.t.toFixed(2)} (mean-only, insensitive)  a=${fmtNs(rr.aMean)} b=${fmtNs(rr.bMean)}`);
      // leading-zero scan: how does k^-1 timing scale with the number of forced leading zero bits?
      // This is the sharpest, most directly exploitable (HNP/Minerva) probe.
      const lz = leadingZeroScan(op, Fn, samples, batch, maxZ);
      console.log('  leading-zero scan (mean, δ vs z=0, |t| vs z=0):');
      for (const p of lz)
        console.log(
          `    z=${String(p.z).padStart(2)} ${pad(fmtNs(p.mean), 7)}` +
            (p.z === 0 ? ' baseline' : ` δ=${fmtNsSigned(p.delta)} |t|=${p.t.toFixed(2)}`)
        );
      const lzTop = lz[lz.length - 1];
      rows.push({
        curve: name,
        method: method.name,
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
  printSummary(rows, maxZ);
  // Euclidean is EXPECTED to leak; only fail the run if the constant-time method (fermat) leaks
  // on the leading-zero probe (the sharpest exploitable metric).
  if (rows.some((r) => r.method.startsWith('fermat') && r.lzT > 4.5)) process.exitCode = 1;
}

function printSummary(rows: Row[], maxZ: number) {
  console.log('\n# summary: k^-1 mod n constant-time (Welch |t|, leak if > 4.5)');
  console.log(`   lz@${maxZ} = leading-zero probe (${maxZ} forced leading-zero-bit nonces vs full) = sharpest exploitable leak; VERDICT`);
  console.log('   structural = varied full-size inputs; harness-max = incl. degenerate 1/n-1; rand-rand = mean-only (insensitive)');
  console.log(
    `${pad('', 2)} ${pad('curve', 10)} ${pad('method', 18)} ${pad(`lz@${maxZ} |t|`, 14)} ${pad('lz δ', 9)} ${pad('struct', 8)} ${pad('h-max', 8)} ${pad('rand', 7)} mean/op`
  );
  for (const r of rows) {
    // The sharpest exploitable verdict is the leading-zero probe |t|.
    const leak = r.lzT > 4.5;
    console.log(
      `${fmtStatus(leak)} ${pad(r.curve, 10)} ${pad(r.method, 18)} ` +
        `${pad(`${r.lzT.toFixed(2)} ${leak ? 'LEAK' : 'ok'}`, 14)} ${pad(fmtNsSigned(r.lzDeltaNs), 9)} ` +
        `${pad(r.structT.toFixed(1), 8)} ${pad(r.maxT.toFixed(0), 8)} ${pad(r.rrT.toFixed(2), 7)} ${fmtNs(r.meanNs)}`
    );
  }
  console.log(`\n# impact (euclid -> fermat): lz@${maxZ} |t| / δ is the sharpest exploitable-leak metric`);
  const byCurve = new Map<string, Row[]>();
  for (const r of rows) (byCurve.get(r.curve) ?? byCurve.set(r.curve, []).get(r.curve)!).push(r);
  for (const [curve, pair] of byCurve) {
    const eu = pair.find((r) => r.method.startsWith('euclid'));
    const fe = pair.find((r) => r.method.startsWith('fermat'));
    if (!eu || !fe) continue;
    console.log(
      `  ${pad(curve, 10)} lz@${maxZ} |t| ${eu.lzT.toFixed(1)} ${eu.lzT > 4.5 ? 'LEAK' : 'ok'} (δ ${fmtNsSigned(eu.lzDeltaNs)}) -> ` +
        `${fe.lzT.toFixed(1)} ${fe.lzT > 4.5 ? 'LEAK' : 'ok'} (δ ${fmtNsSigned(fe.lzDeltaNs)})   ` +
        `speed ${fmtNs(eu.meanNs)} -> ${fmtNs(fe.meanNs)} (${(fe.meanNs / eu.meanNs).toFixed(1)}x)`
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
  batch: number
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
  for (let i = 0; i < samples; i++) {
    if (randomBytes1() & 1) {
      addSample(a, timeOp(op, A[i], batch));
      addSample(b, timeOp(op, B[i], batch));
    } else {
      addSample(b, timeOp(op, B[i], batch));
      addSample(a, timeOp(op, A[i], batch));
    }
  }
  return { t: welch(a, b), aMean: a.mean, bMean: b.mean };
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
  maxZ: number
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
  for (let i = 0; i < samples; i++) {
    for (let j = order.length - 1; j > 0; j--) {
      // reshuffle class order each round (Fisher-Yates) to avoid systematic ordering bias
      const r = randomBytes1() % (j + 1);
      [order[j], order[r]] = [order[r], order[j]];
    }
    for (const idx of order) addSample(stats[idx], timeOp(op, classes[idx].keys[i], batch));
  }
  return classes.map((c, idx) => ({
    z: c.z,
    mean: stats[idx].mean,
    t: welch(stats[idx], stats[0]),
    delta: stats[idx].mean - stats[0].mean,
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
  return `${(ns / 1000).toFixed(0)}us`;
}
function fmtNsSigned(ns: number): string {
  // signed µs with 2 decimals: leading-zero δ is often sub-µs
  return `${ns >= 0 ? '+' : '-'}${(Math.abs(ns) / 1000).toFixed(2)}us`;
}
function pad(value: string, length: number): string {
  return value.padEnd(length);
}
function fmtStatus(failed: boolean): string {
  return failed ? '✕' : '✓';
}
function sampleCount(): number {
  const value = process.env.CT_SAMPLES;
  if (value === undefined) return DEFAULT_SAMPLES;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count <= 0) throw new Error('invalid CT_SAMPLES');
  return count;
}
function selectedCurves(): { name: string; Fn: ScalarFieldLike }[] {
  const value = process.env.CT_CURVES;
  if (value === undefined) return CURVES;
  const names = new Set(value.split(',').map((p) => p.trim()).filter((p) => p.length));
  const selected = CURVES.filter((c) => names.has(c.name));
  if (selected.length !== names.size) {
    const known = new Set(CURVES.map((c) => c.name));
    const unknown = [...names].filter((n) => !known.has(n));
    throw new Error(`unknown CT_CURVES: ${unknown.join(', ')}`);
  }
  return selected;
}
function envNum(name: string, fallback: number): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) throw new Error(`${name} must be a positive number`);
  return num;
}
