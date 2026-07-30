/**
 * Constant-time leakage test for the ECDSA nonce inversion `k⁻¹ mod n`.
 *
 * Reuses the dudect-style Welch t-test harness from ./ct.ts, but the measured secret-key
 * operation is the modular inverse instead of scalar multiplication. For each curve it runs the
 * same battery of secret-input classes plus a leading-zero scan and reports |t|.
 *
 * Compares the two inverse implementations used for the secret nonce:
 *   - euclid  invert()   : extended Euclidean; loop count depends on k. EXPECTED to leak — it is
 *                          this harness's built-in positive control: a wide-gap scan (0 vs
 *                          max(32, BITS/8) leading zeros; euclid's per-value scatter dwarfs its
 *                          per-bit trend at z<=8) must show a leak, else detection power was
 *                          lost and the run fails.
 *   - fermat  invertCt() : a^(n-2), control flow fixed by public exponent. Must NOT leak.
 *
 * Which |t| matters (most-to-least meaningful):
 *   - lz@Z (VERDICT) : leading-zero scan. Populations of nonces with 0..Z forced leading zero
 *                  bits; reports how k^-1 timing scales with the zero count. This is the exact
 *                  quantity a Hidden-Number-Problem lattice attack (Minerva) consumes, so it is
 *                  the sharpest, most directly exploitable probe.
 *   - struct (VERDICT) : max |t| over full-size, structurally-varied (nonce-like) inputs. Also
 *                  Minerva-relevant, but the harness classes are coarser than the lz scan.
 *   - degen      : worst |t| over degenerate inputs (1, 2, 3, n-1, n-2) that a uniform nonce
 *                  never hits — both methods "fail" these, which is why they are quarantined.
 *   - rand-rand  : two random populations; only detects a MEAN shift, so it is insensitive to
 *                  per-sample leaks and reads ~0 even for the leaky Euclidean method. Context
 *                  only. The battery also runs a fixed-vs-fixed rig-bias control.
 *
 * Verdict: the run fails if fermat leaks on lz OR struct (both require |t| > 4.5 AND |δ| above
 * a 0.1%-of-op-time effect floor), if a rig-bias control trips, or if euclid fails to leak
 * (positive control missed). Each battery prints its median minimum-detectable effect (MDE) —
 * a pass only rules out mean leaks larger than that at the given SAMPLES.
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
import {
  DEFAULT_MAX_T,
  ctProgress,
  fmtFixed,
  fmtMark,
  fmtNs,
  fmtNs2,
  fmtNsSigned,
  fmtNum,
  leadingZeroScan,
  lzScanFailed,
  maxZCount,
  meanNs,
  outputFormat,
  pad,
  printCsvRow,
  printLzRows,
  progressEnabled,
  runSecretKeyOperationCt,
  sampleCount,
  selectByEnv,
  type CtTestResult,
  type OutputFormat,
  type ScalarFieldLike,
} from './ct.ts';

type Bytes = Uint8Array<ArrayBuffer>;
type InvFn = (a: bigint, prime: bigint) => bigint;
type Row = {
  curve: string;
  method: string;
  degenT: number; // worst |t| over degenerate 1/n-1-style inputs (quarantined from verdict)
  structT: number; // max |t| over full-size structural classes = the Minerva-relevant leak
  structFail: boolean; // struct verdict incl. the |δ| effect floor
  rrT: number; // random-vs-random |t| (insensitive to per-sample leaks; context only)
  lzT: number; // leading-zero scan |t| at z=maxZ vs z=0 (the sharpest exploitable-leak probe)
  lzDeltaNs: number; // timing δ (ns) between maxZ-leading-zero nonces and full nonces
  lzFail: boolean;
  biased: boolean; // fixed-vs-fixed control tripped — rig suspect
  mdeNs: number; // median minimum detectable effect of the battery
  meanNs: number;
  pcZ: number; // wide positive-control z gap for this curve (scaled to field size)
  pcT?: number; // euclid only: wide-gap (z=0 vs z=pcZ) positive-control |t|
  pcDetected?: boolean;
};

const DEFAULT_SAMPLES = 200;
const DEFAULT_BATCH = 16; // inversion is fast; batch to clear timer noise
// Positive control: euclid's per-value scatter (~2us, continued-fraction structure) dwarfs its
// per-bit trend (~0.08us/bit), so the z<=8 scan reads |t|~2-3 at default n. A wide z gap —
// scaled to 1/8 of the field size so larger moduli keep the same relative gap — makes the
// bit-length dependence unmissable without needing thousands of samples.
const pcZOf = (Fn: ScalarFieldLike): number => Math.max(32, Fn.BITS >> 3);
const PC_MIN_SAMPLES = 150;
const CURVES: { name: string; Fn: ScalarFieldLike }[] = [
  { name: 'p256', Fn: p256.Point.Fn },
  { name: 'p384', Fn: p384.Point.Fn },
  { name: 'p521', Fn: p521.Point.Fn },
  { name: 'secp256k1', Fn: secp256k1.Point.Fn },
  { name: 'ed25519', Fn: ed25519.Point.Fn },
  { name: 'ed448', Fn: ed448.Point.Fn },
];
const METHODS: { id: string; fn: InvFn; expectedLeak: boolean }[] = [
  { id: 'euclid_inv', fn: invert, expectedLeak: true }, // positive control
  { id: 'fermat_inv', fn: invertCt, expectedLeak: false },
];

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();

function main() {
  const samples = sampleCount(DEFAULT_SAMPLES);
  const maxZ = maxZCount();
  const format = outputFormat();
  const rows: Row[] = [];
  if (format === 'csv') printInvCsvHeader();
  for (const { name, Fn } of selectByEnv(CURVES)) {
    for (const method of METHODS) {
      const progress = progressEnabled() ? ctProgress(name, method.id, format) : undefined;
      // operation: bytes(scalar) -> bytes(scalar^-1 mod n)
      const op = (scalarBytes: Bytes): Bytes =>
        Fn.toBytes(method.fn(Fn.fromBytes(scalarBytes), Fn.ORDER)) as Bytes;
      const result = runSecretKeyOperationCt(op, Fn, samples, {
        name: `${name} ${method.id}`,
        batch: DEFAULT_BATCH,
        log: format === 'csv' ? () => {} : console.log,
        onTest: format === 'csv' ? (test) => printInvCsvRow(name, method.id, test) : undefined,
        progress,
        throwOnFailure: false,
      });
      const lz = leadingZeroScan(op, Fn, samples, DEFAULT_BATCH, maxZ, progress);
      printLzRows(lz, format, name, method.id);
      let pcT: number | undefined;
      let pcDetected: boolean | undefined;
      const pcZ = pcZOf(Fn);
      if (method.expectedLeak) {
        const pcSamples = Math.max(PC_MIN_SAMPLES, samples);
        const pc = leadingZeroScan(op, Fn, pcSamples, DEFAULT_BATCH, pcZ, progress, [0, pcZ]);
        const top = pc[pc.length - 1];
        pcT = top.t;
        pcDetected = top.t > DEFAULT_MAX_T;
        if (format === 'csv') {
          printCsvRow([
            pcDetected ? 'pass' : 'fail',
            'positive-control',
            fmtFixed(top.t, 1),
            '',
            fmtFixed(top.delta, 0),
            '',
            name,
            method.id,
            `pctrl-lz@${pcZ}`,
            '',
          ]);
        } else {
          console.log(
            `${fmtStatusOf(!pcDetected)} ${`pctrl-lz@${pcZ}`.padEnd(24)} ${pad('[pctrl]', 10)}` +
              `t=${fmtFixed(top.t, 1).padEnd(7)} δ=${fmtNsSigned(top.delta)} ` +
              (pcDetected
                ? 'leak detected (harness has power)'
                : 'NO LEAK DETECTED — harness power lost')
          );
        }
      }
      const lzTop = lz[lz.length - 1];
      const rr = result.tests.find((t) => t.name === 'random-vs-random');
      rows.push({
        curve: name,
        method: method.id,
        degenT: result.degenT,
        structT: result.structT,
        structFail: result.failed,
        rrT: rr?.t ?? 0,
        lzT: lzTop.t,
        lzDeltaNs: lzTop.delta,
        lzFail: lzScanFailed(lz, DEFAULT_MAX_T),
        biased: result.biased,
        mdeNs: result.mdeNs,
        meanNs: meanNs(result),
        pcZ,
        pcT,
        pcDetected,
      });
    }
  }
  // fermat (the constant-time method) must be clean on lz + struct; euclid is the positive
  // control and must LEAK on the wide-gap probe — a euclid pass means detection power was lost.
  const fermatLeak = rows.some((r) => isFermat(r) && (r.lzFail || r.structFail));
  const bias = rows.some((r) => r.biased);
  const pcMiss = rows.some((r) => r.pcDetected === false);
  if (fermatLeak || bias || pcMiss) process.exitCode = 1;
  if (format === 'csv') return;
  printSummary(rows, maxZ, samples);
  if (bias) console.log(`${fmtMark('✕', 'red')} rig-bias control tripped — all verdicts suspect`);
  if (pcMiss)
    console.log(
      `${fmtMark('✕', 'red')} positive control MISSED: euclid_inv shows no wide-gap lz leak — ` +
        `the harness cannot currently detect leaks, negative results are not trustworthy`
    );
}

function isFermat(row: Row): boolean {
  return row.method.startsWith('fermat');
}

function printInvCsvHeader() {
  printCsvRow([
    'status',
    'kind',
    't',
    't2',
    'delta_ns',
    'mde_ns',
    'curve',
    'method',
    'test',
    'timings_ns',
  ]);
}

function printInvCsvRow(curve: string, method: string, test: CtTestResult) {
  printCsvRow([
    test.failed ? 'fail' : 'pass',
    test.kind,
    fmtFixed(test.t, 1),
    fmtFixed(test.t2, 1),
    fmtFixed(test.delta, 0),
    fmtFixed(test.mdeNs, 0),
    curve,
    method,
    test.name,
    '',
  ]);
}

function printSummary(rows: Row[], maxZ: number, samples: number) {
  console.log(
    '\n# summary — verdict = fermat lz + struct (δ-floored); euclid must leak (positive control)'
  );
  console.log(
    `${pad('', 2)} ${pad('curve', 10)} ${pad('method', 11)} ${pad(`lz@${maxZ}`, 10)} ${pad('lz-δ', 9)} ` +
      `${pad('struct', 8)} ${pad('degen', 8)} ${pad('rand', 7)} ${pad('mde', 8)} mean/op`
  );
  for (const r of rows) {
    const leak = r.lzFail || r.structFail;
    const expected = !isFermat(r);
    // fermat leaking or euclid missing its positive control are failures; a leaking euclid ('!')
    // is the expected result that proves the harness can detect leaks
    const status = expected
      ? r.pcDetected
        ? fmtMark('!', 'yellow')
        : fmtMark('✕', 'red')
      : fmtStatusOf(leak);
    const verdict = expected ? '' : leak ? ' LEAK' : ' ok';
    const note = expected
      ? `  pctrl-lz@${r.pcZ} t=${fmtFixed(r.pcT ?? 0, 1)} ${r.pcDetected ? 'detected (expected leak)' : 'MISSED'}`
      : '';
    console.log(
      `${status}  ${pad(r.curve, 10)} ${pad(r.method, 11)} ` +
        `${pad(`${fmtFixed(r.lzT, 1)}${verdict}`, 10)} ${pad(fmtNsSigned(r.lzDeltaNs), 9)} ` +
        `${pad(fmtFixed(r.structT, 1), 8)} ${pad(fmtFixed(r.degenT, 1), 8)} ${pad(fmtFixed(r.rrT, 1), 7)} ` +
        `${pad(fmtNs2(r.mdeNs), 8)} ${fmtNs(r.meanNs)}${note}`
    );
  }
  console.log(`\n# impact`);
  const byCurve = new Map<string, Row[]>();
  for (const r of rows) (byCurve.get(r.curve) ?? byCurve.set(r.curve, []).get(r.curve)!).push(r);
  for (const [curve, pair] of byCurve) {
    const eu = pair.find((r) => !isFermat(r));
    const fe = pair.find(isFermat);
    if (!eu || !fe) continue;
    console.log(
      `  ${pad(curve, 10)} lz@${maxZ} |t| ${fmtFixed(eu.lzT, 1)} ${eu.lzFail ? 'LEAK' : 'ok'} (δ ${fmtNsSigned(eu.lzDeltaNs)}) -> ` +
        `${fmtFixed(fe.lzT, 1)} ${fe.lzFail ? 'LEAK' : 'ok'} (δ ${fmtNsSigned(fe.lzDeltaNs)})   ` +
        `speed ${fmtNs(eu.meanNs)} -> ${fmtNs(fe.meanNs)} (${fmtFixed(fe.meanNs / eu.meanNs, 1)}x)`
    );
  }
  const medianMde = median(rows.map((r) => r.mdeNs));
  console.log(
    `\n# power: median MDE ≈ ${fmtNs2(medianMde)} at n=${samples} — mean leaks below this are invisible; ` +
      `raise SAMPLES to shrink it. euclid_inv wide-gap pctrl-lz is the positive control ` +
      `(threshold ${fmtNum(DEFAULT_MAX_T)}).`
  );
}

function fmtStatusOf(failed: boolean): string {
  return fmtMark(failed ? '✕' : '✓', failed ? 'red' : 'green');
}

function median(xs: number[]): number {
  const sorted = [...xs].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}
