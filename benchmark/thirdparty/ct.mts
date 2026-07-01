import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { ed25519 } from '../../src/ed25519.ts';
import { p256 } from '../../src/nist.ts';
import { secp256k1 } from '../../src/secp256k1.ts';
import { type CtResult, type ScalarFieldLike, runSecretKeyOperationCt } from '../ct.ts';

type Bytes = Uint8Array<ArrayBuffer>;
type ThirdPartyBench = {
  library: string;
  primitive: string;
  field: ScalarFieldLike;
  operation: (secretKey: Bytes) => Bytes;
  nobleOperation: (secretKey: Bytes) => Bytes;
  note?: string;
};
type SkippedBench = {
  library: string;
  reason: string;
};
type Summary = {
  library: string;
  primitive: string;
  samples: number;
  meanNs: number;
  maxT: number;
  failed: boolean;
  note?: string;
};

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const samples = sampleCount();
const benches: ThirdPartyBench[] = [];
const skipped: SkippedBench[] = [];

addSecp256k1Native();
addElliptic();
addEcurve();
addBipSchnorr();
addEccJsbn();
addSjcl();
addTweetNacl();
addWasmCrypto();

crossTestBenches();

const summary: Summary[] = [];
for (const bench of benches) {
  console.log(`\n# ${bench.library} ${bench.primitive} samples=${samples}`);
  if (bench.note) console.log(`note=${bench.note}`);
  const result = runSecretKeyOperationCt(bench.operation, bench.field, samples, {
    name: `${bench.library}.${bench.primitive}`,
    throwOnFailure: false,
  });
  summary.push({
    library: bench.library,
    primitive: bench.primitive,
    samples,
    meanNs: meanNs(result),
    maxT: maxObservedT(result),
    failed: result.failed,
    note: bench.note,
  });
}

console.log('\n# summary');
console.log(
  `${pad('', 2)} ${pad('library', 13)} ${pad('primitive', 30)} ${pad('samples', 8)} ${pad('mean/op', 9)} ${pad('max |t|', 8)}`
);
for (const row of summary) {
  console.log(
    `${fmtStatus(row.failed)} ${pad(row.library, 13)} ${pad(row.primitive, 30)} ${pad(String(row.samples), 8)} ` +
      `${pad(fmtNs(row.meanNs), 9)} ${row.maxT.toFixed(2)}`
  );
}
if (skipped.length) {
  console.log('\n# skipped');
  for (const row of skipped) console.log(`${row.library}: ${row.reason}`);
}
if (summary.some((row) => row.failed)) process.exitCode = 1;

function addSecp256k1Native() {
  const lib = require('secp256k1');
  benches.push({
    library: 'secp256k1',
    primitive: 'secp256k1 publicKeyCreate',
    field: secp256k1.Point.Fn,
    operation: (secretKey) => bytes(lib.publicKeyCreate(Buffer.from(secretKey), true)),
    nobleOperation: (secretKey) => bytes(secp256k1.getPublicKey(secretKey, true)),
  });
}

function addElliptic() {
  const elliptic = require('elliptic');
  const ec = new elliptic.ec('secp256k1');
  benches.push({
    library: 'elliptic',
    primitive: 'secp256k1 G.mul',
    field: secp256k1.Point.Fn,
    operation: (secretKey) =>
      bytes(ec.g.mul(Buffer.from(secretKey).toString('hex')).encodeCompressed()),
    nobleOperation: (secretKey) => bytes(secp256k1.getPublicKey(secretKey, true)),
  });
}

function addEcurve() {
  const ecurve = require('ecurve');
  const bigi = require('bigi');
  const curve = ecurve.getCurveByName('secp256k1');
  benches.push({
    library: 'ecurve',
    primitive: 'secp256k1 G.multiply',
    field: secp256k1.Point.Fn,
    operation: (secretKey) =>
      bytes(curve.G.multiply(bigi.fromBuffer(Buffer.from(secretKey))).getEncoded(true)),
    nobleOperation: (secretKey) => bytes(secp256k1.getPublicKey(secretKey, true)),
  });
}

function addBipSchnorr() {
  const math = require('bip-schnorr').math;
  const ecurve = require('ecurve');
  const bigi = require('bigi');
  const curve = ecurve.getCurveByName('secp256k1');
  const publicPoint = curve.G.multiply(bigi.valueOf(12345));
  const noblePublicPoint = secp256k1.Point.BASE.multiply(12345n);
  benches.push({
    library: 'bip-schnorr',
    primitive: 'secp256k1 math.getR',
    field: secp256k1.Point.Fn,
    operation: (secretKey) => {
      const scalar = bigi.fromBuffer(Buffer.from(secretKey));
      return bytes(math.getR(scalar, bigi.ONE, publicPoint).getEncoded(true));
    },
    nobleOperation: (secretKey) => {
      const scalar = bytesToNumberBE(secretKey);
      return bytes(secp256k1.Point.BASE.multiply(scalar).subtract(noblePublicPoint).toBytes(true));
    },
    note: 'Uses exported Schnorr math helper getR(s, e, P), which performs secret-dependent secp256k1 scalar multiplication.',
  });
}

function addEccJsbn() {
  const ecc = require('ecc-jsbn');
  const { BigInteger } = require('jsbn');
  const curve = ecc.ECCurves.secp256r1();
  benches.push({
    library: 'ecc-jsbn',
    primitive: 'p256/secp256r1 G.multiply',
    field: p256.Point.Fn,
    operation: (secretKey) => {
      const point = curve
        .getG()
        .multiply(new BigInteger(Buffer.from(secretKey).toString('hex'), 16));
      return hexToBytes(curve.getCurve().encodeCompressedPointHex(point));
    },
    nobleOperation: (secretKey) => bytes(p256.getPublicKey(secretKey, true)),
  });
}

function addSjcl() {
  const sjcl = loadSjclWithEcc();
  const curve = sjcl.ecc.curves.k256;
  benches.push({
    library: 'sjcl',
    primitive: 'secp256k1/k256 G.mult',
    field: secp256k1.Point.Fn,
    operation: (secretKey) => {
      const point = curve.G.mult(new sjcl.bn(`0x${Buffer.from(secretKey).toString('hex')}`));
      return sjclCompressedPoint(sjcl, point);
    },
    nobleOperation: (secretKey) => bytes(secp256k1.getPublicKey(secretKey, true)),
    note: 'Loads sjcl core ECC modules directly because the npm entrypoint was built without sjcl.ecc.',
  });
}

function addTweetNacl() {
  const nacl = require('tweetnacl');
  benches.push({
    library: 'tweetnacl',
    primitive: 'ed25519 sign.keyPair.fromSeed',
    field: ed25519.Point.Fn,
    operation: (seed) => bytes(nacl.sign.keyPair.fromSeed(seed).publicKey),
    nobleOperation: (seed) => bytes(ed25519.getPublicKey(seed)),
    note: 'tweetnacl does not expose secp256k1 or p256; selected its Ed25519 seed-to-public-key operation.',
  });
}

function addWasmCrypto() {
  const wasmPath = join(here, 'node_modules', 'wasm-crypto', 'build', 'optimized.wasm');
  if (!existsSync(wasmPath)) {
    skipped.push({
      library: 'wasm-crypto',
      reason:
        'package contains AssemblyScript sources but no build/*.wasm artifact or installed assemblyscript compiler',
    });
    return;
  }
  skipped.push({
    library: 'wasm-crypto',
    reason: 'wasm artifact unexpectedly exists; adapter not implemented',
  });
}

function loadSjclWithEcc(): any {
  const core = join(here, 'node_modules', 'sjcl', 'core');
  const context = { console };
  vm.createContext(context);
  for (const file of ['sjcl.js', 'bitArray.js', 'bn.js', 'codecBytes.js', 'ecc.js']) {
    vm.runInContext(readFileSync(join(core, file), 'utf8'), context, { filename: file });
  }
  return (context as any).sjcl;
}

function crossTestBenches() {
  console.log('# cross-test noble-curves');
  for (const bench of benches) {
    for (const scalar of crossTestScalars(bench.field)) {
      const secretKey = bytes(bench.field.toBytes(scalar));
      const actual = bench.operation(secretKey);
      const expected = bench.nobleOperation(secretKey);
      if (!equalBytes(actual, expected)) {
        throw new Error(
          `${bench.library} ${bench.primitive} cross-test failed for scalar=${scalar}: ` +
            `${Buffer.from(actual).toString('hex')} != ${Buffer.from(expected).toString('hex')}`
        );
      }
    }
    console.log(`ok ${bench.library} ${bench.primitive}`);
  }
}

function crossTestScalars(field: ScalarFieldLike): bigint[] {
  const order = field.ORDER;
  return [1n, 2n, 3n, 123n, order >> 1n, order - 2n, order - 1n];
}

function sjclCompressedPoint(sjcl: any, point: any): Bytes {
  const x = leftPadBytes(sjcl.codec.bytes.fromBits(point.x.toBits()), 32);
  const y = leftPadBytes(sjcl.codec.bytes.fromBits(point.y.toBits()), 32);
  const out = new Uint8Array(33);
  out[0] = y[y.length - 1] & 1 ? 0x03 : 0x02;
  out.set(x, 1);
  return out as Bytes;
}

function sampleCount(): number {
  const value = process.env.CT_SAMPLES;
  if (value === undefined) return 100;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count <= 0) throw new Error('invalid CT_SAMPLES');
  return count;
}

function bytes(value: Uint8Array | number[]): Bytes {
  return new Uint8Array(value) as Bytes;
}

function leftPadBytes(value: Uint8Array | number[], length: number): Bytes {
  if (value.length > length) throw new Error('value is too long');
  const out = new Uint8Array(length);
  out.set(value, length - value.length);
  return out as Bytes;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function hexToBytes(hex: string): Bytes {
  if (hex.length % 2 !== 0) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out as Bytes;
}

function bytesToNumberBE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
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
  for (const test of result.tests) if (test.t > max) max = test.t;
  return max;
}

function fmtNs(ns: number): string {
  return `${(ns / 1000).toFixed(0)}us`;
}

function pad(value: string, length: number): string {
  return value.padEnd(length);
}

function fmtStatus(failed: boolean): string {
  return failed ? 'x' : 'ok';
}
