import compare from '@paulmillr/jsbt/bench-compare.js';
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { edwards } from '../../src/abstract/edwards.ts';
import { weierstrass } from '../../src/abstract/weierstrass.ts';
import { ed25519 } from '../../src/ed25519.ts';
import { p256, p521 } from '../../src/nist.ts';
import { secp256k1 } from '../../src/secp256k1.ts';

type Bytes = Uint8Array<ArrayBuffer>;
type BenchCase = () => unknown;

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const iterations = envInt('BENCH_ITERATIONS', 10);
let sink = 0;

const secpScalar = scalarBytes(secp256k1.Point.Fn);
const p256Scalar = scalarBytes(p256.Point.Fn);
const p521Scalar = scalarBytes(p521.Point.Fn);
const edScalar = scalarBytes(ed25519.Point.Fn);
const edSeed = new Uint8Array(32).fill(0).map((_, i) => i + 1) as Bytes;

const nobleSecpW8 = nobleWeierstrass(secp256k1.Point, 8);
const nobleSecpComb10 = nobleWeierstrass(secp256k1.Point, 10);
const nobleP256W8 = nobleWeierstrass(p256.Point, 8);
const nobleP256Comb10 = nobleWeierstrass(p256.Point, 10);
const nobleP521W8 = nobleWeierstrass(p521.Point, 8);
const nobleP521Comb10 = nobleWeierstrass(p521.Point, 10);
const nobleEdW8 = nobleEdwards(8);
const nobleEdComb10 = nobleEdwards(10);

const secpCases: Record<string, BenchCase> = {
  'noble wNAF W=8': () => consume(nobleMul(nobleSecpW8, secpScalar, true)),
  'noble default comb W=10': () => consume(nobleMul(nobleSecpComb10, secpScalar, true)),
  'secp256k1 native': secp256k1Native(),
  'elliptic': ellipticSecp256k1(),
  'ecurve': ecurveSecp256k1(),
  'sjcl': sjclSecp256k1(),
};

const p256Cases: Record<string, BenchCase> = {
  'noble wNAF W=8': () => consume(nobleMul(nobleP256W8, p256Scalar, true)),
  'noble default comb W=10': () => consume(nobleMul(nobleP256Comb10, p256Scalar, true)),
  'ecc-jsbn': eccJsbnP256(),
};

const edScalarCases: Record<string, BenchCase> = {
  'noble wNAF W=8': () => consume(nobleMul(nobleEdW8, edScalar)),
  'noble default comb W=10': () => consume(nobleMul(nobleEdComb10, edScalar)),
};

const p521Cases: Record<string, BenchCase> = {
  'noble wNAF W=8': () => consume(nobleMul(nobleP521W8, p521Scalar, true)),
  'noble default comb W=10': () => consume(nobleMul(nobleP521Comb10, p521Scalar, true)),
};

const edSeedCases: Record<string, BenchCase> = {
  'noble ed25519.getPublicKey': () => consume(ed25519.getPublicKey(edSeed)),
  'tweetnacl sign.keyPair.fromSeed': tweetNaclEd25519(),
};

checkCases('secp256k1 scalar-to-public', secpCases);
checkCases('p256 scalar-to-public', p256Cases);
checkCases('ed25519 scalar-to-public', edScalarCases);
checkCases('p521 scalar-to-public', p521Cases);
checkCases('ed25519 seed-to-public', edSeedCases);

await compare(
  'third-party scalar-to-public performance',
  {},
  {
    'secp256k1 scalar-to-public': secpCases,
    'p256 scalar-to-public': p256Cases,
    'ed25519 scalar-to-public': edScalarCases,
    'p521 scalar-to-public': p521Cases,
    'ed25519 seed-to-public': edSeedCases,
  },
  {
    libraryDimensions: ['suite', 'name'],
    dimensions: ['suite', 'name'],
    iterations,
    format: 'table',
  }
);

if (!existsSync(join(here, 'node_modules', 'wasm-crypto', 'build', 'optimized.wasm')))
  console.log('\n# skipped wasm-crypto: package has no build/optimized.wasm artifact');
console.log(`# sink=${sink}`);

function nobleWeierstrass(source: typeof secp256k1.Point, W: number) {
  const Point = weierstrass(source.CURVE(), { Fp: source.Fp, Fn: source.Fn });
  Point.BASE.precompute(W, false);
  return Point;
}

function nobleEdwards(W: number) {
  const Point = edwards(ed25519.Point.CURVE(), {
    Fp: ed25519.Point.Fp,
    Fn: ed25519.Point.Fn,
  });
  Point.BASE.precompute(W, false);
  return Point;
}

function nobleMul(Point: any, scalarBytes: Bytes, compressed?: boolean): Bytes {
  const scalar = Point.Fn.fromBytes(scalarBytes);
  return bytes(Point.BASE.multiply(scalar).toBytes(compressed));
}

function secp256k1Native(): BenchCase {
  const lib = require('secp256k1');
  return () => consume(bytes(lib.publicKeyCreate(Buffer.from(secpScalar), true)));
}

function ellipticSecp256k1(): BenchCase {
  const elliptic = require('elliptic');
  const ec = new elliptic.ec('secp256k1');
  const hex = Buffer.from(secpScalar).toString('hex');
  return () => consume(bytes(ec.g.mul(hex).encodeCompressed()));
}

function ecurveSecp256k1(): BenchCase {
  const ecurve = require('ecurve');
  const bigi = require('bigi');
  const curve = ecurve.getCurveByName('secp256k1');
  const scalar = bigi.fromBuffer(Buffer.from(secpScalar));
  return () => consume(bytes(curve.G.multiply(scalar).getEncoded(true)));
}

function sjclSecp256k1(): BenchCase {
  const sjcl = loadSjclWithEcc();
  const curve = sjcl.ecc.curves.k256;
  const scalar = new sjcl.bn(`0x${Buffer.from(secpScalar).toString('hex')}`);
  return () => consume(sjclCompressedPoint(sjcl, curve.G.mult(scalar)));
}

function eccJsbnP256(): BenchCase {
  const ecc = require('ecc-jsbn');
  const { BigInteger } = require('jsbn');
  const curve = ecc.ECCurves.secp256r1();
  const scalar = new BigInteger(Buffer.from(p256Scalar).toString('hex'), 16);
  return () => {
    const point = curve.getG().multiply(scalar);
    return consume(hexToBytes(curve.getCurve().encodeCompressedPointHex(point)));
  };
}

function tweetNaclEd25519(): BenchCase {
  const nacl = require('tweetnacl');
  return () => consume(bytes(nacl.sign.keyPair.fromSeed(edSeed).publicKey));
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

function sjclCompressedPoint(sjcl: any, point: any): Bytes {
  const x = leftPadBytes(sjcl.codec.bytes.fromBits(point.x.toBits()), 32);
  const y = leftPadBytes(sjcl.codec.bytes.fromBits(point.y.toBits()), 32);
  const out = new Uint8Array(33);
  out[0] = y[y.length - 1] & 1 ? 0x03 : 0x02;
  out.set(x, 1);
  return out as Bytes;
}

function checkCases(title: string, cases: Record<string, BenchCase>): void {
  const entries = Object.entries(cases);
  const expected = entries[0][1]();
  for (const [name, fn] of entries.slice(1)) {
    const actual = fn();
    if (!sameBytes(actual, expected)) throw new Error(`${title}: ${name} produced wrong output`);
  }
}

function scalarBytes(field: { ORDER: bigint; BYTES: number; toBytes: (num: bigint) => Uint8Array }) {
  const hex = 'a5'.repeat(field.BYTES);
  const scalar = (BigInt(`0x${hex}`) % (field.ORDER - 1n)) + 1n;
  return bytes(field.toBytes(scalar));
}

function consume(value: unknown): unknown {
  if (value instanceof Uint8Array) sink ^= value[0];
  return value;
}

function sameBytes(a: unknown, b: unknown): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
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

function hexToBytes(hex: string): Bytes {
  if (hex.length % 2 !== 0) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out as Bytes;
}

function envInt(name: string, fallback: number): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`invalid ${name}`);
  return parsed;
}
