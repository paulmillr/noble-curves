import compare from '@paulmillr/jsbt/bench-compare.js';
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
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
const ecdsaMsgHash = bytes(Array.from({ length: 32 }, (_, i) => 0x31 + i));
const secpSig = bytes(secp256k1.sign(ecdsaMsgHash, secpScalar, { prehash: false }));
const secpPub = bytes(secp256k1.getPublicKey(secpScalar, true));
const secpPubFull = bytes(secp256k1.getPublicKey(secpScalar, false));
const p256Sig = bytes(p256.sign(ecdsaMsgHash, p256Scalar, { prehash: false }));
const p256Pub = bytes(p256.getPublicKey(p256Scalar, true));
const p256PubFull = bytes(p256.getPublicKey(p256Scalar, false));

const secpCases: Record<string, BenchCase> = {
  noble: () => consume(nobleMul(secp256k1.Point, secpScalar, true)),
  'secp256k1 native': secp256k1Native(),
  elliptic: ellipticSecp256k1(),
  ecurve: ecurveSecp256k1(),
  sjcl: sjclSecp256k1(),
};

const p256Cases: Record<string, BenchCase> = {
  noble: () => consume(nobleMul(p256.Point, p256Scalar, true)),
  'ecc-jsbn': eccJsbnP256(),
};

const secpVerifyCases: Record<string, BenchCase> = {
  noble: () => consumeBool(nobleVerify(secp256k1, secpSig, secpPub)),
  'secp256k1 native': secp256k1NativeVerify(),
  elliptic: ellipticVerify('secp256k1', secpSig, secpPub),
  ecurve: ecurveSecp256k1Verify(),
  sjcl: sjclVerify('k256', secpSig, secpPubFull),
};

const p256VerifyCases: Record<string, BenchCase> = {
  noble: () => consumeBool(nobleVerify(p256, p256Sig, p256Pub)),
  elliptic: ellipticVerify('p256', p256Sig, p256Pub),
  'ecc-jsbn': eccJsbnP256Verify(),
  sjcl: sjclVerify('c256', p256Sig, p256PubFull),
};

const edScalarCases: Record<string, BenchCase> = {
  noble: () => consume(nobleMul(ed25519.Point, edScalar)),
};

const p521Cases: Record<string, BenchCase> = {
  noble: () => consume(nobleMul(p521.Point, p521Scalar, true)),
};

const edSeedCases: Record<string, BenchCase> = {
  'noble ed25519.getPublicKey': () => consume(ed25519.getPublicKey(edSeed)),
  'tweetnacl sign.keyPair.fromSeed': tweetNaclEd25519(),
};

checkCases('secp256k1 scalar-to-public', secpCases);
checkCases('p256 scalar-to-public', p256Cases);
checkTrueCases('secp256k1 ecdsa verify', secpVerifyCases);
checkTrueCases('p256 ecdsa verify', p256VerifyCases);
checkCases('ed25519 scalar-to-public', edScalarCases);
checkCases('p521 scalar-to-public', p521Cases);
checkCases('ed25519 seed-to-public', edSeedCases);

await compare(
  'third-party EC performance',
  {},
  {
    'secp256k1 scalar-to-public': secpCases,
    'p256 scalar-to-public': p256Cases,
    'secp256k1 ecdsa verify': secpVerifyCases,
    'p256 ecdsa verify': p256VerifyCases,
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

function nobleMul(Point: any, scalarBytes: Bytes, compressed?: boolean): Bytes {
  const scalar = Point.Fn.fromBytes(scalarBytes);
  return bytes(Point.BASE.multiply(scalar).toBytes(compressed));
}

function nobleVerify(api: any, signature: Bytes, publicKey: Bytes): boolean {
  return api.verify(signature, ecdsaMsgHash, publicKey, { prehash: false });
}

function secp256k1Native(): BenchCase {
  const lib = require('secp256k1');
  return () => consume(bytes(lib.publicKeyCreate(Buffer.from(secpScalar), true)));
}

function secp256k1NativeVerify(): BenchCase {
  const lib = require('secp256k1');
  const signature = Buffer.from(secpSig);
  const message = Buffer.from(ecdsaMsgHash);
  const publicKey = Buffer.from(secpPub);
  return () => consumeBool(lib.ecdsaVerify(signature, message, publicKey));
}

function ellipticSecp256k1(): BenchCase {
  const elliptic = require('elliptic');
  const ec = new elliptic.ec('secp256k1');
  const hex = Buffer.from(secpScalar).toString('hex');
  return () => consume(bytes(ec.g.mul(hex).encodeCompressed()));
}

function ellipticVerify(curveName: 'secp256k1' | 'p256', signatureBytes: Bytes, publicKey: Bytes) {
  const elliptic = require('elliptic');
  const ec = new elliptic.ec(curveName);
  const key = ec.keyFromPublic(Buffer.from(publicKey).toString('hex'), 'hex');
  const message = Buffer.from(ecdsaMsgHash).toString('hex');
  const signature = splitSigHex(signatureBytes);
  return () => consumeBool(key.verify(message, signature));
}

function ecurveSecp256k1(): BenchCase {
  const ecurve = require('ecurve');
  const bigi = require('bigi');
  const curve = ecurve.getCurveByName('secp256k1');
  const scalar = bigi.fromBuffer(Buffer.from(secpScalar));
  return () => consume(bytes(curve.G.multiply(scalar).getEncoded(true)));
}

function ecurveSecp256k1Verify(): BenchCase {
  const ecurve = require('ecurve');
  const bigi = require('bigi');
  const curve = ecurve.getCurveByName('secp256k1');
  const n = curve.n;
  const Q = ecurve.Point.decodeFrom(curve, Buffer.from(secpPubFull));
  const z = bigi.fromBuffer(Buffer.from(ecdsaMsgHash));
  const r = bigi.fromBuffer(Buffer.from(secpSig.subarray(0, 32)));
  const s = bigi.fromBuffer(Buffer.from(secpSig.subarray(32)));
  return () => {
    if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0)
      return consumeBool(false);
    const w = s.modInverse(n);
    const u1 = z.multiply(w).mod(n);
    const u2 = r.multiply(w).mod(n);
    const R = curve.G.multiplyTwo(u1, Q, u2);
    return consumeBool(!curve.isInfinity(R) && R.affineX.mod(n).equals(r));
  };
}

function sjclSecp256k1(): BenchCase {
  const sjcl = loadSjclWithEcc();
  const curve = sjcl.ecc.curves.k256;
  const scalar = new sjcl.bn(`0x${Buffer.from(secpScalar).toString('hex')}`);
  return () => consume(sjclCompressedPoint(sjcl, curve.G.mult(scalar)));
}

function sjclVerify(curveName: 'k256' | 'c256', signature: Bytes, publicKey: Bytes): BenchCase {
  const sjcl = loadSjclWithEcc();
  const curve = sjcl.ecc.curves[curveName];
  const point = curve.fromBits(sjcl.codec.bytes.toBits([...publicKey.subarray(1)]));
  const key = new sjcl.ecc.ecdsa.publicKey(curve, point);
  const hashBits = sjcl.codec.bytes.toBits([...ecdsaMsgHash]);
  const sigBits = sjcl.codec.bytes.toBits([...signature]);
  return () => consumeBool(key.verify(hashBits, sigBits) === true);
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

function eccJsbnP256Verify(): BenchCase {
  const ecc = require('ecc-jsbn');
  const { BigInteger } = require('jsbn');
  const params = ecc.ECCurves.secp256r1();
  const curve = params.getCurve();
  const n = params.getN();
  const Q = curve.decodePointHex(Buffer.from(p256PubFull).toString('hex'));
  const z = new BigInteger(Buffer.from(ecdsaMsgHash).toString('hex'), 16);
  const r = new BigInteger(Buffer.from(p256Sig.subarray(0, 32)).toString('hex'), 16);
  const s = new BigInteger(Buffer.from(p256Sig.subarray(32)).toString('hex'), 16);
  return () => {
    if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0)
      return consumeBool(false);
    const w = s.modInverse(n);
    const u1 = z.multiply(w).mod(n);
    const u2 = r.multiply(w).mod(n);
    const R = params.getG().multiplyTwo(u1, Q, u2);
    return consumeBool(!R.isInfinity() && R.getX().toBigInteger().mod(n).equals(r));
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

function checkTrueCases(title: string, cases: Record<string, BenchCase>): void {
  for (const [name, fn] of Object.entries(cases)) {
    if (fn() !== true) throw new Error(`${title}: ${name} failed`);
  }
}

function scalarBytes(field: {
  ORDER: bigint;
  BYTES: number;
  toBytes: (num: bigint) => Uint8Array;
}) {
  const hex = 'a5'.repeat(field.BYTES);
  const scalar = (BigInt(`0x${hex}`) % (field.ORDER - 1n)) + 1n;
  return bytes(field.toBytes(scalar));
}

function consume(value: unknown): unknown {
  if (value instanceof Uint8Array) sink ^= value[0];
  return value;
}

function consumeBool(value: boolean): boolean {
  sink ^= value ? 1 : 0;
  return value;
}

function splitSigHex(signature: Uint8Array) {
  const size = signature.length / 2;
  return {
    r: Buffer.from(signature.subarray(0, size)).toString('hex'),
    s: Buffer.from(signature.subarray(size)).toString('hex'),
  };
}

function sameBytes(a: unknown, b: unknown): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length)
    return false;
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
