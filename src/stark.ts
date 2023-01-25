/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { weierstrass, ProjectivePointType } from './abstract/weierstrass.js';
import * as cutils from './abstract/utils.js';
import { Fp, mod, Field, validateField } from './abstract/modular.js';
import { getHash } from './_shortw_utils.js';
import * as poseidon from './abstract/poseidon.js';
import { utf8ToBytes } from '@noble/hashes/utils';

type ProjectivePoint = ProjectivePointType<bigint>;
// Stark-friendly elliptic curve
// https://docs.starkware.co/starkex/stark-curve.html

const CURVE_N = BigInt(
  '3618502788666131213697322783095070105526743751716087489154079457884512865583'
);
const nBitLength = 252;
// Copy-pasted from weierstrass.ts
function bits2int(bytes: Uint8Array): bigint {
  const delta = bytes.length * 8 - nBitLength;
  const num = cutils.bytesToNumberBE(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
}
function bits2int_modN(bytes: Uint8Array): bigint {
  return mod(bits2int(bytes), CURVE_N);
}
export const starkCurve = weierstrass({
  // Params: a, b
  a: BigInt(1),
  b: BigInt('3141592653589793238462643383279502884197169399375105820974944592307816406665'),
  // Field over which we'll do calculations; 2n**251n + 17n * 2n**192n + 1n
  // There is no efficient sqrt for field (P%4==1)
  Fp: Fp(BigInt('0x800000000000011000000000000000000000000000000000000000000000001')),
  // Curve order, total count of valid points in the field.
  n: CURVE_N,
  nBitLength: nBitLength, // len(bin(N).replace('0b',''))
  // Base point (x, y) aka generator point
  Gx: BigInt('874739451078007766457464989774322083649278607533249481151382481072868806602'),
  Gy: BigInt('152666792071518830868575557812948353041420400780739481342941381225525861407'),
  h: BigInt(1),
  // Default options
  lowS: false,
  ...getHash(sha256),
  // Custom truncation routines for stark curve
  bits2int: (bytes: Uint8Array): bigint => {
    while (bytes[0] === 0) bytes = bytes.subarray(1);
    return bits2int(bytes);
  },
  bits2int_modN: (bytes: Uint8Array): bigint => {
    let hashS = cutils.bytesToNumberBE(bytes).toString(16);
    if (hashS.length === 63) {
      hashS += '0';
      bytes = hexToBytes0x(hashS);
    }
    // Truncate zero bytes on left (compat with elliptic)
    while (bytes[0] === 0) bytes = bytes.subarray(1);
    return bits2int_modN(bytes);
  },
});

// Custom Starknet type conversion functions that can handle 0x and unpadded hex
function hexToBytes0x(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new Error('hexToBytes: expected string, got ' + typeof hex);
  }
  hex = strip0x(hex);
  if (hex.length & 1) hex = '0' + hex; // padding
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex ' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}
function hexToNumber0x(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new Error('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  // TODO: strip vs no strip?
  return BigInt(`0x${strip0x(hex)}`);
}
function bytesToNumber0x(bytes: Uint8Array): bigint {
  return hexToNumber0x(cutils.bytesToHex(bytes));
}
function ensureBytes0x(hex: Hex): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes0x(hex);
}

function normalizePrivateKey(privKey: Hex) {
  return cutils.bytesToHex(ensureBytes0x(privKey)).padStart(32 * 2, '0');
}
function getPublicKey0x(privKey: Hex, isCompressed?: boolean) {
  return starkCurve.getPublicKey(normalizePrivateKey(privKey), isCompressed);
}
function getSharedSecret0x(privKeyA: Hex, pubKeyB: Hex) {
  return starkCurve.getSharedSecret(normalizePrivateKey(privKeyA), pubKeyB);
}

function sign0x(msgHash: Hex, privKey: Hex, opts?: any) {
  if (typeof privKey === 'string') privKey = strip0x(privKey).padStart(64, '0');
  return starkCurve.sign(ensureBytes0x(msgHash), normalizePrivateKey(privKey), opts);
}
function verify0x(signature: Hex, msgHash: Hex, pubKey: Hex) {
  const sig = signature instanceof Signature ? signature : ensureBytes0x(signature);
  return starkCurve.verify(sig, ensureBytes0x(msgHash), ensureBytes0x(pubKey));
}

const { CURVE, ProjectivePoint, Signature } = starkCurve;
export const utils = starkCurve.utils;
export {
  CURVE,
  Signature,
  ProjectivePoint,
  getPublicKey0x as getPublicKey,
  getSharedSecret0x as getSharedSecret,
  sign0x as sign,
  verify0x as verify,
};

const stripLeadingZeros = (s: string) => s.replace(/^0+/gm, '');
export const bytesToHexEth = (uint8a: Uint8Array): string =>
  `0x${stripLeadingZeros(cutils.bytesToHex(uint8a))}`;
export const strip0x = (hex: string) => hex.replace(/^0x/i, '');
export const numberToHexEth = (num: bigint | number) => `0x${num.toString(16)}`;

// We accept hex strings besides Uint8Array for simplicity
type Hex = Uint8Array | string;

// 1. seed generation
function hashKeyWithIndex(key: Uint8Array, index: number) {
  let indexHex = cutils.numberToHexUnpadded(index);
  if (indexHex.length & 1) indexHex = '0' + indexHex;
  return sha256Num(cutils.concatBytes(key, hexToBytes0x(indexHex)));
}

export function grindKey(seed: Hex) {
  const _seed = ensureBytes0x(seed);
  const sha256mask = 2n ** 256n;

  const limit = sha256mask - mod(sha256mask, CURVE_N);
  for (let i = 0; ; i++) {
    const key = hashKeyWithIndex(_seed, i);
    // key should be in [0, limit)
    if (key < limit) return mod(key, CURVE_N).toString(16);
  }
}

export function getStarkKey(privateKey: Hex) {
  return bytesToHexEth(getPublicKey0x(privateKey, true).slice(1));
}

export function ethSigToPrivate(signature: string) {
  signature = strip0x(signature.replace(/^0x/, ''));
  if (signature.length !== 130) throw new Error('Wrong ethereum signature');
  return grindKey(signature.substring(0, 64));
}

const MASK_31 = 2n ** 31n - 1n;
const int31 = (n: bigint) => Number(n & MASK_31);
export function getAccountPath(
  layer: string,
  application: string,
  ethereumAddress: string,
  index: number
) {
  const layerNum = int31(sha256Num(layer));
  const applicationNum = int31(sha256Num(application));
  const eth = hexToNumber0x(ethereumAddress);
  return `m/2645'/${layerNum}'/${applicationNum}'/${int31(eth)}'/${int31(eth >> 31n)}'/${index}`;
}

// https://docs.starkware.co/starkex/pedersen-hash-function.html
const PEDERSEN_POINTS_AFFINE = [
  new ProjectivePoint(
    2089986280348253421170679821480865132823066470938446095505822317253594081284n,
    1713931329540660377023406109199410414810705867260802078187082345529207694986n,
    1n
  ),
  new ProjectivePoint(
    996781205833008774514500082376783249102396023663454813447423147977397232763n,
    1668503676786377725805489344771023921079126552019160156920634619255970485781n,
    1n
  ),
  new ProjectivePoint(
    2251563274489750535117886426533222435294046428347329203627021249169616184184n,
    1798716007562728905295480679789526322175868328062420237419143593021674992973n,
    1n
  ),
  new ProjectivePoint(
    2138414695194151160943305727036575959195309218611738193261179310511854807447n,
    113410276730064486255102093846540133784865286929052426931474106396135072156n,
    1n
  ),
  new ProjectivePoint(
    2379962749567351885752724891227938183011949129833673362440656643086021394946n,
    776496453633298175483985398648758586525933812536653089401905292063708816422n,
    1n
  ),
];
// for (const p of PEDERSEN_POINTS) p._setWindowSize(8);
const PEDERSEN_POINTS = PEDERSEN_POINTS_AFFINE;

function pedersenPrecompute(p1: ProjectivePoint, p2: ProjectivePoint): ProjectivePoint[] {
  const out: ProjectivePoint[] = [];
  let p = p1;
  for (let i = 0; i < 248; i++) {
    out.push(p);
    p = p.double();
  }
  // NOTE: we cannot use wNAF here, because last 4 bits will require full 248 bits multiplication
  // We can add support for this to wNAF, but it will complicate wNAF.
  p = p2;
  for (let i = 0; i < 4; i++) {
    out.push(p);
    p = p.double();
  }
  return out;
}
const PEDERSEN_POINTS1 = pedersenPrecompute(PEDERSEN_POINTS[1], PEDERSEN_POINTS[2]);
const PEDERSEN_POINTS2 = pedersenPrecompute(PEDERSEN_POINTS[3], PEDERSEN_POINTS[4]);

type PedersenArg = Hex | bigint | number;
function pedersenArg(arg: PedersenArg): bigint {
  let value: bigint;
  if (typeof arg === 'bigint') value = arg;
  else if (typeof arg === 'number') {
    if (!Number.isSafeInteger(arg)) throw new Error(`Invalid pedersenArg: ${arg}`);
    value = BigInt(arg);
  } else value = bytesToNumber0x(ensureBytes0x(arg));
  // [0..Fp)
  if (!(0n <= value && value < starkCurve.CURVE.Fp.ORDER))
    throw new Error(`PedersenArg should be 0 <= value < CURVE.P: ${value}`);
  return value;
}

function pedersenSingle(point: ProjectivePoint, value: PedersenArg, constants: ProjectivePoint[]) {
  let x = pedersenArg(value);
  for (let j = 0; j < 252; j++) {
    const pt = constants[j];
    if (pt.px === point.px) throw new Error('Same point');
    if ((x & 1n) !== 0n) point = point.add(pt);
    x >>= 1n;
  }
  return point;
}

// shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
export function pedersen(x: PedersenArg, y: PedersenArg) {
  let point: ProjectivePoint = PEDERSEN_POINTS[0];
  point = pedersenSingle(point, x, PEDERSEN_POINTS1);
  point = pedersenSingle(point, y, PEDERSEN_POINTS2);
  return bytesToHexEth(point.toRawBytes(true).slice(1));
}

export function hashChain(data: PedersenArg[], fn = pedersen) {
  if (!Array.isArray(data) || data.length < 1)
    throw new Error('data should be array of at least 1 element');
  if (data.length === 1) return numberToHexEth(pedersenArg(data[0]));
  return Array.from(data)
    .reverse()
    .reduce((acc, i) => fn(i, acc));
}
// Same as hashChain, but computes hash even for single element and order is not revesed
export const computeHashOnElements = (data: PedersenArg[], fn = pedersen) =>
  [0, ...data, data.length].reduce((x, y) => fn(x, y));

const MASK_250 = cutils.bitMask(250);
export const keccak = (data: Uint8Array): bigint => bytesToNumber0x(keccak_256(data)) & MASK_250;
const sha256Num = (data: Uint8Array | string): bigint => cutils.bytesToNumberBE(sha256(data));

// Poseidon hash
export const Fp253 = Fp(
  BigInt('14474011154664525231415395255581126252639794253786371766033694892385558855681')
); // 2^253 + 2^199 + 1
export const Fp251 = Fp(
  BigInt('3618502788666131213697322783095070105623107215331596699973092056135872020481')
); // 2^251 + 17 * 2^192 + 1

function poseidonRoundConstant(Fp: Field<bigint>, name: string, idx: number) {
  const val = Fp.fromBytes(sha256(utf8ToBytes(`${name}${idx}`)));
  return Fp.create(val);
}

// NOTE: doesn't check eiginvalues and possible can create unsafe matrix. But any filtration here will break compatibility with starknet
// Please use only if you really know what you doing.
// https://eprint.iacr.org/2019/458.pdf Section 2.3 (Avoiding Insecure Matrices)
export function _poseidonMDS(Fp: Field<bigint>, name: string, m: number, attempt = 0) {
  const x_values: bigint[] = [];
  const y_values: bigint[] = [];
  for (let i = 0; i < m; i++) {
    x_values.push(poseidonRoundConstant(Fp, `${name}x`, attempt * m + i));
    y_values.push(poseidonRoundConstant(Fp, `${name}y`, attempt * m + i));
  }
  if (new Set([...x_values, ...y_values]).size !== 2 * m)
    throw new Error('X and Y values are not distinct');
  return x_values.map((x) => y_values.map((y) => Fp.invert(Fp.sub(x, y))));
}

const MDS_SMALL = [
  [3, 1, 1],
  [1, -1, 1],
  [1, 1, -2],
].map((i) => i.map(BigInt));

export type PoseidonOpts = {
  Fp: Field<bigint>;
  rate: number;
  capacity: number;
  roundsFull: number;
  roundsPartial: number;
};

export function poseidonBasic(opts: PoseidonOpts, mds: bigint[][]) {
  validateField(opts.Fp);
  if (!Number.isSafeInteger(opts.rate) || !Number.isSafeInteger(opts.capacity))
    throw new Error(`Wrong poseidon opts: ${opts}`);
  const m = opts.rate + opts.capacity;
  const rounds = opts.roundsFull + opts.roundsPartial;
  const roundConstants = [];
  for (let i = 0; i < rounds; i++) {
    const row = [];
    for (let j = 0; j < m; j++) row.push(poseidonRoundConstant(opts.Fp, 'Hades', m * i + j));
    roundConstants.push(row);
  }
  return poseidon.poseidon({
    ...opts,
    t: m,
    sboxPower: 3,
    reversePartialPowIdx: true, // Why?!
    mds,
    roundConstants,
  });
}

export function poseidonCreate(opts: PoseidonOpts, mdsAttempt = 0) {
  const m = opts.rate + opts.capacity;
  if (!Number.isSafeInteger(mdsAttempt)) throw new Error(`Wrong mdsAttempt=${mdsAttempt}`);
  return poseidonBasic(opts, _poseidonMDS(opts.Fp, 'HadesMDS', m, mdsAttempt));
}

export const poseidonSmall = poseidonBasic(
  { Fp: Fp251, rate: 2, capacity: 1, roundsFull: 8, roundsPartial: 83 },
  MDS_SMALL
);

export function poseidonHash(x: bigint, y: bigint, fn = poseidonSmall) {
  return fn([x, y, 2n])[0];
}
