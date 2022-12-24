/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { weierstrass, JacobianPointType } from '@noble/curves/weierstrass';
import * as cutils from '@noble/curves/utils';
import { Fp } from '@noble/curves/modular';
import { getHash } from './_shortw_utils.js';

type JacobianPoint = JacobianPointType<bigint>;
// Stark-friendly elliptic curve
// https://docs.starkware.co/starkex/stark-curve.html

const CURVE_N = BigInt(
  '3618502788666131213697322783095070105526743751716087489154079457884512865583'
);
const nBitLength = 252;
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
  truncateHash: (hash: Uint8Array, truncateOnly = false): bigint => {
    // TODO: cleanup, ugly code
    // Fix truncation
    if (!truncateOnly) {
      let hashS = bytesToNumber0x(hash).toString(16);
      if (hashS.length === 63) {
        hashS += '0';
        hash = hexToBytes0x(hashS);
      }
    }
    // Truncate zero bytes on left (compat with elliptic)
    while (hash[0] === 0) hash = hash.subarray(1);
    const byteLength = hash.length;
    const delta = byteLength * 8 - nBitLength; // size of curve.n (252 bits)
    let h = hash.length ? bytesToNumber0x(hash) : 0n;
    if (delta > 0) h = h >> BigInt(delta);
    if (!truncateOnly && h >= CURVE_N) h -= CURVE_N;
    return h;
  },
});

// Custom Starknet type conversion functions that can handle 0x and unpadded hex
function hexToBytes0x(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
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
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
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

function sign0x(msgHash: Hex, privKey: Hex, opts: any) {
  if (typeof privKey === 'string') privKey = strip0x(privKey).padStart(64, '0');
  return starkCurve.sign(ensureBytes0x(msgHash), normalizePrivateKey(privKey), opts);
}
function verify0x(signature: Hex, msgHash: Hex, pubKey: Hex) {
  const sig = signature instanceof Signature ? signature : ensureBytes0x(signature);
  return starkCurve.verify(sig, ensureBytes0x(msgHash), ensureBytes0x(pubKey));
}

const { CURVE, Point, JacobianPoint, Signature } = starkCurve;
export const utils = starkCurve.utils;
export {
  CURVE,
  Point,
  Signature,
  JacobianPoint,
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
  return bytesToNumber0x(sha256(cutils.concatBytes(key, hexToBytes0x(indexHex))));
}

export function grindKey(seed: Hex) {
  const _seed = ensureBytes0x(seed);
  const sha256mask = 2n ** 256n;
  const limit = sha256mask - starkCurve.utils.mod(sha256mask, starkCurve.CURVE.n);
  for (let i = 0; ; i++) {
    const key = hashKeyWithIndex(_seed, i);
    // key should be in [0, limit)
    if (key < limit) return starkCurve.utils.mod(key, starkCurve.CURVE.n).toString(16);
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
  const layerNum = int31(bytesToNumber0x(sha256(layer)));
  const applicationNum = int31(bytesToNumber0x(sha256(application)));
  const eth = hexToNumber0x(ethereumAddress);
  return `m/2645'/${layerNum}'/${applicationNum}'/${int31(eth)}'/${int31(eth >> 31n)}'/${index}`;
}

// https://docs.starkware.co/starkex/pedersen-hash-function.html
const PEDERSEN_POINTS = [
  new Point(
    2089986280348253421170679821480865132823066470938446095505822317253594081284n,
    1713931329540660377023406109199410414810705867260802078187082345529207694986n
  ),
  new Point(
    996781205833008774514500082376783249102396023663454813447423147977397232763n,
    1668503676786377725805489344771023921079126552019160156920634619255970485781n
  ),
  new Point(
    2251563274489750535117886426533222435294046428347329203627021249169616184184n,
    1798716007562728905295480679789526322175868328062420237419143593021674992973n
  ),
  new Point(
    2138414695194151160943305727036575959195309218611738193261179310511854807447n,
    113410276730064486255102093846540133784865286929052426931474106396135072156n
  ),
  new Point(
    2379962749567351885752724891227938183011949129833673362440656643086021394946n,
    776496453633298175483985398648758586525933812536653089401905292063708816422n
  ),
];
// for (const p of PEDERSEN_POINTS) p._setWindowSize(8);
const PEDERSEN_POINTS_JACOBIAN = PEDERSEN_POINTS.map(JacobianPoint.fromAffine);

function pedersenPrecompute(p1: JacobianPoint, p2: JacobianPoint): JacobianPoint[] {
  const out: JacobianPoint[] = [];
  let p = p1;
  for (let i = 0; i < 248; i++) {
    out.push(p);
    p = p.double();
  }
  p = p2;
  for (let i = 0; i < 4; i++) {
    out.push(p);
    p = p.double();
  }
  return out;
}
const PEDERSEN_POINTS1 = pedersenPrecompute(
  PEDERSEN_POINTS_JACOBIAN[1],
  PEDERSEN_POINTS_JACOBIAN[2]
);
const PEDERSEN_POINTS2 = pedersenPrecompute(
  PEDERSEN_POINTS_JACOBIAN[3],
  PEDERSEN_POINTS_JACOBIAN[4]
);

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

function pedersenSingle(point: JacobianPoint, value: PedersenArg, constants: JacobianPoint[]) {
  let x = pedersenArg(value);
  for (let j = 0; j < 252; j++) {
    const pt = constants[j];
    if (pt.x === point.x) throw new Error('Same point');
    if ((x & 1n) !== 0n) point = point.add(pt);
    x >>= 1n;
  }
  return point;
}

// shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
export function pedersen(x: PedersenArg, y: PedersenArg) {
  let point: JacobianPoint = PEDERSEN_POINTS_JACOBIAN[0];
  point = pedersenSingle(point, x, PEDERSEN_POINTS1);
  point = pedersenSingle(point, y, PEDERSEN_POINTS2);
  return bytesToHexEth(point.toAffine().toRawBytes(true).slice(1));
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

const MASK_250 = 2n ** 250n - 1n;
export const keccak = (data: Uint8Array) => bytesToNumber0x(keccak_256(data)) & MASK_250;
