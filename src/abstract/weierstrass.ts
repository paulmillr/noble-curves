/**
 * Short Weierstrass curve methods. The formula is: y² = x³ + ax + b.
 *
 * ### Design rationale for types
 *
 * * Interaction between classes from different curves should fail:
 *   `k256.Point.BASE.add(p256.Point.BASE)`
 * * For this purpose we want to use `instanceof` operator, which is fast and works during runtime
 * * Different calls of `curve()` would return different classes -
 *   `curve(params) !== curve(params)`: if somebody decided to monkey-patch their curve,
 *   it won't affect others
 *
 * TypeScript can't infer types for classes created inside a function. Classes is one instance
 * of nominative types in TypeScript and interfaces only check for shape, so it's hard to create
 * unique type for every function call.
 *
 * We can use generic types via some param, like curve opts, but that would:
 *     1. Enable interaction between `curve(params)` and `curve(params)` (curves of same params)
 *     which is hard to debug.
 *     2. Params can be generic and we can't enforce them to be constant value:
 *     if somebody creates curve from non-constant params,
 *     it would be allowed to interact with other curves with non-constant params
 *
 * @todo https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-7.html#unique-symbol
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { hmac } from '@noble/hashes/hmac.js';
import { ahash } from '@noble/hashes/utils';
import {
  _validateObject,
  abool,
  abytes,
  aInRange,
  bitLen,
  bitMask,
  bytesToHex,
  bytesToNumberBE,
  concatBytes,
  createHmacDrbg,
  ensureBytes,
  hexToBytes,
  inRange,
  isBytes,
  memoized,
  numberToHexUnpadded,
  randomBytes,
  type CHash,
  type Hex,
  type PrivKey,
} from '../utils.ts';
import {
  _createCurveFields,
  mulEndoUnsafe,
  negateCt,
  normalizeZ,
  pippenger,
  wNAF,
  type AffinePoint,
  type BasicCurve,
  type CurveInfo,
  type CurvePoint,
  type CurvePointCons,
} from './curve.ts';
import {
  Field,
  FpInvertBatch,
  getMinHashLength,
  mapHashToField,
  validateField,
  type IField,
  type NLength,
} from './modular.ts';

export type { AffinePoint };
export type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;

type EndoBasis = [[bigint, bigint], [bigint, bigint]];
/**
 * When Weierstrass curve has `a=0`, it becomes Koblitz curve.
 * Koblitz curves allow using **efficiently-computable GLV endomorphism ψ**.
 * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
 * For precomputed wNAF it trades off 1/2 init time & 1/3 ram for 20% perf hit.
 *
 * Endomorphism consists of beta, lambda and splitScalar:
 *
 * 1. GLV endomorphism ψ transforms a point: `P = (x, y) ↦ ψ(P) = (β·x mod p, y)`
 * 2. GLV scalar decomposition transforms a scalar: `k ≡ k₁ + k₂·λ (mod n)`
 * 3. Then these are combined: `k·P = k₁·P + k₂·ψ(P)`
 * 4. Two 128-bit point-by-scalar multiplications + one point addition is faster than
 *    one 256-bit multiplication.
 *
 * where
 * * beta: β ∈ Fₚ with β³ = 1, β ≠ 1
 * * lambda: λ ∈ Fₙ with λ³ = 1, λ ≠ 1
 * * splitScalar decomposes k ↦ k₁, k₂, by using reduced basis vectors.
 *   Gauss lattice reduction calculates them from initial basis vectors `(n, 0), (-λ, 0)`
 *
 * Check out `test/misc/endomorphism.js` and
 * [gist](https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066).
 */
export type EndomorphismOpts = {
  beta: bigint;
  basises?: EndoBasis;
  splitScalar?: (k: bigint) => { k1neg: boolean; k1: bigint; k2neg: boolean; k2: bigint };
};
export type BasicWCurve<T> = BasicCurve<T> & {
  // Params: a, b
  a: T;
  b: T;

  // Optional params
  allowedPrivateKeyLengths?: readonly number[]; // for P521
  wrapPrivateKey?: boolean; // bls12-381 requires mod(n) instead of rejecting keys >= n
  endo?: EndomorphismOpts;
  // When a cofactor != 1, there can be an effective methods to:
  // 1. Determine whether a point is torsion-free
  isTorsionFree?: (c: WeierstrassPointCons<T>, point: WeierstrassPoint<T>) => boolean;
  // 2. Clear torsion component
  clearCofactor?: (c: WeierstrassPointCons<T>, point: WeierstrassPoint<T>) => WeierstrassPoint<T>;
};

// We construct basis in such way that den is always positive and equals n, but num sign depends on basis (not on secret value)
const divNearest = (num: bigint, den: bigint) => (num + (num >= 0 ? den : -den) / _2n) / den;

export type ScalarEndoParts = { k1neg: boolean; k1: bigint; k2neg: boolean; k2: bigint };

/**
 * Splits scalar for GLV endomorphism.
 */
export function _splitEndoScalar(k: bigint, basis: EndoBasis, n: bigint): ScalarEndoParts {
  // Split scalar into two such that part is ~half bits: `abs(part) < sqrt(N)`
  // Since part can be negative, we need to do this on point.
  // TODO: verifyScalar function which consumes lambda
  const [[a1, b1], [a2, b2]] = basis;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  // |k1|/|k2| is < sqrt(N), but can be negative.
  // If we do `k1 mod N`, we'll get big scalar (`> sqrt(N)`): so, we do cheaper negation instead.
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n;
  const k2neg = k2 < _0n;
  if (k1neg) k1 = -k1;
  if (k2neg) k2 = -k2;
  // Double check that resulting scalar less than half bits of N: otherwise wNAF will fail.
  // This should only happen on wrong basises. Also, math inside is too complex and I don't trust it.
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n; // Half bits of N
  if (k1 < _0n || k1 >= MAX_NUM || k2 < _0n || k2 >= MAX_NUM) {
    throw new Error('splitScalar (endomorphism): failed, k=' + k);
  }
  return { k1neg, k1, k2neg, k2 };
}

export type ECDSASigFormat = 'compact' | 'der';
export type Entropy = Hex | boolean;
export type SignOpts = Partial<{
  lowS: boolean;
  extraEntropy: Entropy;
  prehash: boolean;
  format: ECDSASigFormat | 'js';
}>;
export type VerOpts = Partial<{
  lowS: boolean;
  prehash: boolean;
  format: ECDSASigFormat | 'js' | undefined;
}>;

function validateSigVerOpts(opts: SignOpts | VerOpts) {
  if (opts.lowS !== undefined) abool('lowS', opts.lowS);
  if (opts.prehash !== undefined) abool('prehash', opts.prehash);
}

/** Instance methods for 3D XYZ projective points. */
export interface WeierstrassPoint<T> extends CurvePoint<T, WeierstrassPoint<T>> {
  /** projective X coordinate. Different from affine x. */
  readonly X: T;
  /** projective Y coordinate. Different from affine y. */
  readonly Y: T;
  /** projective z coordinate */
  readonly Z: T;
  /** affine x coordinate. Different from projective X. */
  get x(): T;
  /** affine y coordinate. Different from projective Y. */
  get y(): T;
  /** Encodes point using IEEE P1363 (DER) encoding. First byte is 2/3/4. Default = isCompressed. */
  toBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;

  /** @deprecated use .X */
  readonly px: T;
  /** @deprecated use .Y */
  readonly py: T;
  /** @deprecated use .Z */
  readonly pz: T;
  /** @deprecated use `toBytes` */
  toRawBytes(isCompressed?: boolean): Uint8Array;
  /** @deprecated use `multiplyUnsafe` */
  multiplyAndAddUnsafe(
    Q: WeierstrassPoint<T>,
    a: bigint,
    b: bigint
  ): WeierstrassPoint<T> | undefined;
  /** @deprecated use `p.y % 2n === 0n` */
  hasEvenY(): boolean;
  /** @deprecated use `p.precompute(windowSize)` */
  _setWindowSize(windowSize: number): void;
}

/** Static methods for 3D XYZ projective points. */
export interface WeierstrassPointCons<T> extends CurvePointCons<T, WeierstrassPoint<T>> {
  /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
  new (X: T, Y: T, Z: T): WeierstrassPoint<T>;
  /** @deprecated use `Point.BASE.multiply(Point.Fn.fromBytes(privateKey))` */
  fromPrivateKey(privateKey: PrivKey): WeierstrassPoint<T>;
  /** @deprecated use `import { normalizeZ } from '@noble/curves/abstract/curve.js';` */
  normalizeZ(points: WeierstrassPoint<T>[]): WeierstrassPoint<T>[];
  /** @deprecated use `import { pippenger } from '@noble/curves/abstract/curve.js';` */
  msm(points: WeierstrassPoint<T>[], scalars: bigint[]): WeierstrassPoint<T>;
}

/** @deprecated use WeierstrassPoint */
export type ProjPointType<T> = WeierstrassPoint<T>;
/** @deprecated use WeierstrassPointCons */
export type ProjConstructor<T> = WeierstrassPointCons<T>;

// TODO: remove
export type CurvePointsType<T> = BasicWCurve<T> & {
  fromBytes?: (bytes: Uint8Array) => AffinePoint<T>;
  toBytes?: (
    c: WeierstrassPointCons<T>,
    point: WeierstrassPoint<T>,
    isCompressed: boolean
  ) => Uint8Array;
};

// LegacyWeierstrassOpts
export type CurvePointsTypeWithLength<T> = Readonly<CurvePointsType<T> & Partial<NLength>>;

// LegacyWeierstrass
export type CurvePointsRes<T> = {
  Point: WeierstrassPointCons<T>;

  /** @deprecated the property will be removed in next release */
  CURVE: CurvePointsType<T>;
  /** @deprecated use `Point` */
  ProjectivePoint: WeierstrassPointCons<T>;
  /** @deprecated use `Point.Fn.fromBytes(privateKey)` */
  normPrivateKeyToScalar: (key: PrivKey) => bigint;
  /** @deprecated */
  weierstrassEquation: (x: T) => T;
  /** @deprecated use `Point.Fn.isValidNot0(num)` */
  isWithinCurveOrder: (num: bigint) => boolean;
};

// Aliases to legacy types
// export type CurveType = LegacyECDSAOpts;
// export type CurveFn = LegacyECDSA;
// export type CurvePointsRes<T> = LegacyWeierstrass<T>;
// export type CurvePointsType<T> = LegacyWeierstrassOpts<T>;
// export type CurvePointsTypeWithLength<T> = LegacyWeierstrassOpts<T>;
// export type BasicWCurve<T> = LegacyWeierstrassOpts<T>;

/**
 * Weierstrass curve options.
 *
 * * p: prime characteristic (order) of finite field, in which arithmetics is done
 * * n: order of prime subgroup a.k.a total amount of valid curve points
 * * h: cofactor, usually 1. h*n is group order; n is subgroup order
 * * a: formula param, must be in field of p
 * * b: formula param, must be in field of p
 * * Gx: x coordinate of generator point a.k.a. base point
 * * Gy: y coordinate of generator point
 */
export type WeierstrassOpts<T> = Readonly<{
  p: bigint;
  n: bigint;
  h: bigint;
  a: T;
  b: T;
  Gx: T;
  Gy: T;
}>;

// When a cofactor != 1, there can be an effective methods to:
// 1. Determine whether a point is torsion-free
// 2. Clear torsion component
// wrapPrivateKey: bls12-381 requires mod(n) instead of rejecting keys >= n
export type WeierstrassExtraOpts<T> = Partial<{
  Fp: IField<T>;
  Fn: IField<bigint>;
  allowInfinityPoint: boolean;
  endo: EndomorphismOpts;
  isTorsionFree: (c: WeierstrassPointCons<T>, point: WeierstrassPoint<T>) => boolean;
  clearCofactor: (c: WeierstrassPointCons<T>, point: WeierstrassPoint<T>) => WeierstrassPoint<T>;
  fromBytes: (bytes: Uint8Array) => AffinePoint<T>;
  toBytes: (
    c: WeierstrassPointCons<T>,
    point: WeierstrassPoint<T>,
    isCompressed: boolean
  ) => Uint8Array;
}>;

/**
 * Options for ECDSA signatures over a Weierstrass curve.
 */
export type ECDSAOpts = Partial<{
  lowS: boolean;
  hmac: HmacFnSync;
  randomBytes: (bytesLength?: number) => Uint8Array;
  bits2int: (bytes: Uint8Array) => bigint;
  bits2int_modN: (bytes: Uint8Array) => bigint;
}>;

/** ECDSA is only supported for prime fields, not Fp2 (extension fields). */
export interface ECDSA {
  keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
  getPublicKey: (secretKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  sign: (msgHash: Hex, secretKey: PrivKey, opts?: SignOpts) => ECDSASigRecovered;
  verify: (signature: Hex | SignatureLike, msgHash: Hex, publicKey: Hex, opts?: VerOpts) => boolean;
  getSharedSecret: (secretKeyA: PrivKey, publicKeyB: Hex, isCompressed?: boolean) => Uint8Array;
  Point: WeierstrassPointCons<bigint>;
  Signature: ECDSASignatureCons;
  utils: {
    isValidSecretKey: (secretKey: PrivKey) => boolean;
    isValidPublicKey: (publicKey: Uint8Array, isCompressed?: boolean) => boolean;
    randomSecretKey: (seed?: Uint8Array) => Uint8Array;

    /** @deprecated use `randomSecretKey` */
    randomPrivateKey: (seed?: Uint8Array) => Uint8Array;
    /** @deprecated use `isValidSecretKey` */
    isValidPrivateKey: (secretKey: PrivKey) => boolean;
    /** @deprecated use `Point.Fn.fromBytes()` */
    normPrivateKeyToScalar: (key: PrivKey) => bigint;
    /** @deprecated use `point.precompute()` */
    precompute: (windowSize?: number, point?: WeierstrassPoint<bigint>) => WeierstrassPoint<bigint>;
  };
  info: CurveInfo;
}
export class DERErr extends Error {
  constructor(m = '') {
    super(m);
  }
}
export type IDER = {
  // asn.1 DER encoding utils
  Err: typeof DERErr;
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag: number, data: string) => string;
    // v - value, l - left bytes (unparsed)
    decode(tag: number, data: Uint8Array): { v: Uint8Array; l: Uint8Array };
  };
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num: bigint): string;
    decode(data: Uint8Array): bigint;
  };
  toSig(hex: string | Uint8Array): { r: bigint; s: bigint };
  hexFromSig(sig: { r: bigint; s: bigint }): string;
};
/**
 * ASN.1 DER encoding utilities. ASN is very complex & fragile. Format:
 *
 *     [0x30 (SEQUENCE), bytelength, 0x02 (INTEGER), intLength, R, 0x02 (INTEGER), intLength, S]
 *
 * Docs: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/, https://luca.ntop.org/Teaching/Appunti/asn1.html
 */
export const DER: IDER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag: number, data: string): string => {
      const { Err: E } = DER;
      if (tag < 0 || tag > 256) throw new E('tlv.encode: wrong tag');
      if (data.length & 1) throw new E('tlv.encode: unpadded data');
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if ((len.length / 2) & 0b1000_0000) throw new E('tlv.encode: long form length too big');
      // length of length with long form flag
      const lenLen = dataLen > 127 ? numberToHexUnpadded((len.length / 2) | 0b1000_0000) : '';
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag: number, data: Uint8Array): { v: Uint8Array; l: Uint8Array } {
      const { Err: E } = DER;
      let pos = 0;
      if (tag < 0 || tag > 256) throw new E('tlv.encode: wrong tag');
      if (data.length < 2 || data[pos++] !== tag) throw new E('tlv.decode: wrong tlv');
      const first = data[pos++];
      const isLong = !!(first & 0b1000_0000); // First bit of first length byte is flag for short/long form
      let length = 0;
      if (!isLong) length = first;
      else {
        // Long form: [longFlag(1bit), lengthLength(7bit), length (BE)]
        const lenLen = first & 0b0111_1111;
        if (!lenLen) throw new E('tlv.decode(long): indefinite length not supported');
        if (lenLen > 4) throw new E('tlv.decode(long): byte length is too big'); // this will overflow u32 in js
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen) throw new E('tlv.decode: length bytes not complete');
        if (lengthBytes[0] === 0) throw new E('tlv.decode(long): zero leftmost byte');
        for (const b of lengthBytes) length = (length << 8) | b;
        pos += lenLen;
        if (length < 128) throw new E('tlv.decode(long): not minimal encoding');
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length) throw new E('tlv.decode: wrong value length');
      return { v, l: data.subarray(pos + length) };
    },
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num: bigint): string {
      const { Err: E } = DER;
      if (num < _0n) throw new E('integer: negative integers are not allowed');
      let hex = numberToHexUnpadded(num);
      // Pad with zero byte if negative flag is present
      if (Number.parseInt(hex[0], 16) & 0b1000) hex = '00' + hex;
      if (hex.length & 1) throw new E('unexpected DER parsing assertion: unpadded hex');
      return hex;
    },
    decode(data: Uint8Array): bigint {
      const { Err: E } = DER;
      if (data[0] & 0b1000_0000) throw new E('invalid signature integer: negative');
      if (data[0] === 0x00 && !(data[1] & 0b1000_0000))
        throw new E('invalid signature integer: unnecessary leading zero');
      return bytesToNumberBE(data);
    },
  },
  toSig(hex: string | Uint8Array): { r: bigint; s: bigint } {
    // parse DER signature
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = ensureBytes('signature', hex);
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(0x30, data);
    if (seqLeftBytes.length) throw new E('invalid signature: left bytes after parsing');
    const { v: rBytes, l: rLeftBytes } = tlv.decode(0x02, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(0x02, rLeftBytes);
    if (sLeftBytes.length) throw new E('invalid signature: left bytes after parsing');
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig: { r: bigint; s: bigint }): string {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(0x02, int.encode(sig.r));
    const ss = tlv.encode(0x02, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(0x30, seq);
  },
};

// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3), _4n = BigInt(4);

// TODO: remove
export function _legacyHelperEquat<T>(Fp: IField<T>, a: T, b: T): (x: T) => T {
  /**
   * y² = x³ + ax + b: Short weierstrass curve formula. Takes x, returns y².
   * @returns y²
   */
  function weierstrassEquation(x: T): T {
    const x2 = Fp.sqr(x); // x * x
    const x3 = Fp.mul(x2, x); // x² * x
    return Fp.add(Fp.add(x3, Fp.mul(x, a)), b); // x³ + a * x + b
  }
  return weierstrassEquation;
}
export function _normFnElement(Fn: IField<bigint>, key: PrivKey): bigint {
  const { BYTES: expected } = Fn;
  let num: bigint;
  if (typeof key === 'bigint') {
    num = key;
  } else {
    let bytes = ensureBytes('private key', key);
    try {
      num = Fn.fromBytes(bytes);
    } catch (error) {
      throw new Error(`invalid private key: expected ui8a of size ${expected}, got ${typeof key}`);
    }
  }
  if (!Fn.isValidNot0(num)) throw new Error('invalid private key: out of range [1..N-1]');
  return num;
}

export function weierstrassN<T>(
  CURVE: WeierstrassOpts<T>,
  curveOpts: WeierstrassExtraOpts<T> = {}
): WeierstrassPointCons<T> {
  const { Fp, Fn } = _createCurveFields('weierstrass', CURVE, curveOpts);
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  _validateObject(
    curveOpts,
    {},
    {
      allowInfinityPoint: 'boolean',
      clearCofactor: 'function',
      isTorsionFree: 'function',
      fromBytes: 'function',
      toBytes: 'function',
      endo: 'object',
      wrapPrivateKey: 'boolean',
    }
  );

  const { endo } = curveOpts;
  if (endo) {
    // validateObject(endo, { beta: 'bigint', splitScalar: 'function' });
    if (!Fp.is0(CURVE.a) || typeof endo.beta !== 'bigint' || !Array.isArray(endo.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }

  function assertCompressionIsSupported() {
    if (!Fp.isOdd) throw new Error('compression is not supported: Field does not have .isOdd()');
  }

  // Implements IEEE P1363 point encoding
  function pointToBytes(
    _c: WeierstrassPointCons<T>,
    point: WeierstrassPoint<T>,
    isCompressed: boolean
  ): Uint8Array {
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    abool('isCompressed', isCompressed);
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd!(y);
      return concatBytes(pprefix(hasEvenY), bx);
    } else {
      return concatBytes(Uint8Array.of(0x04), bx, Fp.toBytes(y));
    }
  }
  function pointFromBytes(bytes: Uint8Array) {
    abytes(bytes);
    const L = Fp.BYTES;
    const LC = L + 1; // length compressed, e.g. 33 for 32-byte field
    const LU = 2 * L + 1; // length uncompressed, e.g. 65 for 32-byte field
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    // No actual validation is done here: use .assertValidity()
    if (length === LC && (head === 0x02 || head === 0x03)) {
      const x = Fp.fromBytes(tail);
      if (!Fp.isValid(x)) throw new Error('bad point: is not on curve, wrong x');
      const y2 = weierstrassEquation(x); // y² = x³ + ax + b
      let y: T;
      try {
        y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
      } catch (sqrtError) {
        const err = sqrtError instanceof Error ? ': ' + sqrtError.message : '';
        throw new Error('bad point: is not on curve, sqrt error' + err);
      }
      assertCompressionIsSupported();
      const isYOdd = Fp.isOdd!(y); // (y & _1n) === _1n;
      const isHeadOdd = (head & 1) === 1; // ECDSA-specific
      if (isHeadOdd !== isYOdd) y = Fp.neg(y);
      return { x, y };
    } else if (length === LU && head === 0x04) {
      // TODO: more checks
      const x = Fp.fromBytes(tail.subarray(L * 0, L * 1));
      const y = Fp.fromBytes(tail.subarray(L * 1, L * 2));
      if (!isValidXY(x, y)) throw new Error('bad point: is not on curve');
      return { x, y };
    } else {
      throw new Error(
        `bad point: got length ${length}, expected compressed=${LC} or uncompressed=${LU}`
      );
    }
  }

  const toBytes = curveOpts.toBytes || pointToBytes;
  const fromBytes = curveOpts.fromBytes || pointFromBytes;
  const weierstrassEquation = _legacyHelperEquat(Fp, CURVE.a, CURVE.b);

  // TODO: move top-level
  /** Checks whether equation holds for given x, y: y² == x³ + ax + b */
  function isValidXY(x: T, y: T): boolean {
    const left = Fp.sqr(y); // y²
    const right = weierstrassEquation(x); // x³ + ax + b
    return Fp.eql(left, right);
  }

  // Validate whether the passed curve params are valid.
  // Test 1: equation y² = x³ + ax + b should work for generator point.
  if (!isValidXY(CURVE.Gx, CURVE.Gy)) throw new Error('bad curve params: generator point');

  // Test 2: discriminant Δ part should be non-zero: 4a³ + 27b² != 0.
  // Guarantees curve is genus-1, smooth (non-singular).
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n), _4n);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2))) throw new Error('bad curve params: a or b');

  /** Asserts coordinate is valid: 0 <= n < Fp.ORDER. */
  function acoord(title: string, n: T, banZero = false) {
    if (!Fp.isValid(n) || (banZero && Fp.is0(n))) throw new Error(`bad point coordinate ${title}`);
    return n;
  }

  function aprjpoint(other: unknown) {
    if (!(other instanceof Point)) throw new Error('ProjectivePoint expected');
  }

  function splitEndoScalarN(k: bigint) {
    if (!endo || !endo.basises) throw new Error('no endo');
    return _splitEndoScalar(k, endo.basises, Fn.ORDER);
  }

  // Memoized toAffine / validity check. They are heavy. Points are immutable.

  // Converts Projective point to affine (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  // (X, Y, Z) ∋ (x=X/Z, y=Y/Z)
  const toAffineMemo = memoized((p: Point, iz?: T): AffinePoint<T> => {
    const { X, Y, Z } = p;
    // Fast-path for normalized points
    if (Fp.eql(Z, Fp.ONE)) return { x: X, y: Y };
    const is0 = p.is0();
    // If invZ was 0, we return zero point. However we still want to execute
    // all operations, so we replace invZ with a random number, 1.
    if (iz == null) iz = is0 ? Fp.ONE : Fp.inv(Z);
    const x = Fp.mul(X, iz);
    const y = Fp.mul(Y, iz);
    const zz = Fp.mul(Z, iz);
    if (is0) return { x: Fp.ZERO, y: Fp.ZERO };
    if (!Fp.eql(zz, Fp.ONE)) throw new Error('invZ was invalid');
    return { x, y };
  });
  // NOTE: on exception this will crash 'cached' and no value will be set.
  // Otherwise true will be return
  const assertValidMemo = memoized((p: Point) => {
    if (p.is0()) {
      // (0, 1, 0) aka ZERO is invalid in most contexts.
      // In BLS, ZERO can be serialized, so we allow it.
      // (0, 0, 0) is invalid representation of ZERO.
      if (curveOpts.allowInfinityPoint && !Fp.is0(p.Y)) return;
      throw new Error('bad point: ZERO');
    }
    // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
    const { x, y } = p.toAffine();
    if (!Fp.isValid(x) || !Fp.isValid(y)) throw new Error('bad point: x or y not field elements');
    if (!isValidXY(x, y)) throw new Error('bad point: equation left != right');
    if (!p.isTorsionFree()) throw new Error('bad point: not in prime-order subgroup');
    return true;
  });

  function finishEndo(
    endoBeta: EndomorphismOpts['beta'],
    k1p: Point,
    k2p: Point,
    k1neg: boolean,
    k2neg: boolean
  ) {
    k2p = new Point(Fp.mul(k2p.X, endoBeta), k2p.Y, k2p.Z);
    k1p = negateCt(k1neg, k1p);
    k2p = negateCt(k2neg, k2p);
    return k1p.add(k2p);
  }

  /**
   * Projective Point works in 3d / projective (homogeneous) coordinates:(X, Y, Z) ∋ (x=X/Z, y=Y/Z).
   * Default Point works in 2d / affine coordinates: (x, y).
   * We're doing calculations in projective, because its operations don't require costly inversion.
   */
  class Point implements WeierstrassPoint<T> {
    // base / generator point
    static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    // zero / infinity / identity point
    static readonly ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO); // 0, 1, 0
    // fields
    static readonly Fp = Fp;
    static readonly Fn = Fn;

    readonly X: T;
    readonly Y: T;
    readonly Z: T;

    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X: T, Y: T, Z: T) {
      this.X = acoord('x', X);
      this.Y = acoord('y', Y, true);
      this.Z = acoord('z', Z);
      Object.freeze(this);
    }

    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p: AffinePoint<T>): Point {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y)) throw new Error('invalid affine point');
      if (p instanceof Point) throw new Error('projective point not allowed');
      // (0, 0) would've produced (0, 0, 1) - instead, we need (0, 1, 0)
      if (Fp.is0(x) && Fp.is0(y)) return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }

    get x(): T {
      return this.toAffine().x;
    }
    get y(): T {
      return this.toAffine().y;
    }

    // TODO: remove
    get px(): T {
      return this.X;
    }
    get py(): T {
      return this.X;
    }
    get pz(): T {
      return this.Z;
    }
    static normalizeZ(points: Point[]): Point[] {
      return normalizeZ(Point, points);
    }

    static fromBytes(bytes: Uint8Array): Point {
      abytes(bytes);
      return Point.fromHex(bytes);
    }

    /** Converts hash string or Uint8Array to Point. */
    static fromHex(hex: Hex): Point {
      const P = Point.fromAffine(fromBytes(ensureBytes('pointHex', hex)));
      P.assertValidity();
      return P;
    }

    /** Multiplies generator point by privateKey. */
    static fromPrivateKey(privateKey: PrivKey) {
      return Point.BASE.multiply(_normFnElement(Fn, privateKey));
    }

    // TODO: remove
    static msm(points: Point[], scalars: bigint[]): Point {
      return pippenger(Point, Fn, points, scalars);
    }
    _setWindowSize(windowSize: number) {
      this.precompute(windowSize);
    }

    /**
     *
     * @param windowSize
     * @param isLazy true will defer table computation until the first multiplication
     * @returns
     */
    precompute(windowSize: number = 8, isLazy = true): Point {
      wnaf.createCache(this, windowSize);
      if (!isLazy) this.multiply(_3n); // random number
      return this;
    }

    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity(): void {
      assertValidMemo(this);
    }

    hasEvenY(): boolean {
      const { y } = this.toAffine();
      if (!Fp.isOdd) throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }

    /** Compare one point to another. */
    equals(other: Point): boolean {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }

    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate(): Point {
      return new Point(this.X, Fp.neg(this.Y), this.Z);
    }

    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      let t0 = Fp.mul(X1, X1); // step 1
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3); // step 5
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3); // step 10
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3); // step 15
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0); // step 20
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1); // step 25
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3); // step 30
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }

    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other: Point): Point {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n);
      let t0 = Fp.mul(X1, X2); // step 1
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2); // step 5
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2); // step 10
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2); // step 15
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2); // step 20
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0); // step 25
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2); // step 30
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4); // step 35
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0); // step 40
      return new Point(X3, Y3, Z3);
    }

    subtract(other: Point) {
      return this.add(other.negate());
    }

    is0(): boolean {
      return this.equals(Point.ZERO);
    }

    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar: bigint): Point {
      const { endo } = curveOpts;
      if (!Fn.isValidNot0(scalar)) throw new Error('invalid scalar: out of range'); // 0 is invalid
      let point: Point, fake: Point; // Fake point is used to const-time mult
      const mul = (n: bigint) => wnaf.cached(this, n, (p) => normalizeZ(Point, p));
      /** See docs for {@link EndomorphismOpts} */
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(scalar);
        const { p: k1p, f: k1f } = mul(k1);
        const { p: k2p, f: k2f } = mul(k2);
        fake = k1f.add(k2f);
        point = finishEndo(endo.beta, k1p, k2p, k1neg, k2neg);
      } else {
        const { p, f } = mul(scalar);
        point = p;
        fake = f;
      }
      // Normalize `z` for both points, but return only real one
      return normalizeZ(Point, [point, fake])[0];
    }

    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(sc: bigint): Point {
      const { endo } = curveOpts;
      const p = this;
      if (!Fn.isValid(sc)) throw new Error('invalid scalar: out of range'); // 0 is valid
      if (sc === _0n || p.is0()) return Point.ZERO;
      if (sc === _1n) return p; // fast-path
      if (wnaf.hasCache(this)) return this.multiply(sc);
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(sc);
        const { p1, p2 } = mulEndoUnsafe(Point, p, k1, k2); // 30% faster vs wnaf.unsafe
        return finishEndo(endo.beta, p1, p2, k1neg, k2neg);
      } else {
        return wnaf.unsafe(p, sc);
      }
    }

    multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
      const sum = this.multiplyUnsafe(a).add(Q.multiplyUnsafe(b));
      return sum.is0() ? undefined : sum;
    }

    /**
     * Converts Projective point to affine (x, y) coordinates.
     * @param invertedZ Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ?: T): AffinePoint<T> {
      return toAffineMemo(this, invertedZ);
    }

    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree(): boolean {
      const { isTorsionFree } = curveOpts;
      if (cofactor === _1n) return true;
      if (isTorsionFree) return isTorsionFree(Point, this);
      return wnaf.unsafe(this, CURVE_ORDER).is0();
    }

    clearCofactor(): Point {
      const { clearCofactor } = curveOpts;
      if (cofactor === _1n) return this; // Fast-path
      if (clearCofactor) return clearCofactor(Point, this) as Point;
      return this.multiplyUnsafe(cofactor);
    }

    isSmallOrder(): boolean {
      // can we use this.clearCofactor()?
      return this.multiplyUnsafe(cofactor).is0();
    }

    toBytes(isCompressed = true): Uint8Array {
      abool('isCompressed', isCompressed);
      this.assertValidity();
      return toBytes(Point, this, isCompressed);
    }

    /** @deprecated use `toBytes` */
    toRawBytes(isCompressed = true): Uint8Array {
      return this.toBytes(isCompressed);
    }

    toHex(isCompressed = true): string {
      return bytesToHex(this.toBytes(isCompressed));
    }

    toString() {
      return `<Point ${this.is0() ? 'ZERO' : this.toHex()}>`;
    }
  }
  const bits = Fn.BITS;
  const wnaf = new wNAF(Point, curveOpts.endo ? Math.ceil(bits / 2) : bits);
  return Point;
}

// _legacyWeierstrass
// TODO: remove
/** @deprecated use `weierstrass` in newer releases */
export function weierstrassPoints<T>(c: CurvePointsTypeWithLength<T>): CurvePointsRes<T> {
  const { CURVE, curveOpts } = _weierstrass_legacy_opts_to_new(c);
  const Point = weierstrassN(CURVE, curveOpts);
  return _weierstrass_new_output_to_legacy(c, Point);
}

// Instance
export interface ECDSASignature {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  addRecoveryBit(recovery: number): ECDSASigRecovered;
  hasHighS(): boolean;
  normalizeS(): ECDSASignature;
  recoverPublicKey(msgHash: Hex): WeierstrassPoint<bigint>;
  toBytes(format?: string): Uint8Array;
  toHex(format?: string): string;

  /** @deprecated */
  assertValidity(): void;
  /** @deprecated use `.toBytes('compact')` */
  toCompactRawBytes(): Uint8Array;
  /** @deprecated use `.toBytes('compact')` */
  toCompactHex(): string;
  /** @deprecated use `.toBytes('der')` */
  toDERRawBytes(): Uint8Array;
  /** @deprecated use `.toBytes('der')` */
  toDERHex(): string;
}
export type SignatureType = ECDSASignature;
export type ECDSASigRecovered = ECDSASignature & {
  readonly recovery: number;
};
export type RecoveredSignatureType = ECDSASigRecovered;
// Static methods
export type ECDSASignatureCons = {
  new (r: bigint, s: bigint, recovery?: number): ECDSASignature;
  fromBytes(bytes: Uint8Array, format?: ECDSASigFormat): ECDSASignature;
  fromHex(hex: string, format?: ECDSASigFormat): ECDSASignature;

  /** @deprecated use `.fromBytes(bytes, 'compact')` */
  fromCompact(hex: Hex): ECDSASignature;
  /** @deprecated use `.fromBytes(bytes, 'der')` */
  fromDER(hex: Hex): ECDSASignature;
};
export type SignatureLike = { r: bigint; s: bigint };
// TODO: remove
export type PubKey = Hex | WeierstrassPoint<bigint>;

// TODO: remove
export type CurveType = BasicWCurve<bigint> & {
  hash: CHash; // CHash not FHash because we need outputLen for DRBG
  hmac?: HmacFnSync;
  randomBytes?: (bytesLength?: number) => Uint8Array;
  lowS?: boolean;
  bits2int?: (bytes: Uint8Array) => bigint;
  bits2int_modN?: (bytes: Uint8Array) => bigint;
};

// Points start with byte 0x02 when y is even; otherwise 0x03
function pprefix(hasEvenY: boolean): Uint8Array {
  return Uint8Array.of(hasEvenY ? 0x02 : 0x03);
}

// TODO: remove
export type CurveFn = {
  /** @deprecated the property will be removed in next release */
  CURVE: CurvePointsType<bigint>;
  keygen: ECDSA['keygen'];
  getPublicKey: ECDSA['getPublicKey'];
  getSharedSecret: ECDSA['getSharedSecret'];
  sign: ECDSA['sign'];
  verify: ECDSA['verify'];
  Point: WeierstrassPointCons<bigint>;
  /** @deprecated use `Point` */
  ProjectivePoint: WeierstrassPointCons<bigint>;
  Signature: ECDSASignatureCons;
  utils: ECDSA['utils'];
  info: CurveInfo;
};

/**
 * Implementation of the Shallue and van de Woestijne method for any weierstrass curve.
 * TODO: check if there is a way to merge this with uvRatio in Edwards; move to modular.
 * b = True and y = sqrt(u / v) if (u / v) is square in F, and
 * b = False and y = sqrt(Z * (u / v)) otherwise.
 * @param Fp
 * @param Z
 * @returns
 */
export function SWUFpSqrtRatio<T>(
  Fp: IField<T>,
  Z: T
): (u: T, v: T) => { isValid: boolean; value: T } {
  // Generic implementation
  const q = Fp.ORDER;
  let l = _0n;
  for (let o = q - _1n; o % _2n === _0n; o /= _2n) l += _1n;
  const c1 = l; // 1. c1, the largest integer such that 2^c1 divides q - 1.
  // We need 2n ** c1 and 2n ** (c1-1). We can't use **; but we can use <<.
  // 2n ** c1 == 2n << (c1-1)
  const _2n_pow_c1_1 = _2n << (c1 - _1n - _1n);
  const _2n_pow_c1 = _2n_pow_c1_1 * _2n;
  const c2 = (q - _1n) / _2n_pow_c1; // 2. c2 = (q - 1) / (2^c1)  # Integer arithmetic
  const c3 = (c2 - _1n) / _2n; // 3. c3 = (c2 - 1) / 2            # Integer arithmetic
  const c4 = _2n_pow_c1 - _1n; // 4. c4 = 2^c1 - 1                # Integer arithmetic
  const c5 = _2n_pow_c1_1; // 5. c5 = 2^(c1 - 1)                  # Integer arithmetic
  const c6 = Fp.pow(Z, c2); // 6. c6 = Z^c2
  const c7 = Fp.pow(Z, (c2 + _1n) / _2n); // 7. c7 = Z^((c2 + 1) / 2)
  let sqrtRatio = (u: T, v: T): { isValid: boolean; value: T } => {
    let tv1 = c6; // 1. tv1 = c6
    let tv2 = Fp.pow(v, c4); // 2. tv2 = v^c4
    let tv3 = Fp.sqr(tv2); // 3. tv3 = tv2^2
    tv3 = Fp.mul(tv3, v); // 4. tv3 = tv3 * v
    let tv5 = Fp.mul(u, tv3); // 5. tv5 = u * tv3
    tv5 = Fp.pow(tv5, c3); // 6. tv5 = tv5^c3
    tv5 = Fp.mul(tv5, tv2); // 7. tv5 = tv5 * tv2
    tv2 = Fp.mul(tv5, v); // 8. tv2 = tv5 * v
    tv3 = Fp.mul(tv5, u); // 9. tv3 = tv5 * u
    let tv4 = Fp.mul(tv3, tv2); // 10. tv4 = tv3 * tv2
    tv5 = Fp.pow(tv4, c5); // 11. tv5 = tv4^c5
    let isQR = Fp.eql(tv5, Fp.ONE); // 12. isQR = tv5 == 1
    tv2 = Fp.mul(tv3, c7); // 13. tv2 = tv3 * c7
    tv5 = Fp.mul(tv4, tv1); // 14. tv5 = tv4 * tv1
    tv3 = Fp.cmov(tv2, tv3, isQR); // 15. tv3 = CMOV(tv2, tv3, isQR)
    tv4 = Fp.cmov(tv5, tv4, isQR); // 16. tv4 = CMOV(tv5, tv4, isQR)
    // 17. for i in (c1, c1 - 1, ..., 2):
    for (let i = c1; i > _1n; i--) {
      let tv5 = i - _2n; // 18.    tv5 = i - 2
      tv5 = _2n << (tv5 - _1n); // 19.    tv5 = 2^tv5
      let tvv5 = Fp.pow(tv4, tv5); // 20.    tv5 = tv4^tv5
      const e1 = Fp.eql(tvv5, Fp.ONE); // 21.    e1 = tv5 == 1
      tv2 = Fp.mul(tv3, tv1); // 22.    tv2 = tv3 * tv1
      tv1 = Fp.mul(tv1, tv1); // 23.    tv1 = tv1 * tv1
      tvv5 = Fp.mul(tv4, tv1); // 24.    tv5 = tv4 * tv1
      tv3 = Fp.cmov(tv2, tv3, e1); // 25.    tv3 = CMOV(tv2, tv3, e1)
      tv4 = Fp.cmov(tvv5, tv4, e1); // 26.    tv4 = CMOV(tv5, tv4, e1)
    }
    return { isValid: isQR, value: tv3 };
  };
  if (Fp.ORDER % _4n === _3n) {
    // sqrt_ratio_3mod4(u, v)
    const c1 = (Fp.ORDER - _3n) / _4n; // 1. c1 = (q - 3) / 4     # Integer arithmetic
    const c2 = Fp.sqrt(Fp.neg(Z)); // 2. c2 = sqrt(-Z)
    sqrtRatio = (u: T, v: T) => {
      let tv1 = Fp.sqr(v); // 1. tv1 = v^2
      const tv2 = Fp.mul(u, v); // 2. tv2 = u * v
      tv1 = Fp.mul(tv1, tv2); // 3. tv1 = tv1 * tv2
      let y1 = Fp.pow(tv1, c1); // 4. y1 = tv1^c1
      y1 = Fp.mul(y1, tv2); // 5. y1 = y1 * tv2
      const y2 = Fp.mul(y1, c2); // 6. y2 = y1 * c2
      const tv3 = Fp.mul(Fp.sqr(y1), v); // 7. tv3 = y1^2; 8. tv3 = tv3 * v
      const isQR = Fp.eql(tv3, u); // 9. isQR = tv3 == u
      let y = Fp.cmov(y2, y1, isQR); // 10. y = CMOV(y2, y1, isQR)
      return { isValid: isQR, value: y }; // 11. return (isQR, y) isQR ? y : y*c2
    };
  }
  // No curves uses that
  // if (Fp.ORDER % _8n === _5n) // sqrt_ratio_5mod8
  return sqrtRatio;
}
/**
 * Simplified Shallue-van de Woestijne-Ulas Method
 * https://www.rfc-editor.org/rfc/rfc9380#section-6.6.2
 */
export function mapToCurveSimpleSWU<T>(
  Fp: IField<T>,
  opts: {
    A: T;
    B: T;
    Z: T;
  }
): (u: T) => { x: T; y: T } {
  validateField(Fp);
  const { A, B, Z } = opts;
  if (!Fp.isValid(A) || !Fp.isValid(B) || !Fp.isValid(Z))
    throw new Error('mapToCurveSimpleSWU: invalid opts');
  const sqrtRatio = SWUFpSqrtRatio(Fp, Z);
  if (!Fp.isOdd) throw new Error('Field does not have .isOdd()');
  // Input: u, an element of F.
  // Output: (x, y), a point on E.
  return (u: T): { x: T; y: T } => {
    // prettier-ignore
    let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
    tv1 = Fp.sqr(u); // 1.  tv1 = u^2
    tv1 = Fp.mul(tv1, Z); // 2.  tv1 = Z * tv1
    tv2 = Fp.sqr(tv1); // 3.  tv2 = tv1^2
    tv2 = Fp.add(tv2, tv1); // 4.  tv2 = tv2 + tv1
    tv3 = Fp.add(tv2, Fp.ONE); // 5.  tv3 = tv2 + 1
    tv3 = Fp.mul(tv3, B); // 6.  tv3 = B * tv3
    tv4 = Fp.cmov(Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO)); // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
    tv4 = Fp.mul(tv4, A); // 8.  tv4 = A * tv4
    tv2 = Fp.sqr(tv3); // 9.  tv2 = tv3^2
    tv6 = Fp.sqr(tv4); // 10. tv6 = tv4^2
    tv5 = Fp.mul(tv6, A); // 11. tv5 = A * tv6
    tv2 = Fp.add(tv2, tv5); // 12. tv2 = tv2 + tv5
    tv2 = Fp.mul(tv2, tv3); // 13. tv2 = tv2 * tv3
    tv6 = Fp.mul(tv6, tv4); // 14. tv6 = tv6 * tv4
    tv5 = Fp.mul(tv6, B); // 15. tv5 = B * tv6
    tv2 = Fp.add(tv2, tv5); // 16. tv2 = tv2 + tv5
    x = Fp.mul(tv1, tv3); // 17.   x = tv1 * tv3
    const { isValid, value } = sqrtRatio(tv2, tv6); // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
    y = Fp.mul(tv1, u); // 19.   y = tv1 * u  -> Z * u^3 * y1
    y = Fp.mul(y, value); // 20.   y = y * y1
    x = Fp.cmov(x, tv3, isValid); // 21.   x = CMOV(x, tv3, is_gx1_square)
    y = Fp.cmov(y, value, isValid); // 22.   y = CMOV(y, y1, is_gx1_square)
    const e1 = Fp.isOdd!(u) === Fp.isOdd!(y); // 23.  e1 = sgn0(u) == sgn0(y)
    y = Fp.cmov(Fp.neg(y), y, e1); // 24.   y = CMOV(-y, y, e1)
    const tv4_inv = FpInvertBatch(Fp, [tv4], true)[0];
    x = Fp.mul(x, tv4_inv); // 25.   x = x / tv4
    return { x, y };
  };
}

/**
 * Creates ECDSA for given elliptic curve Point and hash function.
 */
export function ecdsa(
  Point: WeierstrassPointCons<bigint>,
  hash: CHash,
  ecdsaOpts: ECDSAOpts = {}
): ECDSA {
  ahash(hash);
  _validateObject(
    ecdsaOpts,
    {},
    {
      hmac: 'function',
      lowS: 'boolean',
      randomBytes: 'function',
      bits2int: 'function',
      bits2int_modN: 'function',
    }
  );

  const randomBytes_ = ecdsaOpts.randomBytes || randomBytes;
  const hmac_: HmacFnSync =
    ecdsaOpts.hmac ||
    (((key, ...msgs) => hmac(hash, key, concatBytes(...msgs))) satisfies HmacFnSync);

  const { Fp, Fn } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;

  const seedLen = getMinHashLength(CURVE_ORDER);
  const lengths = {
    secret: Fn.BYTES,
    public: 1 + Fp.BYTES,
    publicUncompressed: 1 + 2 * Fp.BYTES,
    signature: 2 * Fn.BYTES,
    seed: seedLen,
  };

  function isBiggerThanHalfOrder(number: bigint) {
    const HALF = CURVE_ORDER >> _1n;
    return number > HALF;
  }

  function normalizeS(s: bigint) {
    return isBiggerThanHalfOrder(s) ? Fn.neg(s) : s;
  }
  function aValidRS(title: string, num: bigint) {
    if (!Fn.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..CURVE.n`);
  }

  /**
   * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
   */
  class Signature implements ECDSASignature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;
    constructor(r: bigint, s: bigint, recovery?: number) {
      aValidRS('r', r); // r in [1..N-1]
      aValidRS('s', s); // s in [1..N-1]
      this.r = r;
      this.s = s;
      if (recovery != null) this.recovery = recovery;
      Object.freeze(this);
    }

    static fromBytes(bytes: Uint8Array, format: ECDSASigFormat = 'compact') {
      if (format === 'compact') {
        const L = Fn.BYTES;
        abytes(bytes, L * 2);
        const r = bytes.subarray(0, L);
        const s = bytes.subarray(L, L * 2);
        return new Signature(Fn.fromBytes(r), Fn.fromBytes(s));
      }
      if (format === 'der') {
        abytes(bytes);
        const { r, s } = DER.toSig(bytes);
        return new Signature(r, s);
      }
      throw new Error('invalid format');
    }

    static fromHex(hex: string, format?: ECDSASigFormat) {
      return this.fromBytes(hexToBytes(hex), format);
    }

    addRecoveryBit(recovery: number): RecoveredSignature {
      return new Signature(this.r, this.s, recovery) as RecoveredSignature;
    }

    // ProjPointType<bigint>
    recoverPublicKey(msgHash: Hex): typeof Point.BASE {
      const FIELD_ORDER = Fp.ORDER;
      const { r, s, recovery: rec } = this;
      if (rec == null || ![0, 1, 2, 3].includes(rec)) throw new Error('recovery id invalid');

      // ECDSA recovery is hard for cofactor > 1 curves.
      // In sign, `r = q.x mod n`, and here we recover q.x from r.
      // While recovering q.x >= n, we need to add r+n for cofactor=1 curves.
      // However, for cofactor>1, r+n may not get q.x:
      // r+n*i would need to be done instead where i is unknown.
      // To easily get i, we either need to:
      // a. increase amount of valid recid values (4, 5...); OR
      // b. prohibit non-prime-order signatures (recid > 1).
      const hasCofactor = CURVE_ORDER * _2n < FIELD_ORDER;
      if (hasCofactor && rec > 1) throw new Error('recovery id is ambiguous for h>1 curve');

      const radj = rec === 2 || rec === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj)) throw new Error('recovery id 2 or 3 invalid');
      const x = Fp.toBytes(radj);
      const R = Point.fromHex(concatBytes(pprefix((rec & 1) === 0), x));
      const ir = Fn.inv(radj); // r^-1
      const h = bits2int_modN(ensureBytes('msgHash', msgHash)); // Truncate hash
      const u1 = Fn.create(-h * ir); // -hr^-1
      const u2 = Fn.create(s * ir); // sr^-1
      // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1). unsafe is fine: there is no private data.
      const Q = Point.BASE.multiplyUnsafe(u1).add(R.multiplyUnsafe(u2));
      if (Q.is0()) throw new Error('point at infinify');
      Q.assertValidity();
      return Q;
    }

    // Signatures should be low-s, to prevent malleability.
    hasHighS(): boolean {
      return isBiggerThanHalfOrder(this.s);
    }

    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, Fn.neg(this.s), this.recovery) : this;
    }

    toBytes(format: ECDSASigFormat = 'compact') {
      if (format === 'compact') return concatBytes(Fn.toBytes(this.r), Fn.toBytes(this.s));
      if (format === 'der') return hexToBytes(DER.hexFromSig(this));
      throw new Error('invalid format');
    }

    toHex(format?: ECDSASigFormat) {
      return bytesToHex(this.toBytes(format));
    }

    // TODO: remove
    assertValidity(): void {}
    static fromCompact(hex: Hex) {
      return Signature.fromBytes(ensureBytes('sig', hex), 'compact');
    }
    static fromDER(hex: Hex) {
      return Signature.fromBytes(ensureBytes('sig', hex), 'der');
    }
    toDERRawBytes() {
      return this.toBytes('der');
    }
    toDERHex() {
      return bytesToHex(this.toBytes('der'));
    }
    toCompactRawBytes() {
      return this.toBytes('compact');
    }
    toCompactHex() {
      return bytesToHex(this.toBytes('compact'));
    }
  }
  type RecoveredSignature = Signature & { recovery: number };

  function isValidSecretKey(privateKey: PrivKey) {
    try {
      return !!_normFnElement(Fn, privateKey);
    } catch (error) {
      return false;
    }
  }
  function isValidPublicKey(publicKey: Uint8Array, isCompressed?: boolean): boolean {
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== lengths.public) return false;
      if (isCompressed === false && l !== lengths.publicUncompressed) return false;
      return !!Point.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  }
  /**
   * Produces cryptographically secure secret key from random of size
   * (groupLen + ceil(groupLen / 2)) with modulo bias being negligible.
   */
  function randomSecretKey(seed = randomBytes_(seedLen)): Uint8Array {
    return mapHashToField(seed, CURVE_ORDER);
  }

  const utils = {
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey,

    // TODO: remove
    isValidPrivateKey: isValidSecretKey,
    randomPrivateKey: randomSecretKey,
    normPrivateKeyToScalar: (key: PrivKey) => _normFnElement(Fn, key),
    precompute(windowSize = 8, point = Point.BASE): WeierstrassPoint<bigint> {
      return point.precompute(windowSize, false);
    },
  };

  /**
   * Computes public key for a secret key. Checks for validity of the secret key.
   * @param isCompressed whether to return compact (default), or full key
   * @returns Public key, full when isCompressed=false; short when isCompressed=true
   */
  function getPublicKey(secretKey: PrivKey, isCompressed = true): Uint8Array {
    return Point.BASE.multiply(_normFnElement(Fn, secretKey)).toBytes(isCompressed);
  }

  /**
   * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
   */
  function isProbPub(item: PrivKey | PubKey): boolean | undefined {
    // TODO: remove
    if (typeof item === 'bigint') return false;
    // TODO: remove
    if (item instanceof Point) return true;
    if (Fn.allowedLengths || lengths.secret === lengths.public) return undefined;
    const l = ensureBytes('key', item).length;
    return l === lengths.public || l === lengths.publicUncompressed;
  }

  /**
   * ECDH (Elliptic Curve Diffie Hellman).
   * Computes shared public key from secret key A and public key B.
   * Checks: 1) secret key validity 2) shared key is on-curve.
   * Does NOT hash the result.
   * @param isCompressed whether to return compact (default), or full key
   * @returns shared public key
   */
  function getSharedSecret(secretKeyA: PrivKey, publicKeyB: Hex, isCompressed = true): Uint8Array {
    if (isProbPub(secretKeyA) === true) throw new Error('first arg must be private key');
    if (isProbPub(publicKeyB) === false) throw new Error('second arg must be public key');
    const s = _normFnElement(Fn, secretKeyA);
    const b = Point.fromHex(publicKeyB); // checks for being on-curve
    return b.multiply(s).toBytes(isCompressed);
  }

  // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
  // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
  // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
  // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
  const bits2int =
    ecdsaOpts.bits2int ||
    function (bytes: Uint8Array): bigint {
      // Our custom check "just in case", for protection against DoS
      if (bytes.length > 8192) throw new Error('input is too large');
      // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
      // for some cases, since bytes.length * 8 is not actual bitLength.
      const num = bytesToNumberBE(bytes); // check for == u8 done here
      const delta = bytes.length * 8 - fnBits; // truncate to nBitLength leftmost bits
      return delta > 0 ? num >> BigInt(delta) : num;
    };
  const bits2int_modN =
    ecdsaOpts.bits2int_modN ||
    function (bytes: Uint8Array): bigint {
      return Fn.create(bits2int(bytes)); // can't use bytesToNumberBE here
    };
  // NOTE: pads output with zero as per spec
  const ORDER_MASK = bitMask(fnBits);
  /**
   * Converts to bytes. Checks if num in `[0..ORDER_MASK-1]` e.g.: `[0..2^256-1]`.
   */
  function int2octets(num: bigint): Uint8Array {
    // IMPORTANT: the check ensures working for case `Fn.BYTES != Fn.BITS * 8`
    aInRange('num < 2^' + fnBits, num, _0n, ORDER_MASK);
    return Fn.toBytes(num);
  }

  // Steps A, D of RFC6979 3.2
  // Creates RFC6979 seed; converts msg/privKey to numbers.
  // Used only in sign, not in verify.
  // NOTE: we cannot assume here that msgHash has same amount of bytes as curve order,
  // this will be invalid at least for P521. Also it can be bigger for P224 + SHA256
  function prepSig(msgHash: Hex, privateKey: PrivKey, opts = defaultSigOpts) {
    if (['recovered', 'canonical'].some((k) => k in opts))
      throw new Error('sign() legacy options not supported');
    let { lowS, prehash, extraEntropy: ent } = opts; // generates low-s sigs by default
    if (lowS == null) lowS = true; // RFC6979 3.2: we skip step A, because we already provide hash
    msgHash = ensureBytes('msgHash', msgHash);
    validateSigVerOpts(opts);
    if (prehash) msgHash = ensureBytes('prehashed msgHash', hash(msgHash));

    // We can't later call bits2octets, since nested bits2int is broken for curves
    // with fnBits % 8 !== 0. Because of that, we unwrap it here as int2octets call.
    // const bits2octets = (bits) => int2octets(bits2int_modN(bits))
    const h1int = bits2int_modN(msgHash);
    const d = _normFnElement(Fn, privateKey); // validate secret key, convert to bigint
    const seedArgs = [int2octets(d), int2octets(h1int)];
    // extraEntropy. RFC6979 3.6: additional k' (optional).
    if (ent != null && ent !== false) {
      // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
      const e = ent === true ? randomBytes_(lengths.secret) : ent; // gen random bytes OR pass as-is
      seedArgs.push(ensureBytes('extraEntropy', e)); // check for being bytes
    }
    const seed = concatBytes(...seedArgs); // Step D of RFC6979 3.2
    const m = h1int; // NOTE: no need to call bits2int second time here, it is inside truncateHash!
    // Converts signature params into point w r/s, checks result for validity.
    // To transform k => Signature:
    // q = k⋅G
    // r = q.x mod n
    // s = k^-1(m + rd) mod n
    // Can use scalar blinding b^-1(bm + bdr) where b ∈ [1,q−1] according to
    // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. We've decided against it:
    // a) dependency on CSPRNG b) 15% slowdown c) doesn't really help since bigints are not CT
    function k2sig(kBytes: Uint8Array): RecoveredSignature | undefined {
      // RFC 6979 Section 3.2, step 3: k = bits2int(T)
      // Important: all mod() calls here must be done over N
      const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
      if (!Fn.isValidNot0(k)) return; // Valid scalars (including k) must be in 1..N-1
      const ik = Fn.inv(k); // k^-1 mod n
      const q = Point.BASE.multiply(k).toAffine(); // q = k⋅G
      const r = Fn.create(q.x); // r = q.x mod n
      if (r === _0n) return;
      const s = Fn.create(ik * Fn.create(m + r * d)); // Not using blinding here, see comment above
      if (s === _0n) return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n); // recovery bit (2 or 3, when q.x > n)
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s); // if lowS was passed, ensure s is always
        recovery ^= 1; // // in the bottom half of N
      }
      return new Signature(r, normS, recovery) as RecoveredSignature; // use normS, not s
    }
    return { seed, k2sig };
  }
  const defaultSigOpts: SignOpts = { lowS: ecdsaOpts.lowS, prehash: false };
  const defaultVerOpts: VerOpts = { lowS: ecdsaOpts.lowS, prehash: false };

  /**
   * Signs message hash with a secret key.
   * ```
   * sign(m, d, k) where
   *   (x, y) = G × k
   *   r = x mod n
   *   s = (m + dr)/k mod n
   * ```
   */
  function sign(msgHash: Hex, secretKey: PrivKey, opts = defaultSigOpts): RecoveredSignature {
    const { seed, k2sig } = prepSig(msgHash, secretKey, opts); // Steps A, D of RFC6979 3.2.
    const drbg = createHmacDrbg<RecoveredSignature>(hash.outputLen, Fn.BYTES, hmac_);
    return drbg(seed, k2sig); // Steps B, C, D, E, F, G
  }

  // Enable precomputes. Slows down first publicKey computation by 20ms.
  Point.BASE.precompute(8);

  /**
   * Verifies a signature against message hash and public key.
   * Rejects lowS signatures by default: to override,
   * specify option `{lowS: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
   *
   * ```
   * verify(r, s, h, P) where
   *   U1 = hs^-1 mod n
   *   U2 = rs^-1 mod n
   *   R = U1⋅G - U2⋅P
   *   mod(R.x, n) == r
   * ```
   */
  function verify(
    signature: Hex | SignatureLike,
    msgHash: Hex,
    publicKey: Hex,
    opts = defaultVerOpts
  ): boolean {
    const sg = signature;
    msgHash = ensureBytes('msgHash', msgHash);
    publicKey = ensureBytes('publicKey', publicKey);

    // Verify opts
    validateSigVerOpts(opts);
    const { lowS, prehash, format } = opts;

    // TODO: remove
    if ('strict' in opts) throw new Error('options.strict was renamed to lowS');

    let _sig: Signature | undefined = undefined;
    let P: WeierstrassPoint<bigint>;

    if (format === undefined) {
      // Try to deduce format
      const isHex = typeof sg === 'string' || isBytes(sg);
      const isObj =
        !isHex &&
        sg !== null &&
        typeof sg === 'object' &&
        typeof sg.r === 'bigint' &&
        typeof sg.s === 'bigint';
      if (!isHex && !isObj)
        throw new Error('invalid signature, expected Uint8Array, hex string or Signature instance');
      if (isObj) {
        _sig = new Signature(sg.r, sg.s);
      } else if (isHex) {
        // TODO: remove this malleable check
        // Signature can be represented in 2 ways: compact (2*Fn.BYTES) & DER (variable-length).
        // Since DER can also be 2*Fn.BYTES bytes, we check for it first.
        try {
          _sig = Signature.fromDER(sg);
        } catch (derError) {
          if (!(derError instanceof DER.Err)) throw derError;
        }
        if (!_sig) {
          try {
            _sig = Signature.fromCompact(sg);
          } catch (error) {
            return false;
          }
        }
      }
    } else {
      if (format === 'compact' || format === 'der') {
        if (typeof sg !== 'string' && !isBytes(sg))
          throw new Error('"der" / "compact" format expects Uint8Array signature');
        _sig = Signature.fromBytes(ensureBytes('sig', sg), format);
      } else if (format === 'js') {
        if (!(sg instanceof Signature)) throw new Error('"js" format expects Signature instance');
        _sig = sg;
      } else {
        throw new Error('format must be "compact", "der" or "js"');
      }
    }

    if (!_sig) return false;
    try {
      P = Point.fromHex(publicKey);
      if (lowS && _sig.hasHighS()) return false;
      // todo: optional.hash => hash
      if (prehash) msgHash = hash(msgHash);
      const { r, s } = _sig;
      const h = bits2int_modN(msgHash); // Cannot use fields methods, since it is group element
      const is = Fn.inv(s); // s^-1
      const u1 = Fn.create(h * is); // u1 = hs^-1 mod n
      const u2 = Fn.create(r * is); // u2 = rs^-1 mod n
      const R = Point.BASE.multiplyUnsafe(u1).add(P.multiplyUnsafe(u2));
      if (R.is0()) return false;
      const v = Fn.create(R.x); // v = r.x mod n
      return v === r;
    } catch (e) {
      return false;
    }
  }

  function keygen(seed?: Uint8Array) {
    const secretKey = utils.randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }

  return Object.freeze({
    keygen,
    getPublicKey,
    sign,
    verify,
    getSharedSecret,
    utils,
    Point,
    Signature,
    info: { type: 'weierstrass' as const, lengths, publicKeyHasPrefix: true },
  });
}

// TODO: remove
export type WsPointComposed<T> = {
  CURVE: WeierstrassOpts<T>;
  curveOpts: WeierstrassExtraOpts<T>;
};
// TODO: remove
export type WsComposed = {
  CURVE: WeierstrassOpts<bigint>;
  hash: CHash;
  curveOpts: WeierstrassExtraOpts<bigint>;
  ecdsaOpts: ECDSAOpts;
};
// TODO: remove
function _weierstrass_legacy_opts_to_new<T>(c: CurvePointsType<T>): WsPointComposed<T> {
  const CURVE: WeierstrassOpts<T> = {
    a: c.a,
    b: c.b,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy,
  };
  const Fp = c.Fp;
  let allowedLengths = c.allowedPrivateKeyLengths
    ? Array.from(new Set(c.allowedPrivateKeyLengths.map((l) => Math.ceil(l / 2))))
    : undefined;
  const Fn = Field(CURVE.n, {
    BITS: c.nBitLength,
    allowedLengths: allowedLengths,
    modOnDecode: c.wrapPrivateKey,
  });
  const curveOpts: WeierstrassExtraOpts<T> = {
    Fp,
    Fn,
    allowInfinityPoint: c.allowInfinityPoint,
    endo: c.endo,
    isTorsionFree: c.isTorsionFree,
    clearCofactor: c.clearCofactor,
    fromBytes: c.fromBytes,
    toBytes: c.toBytes,
  };
  return { CURVE, curveOpts };
}
function _ecdsa_legacy_opts_to_new(c: CurveType): WsComposed {
  const { CURVE, curveOpts } = _weierstrass_legacy_opts_to_new(c);
  const ecdsaOpts: ECDSAOpts = {
    hmac: c.hmac,
    randomBytes: c.randomBytes,
    lowS: c.lowS,
    bits2int: c.bits2int,
    bits2int_modN: c.bits2int_modN,
  };
  return { CURVE, curveOpts, hash: c.hash, ecdsaOpts };
}
// TODO: remove
function _weierstrass_new_output_to_legacy<T>(
  c: CurvePointsType<T>,
  Point: WeierstrassPointCons<T>
): CurvePointsRes<T> {
  const { Fp, Fn } = Point;
  // TODO: remove
  function isWithinCurveOrder(num: bigint): boolean {
    return inRange(num, _1n, Fn.ORDER);
  }
  const weierstrassEquation = _legacyHelperEquat(Fp, c.a, c.b);
  return Object.assign(
    {},
    {
      CURVE: c,
      Point: Point,
      ProjectivePoint: Point,
      normPrivateKeyToScalar: (key: PrivKey) => _normFnElement(Fn, key),
      weierstrassEquation,
      isWithinCurveOrder,
    }
  );
}
// TODO: remove
function _ecdsa_new_output_to_legacy(c: CurveType, ecdsa: ECDSA): CurveFn {
  return Object.assign({}, ecdsa, {
    ProjectivePoint: ecdsa.Point,
    CURVE: c,
  });
}

// _ecdsa_legacy
export function weierstrass(c: CurveType): CurveFn {
  const { CURVE, curveOpts, hash, ecdsaOpts } = _ecdsa_legacy_opts_to_new(c);
  const Point = weierstrassN(CURVE, curveOpts);
  const signs = ecdsa(Point, hash, ecdsaOpts);
  return _ecdsa_new_output_to_legacy(c, signs);
}
