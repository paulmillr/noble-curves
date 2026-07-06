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
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { ahash } from '@noble/hashes/utils.js';
import {
  abool,
  abytes,
  aInRange,
  bitLen,
  bitMask,
  bytesToHex,
  bytesToNumberBE,
  concatBytes,
  createHmacDrbg,
  hexToBytes,
  isBytes,
  validateObject,
  randomBytes as wcRandomBytes,
  type CHash,
  type HmacFn,
  type Signer,
  type TArg,
  type TRet,
} from '../utils.ts';
import {
  ScalarMultiplier,
  createCurveFields,
  createKeygen,
  mulAddUnsafe,
  normalizeZ,
  probeRandomBytes,
  validatePointCons,
  type AffinePoint,
  type CurveLengths,
  type CurvePoint,
  type CurvePointCons,
} from './curve.ts';
import { DER } from './der.ts';
import { getMinHashLength, invertCt, mapHashToField, type IField } from './modular.ts';

/** Shared affine point shape used by Weierstrass helpers. */
export type { AffinePoint };

// DER codec lives in der.ts; re-exported here because ECDSA signatures are its main consumer.
export { DER, DERErr, type IDER } from './der.ts';

type EndoBasis = [[bigint, bigint], [bigint, bigint]];
/**
 * When Weierstrass curve has `a=0`, it becomes Koblitz curve.
 * Koblitz curves allow using **efficiently-computable GLV endomorphism ψ**.
 * Endomorphism speeds up un-precomputed public-scalar multiplication (verification / key
 * recovery) by splitting a scalar into two half-width halves that share doublings.
 *
 * Endomorphism consists of beta, lambda and basises:
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
 * * `_splitEndoScalar` decomposes k ↦ k₁, k₂, by using reduced basis vectors.
 *   Gauss lattice reduction calculates them from initial basis vectors `(n, 0), (-λ, 0)`
 *
 * Check out `test/misc/endomorphism.js` and
 * {@link https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066 | this endomorphism gist}.
 */
export type EndomorphismOpts = {
  /** Cube root of unity used by the GLV endomorphism. */
  beta: bigint;
  /** Reduced lattice basis used for scalar splitting. */
  basises?: EndoBasis;
};
// We construct the basis so `den` is always positive and equals `n`,
// but the `num` sign depends on the basis, not on the secret value.
// Exact half-way cases round away from zero, which keeps the split symmetric
// around the reduced-basis boundaries used by endomorphism decomposition.
const divNearest = (num: bigint, den: bigint) => (num + (num >= 0 ? den : -den) / _2n) / den;

/** Two half-sized scalar components returned by endomorphism splitting. */
export type ScalarEndoParts = {
  /** Whether the first split scalar should be negated. */
  k1neg: boolean;
  /** Absolute value of the first split scalar. */
  k1: bigint;
  /** Whether the second split scalar should be negated. */
  k2neg: boolean;
  /** Absolute value of the second split scalar. */
  k2: bigint;
};

/** Splits scalar for GLV endomorphism. */
export function _splitEndoScalar(k: bigint, basis: EndoBasis, n: bigint): ScalarEndoParts {
  // Split scalar into two such that part is ~half bits: `abs(part) < sqrt(N)`
  // Since part can be negative, we need to do this on point.
  // Callers must provide a reduced GLV basis whose vectors satisfy
  // `a + b * lambda ≡ 0 (mod n)`; this helper only sees the basis and `n`.
  // Reject unreduced scalars instead of silently treating them mod n.
  aInRange('scalar', k, _0n, n);
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
  // Double check that resulting scalar is less than half bits of N: the wNAF pair walk
  // relies on the halves being short. This should only happen on wrong bases.
  // Also, the math inside is complex enough that this guard is worth keeping.
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n; // Half bits of N
  if (k1 < _0n || k1 >= MAX_NUM || k2 < _0n || k2 >= MAX_NUM) {
    throw new Error('splitScalar (endomorphism): failed for k');
  }
  return { k1neg, k1, k2neg, k2 };
}

/**
 * Option to enable hedged signatures with improved security.
 *
 * * Randomly generated k is bad, because broken CSPRNG would leak private keys.
 * * Deterministic k (RFC6979) is better; but is suspectible to fault attacks.
 *
 * We allow using technique described in RFC6979 3.6: additional k', a.k.a. adding randomness
 * to deterministic sig. If CSPRNG is broken & randomness is weak, it would STILL be as secure
 * as ordinary sig without ExtraEntropy.
 *
 * * `true` means "fetch data, from CSPRNG, incorporate it into k generation"
 * * `false` means "disable extra entropy, use purely deterministic k"
 * * `Uint8Array` passed means "incorporate following data into k generation"
 *
 * See {@link https://paulmillr.com/posts/deterministic-signatures/ | deterministic signatures}.
 */
export type ECDSAExtraEntropy = boolean | Uint8Array;
/**
 * - `compact` is the default format
 * - `recovered` is the same as compact, but with an extra byte indicating recovery byte
 * - `der` is ASN.1 DER encoding
 */
export type ECDSASignatureFormat = 'compact' | 'recovered' | 'der';
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 */
export type ECDSARecoverOpts = {
  /** Whether to hash the message before signature recovery. */
  prehash?: boolean;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures with `sig.s >= CURVE.n/2n`.
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 */
export type ECDSAVerifyOpts = {
  /** Whether to hash the message before verification. */
  prehash?: boolean;
  /** Whether to reject high-S signatures. */
  lowS?: boolean;
  /** Signature encoding to accept. */
  format?: ECDSASignatureFormat;
};
/**
 * - `prehash`: (default: true) indicates whether to do sha256(message).
 *   When a custom hash is used, it must be set to `false`.
 * - `lowS`: (default: true) prohibits signatures with `sig.s >= CURVE.n/2n`.
 *   Compatible with BTC/ETH. Setting `lowS: false` allows to create malleable signatures,
 *   which is default openssl behavior.
 *   Non-malleable signatures can still be successfully verified in openssl.
 * - `format`: (default: 'compact') 'compact' or 'recovered' with recovery byte
 * - `extraEntropy`: (default: false) creates signatures with increased
 *   security, see {@link ECDSAExtraEntropy}
 */
export type ECDSASignOpts = {
  /** Whether to hash the message before signing. */
  prehash?: boolean;
  /** Whether to normalize signatures into the low-S half-order. */
  lowS?: boolean;
  /** Signature encoding to produce. */
  format?: ECDSASignatureFormat;
  /** Optional hedging input for deterministic k generation. */
  extraEntropy?: ECDSAExtraEntropy;
};

function validateSigFormat(format: string): ECDSASignatureFormat {
  if (!['compact', 'recovered', 'der'].includes(format))
    throw new Error('Signature format must be "compact", "recovered", or "der"');
  return format as ECDSASignatureFormat;
}

function validateSigOpts<T extends ECDSASignOpts, D extends Required<ECDSASignOpts>>(
  opts: T,
  def: D
): D {
  validateObject(opts);
  const optsn = {} as D;
  // Normalize only the declared option subset from `def`; unknown keys are
  // intentionally ignored so shared / superset option bags stay valid here too.
  // `extraEntropy` stays an opaque payload until the signing path consumes it.
  for (let optName of Object.keys(def) as (keyof D)[]) {
    // @ts-ignore
    optsn[optName] = opts[optName] === undefined ? def[optName] : opts[optName];
  }
  abool(optsn.lowS!, 'lowS');
  abool(optsn.prehash!, 'prehash');
  if (optsn.format !== undefined) validateSigFormat(optsn.format);
  return optsn;
}

/** Projective XYZ point used by short Weierstrass curves. */
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
  /**
   * Encode the point into compressed or uncompressed SEC1 bytes.
   * @param isCompressed - Whether to use the compressed form.
   * @returns Encoded point bytes.
   */
  toBytes(isCompressed?: boolean): TRet<Uint8Array>;
  /**
   * Encode the point into compressed or uncompressed SEC1 hex.
   * @param isCompressed - Whether to use the compressed form.
   * @returns Encoded point hex.
   */
  toHex(isCompressed?: boolean): string;
  /**
   * Double-scalar multiplication `a⋅this + b⋅other` via Strauss–Shamir: both scalar walks
   * share one doubling chain, and GLV endomorphism (when the curve has one) halves the chain
   * again by splitting each scalar. 1.3-1.7x faster than two `multiplyUnsafe()` calls.
   * Not constant-time: only for public scalars, e.g. ECDSA verification's `u1⋅G + u2⋅P`.
   * @param a - Scalar for this point.
   * @param other - Second point.
   * @param b - Scalar for the second point.
   * @returns Combined product point.
   */
  mulAddUnsafe(a: bigint, other: WeierstrassPoint<T>, b: bigint): WeierstrassPoint<T>;
}

/** Constructor and metadata helpers for Weierstrass points. */
export interface WeierstrassPointCons<T> extends CurvePointCons<WeierstrassPoint<T>> {
  /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
  new (X: T, Y: T, Z: T): WeierstrassPoint<T>;
  /**
   * Return the curve parameters captured by this point constructor.
   * @returns Curve parameters.
   */
  CURVE(): WeierstrassOpts<T>;
}

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
  /** Base-field modulus. */
  p: bigint;
  /** Prime subgroup order. */
  n: bigint;
  /** Curve cofactor. */
  h: bigint;
  /** Weierstrass curve parameter `a`. */
  a: T;
  /** Weierstrass curve parameter `b`. */
  b: T;
  /** Generator x coordinate. */
  Gx: T;
  /** Generator y coordinate. */
  Gy: T;
}>;

/**
 * Optional helpers and overrides for a Weierstrass point constructor.
 *
 * When a cofactor != 1, there can be effective methods to:
 * 1. Determine whether a point is torsion-free
 * 2. Clear torsion component
 */
export type WeierstrassExtraOpts<T> = Partial<{
  /** Optional base-field override. */
  Fp: IField<T>;
  /** Optional scalar-field override. */
  Fn: IField<bigint>;
  /** Whether the point constructor accepts infinity points. */
  allowInfinityPoint: boolean;
  /** Optional GLV endomorphism data. */
  endo: EndomorphismOpts;
  /** RNG override used for scalar blinding. */
  randomBytes: (bytesLength?: number) => TRet<Uint8Array>;
  /** Optional torsion-check override. */
  isTorsionFree: (c: WeierstrassPointCons<T>, point: WeierstrassPoint<T>) => boolean;
  /** Optional cofactor-clearing override. */
  clearCofactor: (c: WeierstrassPointCons<T>, point: WeierstrassPoint<T>) => WeierstrassPoint<T>;
  /** Optional custom point decoder. */
  fromBytes: (bytes: TArg<Uint8Array>) => AffinePoint<T>;
  /** Optional custom point encoder. */
  toBytes: (
    c: WeierstrassPointCons<T>,
    point: WeierstrassPoint<T>,
    isCompressed: boolean
  ) => TRet<Uint8Array>;
}>;

/**
 * Options for ECDSA signatures over a Weierstrass curve.
 *
 * * lowS: (default: true) whether produced or verified signatures occupy the
 *   low half of `ecdsaOpts.n`. Prevents malleability.
 * * hmac: (default: noble-hashes hmac) function, would be used to init hmac-drbg for k generation.
 * * randomBytes: (default: webcrypto os-level CSPRNG) custom method for fetching secure randomness.
 * * bits2int, bits2int_modN: used in sigs, sometimes overridden by curves. Custom hooks are
 *   treated as pure functions over validated bytes and MUST NOT mutate caller-owned buffers or
 *   closure-captured option bags. `bits2int_modN` must also return a canonical scalar in
 *   `[0..Point.Fn.ORDER-1]`.
 */
export type ECDSAOpts = Partial<{
  /** Default low-S policy for this ECDSA instance. */
  lowS: boolean;
  /** HMAC implementation used by RFC6979 DRBG. */
  hmac: HmacFn;
  /** RNG override used by helper constructors. */
  randomBytes: (bytesLength?: number) => TRet<Uint8Array>;
  /** Hash-to-integer conversion override. */
  bits2int: (bytes: TArg<Uint8Array>) => bigint;
  /** Hash-to-integer-mod-n conversion override. Returns a canonical scalar in `[0..Fn.ORDER-1]`. */
  bits2int_modN: (bytes: TArg<Uint8Array>) => bigint;
}>;

/** Elliptic Curve Diffie-Hellman helper namespace. */
export interface ECDH {
  /**
   * Generate a secret/public key pair.
   * @param seed - Optional seed material.
   * @returns Secret/public key pair.
   */
  keygen: (seed?: TArg<Uint8Array>) => { secretKey: TRet<Uint8Array>; publicKey: TRet<Uint8Array> };
  /**
   * Derive the public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @param isCompressed - Whether to emit compressed SEC1 bytes.
   * @returns Encoded public key.
   */
  getPublicKey: (secretKey: TArg<Uint8Array>, isCompressed?: boolean) => TRet<Uint8Array>;
  /**
   * Compute the shared secret point from a secret key and peer public key.
   * @param secretKeyA - Local secret key bytes.
   * @param publicKeyB - Peer public key bytes.
   * @param isCompressed - Whether to emit compressed SEC1 bytes.
   * @returns Encoded shared point.
   */
  getSharedSecret: (
    secretKeyA: TArg<Uint8Array>,
    publicKeyB: TArg<Uint8Array>,
    isCompressed?: boolean
  ) => TRet<Uint8Array>;
  /** Point constructor used by this ECDH instance. */
  Point: WeierstrassPointCons<bigint>;
  /** Validation and random-key helpers. */
  utils: {
    /** Check whether a secret key has the expected encoding. */
    isValidSecretKey: (secretKey: TArg<Uint8Array>) => boolean;
    /** Check whether a public key decodes to a valid point. */
    isValidPublicKey: (publicKey: TArg<Uint8Array>, isCompressed?: boolean) => boolean;
    /** Generate a valid random secret key. */
    randomSecretKey: (seed?: TArg<Uint8Array>) => TRet<Uint8Array>;
  };
  /** Byte lengths for keys and signatures exposed by this curve. */
  lengths: CurveLengths;
}

/**
 * ECDSA interface.
 * Only supported for prime fields, not Fp2 (extension fields).
 */
export interface ECDSA extends ECDH {
  /**
   * Sign a message with the given secret key.
   * @param message - Message bytes.
   * @param secretKey - Secret key bytes.
   * @param opts - Optional signing tweaks. See {@link ECDSASignOpts}.
   * @returns Encoded signature bytes.
   */
  sign: (
    message: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array>,
    opts?: TArg<ECDSASignOpts>
  ) => TRet<Uint8Array>;
  /**
   * Verify a signature against a message and public key.
   * @param signature - Encoded signature bytes.
   * @param message - Message bytes.
   * @param publicKey - Encoded public key.
   * @param opts - Optional verification tweaks. See {@link ECDSAVerifyOpts}.
   * @returns Whether the signature is valid.
   */
  verify: (
    signature: TArg<Uint8Array>,
    message: TArg<Uint8Array>,
    publicKey: TArg<Uint8Array>,
    opts?: TArg<ECDSAVerifyOpts>
  ) => boolean;
  /**
   * Recover the public key encoded into a recoverable signature.
   * @param signature - Recoverable signature bytes.
   * @param message - Message bytes.
   * @param opts - Optional recovery tweaks. See {@link ECDSARecoverOpts}.
   * @returns Encoded recovered public key.
   */
  recoverPublicKey(
    signature: TArg<Uint8Array>,
    message: TArg<Uint8Array>,
    opts?: TArg<ECDSARecoverOpts>
  ): TRet<Uint8Array>;
  /** Signature constructor and parser helpers. */
  Signature: ECDSASignatureCons;
}
// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3), _4n = /* @__PURE__ */ BigInt(4);

/**
 * Creates weierstrass Point constructor, based on specified curve options.
 *
 * See {@link WeierstrassOpts}.
 * @param params - Curve parameters. See {@link WeierstrassOpts}.
 * @param extraOpts - Optional helpers and overrides. See {@link WeierstrassExtraOpts}.
 * @returns Weierstrass point constructor.
 * @throws If the curve parameters, overrides, or point codecs are invalid. {@link Error}
 *
 * @example
 * Construct a point type from explicit Weierstrass curve parameters.
 *
 * ```js
 * const opts = {
 *   p: 0xfffffffffffffffffffffffffffffffeffffac73n,
 *   n: 0x100000000000000000001b8fa16dfab9aca16b6b3n,
 *   h: 1n,
 *   a: 0n,
 *   b: 7n,
 *   Gx: 0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebbn,
 *   Gy: 0x938cf935318fdced6bc28286531733c3f03c4feen,
 * };
 * const secp160k1_Point = weierstrass(opts);
 * ```
 */
export function weierstrass<T>(
  params: WeierstrassOpts<T>,
  extraOpts: WeierstrassExtraOpts<T> = {}
): WeierstrassPointCons<T> {
  const validated = createCurveFields('weierstrass', params, extraOpts);
  const Fp = validated.Fp as IField<T>;
  const Fn = validated.Fn as IField<bigint>;
  let CURVE = validated.CURVE as WeierstrassOpts<T>;
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  validateObject(
    extraOpts,
    {},
    {
      allowInfinityPoint: 'boolean',
      clearCofactor: 'function',
      isTorsionFree: 'function',
      fromBytes: 'function',
      toBytes: 'function',
      endo: 'object',
      randomBytes: 'function',
    }
  );

  // Snapshot constructor-time flags whose later mutation would otherwise change
  // validity semantics of an already-built point type.
  const { endo, allowInfinityPoint } = extraOpts;
  const randomBytes = extraOpts.randomBytes === undefined ? wcRandomBytes : extraOpts.randomBytes;
  if (endo) {
    if (!Fp.is0(CURVE.a) || typeof endo.beta !== 'bigint' || !Array.isArray(endo.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }

  const lengths = getWLengths(Fp as TArg<IField<T>>, Fn);

  function assertCompressionIsSupported() {
    if (!Fp.isOdd) throw new Error('compression is not supported: Field does not have .isOdd()');
  }

  // Implements IEEE P1363 point encoding
  function pointToBytes(
    _c: WeierstrassPointCons<T>,
    point: WeierstrassPoint<T>,
    isCompressed: boolean
  ): TRet<Uint8Array> {
    // SEC 1 v2.0 §2.3.3 encodes infinity as the single octet 0x00. Only curves
    // that opt into infinity as a public point value should expose that byte form.
    if (allowInfinityPoint && point.is0()) return Uint8Array.of(0) as TRet<Uint8Array>;
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    abool(isCompressed, 'isCompressed');
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd!(y);
      return concatBytes(pprefix(hasEvenY), bx) as TRet<Uint8Array>;
    } else {
      return concatBytes(Uint8Array.of(0x04), bx, Fp.toBytes(y)) as TRet<Uint8Array>;
    }
  }
  function pointFromBytes(bytes: TArg<Uint8Array>) {
    abytes(bytes, undefined, 'Point');
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths; // e.g. for 32-byte: 33, 65
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    if (allowInfinityPoint && length === 1 && head === 0x00) return { x: Fp.ZERO, y: Fp.ZERO };
    // SEC 1 v2.0 §2.3.4 decodes 0x00 as infinity, but §3.2.2 public-key validation
    // rejects infinity. We therefore keep 0x00 rejected by default because callers
    // reuse this parser as the strict public-key boundary, and only admit it when
    // the curve explicitly opts into infinity as a public point value. secp256k1
    // crosstests show OpenSSL raw point codecs accept 0x00 too.
    // No actual validation is done here: use .assertValidity()
    if (length === comp && (head === 0x02 || head === 0x03)) {
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
      const evenY = Fp.isOdd!(y);
      const evenH = (head & 1) === 1; // ECDSA-specific
      if (evenH !== evenY) y = Fp.neg(y);
      return { x, y };
    } else if (length === uncomp && head === 0x04) {
      // TODO: more checks
      const L = Fp.BYTES;
      const x = Fp.fromBytes(tail.subarray(0, L));
      const y = Fp.fromBytes(tail.subarray(L, L * 2));
      if (!isValidXY(x, y)) throw new Error('bad point: is not on curve');
      return { x, y };
    } else {
      throw new Error(
        `bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`
      );
    }
  }

  const encodePoint = extraOpts.toBytes === undefined ? pointToBytes : extraOpts.toBytes;
  const decodePoint = extraOpts.fromBytes === undefined ? pointFromBytes : extraOpts.fromBytes;
  // Hoisted from double() / add(): curve params never change after construction.
  // Koblitz curves (a=0, e.g. secp256k1) skip the three a-multiplications per operation;
  // the selection depends only on public curve constants.
  const b3 = Fp.mul(CURVE.b, _3n);
  const mulA = Fp.is0(CURVE.a) ? (_: T): T => Fp.ZERO : (x: T): T => Fp.mul(CURVE.a, x);
  function weierstrassEquation(x: T): T {
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b); // x³ + a * x + b
  }

  // TODO: move top-level
  /** Checks whether equation holds for given x, y: y² == x³ + ax + b */
  function isValidXY(x: T, y: T): boolean {
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x); // x³ + ax + b
    return Fp.eql(left, right);
  }

  // Keep constructor-time generator validation cheap: callers are responsible for supplying the
  // correct prime-order base point, while eager subgroup checks here would slow heavy module imports.
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

  function aprjpoint(other: unknown): asserts other is Point {
    if (!(other instanceof Point)) throw new Error('Weierstrass Point expected');
  }

  function splitEndoScalarN(k: bigint) {
    if (!endo || !endo.basises) throw new Error('no endo');
    return _splitEndoScalar(k, endo.basises, Fn.ORDER);
  }

  /**
   * Appends a (point, scalar) pair to the inputs of a vartime wNAF walk
   * ({@link mulAddUnsafe}). With GLV endomorphism the scalar is split into two half-width
   * pairs against P and ψ(P) = (β⋅x, y), halving the walk's shared doubling chain;
   * split signs fold into the points.
   */
  function pushWnafPair(points: Point[], scalars: bigint[], p: Point, k: bigint): void {
    if (!Fn.isValid(k)) throw new RangeError('invalid scalar: out of range'); // 0 is valid
    if (endo) {
      const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(k);
      const psi = new Point(Fp.mul(p.X, endo.beta), p.Y, p.Z);
      points.push(k1neg ? p.negate() : p, k2neg ? psi.negate() : psi);
      scalars.push(k1, k2);
    } else {
      points.push(p);
      scalars.push(k);
    }
  }

  // Successful assertValidity() results are cached: Point instances are frozen at construction,
  // so on-curve + subgroup facts cannot change afterwards. Only success is cached — invalid
  // points re-throw on every call. This matters most for pairing curves, where subgroup checks
  // cost a scalar multiplication and the same instance is re-validated across layers
  // (signature fromBytes, pairingBatch) or across repeated verifies with a cached public key.
  const validityCache = new WeakSet<object>();

  /**
   * Projective Point works in 3d / projective (homogeneous) coordinates:(X, Y, Z) ∋ (x=X/Z, y=Y/Z).
   * Default Point works in 2d / affine coordinates: (x, y).
   * We're doing calculations in projective, because its operations don't require costly inversion.
   */
  class Point implements WeierstrassPoint<T> {
    static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    static readonly ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
    static readonly Fp = Fp;
    static readonly Fn = Fn;

    readonly X: T;
    readonly Y: T;
    readonly Z: T;

    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X: T, Y: T, Z: T) {
      this.X = acoord('x', X);
      // This is not just about ZERO / infinity: ambient curves can have real
      // finite points with y=0. Those points are 2-torsion, so they cannot lie
      // in the odd prime-order subgroups this point type is meant to represent.
      this.Y = acoord('y', Y, true);
      this.Z = acoord('z', Z);
      Object.freeze(this);
    }

    static CURVE(): WeierstrassOpts<T> {
      return CURVE;
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

    static fromBytes(bytes: TArg<Uint8Array>): Point {
      const P = Point.fromAffine(decodePoint(abytes(bytes, undefined, 'point')));
      P.assertValidity();
      return P;
    }

    static fromHex(hex: string): Point {
      return Point.fromBytes(hexToBytes(hex));
    }

    get x(): T {
      return this.toAffine().x;
    }
    get y(): T {
      return this.toAffine().y;
    }

    /**
     * @param isLazy - true will defer table computation until the first multiplication
     */
    precompute(windowSize: number = 6, isLazy = true): Point {
      wnaf.setWindowSize(this, windowSize);
      if (!isLazy) this.multiply(_3n); // random number
      return this;
    }

    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity(): void {
      const p = this;
      if (p.is0()) {
        // (0, 1, 0) aka ZERO is invalid in most contexts.
        // In BLS, ZERO can be serialized, so we allow it.
        // Keep the accepted infinity encoding canonical: projective-equivalent (X, Y, 0) points
        // like (1, 1, 0) compare equal to ZERO, but only (0, 1, 0) should pass this guard.
        if (extraOpts.allowInfinityPoint && Fp.is0(p.X) && Fp.eql(p.Y, Fp.ONE) && Fp.is0(p.Z))
          return;
        throw new Error('bad point: ZERO');
      }
      if (validityCache.has(p)) return;
      // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
      const { x, y } = p.toAffine();
      if (!Fp.isValid(x) || !Fp.isValid(y)) throw new Error('bad point: x or y not field elements');
      if (!isValidXY(x, y)) throw new Error('bad point: equation left != right');
      if (!p.isTorsionFree()) throw new Error('bad point: not in prime-order subgroup');
      validityCache.add(p);
    }

    hasEvenY(): boolean {
      const { y } = this.toAffine();
      if (!Fp.isOdd) throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }

    /** Compare one point to another. */
    equals(other: WeierstrassPoint<T>): boolean {
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
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      let t0 = Fp.mul(X1, X1); // step 1
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3); // step 5
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = mulA(Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3); // step 10
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3); // step 15
      t2 = mulA(t2);
      t3 = Fp.sub(t0, t2);
      t3 = mulA(t3);
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
    add(other: WeierstrassPoint<T>): Point {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
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
      Z3 = mulA(t4);
      X3 = Fp.mul(b3, t2); // step 20
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0); // step 25
      t1 = Fp.add(t1, t0);
      t2 = mulA(t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2); // step 30
      t2 = mulA(t2);
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

    subtract(other: WeierstrassPoint<T>) {
      // Validate before calling `negate()` so wrong inputs fail with the point guard
      // instead of leaking a foreign `negate()` error.
      aprjpoint(other);
      return this.add(other.negate());
    }

    is0(): boolean {
      return this.equals(Point.ZERO);
    }

    /**
     * Constant time multiplication.
     * Uses precomputed tables (signed fixed-window wNAF) when available.
     * Uses scalar blinding and avoids endomorphism splitting in the secret-scalar path.
     * @param scalar - by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar: bigint): Point {
      // Keep the subgroup-scalar contract strict instead of reducing 0 / n to ZERO.
      // In key/signature-style callers, those values usually mean broken hash/scalar plumbing,
      // and failing closed is safer than silently producing the identity point.
      if (!Fn.isValidNot0(scalar)) throw new RangeError('invalid scalar: out of range'); // 0 is invalid
      const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);
      return normalize([p, f])[0];
    }

    /**
     * Non-constant-time multiplication. Uses width-4 wNAF with GLV endomorphism splitting
     * when available (two half-width scalars sharing one halved doubling chain).
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(scalar: bigint): Point {
      const p = this as Point;
      const sc = scalar;
      // Public-scalar callers may need 0, but n and larger values stay rejected here too.
      // Reducing them mod n would turn bad caller input into an accidental identity point.
      if (!Fn.isValid(sc)) throw new RangeError('invalid scalar: out of range'); // 0 is valid
      if (sc === _0n || p.is0()) return Point.ZERO;
      if (sc === _1n) return p;
      if (wnaf.hasWindowSize(this)) return wnaf.mulUnsafe(p, sc, normalize); // precomputes
      const points: Point[] = [];
      const scalars: bigint[] = [];
      pushWnafPair(points, scalars, p, sc);
      return mulAddUnsafe(Point, points, scalars);
    }

    /**
     * Non-constant-time double-scalar multiplication `a⋅this + b⋅other` (Strauss–Shamir).
     * Both walks share one doubling chain via {@link mulAddUnsafe}, and GLV endomorphism
     * (when available) halves the chain again by splitting each scalar into two half-width
     * parts. Used by ECDSA verification and public-key recovery for `R = u1⋅G + u2⋅P`.
     * Only for public scalars.
     */
    mulAddUnsafe(a: bigint, other: Point, b: bigint): Point {
      aprjpoint(other);
      const points: Point[] = [];
      const scalars: bigint[] = [];
      pushWnafPair(points, scalars, this as Point, a);
      pushWnafPair(points, scalars, other, b);
      return mulAddUnsafe(Point, points, scalars);
    }

    /**
     * Converts Projective point to affine (x, y) coordinates.
     * (X, Y, Z) ∋ (x=X/Z, y=Y/Z).
     * @param invertedZ - Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ?: T): AffinePoint<T> {
      const p = this;
      let iz = invertedZ;
      if (iz != null && !Fp.isValid(iz))
        throw new RangeError('"invertedZ" expected valid field element');
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
    }

    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree(): boolean {
      const { isTorsionFree } = extraOpts;
      if (cofactor === _1n) return true;
      if (isTorsionFree) return isTorsionFree(Point, this);
      // unsafe() will use the uncached wNAF path internally, since CURVE_ORDER >= Fn.ORDER
      return wnaf.mulUnsafe(this, CURVE_ORDER).is0();
    }

    clearCofactor(): Point {
      const { clearCofactor } = extraOpts;
      if (cofactor === _1n) return this; // Fast-path
      if (clearCofactor) return clearCofactor(Point, this) as Point;
      // Default fallback assumes the cofactor fits the usual subgroup-scalar
      // multiplyUnsafe() contract. Curves with larger / structured cofactors
      // should define a clearCofactor override anyway (e.g. psi/Frobenius maps).
      return this.multiplyUnsafe(cofactor);
    }

    isSmallOrder(): boolean {
      if (cofactor === _1n) return this.is0(); // Fast-path
      return this.clearCofactor().is0();
    }

    toBytes(isCompressed = true): TRet<Uint8Array> {
      abool(isCompressed, 'isCompressed');
      // Same policy as pointFromBytes(): keep ZERO out of the default byte surface because
      // callers use these encodings as public keys, where SEC 1 validation rejects infinity.
      this.assertValidity();
      return encodePoint(Point, this, isCompressed);
    }

    toHex(isCompressed = true): string {
      return bytesToHex(this.toBytes(isCompressed));
    }

    toString() {
      return `<Point ${this.is0() ? 'ZERO' : this.toHex()}>`;
    }
  }
  const normalize = (points: Point[]) => normalizeZ(Point, points);
  const wnaf = new ScalarMultiplier(Point, randomBytes);
  // Enable W=6 wNAF precomputes. Slows down first publicKey computation.
  // Disable for tiny toy curves, with scalar fields < 6 bits.
  if (wnaf.bits >= 6) Point.BASE.precompute(6);
  Object.freeze(Point.prototype);
  Object.freeze(Point);
  return Point;
}

/** Parsed ECDSA signature with helpers for recovery and re-encoding. */
export interface ECDSASignature {
  /** Signature component `r`. */
  readonly r: bigint;
  /** Signature component `s`. */
  readonly s: bigint;
  /** Optional recovery bit for recoverable signatures. */
  readonly recovery?: number;
  /**
   * Return a copy of the signature with a recovery bit attached.
   * @param recovery - Recovery bit to attach.
   * @returns Signature with an attached recovery bit.
   */
  addRecoveryBit(recovery: number): ECDSASignature & { readonly recovery: number };
  /**
   * Check whether the signature uses the high-S half-order.
   * @returns Whether the signature uses the high-S half-order.
   */
  hasHighS(): boolean;
  /**
   * Recover the public key from the hashed message and recovery bit.
   * @param messageHash - Hashed message bytes.
   * @returns Recovered public-key point.
   */
  recoverPublicKey(messageHash: TArg<Uint8Array>): WeierstrassPoint<bigint>;
  /**
   * Encode the signature into bytes.
   * @param format - Signature encoding to produce.
   * @returns Encoded signature bytes.
   */
  toBytes(format?: string): TRet<Uint8Array>;
  /**
   * Encode the signature into hex.
   * @param format - Signature encoding to produce.
   * @returns Encoded signature hex.
   */
  toHex(format?: string): string;
}
/** Constructor and decoding helpers for ECDSA signatures. */
export type ECDSASignatureCons = {
  /** Create a signature from `r`, `s`, and an optional recovery bit. */
  new (r: bigint, s: bigint, recovery?: number): ECDSASignature;
  /**
   * Decode a signature from bytes.
   * @param bytes - Encoded signature bytes.
   * @param format - Signature encoding to parse.
   * @returns Parsed signature.
   */
  fromBytes(bytes: TArg<Uint8Array>, format?: ECDSASignatureFormat): ECDSASignature;
  /**
   * Decode a signature from hex.
   * @param hex - Encoded signature hex.
   * @param format - Signature encoding to parse.
   * @returns Parsed signature.
   */
  fromHex(hex: string, format?: ECDSASignatureFormat): ECDSASignature;
};

// Points start with byte 0x02 when y is even; otherwise 0x03
function pprefix(hasEvenY: boolean): TRet<Uint8Array> {
  return Uint8Array.of(hasEvenY ? 0x02 : 0x03) as TRet<Uint8Array>;
}

function getWLengths<T>(Fp: TArg<IField<T>>, Fn: TArg<IField<bigint>>) {
  return {
    secretKey: Fn.BYTES,
    publicKey: 1 + Fp.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp.BYTES,
    publicKeyHasPrefix: true,
    // Raw compact `(r || s)` signature width; DER and recovered signatures use
    // different lengths outside this helper.
    signature: 2 * Fn.BYTES,
  };
}

/**
 * Sometimes users only need getPublicKey, getSharedSecret, and secret key handling.
 * This helper ensures no signature functionality is present. Less code, smaller bundle size.
 * @param Point - Weierstrass point constructor.
 * @param ecdhOpts - Optional randomness helpers:
 *   - `randomBytes` (optional): Optional RNG override.
 * @returns ECDH helper namespace.
 * @example
 * Sometimes users only need getPublicKey, getSharedSecret, and secret key handling.
 *
 * ```ts
 * import { ecdh } from '@noble/curves/abstract/weierstrass.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const dh = ecdh(p256.Point);
 * const alice = dh.keygen();
 * const shared = dh.getSharedSecret(alice.secretKey, alice.publicKey);
 * ```
 */
export function ecdh(
  Point: WeierstrassPointCons<bigint>,
  ecdhOpts: TArg<{ randomBytes?: (bytesLength?: number) => TRet<Uint8Array> }> = {}
): ECDH {
  validatePointCons(Point);
  const { Fn } = Point;
  const randomBytes_ = ecdhOpts.randomBytes === undefined ? wcRandomBytes : ecdhOpts.randomBytes;
  // Keep the advertised seed length aligned with mapHashToField(), which keeps a hard 16-byte
  // minimum even on toy curves.
  const lengths = Object.assign(getWLengths(Point.Fp, Fn), {
    seed: Math.max(getMinHashLength(Fn.ORDER), 16),
  });

  function isValidSecretKey(secretKey: TArg<Uint8Array>) {
    try {
      const num = Fn.fromBytes(secretKey);
      return Fn.isValidNot0(num);
    } catch (error) {
      return false;
    }
  }

  function isValidPublicKey(publicKey: TArg<Uint8Array>, isCompressed?: boolean): boolean {
    const { publicKey: comp, publicKeyUncompressed } = lengths;
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== comp) return false;
      if (isCompressed === false && l !== publicKeyUncompressed) return false;
      return !!Point.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  }

  /**
   * Produces cryptographically secure secret key from random of size
   * (groupLen + ceil(groupLen / 2)) with modulo bias being negligible.
   */
  function randomSecretKey(seed?: TArg<Uint8Array>): TRet<Uint8Array> {
    seed = seed === undefined ? randomBytes_(lengths.seed) : seed;
    return mapHashToField(abytes(seed, lengths.seed, 'seed'), Fn.ORDER) as TRet<Uint8Array>;
  }

  /**
   * Computes public key for a secret key. Checks for validity of the secret key.
   * @param isCompressed - whether to return compact (default), or full key
   * @returns Public key, full when isCompressed=false; short when isCompressed=true
   */
  function getPublicKey(secretKey: TArg<Uint8Array>, isCompressed = true): TRet<Uint8Array> {
    return Point.BASE.multiply(Fn.fromBytes(secretKey)).toBytes(isCompressed);
  }

  /**
   * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
   */
  function isProbPub(item: TArg<Uint8Array>): boolean | undefined {
    const { secretKey, publicKey, publicKeyUncompressed } = lengths;
    const allowedLengths = (Fn as { _lengths?: readonly number[] })._lengths;
    if (!isBytes(item)) return undefined;
    const l = abytes(item, undefined, 'key').length;
    const isPub = l === publicKey || l === publicKeyUncompressed;
    const isSec = l === secretKey || !!allowedLengths?.includes(l);
    // P-521 accepts both 65- and 66-byte secret keys, so overlapping lengths stay ambiguous.
    if (isPub && isSec) return undefined;
    return isPub;
  }

  /**
   * ECDH (Elliptic Curve Diffie Hellman).
   * Computes encoded shared point from secret key A and public key B.
   * Checks: 1) secret key validity 2) shared key is on-curve.
   * Does NOT hash the result or expose the SEC 1 x-coordinate-only `z`.
   * Returns the encoded shared point on purpose: callers that need `x_P`
   * can derive it from the encoded point, but `x_P` alone cannot recover the
   * point/parity back.
   * This helper only exposes the fully validated public-key path, not cofactor DH.
   * @param isCompressed - whether to return compact (default), or full key
   * @returns shared point encoding
   */
  function getSharedSecret(
    secretKeyA: TArg<Uint8Array>,
    publicKeyB: TArg<Uint8Array>,
    isCompressed = true
  ): TRet<Uint8Array> {
    if (isProbPub(secretKeyA) === true) throw new Error('first arg must be private key');
    if (isProbPub(publicKeyB) === false) throw new Error('second arg must be public key');
    const s = Fn.fromBytes(secretKeyA);
    const b = Point.fromBytes(publicKeyB); // checks for being on-curve
    return b.multiply(s).toBytes(isCompressed);
  }

  const utils = {
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey,
  };
  const keygen = createKeygen(randomSecretKey, getPublicKey);
  Object.freeze(utils);
  Object.freeze(lengths);

  return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
}

/**
 * Creates ECDSA signing interface for given elliptic curve `Point` and `hash` function.
 *
 * @param Point - created using {@link weierstrass} function
 * @param hash - used for 1) message prehash-ing 2) k generation in `sign`, using hmac_drbg(hash)
 * @param ecdsaOpts - rarely needed, see {@link ECDSAOpts}:
 *   - `lowS`: Default low-S policy.
 *   - `hmac`: HMAC implementation used by RFC6979 DRBG.
 *   - `randomBytes`: Optional RNG override.
 *   - `bits2int`: Optional hash-to-int conversion override.
 *   - `bits2int_modN`: Optional hash-to-int-mod-n conversion override.
 *
 * @returns ECDSA helper namespace.
 * @example
 * Create an ECDSA signer/verifier bundle for one curve implementation.
 *
 * ```ts
 * import { ecdsa } from '@noble/curves/abstract/weierstrass.js';
 * import { p256 } from '@noble/curves/nist.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const p256ecdsa = ecdsa(p256.Point, sha256);
 * const { secretKey, publicKey } = p256ecdsa.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = p256ecdsa.sign(msg, secretKey);
 * const isValid = p256ecdsa.verify(sig, msg, publicKey);
 * ```
 */
export function ecdsa(
  Point: WeierstrassPointCons<bigint>,
  hash: TArg<CHash>,
  ecdsaOpts: TArg<ECDSAOpts> = {}
): ECDSA {
  validatePointCons(Point);
  // Custom hash / bits2int hooks are treated as pure functions over validated caller-owned bytes.
  const hash_ = hash as CHash;
  ahash(hash_);
  validateObject(
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
  const opts = Object.assign({}, ecdsaOpts) as ECDSAOpts;
  const randomBytes = opts.randomBytes === undefined ? wcRandomBytes : opts.randomBytes;
  const hmac =
    opts.hmac === undefined
      ? (key: TArg<Uint8Array>, msg: TArg<Uint8Array>) => nobleHmac(hash_, key, msg)
      : (opts.hmac as HmacFn);

  const { Fp, Fn } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;
  // Nonce-inversion blinding in k2sig draws `getMinHashLength(n)` bytes per sign. Probe the RNG
  // once (see {@link probeRandomBytes}, shared with ScalarMultiplier): in environments without
  // working randomness, signing downgrades to Fermat inversion (invertCt) instead of throwing on
  // every sign(). The shape of returned bytes is still validated (by mapHashToField) on every
  // blinded call, where breakage fails closed.
  const blindLength = getMinHashLength(CURVE_ORDER);
  const csprng = probeRandomBytes(randomBytes, blindLength);
  const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point, opts);
  const defaultSigOpts: Required<ECDSASignOpts> = {
    prehash: true,
    lowS: typeof opts.lowS === 'boolean' ? opts.lowS : true,
    format: 'compact' as ECDSASignatureFormat,
    extraEntropy: false,
  };
  // SEC 1 4.1.6 public-key recovery tries x = r + jn for j = 0..h. Our recovered-signature
  // format only stores one overflow bit, so it can only distinguish q.x = r from q.x = r + n.
  // A third lift would have the form q.x = r + 2n. Since valid ECDSA r is in 1..n-1, the
  // smallest such lift is 1 + 2n, not 2n.
  const hasLargeRecoveryLifts = CURVE_ORDER * _2n + _1n < Fp.ORDER;

  function isBiggerThanHalfOrder(number: bigint) {
    const HALF = CURVE_ORDER >> _1n;
    return number > HALF;
  }
  function validateRS(title: string, num: bigint): bigint {
    if (!Fn.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
    return num;
  }
  function assertFieldSignIsSupported(): void {
    if (!Fp.isOdd) throw new Error("Field doesn't support isOdd");
  }
  function assertRecoverableCurve(): void {
    // ECDSA recovery only supports curves where the current recovery id can distinguish
    // q.x = r and q.x = r + n; larger lifts may need additional `r + n*i` branches.
    // SEC 1 4.1.6 recovers candidates via x = r + jn, but this format only encodes j = 0 or 1.
    // The next possible candidate is q.x = r + 2n, and its smallest valid value is 1 + 2n.
    // To easily get i, we either need to:
    // a. increase amount of valid recid values (4, 5...); OR
    // b. prohibit recovered signatures for those curves.
    if (hasLargeRecoveryLifts)
      throw new Error('"recovered" sig type is not supported for cofactor >2 curves');
  }
  function validateSigLength(bytes: TArg<Uint8Array>, format: ECDSASignatureFormat) {
    validateSigFormat(format);
    const size = lengths.signature!;
    const sizer = format === 'compact' ? size : format === 'recovered' ? size + 1 : undefined;
    return abytes(bytes, sizer);
  }

  /**
   * ECDSA signature with its (r, s) properties. Supports compact, recovered & DER representations.
   */
  class Signature implements ECDSASignature {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;

    constructor(r: bigint, s: bigint, recovery?: number) {
      this.r = validateRS('r', r); // r in [1..N-1];
      this.s = validateRS('s', s); // s in [1..N-1];
      if (recovery != null) {
        assertRecoverableCurve();
        if (![0, 1, 2, 3].includes(recovery)) throw new Error('invalid recovery id');
        this.recovery = recovery;
      }
      Object.freeze(this);
    }

    static fromBytes(
      bytes: TArg<Uint8Array>,
      format: ECDSASignatureFormat = defaultSigOpts.format
    ): Signature {
      validateSigLength(bytes, format);
      let recid: number | undefined;
      if (format === 'der') {
        const { r, s } = DER.toSig(abytes(bytes));
        return new Signature(r, s);
      }
      if (format === 'recovered') {
        recid = bytes[0];
        format = 'compact';
        bytes = bytes.subarray(1);
      }
      const L = lengths.signature! / 2;
      const r = bytes.subarray(0, L);
      const s = bytes.subarray(L, L * 2);
      return new Signature(Fn.fromBytes(r), Fn.fromBytes(s), recid);
    }

    static fromHex(hex: string, format?: ECDSASignatureFormat) {
      return this.fromBytes(hexToBytes(hex), format);
    }

    private assertRecovery(): number {
      const { recovery } = this;
      if (recovery == null) throw new Error('invalid recovery id: must be present');
      return recovery;
    }

    addRecoveryBit(recovery: number): RecoveredSignature {
      return new Signature(this.r, this.s, recovery) as RecoveredSignature;
    }

    // Unlike the top-level helper below, this method expects a digest that has
    // already been hashed to the curve's message representative.
    recoverPublicKey(messageHash: TArg<Uint8Array>): WeierstrassPoint<bigint> {
      const { r, s } = this;
      const recovery = this.assertRecovery();
      const radj = recovery === 2 || recovery === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj)) throw new Error('invalid recovery id: sig.r+curve.n != R.x');
      const x = Fp.toBytes(radj);
      const R = Point.fromBytes(concatBytes(pprefix((recovery & 1) === 0), x));
      const ir = Fn.inv(radj); // r^-1
      const h = bits2int_modN(abytes(messageHash, undefined, 'msgHash')); // Truncate hash
      const u1 = Fn.create(-h * ir); // -hr^-1
      const u2 = Fn.create(s * ir); // sr^-1
      // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1). unsafe is fine: there is no private data.
      const Q = Point.BASE.mulAddUnsafe(u1, R, u2);
      if (Q.is0()) throw new Error('invalid recovery: point at infinify');
      Q.assertValidity();
      return Q;
    }

    // Signatures should be low-s, to prevent malleability.
    hasHighS(): boolean {
      return isBiggerThanHalfOrder(this.s);
    }

    toBytes(format: ECDSASignatureFormat = defaultSigOpts.format): TRet<Uint8Array> {
      validateSigFormat(format);
      if (format === 'der') return hexToBytes(DER.hexFromSig(this)) as TRet<Uint8Array>;
      const { r, s } = this;
      const rb = Fn.toBytes(r);
      const sb = Fn.toBytes(s);
      if (format === 'recovered') {
        assertRecoverableCurve();
        return concatBytes(Uint8Array.of(this.assertRecovery()), rb, sb) as TRet<Uint8Array>;
      }
      return concatBytes(rb, sb) as TRet<Uint8Array>;
    }

    toHex(format?: ECDSASignatureFormat) {
      return bytesToHex(this.toBytes(format));
    }
  }
  type RecoveredSignature = Signature & { recovery: number };
  Object.freeze(Signature.prototype);
  Object.freeze(Signature);

  // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
  // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
  // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
  // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
  const bits2int: (bytes: TArg<Uint8Array>) => bigint =
    opts.bits2int === undefined
      ? function bits2int_def(bytes: TArg<Uint8Array>): bigint {
          // Our custom check "just in case", for protection against DoS
          if (bytes.length > 8192) throw new Error('input is too large');
          // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
          // for some cases, since bytes.length * 8 is not actual bitLength.
          const num = bytesToNumberBE(bytes); // check for == u8 done here
          const delta = bytes.length * 8 - fnBits; // truncate to nBitLength leftmost bits
          return delta > 0 ? num >> BigInt(delta) : num;
        }
      : (opts.bits2int as (bytes: TArg<Uint8Array>) => bigint);
  const bits2int_modN: (bytes: TArg<Uint8Array>) => bigint =
    opts.bits2int_modN === undefined
      ? function bits2int_modN_def(bytes: TArg<Uint8Array>): bigint {
          return Fn.create(bits2int(bytes)); // can't use bytesToNumberBE here
        }
      : (opts.bits2int_modN as (bytes: TArg<Uint8Array>) => bigint);
  const ORDER_MASK = bitMask(fnBits);
  // Pads output with zero as per spec.
  /** Converts to bytes. Checks if num in `[0..ORDER_MASK-1]` e.g.: `[0..2^256-1]`. */
  function int2octets(num: bigint): TRet<Uint8Array> {
    aInRange('num < 2^' + fnBits, num, _0n, ORDER_MASK);
    return Fn.toBytes(num) as TRet<Uint8Array>;
  }

  function validateMsgAndHash(message: TArg<Uint8Array>, prehash: boolean): TRet<Uint8Array> {
    abytes(message, undefined, 'message');
    return (
      prehash ? abytes(hash_(message), undefined, 'prehashed message') : message
    ) as TRet<Uint8Array>;
  }

  /**
   * Steps A, D of RFC6979 3.2.
   * Creates RFC6979 seed; converts msg/privKey to numbers.
   * Used only in sign, not in verify.
   *
   * Warning: we cannot assume here that message has same amount of bytes as curve order,
   * this will be invalid at least for P521. Also it can be bigger for P224 + SHA256.
   */
  function prepSig(
    message: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array>,
    opts: TArg<ECDSASignOpts>
  ) {
    const { lowS, prehash, extraEntropy } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash); // RFC6979 3.2 A: h1 = H(m)
    // We can't later call bits2octets, since nested bits2int is broken for curves
    // with fnBits % 8 !== 0. Because of that, we unwrap it here as int2octets call.
    // const bits2octets = (bits) => int2octets(bits2int_modN(bits))
    const h1int = bits2int_modN(message);
    const d = Fn.fromBytes(secretKey); // validate secret key, convert to bigint
    if (!Fn.isValidNot0(d)) throw new Error('invalid private key');
    const seedArgs: TArg<Uint8Array>[] = [int2octets(d), int2octets(h1int)];
    // extraEntropy. RFC6979 3.6: additional k' (optional).
    if (extraEntropy != null && extraEntropy !== false) {
      // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
      // gen random bytes OR pass as-is
      const e = extraEntropy === true ? randomBytes(lengths.secretKey) : extraEntropy;
      seedArgs.push(abytes(e, undefined, 'extraEntropy')); // check for being bytes
    }
    const seed = concatBytes(...seedArgs) as TRet<Uint8Array>; // Step D of RFC6979 3.2
    const m = h1int; // no need to call bits2int second time here, it is inside truncateHash!
    // Converts signature params into point w r/s, checks result for validity.
    // To transform k => Signature:
    // q = k⋅G
    // r = q.x mod n
    // s = k^-1(m + rd) mod n
    // The nonce inversion is blinded: with random b ∈ [1,n−1], s = (bk)^-1(bm + bdr) per
    // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. Fn.inv()'s extended-Euclidean
    // loop count depends on its input (cf. Minerva), but here it only ever sees b·k — uniformly
    // random, independent of k — so its timing reveals nothing about the nonce; b also masks d in
    // the products. Without a CSPRNG (probed in ecdsa()) we fall back to Fermat inversion
    // (invertCt), whose control flow is data-independent, at ~4x the inversion cost.
    function k2sig(kBytes: TArg<Uint8Array>): Signature | undefined {
      // RFC 6979 Section 3.2, step 3: k = bits2int(T)
      // Important: all mod() calls here must be done over N
      const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
      if (!Fn.isValidNot0(k)) return; // Valid scalars (including k) must be in 1..N-1
      const q = Point.BASE.multiply(k).toAffine(); // q = k⋅G
      const r = Fn.create(q.x); // r = q.x mod n
      if (r === _0n) return;
      let s: bigint;
      if (csprng !== undefined) {
        // mapHashToField maps 1.5x-order-length uniform bytes into [1, n-1], negligible bias.
        const b = bytesToNumberBE(mapHashToField(csprng(blindLength), CURVE_ORDER));
        const ibk = Fn.inv(Fn.mul(b, k)); // (bk)^-1: inversion input is decorrelated from k
        const bm = Fn.mul(b, m);
        const bd = Fn.mul(b, d);
        s = Fn.create(ibk * Fn.create(bm + bd * r)); // s = (bk)^-1(bm + bdr) = k^-1(m + rd) mod n
      } else {
        const ik = invertCt(k, CURVE_ORDER); // k^-1 mod n with data-independent control flow
        s = Fn.create(ik * Fn.create(m + r * d)); // s = k^-1(m + rd) mod n
      }
      if (s === _0n) return;
      assertFieldSignIsSupported();
      let recovery = (q.x === r ? 0 : 2) | Number(Fp.isOdd!(q.y)); // recovery bit (2 or 3 when q.x>n)
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = Fn.neg(s); // if lowS was passed, ensure s is always in the bottom half of N
        recovery ^= 1;
      }
      return new Signature(r, normS, hasLargeRecoveryLifts ? undefined : recovery);
    }
    return { seed, k2sig };
  }

  /**
   * Signs a message or message hash with a secret key.
   * With the default `prehash: true`, raw message bytes are hashed internally;
   * only `{ prehash: false }` expects a caller-supplied digest.
   *
   * ```
   * sign(m, d) where
   *   k = rfc6979_hmac_drbg(m, d)
   *   (x, y) = G × k
   *   r = x mod n
   *   s = (m + dr) / k mod n
   * ```
   */
  function sign(
    message: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array>,
    opts: TArg<ECDSASignOpts> = {}
  ): TRet<Uint8Array> {
    const { seed, k2sig } = prepSig(message, secretKey, opts); // Steps A, D of RFC6979 3.2.
    const drbg = createHmacDrbg<Signature>(hash_.outputLen, Fn.BYTES, hmac);
    const sig = drbg(seed, k2sig); // Steps B, C, D, E, F, G
    return sig.toBytes(opts.format);
  }

  /**
   * Verifies a signature against message and public key.
   * Rejects lowS signatures by default: see {@link ECDSAVerifyOpts}.
   * Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
   *
   * ```
   * verify(r, s, h, P) where
   *   u1 = hs^-1 mod n
   *   u2 = rs^-1 mod n
   *   R = u1⋅G + u2⋅P
   *   mod(R.x, n) == r
   * ```
   */
  function verify(
    signature: TArg<Uint8Array>,
    message: TArg<Uint8Array>,
    publicKey: TArg<Uint8Array>,
    opts: TArg<ECDSAVerifyOpts> = {}
  ): boolean {
    const { lowS, prehash, format } = validateSigOpts(opts, defaultSigOpts);
    publicKey = abytes(publicKey, undefined, 'publicKey');
    message = validateMsgAndHash(message, prehash);
    if (!isBytes(signature as any)) {
      const end = signature instanceof Signature ? ', use sig.toBytes()' : '';
      throw new Error('verify expects Uint8Array signature' + end);
    }
    validateSigLength(signature, format); // execute this twice because we want loud error
    try {
      const sig = Signature.fromBytes(signature, format);
      const P = Point.fromBytes(publicKey);
      if (lowS && sig.hasHighS()) return false;
      const { r, s } = sig;
      const h = bits2int_modN(message); // mod n, not mod p
      const is = Fn.inv(s); // s^-1 mod n
      const u1 = Fn.create(h * is); // u1 = hs^-1 mod n
      const u2 = Fn.create(r * is); // u2 = rs^-1 mod n
      const R = Point.BASE.mulAddUnsafe(u1, P, u2); // u1⋅G + u2⋅P, joint Strauss–Shamir
      if (R.is0()) return false;
      const v = Fn.create(R.x); // v = r.x mod n
      return v === r;
    } catch (e) {
      return false;
    }
  }

  function recoverPublicKey(
    signature: TArg<Uint8Array>,
    message: TArg<Uint8Array>,
    opts: TArg<ECDSARecoverOpts> = {}
  ): TRet<Uint8Array> {
    // Top-level recovery mirrors `sign()` / `verify()`: it hashes raw message
    // bytes first unless the caller passes `{ prehash: false }`.
    const { prehash } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    return Signature.fromBytes(signature, 'recovered').recoverPublicKey(message).toBytes();
  }

  return Object.freeze({
    keygen,
    getPublicKey,
    getSharedSecret,
    utils,
    lengths,
    Point,
    sign,
    verify,
    recoverPublicKey,
    Signature,
    hash: hash_,
  }) satisfies Signer;
}
