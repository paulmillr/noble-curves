/**
 * BLS != BLS.
 * The file implements BLS (Boneh-Lynn-Shacham) signatures.
 * Used in both BLS (Barreto-Lynn-Scott) and BN (Barreto-Naehrig)
 * families of pairing-friendly curves.
 * Consists of two curves: G1 and G2:
 * - G1 is a subgroup of (x, y) E(Fq) over y² = x³ + 4.
 * - G2 is a subgroup of ((x₁, x₂+i), (y₁, y₂+i)) E(Fq²) over y² = x³ + 4(1 + i) where i is √-1
 * - Gt, created by bilinear (ate) pairing e(G1, G2), consists of p-th roots of unity in
 *   Fq^k where k is embedding degree. Only degree 12 is currently supported, 24 is not.
 * Pairing is used to aggregate and verify signatures.
 * There are two modes of operation:
 * - Long signatures:  X-byte keys + 2X-byte sigs (G1 keys + G2 sigs).
 * - Short signatures: 2X-byte keys + X-byte sigs (G2 keys + G1 sigs).
 * @module
 **/
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { abytes, notImplemented, randomBytes, type TArg, type TRet } from '../utils.ts';
import { type CurveLengths } from './curve.ts';
import {
  createHasher,
  type H2CDSTOpts,
  type H2CHasher,
  type H2COpts,
  type MapToCurve,
} from './hash-to-curve.ts';
import { getMinHashLength, mapHashToField, type IField } from './modular.ts';
import type { Fp12, Fp12Bls, Fp2, Fp2Bls, Fp6Bls } from './tower.ts';
import { type WeierstrassPoint, type WeierstrassPointCons } from './weierstrass.ts';

type Fp = bigint; // Can be different field?

// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3);

/**
 * Twist convention used by the pairing formulas for a concrete curve family.
 * BLS12-381 uses a multiplicative twist, while BN254 uses a divisive one.
 */
export type BlsTwistType = 'multiplicative' | 'divisive';

/**
 * Codec exposed as `curve.shortSignatures.Signature`.
 * Use it to parse or serialize G1 signatures in short-signature mode.
 * In this mode, public keys live in G2.
 */
export type BlsShortSignatureCoder<Fp> = {
  /**
   * Parse a compressed signature from raw bytes.
   * @param bytes - Compressed signature bytes.
   * @returns Parsed signature point.
   */
  fromBytes(bytes: TArg<Uint8Array>): WeierstrassPoint<Fp>;
  /**
   * Parse a compressed signature from a hex string.
   * @param hex - Compressed signature hex string.
   * @returns Parsed signature point.
   */
  fromHex(hex: string): WeierstrassPoint<Fp>;
  /**
   * Encode a signature point into compressed bytes.
   * @param point - Signature point.
   * @returns Compressed signature bytes.
   */
  toBytes(point: WeierstrassPoint<Fp>): TRet<Uint8Array>;
  /**
   * Encode a signature point into a hex string.
   * @param point - Signature point.
   * @returns Compressed signature hex.
   */
  toHex(point: WeierstrassPoint<Fp>): string;
};

/**
 * Codec exposed as `curve.longSignatures.Signature`.
 * Use it to parse or serialize G2 signatures in long-signature mode.
 * In this mode, public keys live in G1.
 */
export type BlsLongSignatureCoder<Fp> = {
  /**
   * Parse a compressed signature from raw bytes.
   * @param bytes - Compressed signature bytes.
   * @returns Parsed signature point.
   */
  fromBytes(bytes: TArg<Uint8Array>): WeierstrassPoint<Fp>;
  /**
   * Parse a compressed signature from a hex string.
   * @param hex - Compressed signature hex string.
   * @returns Parsed signature point.
   */
  fromHex(hex: string): WeierstrassPoint<Fp>;
  /**
   * Encode a signature point into compressed bytes.
   * @param point - Signature point.
   * @returns Compressed signature bytes.
   */
  toBytes(point: WeierstrassPoint<Fp>): TRet<Uint8Array>;
  /**
   * Encode a signature point into a hex string.
   * @param point - Signature point.
   * @returns Compressed signature hex.
   */
  toHex(point: WeierstrassPoint<Fp>): string;
};

/** Tower fields needed by pairing code, hash-to-curve, and subgroup arithmetic. */
export type BlsFields = {
  /** Base field of G1 coordinates. */
  Fp: IField<Fp>;
  /** Scalar field used for secret scalars and subgroup order arithmetic. */
  Fr: IField<bigint>;
  /** Quadratic extension field used by G2. */
  Fp2: Fp2Bls;
  /** Sextic extension field used inside pairing arithmetic. */
  Fp6: Fp6Bls;
  /** Degree-12 extension field that contains the GT target group. */
  Fp12: Fp12Bls;
};

/**
 * Callback used by pairing post-processing hooks to add one more G2 point to the Miller-loop state.
 * @param Rx - Current projective X coordinate.
 * @param Ry - Current projective Y coordinate.
 * @param Rz - Current projective Z coordinate.
 * @param Qx - G2 affine x coordinate.
 * @param Qy - G2 affine y coordinate.
 * @returns Updated projective accumulator coordinates.
 */
export type BlsPostPrecomputePointAddFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2
) => { Rx: Fp2; Ry: Fp2; Rz: Fp2 };
/**
 * Hook for curve-specific pairing cleanup after the Miller loop precomputes are built.
 * @param Rx - Current projective X coordinate.
 * @param Ry - Current projective Y coordinate.
 * @param Rz - Current projective Z coordinate.
 * @param Qx - G2 affine x coordinate.
 * @param Qy - G2 affine y coordinate.
 * @param pointAdd - Callback used to fold one more point into the accumulator.
 */
export type BlsPostPrecomputeFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2,
  pointAdd: BlsPostPrecomputePointAddFn
) => void;
/** Low-level pairing helpers shared by BLS curve bundles. */
export type BlsPairing = {
  /** Byte lengths for keys and signatures exposed by this pairing family. */
  lengths: CurveLengths;
  /** Scalar field used by the pairing and signing helpers. */
  Fr: IField<bigint>;
  /** Target field used for the GT result of pairings. */
  Fp12: Fp12Bls;
  /**
   * Build Miller-loop precomputes for one G2 point.
   * @param p - G2 point to precompute.
   * @returns Pairing precompute table.
   */
  calcPairingPrecomputes: (p: WeierstrassPoint<Fp2>) => Precompute;
  /**
   * Evaluate a batch of Miller loops from precomputed line coefficients.
   * @param pairs - Precomputed Miller-loop inputs.
   * @returns Accumulated GT value before or after final exponentiation.
   */
  millerLoopBatch: (pairs: [Precompute, Fp, Fp][]) => Fp12;
  /**
   * Pair one G1 point with one G2 point.
   * @param P - G1 point.
   * @param Q - G2 point.
   * @param withFinalExponent - Whether to apply the final exponentiation step.
   * @returns GT pairing result.
   * @throws If either point is the point at infinity. {@link Error}
   */
  pairing: (P: WeierstrassPoint<Fp>, Q: WeierstrassPoint<Fp2>, withFinalExponent?: boolean) => Fp12;
  /**
   * Pair many G1/G2 pairs in one batch.
   * @param pairs - Point pairs to accumulate.
   * @param withFinalExponent - Whether to apply the final exponentiation step.
   * @returns GT pairing result. Empty input returns the multiplicative identity in GT.
   */
  pairingBatch: (
    pairs: { g1: WeierstrassPoint<Fp>; g2: WeierstrassPoint<Fp2> }[],
    withFinalExponent?: boolean
  ) => Fp12;
  /**
   * Generate a random secret key for this pairing family.
   * @param seed - Optional seed material.
   * @returns Secret key bytes.
   */
  randomSecretKey: (seed?: TArg<Uint8Array>) => TRet<Uint8Array>;
};

/**
 * Parameters that define the Miller-loop shape and twist handling
 * for a concrete pairing family.
 */
export type BlsPairingParams = {
  // MSB is always ignored and used as marker for length, otherwise leading zeros will be lost.
  // Can be different from `X` (seed) param.
  /** Signed loop parameter used by the Miller loop. */
  ateLoopSize: bigint;
  /** Whether the signed Miller-loop parameter is negative. */
  xNegative: boolean;
  /**
   * Twist convention used by the pairing formulas.
   * BLS12-381 is multiplicative; BN254 is divisive.
   */
  twistType: BlsTwistType;
  /**
   * Optional RNG override used by helper constructors.
   * Receives the requested byte length and returns random bytes.
   */
  randomBytes?: (len?: number) => TRet<Uint8Array>;
  /**
   * Optional hook for curve-specific untwisting after precomputation.
   * Used by BN254 after the Miller loop.
   */
  postPrecompute?: BlsPostPrecomputeFn;
};
/** Hash-to-curve settings shared by the G1 and G2 hashers inside a BLS curve bundle. */
export type BlsHasherParams = {
  /**
   * Optional map-to-curve override for G1.
   * Receives the hash-to-field tuple and returns one affine G1 point.
   */
  mapToG1?: MapToCurve<Fp>;
  /**
   * Optional map-to-curve override for G2.
   * Receives the hash-to-field tuple and returns one affine G2 point.
   */
  mapToG2?: MapToCurve<Fp2>;
  /** Shared baseline hash-to-curve options. */
  hasherOpts: H2COpts;
  /** G1-specific hash-to-curve options merged on top of `hasherOpts`. */
  hasherOptsG1: H2COpts;
  /** G2-specific hash-to-curve options merged on top of `hasherOpts`. */
  hasherOptsG2: H2COpts;
};
type PrecomputeSingle = [Fp2, Fp2, Fp2][];
type Precompute = PrecomputeSingle[];

/**
 * BLS consists of two curves: G1 and G2:
 * - G1 is a subgroup of (x, y) E(Fq) over y² = x³ + 4.
 * - G2 is a subgroup of ((x₁, x₂+i), (y₁, y₂+i)) E(Fq²) over y² = x³ + 4(1 + i) where i is √-1
 */
export interface BlsCurvePair {
  /** Byte lengths for keys and signatures exposed by this curve family. */
  lengths: CurveLengths;
  /**
   * Shared Miller-loop batch evaluator.
   * @param pairs - Precomputed Miller-loop inputs.
   * @returns Accumulated GT value.
   */
  millerLoopBatch: BlsPairing['millerLoopBatch'];
  /**
   * Pair one G1 point with one G2 point.
   * @param P - G1 point.
   * @param Q - G2 point.
   * @param withFinalExponent - Whether to apply the final exponentiation step.
   * @returns GT pairing result.
   * @throws If either point is the point at infinity. {@link Error}
   */
  pairing: BlsPairing['pairing'];
  /**
   * Pair many G1/G2 pairs in one batch.
   * @param pairs - Point pairs to accumulate.
   * @param withFinalExponent - Whether to apply the final exponentiation step.
   * @returns GT pairing result. Empty input returns the multiplicative identity in GT.
   */
  pairingBatch: BlsPairing['pairingBatch'];
  /** G1 point constructor for the base field subgroup. */
  G1: { Point: WeierstrassPointCons<Fp> };
  /** G2 point constructor for the twist subgroup. */
  G2: { Point: WeierstrassPointCons<Fp2> };
  /** Tower fields exposed by the pairing implementation. */
  fields: {
    Fp: IField<Fp>;
    Fp2: Fp2Bls;
    Fp6: Fp6Bls;
    Fp12: Fp12Bls;
    Fr: IField<bigint>;
  };
  /** Utility helpers shared by hashers and signers. */
  utils: {
    randomSecretKey: (seed?: TArg<Uint8Array>) => TRet<Uint8Array>;
    calcPairingPrecomputes: BlsPairing['calcPairingPrecomputes'];
  };
  /** Public pairing parameters exposed for introspection. */
  params: {
    ateLoopSize: bigint;
    twistType: BlsTwistType;
  };
}

/** BLS curve bundle extended with hash-to-curve helpers for G1 and G2. */
export interface BlsCurvePairWithHashers extends BlsCurvePair {
  /** G1 hasher bundle with RFC 9380 helpers. */
  G1: H2CHasher<WeierstrassPointCons<Fp>>;
  /** G2 hasher bundle with RFC 9380 helpers. */
  G2: H2CHasher<WeierstrassPointCons<Fp2>>;
}

/** BLS curve bundle extended with both hashers and signature helpers. */
export interface BlsCurvePairWithSignatures extends BlsCurvePairWithHashers {
  /** Long-signature mode: G1 public keys and G2 signatures. */
  longSignatures: BlsSigs<bigint, Fp2>;
  /** Short-signature mode: G2 public keys and G1 signatures. */
  shortSignatures: BlsSigs<Fp2, bigint>;
}

type BLSInput = TArg<Uint8Array>;
/** BLS signer helpers for one signature mode. */
export interface BlsSigs<P, S> {
  /** Byte lengths for secret keys, public keys, and signatures. */
  lengths: CurveLengths;
  /**
   * Generate a secret/public key pair for this signature mode.
   * @param seed - Optional seed material.
   * @returns Secret and public key pair.
   */
  keygen(seed?: TArg<Uint8Array>): {
    secretKey: TRet<Uint8Array>;
    publicKey: WeierstrassPoint<P>;
  };
  /**
   * Derive the public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns Public-key point.
   */
  getPublicKey(secretKey: TArg<Uint8Array>): WeierstrassPoint<P>;
  /**
   * Sign a message already hashed onto the signature subgroup.
   * @param hashedMessage - Message mapped to the signature subgroup.
   * @param secretKey - Secret key bytes.
   * @returns Signature point.
   */
  sign(hashedMessage: WeierstrassPoint<S>, secretKey: TArg<Uint8Array>): WeierstrassPoint<S>;
  /**
   * Verify one signature against one public key and hashed message.
   * @param signature - Signature point or encoded signature.
   * @param message - Hashed message point.
   * @param publicKey - Public-key point or encoded key.
   * @returns Whether the signature is valid.
   */
  verify(
    signature: WeierstrassPoint<S> | BLSInput,
    message: WeierstrassPoint<S>,
    publicKey: WeierstrassPoint<P> | BLSInput
  ): boolean;
  /**
   * Verify one aggregated signature against many `(message, publicKey)` pairs.
   * @param signature - Aggregated signature.
   * @param items - Message/public-key pairs.
   * @returns Whether the aggregated signature is valid. Same-message aggregate verification still
   *   requires proof of possession or another rogue-key defense from the caller.
   */
  verifyBatch: (
    signature: WeierstrassPoint<S> | BLSInput,
    items: { message: WeierstrassPoint<S>; publicKey: WeierstrassPoint<P> | BLSInput }[]
  ) => boolean;
  /**
   * Add many public keys into one aggregate point.
   * @param publicKeys - Public keys to aggregate.
   * @returns Aggregated public-key point. This is raw point addition and does not add proof of
   *   possession or rogue-key protection on its own.
   */
  aggregatePublicKeys(publicKeys: (WeierstrassPoint<P> | BLSInput)[]): WeierstrassPoint<P>;
  /**
   * Add many signatures into one aggregate point.
   * @param signatures - Signatures to aggregate.
   * @returns Aggregated signature point. This is raw point addition and does not change the proof
   *   of possession requirements of the aggregate-verification scheme.
   */
  aggregateSignatures(signatures: (WeierstrassPoint<S> | BLSInput)[]): WeierstrassPoint<S>;
  /**
   * Hash an arbitrary message onto the signature subgroup.
   * @param message - Message bytes.
   * @param DST - Optional domain separation tag.
   * @returns Curve point on the signature subgroup.
   */
  hash(message: TArg<Uint8Array>, DST?: TArg<string | Uint8Array>): WeierstrassPoint<S>;
  /** Signature codec for this mode. */
  Signature: BlsLongSignatureCoder<S>;
}

// Signed non-adjacent decomposition of the spec-defined Miller-loop parameter.
// BN254 benefits most because `6x+2` has multiple adjacent `11` runs, but BLS12-381's
// stored `|x|` still starts with `11`, so the Miller loop must also handle one `-1` digit there.
function NAfDecomposition(a: bigint) {
  const res = [];
  // a>1 because of marker bit
  for (; a > _1n; a >>= _1n) {
    if ((a & _1n) === _0n) res.unshift(0);
    else if ((a & _3n) === _3n) {
      res.unshift(-1);
      a += _1n;
    } else res.unshift(1);
  }
  return res;
}
function aNonEmpty(arr: any[]) {
  // Aggregate helpers use this to reject empty variable-length inputs consistently.
  // Without the guard, each caller would fall through into a different empty-input / identity
  // case and hide missing inputs behind outputs that still look structurally valid.
  if (!Array.isArray(arr) || arr.length === 0) throw new Error('expected non-empty array');
}

// This should be enough for bn254, no need to export full stuff?
function createBlsPairing(
  fields: TArg<BlsFields>,
  G1: WeierstrassPointCons<Fp>,
  G2: WeierstrassPointCons<Fp2>,
  params: TArg<BlsPairingParams>
): BlsPairing {
  const { Fr, Fp2, Fp12 } = fields;
  const { twistType, ateLoopSize, xNegative, postPrecompute } = params;
  type G1 = typeof G1.BASE;
  type G2 = typeof G2.BASE;
  // Applies sparse multiplication as line function
  let lineFunction: (c0: Fp2, c1: Fp2, c2: Fp2, f: Fp12, Px: Fp, Py: Fp) => Fp12;
  if (twistType === 'multiplicative') {
    lineFunction = (c0: Fp2, c1: Fp2, c2: Fp2, f: Fp12, Px: Fp, Py: Fp) =>
      Fp12.mul014(f, c0, Fp2.mul(c1, Px), Fp2.mul(c2, Py));
  } else if (twistType === 'divisive') {
    // NOTE: it should be [c0, c1, c2], but we use different order here to reduce complexity of
    // precompute calculations.
    lineFunction = (c0: Fp2, c1: Fp2, c2: Fp2, f: Fp12, Px: Fp, Py: Fp) =>
      Fp12.mul034(f, Fp2.mul(c2, Py), Fp2.mul(c1, Px), c0);
  } else throw new Error('bls: unknown twist type');

  const Fp2div2 = Fp2.div(Fp2.ONE, Fp2.mul(Fp2.ONE, _2n));
  function pointDouble(ell: PrecomputeSingle, Rx: Fp2, Ry: Fp2, Rz: Fp2) {
    const t0 = Fp2.sqr(Ry); // Ry²
    const t1 = Fp2.sqr(Rz); // Rz²
    const t2 = Fp2.mulByB(Fp2.mul(t1, _3n)); // 3 * T1 * B
    const t3 = Fp2.mul(t2, _3n); // 3 * T2
    const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0); // (Ry + Rz)² - T1 - T0
    const c0 = Fp2.sub(t2, t0); // T2 - T0 (i)
    const c1 = Fp2.mul(Fp2.sqr(Rx), _3n); // 3 * Rx²
    const c2 = Fp2.neg(t4); // -T4 (-h)

    ell.push([c0, c1, c2]);

    Rx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), Fp2div2); // ((T0 - T3) * Rx * Ry) / 2
    // ((T0 + T3) / 2)² - 3 * T2²
    Ry = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), Fp2div2)), Fp2.mul(Fp2.sqr(t2), _3n));
    Rz = Fp2.mul(t0, t4); // T0 * T4
    return { Rx, Ry, Rz };
  }
  function pointAdd(ell: PrecomputeSingle, Rx: Fp2, Ry: Fp2, Rz: Fp2, Qx: Fp2, Qy: Fp2) {
    // Addition
    const t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz)); // Ry - Qy * Rz
    const t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz)); // Rx - Qx * Rz
    const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)); // T0 * Qx - T1 * Qy == Ry * Qx  - Rx * Qy
    const c1 = Fp2.neg(t0); // -T0 == Qy * Rz - Ry
    const c2 = t1; // == Rx - Qx * Rz

    ell.push([c0, c1, c2]);

    const t2 = Fp2.sqr(t1); // T1²
    const t3 = Fp2.mul(t2, t1); // T2 * T1
    const t4 = Fp2.mul(t2, Rx); // T2 * Rx
    // T3 - 2 * T4 + T0² * Rz
    const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, _2n)), Fp2.mul(Fp2.sqr(t0), Rz));
    Rx = Fp2.mul(t1, t5); // T1 * T5
    Ry = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry)); // (T4 - T5) * T0 - T3 * Ry
    Rz = Fp2.mul(Rz, t3); // Rz * T3
    return { Rx, Ry, Rz };
  }

  // Pre-compute coefficients for sparse multiplication
  // Point addition and point double calculations is reused for coefficients
  // pointAdd happens only if bit set, so wNAF is reasonable. Unfortunately we cannot combine
  // add + double in windowed precomputes here, otherwise it would be single op (since X is static)
  const ATE_NAF = NAfDecomposition(ateLoopSize);

  const calcPairingPrecomputes = (point: G2) => {
    const p = point;
    const { x, y } = p.toAffine();
    // prettier-ignore
    const Qx = x, Qy = y, negQy = Fp2.neg(y);
    // prettier-ignore
    let Rx = Qx, Ry = Qy, Rz = Fp2.ONE;
    const ell: Precompute = [];
    for (const bit of ATE_NAF) {
      const cur: PrecomputeSingle = [];
      ({ Rx, Ry, Rz } = pointDouble(cur, Rx, Ry, Rz));
      if (bit) ({ Rx, Ry, Rz } = pointAdd(cur, Rx, Ry, Rz, Qx, bit === -1 ? negQy : Qy));
      ell.push(cur);
    }
    if (postPrecompute) {
      const last = ell[ell.length - 1];
      postPrecompute(Rx, Ry, Rz, Qx, Qy, pointAdd.bind(null, last));
    }
    return ell;
  };

  // Main pairing logic is here. Computes product of miller loops + final exponentiate
  // Applies calculated precomputes
  type MillerInput = [Precompute, Fp, Fp][];
  function millerLoopBatch(pairs: MillerInput, withFinalExponent: boolean = false) {
    let f12 = Fp12.ONE;
    if (pairs.length) {
      const ellLen = pairs[0][0].length;
      for (let i = 0; i < ellLen; i++) {
        f12 = Fp12.sqr(f12); // This allows us to do sqr only one time for all pairings
        // NOTE: we apply multiple pairings in parallel here
        for (const [ell, Px, Py] of pairs) {
          for (const [c0, c1, c2] of ell[i]) f12 = lineFunction(c0, c1, c2, f12, Px, Py);
        }
      }
    }
    if (xNegative) f12 = Fp12.conjugate(f12);
    return withFinalExponent ? Fp12.finalExponentiate(f12) : f12;
  }
  type PairingInput = { g1: G1; g2: G2 };
  // Calculates product of multiple pairings
  // This up to x2 faster than just `map(({g1, g2})=>pairing({g1,g2}))`
  function pairingBatch(pairs: PairingInput[], withFinalExponent: boolean = true) {
    const res: MillerInput = [];
    for (const { g1, g2 } of pairs) {
      // Mathematically, a zero pairing term contributes GT.ONE. We still reject it here because
      // this API mainly backs BLS verification, where ZERO inputs usually mean broken hash /
      // wiring. Silently skipping them would turn those failures into a neutral pairing product.
      // Callers that want the algebraic neutral-element behavior can filter ZERO terms first.
      if (g1.is0() || g2.is0()) throw new Error('pairing is not available for ZERO point');
      // This uses toAffine inside
      g1.assertValidity();
      g2.assertValidity();
      const Qa = g1.toAffine();
      res.push([calcPairingPrecomputes(g2), Qa.x, Qa.y]);
    }
    return millerLoopBatch(res, withFinalExponent);
  }
  // Calculates bilinear pairing
  function pairing(Q: G1, P: G2, withFinalExponent: boolean = true): Fp12 {
    return pairingBatch([{ g1: Q, g2: P }], withFinalExponent);
  }
  const lengths = {
    seed: getMinHashLength(Fr.ORDER),
  };
  const rand = params.randomBytes === undefined ? randomBytes : params.randomBytes;
  // Seeded calls deterministically reduce exactly `lengths.seed` bytes into `1..Fr.ORDER-1`;
  // omitting `seed` just fills that input buffer from the configured RNG first.
  const randomSecretKey = (seed?: TArg<Uint8Array>): TRet<Uint8Array> => {
    seed = seed === undefined ? rand(lengths.seed) : seed;
    abytes(seed, lengths.seed, 'seed');
    return mapHashToField(seed, Fr.ORDER) as TRet<Uint8Array>;
  };
  Object.freeze(lengths);
  return {
    lengths,
    Fr,
    Fp12, // NOTE: we re-export Fp12 here because pairing results are Fp12!
    millerLoopBatch,
    pairing,
    pairingBatch,
    calcPairingPrecomputes,
    randomSecretKey,
  };
}

function createBlsSig<P, S>(
  blsPairing: BlsPairing,
  PubPoint: WeierstrassPointCons<P>,
  SigPoint: WeierstrassPointCons<S>,
  isSigG1: boolean,
  hashToSigCurve: (msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>) => WeierstrassPoint<S>,
  SignatureCoder?: BlsLongSignatureCoder<S>
): BlsSigs<P, S> {
  const { Fr, Fp12, pairingBatch, randomSecretKey, lengths } = blsPairing;
  if (!SignatureCoder) {
    SignatureCoder = {
      fromBytes: notImplemented,
      fromHex: notImplemented,
      toBytes: notImplemented,
      toHex: notImplemented,
    };
  }
  type PubPoint = WeierstrassPoint<P>;
  type SigPoint = WeierstrassPoint<S>;
  function normPub(point: PubPoint | BLSInput): PubPoint {
    return point instanceof PubPoint ? (point as PubPoint) : PubPoint.fromBytes(point);
  }
  function normSig(point: SigPoint | BLSInput): SigPoint {
    return point instanceof SigPoint ? (point as SigPoint) : SigPoint.fromBytes(point);
  }
  // Sign/verify here take points already hashed onto the signature subgroup.
  // Raw bytes and points from the other subgroup must fail this constructor-brand
  // check before later validity checks run.
  function amsg(m: unknown): SigPoint {
    if (!(m instanceof SigPoint))
      throw new Error(`expected valid message hashed to ${!isSigG1 ? 'G2' : 'G1'} curve`);
    return m as SigPoint;
  }

  type G1 = WeierstrassPoint<Fp>;
  type G2 = WeierstrassPoint<Fp2>;
  type PairingInput = { g1: G1; g2: G2 };
  // What matters here is what point pairing API accepts as G1 or G2, not actual size or names
  const pair: (a: PubPoint, b: SigPoint) => PairingInput = !isSigG1
    ? (a: PubPoint, b: SigPoint) => ({ g1: a, g2: b }) as PairingInput
    : (a: PubPoint, b: SigPoint) => ({ g1: b, g2: a }) as PairingInput;
  return Object.freeze({
    lengths: Object.freeze({ ...lengths, secretKey: Fr.BYTES }),
    keygen(seed?: TArg<Uint8Array>) {
      const secretKey = randomSecretKey(seed);
      const publicKey = this.getPublicKey(secretKey);
      return { secretKey, publicKey };
    },
    // P = pk x G
    getPublicKey(secretKey: TArg<Uint8Array>): PubPoint {
      let sec;
      try {
        sec = PubPoint.Fn.fromBytes(secretKey);
      } catch (error) {
        // @ts-ignore
        throw new Error('invalid private key: ' + typeof secretKey, { cause: error });
      }
      return PubPoint.BASE.multiply(sec);
    },
    // S = pk x H(m)
    sign(message: SigPoint, secretKey: TArg<Uint8Array>, unusedArg?: any): SigPoint {
      if (unusedArg != null) throw new Error('sign() expects 2 arguments');
      const sec = PubPoint.Fn.fromBytes(secretKey);
      amsg(message).assertValidity();
      return message.multiply(sec);
    },
    // Checks if pairing of public key & hash is equal to pairing of generator & signature.
    // e(P, H(m)) == e(G, S)
    // e(S, G) == e(H(m), P)
    verify(
      signature: SigPoint | BLSInput,
      message: SigPoint,
      publicKey: PubPoint | BLSInput,
      unusedArg?: any
    ): boolean {
      if (unusedArg != null) throw new Error('verify() expects 3 arguments');
      signature = normSig(signature);
      publicKey = normPub(publicKey);
      const P = publicKey.negate();
      const G = PubPoint.BASE;
      const Hm = amsg(message);
      const S = signature;
      // This code was changed in 1.9.x:
      // Before it was G.negate() in G2, now it's always pubKey.negate
      // e(P, -Q)===e(-P, Q)==e(P, Q)^-1. Negate can be done anywhere (as long it is done once per pair).
      // We just moving sign, but since pairing is multiplicative, we doing X * X^-1 = 1
      try {
        const exp = pairingBatch([pair(P, Hm), pair(G, S)]);
        return Fp12.eql(exp, Fp12.ONE);
      } catch {
        return false;
      }
    },
    // https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
    // e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
    // TODO: maybe `{message: G2Hex, publicKey: G1Hex}[]` instead?
    verifyBatch(
      signature: SigPoint | BLSInput,
      items: { message: SigPoint; publicKey: PubPoint | BLSInput }[]
    ): boolean {
      aNonEmpty(items);
      const sig = normSig(signature);
      const nMessages = items.map((i) => i.message);
      const nPublicKeys = items.map((i) => normPub(i.publicKey));
      // NOTE: this works only for exact same object
      const messagePubKeyMap = new Map<SigPoint, PubPoint[]>();
      for (let i = 0; i < nPublicKeys.length; i++) {
        const pub = nPublicKeys[i];
        const msg = nMessages[i];
        let keys = messagePubKeyMap.get(msg);
        if (keys === undefined) {
          keys = [];
          messagePubKeyMap.set(msg, keys);
        }
        keys.push(pub);
      }
      const paired = [];
      const G = PubPoint.BASE;
      try {
        for (const [msg, keys] of messagePubKeyMap) {
          const groupPublicKey = keys.reduce((acc, msg) => acc.add(msg));
          paired.push(pair(groupPublicKey, msg));
        }
        paired.push(pair(G.negate(), sig));
        return Fp12.eql(pairingBatch(paired), Fp12.ONE);
      } catch {
        return false;
      }
    },
    // Adds a bunch of public key points together.
    // pk1 + pk2 + pk3 = pkA
    aggregatePublicKeys(publicKeys: (PubPoint | BLSInput)[]): PubPoint {
      aNonEmpty(publicKeys);
      publicKeys = publicKeys.map((pub) => normPub(pub));
      const agg = (publicKeys as PubPoint[]).reduce((sum, p) => sum.add(p), PubPoint.ZERO);
      agg.assertValidity();
      return agg;
    },

    // Adds a bunch of signature points together.
    // pk1 + pk2 + pk3 = pkA
    aggregateSignatures(signatures: (SigPoint | BLSInput)[]): SigPoint {
      aNonEmpty(signatures);
      signatures = signatures.map((sig) => normSig(sig));
      const agg = (signatures as SigPoint[]).reduce((sum, s) => sum.add(s), SigPoint.ZERO);
      agg.assertValidity();
      return agg;
    },

    hash(messageBytes: TArg<Uint8Array>, DST?: TArg<string | Uint8Array>): SigPoint {
      abytes(messageBytes);
      const opts = DST ? { DST } : undefined;
      return hashToSigCurve(messageBytes, opts);
    },
    Signature: Object.freeze({ ...SignatureCoder }),
  }) /*satisfies Signer */;
}

type BlsSignatureCoders = Partial<{
  LongSignature: BlsLongSignatureCoder<Fp2>;
  ShortSignature: BlsShortSignatureCoder<Fp>;
}>;

// NOTE: separate function instead of function override, so we don't depend on hasher in bn254.
/**
 * @param fields - Tower field implementations.
 * @param G1_Point - G1 point constructor.
 * @param G2_Point - G2 point constructor.
 * @param params - Pairing parameters. See {@link BlsPairingParams}.
 * @returns Pairing-only BLS helpers. The returned pairing surface rejects infinity inputs, while
 *   empty `pairingBatch(...)` calls return the multiplicative identity in GT. This keeps the
 *   low-level pairing API fail-closed for BLS-style callers, where identity points usually signal
 *   broken hash / wiring instead of an intentionally neutral pairing term. This also eagerly
 *   precomputes the G1 base-point table as a performance side effect.
 * @throws If the pairing parameters or underlying curve helpers are inconsistent. {@link Error}
 * @example
 * ```ts
 * import { blsBasic } from '@noble/curves/abstract/bls.js';
 * import { bn254 } from '@noble/curves/bn254.js';
 * // Pair a G1 point with a G2 point without the higher-level signer helpers.
 * const gt = bn254.pairing(bn254.G1.Point.BASE, bn254.G2.Point.BASE);
 * ```
 */
export function blsBasic(
  fields: TArg<BlsFields>,
  G1_Point: WeierstrassPointCons<Fp>,
  G2_Point: WeierstrassPointCons<Fp2>,
  params: TArg<BlsPairingParams>
): BlsCurvePair {
  // Fields are specific for curve, so for now we'll need to pass them with opts
  const { Fp, Fr, Fp2, Fp6, Fp12 } = fields;
  // Point on G1 curve: (x, y)
  // const G1_Point = weierstrass(CURVE.G1, { Fn: Fr });
  const G1 = { Point: G1_Point };
  // Point on G2 curve (complex numbers): (x₁, x₂+i), (y₁, y₂+i)
  const G2 = { Point: G2_Point };

  const pairingRes = createBlsPairing(fields, G1_Point, G2_Point, params);
  const {
    millerLoopBatch,
    pairing,
    pairingBatch,
    calcPairingPrecomputes,
    randomSecretKey,
    lengths,
  } = pairingRes;

  G1.Point.BASE.precompute(4);
  Object.freeze(G1);
  Object.freeze(G2);
  return Object.freeze({
    lengths: Object.freeze(lengths),
    millerLoopBatch,
    pairing,
    pairingBatch,
    G1,
    G2,
    fields: Object.freeze({ Fr, Fp, Fp2, Fp6, Fp12 }),
    params: Object.freeze({
      ateLoopSize: params.ateLoopSize,
      twistType: params.twistType,
    }),
    utils: Object.freeze({
      randomSecretKey,
      calcPairingPrecomputes,
    }),
  });
}

// We can export this too, but seems there is not much reasons for now? If user wants hasher, they can just create hasher.
function blsHashers(
  fields: TArg<BlsFields>,
  G1_Point: WeierstrassPointCons<Fp>,
  G2_Point: WeierstrassPointCons<Fp2>,
  params: TArg<BlsPairingParams>,
  hasherParams: TArg<BlsHasherParams>
): BlsCurvePairWithHashers {
  const base = blsBasic(fields, G1_Point, G2_Point, params);
  // Missing map hooks intentionally fail closed via notImplemented on first hash use.
  const G1Hasher = createHasher(
    G1_Point,
    hasherParams.mapToG1 === undefined ? notImplemented : hasherParams.mapToG1,
    {
      ...hasherParams.hasherOpts,
      ...hasherParams.hasherOptsG1,
    }
  );
  const G2Hasher = createHasher(
    G2_Point,
    hasherParams.mapToG2 === undefined ? notImplemented : hasherParams.mapToG2,
    {
      ...hasherParams.hasherOpts,
      ...hasherParams.hasherOptsG2,
    }
  );
  return Object.freeze({ ...base, G1: G1Hasher, G2: G2Hasher });
}

// G1_Point: ProjConstructor<bigint>, G2_Point: ProjConstructor<Fp2>,
// Rename to blsSignatures?
/**
 * @param fields - Tower field implementations.
 * @param G1_Point - G1 point constructor.
 * @param G2_Point - G2 point constructor.
 * @param params - Pairing parameters. See {@link BlsPairingParams}.
 * @param hasherParams - Hash-to-curve configuration. See {@link BlsHasherParams}.
 * @param signatureCoders - Signature codecs.
 * @returns BLS helpers with signers. The inherited pairing surface still rejects infinity inputs,
 *   and empty `pairingBatch(...)` calls still return the multiplicative identity in GT. Aggregate
 *   verification still requires proof of possession or another rogue-key defense from the caller.
 * @throws If the pairing, hashing, or signature helpers are configured inconsistently. {@link Error}
 * @example
 * ```ts
 * import { bls } from '@noble/curves/abstract/bls.js';
 * import { bls12_381 } from '@noble/curves/bls12-381.js';
 * const sigs = bls12_381.longSignatures;
 * // Use the full BLS helper set when you need hashing, keygen, signing, and verification.
 * const { secretKey, publicKey } = sigs.keygen();
 * const msg = sigs.hash(new TextEncoder().encode('hello noble'));
 * const sig = sigs.sign(msg, secretKey);
 * const isValid = sigs.verify(sig, msg, publicKey);
 * ```
 */
export function bls(
  fields: TArg<BlsFields>,
  G1_Point: WeierstrassPointCons<Fp>,
  G2_Point: WeierstrassPointCons<Fp2>,
  params: TArg<BlsPairingParams>,
  hasherParams: TArg<BlsHasherParams>,
  signatureCoders: BlsSignatureCoders
): BlsCurvePairWithSignatures {
  const base = blsHashers(fields, G1_Point, G2_Point, params, hasherParams);
  const pairingRes: BlsPairing = {
    ...base,
    Fr: base.fields.Fr,
    Fp12: base.fields.Fp12,
    calcPairingPrecomputes: base.utils.calcPairingPrecomputes,
    randomSecretKey: base.utils.randomSecretKey,
  };
  const longSignatures = createBlsSig(
    pairingRes,
    G1_Point,
    G2_Point,
    false,
    base.G2.hashToCurve,
    signatureCoders?.LongSignature
  );
  const shortSignatures = createBlsSig(
    pairingRes,
    G2_Point,
    G1_Point,
    true,
    base.G1.hashToCurve,
    signatureCoders?.ShortSignature
  );
  return Object.freeze({ ...base, longSignatures, shortSignatures });
}
