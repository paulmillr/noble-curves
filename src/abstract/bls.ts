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
import { abytes, memoized, notImplemented, randomBytes } from '../utils.ts';
import { normalizeZ, type CurveLengths } from './curve.ts';
import {
  createHasher,
  type H2CDSTOpts,
  type H2CHasher,
  type H2CHashOpts,
  type H2COpts,
  type MapToCurve,
} from './hash-to-curve.ts';
import { getMinHashLength, mapHashToField, type IField } from './modular.ts';
import type { Fp12, Fp12Bls, Fp2, Fp2Bls, Fp6Bls } from './tower.ts';
import { type WeierstrassPoint, type WeierstrassPointCons } from './weierstrass.ts';

type Fp = bigint; // Can be different field?

// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3);

export type BlsTwistType = 'multiplicative' | 'divisive';

export type BlsShortSignatureCoder<Fp> = {
  fromBytes(bytes: Uint8Array): WeierstrassPoint<Fp>;
  fromHex(hex: string): WeierstrassPoint<Fp>;
  toBytes(point: WeierstrassPoint<Fp>): Uint8Array;
  toHex(point: WeierstrassPoint<Fp>): string;
};

export type BlsLongSignatureCoder<Fp> = {
  fromBytes(bytes: Uint8Array): WeierstrassPoint<Fp>;
  fromHex(hex: string): WeierstrassPoint<Fp>;
  toBytes(point: WeierstrassPoint<Fp>): Uint8Array;
  toHex(point: WeierstrassPoint<Fp>): string;
};

export type BlsFields = {
  Fp: IField<Fp>;
  Fr: IField<bigint>;
  Fp2: Fp2Bls;
  Fp6: Fp6Bls;
  Fp12: Fp12Bls;
};

export type BlsPostPrecomputePointAddFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2
) => { Rx: Fp2; Ry: Fp2; Rz: Fp2 };
export type BlsPostPrecomputeFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2,
  pointAdd: BlsPostPrecomputePointAddFn
) => void;
export type BlsPairing = {
  lengths: CurveLengths;
  Fr: IField<bigint>;
  Fp12: Fp12Bls;
  calcPairingPrecomputes: (p: WeierstrassPoint<Fp2>) => Precompute;
  millerLoopBatch: (pairs: [Precompute, Fp, Fp][]) => Fp12;
  pairing: (P: WeierstrassPoint<Fp>, Q: WeierstrassPoint<Fp2>, withFinalExponent?: boolean) => Fp12;
  pairingBatch: (
    pairs: { g1: WeierstrassPoint<Fp>; g2: WeierstrassPoint<Fp2> }[],
    withFinalExponent?: boolean
  ) => Fp12;
  randomSecretKey: (seed?: Uint8Array) => Uint8Array;
};

export type BlsPairingParams = {
  // MSB is always ignored and used as marker for length, otherwise leading zeros will be lost.
  // Can be different from `X` (seed) param.
  ateLoopSize: bigint;
  xNegative: boolean;
  twistType: BlsTwistType; // BLS12-381: Multiplicative, BN254: Divisive
  randomBytes?: (len?: number) => Uint8Array;
  postPrecompute?: BlsPostPrecomputeFn; // Ugly hack to untwist point in BN254 after miller loop
};
export type BlsHasherParams = {
  mapToG1?: MapToCurve<Fp>;
  mapToG2?: MapToCurve<Fp2>;
  hasherOpts: H2COpts;
  hasherOptsG1: H2COpts;
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
  lengths: CurveLengths;
  millerLoopBatch: BlsPairing['millerLoopBatch'];
  pairing: BlsPairing['pairing'];
  pairingBatch: BlsPairing['pairingBatch'];
  G1: { Point: WeierstrassPointCons<Fp> };
  G2: { Point: WeierstrassPointCons<Fp2> };
  fields: {
    Fp: IField<Fp>;
    Fp2: Fp2Bls;
    Fp6: Fp6Bls;
    Fp12: Fp12Bls;
    Fr: IField<bigint>;
  };
  utils: {
    randomSecretKey: (seed?: Uint8Array) => Uint8Array;
    calcPairingPrecomputes: BlsPairing['calcPairingPrecomputes'];
  };
  params: {
    ateLoopSize: bigint;
    twistType: BlsTwistType;
  };
}

export interface BlsCurvePairWithHashers extends BlsCurvePair {
  G1: H2CHasher<WeierstrassPointCons<Fp>>;
  G2: H2CHasher<WeierstrassPointCons<Fp2>>;
}

export interface BlsCurvePairWithSignatures extends BlsCurvePairWithHashers {
  longSignatures: BlsSigs<bigint, Fp2>;
  shortSignatures: BlsSigs<Fp2, bigint>;
}

type BLSInput = Uint8Array;
export interface BlsSigs<P, S> {
  lengths: CurveLengths;
  keygen(seed?: Uint8Array): {
    secretKey: Uint8Array;
    publicKey: WeierstrassPoint<P>;
  };
  getPublicKey(secretKey: Uint8Array): WeierstrassPoint<P>;
  sign(hashedMessage: WeierstrassPoint<S>, secretKey: Uint8Array): WeierstrassPoint<S>;
  verify(
    signature: WeierstrassPoint<S> | BLSInput,
    message: WeierstrassPoint<S>,
    publicKey: WeierstrassPoint<P> | BLSInput
  ): boolean;
  verifyBatch: (
    signature: WeierstrassPoint<S> | BLSInput,
    items: { message: WeierstrassPoint<S>; publicKey: WeierstrassPoint<P> | BLSInput }[]
  ) => boolean;
  aggregatePublicKeys(publicKeys: (WeierstrassPoint<P> | BLSInput)[]): WeierstrassPoint<P>;
  aggregateSignatures(signatures: (WeierstrassPoint<S> | BLSInput)[]): WeierstrassPoint<S>;
  hash(message: Uint8Array, DST?: string | Uint8Array, hashOpts?: H2CHashOpts): WeierstrassPoint<S>;
  Signature: BlsLongSignatureCoder<S>;
}

// Not used with BLS12-381 (no sequential `11` in X). Useful for other curves.
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
  if (!Array.isArray(arr) || arr.length === 0) throw new Error('expected non-empty array');
}

// This should be enough for bn254, no need to export full stuff?
function createBlsPairing(
  fields: BlsFields,
  G1: WeierstrassPointCons<Fp>,
  G2: WeierstrassPointCons<Fp2>,
  params: BlsPairingParams
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
    Ry = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), Fp2div2)), Fp2.mul(Fp2.sqr(t2), _3n)); // ((T0 + T3) / 2)² - 3 * T2²
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
    const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, _2n)), Fp2.mul(Fp2.sqr(t0), Rz)); // T3 - 2 * T4 + T0² * Rz
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

  const calcPairingPrecomputes = memoized((point: G2) => {
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
  });

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
    // Cache precomputed toAffine for all points
    normalizeZ(
      G1,
      pairs.map(({ g1 }) => g1)
    );
    normalizeZ(
      G2,
      pairs.map(({ g2 }) => g2)
    );
    for (const { g1, g2 } of pairs) {
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
  const rand = params.randomBytes || randomBytes;
  const randomSecretKey = (seed = rand(lengths.seed)): Uint8Array => {
    abytes(seed, lengths.seed, 'seed');
    return mapHashToField(seed, Fr.ORDER);
  };
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
  hashToSigCurve: (msg: Uint8Array, options?: H2CDSTOpts) => WeierstrassPoint<S>,
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
    lengths: { ...lengths, secretKey: Fr.BYTES },
    keygen(seed?: Uint8Array) {
      const secretKey = randomSecretKey(seed);
      const publicKey = this.getPublicKey(secretKey);
      return { secretKey, publicKey };
    },
    // P = pk x G
    getPublicKey(secretKey: Uint8Array): PubPoint {
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
    sign(message: SigPoint, secretKey: Uint8Array, unusedArg?: any): SigPoint {
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

    hash(messageBytes: Uint8Array, DST?: string | Uint8Array): SigPoint {
      abytes(messageBytes);
      const opts = DST ? { DST } : undefined;
      return hashToSigCurve(messageBytes, opts);
    },
    Signature: SignatureCoder,
  }) /*satisfies Signer */;
}

type BlsSignatureCoders = Partial<{
  LongSignature: BlsLongSignatureCoder<Fp2>;
  ShortSignature: BlsShortSignatureCoder<Fp>;
}>;

// NOTE: separate function instead of function override, so we don't depend on hasher in bn254.
export function blsBasic(
  fields: BlsFields,
  G1_Point: WeierstrassPointCons<Fp>,
  G2_Point: WeierstrassPointCons<Fp2>,
  params: BlsPairingParams
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
  return Object.freeze({
    lengths,
    millerLoopBatch,
    pairing,
    pairingBatch,
    G1,
    G2,
    fields: { Fr, Fp, Fp2, Fp6, Fp12 },
    params: {
      ateLoopSize: params.ateLoopSize,
      twistType: params.twistType,
    },
    utils: {
      randomSecretKey,
      calcPairingPrecomputes,
    },
  });
}

// We can export this too, but seems there is not much reasons for now? If user wants hasher, they can just create hasher.
function blsHashers(
  fields: BlsFields,
  G1_Point: WeierstrassPointCons<Fp>,
  G2_Point: WeierstrassPointCons<Fp2>,
  params: BlsPairingParams,
  hasherParams: BlsHasherParams
): BlsCurvePairWithHashers {
  const base = blsBasic(fields, G1_Point, G2_Point, params);
  const G1Hasher = createHasher(G1_Point, hasherParams.mapToG1 || notImplemented, {
    ...hasherParams.hasherOpts,
    ...hasherParams.hasherOptsG1,
  });
  const G2Hasher = createHasher(G2_Point, hasherParams.mapToG2 || notImplemented, {
    ...hasherParams.hasherOpts,
    ...hasherParams.hasherOptsG2,
  });
  return Object.freeze({ ...base, G1: G1Hasher, G2: G2Hasher });
}

// G1_Point: ProjConstructor<bigint>, G2_Point: ProjConstructor<Fp2>,
// Rename to blsSignatures?
export function bls(
  fields: BlsFields,
  G1_Point: WeierstrassPointCons<Fp>,
  G2_Point: WeierstrassPointCons<Fp2>,
  params: BlsPairingParams,
  hasherParams: BlsHasherParams,
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
