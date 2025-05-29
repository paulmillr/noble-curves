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
import {
  abytes,
  ensureBytes,
  memoized,
  randomBytes,
  type CHash,
  type Hex,
  type PrivKey,
} from '../utils.ts';
import { normalizeZ } from './curve.ts';
import {
  createHasher,
  type H2CHasher,
  type H2CHashOpts,
  type H2COpts,
  type H2CPointConstructor,
  type htfBasicOpts,
  type MapToCurve,
} from './hash-to-curve.ts';
import { getMinHashLength, mapHashToField, type IField } from './modular.ts';
import type { Fp12, Fp12Bls, Fp2, Fp2Bls, Fp6Bls } from './tower.ts';
import {
  weierstrassPoints,
  type CurvePointsRes,
  type CurvePointsType,
  type ProjConstructor,
  type ProjPointType,
} from './weierstrass.ts';

type Fp = bigint; // Can be different field?

// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3);

export type TwistType = 'multiplicative' | 'divisive';

export type ShortSignatureCoder<Fp> = {
  fromBytes(bytes: Uint8Array): ProjPointType<Fp>;
  fromHex(hex: Hex): ProjPointType<Fp>;
  toBytes(point: ProjPointType<Fp>): Uint8Array;
  /** @deprecated use `toBytes` */
  toRawBytes(point: ProjPointType<Fp>): Uint8Array;
  toHex(point: ProjPointType<Fp>): string;
};

export type SignatureCoder<Fp> = {
  fromBytes(bytes: Uint8Array): ProjPointType<Fp>;
  fromHex(hex: Hex): ProjPointType<Fp>;
  toBytes(point: ProjPointType<Fp>): Uint8Array;
  /** @deprecated use `toBytes` */
  toRawBytes(point: ProjPointType<Fp>): Uint8Array;
  toHex(point: ProjPointType<Fp>): string;
};

export type PostPrecomputePointAddFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2
) => { Rx: Fp2; Ry: Fp2; Rz: Fp2 };
export type PostPrecomputeFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2,
  pointAdd: PostPrecomputePointAddFn
) => void;
export type CurveType = {
  G1: CurvePointsType<Fp> & {
    ShortSignature: SignatureCoder<Fp>;
    mapToCurve: MapToCurve<Fp>;
    htfDefaults: H2COpts;
  };
  G2: CurvePointsType<Fp2> & {
    Signature: SignatureCoder<Fp2>;
    mapToCurve: MapToCurve<Fp2>;
    htfDefaults: H2COpts;
  };
  fields: {
    Fp: IField<Fp>;
    Fr: IField<bigint>;
    Fp2: Fp2Bls;
    Fp6: Fp6Bls;
    Fp12: Fp12Bls;
  };
  params: {
    // NOTE: MSB is always ignored and used as marker for length,
    // otherwise leading zeros will be lost.
    // Can be different from 'X' (seed) param!
    ateLoopSize: bigint;
    xNegative: boolean;
    r: bigint; // TODO: remove
    twistType: TwistType; // BLS12-381: Multiplicative, BN254: Divisive
  };
  htfDefaults: H2COpts;
  hash: CHash; // Because we need outputLen for DRBG
  randomBytes?: (bytesLength?: number) => Uint8Array;
  // This is super ugly hack for untwist point in BN254 after miller loop
  postPrecompute?: PostPrecomputeFn;
};

type PrecomputeSingle = [Fp2, Fp2, Fp2][];
type Precompute = PrecomputeSingle[];

export type CurveFn = {
  longSignatures: BLSSigs<bigint, Fp2>;
  shortSignatures: BLSSigs<Fp2, bigint>;

  millerLoopBatch: (pairs: [Precompute, Fp, Fp][]) => Fp12;
  pairing: (P: ProjPointType<Fp>, Q: ProjPointType<Fp2>, withFinalExponent?: boolean) => Fp12;
  pairingBatch: (
    pairs: { g1: ProjPointType<Fp>; g2: ProjPointType<Fp2> }[],
    withFinalExponent?: boolean
  ) => Fp12;

  /** @deprecated use `longSignatures.getPublicKey` */
  getPublicKey: (privateKey: PrivKey) => Uint8Array;
  /** @deprecated use `shortSignatures.getPublicKey` */
  getPublicKeyForShortSignatures: (privateKey: PrivKey) => Uint8Array;
  /** @deprecated use `longSignatures.sign` */
  sign: {
    (message: Hex, privateKey: PrivKey, htfOpts?: htfBasicOpts): Uint8Array;
    (message: ProjPointType<Fp2>, privateKey: PrivKey, htfOpts?: htfBasicOpts): ProjPointType<Fp2>;
  };
  /** @deprecated use `shortSignatures.sign` */
  signShortSignature: {
    (message: Hex, privateKey: PrivKey, htfOpts?: htfBasicOpts): Uint8Array;
    (message: ProjPointType<Fp>, privateKey: PrivKey, htfOpts?: htfBasicOpts): ProjPointType<Fp>;
  };
  /** @deprecated use `longSignatures.verify` */
  verify: (
    signature: Hex | ProjPointType<Fp2>,
    message: Hex | ProjPointType<Fp2>,
    publicKey: Hex | ProjPointType<Fp>,
    htfOpts?: htfBasicOpts
  ) => boolean;
  /** @deprecated use `shortSignatures.verify` */
  verifyShortSignature: (
    signature: Hex | ProjPointType<Fp>,
    message: Hex | ProjPointType<Fp>,
    publicKey: Hex | ProjPointType<Fp2>,
    htfOpts?: htfBasicOpts
  ) => boolean;
  verifyBatch: (
    signature: Hex | ProjPointType<Fp2>,
    messages: (Hex | ProjPointType<Fp2>)[],
    publicKeys: (Hex | ProjPointType<Fp>)[],
    htfOpts?: htfBasicOpts
  ) => boolean;
  /** @deprecated use `longSignatures.aggregatePublicKeys` */
  aggregatePublicKeys: {
    (publicKeys: Hex[]): Uint8Array;
    (publicKeys: ProjPointType<Fp>[]): ProjPointType<Fp>;
  };
  /** @deprecated use `longSignatures.aggregateSignatures` */
  aggregateSignatures: {
    (signatures: Hex[]): Uint8Array;
    (signatures: ProjPointType<Fp2>[]): ProjPointType<Fp2>;
  };
  /** @deprecated use `shortSignatures.aggregateSignatures` */
  aggregateShortSignatures: {
    (signatures: Hex[]): Uint8Array;
    (signatures: ProjPointType<Fp>[]): ProjPointType<Fp>;
  };
  /** @deprecated use `curves.G1` and `curves.G2` */
  G1: CurvePointsRes<Fp> & H2CHasher<Fp>;
  G2: CurvePointsRes<Fp2> & H2CHasher<Fp2>;
  /** @deprecated use `longSignatures.Signature` */
  Signature: SignatureCoder<Fp2>;
  /** @deprecated use `shortSignatures.Signature` */
  ShortSignature: ShortSignatureCoder<Fp>;
  params: {
    ateLoopSize: bigint;
    r: bigint;
    twistType: TwistType;
    /** @deprecated */
    G1b: bigint;
    /** @deprecated */
    G2b: Fp2;
  };
  curves: {
    G1: ProjConstructor<bigint>;
    G2: ProjConstructor<Fp2>;
  };
  fields: {
    Fp: IField<Fp>;
    Fp2: Fp2Bls;
    Fp6: Fp6Bls;
    Fp12: Fp12Bls;
    Fr: IField<bigint>;
  };
  utils: {
    randomPrivateKey: () => Uint8Array;
    calcPairingPrecomputes: (p: ProjPointType<Fp2>) => Precompute;
  };
};

type BLSInput = Hex | Uint8Array;
export interface BLSSigs<P, S> {
  getPublicKey(privateKey: PrivKey): ProjPointType<P>;
  sign(hashedMessage: ProjPointType<S>, privateKey: PrivKey): ProjPointType<S>;
  verify(
    signature: ProjPointType<S> | BLSInput,
    message: ProjPointType<S>,
    publicKey: ProjPointType<P> | BLSInput
  ): boolean;
  aggregatePublicKeys(publicKeys: (ProjPointType<P> | BLSInput)[]): ProjPointType<P>;
  aggregateSignatures(signatures: (ProjPointType<S> | BLSInput)[]): ProjPointType<S>;
  hash(message: Uint8Array, DST?: string | Uint8Array, hashOpts?: H2CHashOpts): ProjPointType<S>;
  Signature: SignatureCoder<S>;
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

// G1_Point: ProjConstructor<bigint>, G2_Point: ProjConstructor<Fp2>,
export function bls(CURVE: CurveType): CurveFn {
  // Fields are specific for curve, so for now we'll need to pass them with opts
  const { Fp, Fr, Fp2, Fp6, Fp12 } = CURVE.fields;
  const BLS_X_IS_NEGATIVE = CURVE.params.xNegative;
  const TWIST: TwistType = CURVE.params.twistType;
  // Point on G1 curve: (x, y)
  const G1_ = weierstrassPoints(CURVE.G1);
  const G1 = Object.assign(
    G1_,
    createHasher(G1_.Point, CURVE.G1.mapToCurve, {
      ...CURVE.htfDefaults,
      ...CURVE.G1.htfDefaults,
    })
  );
  // Point on G2 curve (complex numbers): (x₁, x₂+i), (y₁, y₂+i)
  const G2_ = weierstrassPoints(CURVE.G2);
  const G2 = Object.assign(
    G2_,
    createHasher(G2_.Point as H2CPointConstructor<Fp2>, CURVE.G2.mapToCurve, {
      ...CURVE.htfDefaults,
      ...CURVE.G2.htfDefaults,
    })
  );
  type G1 = typeof G1.Point.BASE;
  type G2 = typeof G2.Point.BASE;

  // Applies sparse multiplication as line function
  let lineFunction: (c0: Fp2, c1: Fp2, c2: Fp2, f: Fp12, Px: Fp, Py: Fp) => Fp12;
  if (TWIST === 'multiplicative') {
    lineFunction = (c0: Fp2, c1: Fp2, c2: Fp2, f: Fp12, Px: Fp, Py: Fp) =>
      Fp12.mul014(f, c0, Fp2.mul(c1, Px), Fp2.mul(c2, Py));
  } else if (TWIST === 'divisive') {
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
  const ATE_NAF = NAfDecomposition(CURVE.params.ateLoopSize);

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
    if (CURVE.postPrecompute) {
      const last = ell[ell.length - 1];
      CURVE.postPrecompute(Rx, Ry, Rz, Qx, Qy, pointAdd.bind(null, last));
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
    if (BLS_X_IS_NEGATIVE) f12 = Fp12.conjugate(f12);
    return withFinalExponent ? Fp12.finalExponentiate(f12) : f12;
  }
  type PairingInput = { g1: G1; g2: G2 };
  // Calculates product of multiple pairings
  // This up to x2 faster than just `map(({g1, g2})=>pairing({g1,g2}))`
  function pairingBatch(pairs: PairingInput[], withFinalExponent: boolean = true) {
    const res: MillerInput = [];
    // Cache precomputed toAffine for all points
    normalizeZ(
      G1.Point,
      'pz',
      pairs.map(({ g1 }) => g1)
    );
    normalizeZ(
      G2.Point,
      'pz',
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

  const rand = CURVE.randomBytes || randomBytes;

  const utils = {
    randomPrivateKey: (): Uint8Array => {
      const length = getMinHashLength(Fr.ORDER);
      return mapHashToField(rand(length), Fr.ORDER);
    },
    calcPairingPrecomputes,
  };

  function aNonEmpty(arr: any[]) {
    if (!Array.isArray(arr) || arr.length === 0) throw new Error('expected non-empty array');
  }

  type G1Hex = Hex | G1;
  type G2Hex = Hex | G2;
  function normP1(point: G1Hex): G1 {
    return point instanceof G1.Point ? (point as G1) : G1.Point.fromHex(point);
  }
  function normP2(point: G2Hex): G2 {
    return point instanceof G2.Point ? point : Signature.fromHex(point);
  }

  // TODO: add verifyBatch, fix types, Export Signature property,
  // actually expose the generated APIs
  function createBls<P, S>(PubCurve: any, SigCurve: any): BLSSigs<P, S> {
    type PubPoint = ProjPointType<P>;
    type SigPoint = ProjPointType<S>;
    function normPub(point: PubPoint | BLSInput): PubPoint {
      return point instanceof PubCurve.Point ? (point as PubPoint) : PubCurve.Point.fromHex(point);
    }
    function normSig(point: SigPoint | BLSInput): SigPoint {
      return point instanceof SigCurve.Point ? (point as SigPoint) : SigCurve.Point.fromHex(point);
    }
    function amsg(m: unknown): SigPoint {
      if (!(m instanceof SigCurve.Point))
        throw new Error(`expected valid message hashed to ${isLongSigs ? 'G2' : 'G1'} curve`);
      return m as any;
    }

    // TODO: is this always ok?
    const isLongSigs = SigCurve.Point.Fp.BYTES > PubCurve.Point.Fp.BYTES;
    return {
      // P = pk x G
      getPublicKey(privateKey: PrivKey): PubPoint {
        return PubCurve.Point.fromPrivateKey(privateKey);
      },
      // S = pk x H(m)
      sign(message: SigPoint, privateKey: PrivKey, unusedArg?: any): SigPoint {
        if (unusedArg != null) throw new Error('sign() expects 2 arguments');
        amsg(message).assertValidity();
        return message.multiply(PubCurve.normPrivateKeyToScalar(privateKey));
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
        const G = PubCurve.Point.BASE;
        const Hm = amsg(message);
        const S = signature;
        // This code was changed in 1.9.x:
        // Before it was G.negate() in G2, now it's always pubKey.negate
        // TODO: understand if this is OK?
        // prettier-ignore
        const exp_ = isLongSigs ? [
          { g1: P, g2: Hm },
          { g1: G, g2: S }
        ] : [
          { g1: Hm, g2: P },
          { g1: S, g2: G }
        ];
        // TODO
        // @ts-ignore
        const exp = pairingBatch(exp_);
        return Fp12.eql(exp, Fp12.ONE);
      },

      // Adds a bunch of public key points together.
      // pk1 + pk2 + pk3 = pkA
      aggregatePublicKeys(publicKeys: (PubPoint | BLSInput)[]): PubPoint {
        aNonEmpty(publicKeys);
        publicKeys = publicKeys.map((pub) => normPub(pub));
        const agg = publicKeys.reduce((sum, p) => sum.add(p), PubCurve.Point.ZERO);
        agg.assertValidity();
        return agg;
      },

      // Adds a bunch of signature points together.
      // pk1 + pk2 + pk3 = pkA
      aggregateSignatures(signatures: (SigPoint | BLSInput)[]): SigPoint {
        aNonEmpty(signatures);
        signatures = signatures.map((sig) => normSig(sig));
        const agg = signatures.reduce((sum, s) => sum.add(s), SigCurve.Point.ZERO);
        agg.assertValidity();
        return agg;
      },

      hash(messageBytes: Uint8Array, DST?: string | Uint8Array): SigPoint {
        abytes(messageBytes);
        const opts = DST ? { DST } : undefined;
        return SigCurve.hashToCurve(messageBytes, opts);
      },

      // @ts-ignore
      Signature: isLongSigs ? CURVE.G2.Signature : CURVE.G1.ShortSignature,
    };
  }

  const longSignatures = createBls<bigint, Fp2>(G1, G2);
  const shortSignatures = createBls<Fp2, bigint>(G2, G1);

  // LEGACY code
  const { ShortSignature } = CURVE.G1;
  const { Signature } = CURVE.G2;

  function normP1Hash(point: G1Hex, htfOpts?: htfBasicOpts): G1 {
    return point instanceof G1.Point
      ? point
      : shortSignatures.hash(ensureBytes('point', point), htfOpts?.DST);
  }
  function normP2Hash(point: G2Hex, htfOpts?: htfBasicOpts): G2 {
    return point instanceof G2.Point
      ? point
      : longSignatures.hash(ensureBytes('point', point), htfOpts?.DST);
  }

  function getPublicKey(privateKey: PrivKey): Uint8Array {
    return longSignatures.getPublicKey(privateKey).toBytes(true);
  }
  function getPublicKeyForShortSignatures(privateKey: PrivKey): Uint8Array {
    return shortSignatures.getPublicKey(privateKey).toBytes(true);
  }
  function sign(message: Hex, privateKey: PrivKey, htfOpts?: htfBasicOpts): Uint8Array;
  function sign(message: G2, privateKey: PrivKey, htfOpts?: htfBasicOpts): G2;
  function sign(message: G2Hex, privateKey: PrivKey, htfOpts?: htfBasicOpts): Uint8Array | G2 {
    const Hm = normP2Hash(message, htfOpts);
    const S = longSignatures.sign(Hm, privateKey);
    return message instanceof G2.Point ? S : Signature.toBytes(S);
  }
  function signShortSignature(
    message: Hex,
    privateKey: PrivKey,
    htfOpts?: htfBasicOpts
  ): Uint8Array;
  function signShortSignature(message: G1, privateKey: PrivKey, htfOpts?: htfBasicOpts): G1;
  function signShortSignature(
    message: G1Hex,
    privateKey: PrivKey,
    htfOpts?: htfBasicOpts
  ): Uint8Array | G1 {
    const Hm = normP1Hash(message, htfOpts);
    const S = shortSignatures.sign(Hm, privateKey);
    return message instanceof G1.Point ? S : ShortSignature.toBytes(S);
  }
  function verify(
    signature: G2Hex,
    message: G2Hex,
    publicKey: G1Hex,
    htfOpts?: htfBasicOpts
  ): boolean {
    const Hm = normP2Hash(message, htfOpts);
    return longSignatures.verify(signature, Hm, publicKey);
  }
  function verifyShortSignature(
    signature: G1Hex,
    message: G1Hex,
    publicKey: G2Hex,
    htfOpts?: htfBasicOpts
  ): boolean {
    const Hm = normP1Hash(message, htfOpts);
    return shortSignatures.verify(signature, Hm, publicKey);
  }
  function aggregatePublicKeys(publicKeys: Hex[]): Uint8Array;
  function aggregatePublicKeys(publicKeys: G1[]): G1;
  function aggregatePublicKeys(publicKeys: G1Hex[]): Uint8Array | G1 {
    const agg = longSignatures.aggregatePublicKeys(publicKeys);
    return publicKeys[0] instanceof G1.Point ? agg : agg.toBytes(true);
  }
  function aggregateSignatures(signatures: Hex[]): Uint8Array;
  function aggregateSignatures(signatures: G2[]): G2;
  function aggregateSignatures(signatures: G2Hex[]): Uint8Array | G2 {
    const agg = longSignatures.aggregateSignatures(signatures);
    return signatures[0] instanceof G2.Point ? agg : Signature.toBytes(agg);
  }
  function aggregateShortSignatures(signatures: Hex[]): Uint8Array;
  function aggregateShortSignatures(signatures: G1[]): G1;
  function aggregateShortSignatures(signatures: G1Hex[]): Uint8Array | G1 {
    const agg = shortSignatures.aggregateSignatures(signatures);
    return signatures[0] instanceof G1.Point ? agg : ShortSignature.toBytes(agg);
  }

  // https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
  // e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
  // TODO: maybe `{message: G2Hex, publicKey: G1Hex}[]` instead?
  function verifyBatch(
    signature: G2Hex,
    messages: G2Hex[],
    publicKeys: G1Hex[],
    htfOpts?: htfBasicOpts
  ): boolean {
    aNonEmpty(messages);
    if (publicKeys.length !== messages.length)
      throw new Error('amount of public keys and messages should be equal');
    const sig = normP2(signature);
    const nMessages = messages.map((i) => normP2Hash(i, htfOpts));
    const nPublicKeys = publicKeys.map(normP1);
    // NOTE: this works only for exact same object
    const messagePubKeyMap = new Map<G2, G1[]>();
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
    try {
      for (const [msg, keys] of messagePubKeyMap) {
        const groupPublicKey = keys.reduce((acc, msg) => acc.add(msg));
        paired.push({ g1: groupPublicKey, g2: msg });
      }
      paired.push({ g1: G1.Point.BASE.negate(), g2: sig });
      return Fp12.eql(pairingBatch(paired), Fp12.ONE);
    } catch {
      return false;
    }
  }

  G1.Point.BASE.precompute(4);

  return {
    longSignatures,
    shortSignatures,
    millerLoopBatch,
    pairing,
    pairingBatch,
    // TODO!!!
    verifyBatch,
    curves: {
      G1: G1_.Point,
      G2: G2_.Point,
    },
    fields: {
      Fr,
      Fp,
      Fp2,
      Fp6,
      Fp12,
    },
    params: {
      ateLoopSize: CURVE.params.ateLoopSize,
      twistType: CURVE.params.twistType,
      // deprecated
      r: CURVE.params.r,
      G1b: CURVE.G1.b,
      G2b: CURVE.G2.b,
    },
    utils,

    // deprecated
    getPublicKey,
    getPublicKeyForShortSignatures,
    sign,
    signShortSignature,
    verify,
    verifyShortSignature,
    aggregatePublicKeys,
    aggregateSignatures,
    aggregateShortSignatures,
    G1,
    G2,
    Signature,
    ShortSignature,
  };
}
