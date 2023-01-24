/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/**
 * BLS (Barreto-Lynn-Scott) family of pairing-friendly curves.
 * Implements BLS (Boneh-Lynn-Shacham) signatures.
 * Consists of two curves: G1 and G2:
 * - G1 is a subgroup of (x, y) E(Fq) over y² = x³ + 4.
 * - G2 is a subgroup of ((x₁, x₂+i), (y₁, y₂+i)) E(Fq²) over y² = x³ + 4(1 + i) where i is √-1
 * - Gt, created by bilinear (ate) pairing e(G1, G2), consists of p-th roots of unity in
 *   Fq^k where k is embedding degree. Only degree 12 is currently supported, 24 is not.
 * Pairing is used to aggregate and verify signatures.
 * We are using Fp for private keys (shorter) and Fp₂ for signatures (longer).
 * Some projects may prefer to swap this relation, it is not supported for now.
 */
import * as mod from './modular.js';
import * as ut from './utils.js';
// Types require separate import
import { Hex, PrivKey } from './utils.js';
import * as htf from './hash-to-curve.js';
import {
  CurvePointsType,
  ProjectivePointType as PPointType,
  CurvePointsRes,
  weierstrassPoints,
} from './weierstrass.js';

type Fp = bigint; // Can be different field?

export type SignatureCoder<Fp2> = {
  decode(hex: Hex): PPointType<Fp2>;
  encode(point: PPointType<Fp2>): Uint8Array;
};

export type CurveType<Fp, Fp2, Fp6, Fp12> = {
  r: bigint;
  G1: Omit<CurvePointsType<Fp>, 'n'> & {
    mapToCurve: htf.MapToCurve<Fp>;
    htfDefaults: htf.Opts;
  };
  G2: Omit<CurvePointsType<Fp2>, 'n'> & {
    Signature: SignatureCoder<Fp2>;
    mapToCurve: htf.MapToCurve<Fp2>;
    htfDefaults: htf.Opts;
  };
  x: bigint;
  Fp: mod.Field<Fp>;
  Fr: mod.Field<bigint>;
  Fp2: mod.Field<Fp2> & {
    reim: (num: Fp2) => { re: bigint; im: bigint };
    multiplyByB: (num: Fp2) => Fp2;
    frobeniusMap(num: Fp2, power: number): Fp2;
  };
  Fp6: mod.Field<Fp6>;
  Fp12: mod.Field<Fp12> & {
    frobeniusMap(num: Fp12, power: number): Fp12;
    multiplyBy014(num: Fp12, o0: Fp2, o1: Fp2, o4: Fp2): Fp12;
    conjugate(num: Fp12): Fp12;
    finalExponentiate(num: Fp12): Fp12;
  };
  htfDefaults: htf.Opts;
  hash: ut.CHash; // Because we need outputLen for DRBG
  randomBytes: (bytesLength?: number) => Uint8Array;
};

export type CurveFn<Fp, Fp2, Fp6, Fp12> = {
  CURVE: CurveType<Fp, Fp2, Fp6, Fp12>;
  Fr: mod.Field<bigint>;
  Fp: mod.Field<Fp>;
  Fp2: mod.Field<Fp2>;
  Fp6: mod.Field<Fp6>;
  Fp12: mod.Field<Fp12>;
  G1: CurvePointsRes<Fp>;
  G2: CurvePointsRes<Fp2>;
  Signature: SignatureCoder<Fp2>;
  millerLoop: (ell: [Fp2, Fp2, Fp2][], g1: [Fp, Fp]) => Fp12;
  calcPairingPrecomputes: (x: Fp2, y: Fp2) => [Fp2, Fp2, Fp2][];
  // prettier-ignore
  hashToCurve: {
    G1: ReturnType<(typeof htf.hashToCurve<Fp>)>,
    G2: ReturnType<(typeof htf.hashToCurve<Fp2>)>,
  },
  pairing: (P: PPointType<Fp>, Q: PPointType<Fp2>, withFinalExponent?: boolean) => Fp12;
  getPublicKey: (privateKey: PrivKey) => Uint8Array;
  sign: {
    (message: Hex, privateKey: PrivKey): Uint8Array;
    (message: PPointType<Fp2>, privateKey: PrivKey): PPointType<Fp2>;
  };
  verify: (
    signature: Hex | PPointType<Fp2>,
    message: Hex | PPointType<Fp2>,
    publicKey: Hex | PPointType<Fp>
  ) => boolean;
  aggregatePublicKeys: {
    (publicKeys: Hex[]): Uint8Array;
    (publicKeys: PPointType<Fp>[]): PPointType<Fp>;
  };
  aggregateSignatures: {
    (signatures: Hex[]): Uint8Array;
    (signatures: PPointType<Fp2>[]): PPointType<Fp2>;
  };
  verifyBatch: (
    signature: Hex | PPointType<Fp2>,
    messages: (Hex | PPointType<Fp2>)[],
    publicKeys: (Hex | PPointType<Fp>)[]
  ) => boolean;
  utils: {
    stringToBytes: typeof htf.stringToBytes;
    hashToField: typeof htf.hash_to_field;
    expandMessageXMD: typeof htf.expand_message_xmd;
  };
};

export function bls<Fp2, Fp6, Fp12>(
  CURVE: CurveType<Fp, Fp2, Fp6, Fp12>
): CurveFn<Fp, Fp2, Fp6, Fp12> {
  // Fields looks pretty specific for curve, so for now we need to pass them with options
  const { Fp, Fr, Fp2, Fp6, Fp12 } = CURVE;
  const BLS_X_LEN = ut.bitLen(CURVE.x);
  const groupLen = 32; // TODO: calculate; hardcoded for now

  // Pre-compute coefficients for sparse multiplication
  // Point addition and point double calculations is reused for coefficients
  function calcPairingPrecomputes(x: Fp2, y: Fp2) {
    // prettier-ignore
    const Qx = x, Qy = y, Qz = Fp2.ONE;
    // prettier-ignore
    let Rx = Qx, Ry = Qy, Rz = Qz;
    let ell_coeff: [Fp2, Fp2, Fp2][] = [];
    for (let i = BLS_X_LEN - 2; i >= 0; i--) {
      // Double
      let t0 = Fp2.square(Ry); // Ry²
      let t1 = Fp2.square(Rz); // Rz²
      let t2 = Fp2.multiplyByB(Fp2.mul(t1, 3n)); // 3 * T1 * B
      let t3 = Fp2.mul(t2, 3n); // 3 * T2
      let t4 = Fp2.sub(Fp2.sub(Fp2.square(Fp2.add(Ry, Rz)), t1), t0); // (Ry + Rz)² - T1 - T0
      ell_coeff.push([
        Fp2.sub(t2, t0), // T2 - T0
        Fp2.mul(Fp2.square(Rx), 3n), // 3 * Rx²
        Fp2.negate(t4), // -T4
      ]);
      Rx = Fp2.div(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), 2n); // ((T0 - T3) * Rx * Ry) / 2
      Ry = Fp2.sub(Fp2.square(Fp2.div(Fp2.add(t0, t3), 2n)), Fp2.mul(Fp2.square(t2), 3n)); // ((T0 + T3) / 2)² - 3 * T2²
      Rz = Fp2.mul(t0, t4); // T0 * T4
      if (ut.bitGet(CURVE.x, i)) {
        // Addition
        let t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz)); // Ry - Qy * Rz
        let t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz)); // Rx - Qx * Rz
        ell_coeff.push([
          Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)), // T0 * Qx - T1 * Qy
          Fp2.negate(t0), // -T0
          t1, // T1
        ]);
        let t2 = Fp2.square(t1); // T1²
        let t3 = Fp2.mul(t2, t1); // T2 * T1
        let t4 = Fp2.mul(t2, Rx); // T2 * Rx
        let t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, 2n)), Fp2.mul(Fp2.square(t0), Rz)); // T3 - 2 * T4 + T0² * Rz
        Rx = Fp2.mul(t1, t5); // T1 * T5
        Ry = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry)); // (T4 - T5) * T0 - T3 * Ry
        Rz = Fp2.mul(Rz, t3); // Rz * T3
      }
    }
    return ell_coeff;
  }

  function millerLoop(ell: [Fp2, Fp2, Fp2][], g1: [Fp, Fp]): Fp12 {
    const { x } = CURVE;
    const Px = g1[0];
    const Py = g1[1];
    let f12 = Fp12.ONE;
    for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
      const E = ell[j];
      f12 = Fp12.multiplyBy014(f12, E[0], Fp2.mul(E[1], Px), Fp2.mul(E[2], Py));
      if (ut.bitGet(x, i)) {
        j += 1;
        const F = ell[j];
        f12 = Fp12.multiplyBy014(f12, F[0], Fp2.mul(F[1], Px), Fp2.mul(F[2], Py));
      }
      if (i !== 0) f12 = Fp12.square(f12);
    }
    return Fp12.conjugate(f12);
  }

  const utils = {
    hexToBytes: ut.hexToBytes,
    bytesToHex: ut.bytesToHex,
    stringToBytes: htf.stringToBytes,
    // TODO: do we need to export it here?
    hashToField: (
      msg: Uint8Array,
      count: number,
      options: Partial<typeof CURVE.htfDefaults> = {}
    ) => htf.hash_to_field(msg, count, { ...CURVE.htfDefaults, ...options }),
    expandMessageXMD: (msg: Uint8Array, DST: Uint8Array, lenInBytes: number, H = CURVE.hash) =>
      htf.expand_message_xmd(msg, DST, lenInBytes, H),
    hashToPrivateKey: (hash: Hex): Uint8Array => Fr.toBytes(ut.hashToPrivateScalar(hash, CURVE.r)),
    randomBytes: (bytesLength: number = groupLen): Uint8Array => CURVE.randomBytes(bytesLength),
    randomPrivateKey: (): Uint8Array => utils.hashToPrivateKey(utils.randomBytes(groupLen + 8)),
  };

  // Point on G1 curve: (x, y)
  const G1 = weierstrassPoints({
    n: Fr.ORDER,
    ...CURVE.G1,
  });
  const G1HashToCurve = htf.hashToCurve(G1.ProjectivePoint, CURVE.G1.mapToCurve, {
    ...CURVE.htfDefaults,
    ...CURVE.G1.htfDefaults,
  });

  // Sparse multiplication against precomputed coefficients
  // TODO: replace with weakmap?
  type withPairingPrecomputes = { _PPRECOMPUTES: [Fp2, Fp2, Fp2][] | undefined };
  function pairingPrecomputes(point: G2): [Fp2, Fp2, Fp2][] {
    const p = point as G2 & withPairingPrecomputes;
    if (p._PPRECOMPUTES) return p._PPRECOMPUTES;
    p._PPRECOMPUTES = calcPairingPrecomputes(p.x, p.y);
    return p._PPRECOMPUTES;
  }

  function clearPairingPrecomputes(point: G2) {
    const p = point as G2 & withPairingPrecomputes;
    p._PPRECOMPUTES = undefined;
  }
  clearPairingPrecomputes;

  function millerLoopG1(Q: G1, P: G2): Fp12 {
    return millerLoop(pairingPrecomputes(P), [Q.x, Q.y]);
  }

  // Point on G2 curve (complex numbers): (x₁, x₂+i), (y₁, y₂+i)
  const G2 = weierstrassPoints({
    n: Fr.ORDER,
    ...CURVE.G2,
  });
  const C = G2.ProjectivePoint as htf.H2CPointConstructor<Fp2>; // TODO: fix
  const G2HashToCurve = htf.hashToCurve(C, CURVE.G2.mapToCurve, {
    ...CURVE.htfDefaults,
    ...CURVE.G2.htfDefaults,
  });

  const { Signature } = CURVE.G2;

  // Calculates bilinear pairing
  function pairing(P: G1, Q: G2, withFinalExponent: boolean = true): Fp12 {
    if (P.equals(G1.ProjectivePoint.ZERO) || Q.equals(G2.ProjectivePoint.ZERO))
      throw new Error('No pairings at point of Infinity');
    P.assertValidity();
    Q.assertValidity();
    // Performance: 9ms for millerLoop and ~14ms for exp.
    const looped = millerLoopG1(P, Q);
    return withFinalExponent ? Fp12.finalExponentiate(looped) : looped;
  }
  type G1 = typeof G1.ProjectivePoint.BASE;
  type G2 = typeof G2.ProjectivePoint.BASE;

  type G1Hex = Hex | G1;
  type G2Hex = Hex | G2;
  function normP1(point: G1Hex): G1 {
    return point instanceof G1.ProjectivePoint ? (point as G1) : G1.ProjectivePoint.fromHex(point);
  }
  function normP2(point: G2Hex): G2 {
    return point instanceof G2.ProjectivePoint ? point : Signature.decode(point);
  }
  function normP2Hash(point: G2Hex, htfOpts?: htf.htfBasicOpts): G2 {
    return point instanceof G2.ProjectivePoint
      ? point
      : (G2HashToCurve.hashToCurve(point, htfOpts) as G2);
  }

  // Multiplies generator by private key.
  // P = pk x G
  function getPublicKey(privateKey: PrivKey): Uint8Array {
    return G1.ProjectivePoint.fromPrivateKey(privateKey).toRawBytes(true);
  }

  // Executes `hashToCurve` on the message and then multiplies the result by private key.
  // S = pk x H(m)
  function sign(message: Hex, privateKey: PrivKey, htfOpts?: htf.htfBasicOpts): Uint8Array;
  function sign(message: G2, privateKey: PrivKey, htfOpts?: htf.htfBasicOpts): G2;
  function sign(message: G2Hex, privateKey: PrivKey, htfOpts?: htf.htfBasicOpts): Uint8Array | G2 {
    const msgPoint = normP2Hash(message, htfOpts);
    msgPoint.assertValidity();
    const sigPoint = msgPoint.multiply(G1.normalizePrivateKey(privateKey));
    if (message instanceof G2.ProjectivePoint) return sigPoint;
    return Signature.encode(sigPoint);
  }

  // Checks if pairing of public key & hash is equal to pairing of generator & signature.
  // e(P, H(m)) == e(G, S)
  function verify(
    signature: G2Hex,
    message: G2Hex,
    publicKey: G1Hex,
    htfOpts?: htf.htfBasicOpts
  ): boolean {
    const P = normP1(publicKey);
    const Hm = normP2Hash(message, htfOpts);
    const G = G1.ProjectivePoint.BASE;
    const S = normP2(signature);
    // Instead of doing 2 exponentiations, we use property of billinear maps
    // and do one exp after multiplying 2 points.
    const ePHm = pairing(P.negate(), Hm, false);
    const eGS = pairing(G, S, false);
    const exp = Fp12.finalExponentiate(Fp12.mul(eGS, ePHm));
    return Fp12.equals(exp, Fp12.ONE);
  }

  // Adds a bunch of public key points together.
  // pk1 + pk2 + pk3 = pkA
  function aggregatePublicKeys(publicKeys: Hex[]): Uint8Array;
  function aggregatePublicKeys(publicKeys: G1[]): G1;
  function aggregatePublicKeys(publicKeys: G1Hex[]): Uint8Array | G1 {
    if (!publicKeys.length) throw new Error('Expected non-empty array');
    const agg = publicKeys
      .map(normP1)
      .reduce((sum, p) => sum.add(G1.ProjectivePoint.fromAffine(p)), G1.ProjectivePoint.ZERO);
    const aggAffine = agg; //.toAffine();
    if (publicKeys[0] instanceof G1.ProjectivePoint) {
      aggAffine.assertValidity();
      return aggAffine;
    }
    // toRawBytes ensures point validity
    return aggAffine.toRawBytes(true);
  }

  // Adds a bunch of signature points together.
  function aggregateSignatures(signatures: Hex[]): Uint8Array;
  function aggregateSignatures(signatures: G2[]): G2;
  function aggregateSignatures(signatures: G2Hex[]): Uint8Array | G2 {
    if (!signatures.length) throw new Error('Expected non-empty array');
    const agg = signatures
      .map(normP2)
      .reduce((sum, s) => sum.add(G2.ProjectivePoint.fromAffine(s)), G2.ProjectivePoint.ZERO);
    const aggAffine = agg; //.toAffine();
    if (signatures[0] instanceof G2.ProjectivePoint) {
      aggAffine.assertValidity();
      return aggAffine;
    }
    return Signature.encode(aggAffine);
  }

  // https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
  // e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
  function verifyBatch(
    signature: G2Hex,
    messages: G2Hex[],
    publicKeys: G1Hex[],
    htfOpts?: htf.htfBasicOpts
  ): boolean {
    if (!messages.length) throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
      throw new Error('Pubkey count should equal msg count');
    const sig = normP2(signature);
    const nMessages = messages.map((i) => normP2Hash(i, htfOpts));
    const nPublicKeys = publicKeys.map(normP1);
    try {
      const paired = [];
      for (const message of new Set(nMessages)) {
        const groupPublicKey = nMessages.reduce(
          (groupPublicKey, subMessage, i) =>
            subMessage === message ? groupPublicKey.add(nPublicKeys[i]) : groupPublicKey,
          G1.ProjectivePoint.ZERO
        );
        // const msg = message instanceof PointG2 ? message : await PointG2.hashToCurve(message);
        // Possible to batch pairing for same msg with different groupPublicKey here
        paired.push(pairing(groupPublicKey, message, false));
      }
      paired.push(pairing(G1.ProjectivePoint.BASE.negate(), sig, false));
      const product = paired.reduce((a, b) => Fp12.mul(a, b), Fp12.ONE);
      const exp = Fp12.finalExponentiate(product);
      return Fp12.equals(exp, Fp12.ONE);
    } catch {
      return false;
    }
  }

  // Pre-compute points. Refer to README.
  // TODO
  // G1.ProjectivePoint.BASE._setWindowSize(4);
  return {
    CURVE,
    Fr,
    Fp,
    Fp2,
    Fp6,
    Fp12,
    G1,
    G2,
    Signature,
    millerLoop,
    calcPairingPrecomputes,
    hashToCurve: { G1: G1HashToCurve, G2: G2HashToCurve },
    pairing,
    getPublicKey,
    sign,
    verify,
    aggregatePublicKeys,
    aggregateSignatures,
    verifyBatch,
    utils,
  };
}
