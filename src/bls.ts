/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Barreto-Lynn-Scott Curves. A family of pairing friendly curves, with embedding degree = 12 or 24
// NOTE: only 12 supported for now
// Constructed from pair of weierstrass curves, based pairing logic
import * as mod from './modular.js';
import { ensureBytes, numberToBytesBE, bytesToNumberBE, bitLen, bitGet } from './utils.js';
import * as utils from './utils.js';
// Types
import { hexToBytes, bytesToHex, Hex, PrivKey } from './utils.js';
import { htfOpts, stringToBytes, hash_to_field, expand_message_xmd } from './hashToCurve.js';
import { CurvePointsType, PointType, CurvePointsRes, weierstrassPoints } from './weierstrass.js';

type Fp = bigint; // Can be different field?

export type SignatureCoder<Fp2> = {
  decode(hex: Hex): PointType<Fp2>;
  encode(point: PointType<Fp2>): Uint8Array;
};

export type CurveType<Fp, Fp2, Fp6, Fp12> = {
  r: bigint;
  G1: Omit<CurvePointsType<Fp>, 'n'>;
  G2: Omit<CurvePointsType<Fp2>, 'n'> & {
    Signature: SignatureCoder<Fp2>;
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
  htfDefaults: htfOpts;
  hash: utils.CHash; // Because we need outputLen for DRBG
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
  pairing: (P: PointType<Fp>, Q: PointType<Fp2>, withFinalExponent?: boolean) => Fp12;
  getPublicKey: (privateKey: PrivKey) => Uint8Array;
  sign: {
    (message: Hex, privateKey: PrivKey): Uint8Array;
    (message: PointType<Fp2>, privateKey: PrivKey): PointType<Fp2>;
  };
  verify: (
    signature: Hex | PointType<Fp2>,
    message: Hex | PointType<Fp2>,
    publicKey: Hex | PointType<Fp>
  ) => boolean;
  aggregatePublicKeys: {
    (publicKeys: Hex[]): Uint8Array;
    (publicKeys: PointType<Fp>[]): PointType<Fp>;
  };
  aggregateSignatures: {
    (signatures: Hex[]): Uint8Array;
    (signatures: PointType<Fp2>[]): PointType<Fp2>;
  };
  verifyBatch: (
    signature: Hex | PointType<Fp2>,
    messages: (Hex | PointType<Fp2>)[],
    publicKeys: (Hex | PointType<Fp>)[]
  ) => boolean;
  utils: {
    bytesToHex: typeof utils.bytesToHex;
    hexToBytes: typeof utils.hexToBytes;
    stringToBytes: typeof stringToBytes;
    hashToField: typeof hash_to_field;
    expandMessageXMD: typeof expand_message_xmd;
    mod: typeof mod.mod;
    getDSTLabel: () => string;
    setDSTLabel(newLabel: string): void;
  };
};

export function bls<Fp2, Fp6, Fp12>(
  CURVE: CurveType<Fp, Fp2, Fp6, Fp12>
): CurveFn<Fp, Fp2, Fp6, Fp12> {
  // Fields looks pretty specific for curve, so for now we need to pass them with options
  const Fp = CURVE.Fp;
  const Fr = CURVE.Fr;
  const Fp2 = CURVE.Fp2;
  const Fp6 = CURVE.Fp6;
  const Fp12 = CURVE.Fp12;
  const BLS_X_LEN = bitLen(CURVE.x);

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
      let t2 = Fp2.multiplyByB(Fp2.multiply(t1, 3n)); // 3 * T1 * B
      let t3 = Fp2.multiply(t2, 3n); // 3 * T2
      let t4 = Fp2.subtract(Fp2.subtract(Fp2.square(Fp2.add(Ry, Rz)), t1), t0); // (Ry + Rz)² - T1 - T0
      ell_coeff.push([
        Fp2.subtract(t2, t0), // T2 - T0
        Fp2.multiply(Fp2.square(Rx), 3n), // 3 * Rx²
        Fp2.negate(t4), // -T4
      ]);
      Rx = Fp2.div(Fp2.multiply(Fp2.multiply(Fp2.subtract(t0, t3), Rx), Ry), 2n); // ((T0 - T3) * Rx * Ry) / 2
      Ry = Fp2.subtract(Fp2.square(Fp2.div(Fp2.add(t0, t3), 2n)), Fp2.multiply(Fp2.square(t2), 3n)); // ((T0 + T3) / 2)² - 3 * T2²
      Rz = Fp2.multiply(t0, t4); // T0 * T4
      if (bitGet(CURVE.x, i)) {
        // Addition
        let t0 = Fp2.subtract(Ry, Fp2.multiply(Qy, Rz)); // Ry - Qy * Rz
        let t1 = Fp2.subtract(Rx, Fp2.multiply(Qx, Rz)); // Rx - Qx * Rz
        ell_coeff.push([
          Fp2.subtract(Fp2.multiply(t0, Qx), Fp2.multiply(t1, Qy)), // T0 * Qx - T1 * Qy
          Fp2.negate(t0), // -T0
          t1, // T1
        ]);
        let t2 = Fp2.square(t1); // T1²
        let t3 = Fp2.multiply(t2, t1); // T2 * T1
        let t4 = Fp2.multiply(t2, Rx); // T2 * Rx
        let t5 = Fp2.add(Fp2.subtract(t3, Fp2.multiply(t4, 2n)), Fp2.multiply(Fp2.square(t0), Rz)); // T3 - 2 * T4 + T0² * Rz
        Rx = Fp2.multiply(t1, t5); // T1 * T5
        Ry = Fp2.subtract(Fp2.multiply(Fp2.subtract(t4, t5), t0), Fp2.multiply(t3, Ry)); // (T4 - T5) * T0 - T3 * Ry
        Rz = Fp2.multiply(Rz, t3); // Rz * T3
      }
    }
    return ell_coeff;
  }

  function millerLoop(ell: [Fp2, Fp2, Fp2][], g1: [Fp, Fp]): Fp12 {
    const Px = g1[0];
    const Py = g1[1];
    let f12 = Fp12.ONE;
    for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
      const E = ell[j];
      f12 = Fp12.multiplyBy014(f12, E[0], Fp2.multiply(E[1], Px), Fp2.multiply(E[2], Py));
      if (bitGet(CURVE.x, i)) {
        j += 1;
        const F = ell[j];
        f12 = Fp12.multiplyBy014(f12, F[0], Fp2.multiply(F[1], Px), Fp2.multiply(F[2], Py));
      }
      if (i !== 0) f12 = Fp12.square(f12);
    }
    return Fp12.conjugate(f12);
  }

  // bls12-381 is a construction of two curves:
  // 1. Fp: (x, y)
  // 2. Fp₂: ((x₁, x₂+i), (y₁, y₂+i)) - (complex numbers)
  //
  // Bilinear Pairing (ate pairing) is used to combine both elements into a paired one:
  //   Fp₁₂ = e(Fp, Fp2)
  //   where Fp₁₂ = 12-degree polynomial
  // Pairing is used to verify signatures.
  //
  // We are using Fp for private keys (shorter) and Fp2 for signatures (longer).
  // Some projects may prefer to swap this relation, it is not supported for now.

  const htfDefaults = { ...CURVE.htfDefaults };

  function isWithinCurveOrder(num: bigint): boolean {
    return 0 < num && num < CURVE.r;
  }

  const utils = {
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    mod: mod.mod,
    stringToBytes,
    // TODO: do we need to export it here?
    hashToField: (msg: Uint8Array, count: number, options: Partial<typeof htfDefaults> = {}) =>
      hash_to_field(msg, count, { ...CURVE.htfDefaults, ...options }),
    expandMessageXMD: (msg: Uint8Array, DST: Uint8Array, lenInBytes: number, H = CURVE.hash) =>
      expand_message_xmd(msg, DST, lenInBytes, H),

    /**
     * Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
     * and convert them into private key, with the modulo bias being negligible.
     * As per FIPS 186 B.1.1.
     * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
     * @param hash hash output from sha512, or a similar function
     * @returns valid private key
     */
    hashToPrivateKey: (hash: Hex): Uint8Array => {
      hash = ensureBytes(hash);
      if (hash.length < 40 || hash.length > 1024)
        throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
      //     hashToPrivateScalar(hash, CURVE.r)
      // NOTE: doesn't add +/-1
      const num = mod.mod(bytesToNumberBE(hash), CURVE.r);
      // This should never happen
      if (num === 0n || num === 1n) throw new Error('Invalid private key');
      return numberToBytesBE(num, 32);
    },

    randomBytes: (bytesLength: number = 32): Uint8Array => CURVE.randomBytes(bytesLength),
    // NIST SP 800-56A rev 3, section 5.6.1.2.2
    // https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
    randomPrivateKey: (): Uint8Array => utils.hashToPrivateKey(utils.randomBytes(40)),
    getDSTLabel: () => htfDefaults.DST,
    setDSTLabel(newLabel: string) {
      // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-3.1
      if (typeof newLabel !== 'string' || newLabel.length > 2048 || newLabel.length === 0) {
        throw new TypeError('Invalid DST');
      }
      htfDefaults.DST = newLabel;
    },
  };

  function normalizePrivKey(key: PrivKey): bigint {
    let int: bigint;
    if (key instanceof Uint8Array && key.length === 32) int = bytesToNumberBE(key);
    else if (typeof key === 'string' && key.length === 64) int = BigInt(`0x${key}`);
    else if (typeof key === 'number' && key > 0 && Number.isSafeInteger(key)) int = BigInt(key);
    else if (typeof key === 'bigint' && key > 0n) int = key;
    else throw new TypeError('Expected valid private key');
    int = mod.mod(int, CURVE.r);
    if (!isWithinCurveOrder(int)) throw new Error('Private key must be 0 < key < CURVE.r');
    return int;
  }

  // Point on G1 curve: (x, y)
  const G1 = weierstrassPoints({
    n: Fr.ORDER,
    ...CURVE.G1,
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
  const { Signature } = CURVE.G2;

  // Calculates bilinear pairing
  function pairing(P: G1, Q: G2, withFinalExponent: boolean = true): Fp12 {
    if (P.equals(G1.Point.ZERO) || Q.equals(G2.Point.ZERO))
      throw new Error('No pairings at point of Infinity');
    P.assertValidity();
    Q.assertValidity();
    // Performance: 9ms for millerLoop and ~14ms for exp.
    const looped = millerLoopG1(P, Q);
    return withFinalExponent ? Fp12.finalExponentiate(looped) : looped;
  }
  type G1 = typeof G1.Point.BASE;
  type G2 = typeof G2.Point.BASE;

  type G1Hex = Hex | G1;
  type G2Hex = Hex | G2;
  function normP1(point: G1Hex): G1 {
    return point instanceof G1.Point ? (point as G1) : G1.Point.fromHex(point);
  }
  function normP2(point: G2Hex): G2 {
    return point instanceof G2.Point ? point : Signature.decode(point);
  }
  function normP2Hash(point: G2Hex): G2 {
    return point instanceof G2.Point ? point : G2.Point.hashToCurve(point);
  }

  // Multiplies generator by private key.
  // P = pk x G
  function getPublicKey(privateKey: PrivKey): Uint8Array {
    return G1.Point.fromPrivateKey(privateKey).toRawBytes(true);
  }

  // Executes `hashToCurve` on the message and then multiplies the result by private key.
  // S = pk x H(m)
  function sign(message: Hex, privateKey: PrivKey): Uint8Array;
  function sign(message: G2, privateKey: PrivKey): G2;
  function sign(message: G2Hex, privateKey: PrivKey): Uint8Array | G2 {
    const msgPoint = normP2Hash(message);
    msgPoint.assertValidity();
    const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
    if (message instanceof G2.Point) return sigPoint;
    return Signature.encode(sigPoint);
  }

  // Checks if pairing of public key & hash is equal to pairing of generator & signature.
  // e(P, H(m)) == e(G, S)
  function verify(signature: G2Hex, message: G2Hex, publicKey: G1Hex): boolean {
    const P = normP1(publicKey);
    const Hm = normP2Hash(message);
    const G = G1.Point.BASE;
    const S = normP2(signature);
    // Instead of doing 2 exponentiations, we use property of billinear maps
    // and do one exp after multiplying 2 points.
    const ePHm = pairing(P.negate(), Hm, false);
    const eGS = pairing(G, S, false);
    const exp = Fp12.finalExponentiate(Fp12.multiply(eGS, ePHm));
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
      .reduce((sum, p) => sum.add(G1.JacobianPoint.fromAffine(p)), G1.JacobianPoint.ZERO);
    const aggAffine = agg.toAffine();
    if (publicKeys[0] instanceof G1.Point) {
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
      .reduce((sum, s) => sum.add(G2.JacobianPoint.fromAffine(s)), G2.JacobianPoint.ZERO);
    const aggAffine = agg.toAffine();
    if (signatures[0] instanceof G2.Point) {
      aggAffine.assertValidity();
      return aggAffine;
    }
    return Signature.encode(aggAffine);
  }

  // https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
  // e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))
  function verifyBatch(signature: G2Hex, messages: G2Hex[], publicKeys: G1Hex[]): boolean {
    if (!messages.length) throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
      throw new Error('Pubkey count should equal msg count');
    const sig = normP2(signature);
    const nMessages = messages.map(normP2Hash);
    const nPublicKeys = publicKeys.map(normP1);
    try {
      const paired = [];
      for (const message of new Set(nMessages)) {
        const groupPublicKey = nMessages.reduce(
          (groupPublicKey, subMessage, i) =>
            subMessage === message ? groupPublicKey.add(nPublicKeys[i]) : groupPublicKey,
          G1.Point.ZERO
        );
        // const msg = message instanceof PointG2 ? message : await PointG2.hashToCurve(message);
        // Possible to batch pairing for same msg with different groupPublicKey here
        paired.push(pairing(groupPublicKey, message, false));
      }
      paired.push(pairing(G1.Point.BASE.negate(), sig, false));
      const product = paired.reduce((a, b) => Fp12.multiply(a, b), Fp12.ONE);
      const exp = Fp12.finalExponentiate(product);
      return Fp12.equals(exp, Fp12.ONE);
    } catch {
      return false;
    }
  }

  // Pre-compute points. Refer to README.
  G1.Point.BASE._setWindowSize(4);
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
