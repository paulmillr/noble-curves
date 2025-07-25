/**
 * RFC 9497: Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups.
 * https://www.rfc-editor.org/rfc/rfc9497
 *

OPRF allows to interactively create an `Output = PRF(Input, serverSecretKey)`:

- Server cannot calculate Output by itself: it doesn't know Input
- Client cannot calculate Output by itself: it doesn't know server secretKey
- An attacker interception the communication can't restore Input/Output/serverSecretKey and can't
  link Input to some value.

## Issues

- Low-entropy inputs (e.g. password '123') enable brute-forced dictionary attacks by the server
  (solveable by domain separation in POPRF)
- High-level protocol needs to be constructed on top, because OPRF is low-level

## Use cases

1. **Password-Authenticated Key Exchange (PAKE):** Enables secure password login (e.g., OPAQUE)
   without revealing the password to the server.
2. **Private Set Intersection (PSI):** Allows two parties to compute the intersection of their
   private sets without revealing non-intersecting elements.
3. **Anonymous Credential Systems:** Supports issuance of anonymous, unlinkable credentials
   (e.g., Privacy Pass) using blind OPRF evaluation.
4. **Private Information Retrieval (PIR):** Helps users query databases without revealing which
   item they accessed.
5. **Encrypted Search / Secure Indexing:** Enables keyword search over encrypted data while keeping
   queries private.
6. **Spam Prevention and Rate-Limiting:** Issues anonymous tokens to prevent abuse
   (e.g., CAPTCHA bypass) without compromising user privacy.

## Modes

- OPRF: simple mode, client doesn't need to know server public key
- VOPRF: verifable mode, allows client to verify that server used secret key corresponding to known public key
- POPRF: partially oblivious mode, VOPRF + domain separation

There is also non-interactive mode (Evaluate) that supports creating Output in non-interactive mode with knowledge of secret key.

Flow:
- (once) Server generates secret and public keys, distributes public keys to clients
  - deterministically: `deriveKeyPair` or just random: `generateKeyPair`
- Client blinds input: `blind(secretInput)`
- Server evaluates blinded input: `blindEvaluate` generated by client, sends result to client
- Client creates output using result of evaluation via 'finalize'

 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abytes,
  bytesToNumberBE,
  bytesToNumberLE,
  concatBytes,
  numberToBytesBE,
  randomBytes,
  utf8ToBytes,
  validateObject,
} from '../utils.ts';
import {
  pippenger,
  type CurvePoint,
  type CurvePointCons,
  type GetPointConsF,
  type GetPointConsPoint,
} from './curve.ts';
import { _DST_scalar, type H2CMethod, type htfBasicOpts } from './hash-to-curve.js';
import { getMinHashLength, mapHashToField } from './modular.js';

// OPRF is designed to be used across network, so we default to serialized values.
export type PointBytes = Uint8Array;
export type ScalarBytes = Uint8Array;
export type Bytes = Uint8Array;
export type RNG = typeof randomBytes;

export type OPRFOpts<F, P extends CurvePoint<F, P>, PC extends CurvePointCons<F, P>> = {
  name: string;
  Point: PC;
  // Fn: IField<bigint>;
  hash: (msg: Bytes) => Bytes;
  hashToScalar: (msg: Uint8Array, options: htfBasicOpts) => bigint;
  hashToGroup: ((msg: Uint8Array, options: htfBasicOpts) => P) | H2CMethod<P>;
};

export type Keys = { secretKey: ScalarBytes; publicKey: PointBytes };
export type Blind = { blind: Uint8Array; blinded: Uint8Array };
export type BlindEval = { evaluated: PointBytes; proof: Bytes };
export type BlindEvalBatch = { evaluated: PointBytes[]; proof: Bytes };
export type FinalizeItem = {
  input: Bytes;
  blind: ScalarBytes;
  evaluated: PointBytes;
  blinded: PointBytes;
};

/**
 * Represents a full OPRF ciphersuite implementation according to RFC 9497.
 * This object bundles the three protocol variants (OPRF, VOPRF, POPRF) for a specific
 * prime-order group and hash function combination.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9497.html
 */
export type OPRF = {
  /**
   * The unique identifier for the ciphersuite, e.g., "ristretto255-SHA512".
   * This name is used for domain separation to prevent cross-protocol attacks.
   */
  readonly name: string;

  /**
   * The base Oblivious Pseudorandom Function (OPRF) mode (mode 0x00).
   * This is a two-party protocol between a client and a server to compute F(k, x)
   * where 'k' is the server's key and 'x' is the client's input.
   *
   * The client learns the output F(k, x) but nothing about 'k'.
   * The server learns nothing about 'x' or F(k, x).
   * This mode is NOT verifiable; the client cannot prove the server used a specific key.
   */
  readonly oprf: {
    /**
     * (Server-side) Generates a new random private/public key pair for the server.
     * @returns A new key pair.
     */
    generateKeyPair(): Keys;

    /**
     * (Server-side) Deterministically derives a private/public key pair from a seed.
     * @param seed A 32-byte cryptographically secure random seed.
     * @param keyInfo An optional byte string for domain separation.
     * @returns The derived key pair.
     */
    deriveKeyPair(seed: Bytes, keyInfo: Bytes): Keys;

    /**
     * (Client-side) The first step of the protocol. The client blinds its private input.
     * @param input The client's private input bytes.
     * @param rng An optional cryptographically secure random number generator.
     * @returns An object containing the `blind` scalar (which the client MUST keep secret)
     * and the `blinded` element (which the client sends to the server).
     */
    blind(input: Bytes, rng?: RNG): Blind;

    /**
     * (Server-side) The second step. The server evaluates the client's blinded element
     * using its secret key.
     * @param secretKey The server's private key.
     * @param blinded The blinded group element received from the client.
     * @returns The evaluated group element, to be sent back to the client.
     */
    blindEvaluate(secretKey: ScalarBytes, blinded: PointBytes): PointBytes;

    /**
     * (Client-side) The final step. The client unblinds the server's response to
     * compute the final OPRF output.
     * @param input The original private input from the `blind` step.
     * @param blind The secret scalar from the `blind` step.
     * @param evaluated The evaluated group element received from the server.
     * @returns The final OPRF output, `Hash(len(input)||input||len(unblinded)||unblinded||"Finalize")`.
     */
    finalize(input: Bytes, blind: ScalarBytes, evaluated: PointBytes): Bytes;
  };

  /**
   * The Verifiable Oblivious Pseudorandom Function (VOPRF) mode (mode 0x01).
   * This mode extends the base OPRF by providing a proof that the server used the
   * secret key corresponding to its known public key.
   */
  readonly voprf: {
    /** (Server-side) Generates a key pair for the VOPRF mode. */
    generateKeyPair(): Keys;
    /** (Server-side) Deterministically derives a key pair for the VOPRF mode. */
    deriveKeyPair(seed: Bytes, keyInfo: Bytes): Keys;
    /** (Client-side) Blinds the client's private input for the VOPRF protocol. */
    blind(input: Bytes, rng?: RNG): Blind;

    /**
     * (Server-side) Evaluates the client's blinded element and generates a DLEQ proof
     * of correctness.
     * @param secretKey The server's private key.
     * @param publicKey The server's public key, used in proof generation.
     * @param blinded The blinded group element received from the client.
     * @param rng An optional cryptographically secure random number generator for the proof.
     * @returns The evaluated element and a proof of correct computation.
     */
    blindEvaluate(
      secretKey: ScalarBytes,
      publicKey: PointBytes,
      blinded: PointBytes,
      rng?: RNG
    ): BlindEval;

    /**
     * (Server-side) An optimized batch version of `blindEvaluate`. It evaluates multiple
     * blinded elements and produces a single, constant-size proof for the entire batch,
     * amortizing the cost of proof generation.
     * @param secretKey The server's private key.
     * @param publicKey The server's public key.
     * @param blinded An array of blinded group elements from one or more clients.
     * @param rng An optional cryptographically secure random number generator for the proof.
     * @returns An array of evaluated elements and a single proof for the batch.
     */
    blindEvaluateBatch(
      secretKey: ScalarBytes,
      publicKey: PointBytes,
      blinded: PointBytes[],
      rng?: RNG
    ): BlindEvalBatch;

    /**
     * (Client-side) The final step. The client verifies the server's proof, and if valid,
     * unblinds the result to compute the final VOPRF output.
     * @param input The original private input.
     * @param blind The secret scalar from the `blind` step.
     * @param evaluated The evaluated element from the server.
     * @param blinded The blinded element sent to the server (needed for proof verification).
     * @param publicKey The server's public key against which the proof is verified.
     * @param proof The DLEQ proof from the server.
     * @returns The final VOPRF output.
     * @throws If the proof verification fails.
     */
    finalize(
      input: Bytes,
      blind: ScalarBytes,
      evaluated: PointBytes,
      blinded: PointBytes,
      publicKey: PointBytes,
      proof: Bytes
    ): Bytes;

    /**
     * (Client-side) The batch-aware version of `finalize`. It verifies a single batch proof
     * against a list of corresponding inputs and outputs.
     * @param items An array of objects, each containing the parameters for a single finalization.
     * @param publicKey The server's public key.
     * @param proof The single DLEQ proof for the entire batch.
     * @returns An array of final VOPRF outputs, one for each item in the input.
     * @throws If the proof verification fails.
     */
    finalizeBatch(items: FinalizeItem[], publicKey: PointBytes, proof: Bytes): Bytes[];
  };

  /**
   * A factory for the Partially Oblivious Pseudorandom Function (POPRF) mode (mode 0x02).
   * This mode extends VOPRF to include a public `info` parameter, known to both client and
   * server, which is cryptographically bound to the final output.
   * This is useful for domain separation at the application level.
   * @param info A public byte string to be mixed into the computation.
   * @returns An object with the POPRF protocol functions.
   */
  readonly poprf: (info: Bytes) => {
    /** (Server-side) Generates a key pair for the POPRF mode. */
    generateKeyPair(): Keys;
    /** (Server-side) Deterministically derives a key pair for the POPRF mode. */
    deriveKeyPair(seed: Bytes, keyInfo: Bytes): Keys;

    /**
     * (Client-side) Blinds the client's private input and computes the "tweaked key".
     * The tweaked key is a public value derived from the server's public key and the public `info`.
     * @param input The client's private input.
     * @param publicKey The server's public key.
     * @param rng An optional cryptographically secure random number generator.
     * @returns The `blind`, `blinded` element, and the `tweakedKey` which the client uses for verification.
     */
    blind(input: Bytes, publicKey: PointBytes, rng?: RNG): Blind & { tweakedKey: PointBytes };

    /**
     * (Server-side) Evaluates the blinded element using a key derived from its secret key and the public `info`.
     * It generates a DLEQ proof against the tweaked key.
     * @param secretKey The server's private key.
     * @param blinded The blinded element from the client.
     * @param rng An optional RNG for the proof.
     * @returns The evaluated element and a proof of correct computation.
     */
    blindEvaluate(secretKey: ScalarBytes, blinded: PointBytes, rng?: RNG): BlindEval;

    /**
     * (Server-side) A batch-aware version of `blindEvaluate` for the POPRF mode.
     * @param secretKey The server's private key.
     * @param blinded An array of blinded elements.
     * @param rng An optional RNG for the proof.
     * @returns An array of evaluated elements and a single proof for the batch.
     */
    blindEvaluateBatch(secretKey: ScalarBytes, blinded: PointBytes[], rng: RNG): BlindEvalBatch;

    /**
     * (Client-side) A batch-aware version of `finalize` for the POPRF mode.
     * It verifies the proof against the tweaked key.
     * @param items An array containing the parameters for each finalization.
     * @param proof The single DLEQ proof for the batch.
     * @param tweakedKey The tweaked key corresponding to the proof (all items must share the same `info` and `publicKey`).
     * @returns An array of final POPRF outputs.
     * @throws If proof verification fails.
     */
    finalizeBatch(items: FinalizeItem[], proof: Bytes, tweakedKey: PointBytes): Bytes[];

    /**
     * (Client-side) Finalizes the POPRF protocol. It verifies the server's proof against the
     * `tweakedKey` computed in the `blind` step. The final output is bound to the public `info`.
     * @param input The original private input.
     * @param blind The secret scalar.
     * @param evaluated The evaluated element from the server.
     * @param blinded The blinded element sent to the server.
     * @param proof The DLEQ proof from the server.
     * @param tweakedKey The public tweaked key computed by the client during the `blind` step.
     * @returns The final POPRF output.
     * @throws If proof verification fails.
     */
    finalize(
      input: Bytes,
      blind: ScalarBytes,
      evaluated: PointBytes,
      blinded: PointBytes,
      proof: Bytes,
      tweakedKey: PointBytes
    ): Bytes;

    /**
     * A non-interactive evaluation function for an entity that knows all inputs.
     * Computes the final POPRF output directly. Useful for testing or specific applications
     * where the server needs to compute the output for a known input.
     * @param secretKey The server's private key.
     * @param input The client's private input.
     * @returns The final POPRF output.
     */
    evaluate(secretKey: ScalarBytes, input: Bytes): Bytes;
  };
};

// welcome to generic hell
export function createORPF<
  PC extends CurvePointCons<any, any>,
  F = GetPointConsF<PC>,
  P extends CurvePoint<F, P> = GetPointConsPoint<PC>,
  Opts extends OPRFOpts<F, P, PC> = OPRFOpts<F, P, PC>,
>(opts: Opts): OPRF {
  validateObject(opts, {
    name: 'string',
    hash: 'function',
    hashToScalar: 'function',
    hashToGroup: 'function',
  });
  // TODO
  // Point: 'point',
  const { name, Point, hash } = opts;
  const { Fn } = Point;

  const hashToGroup = (msg: Uint8Array, ctx: Uint8Array) =>
    opts.hashToGroup(msg, {
      DST: concatBytes(utf8ToBytes('HashToGroup-'), ctx),
    }) as P;
  const hashToScalarPrefixed = (msg: Uint8Array, ctx: Uint8Array) =>
    opts.hashToScalar(msg, { DST: concatBytes(_DST_scalar, ctx) });
  const randomScalar = (rng: RNG = randomBytes) => {
    const t = mapHashToField(rng(getMinHashLength(Fn.ORDER)), Fn.ORDER, Fn.isLE);
    // We cannot use Fn.fromBytes here, because field
    // can have different number of bytes (like ed448)
    return Fn.isLE ? bytesToNumberLE(t) : bytesToNumberBE(t);
  };

  const msm = (points: P[], scalars: bigint[]) => pippenger(Point, Point.Fn, points, scalars);

  const getCtx = (mode: number) =>
    concatBytes(utf8ToBytes('OPRFV1-'), new Uint8Array([mode]), utf8ToBytes('-' + name));
  const ctxOPRF = getCtx(0x00);
  const ctxVOPRF = getCtx(0x01);
  const ctxPOPRF = getCtx(0x02);

  function encode(...args: (Uint8Array | number | string)[]) {
    const res = [];
    for (const a of args) {
      if (typeof a === 'number') res.push(numberToBytesBE(a, 2));
      else if (typeof a === 'string') res.push(utf8ToBytes(a));
      else {
        abytes(a);
        res.push(numberToBytesBE(a.length, 2), a);
      }
    }
    // No wipe here, since will modify actual bytes
    return concatBytes(...res);
  }
  const hashInput = (...bytes: Uint8Array[]) => hash(encode(...bytes, 'Finalize'));

  function getTranscripts(B: P, C: P[], D: P[], ctx: Bytes) {
    const Bm = B.toBytes();
    const seed = hash(encode(Bm, concatBytes(utf8ToBytes('Seed-'), ctx)));
    const res = [];
    for (let i = 0; i < C.length; i++) {
      const Ci = C[i].toBytes();
      const Di = D[i].toBytes();
      const di = hashToScalarPrefixed(encode(seed, i, Ci, Di, 'Composite'), ctx);
      res.push(di);
    }
    return res;
  }

  function computeComposites(B: P, C: P[], D: P[], ctx: Bytes) {
    const T = getTranscripts(B, C, D, ctx);
    const M = msm(C, T);
    const Z = msm(D, T);
    return { M, Z };
  }

  function computeCompositesFast(k: bigint, B: P, C: P[], D: P[], ctx: Bytes): { M: P; Z: P } {
    const T = getTranscripts(B, C, D, ctx);
    const M = msm(C, T);
    const Z = M.multiply(k);
    return { M, Z };
  }

  function challengeTranscript(B: P, M: P, Z: P, t2: P, t3: P, ctx: Bytes) {
    const [Bm, a0, a1, a2, a3] = [B, M, Z, t2, t3].map((i) => i.toBytes());
    return hashToScalarPrefixed(encode(Bm, a0, a1, a2, a3, 'Challenge'), ctx);
  }

  function generateProof(ctx: Bytes, k: bigint, B: P, C: P[], D: P[], rng: RNG) {
    const { M, Z } = computeCompositesFast(k, B, C, D, ctx);
    const r = randomScalar(rng);
    const t2 = Point.BASE.multiply(r);
    const t3 = M.multiply(r);
    const c = challengeTranscript(B, M, Z, t2, t3, ctx);
    const s = Fn.sub(r, Fn.mul(c, k)); // r - c*k
    return concatBytes(...[c, s].map(Fn.toBytes));
  }

  function verifyProof(ctx: Bytes, B: P, C: P[], D: P[], proof: Bytes) {
    abytes(proof, 2 * Fn.BYTES);
    const { M, Z } = computeComposites(B, C, D, ctx);
    const [c, s] = [proof.subarray(0, Fn.BYTES), proof.subarray(Fn.BYTES)].map((f) =>
      Fn.fromBytes(f)
    );
    const t2 = Point.BASE.multiply(s).add(B.multiply(c)); // s*G + c*B
    const t3 = M.multiply(s).add(Z.multiply(c)); // s*M + c*Z
    const expectedC = challengeTranscript(B, M, Z, t2, t3, ctx);
    if (!Fn.eql(c, expectedC)) throw new Error('proof verification failed');
  }

  function generateKeyPair() {
    const skS = randomScalar();
    const pkS = Point.BASE.multiply(skS);
    return { secretKey: Fn.toBytes(skS), publicKey: pkS.toBytes() };
  }

  function deriveKeyPair(ctx: Bytes, seed: Bytes, info: Bytes) {
    const dst = concatBytes(utf8ToBytes('DeriveKeyPair'), ctx);
    const msg = concatBytes(seed, encode(info), new Uint8Array([0]));
    for (let counter = 0; counter <= 255; counter++) {
      msg[msg.length - 1] = counter;
      const skS = opts.hashToScalar(msg, { DST: dst });
      if (Fn.is0(skS)) continue; // should not happen
      return { secretKey: Fn.toBytes(skS), publicKey: Point.BASE.multiply(skS).toBytes() };
    }
    throw new Error('Cannot derive key');
  }
  function blind(ctx: Bytes, input: Uint8Array, rng: RNG = randomBytes) {
    const blind = randomScalar(rng);
    const inputPoint = hashToGroup(input, ctx);
    if (inputPoint.equals(Point.ZERO)) throw new Error('Input point at infinity');
    const blinded = inputPoint.multiply(blind);
    return { blind: Fn.toBytes(blind), blinded: blinded.toBytes() };
  }
  function evaluate(ctx: Bytes, secretKey: ScalarBytes, input: Bytes) {
    const skS = Fn.fromBytes(secretKey);
    const inputPoint = hashToGroup(input, ctx);
    if (inputPoint.equals(Point.ZERO)) throw new Error('Input point at infinity');
    const unblinded = inputPoint.multiply(skS).toBytes();
    return hashInput(input, unblinded);
  }
  const oprf = {
    generateKeyPair,
    deriveKeyPair: (seed: Bytes, keyInfo: Bytes) => deriveKeyPair(ctxOPRF, seed, keyInfo),
    blind: (input: Bytes, rng: RNG = randomBytes) => blind(ctxOPRF, input, rng),
    blindEvaluate(secretKey: ScalarBytes, blindedPoint: PointBytes) {
      const skS = Fn.fromBytes(secretKey);
      const elm = Point.fromBytes(blindedPoint);
      return elm.multiply(skS).toBytes();
    },
    finalize(input: Bytes, blindBytes: ScalarBytes, evaluatedBytes: PointBytes) {
      const blind = Fn.fromBytes(blindBytes);
      const evalPoint = Point.fromBytes(evaluatedBytes);
      const unblinded = evalPoint.multiply(Fn.inv(blind)).toBytes();
      return hashInput(input, unblinded);
    },
    evaluate: (secretKey: ScalarBytes, input: Bytes) => evaluate(ctxOPRF, secretKey, input),
  };

  const voprf = {
    generateKeyPair,
    deriveKeyPair: (seed: Bytes, keyInfo: Bytes) => deriveKeyPair(ctxVOPRF, seed, keyInfo),
    blind: (input: Bytes, rng: RNG = randomBytes) => blind(ctxVOPRF, input, rng),
    blindEvaluateBatch(
      secretKey: ScalarBytes,
      publicKey: PointBytes,
      blinded: PointBytes[],
      rng: RNG = randomBytes
    ) {
      if (!Array.isArray(blinded)) throw new Error('expected array');
      const skS = Fn.fromBytes(secretKey);
      const pkS = Point.fromBytes(publicKey);
      const blindedPoints = blinded.map(Point.fromBytes);
      const evaluated = blindedPoints.map((i) => i.multiply(skS));
      const proof = generateProof(ctxVOPRF, skS, pkS, blindedPoints, evaluated, rng);
      return { evaluated: evaluated.map((i) => i.toBytes()), proof };
    },
    blindEvaluate(
      secretKey: ScalarBytes,
      publicKey: PointBytes,
      blinded: PointBytes,
      rng: RNG = randomBytes
    ) {
      const res = this.blindEvaluateBatch(secretKey, publicKey, [blinded], rng);
      return { evaluated: res.evaluated[0], proof: res.proof };
    },
    finalizeBatch(items: FinalizeItem[], publicKey: PointBytes, proof: Bytes) {
      if (!Array.isArray(items)) throw new Error('expected array');
      const pkS = Point.fromBytes(publicKey);
      const blindedPoints = items.map((i) => i.blinded).map(Point.fromBytes);
      const evalPoints = items.map((i) => i.evaluated).map(Point.fromBytes);
      verifyProof(ctxVOPRF, pkS, blindedPoints, evalPoints, proof);
      return items.map((i) => oprf.finalize(i.input, i.blind, i.evaluated));
    },
    finalize(
      input: Bytes,
      blind: ScalarBytes,
      evaluated: PointBytes,
      blinded: PointBytes,
      publicKey: PointBytes,
      proof: Bytes
    ) {
      return this.finalizeBatch([{ input, blind, evaluated, blinded }], publicKey, proof)[0];
    },
    evaluate: (secretKey: ScalarBytes, input: Bytes) => evaluate(ctxVOPRF, secretKey, input),
  };
  // NOTE: info is domain separation
  const poprf = (info: Bytes) => {
    const m = hashToScalarPrefixed(encode('Info', info), ctxPOPRF);
    const T = Point.BASE.multiply(m);
    return {
      generateKeyPair,
      deriveKeyPair: (seed: Bytes, keyInfo: Bytes) => deriveKeyPair(ctxPOPRF, seed, keyInfo),
      blind(input: Bytes, publicKey: PointBytes, rng: RNG = randomBytes) {
        const pkS = Point.fromBytes(publicKey);
        const tweakedKey = T.add(pkS);
        if (tweakedKey.equals(Point.ZERO)) throw new Error('tweakedKey point at infinity');
        const blind = randomScalar(rng);
        const inputPoint = hashToGroup(input, ctxPOPRF);
        if (inputPoint.equals(Point.ZERO)) throw new Error('Input point at infinity');
        const blindedPoint = inputPoint.multiply(blind);
        return {
          blind: Fn.toBytes(blind),
          blinded: blindedPoint.toBytes(),
          tweakedKey: tweakedKey.toBytes(),
        };
      },
      blindEvaluateBatch(secretKey: ScalarBytes, blinded: PointBytes[], rng: RNG = randomBytes) {
        if (!Array.isArray(blinded)) throw new Error('expected array');
        const skS = Fn.fromBytes(secretKey);
        const t = Fn.add(skS, m);
        // "Hence, this error can be a signal for the server to replace its private key". We throw inside,
        // should be impossible.
        const invT = Fn.inv(t);
        const blindedPoints = blinded.map(Point.fromBytes);
        const evalPoints = blindedPoints.map((i) => i.multiply(invT));
        const tweakedKey = Point.BASE.multiply(t);
        const proof = generateProof(ctxPOPRF, t, tweakedKey, evalPoints, blindedPoints, rng);
        return { evaluated: evalPoints.map((i) => i.toBytes()), proof };
      },
      blindEvaluate(secretKey: ScalarBytes, blinded: PointBytes, rng: RNG = randomBytes) {
        const res = this.blindEvaluateBatch(secretKey, [blinded], rng);
        return { evaluated: res.evaluated[0], proof: res.proof };
      },
      finalizeBatch(items: FinalizeItem[], proof: Bytes, tweakedKey: PointBytes) {
        if (!Array.isArray(items)) throw new Error('expected array');
        const evalPoints = items.map((i) => i.evaluated).map(Point.fromBytes);
        verifyProof(
          ctxPOPRF,
          Point.fromBytes(tweakedKey),
          evalPoints,
          items.map((i) => i.blinded).map(Point.fromBytes),
          proof
        );
        return items.map((i, j) => {
          const blind = Fn.fromBytes(i.blind);
          const point = evalPoints[j].multiply(Fn.inv(blind)).toBytes();
          return hashInput(i.input, info, point);
        });
      },
      finalize(
        input: Bytes,
        blind: ScalarBytes,
        evaluated: PointBytes,
        blinded: PointBytes,
        proof: Bytes,
        tweakedKey: PointBytes
      ) {
        return this.finalizeBatch([{ input, blind, evaluated, blinded }], proof, tweakedKey)[0];
      },
      evaluate(secretKey: ScalarBytes, input: Bytes) {
        const skS = Fn.fromBytes(secretKey);
        const inputPoint = hashToGroup(input, ctxPOPRF);
        if (inputPoint.equals(Point.ZERO)) throw new Error('Input point at infinity');
        const t = Fn.add(skS, m);
        const invT = Fn.inv(t);
        const unblinded = inputPoint.multiply(invT).toBytes();
        return hashInput(input, info, unblinded);
      },
    };
  };
  return Object.freeze({ name, oprf, voprf, poprf, __tests: { Fn } });
}
