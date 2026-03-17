/**
 * FROST: Flexible Round-Optimized Schnorr Threshold Protocol for Two-Round Schnorr Signatures.
 *
 * See [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/) and [frost.zfnd.org](https://frost.zfnd.org).
 * @module
 */
import { utf8ToBytes } from '@noble/hashes/utils.js';
import {
  bytesToHex,
  bytesToNumberBE,
  bytesToNumberLE,
  concatBytes,
  hexToBytes,
  randomBytes,
  validateObject,
} from '../utils.ts';
import { pippenger, type CurvePoint, type CurvePointCons } from './curve.ts';
import { poly, type RootsOfUnity } from './fft.ts';
import { type H2CDSTOpts } from './hash-to-curve.ts';
import { getMinHashLength, mapHashToField, type IField } from './modular.ts';

export type RNG = typeof randomBytes;
export type Identifier = string; // Identifiers are hex to make comparison easier
export type Commitment = Uint8Array; // serialized point
export type Coefficient = Uint8Array; // serialized scalar
export type Signature = Uint8Array;
export type Signers = { min: number; max: number };
export type SecretKey = Uint8Array; // Secret key
export type Bytes = Uint8Array;
type Point = Uint8Array;

export type DKG_Round1 = {
  // If identifiers assigned via fromNumber before, it is worth checking that party doesn't impersonate other.
  // But we throw error on duplicate identifiers
  identifier: Identifier;
  commitment: Commitment[]; // sender identifier
  proofOfKnowledge: Signature;
};
export type DKG_Round2 = {
  identifier: Identifier; // sender identifier
  signingShare: Uint8Array;
};
// This is internal, so we can use bigints
export type DKG_Secret = {
  identifier: bigint;
  coefficients?: bigint[];
  commitment: Point[];
  signers: Signers;
  // Keep the local polynomial until round3 succeeds so late DKG failures can be retried.
  step?: 1 | 2 | 3;
};

export type FrostPublic = {
  signers: Signers;
  commitments: Uint8Array[]; // Point[], where commitments[0] is the group public key
  verifyingShares: Record<Identifier, Uint8Array>; // id -> Point
};
export type FrostSecret = {
  identifier: Identifier;
  signingShare: Uint8Array; // Scalar
};
export type Key = { public: FrostPublic; secret: FrostSecret };
export type DealerShares = {
  public: FrostPublic;
  secretShares: Record<Identifier, FrostSecret>;
};
// Sign stuff
export type Nonces = {
  hiding: Uint8Array; // Scalar
  binding: Uint8Array; // Scalar
};
export type NonceCommitments = {
  identifier: Identifier;
  hiding: Uint8Array; // Point
  binding: Uint8Array; // Point
};
export type GenNonce = { nonces: Nonces; commitments: NonceCommitments };

export interface FROSTPoint<T extends CurvePoint<any, T>> extends CurvePoint<any, T> {
  add(rhs: T): T;
  multiply(rhs: bigint): T;
  equals(rhs: T): boolean;
  toBytes(compressed?: boolean): Bytes;
  clearCofactor(): T;
}
export interface FROSTPointConstructor<T extends FROSTPoint<T>> extends CurvePointCons<T> {
  fromBytes(a: Bytes): T;
  Fn: IField<bigint>;
}

// Opts
export type FrostOpts<P extends FROSTPoint<P>> = {
  readonly name: string;
  readonly Point: FROSTPointConstructor<P>;
  readonly Fn?: IField<bigint>;
  readonly validatePoint?: (p: P) => void;
  readonly parsePublicKey?: (bytes: Uint8Array) => P;
  readonly hash: (msg: Uint8Array) => Uint8Array;
  readonly hashToScalar?: (msg: Uint8Array, options?: H2CDSTOpts) => bigint;
  // Hacks for taproot support
  readonly adjustScalar?: (n: bigint) => bigint;
  readonly adjustPoint?: (n: P) => P;
  readonly challenge?: (R: P, PK: P, msg: Uint8Array) => bigint;
  readonly adjustNonces?: (PK: P, nonces: Nonces) => Nonces;
  readonly adjustSecret?: (secret: FrostSecret, pub: FrostPublic) => FrostSecret;
  readonly adjustPublic?: (pub: FrostPublic) => FrostPublic;
  readonly adjustGroupCommitmentShare?: (GC: P, GCShare: P) => P;
  readonly adjustTx?: {
    readonly encode: (tx: Uint8Array) => Uint8Array;
    readonly decode: (tx: Uint8Array) => Uint8Array;
  };
  readonly adjustDKG?: (k: Key) => Key;
  // Hash function prefixes
  readonly H1?: string;
  readonly H2?: string;
  readonly H3?: string;
  readonly H4?: string;
  readonly H5?: string;
  readonly HDKG?: string;
  readonly HID?: string;
};

/**
 * FROST: Threshold Protocol for Two‑Round Schnorr Signatures
 * from [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/).
 */
export type FROST = {
  /**
   * Methods to construct participant identifiers.
   */
  Identifier: {
    /**
     * Constructs an identifier from a numeric index.
     * @param n - A positive integer.
     * @returns A canonical serialized Identifier.
     */
    fromNumber(n: number): Identifier;
    /**
     * Derives an identifier deterministically from a string (e.g. an email).
     * @param s - Arbitrary string.
     * @returns A canonical serialized Identifier.
     */
    derive(s: string): Identifier;
  };
  /**
   * Distributed Key Generation (DKG) protocol interface.
   * RFC 9591 leaves DKG out of scope; Appendix C only specifies dealer/VSS key generation.
   * These helpers follow the split-round API used by frost-rs for interoperable testing.
   */
  DKG: {
    /**
     * Generates the first round of DKG.
     * @param id - Participant's identifier.
     * @param signers - Set of all participants (min/max threshold).
     * @param secret - Optional initial secret scalar.
     * @param rng - Optional RNG for nonce generation.
     * @returns Public broadcast and private DKG state.
     */
    round1: (
      id: Identifier,
      signers: Signers,
      secret?: SecretKey,
      rng?: RNG
    ) => {
      public: DKG_Round1;
      secret: DKG_Secret;
    };
    /**
     * Executes DKG round 2 given public round1 data from others.
     * @param secret - Private DKG state from round1.
     * @param others - Public round1 broadcasts from other participants.
     * @returns A map of round2 messages to be sent to others.
     */
    round2: (secret: DKG_Secret, others: DKG_Round1[]) => Record<string, DKG_Round2>;
    /**
     * Finalizes key generation in round3 using received round1 + round2 messages.
     * @param secret - Private DKG state.
     * @param round1 - Public round1 broadcasts from all participants.
     * @param round2 - Round2 messages received from others.
     * @returns Final secret/public key information for the participant.
     * Callers MUST pass the same verified remote `round1` package set that was already
     * accepted in `round2()`, rather than re-fetching or rebuilding it from the network.
     */
    round3: (secret: DKG_Secret, round1: DKG_Round1[], round2: DKG_Round2[]) => Key;
    /**
     * Securely erases internal secret state.
     * @param secret - Private DKG state from round1.
     */
    clean(secret: DKG_Secret): void;
  };
  /**
   * Trusted dealer mode: generates key shares from a central trusted authority.
   * Mirrors RFC 9591 Appendix C and returns one shared VSS commitment package plus per-participant shares.
   * @param signers - Threshold parameters (min/max).
   * @param identifiers - Optional explicit participant list.
   * @param secret - Optional secret scalar.
   * @param rng - Optional RNG.
   * @returns One shared public package plus the participant secret-share packages.
   */
  trustedDealer(
    signers: Signers,
    identifiers?: Identifier[],
    secret?: SecretKey,
    rng?: RNG
  ): DealerShares;
  /**
   * Validates the consistency of a secret share against the shared public commitments.
   * This is the RFC 9591 Appendix C.2 `vss_verify` check against the shared dealer/DKG commitment.
   * Throws if invalid.
   * @param secret - A FrostSecret containing identifier and signing share.
   * @param pub - Shared public package containing commitments.
   */
  validateSecret(secret: FrostSecret, pub: FrostPublic): void;
  /**
   * Produces nonces and public commitments used in signing.
   * RFC 9591 Section 5.1 `commit()`.
   * @param secret - Participant's secret share.
   * @param rng - Optional RNG.
   * @returns Nonce values and their public commitments.
   * Returned nonces are one-time-use and MUST NOT be reused across signing sessions.
   * This API does not mutate or zeroize caller-owned nonce objects.
   */
  commit(secret: FrostSecret, rng?: RNG): GenNonce;
  /**
   * Signs a message using the participant's secret and nonce.
   * @param secret - Participant's secret share.
   * @param pub - Shared public package containing commitments.
   * @param nonces - Participant's nonce pair.
   * @param commitmentList - Commitments from all signing participants.
   * @param msg - Message to be signed.
   * @returns Signature share as a byte array.
   * RFC 9591 Section 5.2 `sign()`.
   * The caller is responsible for ensuring `nonces` comes from a fresh `commit()` call
   * and is not reused after signing.
   */
  signShare(
    secret: FrostSecret,
    pub: FrostPublic,
    nonces: Nonces,
    commitmentList: NonceCommitments[],
    msg: Uint8Array
  ): Uint8Array;
  /**
   * Verifies a signature share against public commitments.
   * Matches the coordinator-side individual-share verification from RFC 9591 Section 5.4.
   * @param pub - Group public key information.
   * @param commitmentList - Commitments from all signing participants.
   * @param msg - Message being signed.
   * @param identifier - Identifier of the signer whose share is being verified.
   * @param sigShare - Signature share to verify.
   * @returns True if valid, false otherwise.
   */
  verifyShare(
    pub: FrostPublic,
    commitmentList: NonceCommitments[],
    msg: Uint8Array,
    identifier: Identifier,
    sigShare: Uint8Array
  ): boolean;
  /**
   * Aggregates signature shares into a full signature.
   * RFC 9591 Section 5.3 `aggregate()`.
   * @param pub - Group public key.
   * @param commitmentList - Nonce commitments from all signers.
   * @param msg - Message to sign.
   * @param sigShares - Map from identifier to their signature share.
   * @returns Final aggregated signature.
   */
  aggregate(
    pub: FrostPublic,
    commitmentList: NonceCommitments[],
    msg: Uint8Array,
    sigShares: Record<Identifier, Uint8Array>
  ): Uint8Array;
  /**
   * Signs a message using a raw secret key (e.g. from combineSecret).
   * @param msg - Message to sign.
   * @param secretKey - Group secret key as bytes.
   * @returns Signature bytes.
   */
  sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
  /**
   * Verifies a full signature against the group public key.
   * @param sig - Signature bytes.
   * @param msg - Message that was signed.
   * @param publicKey - Group public key.
   * @returns True if valid, false otherwise.
   */
  verify(sig: Signature, msg: Uint8Array, publicKey: Uint8Array): boolean;
  /**
   * Combines multiple secret shares into a single secret key (e.g. for recovery).
   * @param shares - Set of FrostSecret shares.
   * @param signers - Threshold parameters.
   * @returns Group secret key as bytes.
   */
  combineSecret(shares: FrostSecret[], signers: Signers): Uint8Array;
  /**
   * Low-level helper utilities (field arithmetic and polynomial tools).
   */
  utils: {
    /**
     * Finite field used for scalars.
     */
    Fn: IField<bigint>;
    /**
     * Generates a random scalar (private key).
     * @param rng - Optional RNG source.
     * @returns Scalar as 32-byte Uint8Array.
     */
    randomScalar: (rng?: RNG) => Uint8Array;
    /**
     * Generates a secret-sharing polynomial and its public commitments.
     * @param signers - Threshold parameters.
     * @param secret - Optional initial secret scalar.
     * @param coeffs - Optional manual coefficients.
     * @param rng - Optional RNG.
     * @returns Polynomial coefficients, commitments, and secret value.
     */
    generateSecretPolynomial: (
      signers: Signers,
      secret?: Uint8Array,
      coeffs?: bigint[],
      rng?: RNG
    ) => {
      coefficients: bigint[];
      commitment: Point[];
      secret: bigint;
    };
  };
};

// PubKey = commitments, verifyingShares
// PrivKey = id, signingShare, commitment

const validateSigners = (signers: Signers) => {
  if (!Number.isSafeInteger(signers.min) || !Number.isSafeInteger(signers.max))
    throw new Error('Wrong signers info: min=' + signers.min + ' max=' + signers.max);
  // Compatibility with frost-rs, which rejects min=1 even though RFC 9591 allows it.
  if (signers.min < 2 || signers.max < 2 || signers.min > signers.max)
    throw new Error('Wrong signers info: min=' + signers.min + ' max=' + signers.max);
};
const validateCommitmentsNum = (signers: Signers, len: number) => {
  // RFC 9591 Sections 5.2/5.3 require MIN_PARTICIPANTS <= NUM_PARTICIPANTS <= MAX_PARTICIPANTS.
  if (len < signers.min || len > signers.max) throw new Error('Wrong number of commitments=' + len);
};

class AggErr extends Error {
  public cheaters: Identifier[];
  constructor(msg: string, cheaters: Identifier[]) {
    super(msg);
    this.cheaters = cheaters;
  }
}

export function createFROST<P extends FROSTPoint<P>>(opts: FrostOpts<P>): FROST {
  validateObject(
    opts,
    {
      name: 'string',
      hash: 'function',
    },
    {
      hashToScalar: 'function',
      validatePoint: 'function',
      parsePublicKey: 'function',
      adjustScalar: 'function',
      adjustPoint: 'function',
      challenge: 'function',
      adjustNonces: 'function',
      adjustSecret: 'function',
      adjustPublic: 'function',
      adjustGroupCommitmentShare: 'function',
      adjustDKG: 'function',
    }
  );
  const { Point } = opts;
  const Fn = opts.Fn || Point.Fn;
  // Hashes
  const hashBytes = opts.hash;
  const hashToScalar =
    opts.hashToScalar ||
    ((msg: Uint8Array, opts: H2CDSTOpts = { DST: new Uint8Array() }) => {
      const t = hashBytes(concatBytes(opts.DST as Uint8Array, msg));
      return Fn.create(Fn.isLE ? bytesToNumberLE(t) : bytesToNumberBE(t));
    });
  const H1Prefix = utf8ToBytes(opts.H1 !== undefined ? opts.H1 : opts.name + 'rho');
  const H2Prefix = utf8ToBytes(opts.H2 !== undefined ? opts.H2 : opts.name + 'chal');
  const H3Prefix = utf8ToBytes(opts.H3 !== undefined ? opts.H3 : opts.name + 'nonce');
  const H4Prefix = utf8ToBytes(opts.H4 !== undefined ? opts.H4 : opts.name + 'msg');
  const H5Prefix = utf8ToBytes(opts.H5 !== undefined ? opts.H5 : opts.name + 'com');
  const HDKGPrefix = utf8ToBytes(opts.HDKG !== undefined ? opts.HDKG : opts.name + 'dkg');
  const HIDPrefix = utf8ToBytes(opts.HID !== undefined ? opts.HID : opts.name + 'id');
  const H1 = (msg: Uint8Array) => hashToScalar(msg, { DST: H1Prefix });
  const H2 = (msg: Uint8Array) => hashToScalar(msg, { DST: H2Prefix });
  const H3 = (msg: Uint8Array) => hashToScalar(msg, { DST: H3Prefix });
  const H4 = (msg: Uint8Array) => hashBytes(concatBytes(H4Prefix, msg));
  const H5 = (msg: Uint8Array) => hashBytes(concatBytes(H5Prefix, msg));
  const HDKG = (msg: Uint8Array) => hashToScalar(msg, { DST: HDKGPrefix });
  const HID = (msg: Uint8Array) => hashToScalar(msg, { DST: HIDPrefix });
  // /Hashes
  const randomScalar = (rng: RNG = randomBytes) => {
    // Intentional divergence from RFC 9591 Appendix D: reuse noble's
    // mapHashToField generation (FIPS 186-5 / RFC 9380 style) which returns
    // non-zero scalars in 1..n-1 instead of allowing 0.
    const t = mapHashToField(rng(getMinHashLength(Fn.ORDER)), Fn.ORDER, Fn.isLE);
    // We cannot use Fn.fromBytes here, because field can have different number of bytes (like ed448)
    return Fn.isLE ? bytesToNumberLE(t) : bytesToNumberBE(t);
  };
  const serializePoint = (p: P) => p.toBytes();
  const parsePoint = (bytes: Uint8Array) => {
    // RFC 9591 Section 3.1 requires DeserializeElement validation. Suite-specific validatePoint
    // hooks tighten this further for ciphersuites in Section 6.
    const p = Point.fromBytes(bytes);
    if (opts.validatePoint) opts.validatePoint(p);
    return p;
  };
  // RFC 9591 Sections 4.1/5.1 model each participant's round-one output as two public commitments.
  const nonceCommitments = (identifier: Identifier, nonces: Nonces): NonceCommitments => ({
    identifier,
    hiding: serializePoint(Point.BASE.multiply(Fn.fromBytes(nonces.hiding))),
    binding: serializePoint(Point.BASE.multiply(Fn.fromBytes(nonces.binding))),
  });
  const adjustPoint = opts.adjustPoint || ((n) => n);
  // We use hex to make it easier to use inside objects
  const validateIdentifier = (n: bigint) => {
    if (!Fn.isValid(n) || Fn.is0(n)) throw new Error('Invalid identifier ' + n);
    return n;
  };
  const serializeIdentifier = (id: bigint) => bytesToHex(Fn.toBytes(validateIdentifier(id)));
  const parseIdentifier = (id: string) => {
    const n = validateIdentifier(Fn.fromBytes(hexToBytes(id)));
    // Keep string-keyed maps stable by accepting only the canonical serialized form.
    if (serializeIdentifier(n) !== id) throw new Error('expected canonical identifier hex');
    return n;
  };

  const Signature = {
    // RFC 9591 Appendix A encodes signatures canonically as SerializeElement(R) || SerializeScalar(z).
    encode: (R: P, z: bigint) => {
      let res = concatBytes(serializePoint(R), Fn.toBytes(z));
      if (opts.adjustTx) res = opts.adjustTx.encode(res);
      return res;
    },
    decode: (sig: Uint8Array) => {
      if (opts.adjustTx) sig = opts.adjustTx.decode(sig);
      // We don't know size of point, but we know size of scalar
      const R = parsePoint(sig.subarray(0, -Fn.BYTES));
      const z = Fn.fromBytes(sig.subarray(-Fn.BYTES));
      return { R, z };
    },
  };
  // Generates pair of (scalar, point)
  const genPointScalarPair = (rng: RNG = randomBytes) => {
    let n = randomScalar(rng);
    if (opts.adjustScalar) n = opts.adjustScalar(n);
    let p = Point.BASE.multiply(n);
    return { scalar: n, point: p };
  };
  // No roots here, will throw on roots based methods. Poly wants not only cracker, but also roots. This stuff works without roots.
  // Poly -> structured domain, here we have arbitrary domain (different methods/implementations)
  const nrErr = 'roots are unavailable in FROST polynomial mode';
  const noRoots: RootsOfUnity = {
    info: { G: Fn.ZERO, oddFactor: Fn.ZERO, powerOfTwo: 0 },
    roots() {
      throw new Error(nrErr);
    },
    brp() {
      throw new Error(nrErr);
    },
    inverse() {
      throw new Error(nrErr);
    },
    omega() {
      throw new Error(nrErr);
    },
    clear() {},
  };
  const Poly = poly(Fn, noRoots);
  const msm = (points: P[], scalars: bigint[]) => pippenger(Point, points, scalars);

  // Internal stuff uses bigints & Points, external Uint8Arrays
  const polynomialEvaluate = (x: bigint, coeffs: bigint[]): bigint => {
    if (!coeffs.length) throw new Error('empty coefficients');
    return Poly.monomial.eval(coeffs, x);
  };
  const deriveInterpolatingValue = (L: bigint[], xi: bigint): bigint => {
    const err = 'invalid parameters';
    // Generates lagrange coefficient
    if (!L.some((x) => Fn.eql(x, xi))) throw new Error(err);
    // Throws error if any x-coordinate is represented more than once in L.
    const Lset = new Set(L);
    if (Lset.size !== L.length) throw new Error(err);
    // Or if xi is missing
    if (!Lset.has(xi)) throw new Error(err);
    let num = Fn.ONE;
    let den = Fn.ONE;
    for (const x of L) {
      if (Fn.eql(x, xi)) continue;
      num = Fn.mul(num, x); // num *= x
      den = Fn.mul(den, Fn.sub(x, xi)); // den *= x + xi
    }
    return Fn.div(num, den);
  };
  const evalutateVSS = (identifier: bigint, commitment: P[]) => {
    const monomial = Poly.monomial.basis(identifier, commitment.length);
    return msm(commitment, monomial);
  };
  // High-level internal stuff
  const generateSecretPolynomial = (
    signers: Signers,
    secret?: Uint8Array,
    coeffs?: bigint[],
    rng: RNG = randomBytes
  ) => {
    validateSigners(signers);
    const secretScalar = secret === undefined ? randomScalar(rng) : Fn.fromBytes(secret);
    if (!coeffs) {
      coeffs = [];
      for (let i = 0; i < signers.min - 1; i++) coeffs.push(randomScalar(rng));
    }
    if (coeffs.length !== signers.min - 1) throw new Error('wrong coefficients length');
    const coefficients: bigint[] = [secretScalar, ...coeffs];
    // RFC 9591 Appendix C.2 commits to every polynomial coefficient with ScalarBaseMult.
    const commitment = coefficients.map((i) => Point.BASE.multiply(i));
    return { coefficients, commitment, secret: secretScalar };
  };
  // Pretty much sign+verify, same as basic
  const ProofOfKnowledge = {
    challenge: (id: bigint, verKey: P, R: P) =>
      HDKG(concatBytes(Fn.toBytes(id), serializePoint(verKey), serializePoint(R))),
    compute(id: bigint, coefficents: bigint[], commitments: P[], rng: RNG = randomBytes) {
      if (coefficents.length < 1) throw new Error('coefficients should have at least one element');
      const { point: R, scalar: k } = genPointScalarPair(rng);
      const verKey = commitments[0]; // verify key is first one
      const c = this.challenge(id, verKey, R);
      const mu = Fn.add(k, Fn.mul(coefficents[0], c)); // mu = k + coeff[0] * c
      return Signature.encode(R, mu);
    },
    validate(id: bigint, commitment: Commitment[], proof: Uint8Array) {
      if (commitment.length < 1) throw new Error('commitment should have at least one element');
      const { R, z } = Signature.decode(proof);
      const phi = parsePoint(commitment[0]);
      const c = this.challenge(id, phi, R);
      // R === z*G - phi*c
      if (!R.equals(Point.BASE.multiply(z).subtract(phi.multiply(c))))
        throw new Error('invalid proof of knowledge');
    },
  };
  const Basic = {
    challenge: (R: P, PK: P, msg: Uint8Array) => {
      if (opts.challenge) return opts.challenge(R, PK, msg);
      return H2(concatBytes(serializePoint(R), serializePoint(PK), msg));
    },
    sign(msg: Uint8Array, sk: bigint, rng: RNG = randomBytes): [P, bigint] {
      const { point: R, scalar: r } = genPointScalarPair(rng);
      const PK = Point.BASE.multiply(sk); // sk*G
      const c = this.challenge(R, PK, msg);
      const z = Fn.add(r, Fn.mul(c, sk)); // r + c * sk
      return [R, z];
    },
    verify(msg: Uint8Array, R: P, z: bigint, PK: P): boolean {
      if (opts.adjustPoint) PK = opts.adjustPoint(PK);
      if (opts.adjustPoint) R = opts.adjustPoint(R);
      const c = this.challenge(R, PK, msg);
      const zB = Point.BASE.multiply(z); // z*G
      const cA = PK.multiply(c); // c*PK
      let check = zB.subtract(cA).subtract(R); // zB - cA - R
      // No clearCoffactor on ristretto
      if (check.clearCofactor) check = check.clearCofactor();
      return Point.ZERO.equals(check);
    },
  };
  // === vssVerify
  const validateSecretShare = (identifier: bigint, commitment: P[], signingShare: bigint) => {
    // RFC 9591 Appendix C.2 `vss_verify(share_i, vss_commitment)`.
    if (!Point.BASE.multiply(signingShare).equals(evalutateVSS(identifier, commitment)))
      throw new Error('invalid secret share');
  };
  const Identifier = {
    fromNumber(n: number): Identifier {
      if (!Number.isSafeInteger(n)) throw new Error('expected safe interger');
      return serializeIdentifier(BigInt(n));
    },
    // Not in spec, but in FROST implementation,
    // seems useful and nice, no need to sync identifiers (would require more interactions)
    derive(s: string): Identifier {
      if (typeof s !== 'string') throw new Error('wrong identifier string: ' + s);
      return serializeIdentifier(HID(utf8ToBytes(s)));
    },
  };
  const generateNonce = (secret: bigint, rng: RNG = randomBytes) =>
    H3(concatBytes(rng(32), Fn.toBytes(secret)));

  const getGroupCommitment = (GPK: P, commitmentList: NonceCommitments[], msg: Uint8Array) => {
    const CL = commitmentList.map((i) => [
      i.identifier,
      parseIdentifier(i.identifier),
      parsePoint(i.hiding),
      parsePoint(i.binding),
    ]) as [Identifier, bigint, P, P][];
    // RFC 9591 Sections 4.3/4.4/4.5 and 5.2/5.3 treat commitment_list as sorted by identifier.
    CL.sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    // Encode commitment list
    const Cbytes = [];
    for (const [_, id, hC, bC] of CL)
      Cbytes.push(Fn.toBytes(id), serializePoint(hC), serializePoint(bC));
    const encodedCommitmentHash = H5(concatBytes(...Cbytes));
    const rhoPrefix = concatBytes(serializePoint(GPK), H4(msg), encodedCommitmentHash);
    // Compute binding factors
    const bindingFactors: Record<Identifier, bigint> = {};
    for (const [i, id] of CL) {
      bindingFactors[i] = H1(concatBytes(rhoPrefix, Fn.toBytes(id)));
    }
    const points: P[] = [];
    const scalars: bigint[] = [];
    for (const [i, _, hC, bC] of CL) {
      if (Point.ZERO.equals(hC) || Point.ZERO.equals(bC)) throw new Error('infinity commitment');
      points.push(hC, bC);
      scalars.push(Fn.ONE, bindingFactors[i]);
    }
    const groupCommitment = msm(points, scalars); //  GC += hC + bC*bindingFactor
    const identifiers = CL.map((i) => i[1]);
    return { identifiers, groupCommitment, bindingFactors };
  };
  const prepareShare = (
    PK: Uint8Array,
    commitmentList: NonceCommitments[],
    msg: Uint8Array,
    identifier: Identifier
  ) => {
    // RFC 9591 Sections 4.4/4.5/4.6 feed directly into the Section 5.2 signer computation.
    const GPK = adjustPoint(parsePoint(PK));
    const id = parseIdentifier(identifier);
    const { identifiers, groupCommitment, bindingFactors } = getGroupCommitment(
      GPK,
      commitmentList,
      msg
    );
    const bindingFactor = bindingFactors[identifier];
    const lambda = deriveInterpolatingValue(identifiers, id);
    const challenge = Basic.challenge(groupCommitment, GPK, msg);
    return { lambda, challenge, bindingFactor, groupCommitment };
  };
  return {
    Identifier,
    // DKG is Distributed Key Generation (not related to Trusted Dealer Key Generation). Naming is awesome!
    DKG: {
      // NOTE: we allow to pass secret scalar from user side,
      // this way it can be derived, instead of random generation
      round1: (id: Identifier, signers: Signers, secret?: SecretKey, rng: RNG = randomBytes) => {
        validateSigners(signers);
        const idNum = parseIdentifier(id);
        const { coefficients, commitment } = generateSecretPolynomial(
          signers,
          secret,
          undefined,
          rng
        );
        const proofOfKnowledge = ProofOfKnowledge.compute(idNum, coefficients, commitment, rng);
        const commitmentBytes = commitment.map(serializePoint);
        const round1Public: DKG_Round1 = {
          identifier: serializeIdentifier(idNum),
          commitment: commitmentBytes,
          proofOfKnowledge,
        };
        // store secret information for signing
        const round1Secret: DKG_Secret = {
          identifier: idNum,
          coefficients,
          commitment: commitment.map(serializePoint),
          // Copy threshold metadata instead of retaining the caller-owned object by reference.
          signers: { min: signers.min, max: signers.max },
          step: 1,
        };
        return { public: round1Public, secret: round1Secret };
      },
      round2: (secret: DKG_Secret, others: DKG_Round1[]): Record<string, DKG_Round2> => {
        if (others.length !== secret.signers.max - 1)
          throw new Error('wrong number of round1 packages');
        if (!secret.coefficients || secret.step === 3)
          throw new Error('round3 package used in round2');
        const res: Record<Identifier, DKG_Round2> = {};
        for (const p of others) {
          if (p.commitment.length !== secret.signers.min)
            throw new Error('wrong number of commitments');
          const id = parseIdentifier(p.identifier);
          if (id === secret.identifier) throw new Error('duplicate id=' + serializeIdentifier(id));

          ProofOfKnowledge.validate(id, p.commitment, p.proofOfKnowledge);
          for (const c of p.commitment) parsePoint(c);
          if (res[p.identifier]) throw new Error('Duplicate id=' + id);
          const signingShare = Fn.toBytes(polynomialEvaluate(id, secret.coefficients));
          res[p.identifier] = {
            identifier: serializeIdentifier(secret.identifier),
            signingShare,
          };
        }
        secret.step = 2;
        return res;
      },
      round3: (secret: DKG_Secret, round1: DKG_Round1[], round2: DKG_Round2[]): Key => {
        // DKG is outside RFC 9591's signing flow; callers are expected to reuse the same
        // remote round1 packages already accepted in round2, like frost-rs documents.
        if (round1.length !== secret.signers.max - 1)
          throw new Error('wrong length of round1 packages');
        if (!secret.coefficients || secret.step !== 2)
          throw new Error('round2 package used in round3');
        if (round2.length !== round1.length) throw new Error('wrong length of round2 packages');
        const merged: Record<Identifier, DKG_Round1 & { signingShare?: Uint8Array }> = {};
        for (const r1 of round1) {
          if (!r1.identifier || !r1.commitment) throw new Error('wrong round1 share');
          merged[r1.identifier] = { ...r1 };
        }
        for (const r2 of round2) {
          if (!r2.identifier || !r2.signingShare) throw new Error('wrong round2 share');
          if (!merged[r2.identifier])
            throw new Error('round1 share for ' + r2.identifier + ' is missing');
          merged[r2.identifier].signingShare = r2.signingShare;
        }
        if (Object.keys(merged).length !== round1.length)
          throw new Error('mismatch identifiers between rounds');
        let signingShare = Fn.ZERO;
        if (secret.commitment.length !== secret.signers.min)
          throw new Error('wrong commitments length');
        const localCommitment = secret.commitment.map(parsePoint);
        const localShare = polynomialEvaluate(secret.identifier, secret.coefficients);
        validateSecretShare(secret.identifier, localCommitment, localShare);
        const localCommitmentBytes = localCommitment.map(serializePoint);
        const commitments: Record<Identifier, Commitment[]> = {
          [serializeIdentifier(secret.identifier)]: localCommitmentBytes,
        };
        for (const k in merged) {
          const v = merged[k];
          if (!v.signingShare || !v.commitment) throw new Error('mismatch identifiers');
          const id = parseIdentifier(k); // from
          const signingSharePart = Fn.fromBytes(v.signingShare);
          const commitment = v.commitment.map(parsePoint);
          validateSecretShare(secret.identifier, commitment, signingSharePart);
          signingShare = Fn.add(signingShare, signingSharePart);
          const idSer = serializeIdentifier(id);
          if (commitments[idSer]) throw new Error('duplicated id=' + idSer);
          commitments[idSer] = v.commitment;
        }
        signingShare = Fn.add(signingShare, localShare);
        const mergedCommitment = new Array(secret.signers.min).fill(Point.ZERO);
        for (const k in commitments) {
          const v = commitments[k];
          if (v.length !== secret.signers.min) throw new Error('wrong commitments length');
          for (let i = 0; i < v.length; i++)
            mergedCommitment[i] = mergedCommitment[i].add(parsePoint(v[i]));
        }
        const mergedCommitmentBytes = mergedCommitment.map(serializePoint);
        const verifyingShares: Record<Identifier, Uint8Array> = {};
        for (const k in commitments)
          verifyingShares[k] = serializePoint(evalutateVSS(parseIdentifier(k), mergedCommitment));
        // This is enough to sign stuff
        let res: Key = {
          public: {
            signers: { min: secret.signers.min, max: secret.signers.max },
            commitments: mergedCommitmentBytes,
            verifyingShares: Object.fromEntries(
              Object.entries(verifyingShares).map(([k, v]) => [k, v.slice()])
            ),
          },
          secret: {
            identifier: serializeIdentifier(secret.identifier),
            signingShare: Fn.toBytes(signingShare),
          },
        };
        if (opts.adjustDKG) res = opts.adjustDKG(res);
        for (let i = 0; i < secret.coefficients.length; i++)
          secret.coefficients[i] -= secret.coefficients[i];
        delete secret.coefficients;
        secret.step = 3;
        return res;
      },
      clean(secret: DKG_Secret) {
        // Instead of replacing secret bigint with another (zero?), we subtract it from itself
        // in the hope that JIT will modify it inplace, instead of creating new value.
        // This is unverified and may not work, but it is best we can do in regard of bigints.
        secret.identifier -= secret.identifier;
        if (secret.coefficients) {
          for (let i = 0; i < secret.coefficients.length; i++)
            secret.coefficients[i] -= secret.coefficients[i];
        }
        // for (const c of secret.commitment) c.fill(0);
        secret.step = 3;
      },
    },
    // Trusted dealer setup
    // Generates keys for all participants
    trustedDealer(
      signers: Signers,
      identifiers?: Identifier[],
      secret?: SecretKey,
      rng: RNG = randomBytes
    ): DealerShares {
      // if no identifiers provided, we generated default identifiers
      validateSigners(signers);
      if (identifiers === undefined) {
        identifiers = [];
        for (let i = 1; i <= signers.max; i++) identifiers.push(Identifier.fromNumber(i));
      } else {
        if (!Array.isArray(identifiers) || identifiers.length !== signers.max)
          throw new Error('identifiers should be array of ' + signers.max);
      }
      const identifierNums: Record<Identifier, bigint> = {};
      for (const id of identifiers) {
        const idNum = parseIdentifier(id);
        if (id in identifierNums) throw new Error('duplicated id=' + id);
        identifierNums[id] = idNum;
      }
      const sp = generateSecretPolynomial(signers, secret, undefined, rng);
      const commitmentBytes = sp.commitment.map(serializePoint);
      const secretShares: Record<Identifier, FrostSecret> = {};
      const verifyingShares: Record<Identifier, Uint8Array> = {};
      for (const id of identifiers) {
        const signingShare = polynomialEvaluate(identifierNums[id], sp.coefficients);
        verifyingShares[id] = serializePoint(Point.BASE.multiply(signingShare));
        secretShares[id] = {
          identifier: id,
          signingShare: Fn.toBytes(signingShare),
        };
      }
      return {
        public: {
          signers: { min: signers.min, max: signers.max },
          commitments: commitmentBytes,
          verifyingShares,
        },
        secretShares,
      };
    },
    // Validate secret (from trusted dealer or DKG)
    validateSecret(secret: FrostSecret, pub: FrostPublic) {
      const id = parseIdentifier(secret.identifier);
      const commitment = pub.commitments.map(parsePoint);
      const signingShare = Fn.fromBytes(secret.signingShare);
      validateSecretShare(id, commitment, signingShare);
    },
    // Actual signing
    // Round 1: each participant commit to nonces
    // Nonces kept private, commitments sent to coordinator (or every other participant)
    // NOTE: we don't need to know message at this point, which means coordinator can
    // keep multiple nonceCommitments for each participant in advance, which skips round1 for signing.
    // But then each participant needs to remember generated shares
    commit(secret: FrostSecret, rng: RNG = randomBytes): GenNonce {
      const secretScalar = Fn.fromBytes(secret.signingShare);
      const hiding = generateNonce(secretScalar, rng);
      const binding = generateNonce(secretScalar, rng);
      const nonces = { hiding: Fn.toBytes(hiding), binding: Fn.toBytes(binding) };
      return { nonces, commitments: nonceCommitments(secret.identifier, nonces) };
    },
    // Round2: sign. each participant create signature share based on secret and selected nonce commitments
    signShare(
      secret: FrostSecret,
      pub: FrostPublic,
      nonces: Nonces,
      commitmentList: NonceCommitments[],
      msg: Uint8Array
    ) {
      validateCommitmentsNum(pub.signers, commitmentList.length);
      // Reject a coordinator-assigned commitment pair that does not match the signer's own nonce
      // pair. This must happen before suite-specific nonce adjustment; secp256k1-tr may negate the
      // actual signing nonces later, but the coordinator still assigns the original commitments.
      const expectedCommitment = nonceCommitments(secret.identifier, nonces);
      const commitment = commitmentList.find((i) => i.identifier === secret.identifier);
      if (!commitment) throw new Error('missing signer commitment');
      if (
        bytesToHex(commitment.hiding) !== bytesToHex(expectedCommitment.hiding) ||
        bytesToHex(commitment.binding) !== bytesToHex(expectedCommitment.binding)
      )
        throw new Error('incorrect signer commitment');
      if (opts.adjustSecret) secret = opts.adjustSecret(secret, pub);
      if (opts.adjustPublic) pub = opts.adjustPublic(pub);
      const SK = Fn.fromBytes(secret.signingShare);
      const { lambda, challenge, bindingFactor, groupCommitment } = prepareShare(
        pub.commitments[0],
        commitmentList,
        msg,
        secret.identifier
      );
      const N = opts.adjustNonces ? opts.adjustNonces(groupCommitment, nonces) : nonces;
      const hidingNonce = Fn.fromBytes(N.hiding);
      const bindingNonce = Fn.fromBytes(N.binding);
      const t = Fn.mul(Fn.mul(lambda, SK), challenge); // challenge * lambda * SK
      const t2 = Fn.mul(bindingNonce, bindingFactor); // bindingNonce * bindingFactor
      const r = Fn.toBytes(Fn.add(Fn.add(hidingNonce, t2), t)); // t + t2 + hidingNonce
      return r;
    },
    // Each participant (or coordinator) can verify signatures from other participants
    verifyShare(
      pub: FrostPublic,
      commitmentList: NonceCommitments[],
      msg: Uint8Array,
      identifier: Identifier,
      sigShare: Uint8Array
    ) {
      if (opts.adjustPublic) pub = opts.adjustPublic(pub);
      const comm = commitmentList.find((i) => i.identifier === identifier);
      if (!comm) throw new Error('cannot find identifier commitment');
      const PK = parsePoint(pub.verifyingShares[identifier]);
      const hidingNonceCommitment = parsePoint(comm.hiding);
      const bindingNonceCommitment = parsePoint(comm.binding);
      const { lambda, challenge, bindingFactor, groupCommitment } = prepareShare(
        pub.commitments[0],
        commitmentList,
        msg,
        identifier
      );
      let commShare = hidingNonceCommitment.add(bindingNonceCommitment.multiply(bindingFactor)); // hC + bC * bF
      if (opts.adjustGroupCommitmentShare)
        commShare = opts.adjustGroupCommitmentShare(groupCommitment, commShare);
      const l = Point.BASE.multiply(Fn.fromBytes(sigShare)); // sigShare*G
      const r = commShare.add(PK.multiply(Fn.mul(challenge, lambda))); // commShare + PK*(challenge*lambda)
      return l.equals(r);
    },
    // Aggregate multiple signature shares into groupSignature
    aggregate(
      pub: FrostPublic,
      commitmentList: NonceCommitments[],
      msg: Uint8Array,
      sigShares: Record<Identifier, Uint8Array>
    ) {
      if (opts.adjustPublic) pub = opts.adjustPublic(pub);
      try {
        validateCommitmentsNum(pub.signers, commitmentList.length);
      } catch {
        throw new AggErr('aggregation failed', []);
      }
      const ids = commitmentList.map((i) => i.identifier);
      if (ids.length !== Object.keys(sigShares).length) throw new AggErr('aggregation failed', []);
      for (const id of ids) {
        if (!(id in sigShares) || !(id in pub.verifyingShares))
          throw new AggErr('aggregation failed', []);
      }
      const GPK = parsePoint(pub.commitments[0]);
      const { groupCommitment } = getGroupCommitment(GPK, commitmentList, msg);
      let z = Fn.ZERO;
      // RFC 9591 Section 5.3 aggregates by summing the validated signature shares.
      for (const id of ids) z = Fn.add(z, Fn.fromBytes(sigShares[id])); // z += zi
      if (!Basic.verify(msg, groupCommitment, z, GPK)) {
        const cheaters = [];
        for (const id of ids) {
          if (!this.verifyShare(pub, commitmentList, msg, id, sigShares[id])) cheaters.push(id);
        }
        throw new AggErr('aggregation failed', cheaters);
      }
      return Signature.encode(groupCommitment, z);
    },
    // Basic sign/verify using single key
    sign(msg: Uint8Array, secretKey: Uint8Array) {
      let sk = Fn.fromBytes(secretKey);
      // Taproot single-key signing needs the same scalar normalization as threshold keys.
      if (opts.adjustScalar) sk = opts.adjustScalar(sk);
      const [R, z] = Basic.sign(msg, sk);
      return Signature.encode(R, z);
    },
    verify(sig: Signature, msg: Uint8Array, publicKey: Uint8Array) {
      const PK = opts.parsePublicKey ? opts.parsePublicKey(publicKey) : parsePoint(publicKey);
      const { R, z } = Signature.decode(sig);
      return Basic.verify(msg, R, z, PK);
    },
    // Combine multiple secret shares to restore secret
    combineSecret(shares: FrostSecret[], signers: Signers) {
      validateSigners(signers);
      if (!Array.isArray(shares) || shares.length < signers.min)
        throw new Error('wrong secret shares array');
      const points = [];
      const seen: Record<Identifier, boolean> = {};
      // Interpolate over the full provided share set and reject duplicate identifiers.
      for (const s of shares) {
        const idNum = parseIdentifier(s.identifier);
        const id = serializeIdentifier(idNum);
        if (seen[id]) throw new Error('duplicated id=' + id);
        seen[id] = true;
        points.push([idNum, Fn.fromBytes(s.signingShare)]);
      }
      const xCoords = points.map(([x]) => x);
      let res = Fn.ZERO;
      for (const [x, y] of points)
        res = Fn.add(res, Fn.mul(y, deriveInterpolatingValue(xCoords, x)));
      return Fn.toBytes(res);
    },
    // Utils
    utils: {
      Fn, // NOTE: we re-export it here because it may be different from Point.Fn (ed448 is fun!)
      randomScalar: (rng: RNG = randomBytes) => Fn.toBytes(genPointScalarPair(rng).scalar),
      generateSecretPolynomial: (
        signers: Signers,
        secret?: Uint8Array,
        coeffs?: bigint[],
        rng?: RNG
      ) => {
        const res = generateSecretPolynomial(signers, secret, coeffs, rng);
        return { ...res, commitment: res.commitment.map(serializePoint) };
      },
    },
  };
}
