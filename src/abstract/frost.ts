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
  type TArg,
  type TRet,
} from '../utils.ts';
import { pippenger, validatePointCons, type CurvePoint, type CurvePointCons } from './curve.ts';
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
  // If identifiers were assigned via fromNumber before, it is worth checking
  // that a party doesn't impersonate another one.
  // But we throw on duplicate identifiers.
  identifier: Identifier;
  commitment: TRet<Commitment[]>; // sender identifier
  proofOfKnowledge: TRet<Signature>;
};
export type DKG_Round2 = {
  identifier: Identifier; // sender identifier
  signingShare: TRet<Bytes>;
};
// This is internal, so we can use bigints
export type DKG_Secret = {
  identifier: bigint;
  coefficients?: bigint[];
  commitment: TRet<Point[]>;
  signers: Signers;
  // Keep the local polynomial until round3 succeeds so late DKG failures can be retried.
  step?: 1 | 2 | 3;
};

export type FrostPublic = {
  signers: Signers;
  commitments: TRet<Bytes[]>; // Point[], where commitments[0] is the group public key
  verifyingShares: TRet<Record<Identifier, Bytes>>; // id -> Point
};
export type FrostSecret = {
  identifier: Identifier;
  signingShare: TRet<Bytes>; // Scalar
};
export type Key = { public: FrostPublic; secret: FrostSecret };
export type DealerShares = {
  public: FrostPublic;
  secretShares: Record<Identifier, FrostSecret>;
};
// Sign stuff
export type Nonces = {
  hiding: TRet<Bytes>; // Scalar
  binding: TRet<Bytes>; // Scalar
};
export type NonceCommitments = {
  identifier: Identifier;
  hiding: TRet<Bytes>; // Point
  binding: TRet<Bytes>; // Point
};
export type GenNonce = {
  nonces: Nonces;
  commitments: NonceCommitments;
};

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
  /** Optional suite hook that tightens canonical decoding with subgroup / identity checks. */
  readonly validatePoint?: (p: P) => void;
  /** Optional public-key parser. Implementations MUST preserve the same subgroup / identity policy
   * as `validatePoint`, because this bypasses generic canonical decoding in `parsePoint()`. */
  readonly parsePublicKey?: (bytes: TArg<Uint8Array>) => P;
  readonly hash: (msg: TArg<Uint8Array>) => TRet<Uint8Array>;
  /** Custom scalar hash hook. Implementations MUST treat `msg` and `options` as read-only. */
  readonly hashToScalar?: (msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>) => bigint;
  // Hacks for taproot support
  readonly adjustScalar?: (n: bigint) => bigint;
  readonly adjustPoint?: (n: P) => P;
  readonly challenge?: (R: P, PK: P, msg: TArg<Uint8Array>) => bigint;
  readonly adjustNonces?: (PK: P, nonces: TArg<Nonces>) => TRet<Nonces>;
  readonly adjustSecret?: (secret: TArg<FrostSecret>, pub: TArg<FrostPublic>) => TRet<FrostSecret>;
  readonly adjustPublic?: (pub: TArg<FrostPublic>) => TRet<FrostPublic>;
  readonly adjustGroupCommitmentShare?: (GC: P, GCShare: P) => P;
  readonly adjustTx?: {
    readonly encode: (tx: TArg<Uint8Array>) => TRet<Uint8Array>;
    readonly decode: (tx: TArg<Uint8Array>) => TRet<Uint8Array>;
  };
  readonly adjustDKG?: (k: TArg<Key>) => TRet<Key>;
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
     * @returns Public broadcast and private DKG state. The returned `secret` package is mutable
     *   round state that will be consumed by `round2()` and `round3()`.
     */
    round1: (
      id: Identifier,
      signers: Signers,
      secret?: TArg<SecretKey>,
      rng?: RNG
    ) => {
      public: DKG_Round1;
      secret: DKG_Secret;
    };
    /**
     * Executes DKG round 2 given public round1 data from others.
     * @param secret - Private DKG state from round1. This mutates `secret.step` in place.
     * @param others - Public round1 broadcasts from other participants.
     * @returns A map of round2 messages to be sent to others.
     */
    round2: (
      secret: TArg<DKG_Secret>,
      others: TArg<DKG_Round1[]>
    ) => TRet<Record<string, DKG_Round2>>;
    /**
     * Finalizes key generation in round3 using received round1 + round2 messages.
     * @param secret - Private DKG state. This consumes the remaining local polynomial coefficients
     *   and transitions the package to its final post-round3 state.
     * @param round1 - Public round1 broadcasts from all participants.
     * @param round2 - Round2 messages received from others.
     * @returns Final secret/public key information for the participant.
     * Callers MUST pass the same verified remote `round1` package set that was already
     * accepted in `round2()`, rather than re-fetching or rebuilding it from the network.
     */
    round3: (
      secret: TArg<DKG_Secret>,
      round1: TArg<DKG_Round1[]>,
      round2: TArg<DKG_Round2[]>
    ) => TRet<Key>;
    /**
     * Best-effort erasure of internal secret state. Bigint/JIT copies may still survive outside the
     * local object even after cleanup.
     * @param secret - Private DKG state from round1.
     */
    clean(secret: TArg<DKG_Secret>): void;
  };
  /**
   * Trusted dealer mode: generates key shares from a central trusted authority.
   * Mirrors RFC 9591 Appendix C and returns one shared VSS commitment package
   * plus per-participant shares.
   * @param signers - Threshold parameters (min/max).
   * @param identifiers - Optional explicit participant list.
   * @param secret - Optional secret scalar.
   * @param rng - Optional RNG.
   * @returns One shared public package plus the participant secret-share packages.
   */
  trustedDealer(
    signers: Signers,
    identifiers?: Identifier[],
    secret?: TArg<SecretKey>,
    rng?: RNG
  ): TRet<DealerShares>;
  /**
   * Validates the consistency of a secret share against the shared public commitments.
   * This is the RFC 9591 Appendix C.2 `vss_verify` check against the shared dealer/DKG commitment.
   * It does not relax RFC 9591 Section 3.1: public identity elements are still invalid even when
   * the scalar/share algebra would otherwise be self-consistent.
   * Throws if invalid.
   * @param secret - A FrostSecret containing identifier and signing share.
   * @param pub - Shared public package containing commitments.
   */
  validateSecret(secret: TArg<FrostSecret>, pub: TArg<FrostPublic>): void;
  /**
   * Produces nonces and public commitments used in signing.
   * RFC 9591 Section 5.1 `commit()`.
   * @param secret - Participant's secret share.
   * @param rng - Optional RNG.
   * @returns Nonce values and their public commitments.
   * Returned nonces are one-time-use and MUST NOT be reused across signing sessions.
   * This API does not mutate or zeroize caller-owned nonce objects.
   */
  commit(secret: TArg<FrostSecret>, rng?: RNG): TRet<GenNonce>;
  /**
   * Signs a message using the participant's secret and nonce.
   * @param secret - Participant's secret share.
   * @param pub - Shared public package containing commitments.
   * @param nonces - Participant's nonce pair.
   * @param commitmentList - Commitments from all signing participants.
   * @param msg - Message to be signed.
   * @returns Signature share as a byte array.
   * RFC 9591 Sections 4.1/5.1 require round-one commitments to be one-time-use, and
   * Section 5.2 signs with the nonce corresponding to that published commitment.
   * The caller MUST pass fresh nonces from `commit()`. On successful signing, this helper
   * consumes the caller-owned nonce object by zeroing both nonce byte arrays in place.
   * Later calls reject an all-zero nonce package, so same-object reuse fails closed and an
   * accidentally generated zero nonce package is not silently used for signing.
   */
  signShare(
    secret: TArg<FrostSecret>,
    pub: TArg<FrostPublic>,
    nonces: TArg<Nonces>,
    commitmentList: TArg<NonceCommitments[]>,
    msg: TArg<Uint8Array>
  ): TRet<Uint8Array>;
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
    pub: TArg<FrostPublic>,
    commitmentList: TArg<NonceCommitments[]>,
    msg: TArg<Uint8Array>,
    identifier: Identifier,
    sigShare: TArg<Uint8Array>
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
    pub: TArg<FrostPublic>,
    commitmentList: TArg<NonceCommitments[]>,
    msg: TArg<Uint8Array>,
    sigShares: TArg<Record<Identifier, Uint8Array>>
  ): TRet<Uint8Array>;
  /**
   * Signs a message using a raw secret key (e.g. from combineSecret).
   * @param msg - Message to sign.
   * @param secretKey - Group secret key as bytes.
   * @returns Signature bytes.
   */
  sign(msg: TArg<Uint8Array>, secretKey: TArg<Uint8Array>): TRet<Uint8Array>;
  /**
   * Verifies a full signature against the group public key.
   * @param sig - Signature bytes.
   * @param msg - Message that was signed.
   * @param publicKey - Group public key.
   * @returns True if valid, false otherwise.
   */
  verify(sig: TArg<Signature>, msg: TArg<Uint8Array>, publicKey: TArg<Uint8Array>): boolean;
  /**
   * Combines multiple secret shares into a single secret key (e.g. for recovery).
   * @param shares - Set of FrostSecret shares.
   * @param signers - Threshold parameters.
   * @returns Group secret key as bytes.
   */
  combineSecret(shares: TArg<FrostSecret[]>, signers: Signers): TRet<Uint8Array>;
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
    randomScalar: (rng?: RNG) => TRet<Uint8Array>;
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
      secret?: TArg<Uint8Array>,
      coeffs?: bigint[],
      rng?: RNG
    ) => {
      coefficients: bigint[];
      commitment: TRet<Point[]>;
      secret: bigint;
    };
  };
};

// PubKey = commitments, verifyingShares
// PrivKey = id, signingShare, commitment

const validateSigners = (signers: Signers) => {
  if (!Number.isSafeInteger(signers.min) || !Number.isSafeInteger(signers.max))
    throw new Error('Wrong signers info: min=' + signers.min + ' max=' + signers.max);
  // Compatibility with frost-rs intentionally narrows RFC 9591's positive-nonzero threshold rule
  // to `min >= 2`, even though the RFC text itself allows `MIN_PARTICIPANTS = 1`.
  // This API is for actual threshold signing across participants; 1-of-n degenerates to ordinary
  // single-signer mode, which does not need FROST's network/coordination machinery at all.
  if (signers.min < 2 || signers.max < 2 || signers.min > signers.max)
    throw new Error('Wrong signers info: min=' + signers.min + ' max=' + signers.max);
};
const validateCommitmentsNum = (signers: Signers, len: number) => {
  // RFC 9591 Sections 5.2/5.3 require MIN_PARTICIPANTS <= NUM_PARTICIPANTS <= MAX_PARTICIPANTS.
  if (len < signers.min || len > signers.max) throw new Error('Wrong number of commitments=' + len);
};

class AggErr extends Error {
  // Empty means aggregation failed before per-share verification could attribute a signer.
  public cheaters: Identifier[];
  constructor(msg: string, cheaters: Identifier[]) {
    super(msg);
    this.cheaters = cheaters;
  }
}

export function createFROST<P extends FROSTPoint<P>>(opts: FrostOpts<P>): TRet<FROST> {
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
  // Cheap constructor-surface sanity check only: this verifies the generic static hooks/fields that
  // FROST consumes, but it does not certify point semantics like BASE/ZERO correctness.
  validatePointCons(opts.Point);
  const { Point } = opts;
  const Fn = opts.Fn === undefined ? Point.Fn : opts.Fn;
  // Hashes
  const hashBytes = opts.hash;
  const hashToScalar =
    opts.hashToScalar === undefined
      ? (msg: TArg<Uint8Array>, opts: TArg<H2CDSTOpts> = { DST: new Uint8Array() }) => {
          const t = hashBytes(concatBytes(opts.DST as Uint8Array, msg));
          return Fn.create(Fn.isLE ? bytesToNumberLE(t) : bytesToNumberBE(t));
        }
      : opts.hashToScalar;
  const H1Prefix = utf8ToBytes(opts.H1 !== undefined ? opts.H1 : opts.name + 'rho');
  const H2Prefix = utf8ToBytes(opts.H2 !== undefined ? opts.H2 : opts.name + 'chal');
  const H3Prefix = utf8ToBytes(opts.H3 !== undefined ? opts.H3 : opts.name + 'nonce');
  const H4Prefix = utf8ToBytes(opts.H4 !== undefined ? opts.H4 : opts.name + 'msg');
  const H5Prefix = utf8ToBytes(opts.H5 !== undefined ? opts.H5 : opts.name + 'com');
  const HDKGPrefix = utf8ToBytes(opts.HDKG !== undefined ? opts.HDKG : opts.name + 'dkg');
  const HIDPrefix = utf8ToBytes(opts.HID !== undefined ? opts.HID : opts.name + 'id');
  const H1 = (msg: TArg<Uint8Array>) => hashToScalar(msg, { DST: H1Prefix });
  // Empty H2 still passes `{ DST: new Uint8Array() }` into custom hashToScalar hooks.
  // The built-in fallback hashes that identically to omitted DST, which is how
  // the Ed25519 suite models RFC 9591's undecorated H2 challenge hash.
  const H2 = (msg: TArg<Uint8Array>) => hashToScalar(msg, { DST: H2Prefix });
  const H3 = (msg: TArg<Uint8Array>) => hashToScalar(msg, { DST: H3Prefix });
  const H4 = (msg: TArg<Uint8Array>) => hashBytes(concatBytes(H4Prefix, msg));
  const H5 = (msg: TArg<Uint8Array>) => hashBytes(concatBytes(H5Prefix, msg));
  const HDKG = (msg: TArg<Uint8Array>) => hashToScalar(msg, { DST: HDKGPrefix });
  const HID = (msg: TArg<Uint8Array>) => hashToScalar(msg, { DST: HIDPrefix });
  // /Hashes
  const randomScalar = (rng: RNG = randomBytes) => {
    // Intentional divergence from RFC 9591 §4.1 / §5.1: the RFC nonce_generate helper outputs a
    // Scalar in [0, p-1], but round-one commit publishes ScalarBaseMult(nonce) values and §3.1
    // requires SerializeElement / DeserializeElement to reject the identity element. Keep noble's
    // mapHashToField generation here so round-one public nonce commitments stay in 1..n-1.
    const t = mapHashToField(rng(getMinHashLength(Fn.ORDER)), Fn.ORDER, Fn.isLE);
    // We cannot use Fn.fromBytes here because the field can have a different
    // byte width, like ed448.
    return Fn.isLE ? bytesToNumberLE(t) : bytesToNumberBE(t);
  };
  const serializePoint = (p: P) => p.toBytes();
  const parsePoint = (bytes: TArg<Uint8Array>) => {
    // RFC 9591 Section 3.1 requires DeserializeElement validation. Suite-specific validatePoint
    // hooks tighten this further for ciphersuites in Section 6. Bare createFROST(...) only gets
    // canonical point decoding unless the caller installs those extra subgroup / identity checks.
    const p = Point.fromBytes(bytes);
    if (opts.validatePoint) opts.validatePoint(p);
    return p;
  };
  // RFC 9591 Sections 4.1/5.1 model each participant's round-one output as two public commitments.
  const nonceCommitments = (identifier: Identifier, nonces: TArg<Nonces>): TRet<NonceCommitments> =>
    ({
      identifier,
      hiding: serializePoint(Point.BASE.multiply(Fn.fromBytes(nonces.hiding))),
      binding: serializePoint(Point.BASE.multiply(Fn.fromBytes(nonces.binding))),
    }) as TRet<NonceCommitments>;
  const adjustPoint = opts.adjustPoint === undefined ? (n: P) => n : opts.adjustPoint;
  // We use hex to make it easier to use inside objects
  const validateIdentifier = (n: bigint) => {
    // Identifiers are canonical non-zero scalars. Custom / derived identifiers are allowed, so this
    // is intentionally not bounded by the current signers.max slot count.
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
    // RFC 9591 Appendix A encodes signatures canonically as
    // SerializeElement(R) || SerializeScalar(z).
    encode: (R: P, z: bigint): TRet<Signature> => {
      let res: Uint8Array = concatBytes(serializePoint(R), Fn.toBytes(z));
      if (opts.adjustTx) res = opts.adjustTx.encode(res);
      return res as TRet<Signature>;
    },
    decode: (sig: TArg<Uint8Array>) => {
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
  // No roots here: root-based methods will throw.
  // `poly` expects a structured roots-of-unity domain, but FROST uses an
  // arbitrary domain and only needs the non-root operations below.
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
      den = Fn.mul(den, Fn.sub(x, xi)); // RFC 9591 §4.2: denominator *= x_j - x_i
    }
    return Fn.div(num, den);
  };
  const evalutateVSS = (identifier: bigint, commitment: P[]) => {
    // RFC 9591 Appendix C.2: S_i' = Σ_j ScalarMult(vss_commitment[j], i^j).
    const monomial = Poly.monomial.basis(identifier, commitment.length);
    return msm(commitment, monomial);
  };
  // High-level internal stuff
  const generateSecretPolynomial = (
    signers: Signers,
    secret?: TArg<Uint8Array>,
    coeffs?: bigint[],
    rng: RNG = randomBytes
  ) => {
    validateSigners(signers);
    // Dealer/DKG polynomial sampling reuses the same hardened scalar derivation as round-one
    // nonces: overriding `rng` only swaps the entropy source, not the non-zero `1..n-1` policy.
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
    validate(id: bigint, commitment: TArg<Commitment[]>, proof: TArg<Uint8Array>) {
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
    challenge: (R: P, PK: P, msg: TArg<Uint8Array>) => {
      if (opts.challenge) return opts.challenge(R, PK, msg);
      return H2(concatBytes(serializePoint(R), serializePoint(PK), msg));
    },
    sign(msg: TArg<Uint8Array>, sk: bigint, rng: RNG = randomBytes): [P, bigint] {
      const { point: R, scalar: r } = genPointScalarPair(rng);
      const PK = Point.BASE.multiply(sk); // sk*G
      const c = this.challenge(R, PK, msg);
      const z = Fn.add(r, Fn.mul(c, sk)); // r + c * sk
      return [R, z];
    },
    verify(msg: TArg<Uint8Array>, R: P, z: bigint, PK: P): boolean {
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
    // RFC 9591 Appendix C.2 `vss_verify(share_i, vss_commitment)` is purely algebraic.
    // Public FROST packages still go through Section 3.1 element encoding,
    // which rejects identity points, so a zero share or commitment does not
    // become valid wire data just because VSS matches.
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
      // Derived identifiers may land anywhere in the scalar field; they are not restricted to
      // sequential `1..max_signers` values.
      return serializeIdentifier(HID(utf8ToBytes(s)));
    },
  };
  // RFC 9591 §4.1: nonce_generate() hashes 32 fresh RNG bytes with SerializeScalar(secret).
  const generateNonce = (secret: bigint, rng: RNG = randomBytes) =>
    H3(concatBytes(rng(32), Fn.toBytes(secret)));

  const getGroupCommitment = (
    GPK: P,
    commitmentList: TArg<NonceCommitments[]>,
    msg: TArg<Uint8Array>
  ) => {
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
    PK: TArg<Uint8Array>,
    commitmentList: TArg<NonceCommitments[]>,
    msg: TArg<Uint8Array>,
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
  Object.freeze(Identifier);
  const frost = {
    Identifier,
    // DKG is Distributed Key Generation, not Trusted Dealer Key Generation.
    DKG: Object.freeze({
      // NOTE: we allow to pass secret scalar from user side,
      // this way it can be derived, instead of random generation
      round1: (
        id: Identifier,
        signers: Signers,
        secret?: TArg<SecretKey>,
        rng: RNG = randomBytes
      ) => {
        validateSigners(signers);
        const idNum = parseIdentifier(id);
        const { coefficients, commitment } = generateSecretPolynomial(
          signers,
          secret,
          undefined,
          rng
        );
        const proofOfKnowledge = ProofOfKnowledge.compute(idNum, coefficients, commitment, rng);
        const commitmentBytes = commitment.map(serializePoint) as TRet<Commitment[]>;
        const round1Public: DKG_Round1 = {
          identifier: serializeIdentifier(idNum),
          commitment: commitmentBytes,
          proofOfKnowledge,
        };
        // store secret information for signing
        const round1Secret: DKG_Secret = {
          identifier: idNum,
          coefficients,
          commitment: commitment.map(serializePoint) as TRet<Point[]>,
          // Copy threshold metadata instead of retaining the caller-owned object by reference.
          signers: { min: signers.min, max: signers.max },
          step: 1,
        };
        return { public: round1Public, secret: round1Secret };
      },
      round2: (
        secret: TArg<DKG_Secret>,
        others: TArg<DKG_Round1[]>
      ): TRet<Record<string, DKG_Round2>> => {
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
            signingShare: signingShare as TRet<Bytes>,
          };
        }
        secret.step = 2;
        return res as TRet<Record<string, DKG_Round2>>;
      },
      round3: (
        secret: TArg<DKG_Secret>,
        round1: TArg<DKG_Round1[]>,
        round2: TArg<DKG_Round2[]>
      ): TRet<Key> => {
        // DKG is outside RFC 9591's signing flow; callers are expected to reuse the same
        // remote round1 packages already accepted in round2, like frost-rs documents.
        if (round1.length !== secret.signers.max - 1)
          throw new Error('wrong length of round1 packages');
        if (!secret.coefficients || secret.step !== 2)
          throw new Error('round2 package used in round3');
        if (round2.length !== round1.length) throw new Error('wrong length of round2 packages');
        const merged: Record<Identifier, TArg<DKG_Round1> & { signingShare?: TArg<Bytes> }> = {};
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
        const commitments: Record<Identifier, TArg<Commitment[]>> = {
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
        const mergedCommitmentBytes = mergedCommitment.map(serializePoint) as TRet<Commitment[]>;
        const verifyingShares: Record<Identifier, Uint8Array> = {};
        for (const k in commitments)
          verifyingShares[k] = serializePoint(evalutateVSS(parseIdentifier(k), mergedCommitment));
        // This is enough to sign stuff
        let res: TRet<Key> = {
          public: {
            signers: { min: secret.signers.min, max: secret.signers.max },
            commitments: mergedCommitmentBytes,
            verifyingShares: Object.fromEntries(
              Object.entries(verifyingShares).map(([k, v]) => [k, v.slice()])
            ),
          },
          secret: {
            identifier: serializeIdentifier(secret.identifier),
            signingShare: Fn.toBytes(signingShare) as TRet<Bytes>,
          },
        };
        if (opts.adjustDKG) res = opts.adjustDKG(res);
        for (let i = 0; i < secret.coefficients.length; i++)
          secret.coefficients[i] -= secret.coefficients[i];
        delete secret.coefficients;
        secret.step = 3;
        return res;
      },
      clean(secret: TArg<DKG_Secret>) {
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
    }),
    // Trusted dealer setup
    // Generates keys for all participants
    trustedDealer(
      signers: Signers,
      identifiers?: Identifier[],
      secret?: TArg<SecretKey>,
      rng: RNG = randomBytes
    ): TRet<DealerShares> {
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
          signingShare: Fn.toBytes(signingShare) as TRet<Bytes>,
        };
      }
      return {
        public: {
          signers: { min: signers.min, max: signers.max },
          commitments: commitmentBytes,
          verifyingShares,
        },
        secretShares,
      } as TRet<DealerShares>;
    },
    // Validate secret (from trusted dealer or DKG)
    validateSecret(secret: TArg<FrostSecret>, pub: TArg<FrostPublic>) {
      const id = parseIdentifier(secret.identifier);
      const commitment = pub.commitments.map(parsePoint);
      const signingShare = Fn.fromBytes(secret.signingShare);
      validateSecretShare(id, commitment, signingShare);
    },
    // Actual signing
    // Round 1: each participant commit to nonces
    // Nonces kept private, commitments sent to coordinator (or every other participant)
    // NOTE: we don't need the message at this point, which lets a coordinator
    // keep multiple nonce commitments per participant in advance and skip
    // round1 for signing.
    // But then each participant needs to remember generated shares
    commit(secret: TArg<FrostSecret>, rng: RNG = randomBytes): TRet<GenNonce> {
      const secretScalar = Fn.fromBytes(secret.signingShare);
      const hiding = generateNonce(secretScalar, rng);
      const binding = generateNonce(secretScalar, rng);
      const nonces = { hiding: Fn.toBytes(hiding), binding: Fn.toBytes(binding) };
      return { nonces, commitments: nonceCommitments(secret.identifier, nonces) } as TRet<GenNonce>;
    },
    // Round2: sign. Each participant creates a signature share from the secret
    // and the selected nonce commitments.
    signShare(
      secret: TArg<FrostSecret>,
      pub: TArg<FrostPublic>,
      nonces: TArg<Nonces>,
      commitmentList: TArg<NonceCommitments[]>,
      msg: TArg<Uint8Array>
    ): TRet<Uint8Array> {
      validateCommitmentsNum(pub.signers, commitmentList.length);
      const hidingNonce0 = Fn.fromBytes(nonces.hiding);
      const bindingNonce0 = Fn.fromBytes(nonces.binding);
      if (Fn.is0(hidingNonce0) || Fn.is0(bindingNonce0))
        throw new Error('signing nonces already used');
      // Reject a coordinator-assigned commitment pair that does not match the signer's own nonce
      // pair. This must happen before suite-specific nonce adjustment; secp256k1-tr may negate the
      // actual signing nonces later, but the coordinator still assigns the original commitments.
      const expectedCommitment = {
        identifier: secret.identifier,
        hiding: serializePoint(Point.BASE.multiply(hidingNonce0)),
        binding: serializePoint(Point.BASE.multiply(bindingNonce0)),
      };
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
      const hidingNonce = opts.adjustNonces ? Fn.fromBytes(N.hiding) : hidingNonce0;
      const bindingNonce = opts.adjustNonces ? Fn.fromBytes(N.binding) : bindingNonce0;
      const t = Fn.mul(Fn.mul(lambda, SK), challenge); // challenge * lambda * SK
      const t2 = Fn.mul(bindingNonce, bindingFactor); // bindingNonce * bindingFactor
      const r = Fn.toBytes(Fn.add(Fn.add(hidingNonce, t2), t)); // t + t2 + hidingNonce
      // RFC 9591 round-one commitments are one-time-use, and round two must use the nonce
      // corresponding to the published commitment. This API returns mutable local nonce bytes,
      // so consume them after a successful signShare() call: later all-zero reuse fails closed.
      nonces.hiding.fill(0);
      nonces.binding.fill(0);
      return r as TRet<Uint8Array>;
    },
    // Each participant (or coordinator) can verify signatures from other participants
    verifyShare(
      pub: TArg<FrostPublic>,
      commitmentList: TArg<NonceCommitments[]>,
      msg: TArg<Uint8Array>,
      identifier: Identifier,
      sigShare: TArg<Uint8Array>
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
      // hC + bC * bF
      let commShare = hidingNonceCommitment.add(bindingNonceCommitment.multiply(bindingFactor));
      if (opts.adjustGroupCommitmentShare)
        commShare = opts.adjustGroupCommitmentShare(groupCommitment, commShare);
      const l = Point.BASE.multiply(Fn.fromBytes(sigShare)); // sigShare*G
      // commShare + PK * (challenge * lambda)
      const r = commShare.add(PK.multiply(Fn.mul(challenge, lambda)));
      return l.equals(r);
    },
    // Aggregate multiple signature shares into groupSignature
    aggregate(
      pub: TArg<FrostPublic>,
      commitmentList: TArg<NonceCommitments[]>,
      msg: TArg<Uint8Array>,
      sigShares: TArg<Record<Identifier, Uint8Array>>
    ): TRet<Uint8Array> {
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
    sign(msg: TArg<Uint8Array>, secretKey: TArg<Uint8Array>): TRet<Uint8Array> {
      let sk = Fn.fromBytes(secretKey);
      // Taproot single-key signing needs the same scalar normalization as threshold keys.
      if (opts.adjustScalar) sk = opts.adjustScalar(sk);
      const [R, z] = Basic.sign(msg, sk);
      return Signature.encode(R, z);
    },
    verify(sig: TArg<Signature>, msg: TArg<Uint8Array>, publicKey: TArg<Uint8Array>) {
      const PK = opts.parsePublicKey ? opts.parsePublicKey(publicKey) : parsePoint(publicKey);
      const { R, z } = Signature.decode(sig);
      return Basic.verify(msg, R, z, PK);
    },
    // Combine multiple secret shares to restore secret
    combineSecret(shares: TArg<FrostSecret[]>, signers: Signers): TRet<Uint8Array> {
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
      return Fn.toBytes(res) as TRet<Uint8Array>;
    },
    // Utils
    utils: Object.freeze({
      Fn, // NOTE: we re-export it here because it may be different from Point.Fn (ed448 is fun!)
      // Test RNG overrides still go through noble's non-zero scalar derivation; this is not a raw
      // "bytes become scalar" escape hatch.
      randomScalar: (rng: RNG = randomBytes) =>
        Fn.toBytes(genPointScalarPair(rng).scalar) as TRet<Uint8Array>,
      generateSecretPolynomial: (
        signers: Signers,
        secret?: TArg<Uint8Array>,
        coeffs?: bigint[],
        rng?: RNG
      ) => {
        const res = generateSecretPolynomial(signers, secret, coeffs, rng);
        return { ...res, commitment: res.commitment.map(serializePoint) as TRet<Point[]> };
      },
    }),
  };
  return Object.freeze(frost) as TRet<FROST>;
}
