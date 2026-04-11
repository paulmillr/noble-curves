/**
 * bls12-381 is pairing-friendly Barreto-Lynn-Scott elliptic curve construction allowing to:

* Construct zk-SNARKs at the ~120-bit security, as per [Barbulescu-Duquesne 2017](https://hal.science/hal-01534101/file/main.pdf)
* Efficiently verify N aggregate signatures with 1 pairing and N ec additions:
the Boneh-Lynn-Shacham signature scheme is orders of magnitude more efficient than Schnorr

BLS can mean 2 different things:

* Barreto-Lynn-Scott: BLS12, a Pairing Friendly Elliptic Curve
* Boneh-Lynn-Shacham: A Signature Scheme.

### Summary

1. BLS Relies on expensive bilinear pairing
2. Secret Keys: 32 bytes
3. Public Keys: 48 OR 96 bytes - big-endian x coordinate of point on G1 OR G2 curve
4. Signatures: 96 OR 48 bytes - big-endian x coordinate of point on G2 OR G1 curve
5. The 12 stands for the Embedding degree.

Modes of operation:

* Long signatures:  48-byte keys + 96-byte sigs (G1 keys + G2 sigs).
* Short signatures: 96-byte keys + 48-byte sigs (G2 keys + G1 sigs).

### Formulas

- `P = pk x G` - public keys
- `S = pk x H(m)` - signing, uses hash-to-curve on m
- `e(P, H(m)) == e(G, S)` - verification using pairings
- `e(G, S) = e(G, SUM(n)(Si)) = MUL(n)(e(G, Si))` - signature aggregation

### Curves

G1 is ordinary elliptic curve. G2 is extension field curve, think "over complex numbers".

- G1: y² = x³ + 4
- G2: y² = x³ + 4(u + 1) where u = √−1; r-order subgroup of E'(Fp²), M-type twist

### Towers

Pairing G1 + G2 produces element in Fp₁₂, 12-degree polynomial.
Fp₁₂ is usually implemented using tower of lower-degree polynomials for speed.

- Fp₁₂ = Fp₆² => Fp₂³
- Fp(u) / (u² - β) where β = -1
- Fp₂(v) / (v³ - ξ) where ξ = u + 1
- Fp₆(w) / (w² - γ) where γ = v
- Fp²[u] = Fp/u²+1
- Fp⁶[v] = Fp²/v³-1-u
- Fp¹²[w] = Fp⁶/w²-v

### Params

* Embedding degree (k): 12
* Seed is sometimes named x or t
* t = -15132376222941642752
* p = (t-1)² * (t⁴-t²+1)/3 + t
* r = t⁴-t²+1
* Ate loop size: X

To verify curve parameters, see
[pairing-friendly-curves spec](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11).
Basic math is done over finite fields over p.
More complicated math is done over polynominal extension fields.

### Compatibility and notes
1. It is compatible with Algorand, Chia, Dfinity, Ethereum, Filecoin, ZEC.
Filecoin uses little endian byte arrays for secret keys - make sure to reverse byte order.
2. Make sure to correctly select mode: "long signature" or "short signature".
3. Compatible with specs:
   RFC 9380,
   [cfrg-pairing-friendly-curves-11](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11),
   [cfrg-bls-signature-05](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

 *
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha2.js';
import { bls, type BlsCurvePairWithSignatures } from './abstract/bls.ts';
import { Field, type IField } from './abstract/modular.ts';
import {
  abytes,
  bitLen,
  bitMask,
  bytesToHex,
  bytesToNumberBE,
  concatBytes,
  copyBytes,
  hexToBytes,
  numberToBytesBE,
  randomBytes,
  type TArg,
  type TRet,
} from './utils.ts';
// Types
import { isogenyMap } from './abstract/hash-to-curve.ts';
import type { BigintTuple, Fp, Fp12, Fp2, Fp6 } from './abstract/tower.ts';
import { psiFrobenius, tower12 } from './abstract/tower.ts';
import {
  mapToCurveSimpleSWU,
  weierstrass,
  type AffinePoint,
  type WeierstrassOpts,
  type WeierstrassPoint,
  type WeierstrassPointCons,
} from './abstract/weierstrass.ts';

// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3), _4n = BigInt(4);

// To verify math:
// https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-11

// The BLS parameter x (seed) for BLS12-381. The stored constant is `|x|`; call
// sites that need the signed parameter apply the minus sign themselves.
// x = -2^63 - 2^62 - 2^60 - 2^57 - 2^48 - 2^16
const BLS_X = BigInt('0xd201000000010000');
// t = x (called differently in different places)
// const t = -BLS_X;
const BLS_X_LEN = bitLen(BLS_X);

// a=0, b=4
// P is characteristic of field Fp, in which curve calculations are done.
// p = (t-1)² * (t⁴-t²+1)/3 + t
// bls12_381_Fp = (t-1n)**2n * (t**4n - t**2n + 1n) / 3n + t
// r*h is curve order, amount of points on curve,
// where r is order of prime subgroup and h is cofactor.
// r = t⁴-t²+1
// r = (t**4n - t**2n + 1n)
// cofactor h of G1: (t - 1)²/3, with the signed convention `t = -x`
// cofactorG1 = (t-1n)**2n/3n
// x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
// y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
const bls12_381_CURVE_G1: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab'
  ),
  n: BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'),
  h: BigInt('0x396c8c005555e1568c00aaab0000aaab'),
  a: _0n,
  b: _4n,
  Gx: BigInt(
    '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
  ),
  Gy: BigInt(
    '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
  ),
};

// CURVE FIELDS
// r = z⁴ − z² + 1; CURVE.n from other curves
/**
 * bls12-381 Fr (Fn) field.
 * `fromBytes()` reduces modulo `q` instead of rejecting non-canonical encodings.
 */
export const bls12_381_Fr: TRet<IField<bigint>> = Field(bls12_381_CURVE_G1.n, {
  modFromBytes: true,
}) as TRet<IField<bigint>>;
const { Fp, Fp2, Fp6, Fp12 } = tower12({
  ORDER: bls12_381_CURVE_G1.p,
  X_LEN: BLS_X_LEN,
  // Finite extension field over irreducible polynominal.
  // Fp(u) / (u² - β) where β = -1
  // Public `Fp2.NONRESIDUE` below is the sextic-tower value `(1, 1) = u + 1`;
  // the quadratic non-residue for the base Fp2 construction is still `-1`.
  FP2_NONRESIDUE: [_1n, _1n],
  Fp2mulByB: ({ c0, c1 }: Fp2) => {
    const t0 = Fp.mul(c0, _4n); // 4 * c0
    const t1 = Fp.mul(c1, _4n); // 4 * c1
    // (T0-T1) + (T0+T1)*i
    return { c0: Fp.sub(t0, t1), c1: Fp.add(t0, t1) };
  },
  Fp12finalExponentiate: (num: Fp12) => {
    const x = BLS_X;
    // this^(q⁶) / this
    const t0 = Fp12.div(Fp12.frobeniusMap(num, 6), num);
    // t0^(q²) * t0
    const t1 = Fp12.mul(Fp12.frobeniusMap(t0, 2), t0);
    const t2 = Fp12.conjugate(Fp12._cyclotomicExp(t1, x));
    const t3 = Fp12.mul(Fp12.conjugate(Fp12._cyclotomicSquare(t1)), t2);
    const t4 = Fp12.conjugate(Fp12._cyclotomicExp(t3, x));
    const t5 = Fp12.conjugate(Fp12._cyclotomicExp(t4, x));
    const t6 = Fp12.mul(Fp12.conjugate(Fp12._cyclotomicExp(t5, x)), Fp12._cyclotomicSquare(t2));
    const t7 = Fp12.conjugate(Fp12._cyclotomicExp(t6, x));
    const t2_t5_pow_q2 = Fp12.frobeniusMap(Fp12.mul(t2, t5), 2);
    const t4_t1_pow_q3 = Fp12.frobeniusMap(Fp12.mul(t4, t1), 3);
    const t6_t1c_pow_q1 = Fp12.frobeniusMap(Fp12.mul(t6, Fp12.conjugate(t1)), 1);
    const t7_t3c_t1 = Fp12.mul(Fp12.mul(t7, Fp12.conjugate(t3)), t1);
    // (t2 * t5)^(q²) * (t4 * t1)^(q³) * (t6 * t1.conj)^(q^1) * t7 * t3.conj * t1
    return Fp12.mul(Fp12.mul(Fp12.mul(t2_t5_pow_q2, t4_t1_pow_q3), t6_t1c_pow_q1), t7_t3c_t1);
  },
});

// GLV endomorphism Ψ(P), for fast cofactor clearing. `Fp2.NONRESIDUE` here is
// the tower value `u + 1`, so the Frobenius base passed to psiFrobenius is
// `1 / (u + 1)`, and psi2 derives the published `1 / 2^((p - 1) / 3)` constant internally.
let frob: ReturnType<typeof psiFrobenius> | undefined;
const getFrob = () => frob || (frob = psiFrobenius(Fp, Fp2, Fp2.div(Fp2.ONE, Fp2.NONRESIDUE)));
// Eager psiFrobenius setup now dominates `bls12-381.js` import, so defer it to
// first use. After that these locals are rewritten to the direct helper refs.
let G2psi: ReturnType<typeof psiFrobenius>['G2psi'] = (c, P) => {
  const fn = getFrob().G2psi;
  G2psi = fn;
  return fn(c, P);
};
let G2psi2: ReturnType<typeof psiFrobenius>['G2psi2'] = (c, P) => {
  const fn = getFrob().G2psi2;
  G2psi2 = fn;
  return fn(c, P);
};

/**
 * Default hash_to_field / hash-to-curve for BLS.
 * m: 1 for G1, 2 for G2
 * k: target security level in bits
 * hash: any function, e.g. BBS+ uses BLAKE2: see [github](https://github.com/hyperledger/aries-framework-go/issues/2247).
 * Field/hash parameters come from [section 8.8.2 of RFC 9380](https://www.rfc-editor.org/rfc/rfc9380#section-8.8.2),
 * but the `DST` / `encodeDST` strings below are the BLS-signature-suite override.
 */
const hasher_opts = Object.freeze({
  DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_',
  encodeDST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_',
  p: Fp.ORDER,
  m: 2,
  k: 128,
  expand: 'xmd',
  hash: sha256,
});

// a=0, b=4
// cofactor h of G2, derived with the signed convention `t = -x`
// (t^8 - 4t^7 + 5t^6 - 4t^4 + 6t^3 - 4t^2 - 4t + 13)/9
// cofactorG2 = (t**8n - 4n*t**7n + 5n*t**6n - 4n*t**4n + 6n*t**3n - 4n*t**2n - 4n*t+13n)/9n
// x = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758*u + 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
// y = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582*u + 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
const bls12_381_CURVE_G2 = {
  p: Fp2.ORDER,
  n: bls12_381_CURVE_G1.n,
  h: BigInt(
    '0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5'
  ),
  a: Fp2.ZERO,
  b: Fp2.fromBigTuple([_4n, _4n]),
  Gx: Fp2.fromBigTuple([
    BigInt(
      '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
    ),
    BigInt(
      '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
    ),
  ]),
  Gy: Fp2.fromBigTuple([
    BigInt(
      '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    ),
    BigInt(
      '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
    ),
  ]),
};

// Encoding utils
const sortBit = (parts: bigint[], p: bigint) => {
  for (const part of parts) {
    if (part !== _0n) return Boolean((part * _2n) / p);
  }
  return false;
};
const fp2 = {
  // Generic tower bytes use `c0 || c1`, but the BLS12-381 G2 point/signature wire encoding uses
  // `c1 || c0`, so keep this local wrapper instead of changing generic field serialization.
  encode({ c0, c1 }: Fp2): TRet<Uint8Array> {
    const { BYTES: L } = Fp;
    return concatBytes(numberToBytesBE(c1, L), numberToBytesBE(c0, L)) as TRet<Uint8Array>;
  },
  decode(bytes: TArg<Uint8Array>) {
    const { BYTES: L } = Fp;
    return Fp2.create({
      c0: Fp.create(bytesToNumberBE(bytes.subarray(L))),
      c1: Fp.create(bytesToNumberBE(bytes.subarray(0, L))),
    });
  },
};
const BaseFp = Fp;
type Mask = { compressed: boolean; infinity: boolean; sort: boolean };
// Keep BLS12-381 point/signature codecs on one control-flow skeleton: the G1/G2
// and point/signature variants differ only in field packing, subgroup bytes, and
// whether uncompressed form is allowed. Copy-paste decoders were diverging.
const coder = <T>(
  name: 'G1' | 'G2',
  Fp: TArg<IField<T>>,
  b: T,
  encode: TArg<(v: T) => TRet<Uint8Array>>,
  decode: TArg<(bytes: TArg<Uint8Array>) => T>,
  yparts: (y: T) => bigint[]
) => {
  const F = Fp as IField<T>;
  const enc = encode as (v: T) => TRet<Uint8Array>;
  const dec = decode as (bytes: TArg<Uint8Array>) => T;
  const W = F.BYTES;
  return (allowUncompressed: boolean) => ({
    encode(point: WeierstrassPoint<T>, compressed = true): TRet<Uint8Array> {
      if (!compressed && !allowUncompressed)
        throw new Error('invalid signature: expected compressed encoding');
      const infinity = point.is0();
      const { x, y } = point.toAffine();
      const bytes = compressed ? enc(x) : concatBytes(enc(x), enc(y));
      let sort;
      if (compressed && !infinity) sort = sortBit(yparts(y), BaseFp.ORDER);
      return setMask(bytes, { compressed, infinity, sort }) as TRet<Uint8Array>;
    },
    decode(bytes: TArg<Uint8Array>): AffinePoint<T> {
      const raw = allowUncompressed
        ? abytes(bytes, undefined, 'point')
        : abytes(bytes, W, 'signature');
      const { compressed, infinity, sort, value } = parseMask(raw);
      if (!allowUncompressed && !compressed)
        throw new Error('invalid signature: expected compressed encoding');
      const len = compressed ? W : 2 * W;
      if (value.length !== len) throw new Error(`invalid ${name} point: expected ${len} bytes`);
      if (infinity) {
        // Infinity canonicality has to be checked on raw bytes before decode()
        // reduces coordinates modulo p and turns non-empty payloads into zero.
        for (const b of value) {
          if (b) throw new Error(`invalid ${name} point: non-canonical zero`);
        }
        return { x: F.ZERO, y: F.ZERO };
      }
      const x = dec(compressed ? value : value.subarray(0, W));
      let y;
      if (compressed) {
        y = F.sqrt(F.add(F.pow(x, _3n), b));
        if (!y) throw new Error(`invalid ${name} point: compressed`);
        if (sortBit(yparts(y), BaseFp.ORDER) !== sort) y = F.neg(y);
      } else {
        y = dec(value.subarray(W));
      }
      // Noble keeps the permissive coordinate reduction path here, but an
      // omitted infinity flag must not still decode to ZERO afterwards.
      if (!compressed && F.is0(x) && F.is0(y))
        throw new Error(`invalid ${name} point: uncompressed`);
      return { x, y };
    },
  });
};

// Internal helper only: it copies before clearing the top flag bits. The
// pairing-friendly-curves draft C.2 step 1 rejects 0x20 / 0x60 / 0xe0 because
// S_bit must be zero for infinity and for all uncompressed encodings.
function validateMask({ compressed, infinity, sort }: Mask) {
  if (
    (!compressed && !infinity && sort) || // 0010_0000 = 0x20
    (!compressed && infinity && sort) || // 0110_0000 = 0x60
    (compressed && infinity && sort) // 1110_0000 = 0xe0
  )
    throw new Error('invalid encoding flag');
}
function parseMask(bytes: TArg<Uint8Array>) {
  // Copy, so we can remove mask data.
  // It will be removed also later, when Fp.create will call modulo.
  bytes = copyBytes(bytes);
  const mask = bytes[0] & 0b1110_0000;
  const compressed = !!((mask >> 7) & 1); // compression bit (0b1000_0000)
  const infinity = !!((mask >> 6) & 1); // point at infinity bit (0b0100_0000)
  const sort = !!((mask >> 5) & 1); // sort bit (0b0010_0000)
  validateMask({ compressed, infinity, sort });
  bytes[0] &= 0b0001_1111; // clear mask (zero first 3 bits)
  return { compressed, infinity, sort, value: bytes };
}

// Internal helper only: mutates a non-empty fresh buffer in place and just
// sets bits. Keep the same invalid-flag guard as parseMask() so encoders cannot
// manufacture states that decoders already reject.
function setMask(bytes: TArg<Uint8Array>, mask: Partial<Mask>) {
  if (bytes[0] & 0b1110_0000) throw new Error('setMask: non-empty mask');
  validateMask({ compressed: !!mask.compressed, infinity: !!mask.infinity, sort: !!mask.sort });
  if (mask.compressed) bytes[0] |= 0b1000_0000;
  if (mask.infinity) bytes[0] |= 0b0100_0000;
  if (mask.sort) bytes[0] |= 0b0010_0000;
  return bytes;
}

const g1coder = coder(
  'G1',
  Fp,
  Fp.create(bls12_381_CURVE_G1.b),
  (x: Fp) => numberToBytesBE(x, Fp.BYTES),
  (bytes: TArg<Uint8Array>) => Fp.create(bytesToNumberBE(bytes) & bitMask(Fp.BITS)),
  (y: Fp) => [y]
);
const g1 = { point: g1coder(true), sig: g1coder(false) };
const signatureG1ToBytes = (point: WeierstrassPoint<Fp>): TRet<Uint8Array> => {
  point.assertValidity();
  return g1.sig.encode(point);
};
function signatureG1FromBytes(bytes: TArg<Uint8Array>): WeierstrassPoint<Fp> {
  const Point = bls12_381.G1.Point;
  const point = Point.fromAffine(g1.sig.decode(bytes));
  point.assertValidity();
  return point;
}

const g2coder = coder('G2', Fp2, bls12_381_CURVE_G2.b, fp2.encode, fp2.decode, (y: Fp2) => [
  y.c1,
  y.c0,
]);
const g2 = { point: g2coder(true), sig: g2coder(false) };
const signatureG2ToBytes = (point: WeierstrassPoint<Fp2>): TRet<Uint8Array> => {
  point.assertValidity();
  return g2.sig.encode(point);
};
function signatureG2FromBytes(bytes: TArg<Uint8Array>) {
  const Point = bls12_381.G2.Point;
  const point = Point.fromAffine(g2.sig.decode(bytes));
  point.assertValidity();
  return point;
}

const signatureCoders = {
  ShortSignature: {
    fromBytes(bytes: TArg<Uint8Array>) {
      return signatureG1FromBytes(abytes(bytes));
    },
    fromHex(hex: string): WeierstrassPoint<Fp> {
      return signatureG1FromBytes(hexToBytes(hex));
    },
    toBytes(point: WeierstrassPoint<Fp>) {
      return signatureG1ToBytes(point);
    },
    // Historical alias: BLS signatures have a single compressed byte format here.
    toRawBytes(point: WeierstrassPoint<Fp>) {
      return signatureG1ToBytes(point);
    },
    toHex(point: WeierstrassPoint<Fp>) {
      return bytesToHex(signatureG1ToBytes(point));
    },
  },
  LongSignature: {
    fromBytes(bytes: TArg<Uint8Array>): WeierstrassPoint<Fp2> {
      return signatureG2FromBytes(abytes(bytes));
    },
    fromHex(hex: string): WeierstrassPoint<Fp2> {
      return signatureG2FromBytes(hexToBytes(hex));
    },
    toBytes(point: WeierstrassPoint<Fp2>) {
      return signatureG2ToBytes(point);
    },
    // Historical alias: BLS signatures have a single compressed byte format here.
    toRawBytes(point: WeierstrassPoint<Fp2>) {
      return signatureG2ToBytes(point);
    },
    toHex(point: WeierstrassPoint<Fp2>) {
      return bytesToHex(signatureG2ToBytes(point));
    },
  },
};

const fields = {
  Fp,
  Fp2,
  Fp6,
  Fp12,
  Fr: bls12_381_Fr,
};
const G1_Point = weierstrass(bls12_381_CURVE_G1, {
  // Public point APIs still accept infinity, even though the Zcash proof
  // encoding rules cited above only define nonzero point encodings.
  allowInfinityPoint: true,
  Fn: bls12_381_Fr,
  fromBytes: g1.point.decode,
  toBytes: (
    _c: WeierstrassPointCons<Fp>,
    point: WeierstrassPoint<Fp>,
    isComp: boolean
  ): TRet<Uint8Array> => g1.point.encode(point, isComp) as TRet<Uint8Array>,
  // Checks is the point resides in prime-order subgroup.
  // point.isTorsionFree() should return true for valid points
  // It returns false for shitty points.
  // https://eprint.iacr.org/2021/1130.pdf
  isTorsionFree: (c, point): boolean => {
    // GLV endomorphism ψ(P)
    const beta = BigInt(
      '0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe'
    );
    const phi = new c(Fp.mul(point.X, beta), point.Y, point.Z);
    // TODO: unroll
    const xP = point.multiplyUnsafe(BLS_X).negate(); // [x]P
    const u2P = xP.multiplyUnsafe(BLS_X); // [u2]P
    return u2P.equals(phi);
  },
  // Clear cofactor of G1
  // https://eprint.iacr.org/2019/403
  clearCofactor: (_c, point) => {
    // return this.multiplyUnsafe(CURVE.h);
    return point.multiplyUnsafe(BLS_X).add(point); // x*P + P
  },
});
const G2_Point = weierstrass(bls12_381_CURVE_G2, {
  Fp: Fp2,
  // Public point APIs still accept infinity, even though the Zcash proof
  // encoding rules cited above only define nonzero point encodings.
  allowInfinityPoint: true,
  Fn: bls12_381_Fr,
  fromBytes: g2.point.decode,
  toBytes: (
    _c: WeierstrassPointCons<Fp2>,
    point: WeierstrassPoint<Fp2>,
    isComp: boolean
  ): TRet<Uint8Array> => g2.point.encode(point, isComp) as TRet<Uint8Array>,
  // https://eprint.iacr.org/2021/1130.pdf
  // Older version: https://eprint.iacr.org/2019/814.pdf
  isTorsionFree: (c, P): boolean => {
    return P.multiplyUnsafe(BLS_X).negate().equals(G2psi(c, P)); // ψ(P) == [u](P)
  },
  // clear_cofactor_bls12381_g2 from RFC 9380.
  // https://eprint.iacr.org/2017/419.pdf
  // prettier-ignore
  clearCofactor: (c, P) => {
    const x = BLS_X;
    let t1 = P.multiplyUnsafe(x).negate();  // [-x]P
    let t2 = G2psi(c, P);                   // Ψ(P)
    let t3 = P.double();                    // 2P
    t3 = G2psi2(c, t3);                     // Ψ²(2P)
    t3 = t3.subtract(t2);                   // Ψ²(2P) - Ψ(P)
    t2 = t1.add(t2);                        // [-x]P + Ψ(P)
    t2 = t2.multiplyUnsafe(x).negate();     // [x²]P - [x]Ψ(P)
    t3 = t3.add(t2);                        // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P)
    t3 = t3.subtract(t1);                   // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P) + [x]P
    const Q = t3.subtract(P);               // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P) + [x]P - 1P
    return Q;                               // [x²-x-1]P + [x-1]Ψ(P) + Ψ²(2P)
  },
});

const bls12_hasher_opts = {
  mapToG1: mapToG1,
  mapToG2: mapToG2,
  hasherOpts: hasher_opts,
  // RFC 9380 Appendix J defines distinct G1/G2 RO and NU suite IDs, and
  // draft-irtf-cfrg-bls-signature-06 §4.2.1 gives separate G1/G2 `_NUL_` DSTs.
  // Keep G1 encode-to-curve on the G1 domain instead of inheriting G2's `encodeDST`.
  hasherOptsG1: {
    ...hasher_opts,
    m: 1,
    DST: 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_',
    encodeDST: 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_',
  },
  hasherOptsG2: { ...hasher_opts },
} as const;

const bls12_params = {
  ateLoopSize: BLS_X, // The BLS parameter x for BLS12-381
  xNegative: true,
  twistType: 'multiplicative' as const,
  randomBytes: randomBytes,
};

/**
 * bls12-381 pairing-friendly curve construction.
 * Provides both longSignatures and shortSignatures.
 * @example
 * bls12-381 pairing-friendly curve construction.
 *
 * ```ts
 * const bls = bls12_381.longSignatures;
 * const { secretKey, publicKey } = bls.keygen();
 * const msg = bls.hash(new TextEncoder().encode('hello noble'));
 * const sig = bls.sign(msg, secretKey);
 * const isValid = bls.verify(sig, msg, publicKey);
 * ```
 */
export const bls12_381: BlsCurvePairWithSignatures = bls(
  fields,
  G1_Point,
  G2_Point,
  bls12_params,
  bls12_hasher_opts,
  signatureCoders
);

// 3-isogeny map from E' to E https://www.rfc-editor.org/rfc/rfc9380#appendix-E.3
// Coefficients stay in ascending `k_(?,0)`..`k_(?,d)` order; isogenyMap()
// reverses them internally for Horner evaluation.
const isogenyMapG2 = isogenyMap(
  Fp2,
  [
    // xNum
    [
      [
        '0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6',
        '0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6',
      ],
      [
        '0x0',
        '0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a',
      ],
      [
        '0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e',
        '0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d',
      ],
      [
        '0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1',
        '0x0',
      ],
    ],
    // xDen
    [
      [
        '0x0',
        '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63',
      ],
      [
        '0xc',
        '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f',
      ],
      ['0x1', '0x0'], // LAST 1
    ],
    // yNum
    [
      [
        '0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706',
        '0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706',
      ],
      [
        '0x0',
        '0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be',
      ],
      [
        '0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c',
        '0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f',
      ],
      [
        '0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10',
        '0x0',
      ],
    ],
    // yDen
    [
      [
        '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb',
        '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb',
      ],
      [
        '0x0',
        '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3',
      ],
      [
        '0x12',
        '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99',
      ],
      ['0x1', '0x0'], // LAST 1
    ],
  ].map((i) => i.map((pair) => Fp2.fromBigTuple(pair.map(BigInt) as BigintTuple))) as [
    Fp2[],
    Fp2[],
    Fp2[],
    Fp2[],
  ]
);
// 11-isogeny map from E' to E. Coefficients stay in ascending
// `k_(?,0)`..`k_(?,d)` order; isogenyMap() reverses them for Horner evaluation.
const isogenyMapG1 = isogenyMap(
  Fp,
  [
    // xNum
    [
      '0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7',
      '0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb',
      '0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0',
      '0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861',
      '0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9',
      '0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983',
      '0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84',
      '0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e',
      '0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317',
      '0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e',
      '0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b',
      '0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229',
    ],
    // xDen
    [
      '0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c',
      '0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff',
      '0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19',
      '0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8',
      '0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e',
      '0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5',
      '0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a',
      '0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e',
      '0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641',
      '0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a',
      '0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001', // LAST 1
    ],
    // yNum
    [
      '0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33',
      '0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696',
      '0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6',
      '0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb',
      '0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb',
      '0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0',
      '0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2',
      '0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29',
      '0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587',
      '0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30',
      '0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132',
      '0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e',
      '0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8',
      '0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133',
      '0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b',
      '0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604',
    ],
    // yDen
    [
      '0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1',
      '0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d',
      '0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2',
      '0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416',
      '0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d',
      '0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac',
      '0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c',
      '0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9',
      '0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a',
      '0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55',
      '0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8',
      '0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092',
      '0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc',
      '0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7',
      '0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f',
      '0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001', // LAST 1
    ],
  ].map((i) => i.map((j) => BigInt(j))) as [Fp[], Fp[], Fp[], Fp[]]
);

let G1_SWU: ((u: bigint) => { x: bigint; y: bigint }) | undefined;
let G2_SWU: ((u: Fp2) => { x: Fp2; y: Fp2 }) | undefined;
// SWU setup validates the pre-isogeny curve parameters and builds sqrt-ratio helpers.
// Doing that eagerly adds about 10ms to `bls12-381.js` import here, so keep it lazy; after the
// first map call the cached mapper is reused directly.
const getG1_SWU = () =>
  G1_SWU ||
  (G1_SWU = mapToCurveSimpleSWU(Fp, {
    A: Fp.create(
      BigInt(
        '0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d'
      )
    ),
    B: Fp.create(
      BigInt(
        '0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0'
      )
    ),
    Z: Fp.create(BigInt(11)),
  }));
const getG2_SWU = () =>
  G2_SWU ||
  (G2_SWU = mapToCurveSimpleSWU(Fp2, {
    // SWU map for the RFC 9380 §8.8.2 pre-isogeny G2 curve E':
    // y² = x³ + 240i * x + 1012 + 1012i
    A: Fp2.create({ c0: Fp.create(_0n), c1: Fp.create(BigInt(240)) }), // A' = 240 * I
    B: Fp2.create({ c0: Fp.create(BigInt(1012)), c1: Fp.create(BigInt(1012)) }), // B' = 1012 * (1 + I)
    Z: Fp2.create({ c0: Fp.create(BigInt(-2)), c1: Fp.create(BigInt(-1)) }), // Z: -(2 + I)
  }));

// Internal hash-to-curve step: G1 uses `m = 1`, so only `scalars[0]` is read,
// and the result is the isogeny image on E before the subgroup clear.
function mapToG1(scalars: bigint[]) {
  const { x, y } = getG1_SWU()(Fp.create(scalars[0]));
  return isogenyMapG1(x, y);
}
// Internal hash-to-curve step: G2 expects the RFC `m = 2` pair, and the result
// is the isogeny image on E before the subgroup clear.
function mapToG2(scalars: bigint[]) {
  const { x, y } = getG2_SWU()(Fp2.fromBigTuple(scalars as BigintTuple));
  return isogenyMapG2(x, y);
}
