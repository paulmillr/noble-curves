import { sha512 } from '@noble/hashes/sha512';
import { shake256 } from '@noble/hashes/sha3';
import { concatBytes, randomBytes, utf8ToBytes, wrapConstructor } from '@noble/hashes/utils';
import { twistedEdwards } from '@noble/curves/edwards';
import { mod, pow2, isNegativeLE } from '@noble/curves/modular';

const ed25519P = BigInt(
  '57896044618658097711785492504343953926634992332820282019728792003956564819949'
);
// √(-1) aka √(a) aka 2^((p-1)/4)
const ED25519_SQRT_M1 = BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);

function ed25519_pow_2_252_3(x: bigint) {
  const P = ed25519P;
  const _1n = BigInt(1);
  const _2n = BigInt(2);
  const _5n = BigInt(5);
  const _10n = BigInt(10);
  const _20n = BigInt(20);
  const _40n = BigInt(40);
  const _80n = BigInt(80);
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, _2n, P) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, _1n, P) * x) % P; // x^31
  const b10 = (pow2(b5, _5n, P) * b5) % P;
  const b20 = (pow2(b10, _10n, P) * b10) % P;
  const b40 = (pow2(b20, _20n, P) * b20) % P;
  const b80 = (pow2(b40, _40n, P) * b40) % P;
  const b160 = (pow2(b80, _80n, P) * b80) % P;
  const b240 = (pow2(b160, _80n, P) * b80) % P;
  const b250 = (pow2(b240, _10n, P) * b10) % P;
  const pow_p_5_8 = (pow2(b250, _2n, P) * x) % P;
  // ^ To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}

export const ed25519 = twistedEdwards({
  // Param: a
  a: BigInt(-1),
  // Equal to -121665/121666 over finite field.
  // Negative number is P - number, and division is invert(number, P)
  d: BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
  // Finite field 𝔽p over which we'll do calculations; 2n ** 255n - 19n
  P: ed25519P,
  // Subgroup order: how many points ed25519 has
  // 2n ** 252n + 27742317777372353535851937790883648493n;
  n: BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989'),
  // Cofactor
  h: BigInt(8),
  // Base point (x, y) aka generator point
  Gx: BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
  Gy: BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
  // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
  a24: BigInt('121665'),
  scalarBits: 255,
  hash: sha512,
  randomBytes,
  adjustScalarBytes: (bytes: Uint8Array): Uint8Array => {
    // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
    // set the three least significant bits of the first byte
    bytes[0] &= 248; // 0b1111_1000
    // and the most significant bit of the last to zero,
    bytes[31] &= 127; // 0b0111_1111
    // set the second most significant bit of the last byte to 1
    bytes[31] |= 64; // 0b0100_0000
    return bytes;
  },
  // dom2
  domain: (data: Uint8Array, ctx: Uint8Array, hflag: boolean) => {
    if (ctx.length || hflag) throw new Error('Contexts/pre-hash are not supported');
    // TODO: support for ph/ctx too?
    return data;
  },
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio: (u: bigint, v: bigint): { isValid: boolean; value: bigint } => {
    const P = ed25519P;
    const v3 = mod(v * v * v, P); // v³
    const v7 = mod(v3 * v3 * v, P); // v⁷
    // (p+3)/8 and (p-5)/8
    const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
    let x = mod(u * v3 * pow, P); // (uv³)(uv⁷)^(p-5)/8
    const vx2 = mod(v * x * x, P); // vx²
    const root1 = x; // First root candidate
    const root2 = mod(x * ED25519_SQRT_M1, P); // Second root candidate
    const useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
    const useRoot2 = vx2 === mod(-u, P); // If vx² = -u, set x <-- x * 2^((p-1)/4)
    const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P); // There is no valid root, vx² = -u√(-1)
    if (useRoot1) x = root1;
    if (useRoot2 || noRoot) x = root2; // We return root2 anyway, for const-time
    if (isNegativeLE(x, P)) x = mod(-x, P);
    return { isValid: useRoot1 || useRoot2, value: x };
  },
});

// https://www.rfc-editor.org/rfc/rfc8032.html says bitLength is 456
// https://www.rfc-editor.org/rfc/rfc7748 says bitLength is 448
// WTF?!

// So, if we looking at wycheproof:
// EdDSA: 456
// X448 (sharedkey stuff) is 448. Awesome!

const ed448P = BigInt(
  '726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439'
);

// powPminus3div4 calculates z = x^k mod p, where k = (p-3)/4.
function ed448_pow_Pminus3div4(x: bigint): bigint {
  const P = ed448P;
  // x ** ((P - 3n)/4n) % P
  // [223 of 1, 0, 222 of 1], almost same as secp!
  const b2 = (x * x * x) % P;
  const b3 = (b2 * b2 * x) % P;
  const b6 = (pow2(b3, 3n, P) * b3) % P;
  const b9 = (pow2(b6, 3n, P) * b3) % P;
  const b11 = (pow2(b9, 2n, P) * b2) % P;
  const b22 = (pow2(b11, 11n, P) * b11) % P;
  const b44 = (pow2(b22, 22n, P) * b22) % P;
  const b88 = (pow2(b44, 44n, P) * b44) % P;
  const b176 = (pow2(b88, 88n, P) * b88) % P;
  const b220 = (pow2(b176, 44n, P) * b44) % P;
  const b222 = (pow2(b220, 2n, P) * b2) % P;
  const b223 = (pow2(b222, 1n, P) * x) % P;
  return (pow2(b223, 223n, P) * b222) % P;
}
export const ed448 = twistedEdwards({
  // Param: a
  a: BigInt(1),
  // Equal to -39081 over finite field.
  // Negative number is P - number
  d: BigInt(
    '726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018326358'
  ),
  // Finite field 𝔽p over which we'll do calculations; 2n ** 448n - 2n ** 224n - 1n
  P: ed448P,
  // Subgroup order: how many points ed448 has; 2n**446n - 13818066809895115352007386748515426880336692474882178609894547503885n
  n: BigInt(
    '181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779'
  ),
  nBitLength: 456,
  // Cofactor
  h: BigInt(4),
  // Base point (x, y) aka generator point
  Gx: BigInt(
    '224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710'
  ),
  Gy: BigInt(
    '298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660'
  ),
  // The constant a24 is (156326 - 2) / 4 = 39081 for curve448/X448.
  a24: BigInt('39081'),
  scalarBits: 448, // TODO: fix that
  // SHAKE256(dom4(phflag,context)||x, 114)
  hash: wrapConstructor(() => shake256.create({ dkLen: 114 })),
  randomBytes,
  adjustScalarBytes: (bytes: Uint8Array): Uint8Array => {
    // Section 5: Likewise, for X448, set the two least significant bits of the first byte to 0, and the most
    // significant bit of the last byte to 1.
    bytes[0] &= 252; // 0b11111100
    // and the most significant bit of the last byte to 1.
    bytes[55] |= 128; // 0b10000000
    bytes[56] = 0; // Byte outside of group (456 buts vs 448 bits)
    return bytes;
  },
  // dom4
  domain: (data: Uint8Array, ctx: Uint8Array, hflag: boolean) => {
    if (ctx.length > 255) throw new Error(`Context is too big: ${ctx.length}`);
    return concatBytes(utf8ToBytes('SigEd448'), new Uint8Array([hflag ? 1 : 0, ctx.length]), data);
  },
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio: (u: bigint, v: bigint): { isValid: boolean; value: bigint } => {
    const P = ed448P;
    // https://datatracker.ietf.org/doc/html/rfc8032#section-5.2.3
    // To compute the square root of (u/v), the first step is to compute the
    //   candidate root x = (u/v)^((p+1)/4).  This can be done using the
    // following trick, to use a single modular powering for both the
    // inversion of v and the square root:
    //           (p+1)/4    3            (p-3)/4
    // x = (u/v)        = u  v (u^5 v^3)         (mod p)
    const u2v = mod(u * u * v, P);
    const u3v = mod(u2v * u, P); // u^2v
    const u5v3 = mod(u3v * u2v * v, P); // u^5v^3
    const root = ed448_pow_Pminus3div4(u5v3);
    const x = mod(u3v * root, P);
    // Verify that root is exists
    const x2 = mod(x * x, P); // x^2
    // If v * x^2 = u, the recovered x-coordinate is x.  Otherwise, no
    // square root exists, and the decoding fails.
    return { isValid: mod(x2 * v, P) === u, value: x };
  },
});
