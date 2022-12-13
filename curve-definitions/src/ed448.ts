/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { shake256 } from '@noble/hashes/sha3';
import { concatBytes, randomBytes, utf8ToBytes, wrapConstructor } from '@noble/hashes/utils';
import { PointType, twistedEdwards } from '@noble/curves/edwards';
import { mod, pow2, invert } from '@noble/curves/modular';
import { numberToBytesLE } from '@noble/curves/utils';
import { montgomery } from '../../lib/montgomery.js';

const _0n = BigInt(0);

const shake256_114 = wrapConstructor(() => shake256.create({ dkLen: 114 }));
const shake256_64 = wrapConstructor(() => shake256.create({ dkLen: 64 }));
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

function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: Likewise, for X448, set the two least significant bits of the first byte to 0, and the most
  // significant bit of the last byte to 1.
  bytes[0] &= 252; // 0b11111100
  // and the most significant bit of the last byte to 1.
  bytes[55] |= 128; // 0b10000000
  // NOTE: is is NOOP for 56 bytes scalars (X25519/X448)
  bytes[56] = 0; // Byte outside of group (456 buts vs 448 bits)
  return bytes;
}
// Edwards448 from RFC 8032 (https://www.rfc-editor.org/rfc/rfc8032.html#section-5.2).
// NOTE: Ed448-Goldilocks is different curve
const ED448_DEF = {
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
  // SHAKE256(dom4(phflag,context)||x, 114)
  hash: shake256_114,
  randomBytes,
  adjustScalarBytes,
  // dom4
  domain: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => {
    if (ctx.length > 255) throw new Error(`Context is too big: ${ctx.length}`);
    return concatBytes(
      utf8ToBytes('SigEd448'),
      new Uint8Array([phflag ? 1 : 0, ctx.length]),
      ctx,
      data
    );
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
} as const;

export const ed448 = twistedEdwards(ED448_DEF);
// NOTE: there is no ed448ctx, since ed448 supports ctx by default
export const ed448ph = twistedEdwards({ ...ED448_DEF, preHash: shake256_64 });

export const x448 = montgomery({
  a24: BigInt('39081'),
  montgomeryBits: 448,
  nByteLength: 57,
  P: ed448P,
  Gu: '0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  powPminus2: (x: bigint): bigint => {
    const P = ed448P;
    const Pminus3div4 = ed448_pow_Pminus3div4(x);
    const Pminus3 = pow2(Pminus3div4, BigInt(2), P);
    return mod(Pminus3 * x, P); // Pminus3 * x = Pminus2
  },
  adjustScalarBytes,
  // The 4-isogeny maps between the Montgomery curve and this Edwards
  // curve are:
  //   (u, v) = (y^2/x^2, (2 - x^2 - y^2)*y/x^3)
  //   (x, y) = (4*v*(u^2 - 1)/(u^4 - 2*u^2 + 4*v^2 + 1),
  //             -(u^5 - 2*u^3 - 4*u*v^2 + u)/
  //             (u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u))
  // xyToU: (p: PointType) => {
  //   const P = ed448P;
  //   const { x, y } = p;
  //   if (x === _0n) throw new Error(`Point with x=0 doesn't have mapping`);
  //   const invX = invert(x * x, P); // x^2
  //   const u = mod(y * y * invX, P); // (y^2/x^2)
  //   return numberToBytesLE(u, 56);
  // },
});
