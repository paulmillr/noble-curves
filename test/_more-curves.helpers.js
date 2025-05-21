/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha224, sha256, sha512 } from '@noble/hashes/sha2';
import { createCurve } from '../esm/_shortw_utils.js';
import { Field } from '../esm/abstract/modular.js';
import curvesInit from './vectors/curves-init.json' with { type: 'json' };
const { categories: JSON_CATEGORIES } = curvesInit;

// NIST secp192r1 aka p192
// https://www.secg.org/sec2-v2.pdf, https://neuromancer.sk/std/secg/secp192r1
export const p192 = createCurve(
  {
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffc'),
    b: BigInt('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    Fp: Field(BigInt('0xfffffffffffffffffffffffffffffffeffffffffffffffff')),
    n: BigInt('0xffffffffffffffffffffffff99def836146bc9b1b4d22831'),
    Gx: BigInt('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
    Gy: BigInt('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
    h: BigInt(1),
    lowS: false,
  },
  sha256
);
export const secp192r1 = p192;

export const p224 = createCurve(
  {
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
    b: BigInt('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
    Fp: Field(BigInt('0xffffffffffffffffffffffffffffffff000000000000000000000001')),
    n: BigInt('0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
    Gx: BigInt('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
    Gy: BigInt('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
    h: BigInt(1),
    lowS: false,
  },
  sha224
);
export const secp224r1 = p224;

export const miscCurves = {};
for (let category of JSON_CATEGORIES) {
  for (let c of category.curves) {
    if (c.form !== 'Weierstrass') continue;
    if (c.field.type !== 'Prime') continue;
    if (!c.generator) continue;
    const a = BigInt(c.params.a?.raw);
    const b = BigInt(c.params.b?.raw);
    const Gx = BigInt(c.generator?.x.raw);
    const Gy = BigInt(c.generator?.y.raw);
    const n = BigInt(c.order);
    const h = BigInt(c.cofactor);
    const p = BigInt(c.field.p);
    const Fp = Field(p);
    const norm = {
      Fp,
      a,
      b,
      Gx,
      Gy,
      n,
      h,
    };
    miscCurves['misc_' + c.name] = createCurve(norm, sha512);
  }
}
