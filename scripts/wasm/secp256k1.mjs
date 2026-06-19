import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Module, array } from '@awasm/compiler/module.js';
import { toMod } from '@awasm/compiler/codegen.js';
import { createWasm } from '@awasm/compiler/wasm.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..', '..');

const wasmPath = join(root, 'src', 'wasm', 'secp256k1.wasm');
const tsPath = join(root, 'src', 'wasm', 'secp256k1.wasm.ts');

const compilerOpts = {
  freeze: true,
  optimize: true,
  lowerSmallInt: true,
  lowerPattern: true,
  wasmBlockType: true,
  wasmTee: true,
  optExtMul: true,
  lowerWasm: true,
  useSIMD: false,
  nativeSIMD: false,
  native64bit: true,
};

const FE_LIMBS = 16;
const POINT_LIMBS = FE_LIMBS * 3;
const FE_TYPES = Array.from({ length: FE_LIMBS }, () => 'u64');
const POINT_TYPES = Array.from({ length: POINT_LIMBS }, () => 'u64');
const MASK16 = 0xffffn;
const P16 = [
  0xfc2fn,
  0xffffn,
  0xfffen,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
  0xffffn,
];

const slice = (xs, pos, len) => xs.slice(pos, pos + len);

function fieldOps(s) {
  const { u32, u64 } = s.types;
  const U64_0 = u64.const(0);
  const U64_977 = u64.const(977);
  const U64_MASK = u64.const(MASK16);
  const FE_P = P16.map((x) => u64.const(x));

  function normalize(limbs, len) {
    let carry = U64_0;
    const out = limbs.slice();
    for (let i = 0; i < len; i++) {
      const acc = u64.add(out[i] || U64_0, carry);
      out[i] = u64.and(acc, U64_MASK);
      carry = u64.shr(acc, 16);
    }
    if (out.length > len) out[len] = u64.add(out[len] || U64_0, carry);
    return out;
  }

  function foldHigh(limbs) {
    const out = limbs.slice();
    for (let i = FE_LIMBS; i < out.length; i++) {
      const h = out[i] || U64_0;
      out[i] = U64_0;
      out[i - FE_LIMBS] = u64.add(out[i - FE_LIMBS] || U64_0, u64.mul(h, U64_977));
      out[i - FE_LIMBS + 2] = u64.add(out[i - FE_LIMBS + 2] || U64_0, h);
    }
    return normalize(out, out.length - 1);
  }

  function subP(a) {
    let borrow = U64_0;
    const diff = [];
    for (let i = 0; i < FE_LIMBS; i++) {
      const b0 = u64.add(FE_P[i], borrow);
      const carryB = u64.lt(b0, FE_P[i]);
      const d = u64.sub(a[i], b0);
      const borrowA = u64.lt(a[i], b0);
      borrow = u64.fromN('u32', u32.or(borrowA, carryB));
      diff.push(u64.and(d, U64_MASK));
    }
    const keepDiff = u64.eq(borrow, U64_0);
    return a.map((v, i) => u64.select(keepDiff, diff[i], v));
  }

  function reduce(limbs) {
    let r = limbs.slice();
    while (r.length < 36) r.push(U64_0);
    r = normalize(r, 35);
    r = foldHigh(r);
    r = foldHigh(r);
    r = foldHigh(r);
    r = foldHigh(r);
    r = foldHigh(r);
    let out = Array.from({ length: FE_LIMBS }, (_, i) => u64.and(r[i] || U64_0, U64_MASK));
    out = subP(out);
    out = subP(out);
    out = subP(out);
    out = subP(out);
    return out;
  }

  function add(a, b) {
    const r = [];
    let carry = U64_0;
    for (let i = 0; i < FE_LIMBS; i++) {
      const acc = u64.add(a[i], b[i], carry);
      r.push(u64.and(acc, U64_MASK));
      carry = u64.shr(acc, 16);
    }
    r.push(carry);
    return reduce(r);
  }

  function sub(a, b) {
    let borrow = U64_0;
    const diff = [];
    for (let i = 0; i < FE_LIMBS; i++) {
      const b0 = u64.add(b[i], borrow);
      const carryB = u64.lt(b0, b[i]);
      const d = u64.sub(a[i], b0);
      const borrowA = u64.lt(a[i], b0);
      borrow = u64.fromN('u32', u32.or(borrowA, carryB));
      diff.push(u64.and(d, U64_MASK));
    }
    const mask = u64.sub(U64_0, borrow);
    const out = [];
    let carry = U64_0;
    for (let i = 0; i < FE_LIMBS; i++) {
      const addend = u64.and(FE_P[i], mask);
      const acc = u64.add(diff[i], addend, carry);
      out.push(u64.and(acc, U64_MASK));
      carry = u64.shr(acc, 16);
    }
    return out;
  }

  function mulSmall(a, n) {
    const limbs = [];
    let carry = U64_0;
    for (let i = 0; i < FE_LIMBS; i++) {
      const acc = u64.add(u64.mul(a[i], n), carry);
      limbs.push(u64.and(acc, U64_MASK));
      carry = u64.shr(acc, 16);
    }
    limbs.push(carry);
    return reduce(limbs);
  }

  function mul(a, b) {
    const out = [];
    let carry = U64_0;
    for (let k = 0; k < FE_LIMBS * 2 - 1; k++) {
      let acc = carry;
      const lo = Math.max(0, k - (FE_LIMBS - 1));
      const hi = Math.min(FE_LIMBS - 1, k);
      for (let i = lo; i <= hi; i++) acc = u64.add(acc, u64.mul(a[i], b[k - i]));
      out.push(u64.and(acc, U64_MASK));
      carry = u64.shr(acc, 16);
    }
    out.push(carry);
    return reduce(out);
  }

  return { add, sub, mul, mulSmall };
}

function addFieldFunctions(mod) {
  return mod
    .fn('fe_add', [...FE_TYPES, ...FE_TYPES], FE_TYPES, (s, ...args) => {
      const { add } = fieldOps(s);
      return add(slice(args, 0, FE_LIMBS), slice(args, FE_LIMBS, FE_LIMBS));
    })
    .fn('fe_sub', [...FE_TYPES, ...FE_TYPES], FE_TYPES, (s, ...args) => {
      const { sub } = fieldOps(s);
      return sub(slice(args, 0, FE_LIMBS), slice(args, FE_LIMBS, FE_LIMBS));
    })
    .fn('fe_mul', [...FE_TYPES, ...FE_TYPES], FE_TYPES, (s, ...args) => {
      const { mul } = fieldOps(s);
      return mul(slice(args, 0, FE_LIMBS), slice(args, FE_LIMBS, FE_LIMBS));
    })
    .fn('fe_mul_small', [...FE_TYPES, 'u64'], FE_TYPES, (s, ...args) => {
      const { mulSmall } = fieldOps(s);
      return mulSmall(slice(args, 0, FE_LIMBS), args[FE_LIMBS]);
    });
}

function pointOps(s) {
  const { u64 } = s.types;
  const U64_3 = u64.const(3);
  const U64_21 = u64.const(21);
  const { add: feAdd, sub: feSub, mul: feMul, mulSmall: feMulSmall } = fieldOps(s);
  const feSqr = (a) => feMul(a, a);
  const px = (p) => slice(p, 0, FE_LIMBS);
  const py = (p) => slice(p, FE_LIMBS, FE_LIMBS);
  const pz = (p) => slice(p, FE_LIMBS * 2, FE_LIMBS);
  const point = (x, y, z) => [...x, ...y, ...z];

  function double(p) {
    const X1 = px(p), Y1 = py(p), Z1 = pz(p);
    const t0 = feSqr(X1);
    const t1 = feSqr(Y1);
    const t2 = feSqr(Z1);
    let t3 = feMul(X1, Y1);
    t3 = feAdd(t3, t3);
    let Z3 = feMul(X1, Z1);
    Z3 = feAdd(Z3, Z3);
    let Y3 = feMulSmall(t2, U64_21);
    let X3 = feSub(t1, Y3);
    Y3 = feAdd(t1, Y3);
    Y3 = feMul(X3, Y3);
    X3 = feMul(t3, X3);
    Z3 = feMulSmall(Z3, U64_21);
    t3 = Z3;
    Z3 = feAdd(t0, t0);
    let t0x = feAdd(Z3, t0);
    t0x = feMul(t0x, t3);
    Y3 = feAdd(Y3, t0x);
    let t2x = feMul(Y1, Z1);
    t2x = feAdd(t2x, t2x);
    const t0y = feMul(t2x, t3);
    X3 = feSub(X3, t0y);
    Z3 = feMul(t2x, t1);
    Z3 = feAdd(Z3, Z3);
    Z3 = feAdd(Z3, Z3);
    return point(X3, Y3, Z3);
  }

  function add(p, q) {
    const X1 = px(p), Y1 = py(p), Z1 = pz(p);
    const X2 = px(q), Y2 = py(q), Z2 = pz(q);
    let t0 = feMul(X1, X2);
    let t1 = feMul(Y1, Y2);
    let t2 = feMul(Z1, Z2);
    let t3 = feAdd(X1, Y1);
    let t4 = feAdd(X2, Y2);
    t3 = feMul(t3, t4);
    t4 = feAdd(t0, t1);
    t3 = feSub(t3, t4);
    t4 = feAdd(X1, Z1);
    let t5 = feAdd(X2, Z2);
    t4 = feMul(t4, t5);
    t5 = feAdd(t0, t2);
    t4 = feSub(t4, t5);
    t5 = feAdd(Y1, Z1);
    let X3 = feAdd(Y2, Z2);
    t5 = feMul(t5, X3);
    X3 = feAdd(t1, t2);
    t5 = feSub(t5, X3);
    X3 = feMulSmall(t2, U64_21);
    let Z3 = X3;
    X3 = feSub(t1, Z3);
    Z3 = feAdd(t1, Z3);
    let Y3 = feMul(X3, Z3);
    t1 = feMulSmall(t0, U64_3);
    t4 = feMulSmall(t4, U64_21);
    t0 = feMul(t1, t4);
    Y3 = feAdd(Y3, t0);
    t0 = feMul(t5, t4);
    X3 = feMul(t3, X3);
    X3 = feSub(X3, t0);
    t0 = feMul(t3, t1);
    Z3 = feMul(t5, Z3);
    Z3 = feAdd(Z3, t0);
    return point(X3, Y3, Z3);
  }

  return { add, double };
}

function addPointFunctions(mod) {
  return mod
    .fn('point_add', [...POINT_TYPES, ...POINT_TYPES], POINT_TYPES, (s, ...args) => {
      const { add } = pointOps(s);
      return add(slice(args, 0, POINT_LIMBS), slice(args, POINT_LIMBS, POINT_LIMBS));
    })
    .fn('point_double', POINT_TYPES, POINT_TYPES, (s, ...p) => {
      const { double } = pointOps(s);
      return double(p);
    })
    .fn('point_select', ['u32', ...POINT_TYPES, ...POINT_TYPES], POINT_TYPES, (s, cond, ...args) => {
      const { u64 } = s.types;
      const a = slice(args, 0, POINT_LIMBS);
      const b = slice(args, POINT_LIMBS, POINT_LIMBS);
      return a.map((v, i) => u64.select(cond, v, b[i]));
    });
}

function addMultiplyFunction(mod) {
  return mod.fn('multiply', [], 'void', (s) => {
    const { u64 } = s.types;
    const U64_0 = u64.const(0);
    const U64_1 = u64.const(1);
    const U64_15 = u64.const(15);
    const U64_MASK = u64.const(MASK16);

    const FE_ZERO = Array.from({ length: FE_LIMBS }, () => U64_0);
    const FE_ONE = [U64_1, ...Array.from({ length: FE_LIMBS - 1 }, () => U64_0)];
    const pointZero = () => [...FE_ZERO, ...FE_ONE, ...FE_ZERO];
    const pointAdd = (a, b) => s.functions.point_add.call(...a, ...b);
    const pointDouble = (p) => s.functions.point_double.call(...p);
    const pointSelect = (cond, a, b) => s.functions.point_select.call(cond, ...a, ...b);

    function loadFe(pos) {
      const out = [];
      for (let i = 0; i < 4; i++) {
        const w = s.memory.point[pos + i].get();
        out.push(u64.and(w, U64_MASK));
        out.push(u64.and(u64.shr(w, 16), U64_MASK));
        out.push(u64.and(u64.shr(w, 32), U64_MASK));
        out.push(u64.and(u64.shr(w, 48), U64_MASK));
      }
      return out;
    }

    function storeFe(pos, a) {
      for (let i = 0; i < 4; i++) {
        const j = 4 * i;
        s.memory.out[pos + i].set(
          u64.or(a[j], u64.shl(a[j + 1], 16), u64.shl(a[j + 2], 32), u64.shl(a[j + 3], 48))
        );
      }
    }

    function window(offset, index) {
      const word = s.memory.scalar[offset + Math.floor(index / 16)].get();
      return u64.and(u64.shr(word, (index % 16) * 4), U64_15);
    }

    function selectTable(table, win) {
      let out = table[0];
      for (let i = 1; i < 16; i++) out = pointSelect(u64.eq(win, u64.const(i)), table[i], out);
      return out;
    }

    const base1 = [...loadFe(0), ...loadFe(4), ...loadFe(8)];
    const base2 = [...loadFe(12), ...loadFe(16), ...loadFe(20)];
    const table1 = [pointZero(), base1];
    const table2 = [pointZero(), base2];
    for (let i = 2; i < 16; i++) {
      table1.push(pointAdd(table1[i - 1], base1));
      table2.push(pointAdd(table2[i - 1], base2));
    }

    let acc = pointZero();
    for (let i = 31; i >= 0; i--) {
      acc = pointDouble(pointDouble(pointDouble(pointDouble(acc))));
      acc = pointAdd(acc, selectTable(table1, window(0, i)));
      acc = pointAdd(acc, selectTable(table2, window(4, i)));
    }

    storeFe(0, slice(acc, 0, FE_LIMBS));
    storeFe(4, slice(acc, FE_LIMBS, FE_LIMBS));
    storeFe(8, slice(acc, FE_LIMBS * 2, FE_LIMBS));
  });
}

function buildModule() {
  let mod = new Module('secp256k1_mul')
    .mem('point', array('u64', {}, 24))
    .mem('scalar', array('u64', {}, 8))
    .mem('out', array('u64', {}, 12));
  mod = addPointFunctions(mod);
  mod = addMultiplyFunction(mod);
  return mod;
}

const { wasmMod, memory } = toMod(buildModule(), compilerOpts);
const wasmBytes = createWasm(wasmMod);

mkdirSync(dirname(wasmPath), { recursive: true });
writeFileSync(wasmPath, wasmBytes);

const generated = `// This file is generated by scripts/wasm/secp256k1.mjs. Do not edit by hand.
export const SECP256K1_WASM_BASE64: string = '${Buffer.from(wasmBytes).toString('base64')}';

export const SECP256K1_WASM_OFFSETS: { readonly point: number; readonly scalar: number; readonly out: number } = ${JSON.stringify(
  {
    point: memory.point.pos,
    scalar: memory.scalar.pos,
    out: memory.out.pos,
  },
  null,
  2
)};
`;
writeFileSync(tsPath, generated);

console.log(`wrote ${wasmPath} (${wasmBytes.length} bytes)`);
console.log(`wrote ${tsPath}`);
