// Minerva timing-leak test against third-party JS ECC (elliptic, sjcl) on P-256.
// Does ECDSA sign() time correlate with the secret nonce bit-length? (noble: no; classic Minerva
// targets: yes). We know the private key, so we recover each nonce k = s^-1(z + r*d) mod n, bin the
// best-of-R sign timing by bit_length(k), and report correlation + leading-zero enrichment.
// Emits CSV (elapsed,h,r,s,bitlen) for the lattice attack (lattice_ct.py, secp256r1).
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const require = createRequire(import.meta.url);

const LIB = process.argv[2] || 'elliptic';
const N = +(process.argv[3] || 4000);
const R = +(process.argv[4] || 200);
const OUT = process.argv[5];

const mod = (a, m) => ((a % m) + m) % m;
const inv = (a, m) => { let [g, x, r, s] = [mod(a, m), 1n, m, 0n]; while (r) { const q = g / r; [g, r] = [r, g - q * r]; [x, s] = [s, x - q * s]; } return mod(x, m); };
const H = (b) => BigInt('0x' + createHash('sha256').update(b).digest('hex'));
const hx = (x) => x.toString(16);

// --- per-library P-256 signer: returns { n, d, pubHex, sign(msg)->{r,s,z,timeNs} } ---
function makeSigner(lib) {
  if (lib === 'elliptic') {
    const EC = require('elliptic').ec;
    const ec = new EC('p256');
    const n = BigInt('0x' + ec.n.toString(16));
    const key = ec.genKeyPair();
    const d = BigInt('0x' + key.getPrivate().toString(16));
    const pubHex = key.getPublic().encode('hex', false);
    const gMulX = (k) => BigInt('0x' + ec.g.mul(k.toString(16)).getX().toString(16)) % n; // (k*G).x mod n
    const sign = (msg) => {
      const digest = createHash('sha256').update(msg).digest(); // 32-byte hash
      const z = mod(H(msg), n);
      let best = Infinity, r, s;
      for (let t = 0; t < R; t++) {
        const t0 = process.hrtime.bigint();
        const sig = key.sign(digest, { canonical: false }); // deterministic RFC6979, raw s (no low-S flip)
        const el = Number(process.hrtime.bigint() - t0);
        if (el < best) { best = el; r = BigInt('0x' + sig.r.toString(16)); s = BigInt('0x' + sig.s.toString(16)); }
      }
      return { r, s, z, timeNs: best };
    };
    return { n, d, pubHex, sign, gMulX };
  }
  if (lib === 'sjcl') {
    const sjcl = require('sjcl');
    // load ecc core (npm build ships without sjcl.ecc)
    const path = require('path'); const fs = require('fs');
    const base = path.dirname(require.resolve('sjcl/package.json'));
    for (const f of ['core/bn.js', 'core/ecc.js', 'core/ecdsa.js', 'core/sha256.js', 'core/random.js', 'core/bitArray.js', 'core/codecBytes.js'])
      { const p = path.join(base, f); if (fs.existsSync(p)) eval(fs.readFileSync(p, 'utf8')); }
    const curve = sjcl.ecc.curves.c256;
    const n = BigInt('0x' + curve.r.toString().replace('0x', ''));
    // seed sjcl RNG (otherwise "generator isn't seeded")
    const seed = []; const rb = require('crypto').randomBytes(128);
    for (let i = 0; i < rb.length; i += 4) seed.push(rb.readUInt32BE(i));
    sjcl.random.addEntropy(seed, 1024, 'crypto');
    const keys = sjcl.ecc.ecdsa.generateKeys(curve, 6);
    const sk = keys.sec, pk = keys.pub;
    const d = BigInt('0x' + sjcl.codec.hex.fromBits(sk.get())); // sec.get() -> bitArray
    const pubHex = sjcl.codec.hex.fromBits(pk.get().x.concat(pk.get().y));
    const sign = (msg) => {
      const ba = sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits([...msg]));
      const z = mod(H(msg), n);
      const t0 = process.hrtime.bigint();
      const sig = sk.sign(ba, 6); // random nonce -> one shot (can't average a fixed nonce)
      const el = Number(process.hrtime.bigint() - t0);
      const bits = sjcl.bitArray;
      const rs = sig; const l = bits.bitLength(rs) / 2;
      const r = BigInt('0x' + sjcl.codec.hex.fromBits(bits.bitSlice(rs, 0, l)));
      const s = BigInt('0x' + sjcl.codec.hex.fromBits(bits.bitSlice(rs, l)));
      return { r, s, z, timeNs: el };
    };
    return { n, d, pubHex, sign, pubUncompressed: '04' + pubHex };
  }
  throw new Error('unknown lib ' + lib);
}

const { n, d, pubHex, sign, gMulX } = makeSigner(LIB);
console.log(`# ${LIB} P-256 ECDSA sign timing vs nonce bit-length  (N=${N}, R=${R})`);

const bl = [], tm = [], rows = [];
let checked = 0, ok = 0;
for (let i = 0; i < N; i++) {
  const msg = Buffer.from(`m${i}:${LIB}`);
  const { r, s, z, timeNs } = sign(msg);
  const k = mod(inv(s, n) * mod(z + r * d, n), n);   // recover nonce
  if (gMulX && i < 20) { checked++; if (gMulX(k) === mod(r, n)) ok++; }   // sanity: (k*G).x ?= r
  bl.push(k.toString(2).length); tm.push(timeNs);
  rows.push(`${Math.round(timeNs)},${hx(z)},${hx(r)},${hx(s)},${k.toString(2).length}`);
}
if (checked) console.log(`  nonce-recovery sanity: ${ok}/${checked} verified (k*G).x == r`);

// stats
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const mb = mean(bl), mt = mean(tm);
let sxy = 0, sxx = 0, syy = 0;
for (let i = 0; i < N; i++) { const dx = bl[i] - mb, dy = tm[i] - mt; sxy += dx * dy; sxx += dx * dx; syy += dy * dy; }
const rcorr = sxy / Math.sqrt(sxx * syy);
// leading-zero enrichment of fastest-timed
const idx = [...tm.keys()].sort((a, b) => tm[a] - tm[b]);
const lz = idx.map((i) => 256 - bl[i]);
const avg = (a) => a.reduce((x, y) => x + y, 0) / a.length;
console.log(`  Pearson r(bitlen, time) = ${rcorr.toFixed(4)}`);
console.log(`  overall mean leading-zeros = ${avg(lz).toFixed(3)} (random ~1.0)`);
for (const K of [90, 200, 500]) console.log(`  fastest ${K}: mean lz = ${avg(lz.slice(0, K)).toFixed(3)}`);

if (OUT) {
  const priv = mod(d, n);
  writeFileSync(OUT, `${LIB === 'sjcl' ? '04' + pubHex : pubHex} ${hx(priv)}\n` + rows.join('\n') + '\n');
  console.log(`  wrote ${N} sigs -> ${OUT}`);
}
