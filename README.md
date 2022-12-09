# noble-curves

Minimal, zero-dependency JS implementation of elliptic curve cryptography.

Implements Short Weierstrass curve with ECDSA signatures & Twisted Edwards curve with EdDSA signatures.

To keep the package minimal, no curve definitions are provided out-of-box. Use `micro-curve-definitions` module:

- It provides P192, P224, P256, P384, P521, secp256k1, stark curve, bn254, pasta (pallas/vesta) short weierstrass curves
- It also provides ed25519 and ed448 twisted edwards curves
- Main reason for separate package is the fact hashing library (like `@noble/hashes`) is required for full functionality
- We may reconsider merging packages in future, when a stable version would be ready

Future plans:

- Edwards and Montgomery curves
- hash-to-curve standard
- point indistinguishability
- pairings

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, small files
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [curves](https://github.com/paulmillr/noble-curves)

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-curves/releases):

## Usage

```sh
npm install @noble/curves
```

```ts
import shortw from '@noble/curves/shortw'; // Short Weierstrass curve
import twistede from '@noble/curves/twistede'; // Twisted Edwards curve
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

export const secp256k1 = shortw({
  a: 0n,
  b: 7n,
  // Field over which we'll do calculations
  P: 2n ** 256n - 2n ** 32n - 2n ** 9n - 2n ** 8n - 2n ** 7n - 2n ** 6n - 2n ** 4n - 1n,
  // Curve order, total count of valid points in the field
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  // Base point (x, y) aka generator point
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (k: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
  randomBytes: randomBytes
});

// secp256k1.getPublicKey(priv)
// secp256k1.sign(msg, priv)
// secp256k1.verify(sig, msg, pub)
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
