# noble-curves

Minimal, zero-dependency JS implementation of elliptic curve cryptography.

Implements Short Weierstrass curves with ECDSA signature scheme. Edwards, Twisted Edwards & Montgomery could be coming soon.

To keep the package minimal, no curve definitions are provided out-of-box.
Use separate pkg that defines popular curves: `pkgd` for P256, P384, P521, secp256k1.

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
// Short Weierstrass curve
import shortw from '@noble/curves/shortw';

export const secp256k1 = shortw({
  a: 0n,
  b: 7n,
  // Field over which we'll do calculations. Verify with:
  P: 2n ** 256n - 2n ** 32n - 2n ** 9n - 2n ** 8n - 2n ** 7n - 2n ** 6n - 2n ** 4n - 1n,
  // Curve order, total count of valid points in the field. Verify with:
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  // Base point (x, y) aka generator point
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  ...getHash(sha256),
  // noble-secp256k1 compat
  signOpts: { canonical: true },
  verifyOpts: { strict: true },
});

// secp256k1.getPublicKey(priv)
// secp256k1.sign(msg, priv)
// secp256k1.verify(sig, msg, pub)
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
